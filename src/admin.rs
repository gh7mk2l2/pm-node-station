//! 管理后台 API（全部操作记审计日志）。

use crate::audit::write_audit;
use crate::auth::{AdminUser, RootUser};
use crate::batches::{activate_batch, deactivate_batch};
use crate::error::AppError;
use crate::models::NodeBatch;
use crate::nodes::{dedupe_nodes, parse_subscription_nodes};
use crate::settings::*;
use crate::socks_parse::{
    is_eligible, parse_socks_line, proxy_identity, redact_proxy_credentials,
};
use crate::socks_runner::SOCKS_RUNNER;
use crate::state::AppState;
use crate::sync::{get_sync_admin_state, run_sync, save_sync_config, SyncTrigger};
use crate::util::sha256_hex;
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub q: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

fn page_of(q: &PageQuery) -> (i64, i64) {
    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(20).clamp(1, 100);
    (page, per_page)
}

// ---------------------------------------------------------------------------
// 概览
// ---------------------------------------------------------------------------

pub async fn admin_stats(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let (users_total,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (users_banned,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM users WHERE is_banned = TRUE")
            .fetch_one(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let (batches_total,): (i64,) = sqlx::query_as("SELECT count(*) FROM node_batches")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (socks_total,): (i64,) = sqlx::query_as("SELECT count(*) FROM socks_pool")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (socks_ok,): (i64,) = sqlx::query_as("SELECT count(*) FROM socks_pool WHERE status = 'ok'")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (pulls_today,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM sub_pulls WHERE pulled_at >= date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let (pulls_total,): (i64,) = sqlx::query_as("SELECT count(*) FROM sub_pulls")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    // 各分级的激活批次（两个分级各自独立生效）
    let active_batches: Vec<(i64, String, i32, i16)> = sqlx::query_as(
        "SELECT id, title, node_count, tier FROM node_batches WHERE is_active = TRUE ORDER BY tier ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let nodes_active: i64 = active_batches.iter().map(|(_, _, n, _)| *n as i64).sum();
    Ok(Json(json!({
        "users": users_total,
        "users_total": users_total,
        "users_banned": users_banned,
        "batches": batches_total,
        "batches_total": batches_total,
        "nodes_active": nodes_active,
        "socks_total": socks_total,
        "socks_ok": socks_ok,
        "pulls_today": pulls_today,
        "pulls_total": pulls_total,
        "active_batch": active_batches.first().map(|(id, title, node_count, _)| json!({"id": id, "title": title, "node_count": node_count})),
        "active_batches": active_batches.iter().map(|(id, title, node_count, tier)| json!({"id": id, "title": title, "node_count": node_count, "tier": tier})).collect::<Vec<_>>(),
    })))
}

// ---------------------------------------------------------------------------
// 批次
// ---------------------------------------------------------------------------

pub async fn list_batches(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (page, per_page) = page_of(&q);
    let total: (i64,) = sqlx::query_as("SELECT count(*) FROM node_batches")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let rows: Vec<NodeBatch> = sqlx::query_as(
        "SELECT * FROM node_batches ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(per_page)
    .bind((page - 1) * per_page)
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "items": rows.iter().map(|b| json!({
            "id": b.id, "title": b.title, "batch_date": b.batch_date,
            "node_count": b.node_count, "is_active": b.is_active, "tier": b.tier,
            "source": b.source, "created_at": b.created_at,
        })).collect::<Vec<_>>(),
        "total": total.0, "page": page, "per_page": per_page,
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateBatchInput {
    pub title: String,
    pub nodes: String,
    pub tier: Option<i16>,
}

pub async fn create_batch(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<CreateBatchInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let title = input.title.trim().to_string();
    if title.is_empty() || title.chars().count() > 120 {
        return Err(AppError::bad_request("标题不能为空且不超过 120 字"));
    }
    let nodes = dedupe_nodes(&parse_subscription_nodes(&input.nodes));
    if nodes.is_empty() {
        return Err(AppError::bad_request("没有解析到可用节点"));
    }
    let tier = crate::settings::normalize_tier(input.tier.unwrap_or(1));
    let today = crate::timeutil::shanghai_today();
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO node_batches (title, nodes, batch_date, node_count, is_active, source, created_by, tier) \
         VALUES ($1, $2, $3, $4, FALSE, 'manual', $5, $6) RETURNING id",
    )
    .bind(&title)
    .bind(serde_json::to_value(&nodes).unwrap())
    .bind(today)
    .bind(nodes.len() as i32)
    .bind(admin.0.id)
    .bind(tier)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "batch.create",
        Some("batch"),
        Some(&row.0.to_string()),
        json!({"title": title, "node_count": nodes.len(), "tier": tier}),
    )
    .await;
    Ok(Json(json!({"id": row.0, "node_count": nodes.len(), "tier": tier})))
}

pub async fn activate_batch_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = state.pool.begin().await.map_err(|e| AppError::internal(e.to_string()))?;
    activate_batch(&mut tx, id)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::not_found("批次不存在"),
            _ => AppError::internal(e.to_string()),
        })?;
    tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "batch.activate",
        Some("batch"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn deactivate_batch_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut tx = state.pool.begin().await.map_err(|e| AppError::internal(e.to_string()))?;
    deactivate_batch(&mut tx, id)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    tx.commit().await.map_err(|e| AppError::internal(e.to_string()))?;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "batch.deactivate",
        Some("batch"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn delete_batch(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query("DELETE FROM node_batches WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("批次不存在"));
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "batch.delete",
        Some("batch"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn batch_nodes(
    State(state): State<AppState>,
    _admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row: Option<(String, serde_json::Value)> =
        sqlx::query_as("SELECT title, nodes FROM node_batches WHERE id = $1")
            .bind(id)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let Some((title, nodes)) = row else {
        return Err(AppError::not_found("批次不存在"));
    };
    let uris: Vec<String> = nodes
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    Ok(Json(json!({"id": id, "title": title, "nodes": uris})))
}

// ---------------------------------------------------------------------------
// 同步
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct TierQuery {
    pub tier: Option<i16>,
}

pub async fn get_sync(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<TierQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let s = get_sync_admin_state(&state.pool, q.tier.unwrap_or(1)).await;
    Ok(Json(json!({
        "tier": s.tier,
        "config": s.config,
        "status": s.status,
        "schedule": s.schedule,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SyncConfigInput {
    pub tier: Option<i16>,
    pub source_url: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn post_sync_config(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<SyncConfigInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tier = crate::settings::normalize_tier(input.tier.unwrap_or(1));
    let cfg = save_sync_config(&state.pool, tier, input.source_url, input.enabled)
        .await
        .map_err(AppError::bad_request)?;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "sync.config",
        Some("sync"),
        None,
        json!({"tier": tier, "source_set": !cfg.source_url.is_empty(), "enabled": cfg.enabled}),
    )
    .await;
    Ok(Json(json!({"ok": true, "tier": tier, "source_set": !cfg.source_url.is_empty(), "enabled": cfg.enabled})))
}

pub async fn run_sync_handler(
    State(state): State<AppState>,
    admin: AdminUser,
    Query(q): Query<TierQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let tier = crate::settings::normalize_tier(q.tier.unwrap_or(1));
    // 环境变量兜底地址只属于一级；二级必须在后台配好自己的上游
    let env_url = if tier == 1 {
        state.cfg.upstream_url.as_str()
    } else {
        ""
    };
    let result = run_sync(
        &state.pool,
        &state.http,
        SyncTrigger::Manual,
        Some(admin.0.id),
        env_url,
        None,
        tier,
        None,
    )
    .await;
    match result {
        Ok(r) => {
            write_audit(
                &state.pool,
                Some(admin.0.id),
                "sync.run",
                Some("sync"),
                r.batch_id.map(|id| id.to_string()).as_deref(),
                json!({"tier": tier, "outcome": r.outcome, "total": r.total_node_count}),
            )
            .await;
            Ok(Json(json!({
                "tier": tier,
                "outcome": r.outcome,
                "batch_id": r.batch_id,
                "upstream_node_count": r.upstream_node_count,
                "extra_node_count": r.extra_node_count,
                "total_node_count": r.total_node_count,
                "sources": r.sources,
                "skipped": r.skipped,
                "unrecognized_count": r.unrecognized_count,
            })))
        }
        Err(e) => Err(AppError::bad_request(e)),
    }
}

// ---------------------------------------------------------------------------
// 代理池
// ---------------------------------------------------------------------------

pub async fn list_socks(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (page, per_page) = page_of(&q);
    let total: (i64,) = sqlx::query_as("SELECT count(*) FROM socks_pool")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let rows: Vec<(i64, String, i32, String, Option<String>, Option<String>, Option<String>, Option<i32>, serde_json::Value, String, Option<i32>, Option<chrono::DateTime<chrono::Utc>>, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT id, host, port, protocol, country, region, provider, risk_score, tags, status, latency_ms, last_checked_at, created_at \
             FROM socks_pool ORDER BY id DESC LIMIT $1 OFFSET $2",
        )
        .bind(per_page)
        .bind((page - 1) * per_page)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.0, "host": r.1, "port": r.2, "protocol": r.3,
            "country": r.4, "region": r.5, "provider": r.6, "risk_score": r.7,
            "tags": r.8, "status": r.9, "latency_ms": r.10,
            "last_checked_at": r.11, "created_at": r.12,
        })).collect::<Vec<_>>(),
        "total": total.0, "page": page, "per_page": per_page,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ImportSocksInput {
    pub text: String,
}

pub async fn import_socks(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<ImportSocksInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    if input.text.len() > 1024 * 1024 {
        return Err(AppError::bad_request("导入文本超过 1MB"));
    }
    let mut inserted = 0i64;
    let mut skipped = 0i64;
    let mut invalid = 0i64;
    let mut errors: Vec<String> = Vec::new();
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for line in input.text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(e) = parse_socks_line(line) else {
            invalid += 1;
            if errors.len() < 20 {
                errors.push(redact_proxy_credentials(line));
            }
            continue;
        };
        if !is_eligible(&e) {
            skipped += 1;
            continue;
        }
        let identity = proxy_identity(&e);
        if !seen.insert(identity.clone()) {
            skipped += 1;
            continue;
        }
        let id_hash = sha256_hex(&identity);
        let res = sqlx::query(
            "INSERT INTO socks_pool (host, port, protocol, username, password, line, tags, country, region, provider, risk_score, identity_hash, status) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'untested') \
             ON CONFLICT (identity_hash) DO NOTHING",
        )
        .bind(&e.host)
        .bind(e.port as i32)
        .bind(&e.protocol)
        .bind(e.username.clone().unwrap_or_default())
        .bind(e.password.clone().unwrap_or_default())
        .bind(&e.line)
        .bind(serde_json::to_value(&e.tags).unwrap())
        .bind(&e.country)
        .bind(&e.region)
        .bind(&e.provider)
        .bind(e.risk_score)
        .bind(&id_hash)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
        if res.rows_affected() == 1 {
            inserted += 1;
        } else {
            skipped += 1;
        }
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "socks.import",
        Some("socks"),
        None,
        json!({"inserted": inserted, "skipped": skipped, "invalid": invalid}),
    )
    .await;
    Ok(Json(json!({"inserted": inserted, "skipped": skipped, "invalid": invalid, "errors": errors})))
}

#[derive(Debug, Deserialize)]
pub struct SocksTestInput {
    pub scope: Option<String>,
}

pub async fn test_socks(
    State(_state): State<AppState>,
    _admin: AdminUser,
    Json(_input): Json<SocksTestInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    // 已永久停用（2026-11-14 Wing 紧急要求：服务端禁止主动探测任何节点/代理地址，
    // 否则会被封机器）。代理池测活不再执行；状态只展示入库信息。
    Err(AppError::forbidden(
        "代理池测速已停用：服务端禁止主动探测节点地址",
    ))
}

pub async fn socks_test_state(
    State(_state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let runner = SOCKS_RUNNER
        .get()
        .cloned()
        .ok_or_else(|| AppError::internal("测活器未初始化"))?;
    let s = runner.state();
    Ok(Json(json!({
        "running": s.running, "scope": s.scope, "total": s.total,
        "done": s.done, "ok": s.ok, "fail": s.fail,
        "started_at": s.started_at, "finished_at": s.finished_at,
    })))
}

pub async fn delete_socks(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query("DELETE FROM socks_pool WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("代理不存在"));
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "socks.delete",
        Some("socks"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn clear_failed_socks(
    State(state): State<AppState>,
    admin: AdminUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query("DELETE FROM socks_pool WHERE status = 'fail'")
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .rows_affected();
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "socks.clear_failed",
        Some("socks"),
        None,
        json!({"deleted": n}),
    )
    .await;
    Ok(Json(json!({"ok": true, "deleted": n})))
}

// ---------------------------------------------------------------------------
// 用户
// ---------------------------------------------------------------------------

pub async fn list_users(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (page, per_page) = page_of(&q);
    let keyword = q.q.as_deref().unwrap_or("").trim().to_string();
    let (total, rows): (i64, Vec<(i64, String, Option<String>, Option<String>, i32, String, bool, Option<String>, chrono::DateTime<chrono::Utc>, Option<chrono::DateTime<chrono::Utc>>)>) =
        if keyword.is_empty() {
            let total: (i64,) = sqlx::query_as("SELECT count(*) FROM users")
                .fetch_one(&state.pool)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
            let rows = sqlx::query_as(
                "SELECT id, username, display_name, avatar_url, trust_level, role, is_banned, ban_reason, created_at, last_login_at \
                 FROM users ORDER BY id LIMIT $1 OFFSET $2",
            )
            .bind(per_page)
            .bind((page - 1) * per_page)
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            (total.0, rows)
        } else {
            let pattern = format!("%{keyword}%");
            let total: (i64,) = sqlx::query_as(
                "SELECT count(*) FROM users WHERE username ILIKE $1 OR display_name ILIKE $1",
            )
            .bind(&pattern)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            let rows = sqlx::query_as(
                "SELECT id, username, display_name, avatar_url, trust_level, role, is_banned, ban_reason, created_at, last_login_at \
                 FROM users WHERE username ILIKE $1 OR display_name ILIKE $1 ORDER BY id LIMIT $2 OFFSET $3",
            )
            .bind(&pattern)
            .bind(per_page)
            .bind((page - 1) * per_page)
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
            (total.0, rows)
        };
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.0, "username": r.1, "display_name": r.2, "avatar_url": r.3,
            "trust_level": r.4, "role": r.5, "is_banned": r.6, "ban_reason": r.7,
            "created_at": r.8, "last_login_at": r.9,
        })).collect::<Vec<_>>(),
        "total": total, "page": page, "per_page": per_page,
    })))
}

#[derive(Debug, Deserialize)]
pub struct BanInput {
    pub reason: Option<String>,
}

pub async fn ban_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
    Json(input): Json<BanInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let reason = input.reason.unwrap_or_default();
    let n = sqlx::query(
        "UPDATE users SET is_banned = TRUE, ban_reason = NULLIF($2, ''), updated_at = now() WHERE id = $1 AND role != 'root'",
    )
    .bind(id)
    .bind(&reason)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .rows_affected();
    if n == 0 {
        return Err(AppError::bad_request("用户不存在或不能封禁站长"));
    }
    // 封禁后立即踢掉该用户全部会话
    let _ = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(id)
        .execute(&state.pool)
        .await;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "user.ban",
        Some("user"),
        Some(&id.to_string()),
        json!({"reason": reason}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn unban_user(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query(
        "UPDATE users SET is_banned = FALSE, ban_reason = NULL, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("用户不存在"));
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "user.unban",
        Some("user"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn promote_user(
    State(state): State<AppState>,
    root: RootUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query(
        "UPDATE users SET role = 'admin', updated_at = now() WHERE id = $1 AND role = 'user'",
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .rows_affected();
    if n == 0 {
        return Err(AppError::bad_request("用户不存在或角色不是 user"));
    }
    write_audit(
        &state.pool,
        Some(root.0.id),
        "user.promote",
        Some("user"),
        Some(&id.to_string()),
        json!({"role": "admin"}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn demote_user(
    State(state): State<AppState>,
    root: RootUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query(
        "UPDATE users SET role = 'user', updated_at = now() WHERE id = $1 AND role = 'admin'",
    )
    .bind(id)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?
    .rows_affected();
    if n == 0 {
        return Err(AppError::bad_request("用户不存在或角色不是 admin"));
    }
    write_audit(
        &state.pool,
        Some(root.0.id),
        "user.demote",
        Some("user"),
        Some(&id.to_string()),
        json!({"role": "user"}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 公告
// ---------------------------------------------------------------------------

pub async fn list_announcements(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let rows: Vec<(i64, String, String, bool, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, content, level, is_active, created_at FROM announcements ORDER BY created_at DESC LIMIT 100",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.0, "content": r.1, "level": r.2, "is_active": r.3, "created_at": r.4,
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateAnnouncementInput {
    pub content: String,
    pub level: Option<String>,
}

pub async fn create_announcement(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<CreateAnnouncementInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    let content = input.content.trim().to_string();
    if content.is_empty() || content.chars().count() > 1000 {
        return Err(AppError::bad_request("公告内容不能为空且不超过 1000 字"));
    }
    let level = match input.level.as_deref() {
        Some("warning") | Some("alert") | Some("info") => input.level.clone().unwrap(),
        _ => "info".to_string(),
    };
    let row: (i64,) = sqlx::query_as(
        "INSERT INTO announcements (content, level, is_active, created_by) VALUES ($1, $2, TRUE, $3) RETURNING id",
    )
    .bind(&content)
    .bind(&level)
    .bind(admin.0.id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "announcement.create",
        Some("announcement"),
        Some(&row.0.to_string()),
        json!({"level": level}),
    )
    .await;
    Ok(Json(json!({"id": row.0})))
}

pub async fn toggle_announcement(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let row: Option<(bool,)> = sqlx::query_as(
        "UPDATE announcements SET is_active = NOT is_active WHERE id = $1 RETURNING is_active",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let Some((active,)) = row else {
        return Err(AppError::not_found("公告不存在"));
    };
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "announcement.toggle",
        Some("announcement"),
        Some(&id.to_string()),
        json!({"is_active": active}),
    )
    .await;
    Ok(Json(json!({"ok": true, "is_active": active})))
}

pub async fn delete_announcement(
    State(state): State<AppState>,
    admin: AdminUser,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let n = sqlx::query("DELETE FROM announcements WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?
        .rows_affected();
    if n == 0 {
        return Err(AppError::not_found("公告不存在"));
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "announcement.delete",
        Some("announcement"),
        Some(&id.to_string()),
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 设置
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SettingsOut {
    pub trust_level_min: i32,
    pub routing_mode: String,
    pub admin_usernames: Vec<String>,
}

pub async fn get_settings(
    State(state): State<AppState>,
    _admin: AdminUser,
) -> Result<Json<SettingsOut>, AppError> {
    Ok(Json(SettingsOut {
        trust_level_min: trust_level_min(&state.pool, state.cfg.trust_level_min).await,
        routing_mode: routing_mode(&state.pool).await,
        admin_usernames: admin_usernames(&state.pool, &state.cfg.admin_usernames).await,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SettingsInput {
    pub trust_level_min: Option<i32>,
    pub routing_mode: Option<String>,
    pub admin_usernames: Option<Vec<String>>,
}

pub async fn post_settings(
    State(state): State<AppState>,
    admin: AdminUser,
    Json(input): Json<SettingsInput>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(tl) = input.trust_level_min {
        if !(0..=4).contains(&tl) {
            return Err(AppError::bad_request("信任等级范围 0–4"));
        }
        set_setting(&state.pool, KEY_TRUST_LEVEL_MIN, &json!(tl))
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    if let Some(mode) = input.routing_mode {
        if mode != "rules" && mode != "global" {
            return Err(AppError::bad_request("路由模式只能是 rules/global"));
        }
        set_setting(&state.pool, KEY_ROUTING_MODE, &json!(mode))
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    if let Some(names) = input.admin_usernames {
        let cleaned: Vec<String> = names
            .iter()
            .map(|n| n.trim().to_string())
            .filter(|n| !n.is_empty())
            .collect();
        set_setting(&state.pool, KEY_ADMIN_USERNAMES, &json!(cleaned))
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    }
    write_audit(
        &state.pool,
        Some(admin.0.id),
        "settings.update",
        Some("settings"),
        None,
        json!({}),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

// ---------------------------------------------------------------------------
// 审计日志
// ---------------------------------------------------------------------------

pub async fn list_audit(
    State(state): State<AppState>,
    _admin: AdminUser,
    Query(q): Query<PageQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = q.offset.unwrap_or(0).max(0);
    let rows: Vec<(i64, Option<i64>, Option<String>, String, Option<String>, Option<String>, serde_json::Value, chrono::DateTime<chrono::Utc>)> =
        sqlx::query_as(
            "SELECT a.id, a.actor_user_id, u.username, a.action, a.target_type, a.target, a.detail, a.created_at \
             FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id \
             ORDER BY a.id DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "items": rows.iter().map(|r| json!({
            "id": r.0, "actor_user_id": r.1, "actor_username": r.2,
            "action": r.3, "target_type": r.4, "target": r.5,
            "detail": r.6, "created_at": r.7,
        })).collect::<Vec<_>>(),
        "limit": limit, "offset": offset,
    })))
}
