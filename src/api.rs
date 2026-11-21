//! 公开 API 与路由组装。
//! POST /api/* 要求 x-pmnodes-csrf: 1（与 PM-Plan 的 x-pmplan-csrf: 1 同一约定）。

use crate::admin::*;
use crate::auth::{oauth_callback, oauth_login, oauth_logout, AuthUser};
use crate::error::AppError;
use crate::models::{NodeBatch, NodeTier};
use crate::nodes::{endpoint_key, openvpn_proto, parse_node_endpoint};
use crate::probe_results::probe_results;
use crate::state::AppState;
use crate::subs::subscription;
use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tower_http::services::ServeDir;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

pub async fn health() -> Json<serde_json::Value> {
    Json(json!({"name": "PM-Node-Station", "ok": true}))
}

async fn csrf_guard(req: Request<axum::body::Body>, next: Next) -> Result<Response, AppError> {
    if req.method() == Method::POST {
        let ok = req
            .headers()
            .get("x-pmnodes-csrf")
            .and_then(|v| v.to_str().ok())
            == Some("1");
        if !ok {
            return Err(AppError::forbidden("缺少 CSRF 请求头"));
        }
    }
    Ok(next.run(req).await)
}

/// 公开接口用的节点展示名：名字里带 IPv4 地址的改用通用名，避免未登录用户从
/// /api/public/status 批量拿到节点 IP（未改名的代理池节点原名本身就是 IP:port）。
/// `seq` 是本分级内已替换名的计数（调用方维护），保证替换名唯一且在批次顺序
/// 不变时稳定。登录后的 /api/nodes 不受影响，仍显示原名。
fn public_node_name(name: &str, tier: i16, seq: &mut usize) -> String {
    if name_contains_ipv4(name) {
        *seq += 1;
        let label = match tier {
            1 => "一级",
            2 => "二级",
            3 => "三级",
            _ => "",
        };
        format!("{label}节点{seq}")
    } else {
        name.to_string()
    }
}

/// 名字里是否包含一个 IPv4 地址（形如 a.b.c.d，每段 0-255）。
fn name_contains_ipv4(name: &str) -> bool {
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() && parse_ipv4_at(bytes, i).is_some() {
            return true;
        }
        i += 1;
    }
    false
}

/// 从 `start` 处尝试解析一个 IPv4 地址，成功返回地址结尾的下标。
fn parse_ipv4_at(bytes: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    for group in 0..4 {
        let gs = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == gs {
            return None;
        }
        let octet: u32 = std::str::from_utf8(&bytes[gs..pos]).ok()?.parse().ok()?;
        if octet > 255 {
            return None;
        }
        if group < 3 {
            if pos < bytes.len() && bytes[pos] == b'.' {
                pos += 1;
            } else {
                return None;
            }
        }
    }
    Some(pos)
}

pub async fn public_status(State(state): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    let announcements: Vec<(i64, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, content, level, created_at FROM announcements WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 5",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    let tiers: Vec<NodeTier> = sqlx::query_as("SELECT * FROM node_tiers ORDER BY sort_order ASC, tier ASC")
        .fetch_all(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let active_batches: Vec<NodeBatch> = sqlx::query_as(
        "SELECT * FROM node_batches WHERE is_active = TRUE ORDER BY tier ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (batches,): (i64,) = sqlx::query_as("SELECT count(*) FROM node_batches")
        .fetch_one(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let (pulls_today,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM sub_pulls WHERE pulled_at >= date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    let mut tiers_json = Vec::new();
    let mut total_nodes = 0i64;
    let mut legacy_batch: Option<serde_json::Value> = None;
    let mut legacy_nodes: Vec<serde_json::Value> = Vec::new();
    // 三级 VPNGate：CSV 自带的 Ping/Speed（只展示，不探测）
    let vpngate_meta: std::collections::HashMap<String, (i32, i64)> = {
        let t3 = active_batches.iter().find(|b| b.tier == 3);
        match t3 {
            Some(batch) => {
                let rows: Vec<(String, i32, i64)> = sqlx::query_as(
                    "SELECT node_name, ping_ms, speed_bps FROM vpngate_configs WHERE batch_id = $1",
                )
                .bind(batch.id)
                .fetch_all(&state.pool)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
                rows.into_iter().map(|(n, p, s)| (n, (p, s))).collect()
            }
            None => std::collections::HashMap::new(),
        }
    };
    for t in &tiers {
        let batch = active_batches.iter().find(|b| b.tier == t.tier);
        let mut nodes: Vec<serde_json::Value> = Vec::new();
        // 本分级内已替换名的计数（仅公开接口用，见 public_node_name）。
        let mut sanitized_seq = 0usize;
        if let Some(batch) = batch {
            let uris = batch.node_uris();
            // 服务端延迟/状态已停用（2026-11-14 Wing 要求：禁止从服务器 IP 探测节点）：
            // 只返回上游同步来的节点信息（名称/协议/地区），延迟一律 null，不展示服务端测出的状态。
            for uri in &uris {
                let name = crate::nodes::read_node_name(uri);
                // 公开接口不泄露节点 IP：带 IPv4 的名字改用通用名；vpngate 元数据仍用原名查。
                let display_name = public_node_name(&name, t.tier, &mut sanitized_seq);
                let mut node = json!({
                    "name": display_name,
                    "protocol": crate::nodes::protocol_of(uri),
                    "region": crate::nodes::region_of(uri),
                    "latency_ms": serde_json::Value::Null,
                    "online": serde_json::Value::Null,
                    "checked": false,
                    "checked_at": serde_json::Value::Null,
                });
                // 三级：VPNGate 自测 Ping/Speed（CSV 列，绝不从机器探测）
                if t.tier == 3 {
                    node["vpngate"] = vpngate_meta
                        .get(&name)
                        .map(|(ping_ms, speed_bps)| json!({"ping_ms": ping_ms, "speed_bps": speed_bps}))
                        .unwrap_or(serde_json::Value::Null);
                }
                nodes.push(node);
            }
            total_nodes += batch.node_count as i64;
            if t.tier == 1 {
                legacy_batch = Some(json!({
                    "id": batch.id, "title": batch.title, "batch_date": batch.batch_date,
                    "node_count": batch.node_count, "created_at": batch.created_at,
                }));
                legacy_nodes = nodes.clone();
            }
        }
        tiers_json.push(json!({
            "tier": t.tier,
            "name": t.name,
            "description": t.description,
            "ip_type": t.ip_type,
            "rate_limited": t.rate_limited,
            "anti_redistribution": t.anti_redistribution,
            "daily_limit_gb": t.daily_limit_gb,
            "monthly_limit_gb": t.monthly_limit_gb,
            "tags": t.tag_lines(),
            "batch": batch.map(|b| json!({
                "id": b.id, "title": b.title, "batch_date": b.batch_date,
                "node_count": b.node_count, "created_at": b.created_at,
            })),
            "nodes": nodes,
        }));
    }

    Ok(Json(json!({
        "announcements": announcements.iter().map(|a| json!({
            "id": a.0, "content": a.1, "level": a.2, "created_at": a.3,
        })).collect::<Vec<_>>(),
        "active_batch": legacy_batch,
        "stats": {
            "users": users,
            "nodes": total_nodes,
            "batches": batches,
            "pulls_today": pulls_today,
        },
        "nodes": legacy_nodes,
        "tiers": tiers_json,
    })))
}

pub async fn me(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let (pulls_today,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM sub_pulls WHERE user_id = $1 AND pulled_at >= date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai'",
    )
    .bind(user.id)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "user": {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "trust_level": user.trust_level,
            "role": user.role,
            "is_banned": user.is_banned,
        },
        "sub_url": format!("{}/{}", state.cfg.app_url.trim_end_matches('/'), user.sub_token),
        "pulls_today": pulls_today,
    })))
}

pub async fn reset_token(
    State(state): State<AppState>,
    AuthUser(user): AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    // 轮换订阅 token：旧链接立即失效
    let new_token = Uuid::new_v4();
    sqlx::query("UPDATE users SET sub_token = $2, updated_at = now() WHERE id = $1")
        .bind(user.id)
        .bind(new_token.to_string())
        .execute(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(Json(json!({
        "sub_token": new_token.to_string(),
        "sub_url": format!("{}/{}", state.cfg.app_url.trim_end_matches('/'), new_token),
    })))
}

#[derive(Debug, Deserialize)]
pub struct OvpnQuery {
    pub batch: i64,
    pub node: String,
}

/// 三级 VPNGate 节点的 .ovpn 配置下载（需登录：配置里含节点 remote IP，未登录不可下载）。
/// 配置来自同步时存入 vpngate_configs 的 OpenVPN_ConfigData_Base64。
pub async fn download_ovpn(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
    Query(q): Query<OvpnQuery>,
) -> Result<Response, AppError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT config_b64 FROM vpngate_configs WHERE batch_id = $1 AND node_name = $2",
    )
    .bind(q.batch)
    .bind(&q.node)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let Some((config_b64,)) = row else {
        return Err(AppError::not_found("该节点的 OpenVPN 配置不存在"));
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let config = STANDARD
        .decode(config_b64.trim())
        .map_err(|_| AppError::internal("OpenVPN 配置损坏".to_string()))?;
    let filename = format!("{}.ovpn", q.node);
    let encoded = percent_encode_filename(&filename);
    let mut resp = Response::new(axum::body::Body::from(config));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/x-openvpn-profile"),
    );
    resp.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        header::HeaderValue::from_str(&format!("attachment; filename*=UTF-8''{encoded}"))
            .map_err(|_| AppError::internal("文件名编码失败".to_string()))?,
    );
    Ok(resp)
}

fn percent_encode_filename(name: &str) -> String {
    let mut out = String::new();
    for b in name.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "-._".contains(c) {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 节点列表页数据（需登录）：全部节点按三级分组。
/// 每行：名称/级别/地区/协议 + 可用性（外部探测器写回 node_availability 的结果，
/// 非本站服务器实测）+ 同步见证（node_presence：同步中可见 / 已下线）+
/// IP 纯净度（ip_purity：teleapi 缓存）。只返回 host/port/endpoint，
/// 不返回含认证信息的完整订阅 URI。
pub async fn list_nodes(
    State(state): State<AppState>,
    AuthUser(_user): AuthUser,
) -> Result<Json<serde_json::Value>, AppError> {
    let tiers: Vec<NodeTier> =
        sqlx::query_as("SELECT * FROM node_tiers ORDER BY sort_order ASC, tier ASC")
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let active_batches: Vec<NodeBatch> =
        sqlx::query_as("SELECT * FROM node_batches WHERE is_active = TRUE ORDER BY tier ASC")
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;

    // 可用性（外部探测器写回）、端点→IP、纯净度缓存、同步见证：各一次拉出
    let avail_rows: Vec<(String, bool, Option<i32>, DateTime<Utc>)> = sqlx::query_as(
        "SELECT endpoint, online, latency_ms, checked_at FROM node_availability",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let avail_map: HashMap<String, (bool, Option<i32>, DateTime<Utc>)> =
        avail_rows.into_iter().map(|(e, o, l, c)| (e, (o, l, c))).collect();
    let ip_rows: Vec<(String, String)> =
        sqlx::query_as("SELECT endpoint, ip FROM node_ip")
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let ip_map: HashMap<String, String> = ip_rows.into_iter().collect();
    let purity_rows: Vec<(String, i32, String, Option<String>, Option<String>, DateTime<Utc>)> =
        sqlx::query_as(
            "SELECT ip, coefficient, band, ip_type, verdict, checked_at FROM ip_purity",
        )
        .fetch_all(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
    let purity_map: HashMap<String, (i32, String, Option<String>, Option<String>, DateTime<Utc>)> =
        purity_rows
            .into_iter()
            .map(|(ip, c, b, t, v, at)| (ip, (c, b, t, v, at)))
            .collect();
    let presence_rows: Vec<(String, i16, DateTime<Utc>, Option<i64>, i32)> = sqlx::query_as(
        "SELECT node_uri, tier, last_seen_at, last_seen_batch_id, misses FROM node_presence",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;
    let presence_map: HashMap<String, (i16, DateTime<Utc>, Option<i64>, i32)> = presence_rows
        .iter()
        .map(|(u, t, l, b, m)| (u.clone(), (*t, *l, *b, *m)))
        .collect();

    // 三级 VPNGate：CSV 自带的 Ping/Speed（只展示，不探测）
    let vpngate_map: HashMap<String, (i32, i64)> = {
        let t3 = active_batches.iter().find(|b| b.tier == 3);
        match t3 {
            Some(batch) => {
                let rows: Vec<(String, i32, i64)> = sqlx::query_as(
                    "SELECT node_name, ping_ms, speed_bps FROM vpngate_configs WHERE batch_id = $1",
                )
                .bind(batch.id)
                .fetch_all(&state.pool)
                .await
                .map_err(|e| AppError::internal(e.to_string()))?;
                rows.into_iter().map(|(n, p, s)| (n, (p, s))).collect()
            }
            None => HashMap::new(),
        }
    };

    // 单个节点行：URI → 展示字段（不含认证信息）
    let item = |uri: &str, tier: i16, batch_id: Option<i64>| -> serde_json::Value {
        let name = crate::nodes::read_node_name(uri);
        let region = crate::nodes::region_of(uri);
        let protocol = crate::nodes::protocol_of(uri);
        let (host, port, endpoint) = match parse_node_endpoint(uri) {
            Some(ep) => (ep.host.clone(), ep.port, endpoint_key(&ep)),
            None => (String::new(), 0, String::new()),
        };
        let presence = presence_map.get(uri).map(|(_, last_seen, _, misses)| {
            json!({
                "status": if *misses == 0 { "visible" } else { "offline" },
                "last_seen_at": last_seen,
                "misses": misses,
            })
        });
        let availability = if endpoint.is_empty() {
            serde_json::Value::Null
        } else {
            match avail_map.get(&endpoint) {
                Some((online, latency_ms, checked_at)) => json!({
                    "online": online,
                    "latency_ms": latency_ms,
                    "checked_at": checked_at,
                }),
                None => serde_json::Value::Null,
            }
        };
        let purity = if endpoint.is_empty() {
            serde_json::Value::Null
        } else {
            match ip_map.get(&endpoint).and_then(|ip| purity_map.get(ip)) {
                Some((coefficient, band, ip_type, verdict, checked_at)) => json!({
                    "coefficient": coefficient,
                    "band": band,
                    "type": ip_type,
                    "verdict": verdict,
                    "checked_at": checked_at,
                }),
                None => serde_json::Value::Null,
            }
        };
        json!({
            "name": name,
            "tier": tier,
            "region": region,
            "protocol": protocol,
            "host": host,
            "port": port,
            "endpoint": endpoint,
            "proto": openvpn_proto(uri),
            "presence": presence,
            "availability": availability,
            "purity": purity,
            // 三级：VPNGate 自测 Ping/Speed（CSV 列，绝不从机器探测）
            "vpngate": vpngate_map
                .get(&name)
                .map(|(ping_ms, speed_bps)| json!({"ping_ms": ping_ms, "speed_bps": speed_bps}))
                .unwrap_or(serde_json::Value::Null),
            // 三级 OpenVPN 节点：生效批次的 .ovpn 下载用 batch id（已下线节点无配置）
            "ovpn_batch": if protocol == "openvpn" { batch_id } else { None::<i64> },
        })
    };

    let cutoff = Utc::now() - chrono::Duration::days(30);
    let mut tiers_json = Vec::new();
    for t in &tiers {
        let batch = active_batches.iter().find(|b| b.tier == t.tier);
        let mut nodes: Vec<serde_json::Value> = Vec::new();
        let mut visible_uris: HashSet<String> = HashSet::new();
        if let Some(batch) = batch {
            for uri in batch.node_uris() {
                visible_uris.insert(uri.clone());
                nodes.push(item(&uri, t.tier, Some(batch.id)));
            }
        }
        // 已下线：同级连续缺席同步、且 30 天内还见过的节点（再久的就不展示了）
        let mut offline: Vec<&(String, i16, DateTime<Utc>, Option<i64>, i32)> = presence_rows
            .iter()
            .filter(|(u, tier, last_seen, _, misses)| {
                *tier == t.tier && *misses >= 1 && *last_seen >= cutoff && !visible_uris.contains(u)
            })
            .collect();
        offline.sort_by(|a, b| b.2.cmp(&a.2));
        let offline_count = offline.len();
        for (uri, _, _, _, _) in offline.iter().take(100) {
            nodes.push(item(uri, t.tier, None));
        }
        tiers_json.push(json!({
            "tier": t.tier,
            "name": t.name,
            "description": t.description,
            "ip_type": t.ip_type,
            "rate_limited": t.rate_limited,
            "anti_redistribution": t.anti_redistribution,
            "daily_limit_gb": t.daily_limit_gb,
            "monthly_limit_gb": t.monthly_limit_gb,
            "tags": t.tag_lines(),
            "batch": batch.map(|b| json!({
                "id": b.id, "title": b.title, "batch_date": b.batch_date,
                "node_count": b.node_count, "created_at": b.created_at,
            })),
            "nodes": nodes,
            "offline_count": offline_count,
        }));
    }

    Ok(Json(json!({
        "generated_at": Utc::now(),
        "tiers": tiers_json,
    })))
}

/// 外部探测器取节点清单（主 Agent 沙箱跑探测器用）：只返回测速端点，不含任何认证信息。
/// 鉴权：`Authorization: Bearer <PROBE_TOKEN>`（生产 .env 里配）；未配置 token 时整个接口 404。
/// 探测器对每个端点做 TCP 连接（3 秒超时），把结果用 SQL 写回 node_availability：
///   INSERT INTO node_availability (endpoint, online, latency_ms, checked_at, updated_at)
///   VALUES ('vless://1.2.3.4:443', TRUE, 87, now(), now())
///   ON CONFLICT (endpoint) DO UPDATE SET online = EXCLUDED.online,
///     latency_ms = EXCLUDED.latency_ms, checked_at = EXCLUDED.checked_at, updated_at = now();
/// 注意：openvpn 端点带 proto 字段；proto=udp 的无法用 TCP 连接判断，探测器应跳过（显示“未检测”）。
pub async fn probe_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let token = state.cfg.probe_token.clone().filter(|s| !s.is_empty());
    let Some(token) = token else {
        return Err(AppError::not_found("接口未启用"));
    };
    let authed = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {token}"))
        .unwrap_or(false);
    if !authed {
        return Err(AppError::unauthorized("探测 token 无效"));
    }
    let active_batches: Vec<NodeBatch> =
        sqlx::query_as("SELECT * FROM node_batches WHERE is_active = TRUE ORDER BY tier ASC")
            .fetch_all(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let mut seen: HashSet<String> = HashSet::new();
    let mut nodes: Vec<serde_json::Value> = Vec::new();
    for batch in &active_batches {
        for uri in batch.node_uris() {
            let Some(ep) = parse_node_endpoint(&uri) else {
                continue;
            };
            let key = endpoint_key(&ep);
            if !seen.insert(key.clone()) {
                continue;
            }
            nodes.push(json!({
                "endpoint": key,
                "scheme": ep.scheme,
                "host": ep.host,
                "port": ep.port,
                "proto": openvpn_proto(&uri),
                "name": crate::nodes::read_node_name(&uri),
                "tier": batch.tier,
            }));
        }
    }
    Ok(Json(json!({
        "generated_at": Utc::now(),
        "count": nodes.len(),
        "nodes": nodes,
    })))
}

pub fn build_router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/public/status", get(public_status))
        .route("/public/ovpn", get(download_ovpn))
        .route("/auth/login", get(oauth_login))
        .route("/auth/callback", get(oauth_callback))
        .route("/auth/logout", get(oauth_logout))
        .route("/me", get(me))
        .route("/me/reset-token", post(reset_token))
        .route("/nodes", get(list_nodes))
        .route("/probe/nodes", get(probe_nodes))
        .route("/probe/results", post(probe_results))
        .route("/admin/stats", get(admin_stats))
        .route("/admin/batches", get(list_batches).post(create_batch))
        .route(
            "/admin/batches/{id}/activate",
            post(activate_batch_handler),
        )
        .route(
            "/admin/batches/{id}/deactivate",
            post(deactivate_batch_handler),
        )
        .route("/admin/batches/{id}", delete(delete_batch))
        .route("/admin/batches/{id}/nodes", get(batch_nodes))
        .route("/admin/sync", get(get_sync))
        .route("/admin/sync/config", post(post_sync_config))
        .route("/admin/sync/run", post(run_sync_handler))
        .route("/admin/socks", get(list_socks))
        .route("/admin/socks/import", post(import_socks))
        .route("/admin/socks/test", post(test_socks))
        .route("/admin/socks/test/state", get(socks_test_state))
        .route("/admin/socks/{id}", delete(delete_socks))
        .route("/admin/socks/clear-failed", post(clear_failed_socks))
        .route("/admin/users", get(list_users))
        .route("/admin/users/{id}/ban", post(ban_user))
        .route("/admin/users/{id}/unban", post(unban_user))
        .route("/admin/users/{id}/promote", post(promote_user))
        .route("/admin/users/{id}/demote", post(demote_user))
        .route(
            "/admin/announcements",
            get(list_announcements).post(create_announcement),
        )
        .route(
            "/admin/announcements/{id}/toggle",
            post(toggle_announcement),
        )
        .route(
            "/admin/announcements/{id}",
            delete(delete_announcement),
        )
        .route("/admin/settings", get(get_settings).post(post_settings))
        .route("/admin/audit", get(list_audit))
        .layer(middleware::from_fn(csrf_guard));

    Router::new()
        // LINUX DO Connect 注册的回调地址（与 /api/auth/callback 同一个处理函数）
        .route("/oauth/linuxdo", get(oauth_callback))
        .route("/{token}", get(subscription))
        .nest("/api", api)
        .fallback_service(ServeDir::new(&state.cfg.web_dir).append_index_html_on_directories(true))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(60),
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_name_ip_port_sanitized() {
        let mut seq = 0;
        assert_eq!(public_node_name("203.0.113.47:6760", 1, &mut seq), "一级节点1");
        assert_eq!(seq, 1);
    }

    #[test]
    fn public_name_ip_with_prefix_sanitized() {
        let mut seq = 0;
        assert_eq!(public_node_name("DO-203.0.113.76:999", 1, &mut seq), "一级节点1");
        assert_eq!(public_node_name("AE-94.202.58.154:8080", 1, &mut seq), "一级节点2");
    }

    #[test]
    fn public_name_clean_unchanged() {
        let mut seq = 0;
        assert_eq!(public_node_name("🇺🇸一级美国节点1", 1, &mut seq), "🇺🇸一级美国节点1");
        assert_eq!(seq, 0);
        assert_eq!(public_node_name("AE-Fujairah-361626-wngn", 1, &mut seq), "AE-Fujairah-361626-wngn");
        assert_eq!(seq, 0);
        assert_eq!(public_node_name("(无备注)", 1, &mut seq), "(无备注)");
        assert_eq!(seq, 0);
    }

    #[test]
    fn public_name_numbering_deterministic() {
        let mut seq = 0;
        assert_eq!(public_node_name("1.2.3.4:8080", 1, &mut seq), "一级节点1");
        assert_eq!(public_node_name("5.6.7.8:9090", 1, &mut seq), "一级节点2");
        assert_eq!(public_node_name("🇯🇵一级日本节点1", 1, &mut seq), "🇯🇵一级日本节点1");
        assert_eq!(public_node_name("9.9.9.9:3128", 1, &mut seq), "一级节点3");
        let mut seq2 = 0;
        assert_eq!(public_node_name("10.0.0.1:80", 2, &mut seq2), "二级节点1");
        assert_eq!(public_node_name("10.0.0.2:80", 3, &mut seq2), "三级节点2");
    }

    #[test]
    fn name_contains_ipv4_cases() {
        assert!(name_contains_ipv4("203.0.113.47:6760"));
        assert!(name_contains_ipv4("DO-203.0.113.76:999"));
        assert!(name_contains_ipv4("prefix 192.168.0.1 suffix"));
        assert!(name_contains_ipv4("1.2.3.4.5"));
        assert!(!name_contains_ipv4("🇺🇸一级美国节点1"));
        assert!(!name_contains_ipv4("node v2.0"));
        assert!(!name_contains_ipv4("AE-Fujairah-361626-wngn"));
        assert!(!name_contains_ipv4("1.2.3"));
        assert!(name_contains_ipv4("999.1.1.1")); // contains "99.1.1.1" as a substring: sanitized (safe)
        assert!(!name_contains_ipv4("999.999.999.999"));
        assert!(!name_contains_ipv4("no ip here"));
    }
}
