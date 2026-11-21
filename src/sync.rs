//! 上游订阅同步（原创实现，功能模型参考 Arkadia）。
//! - 管理员在后台配置上游订阅地址（只存数据库，页面上不回显完整地址）
//! - 支持 Raw URI、Base64、Clash YAML 三种上游格式；三级另用 VPNGate CSV（OpenVPN 列表）；
//!   去重后建新批次并原子切换
//! - 每天在上海时区两个持久化随机时段自动同步（服务重启后时段不变），手动同步不占自动槽位
//! - PostgreSQL advisory lock 防止重复拉取；同步失败不影响当前激活批次

use crate::batches::activate_batch;
use crate::nodes::{
    dedupe_nodes, hash_nodes, parse_subscription_nodes, parse_vpngate_csv, read_node_name,
    rename_nodes,
};
use crate::settings::*;
use crate::socks_parse::{pick_daily_socks, proxy_uri, CheckedSocks, SocksEntry};
use crate::timeutil::*;
use crate::upstreams::{
    dedupe_by_endpoint, filter_supported, parse_format, parse_upstream_content,
    resolve_url_template, Tier1Upstream,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Transaction};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const ADVISORY_LOCK_ID: i64 = 0x504D_5359; // 同步锁 "PMSY"，与批次激活锁不同值
const FETCH_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub source_url: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            source_url: String::new(),
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    pub state: String, // never | success | unchanged | failed
    pub last_attempt_at: Option<String>,
    pub last_auto_attempt_at: Option<String>,
    pub last_success_at: Option<String>,
    pub last_batch_id: Option<i64>,
    pub upstream_node_count: i64,
    pub extra_node_count: i64,
    pub total_node_count: i64,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// 一级多上游时各源的贡献（标签 + 节点数 + 失败原因 + 跳过的类型统计）。
    /// 只含标签与数量，绝不含上游地址。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceContribution>,
    /// 本次同步跳过的不支持类型汇总（类型 → 个数）
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<(String, i64)>,
    /// 本次同步无法识别地区、保留原名的节点数
    #[serde(default)]
    pub unrecognized_count: i64,
}

/// 单个上游在一次同步里的贡献（只含标签与数量，绝不含上游地址）
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SourceContribution {
    pub label: String,
    pub nodes: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<(String, i64)>,
}

impl Default for SyncStatus {
    fn default() -> Self {
        Self {
            state: "never".into(),
            last_attempt_at: None,
            last_auto_attempt_at: None,
            last_success_at: None,
            last_batch_id: None,
            upstream_node_count: 0,
            extra_node_count: 0,
            total_node_count: 0,
            error: None,
            content_hash: None,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSyncSlot {
    pub id: usize,
    pub scheduled_at: String,
    pub status: String, // pending | claimed | skipped
    pub handled_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncSchedule {
    pub date: String,
    pub slots: Vec<AutoSyncSlot>,
}

/// 每天两个随机时段：07:00–10:00 与 14:00–23:00（上海时间）
pub const AUTO_SYNC_WINDOWS: [(i32, i32); 2] = [(7 * 60, 10 * 60), (14 * 60, 23 * 60)];
const MIN_INITIAL_DELAY_MINUTES: i32 = 15;

#[derive(Debug, Clone, Serialize)]
pub struct SyncAdminState {
    pub tier: i16,
    pub config: SyncConfigPublic,
    pub status: SyncStatus,
    pub schedule: Option<ScheduleSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncConfigPublic {
    pub source_set: bool,
    pub source_host: Option<String>,
    pub enabled: bool,
    /// 一级多上游表里启用的上游个数（0 = 未用多上游，走旧的单上游配置）
    pub multi_upstream_count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScheduleSummary {
    pub date: String,
    pub next_run_at: Option<String>,
    pub slots: Vec<AutoSyncSlot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SyncResult {
    pub outcome: String, // created | unchanged | busy | disabled | not_due
    pub batch_id: Option<i64>,
    pub upstream_node_count: i64,
    pub extra_node_count: i64,
    pub total_node_count: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sources: Vec<SourceContribution>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped: Vec<(String, i64)>,
    #[serde(default)]
    pub unrecognized_count: i64,
}

impl SyncResult {
    fn empty(outcome: &str) -> Self {
        Self {
            outcome: outcome.into(),
            batch_id: None,
            upstream_node_count: 0,
            extra_node_count: 0,
            total_node_count: 0,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: 0,
        }
    }
}

fn normalize_config(v: Option<serde_json::Value>) -> SyncConfig {
    let mut cfg = SyncConfig::default();
    if let Some(v) = v {
        if let Some(s) = v.get("source_url").and_then(|x| x.as_str()) {
            cfg.source_url = s.trim().to_string();
        }
        if let Some(b) = v.get("enabled").and_then(|x| x.as_bool()) {
            cfg.enabled = b;
        }
    }
    cfg
}

fn normalize_status(v: Option<serde_json::Value>) -> SyncStatus {
    let mut st = SyncStatus::default();
    if let Some(v) = v {
        if let Ok(parsed) = serde_json::from_value::<SyncStatus>(v) {
            st = parsed;
        }
    }
    st
}

fn normalize_schedule(v: Option<serde_json::Value>) -> Option<SyncSchedule> {
    v.and_then(|v| serde_json::from_value::<SyncSchedule>(v).ok())
        .filter(|s| is_valid_schedule(s))
}

pub fn is_valid_schedule(s: &SyncSchedule) -> bool {
    if s.slots.len() != AUTO_SYNC_WINDOWS.len() {
        return false;
    }
    s.slots.iter().enumerate().all(|(i, slot)| {
        slot.id == i
            && DateTime::parse_from_rfc3339(&slot.scheduled_at).is_ok()
            && ["pending", "claimed", "skipped"].contains(&slot.status.as_str())
            && slot
                .handled_at
                .as_ref()
                .map(|h| DateTime::parse_from_rfc3339(h).is_ok())
                .unwrap_or(true)
    })
}

pub async fn get_sync_admin_state(pool: &PgPool, tier: i16) -> SyncAdminState {
    let tier = normalize_tier(tier);
    let cfg = normalize_config(get_setting(pool, sync_config_key(tier)).await);
    let status = normalize_status(get_setting(pool, sync_status_key(tier)).await);
    let schedule = normalize_schedule(get_setting(pool, KEY_SYNC_SCHEDULE).await);
    let source_host = if cfg.source_url.is_empty() {
        None
    } else {
        url::Url::parse(&cfg.source_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
    };
    // 一级多上游：表里有启用的上游即算已配置（旧的单上游配置仍保留作兜底）
    let multi_upstream_count = if tier == 1 {
        load_tier1_upstreams(pool)
            .await
            .iter()
            .filter(|u| u.enabled)
            .count() as i64
    } else {
        0
    };
    SyncAdminState {
        tier,
        config: SyncConfigPublic {
            source_set: !cfg.source_url.is_empty() || multi_upstream_count > 0,
            source_host,
            enabled: cfg.enabled,
            multi_upstream_count,
        },
        status,
        schedule: schedule.map(|s| ScheduleSummary {
            next_run_at: next_pending_at(&s),
            date: s.date,
            slots: s.slots,
        }),
    }
}

/// 读 tier1_upstreams 全表（按 id 排序）；表不存在（迁移前）或格式未知时跳过对应行，
/// 返回空表则调用方退回旧的单上游逻辑。
pub async fn load_tier1_upstreams(pool: &PgPool) -> Vec<Tier1Upstream> {
    let rows: Vec<(i64, String, String, String, String, bool)> = match sqlx::query_as(
        "SELECT id, label, url_template, format, kind, enabled FROM tier1_upstreams ORDER BY id ASC",
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };
    rows.into_iter()
        .filter_map(|(id, label, url_template, format, kind, enabled)| {
            parse_format(&format).map(|f| Tier1Upstream {
                id,
                label,
                url_template,
                format: f,
                kind,
                enabled,
            })
        })
        .collect()
}

/// 回写单个一级上游的同步结果（只记节点数与脱敏后的失败原因，绝不记 URL）
async fn update_tier1_upstream_row(pool: &PgPool, id: i64, nodes: i64, error: Option<&str>) {
    let _ = sqlx::query(
        "UPDATE tier1_upstreams SET last_sync_at = now(), last_nodes = $2, last_error = $3, updated_at = now() WHERE id = $1",
    )
    .bind(id)
    .bind(nodes as i32)
    .bind(error)
    .execute(pool)
    .await;
}

pub async fn save_sync_config(
    pool: &PgPool,
    tier: i16,
    source_url: Option<String>,
    enabled: Option<bool>,
) -> Result<SyncConfig, String> {
    let tier = normalize_tier(tier);
    let mut cfg = normalize_config(get_setting(pool, sync_config_key(tier)).await);
    if let Some(u) = source_url {
        cfg.source_url = u.trim().to_string();
    }
    if let Some(e) = enabled {
        cfg.enabled = e;
    }
    if !cfg.source_url.is_empty() {
        validate_source_url_syntax(&cfg.source_url)?;
    }
    if cfg.enabled && cfg.source_url.is_empty() {
        return Err("未配置上游订阅地址".to_string());
    }
    set_setting(
        pool,
        sync_config_key(tier),
        &serde_json::to_value(&cfg).unwrap(),
    )
    .await
    .map_err(|e| e.to_string())?;
    Ok(cfg)
}

pub fn resolve_source_url(cfg: &SyncConfig, env_url: &str) -> Result<String, String> {
    let url = if !cfg.source_url.trim().is_empty() {
        cfg.source_url.trim().to_string()
    } else {
        env_url.trim().to_string()
    };
    if url.is_empty() {
        return Err("未配置上游订阅地址，请在后台填写或设置 UPSTREAM_SUBSCRIPTION_URL".into());
    }
    validate_source_url_syntax(&url)?;
    Ok(url)
}

fn validate_source_url_syntax(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|_| "订阅地址格式不正确".to_string())?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err("订阅地址仅支持 http/https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("订阅地址不能包含 URL 认证信息".to_string());
    }
    Ok(())
}

/// 生成当天两个随机时段；结果必须持久化，不能每次 tick 重新生成
pub fn build_daily_schedule(date: &str, now: DateTime<Utc>) -> SyncSchedule {
    let mut rng = rand::thread_rng();
    let current_minute = if shanghai_date_at(now).to_string() == date {
        Some(shanghai_minute_at(now))
    } else {
        None
    };
    let slots = AUTO_SYNC_WINDOWS
        .iter()
        .enumerate()
        .map(|(id, (start, end))| {
            if let Some(cm) = current_minute {
                if cm >= end - MIN_INITIAL_DELAY_MINUTES {
                    return AutoSyncSlot {
                        id,
                        scheduled_at: shanghai_minute_to_utc(
                            chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap(),
                            end - 1,
                        )
                        .to_rfc3339(),
                        status: "skipped".into(),
                        handled_at: Some(now.to_rfc3339()),
                    };
                }
            }
            let effective_start = match current_minute {
                Some(cm) if cm >= *start => cm + MIN_INITIAL_DELAY_MINUTES,
                _ => *start,
            };
            let span = (end - effective_start).max(1);
            let offset = rng.gen_range(0..span);
            AutoSyncSlot {
                id,
                scheduled_at: shanghai_minute_to_utc(
                    chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").unwrap(),
                    effective_start + offset,
                )
                .to_rfc3339(),
                status: "pending".into(),
                handled_at: None,
            }
        })
        .collect();
    SyncSchedule {
        date: date.to_string(),
        slots,
    }
}

pub fn ensure_daily_schedule(stored: Option<SyncSchedule>, now: DateTime<Utc>) -> SyncSchedule {
    let date = shanghai_date_at(now).to_string();
    if let Some(s) = stored {
        if s.date == date {
            return s;
        }
    }
    build_daily_schedule(&date, now)
}

/// 认领一个到期槽位；多个积压时只执行最新槽位，旧槽跳过
pub fn claim_due_slot(
    schedule: &SyncSchedule,
    now: DateTime<Utc>,
) -> (SyncSchedule, Option<AutoSyncSlot>) {
    let now_ms = now.timestamp_millis();
    let mut due: Vec<&AutoSyncSlot> = schedule
        .slots
        .iter()
        .filter(|s| {
            s.status == "pending"
                && DateTime::parse_from_rfc3339(&s.scheduled_at)
                    .map(|t| t.timestamp_millis() <= now_ms)
                    .unwrap_or(false)
        })
        .collect();
    due.sort_by_key(|s| {
        DateTime::parse_from_rfc3339(&s.scheduled_at)
            .map(|t| t.timestamp_millis())
            .unwrap_or(0)
    });
    if due.is_empty() {
        return (schedule.clone(), None);
    }
    let claimed_id = due.last().unwrap().id;
    let overdue: std::collections::HashSet<usize> = due.iter().map(|s| s.id).collect();
    let handled = now.to_rfc3339();
    let slots = schedule
        .slots
        .iter()
        .map(|s| {
            if !overdue.contains(&s.id) {
                return s.clone();
            }
            AutoSyncSlot {
                id: s.id,
                scheduled_at: s.scheduled_at.clone(),
                status: if s.id == claimed_id {
                    "claimed".into()
                } else {
                    "skipped".into()
                },
                handled_at: Some(handled.clone()),
            }
        })
        .collect::<Vec<_>>();
    let claimed = slots.iter().find(|s| s.id == claimed_id).cloned();
    (
        SyncSchedule {
            date: schedule.date.clone(),
            slots,
        },
        claimed,
    )
}

pub fn next_pending_at(schedule: &SyncSchedule) -> Option<String> {
    schedule
        .slots
        .iter()
        .filter(|s| s.status == "pending")
        .map(|s| s.scheduled_at.clone())
        .min()
}

pub fn selection_seed(schedule: &SyncSchedule, slot: &AutoSyncSlot) -> String {
    format!("{}:{}:{}", schedule.date, slot.id, slot.scheduled_at)
}

pub enum SyncTrigger {
    Manual,
    Automatic,
}

/// 获取、解析并发布一次上游订阅。
/// 网络拉取在事务外完成，事务内只做二次校验、建批次与切换，避免慢上游占满连接池。
pub async fn run_sync(
    pool: &PgPool,
    http: &reqwest::Client,
    trigger: SyncTrigger,
    actor_user_id: Option<i64>,
    env_upstream_url: &str,
    extra_nodes: Option<Vec<String>>,
    tier: i16,
    auto_seed: Option<String>,
) -> Result<SyncResult, String> {
    let tier = normalize_tier(tier);
    let now = Utc::now();
    let is_auto = matches!(trigger, SyncTrigger::Automatic);
    let mut selection_seed_opt: Option<String> = None;

    // 自动同步：先原子认领当天随机槽位（认领即消耗一次自动机会）。
    // 主循环一次认领、三级共用时传 auto_seed，避免后两级重复认领不到槽位。
    if is_auto {
        if let Some(seed) = auto_seed {
            selection_seed_opt = Some(seed);
        } else if let Ok(preparation) = prepare_automatic(pool, now).await {
            match preparation {
                AutoPrep::Ready { seed } => selection_seed_opt = Some(seed),
                AutoPrep::NotDue => {
                    return Ok(SyncResult::empty("not_due"))
                }
                AutoPrep::Busy => {
                    return Ok(SyncResult::empty("busy"))
                }
                AutoPrep::Disabled => {
                    return Ok(SyncResult::empty("disabled"))
                }
            }
        }
    }

    let result = run_sync_inner(
        pool,
        http,
        is_auto,
        actor_user_id,
        env_upstream_url,
        extra_nodes,
        tier,
        selection_seed_opt,
        now,
    )
    .await;
    match result {
        Ok(r) => Ok(r),
        Err(e) => {
            record_sync_failure(pool, tier, is_auto, now, &e).await;
            Err(e)
        }
    }
}

pub enum AutoPrep {
    Ready { seed: String },
    NotDue,
    Busy,
    Disabled,
}

/// 该分级有没有配置上游（自动同步是否应跑它）：一级看后台配置或环境变量兜底，
/// 二/三级只看后台配置。无配置 → 跳过该级，不报错、不写失败状态。
/// 二级是快照导入（无配置），自动循环永远跳过它，快照批次永不自动刷新。
pub async fn tier_sync_configured(pool: &PgPool, tier: i16, env_upstream_url: &str) -> bool {
    let tier = normalize_tier(tier);
    let state = get_sync_admin_state(pool, tier).await;
    if state.config.source_set {
        return true;
    }
    tier == 1 && !env_upstream_url.trim().is_empty()
}

/// 二级一次性快照导入（只手动跑，永不自动触发）：
/// 拉取一次给定的上游订阅，解析、按新格式改名、建批次并激活（source='snapshot'），
/// 更新同步见证（新批次节点 misses=0）。不写 subscription_sync_config_tier2，
/// 不参与自动同步；内容不变时重复导入返回 unchanged，不建新批次。
pub async fn import_tier2_snapshot(
    pool: &PgPool,
    http: &reqwest::Client,
    source_url: &str,
) -> Result<SyncResult, String> {
    let tier: i16 = 2;
    let now = Utc::now();
    let raw = fetch_subscription_text(http, source_url).await?;
    let upstream_nodes = parse_subscription_nodes(&raw);
    if upstream_nodes.is_empty() {
        return Err("上游内容中没有解析到可用节点".into());
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| e.to_string())?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if !acquired {
        tx.rollback().await.ok();
        return Ok(SyncResult {
            outcome: "busy".into(),
            batch_id: None,
            upstream_node_count: upstream_nodes.len() as i64,
            extra_node_count: 0,
            total_node_count: 0,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: 0,
        });
    }

    // 快照只含上游节点，不混入代理池福利节点
    let combined = dedupe_nodes(&upstream_nodes);
    let (nodes, unrecognized) = rename_nodes(&combined, tier);
    if !unrecognized.is_empty() {
        tracing::warn!(
            tier,
            unrecognized = unrecognized.len(),
            "snapshot rename: {} 个节点无法识别地区，保留原名",
            unrecognized.len()
        );
    }
    let hash = hash_nodes(&nodes);
    let active: Option<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, nodes FROM node_batches WHERE is_active = TRUE AND tier = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let active_hash = active.as_ref().map(|(_, n)| {
        hash_nodes(
            &n.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
    });

    let attempted_at = now.to_rfc3339();
    let mut status_base = normalize_status(get_setting_tx(&mut tx, sync_status_key(tier)).await);
    status_base.last_attempt_at = Some(attempted_at.clone());
    status_base.last_success_at = Some(attempted_at.clone());
    status_base.upstream_node_count = upstream_nodes.len() as i64;
    status_base.extra_node_count = 0;
    status_base.total_node_count = nodes.len() as i64;
    status_base.error = None;
    status_base.content_hash = Some(hash.clone());

    // 内容不变也是成功：更新见证，不建新批次
    if active_hash.as_deref() == Some(hash.as_str()) {
        status_base.state = "unchanged".into();
        status_base.last_batch_id = active
            .as_ref()
            .map(|(id, _)| *id)
            .or(status_base.last_batch_id);
        set_setting_tx(
            &mut tx,
            sync_status_key(tier),
            &serde_json::to_value(&status_base).unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
        if let Some((active_id, active_nodes)) = &active {
            let active_uris: Vec<String> = active_nodes
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            touch_presence(&mut tx, tier, &active_uris, *active_id, now)
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(SyncResult {
            outcome: "unchanged".into(),
            batch_id: active.map(|(id, _)| id),
            upstream_node_count: upstream_nodes.len() as i64,
            extra_node_count: 0,
            total_node_count: nodes.len() as i64,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: unrecognized.len() as i64,
        });
    }

    let batch_date = shanghai_date_at(now);
    let title = format!(
        "二级快照导入 {}",
        now.with_timezone(&SHANGHAI).format("%m-%d %H:%M")
    );
    let created: (i64,) = sqlx::query_as(
        "INSERT INTO node_batches (title, nodes, batch_date, node_count, is_active, source, created_by, tier) \
         VALUES ($1, $2, $3, $4, FALSE, 'snapshot', NULL, $5) RETURNING id",
    )
    .bind(&title)
    .bind(serde_json::to_value(&nodes).unwrap())
    .bind(batch_date)
    .bind(nodes.len() as i32)
    .bind(tier)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    activate_batch(&mut tx, created.0)
        .await
        .map_err(|e| e.to_string())?;
    touch_presence(&mut tx, tier, &nodes, created.0, now)
        .await
        .map_err(|e| e.to_string())?;
    status_base.state = "success".into();
    status_base.last_batch_id = Some(created.0);
    set_setting_tx(
        &mut tx,
        sync_status_key(tier),
        &serde_json::to_value(&status_base).unwrap(),
    )
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(SyncResult {
        outcome: "created".into(),
        batch_id: Some(created.0),
        upstream_node_count: upstream_nodes.len() as i64,
        extra_node_count: 0,
        total_node_count: nodes.len() as i64,
        sources: Vec::new(),
        skipped: Vec::new(),
        unrecognized_count: unrecognized.len() as i64,
    })
}

pub async fn prepare_automatic(pool: &PgPool, now: DateTime<Utc>) -> Result<AutoPrep, String> {
    let mut tx = pool.begin().await.map_err(|e| e.to_string())?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if !acquired {
        return Ok(AutoPrep::Busy);
    }
    // 任一分级启用即不算 Disabled；各分级在 run_sync_inner 里再单独判断。
    // 一级多上游表里有启用的上游也算启用（即使旧的单上游配置被关掉）。
    let cfg1 = normalize_config(get_setting_tx(&mut tx, KEY_SYNC_CONFIG).await);
    let cfg2 = normalize_config(get_setting_tx(&mut tx, KEY_SYNC_CONFIG_TIER2).await);
    let cfg3 = normalize_config(get_setting_tx(&mut tx, KEY_SYNC_CONFIG_TIER3).await);
    let multi1: i64 = sqlx::query_scalar("SELECT count(*) FROM tier1_upstreams WHERE enabled = TRUE")
        .fetch_one(&mut *tx)
        .await
        .unwrap_or(0);
    if !cfg1.enabled && !cfg2.enabled && !cfg3.enabled && multi1 == 0 {
        tx.rollback().await.ok();
        return Ok(AutoPrep::Disabled);
    }
    let stored = normalize_schedule(get_setting_tx(&mut tx, KEY_SYNC_SCHEDULE).await);
    let daily = ensure_daily_schedule(stored.clone(), now);
    let (new_schedule, claimed) = claim_due_slot(&daily, now);
    let schedule_changed = stored.as_ref().map(|s| serde_json::to_value(s).unwrap())
        != Some(serde_json::to_value(&new_schedule).unwrap());
    if schedule_changed {
        set_setting_tx(
            &mut tx,
            KEY_SYNC_SCHEDULE,
            &serde_json::to_value(&new_schedule).unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    match claimed {
        Some(slot) => Ok(AutoPrep::Ready {
            seed: selection_seed(&new_schedule, &slot),
        }),
        None => Ok(AutoPrep::NotDue),
    }
}

#[allow(clippy::too_many_arguments)]
/// 同步见证更新（列表页“同步中可见 / 已下线”的数据来源）：
/// 新批次里的节点记为“本次可见”（misses 清零），同级里本次没出现的旧节点 misses +1。
/// 在 run_sync_inner 的同一个事务里调用；手动重复同步（内容不变）也要更新见证。
async fn touch_presence(
    tx: &mut Transaction<'_, Postgres>,
    tier: i16,
    uris: &[String],
    batch_id: i64,
    now: DateTime<Utc>,
) -> Result<(), String> {
    for uri in uris {
        sqlx::query(
            "INSERT INTO node_presence (node_uri, tier, first_seen_at, last_seen_at, last_seen_batch_id, misses) \
             VALUES ($1, $2, $3, $3, $4, 0) \
             ON CONFLICT (node_uri) DO UPDATE SET tier = EXCLUDED.tier, \
             last_seen_at = EXCLUDED.last_seen_at, last_seen_batch_id = EXCLUDED.last_seen_batch_id, misses = 0",
        )
        .bind(uri)
        .bind(tier)
        .bind(now)
        .bind(batch_id)
        .execute(&mut **tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    sqlx::query(
        "UPDATE node_presence SET misses = misses + 1 \
         WHERE tier = $1 AND NOT (node_uri = ANY($2))",
    )
    .bind(tier)
    .bind(uris)
    .execute(&mut **tx)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// 一级多上游同步（tier == 1 且 tier1_upstreams 里有启用的上游时走这里）。
/// 流程：逐个拉取全部 enabled 上游（日期模板按当天上海日期现拼；单个源
/// HTTP / 解析 / 0 节点失败只记 error、回写该行 last_error，继续跑别的源）→
/// 全部合并后按 server+port+类型去重 → 混入当日代理池福利节点 → 按新格式
/// 改名 → 写进一个新的一级批次（旧批次保留在库里不删除）。
/// 只有全部上游都失败（或合并后 0 节点）才整体报错。
#[allow(clippy::too_many_arguments)]
async fn run_sync_tier1_multi(
    pool: &PgPool,
    http: &reqwest::Client,
    is_auto: bool,
    actor_user_id: Option<i64>,
    extra_nodes: Option<Vec<String>>,
    selection_seed: Option<String>,
    now: DateTime<Utc>,
    upstreams: Vec<Tier1Upstream>,
) -> Result<SyncResult, String> {
    let tier: i16 = 1;
    let today = shanghai_date_at(now);
    let mut contributions: Vec<SourceContribution> = Vec::new();
    let mut all_nodes: Vec<String> = Vec::new();
    // (openvpn URI, 改名前节点名, .ovpn 文本)
    let mut openvpn_parts: Vec<(String, String, String)> = Vec::new();
    let mut total_skipped_map: HashMap<String, i64> = HashMap::new();

    for u in &upstreams {
        let url = resolve_url_template(&u.url_template, today);
        let parsed = match fetch_subscription_text(http, &url).await {
            Ok(raw) => parse_upstream_content(&raw, u.format),
            Err(e) => {
                let err = safe_error_message(&e);
                update_tier1_upstream_row(pool, u.id, 0, Some(&err)).await;
                tracing::warn!(label = %u.label, error = %err, "tier1 upstream fetch failed, continuing with other upstreams");
                contributions.push(SourceContribution {
                    label: u.label.clone(),
                    nodes: 0,
                    error: Some(err),
                    skipped: vec![],
                });
                continue;
            }
        };
        // 支持的协议才并入；不支持的只计数（解析层已按源统计）
        let (kept, filter_skipped) = filter_supported(&parsed.nodes);
        let mut src_skipped: HashMap<String, i64> = HashMap::new();
        for (k, v) in parsed.skipped.iter() {
            *src_skipped.entry(k.clone()).or_insert(0) += *v as i64;
        }
        for (k, v) in filter_skipped.iter() {
            *src_skipped.entry(k.clone()).or_insert(0) += *v as i64;
        }
        let mut src_skipped_vec: Vec<(String, i64)> = src_skipped.into_iter().collect();
        src_skipped_vec.sort();
        for (k, v) in &src_skipped_vec {
            *total_skipped_map.entry(k.clone()).or_insert(0) += *v;
        }
        if parsed.nodes.is_empty() || kept.is_empty() {
            let err = if parsed.nodes.is_empty() {
                "解析到 0 个节点".to_string()
            } else {
                "解析到的节点全部为不支持的类型".to_string()
            };
            update_tier1_upstream_row(pool, u.id, 0, Some(&err)).await;
            tracing::warn!(label = %u.label, error = %err, "tier1 upstream parsed 0 usable nodes, continuing");
            contributions.push(SourceContribution {
                label: u.label.clone(),
                nodes: 0,
                error: Some(err),
                skipped: src_skipped_vec,
            });
            continue;
        }
        // .ovpn 配置按改名前节点名挂接（改名后重新映射入库）
        for (pre_name, text) in &parsed.openvpn {
            if let Some(uri) = kept.iter().find(|n| read_node_name(n) == *pre_name) {
                openvpn_parts.push((uri.clone(), pre_name.clone(), text.clone()));
            }
        }
        update_tier1_upstream_row(pool, u.id, kept.len() as i64, None).await;
        contributions.push(SourceContribution {
            label: u.label.clone(),
            nodes: kept.len() as i64,
            error: None,
            skipped: src_skipped_vec,
        });
        all_nodes.extend(kept);
    }

    let merged = dedupe_by_endpoint(&all_nodes);
    if merged.is_empty() {
        return Err("全部一级上游均未解析到可用节点".into());
    }
    let mut total_skipped: Vec<(String, i64)> = total_skipped_map.into_iter().collect();
    total_skipped.sort();

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| e.to_string())?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if !acquired {
        tx.rollback().await.ok();
        return Ok(SyncResult {
            outcome: "busy".into(),
            batch_id: None,
            upstream_node_count: merged.len() as i64,
            extra_node_count: 0,
            total_node_count: 0,
            sources: contributions,
            skipped: total_skipped,
            unrecognized_count: 0,
        });
    }

    // 一级混入当日代理池福利节点（与旧的单上游同步行为一致）
    let extra = dedupe_nodes(&match extra_nodes {
        Some(v) => v,
        None => select_daily_pool_proxy_uris(&mut tx, selection_seed.as_deref()).await?,
    });
    let combined = dedupe_by_endpoint(&{
        let mut v = merged.clone();
        v.extend(extra.clone());
        v
    });
    let (nodes, unrecognized) = rename_nodes(&combined, tier);
    if !unrecognized.is_empty() {
        tracing::warn!(
            tier,
            unrecognized = unrecognized.len(),
            "tier1 multi sync rename: {} 个节点无法识别地区，保留原名",
            unrecognized.len()
        );
    }
    // OpenVPN 配置按改名映射：改名前节点名 → 改名后节点名
    let renamed_names: HashMap<String, String> = combined
        .iter()
        .zip(nodes.iter())
        .map(|(old, new)| (read_node_name(old), read_node_name(new)))
        .collect();
    let combined_set: std::collections::HashSet<&str> =
        combined.iter().map(|s| s.as_str()).collect();
    let openvpn_renamed: Vec<(String, String)> = openvpn_parts
        .iter()
        .filter(|(uri, _, _)| combined_set.contains(uri.as_str()))
        .filter_map(|(_, pre_name, text)| {
            renamed_names
                .get(pre_name)
                .map(|n| (n.clone(), B64.encode(text.as_bytes())))
        })
        .collect();

    let hash = hash_nodes(&nodes);
    let active: Option<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, nodes FROM node_batches WHERE is_active = TRUE AND tier = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let active_hash = active.as_ref().map(|(_, n)| {
        hash_nodes(
            &n.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
    });
    let attempted_at = now.to_rfc3339();
    let mut status_base = normalize_status(get_setting_tx(&mut tx, sync_status_key(tier)).await);
    status_base.last_attempt_at = Some(attempted_at.clone());
    if is_auto {
        status_base.last_auto_attempt_at = Some(attempted_at.clone());
    }
    status_base.last_success_at = Some(attempted_at.clone());
    status_base.upstream_node_count = merged.len() as i64;
    status_base.extra_node_count = extra.len() as i64;
    status_base.total_node_count = nodes.len() as i64;
    status_base.error = None;
    status_base.content_hash = Some(hash.clone());
    status_base.sources = contributions.clone();
    status_base.skipped = total_skipped.clone();
    status_base.unrecognized_count = unrecognized.len() as i64;

    // 手动重复点击时避免制造完全相同的历史记录
    if !is_auto && active_hash.as_deref() == Some(hash.as_str()) {
        status_base.state = "unchanged".into();
        status_base.last_batch_id = active
            .as_ref()
            .map(|(id, _)| *id)
            .or(status_base.last_batch_id);
        set_setting_tx(
            &mut tx,
            sync_status_key(tier),
            &serde_json::to_value(&status_base).unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
        if let Some((active_id, active_nodes)) = &active {
            let active_uris: Vec<String> = active_nodes
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            touch_presence(&mut tx, tier, &active_uris, *active_id, now)
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(SyncResult {
            outcome: "unchanged".into(),
            batch_id: active.map(|(id, _)| id),
            upstream_node_count: merged.len() as i64,
            extra_node_count: extra.len() as i64,
            total_node_count: nodes.len() as i64,
            sources: contributions,
            skipped: total_skipped,
            unrecognized_count: unrecognized.len() as i64,
        });
    }

    let batch_date = shanghai_date_at(now);
    let title = format!(
        "一级订阅同步 {}",
        now.with_timezone(&SHANGHAI).format("%m-%d %H:%M")
    );
    let created: (i64,) = sqlx::query_as(
        "INSERT INTO node_batches (title, nodes, batch_date, node_count, is_active, source, created_by, tier) \
         VALUES ($1, $2, $3, $4, FALSE, 'sync', $5, $6) RETURNING id",
    )
    .bind(&title)
    .bind(serde_json::to_value(&nodes).unwrap())
    .bind(batch_date)
    .bind(nodes.len() as i32)
    .bind(actor_user_id)
    .bind(tier)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    activate_batch(&mut tx, created.0)
        .await
        .map_err(|e| e.to_string())?;
    touch_presence(&mut tx, tier, &nodes, created.0, now)
        .await
        .map_err(|e| e.to_string())?;
    status_base.state = "success".into();
    status_base.last_batch_id = Some(created.0);
    set_setting_tx(
        &mut tx,
        sync_status_key(tier),
        &serde_json::to_value(&status_base).unwrap(),
    )
    .await
    .map_err(|e| e.to_string())?;
    // 一级 OpenVPN 配置入库，并清理旧批次的配置（只保留当前生效批次的）
    for (node_name, cfg_b64) in &openvpn_renamed {
        sqlx::query(
            "INSERT INTO openvpn_configs (batch_id, node_name, config_b64) VALUES ($1, $2, $3) \
             ON CONFLICT (batch_id, node_name) DO UPDATE SET config_b64 = EXCLUDED.config_b64",
        )
        .bind(created.0)
        .bind(node_name)
        .bind(cfg_b64)
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    sqlx::query(
        "DELETE FROM openvpn_configs WHERE batch_id IN \
         (SELECT id FROM node_batches WHERE tier = 1 AND is_active = FALSE)",
    )
    .execute(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(SyncResult {
        outcome: "created".into(),
        batch_id: Some(created.0),
        upstream_node_count: merged.len() as i64,
        extra_node_count: extra.len() as i64,
        total_node_count: nodes.len() as i64,
        sources: contributions,
        skipped: total_skipped,
        unrecognized_count: unrecognized.len() as i64,
    })
}

async fn run_sync_inner(
    pool: &PgPool,
    http: &reqwest::Client,
    is_auto: bool,
    actor_user_id: Option<i64>,
    env_upstream_url: &str,
    extra_nodes: Option<Vec<String>>,
    tier: i16,
    selection_seed: Option<String>,
    now: DateTime<Utc>,
) -> Result<SyncResult, String> {
    // 一级多上游：tier1_upstreams 表里有启用的上游时走多上游合并流程；
    // 表为空（迁移前 / 未配置）时退回旧的单上游逻辑。
    if tier == 1 {
        let enabled: Vec<Tier1Upstream> = load_tier1_upstreams(pool)
            .await
            .into_iter()
            .filter(|u| u.enabled)
            .collect();
        if !enabled.is_empty() {
            return run_sync_tier1_multi(
                pool,
                http,
                is_auto,
                actor_user_id,
                extra_nodes,
                selection_seed,
                now,
                enabled,
            )
            .await;
        }
    }
    let initial_cfg = normalize_config(get_setting(pool, sync_config_key(tier)).await);
    let source_url = resolve_source_url(&initial_cfg, env_upstream_url)?;

    let raw = fetch_subscription_text(http, &source_url).await?;
    // 三级是 VPNGate CSV（OpenVPN 服务器列表），其余分级走通用订阅解析
    let (upstream_nodes, vpngate_configs, vpngate_metas) = if tier == 3 {
        parse_vpngate_csv(&raw)
    } else {
        (parse_subscription_nodes(&raw), Vec::new(), Vec::new())
    };
    if upstream_nodes.is_empty() {
        return Err("上游内容中没有解析到可用节点".into());
    }

    let mut tx: Transaction<'_, Postgres> = pool.begin().await.map_err(|e| e.to_string())?;
    let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_xact_lock($1)")
        .bind(ADVISORY_LOCK_ID)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    if !acquired {
        tx.rollback().await.ok();
        return Ok(SyncResult {
            outcome: "busy".into(),
            batch_id: None,
            upstream_node_count: upstream_nodes.len() as i64,
            extra_node_count: 0,
            total_node_count: 0,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: 0,
        });
    }

    let cfg = normalize_config(get_setting_tx(&mut tx, sync_config_key(tier)).await);
    if is_auto && !cfg.enabled {
        tx.rollback().await.ok();
        return Ok(SyncResult {
            outcome: "disabled".into(),
            batch_id: None,
            upstream_node_count: upstream_nodes.len() as i64,
            extra_node_count: 0,
            total_node_count: 0,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: 0,
        });
    }
    if resolve_source_url(&cfg, env_upstream_url)? != source_url {
        return Err("订阅配置已变化，请重新同步".into());
    }

    let previous_status = normalize_status(get_setting_tx(&mut tx, sync_status_key(tier)).await);
    // 三级只用 VPNGate 自身节点，不混入代理池福利节点（分级身份 = 上游本身）
    let extra = if tier == 3 {
        Vec::new()
    } else {
        dedupe_nodes(&match extra_nodes {
            Some(v) => v,
            None => select_daily_pool_proxy_uris(&mut tx, selection_seed.as_deref()).await?,
        })
    };
    let combined = dedupe_nodes(&{
        let mut v = upstream_nodes.clone();
        v.extend(extra.clone());
        v
    });
    // 同步拉取后按「[国旗][级别]xx国节点n」统一改名（同一国家按出现顺序编号）
    let (nodes, unrecognized) = rename_nodes(&combined, tier);
    if !unrecognized.is_empty() {
        tracing::warn!(
            tier,
            unrecognized = unrecognized.len(),
            "sync rename: {} 个节点无法识别地区，保留原名",
            unrecognized.len()
        );
    }
    // 三级：把 .ovpn 配置按改名后的节点名重新挂接（改名前后顺序一一对应），
    // Ping/Speed 同理（CSV 自带数字，只展示不探测）
    let vpngate_configs_renamed: Vec<(String, String, i32, i64)> = if tier == 3 {
        let renamed_names: std::collections::HashMap<String, String> = combined
            .iter()
            .zip(nodes.iter())
            .map(|(old, new)| (read_node_name(old), read_node_name(new)))
            .collect();
        let meta_by_old: std::collections::HashMap<&str, (i32, i64)> = vpngate_metas
            .iter()
            .map(|(n, p, s)| (n.as_str(), (*p, *s)))
            .collect();
        vpngate_configs
            .iter()
            .filter_map(|(old_name, cfg)| {
                let (ping_ms, speed_bps) = meta_by_old
                    .get(old_name.as_str())
                    .copied()
                    .unwrap_or((0, 0));
                renamed_names
                    .get(old_name)
                    .map(|n| (n.clone(), cfg.clone(), ping_ms, speed_bps))
            })
            .collect()
    } else {
        Vec::new()
    };
    let hash = hash_nodes(&nodes);
    let active: Option<(i64, serde_json::Value)> = sqlx::query_as(
        "SELECT id, nodes FROM node_batches WHERE is_active = TRUE AND tier = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(tier)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;
    let active_hash = active.as_ref().map(|(_, n)| {
        hash_nodes(
            &n.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
    });
    let attempted_at = now.to_rfc3339();
    let mut status_base = previous_status.clone();
    status_base.last_attempt_at = Some(attempted_at.clone());
    if is_auto {
        status_base.last_auto_attempt_at = Some(attempted_at.clone());
    }
    status_base.last_success_at = Some(attempted_at.clone());
    status_base.upstream_node_count = upstream_nodes.len() as i64;
    status_base.extra_node_count = extra.len() as i64;
    status_base.total_node_count = nodes.len() as i64;
    status_base.error = None;
    status_base.content_hash = Some(hash.clone());

    // 手动重复点击时避免制造完全相同的历史记录
    if !is_auto && active_hash.as_deref() == Some(hash.as_str()) {
        status_base.state = "unchanged".into();
        status_base.last_batch_id = active
            .as_ref()
            .map(|(id, _)| *id)
            .or(previous_status.last_batch_id);
        set_setting_tx(
            &mut tx,
            sync_status_key(tier),
            &serde_json::to_value(&status_base).unwrap(),
        )
        .await
        .map_err(|e| e.to_string())?;
        // 内容不变也是成功同步：更新见证（本次又见到了这些节点）
        if let Some((active_id, active_nodes)) = &active {
            let active_uris: Vec<String> = active_nodes
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            touch_presence(&mut tx, tier, &active_uris, *active_id, now)
                .await
                .map_err(|e| e.to_string())?;
        }
        tx.commit().await.map_err(|e| e.to_string())?;
        return Ok(SyncResult {
            outcome: "unchanged".into(),
            batch_id: active.map(|(id, _)| id),
            upstream_node_count: upstream_nodes.len() as i64,
            extra_node_count: extra.len() as i64,
            total_node_count: nodes.len() as i64,
            sources: Vec::new(),
            skipped: Vec::new(),
            unrecognized_count: unrecognized.len() as i64,
        });
    }

    let batch_date = shanghai_date_at(now);
    let tier_label = match tier {
        2 => "二级",
        3 => "三级",
        _ => "一级",
    };
    let title = format!(
        "{tier_label}订阅同步 {}",
        now.with_timezone(&SHANGHAI).format("%m-%d %H:%M")
    );
    let created: (i64,) = sqlx::query_as(
        "INSERT INTO node_batches (title, nodes, batch_date, node_count, is_active, source, created_by, tier) \
         VALUES ($1, $2, $3, $4, FALSE, 'sync', $5, $6) RETURNING id",
    )
    .bind(&title)
    .bind(serde_json::to_value(&nodes).unwrap())
    .bind(batch_date)
    .bind(nodes.len() as i32)
    .bind(actor_user_id)
    .bind(tier)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| e.to_string())?;

    activate_batch(&mut tx, created.0)
        .await
        .map_err(|e| e.to_string())?;
    // 同步见证：新批次节点记为“本次可见”，同级缺席节点 misses +1
    touch_presence(&mut tx, tier, &nodes, created.0, now)
        .await
        .map_err(|e| e.to_string())?;
    status_base.state = "success".into();
    status_base.last_batch_id = Some(created.0);
    set_setting_tx(
        &mut tx,
        sync_status_key(tier),
        &serde_json::to_value(&status_base).unwrap(),
    )
    .await
    .map_err(|e| e.to_string())?;
    // 三级：把 .ovpn 配置入库，并清理旧批次的配置（只保留当前生效批次的）
    if tier == 3 {
        for (node_name, cfg_b64, ping_ms, speed_bps) in &vpngate_configs_renamed {
            sqlx::query(
                "INSERT INTO vpngate_configs (batch_id, node_name, config_b64, ping_ms, speed_bps) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (batch_id, node_name) DO UPDATE SET config_b64 = EXCLUDED.config_b64, ping_ms = EXCLUDED.ping_ms, speed_bps = EXCLUDED.speed_bps",
            )
            .bind(created.0)
            .bind(node_name)
            .bind(cfg_b64)
            .bind(ping_ms)
            .bind(speed_bps)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
        }
        sqlx::query(
            "DELETE FROM vpngate_configs WHERE batch_id IN \
             (SELECT id FROM node_batches WHERE tier = 3 AND is_active = FALSE)",
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;

    Ok(SyncResult {
        outcome: "created".into(),
        batch_id: Some(created.0),
        upstream_node_count: upstream_nodes.len() as i64,
        extra_node_count: extra.len() as i64,
        total_node_count: nodes.len() as i64,
        sources: Vec::new(),
        skipped: Vec::new(),
        unrecognized_count: unrecognized.len() as i64,
    })
}

/// 从已测可用代理池生成当次 60 个福利 URI：30 个原生/家宽 + 30 个速度优选
async fn select_daily_pool_proxy_uris(
    tx: &mut Transaction<'_, Postgres>,
    selection_seed: Option<&str>,
) -> Result<Vec<String>, String> {
    let rows: Vec<(String, i32, String, String, String, Option<String>, Option<String>, Option<String>, Option<i32>, serde_json::Value, Option<i32>)> =
        sqlx::query_as(
            "SELECT host, port, protocol, username, password, country, region, provider, risk_score, tags, latency_ms \
             FROM socks_pool WHERE status = 'ok' ORDER BY latency_ms ASC NULLS LAST LIMIT 2000",
        )
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| e.to_string())?;
    let checked: Vec<CheckedSocks> = rows
        .into_iter()
        .map(
            |(
                host,
                port,
                protocol,
                username,
                password,
                country,
                region,
                provider,
                risk_score,
                tags,
                latency_ms,
            )| {
                let tag_list: Vec<String> = tags
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                CheckedSocks {
                    entry: SocksEntry {
                        host,
                        port: port as u16,
                        protocol,
                        username: if username.is_empty() {
                            None
                        } else {
                            Some(username)
                        },
                        password: if password.is_empty() {
                            None
                        } else {
                            Some(password)
                        },
                        line: String::new(),
                        tags: tag_list.clone(),
                        native_ip: tag_list.iter().any(|t| t == "原生IP"),
                        residential: tag_list.iter().any(|t| t == "家宽"),
                        country,
                        region,
                        provider,
                        risk_score,
                    },
                    latency_ms: latency_ms.unwrap_or(9999) as i64,
                }
            },
        )
        .collect();
    let selected = pick_daily_socks(&checked, 60, 30, selection_seed);
    Ok(selected
        .iter()
        .map(|c| {
            proxy_uri(
                &c.entry,
                Some(&crate::socks_parse::socks_node_name(&c.entry)),
            )
        })
        .collect())
}

async fn record_sync_failure(
    pool: &PgPool,
    tier: i16,
    is_auto: bool,
    now: DateTime<Utc>,
    error: &str,
) {
    let previous = normalize_status(get_setting(pool, sync_status_key(tier)).await);
    let mut st = previous;
    st.state = "failed".into();
    let attempted = now.to_rfc3339();
    st.last_attempt_at = Some(attempted.clone());
    if is_auto {
        st.last_auto_attempt_at = Some(attempted);
    }
    st.error = Some(safe_error_message(error));
    if let Err(e) = set_setting(
        pool,
        sync_status_key(tier),
        &serde_json::to_value(&st).unwrap(),
    )
    .await
    {
        tracing::error!(error = %e, "failed to save sync failure status");
    }
}

fn safe_error_message(error: &str) -> String {
    // 把上游地址脱敏，避免把带 token 的地址写进状态
    let msg = error.to_string();
    // 简单处理：把 http(s)://... 整体替换
    let mut out = String::new();
    let mut rest = msg.as_str();
    while let Some(idx) = rest.find("http") {
        let (before, after) = rest.split_at(idx);
        out.push_str(before);
        let end = after
            .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(after.len());
        out.push_str("[上游地址]");
        rest = &after[end..];
    }
    out.push_str(rest);
    let msg = out.replace(['\r', '\n'], " ");
    msg.chars().take(240).collect()
}

async fn fetch_subscription_text(
    http: &reqwest::Client,
    source_url: &str,
) -> Result<String, String> {
    validate_source_url_syntax(source_url)?;
    let mut current = url::Url::parse(source_url).map_err(|_| "订阅地址格式不正确".to_string())?;
    for _redirect in 0..=3 {
        assert_public_remote(&current).await?;
        let resp = http
            .get(current.clone())
            .header(
                "Accept",
                "text/plain, text/yaml, application/yaml, */*;q=0.5",
            )
            .header("User-Agent", "PM-Node-Station-Sync/1.0")
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| format!("上游请求失败：{e}"))?;
        if resp.status().is_redirection() {
            let Some(loc) = resp.headers().get("location").and_then(|v| v.to_str().ok()) else {
                return Err("上游重定向缺少 Location".into());
            };
            current = current.join(loc).unwrap_or_else(|_| current.clone());
            continue;
        }
        if !resp.status().is_success() {
            return Err(format!("上游请求失败（{}）", resp.status()));
        }
        if let Some(len) = resp.content_length() {
            if len > MAX_RESPONSE_BYTES as u64 {
                return Err("上游内容超过 16MB 安全上限".into());
            }
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| format!("读取上游失败：{e}"))?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err("上游内容超过 16MB 安全上限".into());
        }
        return String::from_utf8(bytes.to_vec()).map_err(|_| "上游内容不是合法 UTF-8".to_string());
    }
    Err("上游重定向次数过多".into())
}

async fn assert_public_remote(url: &url::Url) -> Result<(), String> {
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        return Err("订阅地址不能指向内网".into());
    }
    let addrs: Vec<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![ip]
    } else {
        tokio::net::lookup_host((host.as_str(), url.port().unwrap_or(443)))
            .await
            .map_err(|e| format!("解析上游域名失败：{e}"))?
            .map(|s| s.ip())
            .collect()
    };
    if addrs.is_empty() || addrs.iter().any(|ip| !is_public_ip(ip)) {
        return Err("订阅地址不能指向内网".into());
    }
    Ok(())
}

pub fn is_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(o[0] == 0
                || o[0] == 10
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || o[0] >= 224)
        }
        IpAddr::V6(v6) => {
            let s = v6.to_string().to_ascii_lowercase();
            !(v6.is_loopback()
                || v6.is_unspecified()
                || s.starts_with("fc")
                || s.starts_with("fd")
                || s.starts_with("fe8")
                || s.starts_with("fe9")
                || s.starts_with("fea")
                || s.starts_with("feb")
                || s.starts_with("ff"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_builds_two_slots_and_claims_latest() {
        let now = Utc::now();
        let date = shanghai_date_at(now).to_string();
        let sched = build_daily_schedule(&date, now);
        assert_eq!(sched.slots.len(), 2);
        assert!(sched
            .slots
            .iter()
            .all(|s| s.status == "pending" || s.status == "skipped"));
        // 认领未到期不认领
        let (s2, claimed) = claim_due_slot(&sched, now);
        assert!(claimed.is_none() || s2.slots.iter().any(|s| s.status == "claimed"));
    }

    #[test]
    fn claim_skips_backlog_except_latest() {
        // 构造两个都已到期的槽位
        let sched = SyncSchedule {
            date: "2026-11-14".into(),
            slots: vec![
                AutoSyncSlot {
                    id: 0,
                    scheduled_at: "2026-11-14T00:00:00+00:00".into(),
                    status: "pending".into(),
                    handled_at: None,
                },
                AutoSyncSlot {
                    id: 1,
                    scheduled_at: "2026-11-14T01:00:00+00:00".into(),
                    status: "pending".into(),
                    handled_at: None,
                },
            ],
        };
        let now = DateTime::parse_from_rfc3339("2026-11-14T02:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let (s2, claimed) = claim_due_slot(&sched, now);
        assert_eq!(claimed.map(|c| c.id), Some(1));
        assert_eq!(s2.slots[0].status, "skipped");
        assert_eq!(s2.slots[1].status, "claimed");
    }

    #[test]
    fn public_ip_classification() {
        assert!(is_public_ip(&"8.8.8.8".parse().unwrap()));
        assert!(!is_public_ip(&"10.0.0.5".parse().unwrap()));
        assert!(!is_public_ip(&"192.168.1.1".parse().unwrap()));
        assert!(!is_public_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_public_ip(&"100.64.0.1".parse().unwrap()));
        assert!(!is_public_ip(&"::1".parse().unwrap()));
        assert!(is_public_ip(&"2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn source_url_validation() {
        assert!(validate_source_url_syntax("https://example.com/sub").is_ok());
        assert!(validate_source_url_syntax("ftp://example.com/sub").is_err());
        assert!(validate_source_url_syntax("https://user:pass@example.com/sub").is_err());
        assert!(validate_source_url_syntax("not a url").is_err());
    }

    #[test]
    fn error_message_redacts_urls() {
        let msg = safe_error_message("fetch https://example.com/secret-token failed");
        assert!(!msg.contains("secret-token"));
        assert!(msg.contains("[上游地址]"));
    }

    #[test]
    fn multi_upstream_merge_dedupe_rename() {
        // 两个源同一 http 端点各出现一次（Clash YAML + geonode JSON），合并去重只留一份
        let clash = r#"
proxies:
  - name: "US-01"
    type: http
    server: 1.2.3.4
    port: 8080
  - name: "HK-01"
    type: vless
    server: hk.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    tls: true
"#;
        let geo = r#"{"data":[
          {"ip":"1.2.3.4","port":"8080","protocols":["http"],"country":"US"},
          {"ip":"5.6.7.8","port":1080,"protocols":["socks5"],"country":"JP"}
        ]}"#;
        let p1 = parse_upstream_content(clash, crate::upstreams::UpstreamFormat::Clash);
        let p2 = parse_upstream_content(geo, crate::upstreams::UpstreamFormat::JsonGeonode);
        assert_eq!(p1.nodes.len(), 2);
        assert_eq!(p2.nodes.len(), 2);
        let mut all = Vec::new();
        all.extend(p1.nodes);
        all.extend(p2.nodes);
        let merged = dedupe_by_endpoint(&all);
        assert_eq!(merged.len(), 3, "同一 http 端点在两源出现只留一份: {merged:?}");
        let (renamed, unrecognized) = rename_nodes(&merged, 1);
        let names: Vec<String> = renamed.iter().map(|u| read_node_name(u)).collect();
        assert!(names.contains(&"🇺🇸一级美国节点1".to_string()), "改名后缺美国节点: {names:?}");
        assert!(names.contains(&"🇯🇵一级日本节点1".to_string()), "改名后缺日本节点: {names:?}");
        assert!(names.contains(&"🇭🇰一级香港节点1".to_string()), "改名后缺香港节点: {names:?}");
        assert!(unrecognized.is_empty());
    }

    #[test]
    fn yoyapai_date_url_template() {
        // 日期模板用固定日期断言：2026-11-14 必须拼出当日文件 URL
        let tpl = "https://example.invalid/{YYYY}/{MM}/{DD}-node.yaml";
        let date = chrono::NaiveDate::from_ymd_opt(2026, 11, 14).unwrap();
        assert_eq!(
            resolve_url_template(tpl, date),
            "https://example.invalid/2026/11/14-node.yaml"
        );
    }
}
