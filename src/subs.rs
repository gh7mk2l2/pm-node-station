//! 个人订阅链接：/{token}?target=clash|singbox&raw=1
//! - token 错误 → 404（不区分“不存在”与“已封禁”，不泄露节点）
//! - 订阅限流 30 次/分钟/IP；每次拉取记 sub_pulls

use crate::clash::{build_clash_yaml, build_clash_yaml_mixed, build_clash_yaml_openvpn};
use crate::error::AppError;
use crate::nodes::dedupe_nodes;
use crate::rules::GROUP_MAIN;
use crate::settings::{get_setting, KEY_ROUTING_MODE};
use crate::singbox::{build_singbox_config, build_singbox_config_mixed, build_singbox_config_openvpn};
use crate::state::AppState;
use crate::util::client_ip;
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Deserialize;
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct SubQuery {
    pub target: Option<String>,
    pub raw: Option<String>,
    pub tier: Option<i16>,
}

/// 反分发策略（内部策略，绝不在前端、订阅页、公告或报错中透露）：
/// - 二级订阅：60 分钟内出现第 6 个不同拉取 IP → 视为超过 5 设备，直接封号。
///   依据是 sub_pulls 拉取记录的 IP 分布（启发式信号，不是真实在线设备数：
///   本站不代理流量，看不到设备是否在线；IP 轮换频繁的用户存在误伤可能，
///   封号后管理员可在后台解封）。
/// - 突发用量（如 1 分钟 1G）本站无法检测：本站不代理流量，没有任何字节统计，
///   流量字节只能由上游（PigeonW）侧统计。
const TIER2_DEVICE_LIMIT: i64 = 5;
const TIER2_DEVICE_WINDOW_MINUTES: i64 = 60;

/// distinct IP 数已达上限且当前 IP 是新的 → 触发反分发处理
pub fn exceeds_device_limit(distinct_ips: i64, current_ip_known: bool, limit: i64) -> bool {
    distinct_ips >= limit && !current_ip_known
}

/// 反分发封号（静默执行）：封禁账号 + 写审计；对外只返回通用 404，不透露原因。
async fn ban_for_redistribution(
    pool: &sqlx::PgPool,
    user_id: i64,
    reason: &str,
    detail: serde_json::Value,
) {
    let _ = sqlx::query(
        "UPDATE users SET is_banned = TRUE, ban_reason = $2, updated_at = now() WHERE id = $1",
    )
    .bind(user_id)
    .bind(reason)
    .execute(pool)
    .await;
    crate::audit::write_audit(
        pool,
        None,
        "user.ban",
        Some("user"),
        Some(&user_id.to_string()),
        detail,
    )
    .await;
}

/// 三级：取某批次的 .ovpn 配置（改名后节点名 → 配置 base64）。
/// 无活跃批次时返回空表，转换随即返回 None（订阅 404）。
async fn load_vpngate_configs(
    pool: &sqlx::PgPool,
    batch_id: Option<i64>,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    let Some(batch_id) = batch_id else {
        return Ok(std::collections::HashMap::new());
    };
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT node_name, config_b64 FROM vpngate_configs WHERE batch_id = $1")
            .bind(batch_id)
            .fetch_all(pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(rows.into_iter().collect())
}

/// 一级：取某批次的 .ovpn 配置（改名后节点名 → 配置 base64，与三级同构分表）。
/// 无配置时返回空表，调用方走普通构造器。
async fn load_openvpn_configs(
    pool: &sqlx::PgPool,
    batch_id: Option<i64>,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    let Some(batch_id) = batch_id else {
        return Ok(std::collections::HashMap::new());
    };
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT node_name, config_b64 FROM openvpn_configs WHERE batch_id = $1")
            .bind(batch_id)
            .fetch_all(pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    Ok(rows.into_iter().collect())
}

pub async fn subscription(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(q): Query<SubQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    // 限流：30 次/分钟/IP
    let ip = client_ip(&headers);
    if let Err(retry) =
        state
            .limiter
            .check(&format!("sub:{ip}"), 30, std::time::Duration::from_secs(60))
    {
        return Err(AppError::rate_limited(retry));
    }

    let uuid = Uuid::parse_str(&token).map_err(|_| AppError::not_found("订阅不存在"))?;
    let user: Option<(i64, bool)> =
        sqlx::query_as("SELECT id, is_banned FROM users WHERE sub_token = $1")
            .bind(uuid.to_string())
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let Some((user_id, is_banned)) = user else {
        return Err(AppError::not_found("订阅不存在"));
    };
    if is_banned {
        return Err(AppError::not_found("订阅不存在"));
    }

    // 二级反分发检测（静默）：60 分钟内第 6 个不同拉取 IP → 直接封号，对外仍是通用 404
    let tier = crate::settings::normalize_tier(q.tier.unwrap_or(1));
    if tier == 2 {
        let row: Option<(i64, bool)> = sqlx::query_as(
            "SELECT count(DISTINCT ip), coalesce(bool_or(ip = $3), FALSE) FROM sub_pulls \
             WHERE user_id = $1 AND tier = 2 AND pulled_at >= now() - make_interval(mins => $2::int) AND ip IS NOT NULL",
        )
        .bind(user_id)
        .bind(TIER2_DEVICE_WINDOW_MINUTES)
        .bind(&ip)
        .fetch_optional(&state.pool)
        .await
        .map_err(|e| AppError::internal(e.to_string()))?;
        if let Some((distinct_ips, current_known)) = row {
            if exceeds_device_limit(distinct_ips, current_known, TIER2_DEVICE_LIMIT) {
                tracing::warn!(
                    user_id,
                    distinct_ips,
                    "tier2 anti-redistribution: device limit exceeded, banning"
                );
                ban_for_redistribution(
                    &state.pool,
                    user_id,
                    "tier2_distinct_ip",
                    serde_json::json!({
                        "reason": "tier2_distinct_ip",
                        "distinct_ips": distinct_ips,
                        "window_minutes": TIER2_DEVICE_WINDOW_MINUTES,
                        "limit": TIER2_DEVICE_LIMIT,
                    }),
                )
                .await;
                return Err(AppError::not_found("订阅不存在"));
            }
        }
    }

    let active: Option<(i64, serde_json::Value)> =
        sqlx::query_as("SELECT id, nodes FROM node_batches WHERE is_active = TRUE AND tier = $1 ORDER BY created_at DESC LIMIT 1")
            .bind(tier)
            .fetch_optional(&state.pool)
            .await
            .map_err(|e| AppError::internal(e.to_string()))?;
    let (batch_id, nodes): (Option<i64>, Vec<String>) = match active {
        Some((id, v)) => (
            Some(id),
            v.as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        ),
        None => (None, vec![]),
    };
    let nodes = dedupe_nodes(&nodes);

    // 二级只下发中继 URI：订阅里不出现任何上游服务器与账号密码，
    // 流量强制走 relay.pmcat.top 中继。一级/三级保持直连，不变。
    let nodes = if tier == 2 {
        crate::relay::relay_uris(&nodes, &token, &state.cfg.relay_host, state.cfg.relay_port)
    } else {
        nodes
    };

    let target = q.target.as_deref().unwrap_or("base64").to_ascii_lowercase();
    let raw = q.raw.as_deref() == Some("1") || q.raw.as_deref() == Some("true");
    let routing_mode = get_setting(&state.pool, KEY_ROUTING_MODE)
        .await
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "rules".to_string());

    // 三级节点是 OpenVPN 服务器：Clash / sing-box 走转换路径——
    // .ovpn 配置 → mihomo `type: openvpn`（需 mihomo ≥1.19.29）/
    // sing-box `openvpn-client` endpoint（需 sing-box ≥1.14）。
    // Base64 仍是 openvpn:// 链接列表，不走转换。
    // 一级是混合批次（普通节点 + 少量 OpenVPN 节点）：有 .ovpn 配置时走混合
    // 构造器（普通节点进 proxies/outbounds，OpenVPN 节点进 openvpn 转换），
    // 无配置时走普通构造器。
    let (body, content_type) = match target.as_str() {
        "clash" => {
            let yaml = if tier == 3 {
                let configs = load_vpngate_configs(&state.pool, batch_id).await?;
                build_clash_yaml_openvpn(&nodes, &configs, GROUP_MAIN, &routing_mode)
                    .ok_or_else(|| AppError::not_found("三级暂无可转换的 OpenVPN 节点"))?
            } else if tier == 1 {
                let configs = load_openvpn_configs(&state.pool, batch_id).await?;
                if configs.is_empty() {
                    build_clash_yaml(&nodes, GROUP_MAIN, &routing_mode)
                        .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
                } else {
                    build_clash_yaml_mixed(&nodes, &configs, GROUP_MAIN, &routing_mode)
                        .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
                }
            } else {
                build_clash_yaml(&nodes, GROUP_MAIN, &routing_mode)
                    .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
            };
            (yaml, "text/yaml; charset=utf-8")
        }
        "singbox" | "sing-box" => {
            let json = if tier == 3 {
                let configs = load_vpngate_configs(&state.pool, batch_id).await?;
                build_singbox_config_openvpn(&nodes, &configs, GROUP_MAIN, &routing_mode)
                    .ok_or_else(|| AppError::not_found("三级暂无可转换的 OpenVPN 节点"))?
            } else if tier == 1 {
                let configs = load_openvpn_configs(&state.pool, batch_id).await?;
                if configs.is_empty() {
                    build_singbox_config(&nodes, GROUP_MAIN, &routing_mode)
                        .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
                } else {
                    build_singbox_config_mixed(&nodes, &configs, GROUP_MAIN, &routing_mode)
                        .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
                }
            } else {
                build_singbox_config(&nodes, GROUP_MAIN, &routing_mode)
                    .ok_or_else(|| AppError::not_found("当前没有可用节点"))?
            };
            (json, "application/json; charset=utf-8")
        }
        _ => {
            if raw {
                (nodes.join("\n"), "text/plain; charset=utf-8")
            } else {
                (
                    STANDARD.encode(nodes.join("\n").as_bytes()),
                    "text/plain; charset=utf-8",
                )
            }
        }
    };

    // 记一次拉取（异步，不阻塞响应）
    let pool = state.pool.clone();
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();
    let format = target.clone();
    tokio::spawn(async move {
        let _ = sqlx::query(
            "INSERT INTO sub_pulls (user_id, format, user_agent, ip, tier) VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5)",
        )
        .bind(user_id)
        .bind(&format)
        .bind(&ua)
        .bind(&ip)
        .bind(tier)
        .execute(&pool)
        .await;
    });

    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_limit_decision() {
        assert!(!exceeds_device_limit(4, false, 5));
        assert!(!exceeds_device_limit(5, true, 5));
        assert!(exceeds_device_limit(5, false, 5));
        assert!(exceeds_device_limit(8, false, 5));
        assert!(!exceeds_device_limit(0, false, 5));
    }
}
