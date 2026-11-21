//! teleapi IP 纯净度（https://ai01.teleapi.top/ipcheck/）：服务端拉取 + 入库缓存。
//!
//! 接口实测（2026-11-14）：
//! - 公开 API，无需 key：`GET /ipcheck/api/check?ip=8.8.8.8`（单个 IP，完整报告）；
//!   `GET /ipcheck/api/compare?ips=1.1.1.1,8.8.8.8`（批量对比，精简字段）。
//! - compare 一次最多返回 5 个 IP（实测传 20 个只回 5 个），本模块按 5 个一批调用。
//! - compare 返回字段：`{ip, ok, coef, band, type, origin, risk, dnsbl, dnsbl_mail, ai_stars, verdict}`，
//!   其中纯净度分数就是 `coef`（0–100，站内刻度 0 极度纯净 / 35 / 55 / 75 / 100 高风险；
//!   band 如“纯净”）。上游源偶发 429 时 API 优雅降级（sources_ok 下降仍出报告）；
//!   数据源多数不可用时返回 503，此时不入库。
//! - 响应没有 `Access-Control-Allow-Origin`，浏览器端直连会被 CORS 拦，只能服务端查。
//! - 分数变化慢：缓存 7 天复查一次；每轮最多 50 个 IP，批次间 sleep 1 秒，绝不并发打爆。
//! - 查不到（ok=false / 503 / 超时 / 解析失败）不入库，列表页显示“未检测”，不编数据。
//!
//! 注意：这只是查公开体检接口，不连节点地址/端口，与“禁止服务端探测节点”不冲突。

use crate::nodes::{endpoint_key, parse_node_endpoint};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

pub const TELEAPI_BASE: &str = "https://ai01.teleapi.top/ipcheck";
/// compare 一次最多 5 个 IP（实测上限）
pub const COMPARE_BATCH: usize = 5;
/// 纯净度缓存有效期（天）：分数变化慢，7 天复查一次
pub const PURITY_TTL_DAYS: i64 = 7;

#[derive(Debug, Clone)]
pub struct PurityHit {
    pub ip: String,
    pub coefficient: i32,
    pub band: String,
    pub ip_type: Option<String>,
    pub verdict: Option<String>,
    pub raw: serde_json::Value,
}

/// 解析 /api/compare 的响应：只收 ok=true 的行，ok=false 的 IP 不入库（显示“未检测”）。
pub fn parse_compare_response(body: &serde_json::Value) -> Vec<PurityHit> {
    let mut out = Vec::new();
    let Some(results) = body.get("results").and_then(|v| v.as_array()) else {
        return out;
    };
    for r in results {
        if r.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            continue;
        }
        let Some(ip) = r.get("ip").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some(coef) = r.get("coef").and_then(|v| v.as_i64()) else {
            continue;
        };
        out.push(PurityHit {
            ip: ip.to_string(),
            coefficient: coef as i32,
            band: r
                .get("band")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            ip_type: r.get("type").and_then(|v| v.as_str()).map(|s| s.to_string()),
            verdict: r
                .get("verdict")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            raw: r.clone(),
        });
    }
    out
}

/// 解析单个 IP 的主机名：IP 字面量直接用；域名做一次 DNS 解析（只查 A/AAAA，不连节点）。
async fn resolve_host(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    let mut iter = tokio::net::lookup_host((host, 443)).await.ok()?;
    iter.next().map(|s| s.ip())
}

/// 一轮刷新：生效批次的端点 → DNS 解析 → 查缺失/过期的 IP（最多 max_ips 个）。
/// 返回 (本轮实际查的 IP 数，成功入库的行数)。
pub async fn refresh_purity_once(
    pool: &PgPool,
    http: &reqwest::Client,
    max_ips: usize,
) -> Result<(usize, usize), String> {
    // 1. 当前生效批次里的全部去重端点（endpoint → host）
    let batches: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT nodes FROM node_batches WHERE is_active = TRUE")
            .fetch_all(pool)
            .await
            .map_err(|e| e.to_string())?;
    let mut endpoints: HashMap<String, String> = HashMap::new();
    for (nodes,) in &batches {
        let Some(arr) = nodes.as_array() else {
            continue;
        };
        for v in arr {
            let Some(uri) = v.as_str() else {
                continue;
            };
            let Some(ep) = parse_node_endpoint(uri) else {
                continue;
            };
            endpoints
                .entry(endpoint_key(&ep))
                .or_insert_with(|| ep.host.clone());
        }
    }
    if endpoints.is_empty() {
        return Ok((0, 0));
    }

    // 2. 解析 IP 并维护 node_ip 映射（域名解析失败的端点跳过，不影响其余）
    for (endpoint, host) in &endpoints {
        let Some(ip) = resolve_host(host).await else {
            continue;
        };
        sqlx::query(
            "INSERT INTO node_ip (endpoint, ip, resolved_at) VALUES ($1, $2, now()) \
             ON CONFLICT (endpoint) DO UPDATE SET ip = EXCLUDED.ip, resolved_at = now()",
        )
        .bind(endpoint)
        .bind(ip.to_string())
        .execute(pool)
        .await
        .map_err(|e| e.to_string())?;
    }

    // 3. 挑出需要查的 IP：从未查过，或缓存超过 7 天（最旧的优先）
    let todo: Vec<(String,)> = sqlx::query_as(
        "SELECT ni.ip FROM node_ip ni LEFT JOIN ip_purity p ON p.ip = ni.ip \
         WHERE p.ip IS NULL OR p.checked_at < now() - ($1 || ' days')::interval \
         GROUP BY ni.ip ORDER BY min(p.checked_at) ASC NULLS FIRST LIMIT $2",
    )
    .bind(PURITY_TTL_DAYS.to_string())
    .bind(max_ips as i64)
    .fetch_all(pool)
    .await
    .map_err(|e| e.to_string())?;
    if todo.is_empty() {
        return Ok((0, 0));
    }
    let ips: Vec<String> = todo.into_iter().map(|(ip,)| ip).collect();

    // 4. compare 每批 5 个，顺序调用，批次间 sleep 1 秒
    let mut checked = 0usize;
    let mut stored = 0usize;
    for chunk in ips.chunks(COMPARE_BATCH) {
        let url = format!("{TELEAPI_BASE}/api/compare?ips={}", chunk.join(","));
        let resp = http
            .get(&url)
            .timeout(Duration::from_secs(30))
            .send()
            .await;
        let resp = match resp {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "teleapi compare 请求失败，本轮停止");
                break;
            }
        };
        if !resp.status().is_success() {
            tracing::warn!(status = %resp.status(), "teleapi compare 非 2xx，本轮停止");
            break;
        }
        let body: serde_json::Value = match resp.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(error = %e, "teleapi compare 响应解析失败，本轮停止");
                break;
            }
        };
        let hits = parse_compare_response(&body);
        checked += chunk.len();
        for hit in hits {
            sqlx::query(
                "INSERT INTO ip_purity (ip, coefficient, band, ip_type, verdict, raw, checked_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, now()) \
                 ON CONFLICT (ip) DO UPDATE SET coefficient = EXCLUDED.coefficient, \
                 band = EXCLUDED.band, ip_type = EXCLUDED.ip_type, verdict = EXCLUDED.verdict, \
                 raw = EXCLUDED.raw, checked_at = now()",
            )
            .bind(&hit.ip)
            .bind(hit.coefficient)
            .bind(&hit.band)
            .bind(&hit.ip_type)
            .bind(&hit.verdict)
            .bind(&hit.raw)
            .execute(pool)
            .await
            .map_err(|e| e.to_string())?;
            stored += 1;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Ok((checked, stored))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_response_parses_and_skips_failed() {
        let body = serde_json::json!({
            "results": [
                {"ip": "1.1.1.1", "ok": true, "coef": 26, "band": "纯净", "type": "机房 / 商业",
                 "origin": "原生IP", "risk": 0, "dnsbl": 0, "dnsbl_mail": 0, "ai_stars": 3,
                 "verdict": "挺干净的机房 IP。"},
                {"ip": "203.0.113.9", "ok": false, "coef": null, "band": "", "error": "上游不可用"},
                {"ip": "8.8.8.8", "ok": true, "coef": 29, "band": "纯净", "type": "机房 / 商业",
                 "risk": 0, "dnsbl": 0, "dnsbl_mail": 0, "ai_stars": 3, "verdict": "挺干净的。"}
            ]
        });
        let hits = parse_compare_response(&body);
        assert_eq!(hits.len(), 2, "ok=false 的行不应入库");
        assert_eq!(hits[0].ip, "1.1.1.1");
        assert_eq!(hits[0].coefficient, 26);
        assert_eq!(hits[0].band, "纯净");
        assert_eq!(hits[0].ip_type.as_deref(), Some("机房 / 商业"));
        assert_eq!(hits[1].ip, "8.8.8.8");
        assert_eq!(hits[1].coefficient, 29);
        // 缺 results / 空响应不炸
        assert!(parse_compare_response(&serde_json::json!({})).is_empty());
        assert!(parse_compare_response(&serde_json::json!({"results": []})).is_empty());
    }
}
