//! 探测器写回端点 `POST /api/probe/results`（Phase 1：探测器迁到 Wing 的私有服务器后用）。
//!
//! 鉴权与 `GET /api/probe/nodes` 完全一致（Bearer PROBE_TOKEN，未配 token → 404，
//! 错 token → 401）；POST 必须带 `x-pmnodes-csrf: 1`（全局 csrf_guard）。
//! 请求体 {"results": [{"endpoint", "online", "latency_ms"}]}，1–1000 行；
//! 单事务、单条批量 upsert 进 node_availability；60 秒内只许一次成功写入。

use crate::error::AppError;
use crate::state::AppState;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use bytes::Bytes;
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

const PROBE_RESULT_SCHEMES: [&str; 10] = [
    "vless", "vmess", "trojan", "https", "http", "socks5", "ss", "hysteria2", "tuic", "openvpn",
];

/// 与规格正则 ^[a-z0-9+.\-]+://[0-9a-zA-Z.\-]+:\d+$ 等价的手工校验（不引 regex crate）。
/// 注意：IPv6 端点（host 含冒号）按此正则是不合法的；当前库里 0 个此类端点。
pub fn valid_probe_endpoint(ep: &str) -> bool {
    let Some((scheme, hostport)) = ep.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '.' || c == '-')
        || !PROBE_RESULT_SCHEMES.contains(&scheme)
    {
        return false;
    }
    let Some((host, port)) = hostport.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    !port.is_empty() && port.chars().all(|c| c.is_ascii_digit())
}

#[derive(Deserialize)]
struct ProbeResultRow {
    endpoint: String,
    online: bool,
    /// latency_ms 必须是 JSON 值（Value 而非 Option<i32>，这样才能区分“缺 key”与“null”）：
    /// 缺 key → serde 报错 → 400；null → None；整数 → 校验 0–60000。
    latency_ms: serde_json::Value,
}

#[derive(Deserialize)]
struct ProbeResultsRequest {
    results: Vec<ProbeResultRow>,
}

/// 一行校验后的写回数据（endpoint, online, latency_ms）。
type ProbeRow = (String, bool, Option<i32>);

fn validate_probe_row(row: &ProbeResultRow) -> Result<ProbeRow, String> {
    if !valid_probe_endpoint(&row.endpoint) {
        return Err(format!("endpoint 非法：{}", row.endpoint));
    }
    let latency = match &row.latency_ms {
        serde_json::Value::Null => None,
        serde_json::Value::Number(n) => {
            let v = n
                .as_i64()
                .ok_or_else(|| format!("latency_ms 非整数：{n}"))?;
            if !(0..=60000).contains(&v) {
                return Err(format!("latency_ms 超出范围：{v}"));
            }
            Some(v as i32)
        }
        other => return Err(format!("latency_ms 非法：{other}")),
    };
    Ok((row.endpoint.clone(), row.online, latency))
}

/// 同请求内重复端点去重（最后一条胜出，保持首次出现顺序）。
fn dedupe_probe_rows(rows: Vec<ProbeRow>) -> Vec<ProbeRow> {
    let mut order: Vec<String> = Vec::new();
    let mut map: HashMap<String, (bool, Option<i32>)> = HashMap::new();
    for (ep, online, lat) in rows {
        if !map.contains_key(&ep) {
            order.push(ep.clone());
        }
        map.insert(ep, (online, lat));
    }
    order
        .into_iter()
        .map(|ep| {
            let (online, lat) = map.remove(&ep).expect("dedupe map");
            (ep, online, lat)
        })
        .collect()
}

fn validate_probe_results(body: &[u8]) -> Result<Vec<ProbeRow>, AppError> {
    let req: ProbeResultsRequest = serde_json::from_slice(body)
        .map_err(|e| AppError::bad_request(format!("请求体不是合法 JSON：{e}")))?;
    if req.results.is_empty() {
        return Err(AppError::bad_request("results 为空"));
    }
    if req.results.len() > 1000 {
        return Err(AppError::bad_request("results 最多 1000 行"));
    }
    let mut rows = Vec::with_capacity(req.results.len());
    for row in &req.results {
        rows.push(validate_probe_row(row).map_err(AppError::bad_request)?);
    }
    Ok(dedupe_probe_rows(rows))
}

pub async fn probe_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let token = state.cfg.probe_token.clone().filter(|s| !s.is_empty());
    let Some(token) = token else {
        return AppError::not_found("接口未启用").into_response();
    };
    let authed = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v == format!("Bearer {token}"))
        .unwrap_or(false);
    if !authed {
        return AppError::unauthorized("探测 token 无效").into_response();
    }
    let rows = match validate_probe_results(&body) {
        Ok(rows) => rows,
        Err(e) => return e.into_response(),
    };
    // 防滥用：60 秒内只许一次成功写入。先校验后记账；DB 失败也会占一次窗口（60 秒后可重试）。
    if state
        .limiter
        .check("probe-results", 1, Duration::from_secs(60))
        .is_err()
    {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({"error": "too soon, wait 60s"})),
        )
            .into_response();
    }
    let written = rows.len();
    let now = Utc::now();
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(e) => return AppError::internal(e.to_string()).into_response(),
    };
    // 注意：push_values() 自己会拼 "VALUES (...), (...)"，初始 SQL 里不要写 VALUES。
    let mut qb = sqlx::QueryBuilder::new(
        "INSERT INTO node_availability (endpoint, online, latency_ms, checked_at, updated_at) ",
    );
    qb.push_values(rows.into_iter(), |mut b, (ep, online, lat)| {
        b.push_bind(ep)
            .push_bind(online)
            .push_bind(lat)
            .push_bind(now)
            .push_bind(now);
    });
    qb.push(
        " ON CONFLICT (endpoint) DO UPDATE SET online = EXCLUDED.online, \
         latency_ms = EXCLUDED.latency_ms, checked_at = EXCLUDED.checked_at, updated_at = now()",
    );
    if let Err(e) = qb.build().execute(&mut *tx).await {
        let _ = tx.rollback().await;
        return AppError::internal(e.to_string()).into_response();
    }
    if let Err(e) = tx.commit().await {
        return AppError::internal(e.to_string()).into_response();
    }
    (
        StatusCode::OK,
        Json(json!({"written": written, "checked_at": now.to_rfc3339()})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn endpoint_validation_matches_spec_regex() {
        for ok in [
            "vless://1.2.3.4:443",
            "trojan://5.6.7.8:443",
            "https://example.com:8443",
            "http://a-b.c-d.example:8080",
            "socks5://127.0.0.1:1080",
            "ss://host:8388",
            "hysteria2://203.0.113.1:443",
            "tuic://203.0.113.2:443",
            "openvpn://10.0.0.1:1194",
            "vmess://203.0.113.9:8443",
        ] {
            assert!(valid_probe_endpoint(ok), "{ok} 应合法");
        }
        for bad in [
            "not-a-url",
            "http://no-port",
            "unknown://x:1",
            "VLESS://1.2.3.4:443",
            "vless://1.2.3.4:443/path",
            "vless://1.2.3.4:abc",
            "vless://:443",
            "vless://[::1]:443",
            "vless://2001:db8::1:443",
            "vless://a_b:443",
            "",
            "vless://",
        ] {
            assert!(!valid_probe_endpoint(bad), "{bad} 应非法");
        }
    }

    #[test]
    fn dedupe_keeps_last_value() {
        let rows = dedupe_probe_rows(vec![
            ("vless://a:1".to_string(), true, Some(10)),
            ("vless://b:2".to_string(), false, None),
            ("vless://a:1".to_string(), false, Some(99)),
        ]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("vless://a:1".to_string(), false, Some(99)));
        assert_eq!(rows[1], ("vless://b:2".to_string(), false, None));
    }

    fn is_400<T>(r: Result<T, AppError>) -> bool {
        matches!(r, Err(e) if e.status == StatusCode::BAD_REQUEST)
    }

    #[test]
    fn request_validation() {
        // 有效：2 行，null 延迟可接受；未知字段忽略
        let ok = validate_probe_results(
            br#"{"results": [
                {"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": 87},
                {"endpoint": "trojan://5.6.7.8:443", "online": false, "latency_ms": null}
            ]}"#,
        );
        assert_eq!(ok.unwrap().len(), 2);
        let ok2 = validate_probe_results(
            br#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": 1, "extra": "x"}], "note": 1}"#,
        );
        assert_eq!(ok2.unwrap().len(), 1);
        // 空数组 / >1000 行 → 400
        assert!(is_400(validate_probe_results(br#"{"results": []}"#)));
        let many = format!(
            "{{\"results\": [{}]}}",
            (0..1001)
                .map(|i| format!(
                    "{{\"endpoint\": \"vless://10.0.{}.{}:443\", \"online\": true, \"latency_ms\": 1}}",
                    i / 256,
                    i % 256
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(is_400(validate_probe_results(many.as_bytes())));
        // 坏端点 / 坏延迟 / 缺字段 / 错类型 → 400
        for bad in [
            r#"{"results": [{"endpoint": "not-a-url", "online": true, "latency_ms": 1}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": -1}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": 60001}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "latency_ms": 1}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": "true", "latency_ms": 1}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": 1.5}]}"#,
            r#"{"results": [{"endpoint": "vless://1.2.3.4:443", "online": true, "latency_ms": "87"}]}"#,
            r#"{}"#,
            r#"not json"#,
        ] {
            assert!(
                is_400(validate_probe_results(bad.as_bytes())),
                "{bad} 应 400"
            );
        }
    }
}
