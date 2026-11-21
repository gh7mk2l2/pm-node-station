//! settings 表（key/value JSON）读写。默认值在代码里，库里没有行时退回默认值。

use serde_json::Value;
use sqlx::{PgPool, Postgres, Transaction};

pub const KEY_TRUST_LEVEL_MIN: &str = "trust_level_min";
pub const KEY_ROUTING_MODE: &str = "routing_mode";
pub const KEY_ADMIN_USERNAMES: &str = "admin_usernames";
pub const KEY_SYNC_CONFIG: &str = "subscription_sync_config";
pub const KEY_SYNC_STATUS: &str = "subscription_sync_status";
pub const KEY_SYNC_SCHEDULE: &str = "subscription_sync_schedule";
/// 二级上游配置 / 状态（一级沿用上面两个旧 key，保持兼容）
pub const KEY_SYNC_CONFIG_TIER2: &str = "subscription_sync_config_tier2";
pub const KEY_SYNC_STATUS_TIER2: &str = "subscription_sync_status_tier2";
/// 三级上游配置 / 状态（VPNGate CSV）
pub const KEY_SYNC_CONFIG_TIER3: &str = "subscription_sync_config_tier3";
pub const KEY_SYNC_STATUS_TIER3: &str = "subscription_sync_status_tier3";

/// 分级归一化：只认 1 / 2 / 3，其余一律按一级处理
pub fn normalize_tier(tier: i16) -> i16 {
    if tier == 2 {
        2
    } else if tier == 3 {
        3
    } else {
        1
    }
}

pub fn sync_config_key(tier: i16) -> &'static str {
    match normalize_tier(tier) {
        2 => KEY_SYNC_CONFIG_TIER2,
        3 => KEY_SYNC_CONFIG_TIER3,
        _ => KEY_SYNC_CONFIG,
    }
}

pub fn sync_status_key(tier: i16) -> &'static str {
    match normalize_tier(tier) {
        2 => KEY_SYNC_STATUS_TIER2,
        3 => KEY_SYNC_STATUS_TIER3,
        _ => KEY_SYNC_STATUS,
    }
}

pub async fn get_setting(pool: &PgPool, key: &str) -> Option<Value> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()?;
    row.map(|(v,)| v)
}

pub async fn set_setting(pool: &PgPool, key: &str, value: &Value) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn set_setting_tx(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
    value: &Value,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn get_setting_tx(
    tx: &mut Transaction<'_, Postgres>,
    key: &str,
) -> Option<Value> {
    let row: Option<(Value,)> = sqlx::query_as("SELECT value FROM settings WHERE key = $1")
        .bind(key)
        .fetch_optional(&mut **tx)
        .await
        .ok()?;
    row.map(|(v,)| v)
}

/// 信任等级下限（库里没有时用配置默认值）
pub async fn trust_level_min(pool: &PgPool, default: i32) -> i32 {
    match get_setting(pool, KEY_TRUST_LEVEL_MIN).await {
        Some(Value::Number(n)) => n.as_i64().map(|v| v as i32).unwrap_or(default),
        _ => default,
    }
}

/// 分流模式：rules（分流）或 global（全量代理）
pub async fn routing_mode(pool: &PgPool) -> String {
    match get_setting(pool, KEY_ROUTING_MODE).await {
        Some(Value::String(s)) if s == "global" => "global".to_string(),
        _ => "rules".to_string(),
    }
}

/// 管理员用户名列表（库里的优先于环境变量；支持 JSON 数组或逗号分隔字符串）
pub async fn admin_usernames(pool: &PgPool, env_default: &[String]) -> Vec<String> {
    match get_setting(pool, KEY_ADMIN_USERNAMES).await {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
            .filter(|s| !s.is_empty())
            .collect(),
        Some(Value::String(s)) => parse_usernames(&s),
        _ => env_default.to_vec(),
    }
}

pub fn parse_usernames(value: &str) -> Vec<String> {
    value
        .split([',', '，', ' ', '\n', '\t'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usernames_split_on_separators() {
        assert_eq!(parse_usernames("a,b，c d"), vec!["a", "b", "c", "d"]);
        assert!(parse_usernames("").is_empty());
    }
}
