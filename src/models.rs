use chrono::{DateTime, NaiveDate, Utc};
use serde::Serialize;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: i64,
    pub linuxdo_id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub trust_level: i32,
    pub role: String,
    pub is_banned: bool,
    pub ban_reason: Option<String>,
    pub sub_token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.role == "root" || self.role == "admin"
    }

    pub fn is_root(&self) -> bool {
        self.role == "root"
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct NodeBatch {
    pub id: i64,
    pub title: String,
    pub nodes: serde_json::Value,
    pub batch_date: NaiveDate,
    pub node_count: i32,
    pub is_active: bool,
    pub tier: i16,
    pub source: String,
    pub created_by: Option<i64>,
    pub created_at: DateTime<Utc>,
}

impl NodeBatch {
    pub fn node_uris(&self) -> Vec<String> {
        self.nodes
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct SocksEntry {
    pub id: i64,
    pub host: String,
    pub port: i32,
    pub protocol: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password: String,
    pub line: String,
    pub tags: serde_json::Value,
    pub country: Option<String>,
    pub region: Option<String>,
    pub provider: Option<String>,
    pub risk_score: Option<i32>,
    pub identity_hash: String,
    pub status: String,
    pub latency_ms: Option<i32>,
    pub last_checked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl SocksEntry {
    pub fn tag_list(&self) -> Vec<String> {
        self.tags
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Announcement {
    pub id: i64,
    pub content: String,
    pub level: String,
    pub is_active: bool,
    pub created_by: Option<i64>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct AuditLog {
    pub id: i64,
    pub actor_user_id: Option<i64>,
    pub action: String,
    pub target_type: Option<String>,
    pub target: Option<String>,
    pub detail: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct NodeLatency {
    pub id: i64,
    pub batch_id: i64,
    pub node_uri: String,
    pub latency_ms: Option<i32>,
    pub online: bool,
    pub checked_at: DateTime<Utc>,
}

/// 节点分级元数据（node_tiers 表）
#[derive(Debug, Clone, FromRow, Serialize)]
pub struct NodeTier {
    pub tier: i16,
    pub name: String,
    pub description: String,
    pub ip_type: String,
    pub rate_limited: bool,
    pub anti_redistribution: bool,
    pub daily_limit_gb: Option<i32>,
    pub monthly_limit_gb: Option<i32>,
    pub sort_order: i16,
}

impl NodeTier {
    /// 分级属性标签（前端展示用）
    pub fn tag_lines(&self) -> Vec<String> {
        let mut tags = vec![match self.ip_type.as_str() {
            "residential" => "住宅 IP".to_string(),
            "volunteer" => "志愿者节点".to_string(),
            _ => "机房 IP".to_string(),
        }];
        if self.rate_limited {
            let d = self
                .daily_limit_gb
                .map(|v| format!("{v}G/天"))
                .unwrap_or_else(|| "限流".to_string());
            let m = self
                .monthly_limit_gb
                .map(|v| format!("{v}G/月"))
                .unwrap_or_default();
            tags.push(if m.is_empty() {
                format!("限流 {d}")
            } else {
                format!("限流 {d} · {m}")
            });
        } else {
            tags.push("不限流".to_string());
        }
        tags.push(if self.anti_redistribution {
            "反分发".to_string()
        } else {
            "不反分发".to_string()
        });
        tags
    }
}

/// 公开节点展示（首页用）：名称、协议、地区、延迟、状态
#[derive(Debug, Clone, Serialize)]
pub struct PublicNode {
    pub name: String,
    pub protocol: String,
    pub region: String,
    pub latency_ms: Option<i32>,
    pub online: Option<bool>,
    pub checked_at: Option<DateTime<Utc>>,
}
