use anyhow::{Context, Result};
use chrono::{FixedOffset, NaiveDate, Utc};

#[derive(Clone, Debug)]
pub struct Config {
    pub bind: String,
    /// 站点对外地址（APP_URL，兼容 BASE_URL），用于订阅链接与 OAuth 回调
    pub app_url: String,
    pub database_url: String,
    /// LinuxDo OAuth 凭据（可为空：未配置时登录接口返回明确的 503，服务仍可启动）
    pub oauth_client_id: Option<String>,
    pub oauth_client_secret: Option<String>,
    pub auth_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
    pub cookie_secure: bool,
    pub web_dir: String,
    pub tz_offset: FixedOffset,
    /// 最低信任等级（默认 1）
    pub trust_level_min: i32,
    /// 初始管理员 LinuxDo 用户名（逗号分隔）
    pub admin_usernames: Vec<String>,
    /// 上游订阅地址兜底（优先用后台数据库配置）
    pub upstream_url: String,
    /// 外部探测器取节点清单的 Bearer token（PROBE_TOKEN，未配置时 /api/probe/nodes 返回 404）
    pub probe_token: Option<String>,
    /// Tier-2 中继地址（订阅里下发的 relay URI 用；默认 relay.pmcat.top:443）
    pub relay_host: String,
    pub relay_port: u16,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok();
        let get = |key: &str| -> Result<String> {
            std::env::var(key).with_context(|| format!("缺少环境变量 {key}"))
        };

        let app_url = std::env::var("APP_URL")
            .or_else(|_| std::env::var("BASE_URL"))
            .unwrap_or_else(|_| "http://127.0.0.1:8882".into())
            .trim_end_matches('/')
            .to_string();
        let cookie_secure = std::env::var("COOKIE_SECURE")
            .map(|v| v == "true" || v == "1")
            .unwrap_or_else(|_| app_url.starts_with("https://"));
        let offset_raw = std::env::var("APP_TIMEZONE_OFFSET").unwrap_or_else(|_| "+08:00".into());
        let tz_offset = parse_offset(&offset_raw)?;
        let trust_level_min = std::env::var("TRUST_LEVEL_MIN")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let admin_usernames = std::env::var("ADMIN_USERNAMES")
            .unwrap_or_default()
            .split([',', '，'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let opt = |key: &str| -> Option<String> {
            std::env::var(key)
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };

        Ok(Self {
            bind: std::env::var("BIND").unwrap_or_else(|_| "127.0.0.1:8882".into()),
            app_url,
            database_url: get("DATABASE_URL")?,
            oauth_client_id: opt("LINUXDO_CLIENT_ID"),
            oauth_client_secret: opt("LINUXDO_CLIENT_SECRET"),
            auth_endpoint: opt("LINUXDO_AUTH_ENDPOINT")
                .or_else(|| Some("https://connect.linux.do/oauth2/authorize".into())),
            token_endpoint: opt("LINUXDO_TOKEN_ENDPOINT")
                .or_else(|| Some("https://connect.linux.do/oauth2/token".into())),
            userinfo_endpoint: opt("LINUXDO_USERINFO_ENDPOINT")
                .or_else(|| Some("https://connect.linux.do/api/user".into())),
            cookie_secure,
            web_dir: std::env::var("WEB_DIR").unwrap_or_else(|_| "./web".into()),
            tz_offset,
            trust_level_min,
            admin_usernames,
            upstream_url: std::env::var("UPSTREAM_SUBSCRIPTION_URL")
                .unwrap_or_default()
                .trim()
                .to_string(),
            probe_token: opt("PROBE_TOKEN"),
            relay_host: std::env::var("RELAY_HOST")
                .ok()
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| "relay.pmcat.top".into()),
            relay_port: std::env::var("RELAY_PORT")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(443),
        })
    }

    pub fn oauth_configured(&self) -> bool {
        self.oauth_client_id
            .as_ref()
            .map(|s| !s.trim().is_empty())
            .unwrap_or(false)
            && self
                .oauth_client_secret
                .as_ref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
    }

    pub fn redirect_uri(&self) -> String {
        format!("{}/oauth/linuxdo", self.app_url)
    }

    pub fn today(&self) -> NaiveDate {
        Utc::now().with_timezone(&self.tz_offset).date_naive()
    }
}

fn parse_offset(raw: &str) -> Result<FixedOffset> {
    let raw = raw.trim();
    let (sign, rest) = match raw.chars().next() {
        Some('+') => (1, &raw[1..]),
        Some('-') => (-1, &raw[1..]),
        _ => (1, raw),
    };
    let mut parts = rest.split(':');
    let hours: i32 = parts
        .next()
        .unwrap_or("8")
        .parse()
        .context("APP_TIMEZONE_OFFSET 小时部分非法")?;
    let minutes: i32 = parts.next().unwrap_or("0").parse().unwrap_or(0);
    let seconds = sign * (hours * 3600 + minutes * 60);
    FixedOffset::east_opt(seconds).context("APP_TIMEZONE_OFFSET 超出范围")
}
