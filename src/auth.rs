//! LinuxDo OAuth 登录与会话（原创实现，约定沿用 PM-Plan）。
//! - PKCE S256；state 一次性消费（UPDATE … RETURNING 原子认领）+ bind cookie 绑定浏览器
//! - 会话：32 字节随机 token，sha256 存库，30 天有效，cookie pmnodes_session
//! - 首位注册用户 → root；ADMIN_USERNAMES 环境变量 → admin；封禁用户无法登录

use crate::error::AppError;
use crate::models::User;
use crate::state::AppState;
use crate::util::{random_token, sha256};
use axum::{
    extract::{FromRequestParts, Query, State},
    http::{header, request::Parts, HeaderMap},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use sqlx::PgPool;

pub const SESSION_COOKIE: &str = "pmnodes_session";
pub const OAUTH_BIND_COOKIE: &str = "pmnodes_oauth_bind";

#[derive(Debug, Clone)]
pub struct SessionUser {
    pub id: i64,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub trust_level: i32,
    pub role: String,
    pub is_banned: bool,
    pub sub_token: String,
}

impl SessionUser {
    pub fn is_admin(&self) -> bool {
        self.role == "admin" || self.role == "root"
    }
    pub fn is_root(&self) -> bool {
        self.role == "root"
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|raw| {
            raw.split(';').find_map(|part| {
                let (k, v) = part.trim().split_once('=')?;
                if k.trim() == name {
                    Some(v.trim().to_string())
                } else {
                    None
                }
            })
        })
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    let mut c = format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        30 * 24 * 3600
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

pub fn clear_cookie(name: &str, secure: bool) -> String {
    let mut c = format!("{name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0");
    if secure {
        c.push_str("; Secure");
    }
    c
}

fn append_cookie(resp: &mut Response, cookie: String) {
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
}

pub async fn lookup_session(pool: &PgPool, token: &str) -> Option<SessionUser> {
    let hash = sha256(token.as_bytes());
    sqlx::query_as::<_, (i64, String, Option<String>, Option<String>, i32, String, bool, String)>(
        "SELECT u.id, u.username, u.display_name, u.avatar_url, u.trust_level, u.role, u.is_banned, u.sub_token \
         FROM sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = $1 AND s.expires_at > now()",
    )
    .bind(&hash)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(id, username, display_name, avatar_url, trust_level, role, is_banned, sub_token)| {
        SessionUser {
            id,
            username,
            display_name,
            avatar_url,
            trust_level,
            role,
            is_banned,
            sub_token,
        }
    })
}

/// 登录用户守卫：未登录 401
pub struct AuthUser(pub SessionUser);

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = cookie_value(&parts.headers, SESSION_COOKIE)
            .ok_or_else(|| AppError::unauthorized("请先登录"))?;
        let user = lookup_session(&state.pool, &token)
            .await
            .ok_or_else(|| AppError::unauthorized("登录已过期，请重新登录"))?;
        if user.is_banned {
            return Err(AppError::forbidden("账号已被封禁"));
        }
        Ok(AuthUser(user))
    }
}

/// 管理员守卫：未登录 401，非管理员 403
pub struct AdminUser(pub SessionUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_admin() {
            return Err(AppError::forbidden("需要管理员权限"));
        }
        Ok(AdminUser(user))
    }
}

/// 站长守卫：只有 root 能改角色
pub struct RootUser(pub SessionUser);

impl FromRequestParts<AppState> for RootUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let AuthUser(user) = AuthUser::from_request_parts(parts, state).await?;
        if !user.is_root() {
            return Err(AppError::forbidden("只有站长可以执行此操作"));
        }
        Ok(RootUser(user))
    }
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

pub async fn oauth_login(State(state): State<AppState>) -> Result<Response, AppError> {
    let cfg = &state.cfg;
    let (Some(client_id), Some(_secret)) = (&cfg.oauth_client_id, &cfg.oauth_client_secret) else {
        return Err(AppError::service_unavailable(
            "本站尚未配置 LinuxDo OAuth，请站长在 .env 中填写 LINUXDO_CLIENT_ID / LINUXDO_CLIENT_SECRET",
        ));
    };
    let _ = client_id;
    let oauth_state = random_token(32);
    let bind = random_token(32);
    let verifier = random_token(48);
    let challenge = {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        use sha2::{Digest, Sha256};
        URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
    };
    sqlx::query(
        "INSERT INTO oauth_states (state_hash, bind_hash, code_verifier, next_path, expires_at) \
         VALUES ($1, $2, $3, '/#/dashboard', now() + interval '10 minutes')",
    )
    .bind(sha256(oauth_state.as_bytes()))
    .bind(sha256(bind.as_bytes()))
    .bind(&verifier)
    .execute(&state.pool)
    .await
    .map_err(|e| AppError::internal(e.to_string()))?;

    let mut url = url::Url::parse(
        cfg.auth_endpoint
            .as_deref()
            .unwrap_or("https://connect.linux.do/oauth2/authorize"),
    )
    .map_err(|e| AppError::internal(e.to_string()))?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", cfg.oauth_client_id.as_deref().unwrap())
        .append_pair("redirect_uri", &cfg.redirect_uri())
        .append_pair("scope", "openid profile email")
        .append_pair("state", &oauth_state)
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256");
    let mut resp = Redirect::to(url.as_str()).into_response();
    append_cookie(
        &mut resp,
        format!(
            "{OAUTH_BIND_COOKIE}={bind}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{}",
            if cfg.cookie_secure { "; Secure" } else { "" }
        ),
    );
    Ok(resp)
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Response {
    match callback_inner(&state, &query, &headers).await {
        Ok((session_token, next_path)) => {
            let mut resp = Redirect::to(&format!("{}{}", state.cfg.app_url, next_path)).into_response();
            append_cookie(&mut resp, session_cookie(&session_token, state.cfg.cookie_secure));
            append_cookie(&mut resp, clear_cookie(OAUTH_BIND_COOKIE, state.cfg.cookie_secure));
            resp
        }
        Err(message) => {
            tracing::warn!(error = %message, "oauth callback failed");
            let encoded: String =
                url::form_urlencoded::byte_serialize(message.as_bytes()).collect();
            let mut resp = Redirect::to(&format!(
                "{}/?oauth_error={}",
                state.cfg.app_url, encoded
            ))
            .into_response();
            append_cookie(&mut resp, clear_cookie(OAUTH_BIND_COOKIE, state.cfg.cookie_secure));
            resp
        }
    }
}

async fn callback_inner(
    state: &AppState,
    query: &CallbackQuery,
    headers: &HeaderMap,
) -> Result<(String, String), String> {
    if let Some(err) = &query.error {
        let detail = query
            .error_description
            .clone()
            .unwrap_or_else(|| err.clone());
        return Err(format!("LINUX DO 授权失败：{detail}"));
    }
    let code = query
        .code
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "缺少授权码".to_string())?;
    let oauth_state = query
        .state
        .as_deref()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "缺少 state 参数".to_string())?;
    let bind = cookie_value(headers, OAUTH_BIND_COOKIE)
        .ok_or_else(|| "浏览器登录状态缺失，请重新发起登录".to_string())?;

    let state_hash = sha256(oauth_state.as_bytes());
    let row: Option<(Vec<u8>, String, String)> = sqlx::query_as(
        "UPDATE oauth_states SET used_at = now() \
         WHERE state_hash = $1 AND used_at IS NULL AND expires_at > now() \
         RETURNING bind_hash, code_verifier, next_path",
    )
    .bind(&state_hash)
    .fetch_optional(&state.pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "consume oauth state failed");
        "登录状态校验失败，请重试".to_string()
    })?;
    let (bind_hash, verifier, next_path) =
        row.ok_or_else(|| "登录状态已失效或已被使用，请重新登录".to_string())?;
    if sha256(bind.as_bytes()) != bind_hash {
        return Err("登录状态与浏览器不匹配，请重新登录".to_string());
    }

    let token = exchange_code(state, code, &verifier).await?;
    let profile = fetch_user(state, &token.access_token).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| format!("数据库连接失败：{e}"))?;
    // 串行化注册，避免并发登录时出现两个 root
    sqlx::query("SELECT pg_advisory_xact_lock(20261114)")
        .execute(&mut *tx)
        .await
        .map_err(|e| format!("数据库锁失败：{e}"))?;

    let existing: Option<User> = sqlx::query_as("SELECT * FROM users WHERE linuxdo_id = $1")
        .bind(profile.id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| format!("读取用户失败：{e}"))?;

    let user = if let Some(existing) = existing {
        if existing.is_banned {
            return Err(existing
                .ban_reason
                .unwrap_or_else(|| "账号已被封禁".to_string()));
        }
        if profile.trust_level < state.cfg.trust_level_min {
            return Err(format!(
                "需要 LINUX DO 信任等级 {} 及以上，当前为 {}",
                state.cfg.trust_level_min, profile.trust_level
            ));
        }
        sqlx::query_as::<_, User>(
            "UPDATE users SET username = $2, display_name = $3, avatar_url = $4, \
             trust_level = $5, last_login_at = now(), updated_at = now() \
             WHERE id = $1 RETURNING *",
        )
        .bind(existing.id)
        .bind(&profile.username)
        .bind(&profile.display_name)
        .bind(&profile.avatar_url)
        .bind(profile.trust_level)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("更新用户失败：{e}"))?
    } else {
        if profile.trust_level < state.cfg.trust_level_min {
            return Err(format!(
                "需要 LINUX DO 信任等级 {} 及以上，当前为 {}",
                state.cfg.trust_level_min, profile.trust_level
            ));
        }
        let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| format!("统计用户失败：{e}"))?;
        let role = if user_count == 0 {
            "root"
        } else if state
            .cfg
            .admin_usernames
            .iter()
            .any(|n| n.eq_ignore_ascii_case(&profile.username))
        {
            "admin"
        } else {
            "user"
        };
        sqlx::query_as::<_, User>(
            "INSERT INTO users (linuxdo_id, username, display_name, avatar_url, trust_level, role, sub_token, last_login_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, now()) RETURNING *",
        )
        .bind(profile.id)
        .bind(&profile.username)
        .bind(&profile.display_name)
        .bind(&profile.avatar_url)
        .bind(profile.trust_level)
        .bind(role)
        .bind(uuid::Uuid::new_v4().to_string())
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| format!("创建用户失败：{e}"))?
    };

    let session_token = random_token(32);
    let session_hash = sha256(session_token.as_bytes());
    let ip = crate::util::client_ip(headers);
    let user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(300)
        .collect::<String>();
    sqlx::query(
        "INSERT INTO sessions (user_id, token_hash, expires_at, ip, user_agent) \
         VALUES ($1, $2, now() + interval '30 days', NULLIF($3, ''), NULLIF($4, ''))",
    )
    .bind(user.id)
    .bind(&session_hash)
    .bind(&ip)
    .bind(&user_agent)
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("创建会话失败：{e}"))?;

    tx.commit()
        .await
        .map_err(|e| format!("提交登录失败：{e}"))?;
    tracing::info!(user_id = user.id, username = %user.username, role = %user.role, "linux.do login");
    Ok((session_token, next_path))
}

pub async fn oauth_logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(token) = cookie_value(&headers, SESSION_COOKIE) {
        let hash = sha256(token.as_bytes());
        let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(&hash)
            .execute(&state.pool)
            .await;
    }
    let mut resp = Redirect::to(&format!("{}/", state.cfg.app_url)).into_response();
    append_cookie(&mut resp, clear_cookie(SESSION_COOKIE, state.cfg.cookie_secure));
    resp
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[allow(dead_code)]
    refresh_token: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
    #[allow(dead_code)]
    scope: Option<String>,
}

async fn exchange_code(
    state: &AppState,
    code: &str,
    verifier: &str,
) -> Result<TokenResponse, String> {
    let cfg = &state.cfg;
    let endpoint = cfg.token_endpoint.as_deref().unwrap_or("");
    let redirect_uri = cfg.redirect_uri();
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier),
    ];
    let first = state
        .http
        .post(endpoint)
        .basic_auth(
            cfg.oauth_client_id.as_deref().unwrap_or(""),
            cfg.oauth_client_secret.as_deref(),
        )
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("连接 LINUX DO 令牌端点失败：{e}"))?;
    let status = first.status();
    let body = first
        .text()
        .await
        .map_err(|e| format!("读取令牌响应失败：{e}"))?;
    if status.is_success() {
        return serde_json::from_str(&body).map_err(|e| format!("解析令牌响应失败：{e}"));
    }
    // 部分部署只接受 client_secret_post，401/400 时重试一次
    if status.as_u16() == 401 || status.as_u16() == 400 {
        let form = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri.as_str()),
            ("code_verifier", verifier),
            ("client_id", cfg.oauth_client_id.as_deref().unwrap_or("")),
            ("client_secret", cfg.oauth_client_secret.as_deref().unwrap_or("")),
        ];
        let second = state
            .http
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("连接 LINUX DO 令牌端点失败：{e}"))?;
        let status = second.status();
        let body = second
            .text()
            .await
            .map_err(|e| format!("读取令牌响应失败：{e}"))?;
        if status.is_success() {
            return serde_json::from_str(&body).map_err(|e| format!("解析令牌响应失败：{e}"));
        }
    }
    let detail = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("error_description")
                .or_else(|| v.get("error"))
                .and_then(|x| x.as_str().map(str::to_string))
        })
        .unwrap_or_else(|| format!("HTTP {status}"));
    Err(format!("换取访问令牌失败：{detail}"))
}

struct OAuthProfile {
    id: i64,
    username: String,
    display_name: Option<String>,
    avatar_url: Option<String>,
    trust_level: i32,
}

async fn fetch_user(state: &AppState, access_token: &str) -> Result<OAuthProfile, String> {
    let endpoint = state.cfg.userinfo_endpoint.as_deref().unwrap_or("");
    let resp = state
        .http
        .get(endpoint)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| format!("请求 LINUX DO 用户信息失败：{e}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| format!("读取用户信息失败：{e}"))?;
    if !status.is_success() {
        return Err(format!("获取 LINUX DO 用户信息失败：HTTP {status}"));
    }
    let value: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| format!("解析用户信息失败：{e}"))?;

    let id = value
        .get("id")
        .and_then(value_i64)
        .or_else(|| value.get("sub").and_then(value_i64))
        .ok_or_else(|| "LINUX DO 用户信息缺少 id".to_string())?;
    if value.get("active").and_then(serde_json::Value::as_bool) == Some(false) {
        return Err("LINUX DO 账号当前不可用".to_string());
    }
    let username = value
        .get("username")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("login").and_then(serde_json::Value::as_str))
        .or_else(|| value.get("preferred_username").and_then(serde_json::Value::as_str))
        .unwrap_or("linuxdo-user")
        .to_string();
    let display_name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("display_name").and_then(serde_json::Value::as_str))
        .map(|s| s.to_string());
    let trust_level = value
        .get("trust_level")
        .and_then(value_i64)
        .unwrap_or(0) as i32;

    let mut avatar = value
        .get("avatar_url")
        .and_then(serde_json::Value::as_str)
        .or_else(|| value.get("picture").and_then(serde_json::Value::as_str))
        .map(|s| s.to_string());
    if avatar.is_none() {
        if let Some(template) = value.get("avatar_template").and_then(serde_json::Value::as_str) {
            let replaced = template.replace("{size}", "144");
            avatar = Some(if replaced.starts_with('/') {
                format!("https://linux.do{replaced}")
            } else {
                replaced
            });
        }
    }

    Ok(OAuthProfile {
        id,
        username,
        display_name,
        avatar_url: avatar,
        trust_level,
    })
}

fn value_i64(v: &serde_json::Value) -> Option<i64> {
    v.as_i64().or_else(|| {
        v.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| v.as_u64().map(|n| n as i64))
    })
}
