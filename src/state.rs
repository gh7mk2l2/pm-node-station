//! 应用状态：连接池、HTTP 客户端、配置、限流器、代理测活器。

use crate::config::Config;
use crate::ratelimit::RateLimiter;
use crate::socks_runner::SocksRunner;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub http: reqwest::Client,
    pub cfg: Config,
    pub limiter: Arc<RateLimiter>,
    pub socks_runner: Arc<SocksRunner>,
}
