//! PM 节点公益站入口：连接池 → 迁移 → 测活器 → 自动同步循环 → HTTP 服务。

use pm_node_station::api::build_router;
use pm_node_station::config::Config;
use pm_node_station::socks_runner::SocksRunner;
use pm_node_station::state::AppState;
use pm_node_station::sync::{
    get_sync_admin_state, prepare_automatic, run_sync, AutoPrep, SyncTrigger,
};
use pm_node_station::{ratelimit::RateLimiter, socks_runner::SOCKS_RUNNER};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let cfg = Config::from_env()?;
    tracing::info!(bind = %cfg.bind, app_url = %cfg.app_url, "PM Node Station starting");

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&cfg.database_url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("migrations applied");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("PM-Node-Station/1.0")
        .build()?;

    let socks_runner = SocksRunner::new(pool.clone());
    let _ = SOCKS_RUNNER.set(socks_runner.clone());

    let state = AppState {
        pool: pool.clone(),
        http: http.clone(),
        cfg: cfg.clone(),
        limiter: Arc::new(RateLimiter::new()),
        socks_runner,
    };

    // 自动同步循环：每 60 秒检查一次当天随机槽位；未配置上游时静默跳过。
    // 一个槽位触发后，一级、二级、三级依次同步（共用同一次认领）。
    {
        let pool = pool.clone();
        let http = http.clone();
        let env_url = cfg.upstream_url.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let configured = {
                    let s1 = get_sync_admin_state(&pool, 1).await;
                    let s2 = get_sync_admin_state(&pool, 2).await;
                    let s3 = get_sync_admin_state(&pool, 3).await;
                    s1.config.source_set
                        || s2.config.source_set
                        || s3.config.source_set
                        || !env_url.trim().is_empty()
                };
                if !configured {
                    continue;
                }
                let seed = match prepare_automatic(&pool, chrono::Utc::now()).await {
                    Ok(AutoPrep::Ready { seed }) => seed,
                    Ok(_) => continue,
                    Err(e) => {
                        tracing::warn!(error = %e, "auto sync prepare failed");
                        continue;
                    }
                };
                for tier in [1i16, 2, 3] {
                    // 无上游配置的分级直接跳过（不跑同步、不报错、不写失败状态）。
                    // 二级是快照导入、永远无配置，自动循环永远跳过它。
                    if !pm_node_station::sync::tier_sync_configured(&pool, tier, &env_url).await {
                        tracing::info!(tier, "auto sync skipped: tier has no upstream configured");
                        continue;
                    }
                    // 环境变量兜底地址只属于一级；二级、三级必须在后台配好自己的上游
                    let tier_env = if tier == 1 { env_url.as_str() } else { "" };
                    match run_sync(
                        &pool,
                        &http,
                        SyncTrigger::Automatic,
                        None,
                        tier_env,
                        None,
                        tier,
                        Some(seed.clone()),
                    )
                    .await
                    {
                        Ok(r) if r.outcome != "not_due" => {
                            tracing::info!(tier, outcome = %r.outcome, total = r.total_node_count, "auto sync tick");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(tier, error = %e, "auto sync tick failed");
                        }
                    }
                }
            }
        });
    }

    // IP 纯净度后台刷新：每 30 分钟一轮，每轮最多 50 个 IP（teleapi compare 每批 5 个，
    // 批次间 sleep 1 秒，不并发）；首轮延迟 60 秒等服务就绪。查不到的不入库，列表页显示“未检测”。
    // 只查公开体检接口 + DNS，不连节点地址/端口。
    {
        let pool = pool.clone();
        let http = http.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(60)).await;
            let mut interval = tokio::time::interval(Duration::from_secs(30 * 60));
            loop {
                interval.tick().await;
                match pm_node_station::purity::refresh_purity_once(&pool, &http, 50).await {
                    Ok((checked, stored)) if checked > 0 => {
                        tracing::info!(checked, stored, "purity refresh done");
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "purity refresh failed"),
                }
            }
        });
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("listening on {}", cfg.bind);
    axum::serve(listener, app).await?;
    Ok(())
}
