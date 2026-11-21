//! One-off tier-1 manual sync (token-merge run, 2026-11-15): run once on the
//! machine with the prod .env sourced. Prints the per-source table; does NOT
//! assert on disabled counts or per-source success (a dead token source is
//! recorded, not fatal).
//!   set -a; source /data/pm-node-station-prod/.env; set +a
//!   cargo test --test run_tier1_sync_once -- --ignored --nocapture
use pm_node_station::sync::{run_sync, SyncTrigger};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn run_tier1_sync_once() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL 未设置");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db)
        .await
        .expect("连不上数据库");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("PM-Node-Station/1.0")
        .build()
        .unwrap();

    let rows: Vec<(String, String, bool, i32)> = sqlx::query_as(
        "SELECT label, kind, enabled, last_nodes FROM tier1_upstreams ORDER BY kind, label",
    )
    .fetch_all(&pool)
    .await
    .expect("读 tier1_upstreams 失败");
    for (label, kind, enabled, last_nodes) in &rows {
        println!(
            "upstream {} kind={} enabled={} last_nodes={}",
            label, kind, enabled, last_nodes
        );
    }

    // 一级真实同步（多上游合并，单源失败只记 error 继续）
    let r = run_sync(&pool, &http, SyncTrigger::Manual, None, "", None, 1, None)
        .await
        .expect("一级同步失败");
    println!(
        "tier1 sync: outcome={} batch_id={:?} upstream={} extra={} total={} unrecognized={} skipped={:?}",
        r.outcome, r.batch_id, r.upstream_node_count, r.extra_node_count, r.total_node_count,
        r.unrecognized_count, r.skipped
    );
    for s in &r.sources {
        println!(
            "  source {}: nodes={} error={:?} skipped={:?}",
            s.label, s.nodes, s.error, s.skipped
        );
    }
    assert!(
        r.outcome == "created" || r.outcome == "unchanged",
        "一级同步 outcome 异常: {}",
        r.outcome
    );
    assert!(
        r.total_node_count > 1000,
        "一级节点数异常少: {}",
        r.total_node_count
    );
}
