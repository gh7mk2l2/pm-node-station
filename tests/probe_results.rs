//! POST /api/probe/results 端到端测试（ignored，需真实数据库）：
//!   DATABASE_URL=postgres://user:pass@host:5432/pmnodes_probe_test \
//!   PROBE_TOKEN=test-probe-token \
//!     cargo test --test probe_results -- --ignored --nocapture
//!
//! 先在空库上跑迁移，再起一个 127.0.0.1 随机端口的真服务，按顺序跑规格的 7 类用例。
//! 写回用的端点全是 TEST-NET（203.0.113.x），跑完删除，不留脏数据。
//! 注意：60 秒窗口测试会真实等待 61 秒。

use pm_node_station::api::build_router;
use pm_node_station::config::Config;
use pm_node_station::ratelimit::RateLimiter;
use pm_node_station::socks_runner::SocksRunner;
use pm_node_station::state::AppState;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;

const TOKEN: &str = "test-probe-token-20261115";
const EP1: &str = "vless://203.0.113.10:443";
const EP2: &str = "trojan://203.0.113.11:443";

async fn read_row(pool: &sqlx::PgPool, ep: &str) -> Option<(bool, Option<i32>)> {
    sqlx::query_as("SELECT online, latency_ms FROM node_availability WHERE endpoint = $1")
        .bind(ep)
        .fetch_optional(pool)
        .await
        .unwrap()
}

async fn delete_test_rows(pool: &sqlx::PgPool) {
    sqlx::query("DELETE FROM node_availability WHERE endpoint = $1 OR endpoint = $2")
        .bind(EP1)
        .bind(EP2)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
#[ignore]
async fn probe_results_end_to_end() {
    if std::env::var("PROBE_TOKEN").is_err() {
        std::env::set_var("PROBE_TOKEN", TOKEN);
    }
    let token = std::env::var("PROBE_TOKEN").unwrap();
    let cfg = Config::from_env().expect("Config::from_env（需 DATABASE_URL）");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&cfg.database_url)
        .await
        .expect("connect test db");
    sqlx::migrate!("./migrations").run(&pool).await.expect("migrate");
    delete_test_rows(&pool).await;

    let state = AppState {
        pool: pool.clone(),
        http: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap(),
        cfg: cfg.clone(),
        limiter: Arc::new(RateLimiter::new()),
        socks_runner: SocksRunner::new(pool.clone()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = build_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let client = reqwest::Client::new();
    let base = format!("http://{addr}/api");
    let post = |body: Value, token: Option<&str>, csrf: bool| {
        let mut req = client.post(format!("{base}/probe/results")).json(&body);
        if let Some(t) = token {
            req = req.header("Authorization", format!("Bearer {t}"));
        }
        if csrf {
            req = req.header("x-pmnodes-csrf", "1");
        }
        req
    };

    // 0. health
    let r = client
        .get(format!("{base}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    // 1. 有效写（2 行）+ 读回
    let r = post(
        json!({"results": [
            {"endpoint": EP1, "online": true, "latency_ms": 87},
            {"endpoint": EP2, "online": false, "latency_ms": null},
        ]}),
        Some(&token),
        true,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "valid write: {}", r.text().await.unwrap());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["written"], 2);
    assert!(body["checked_at"].as_str().is_some());
    assert_eq!(read_row(&pool, EP1).await, Some((true, Some(87))));
    assert_eq!(read_row(&pool, EP2).await, Some((false, None)));

    // 2. 错 token → 401；缺 token → 401；无 CSRF → 403
    let r = post(json!({"results": [{"endpoint": EP1, "online": true, "latency_ms": 1}]}), Some("wrong"), true)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = post(json!({"results": [{"endpoint": EP1, "online": true, "latency_ms": 1}]}), None, true)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = post(json!({"results": [{"endpoint": EP1, "online": true, "latency_ms": 1}]}), Some(&token), false)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // 3. 坏端点 → 400 且零行写入；空数组 / 1001 行 → 400
    let r = post(json!({"results": [{"endpoint": "not-a-url", "online": true, "latency_ms": 1}]}), Some(&token), true)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(read_row(&pool, "not-a-url").await, None);
    let r = post(json!({"results": []}), Some(&token), true).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let many: Vec<Value> = (0..1001)
        .map(|i| json!({"endpoint": format!("vless://203.0.113.{}:443", 20 + (i % 200)), "online": true, "latency_ms": 1}))
        .collect();
    let r = post(json!({"results": many}), Some(&token), true).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);

    // 4. 60 秒内第二次写 → 429（精确 body）
    let r = post(json!({"results": [{"endpoint": EP1, "online": true, "latency_ms": 1}]}), Some(&token), true)
        .send().await.unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body, json!({"error": "too soon, wait 60s"}));

    // 5. 窗口后 → 200；重复端点只写一次（最后一条胜出），且覆盖第一次写的值
    tokio::time::sleep(Duration::from_secs(61)).await;
    let r = post(
        json!({"results": [
            {"endpoint": EP1, "online": true, "latency_ms": 87},
            {"endpoint": EP1, "online": false, "latency_ms": 12},
            {"endpoint": EP2, "online": true, "latency_ms": 55},
        ]}),
        Some(&token),
        true,
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status(), StatusCode::OK, "after window: {}", r.text().await.unwrap());
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["written"], 2, "重复端点去重后只算 2 行");
    assert_eq!(read_row(&pool, EP1).await, Some((false, Some(12))));
    assert_eq!(read_row(&pool, EP2).await, Some((true, Some(55))));

    // 清理
    delete_test_rows(&pool).await;
    assert_eq!(read_row(&pool, EP1).await, None);
    assert_eq!(read_row(&pool, EP2).await, None);
}
