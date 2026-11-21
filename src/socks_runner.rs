//! 进程内代理测活任务（单例）：一次只允许一个 run，进度写库 + 内存快照。

use crate::socks_test::{check_proxy, run_pool, ProxyAuth};
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tokio::sync::OnceCell;

#[derive(Debug, Clone, Default)]
pub struct SocksRunState {
    pub running: bool,
    pub scope: Option<String>,
    pub total: usize,
    pub done: usize,
    pub ok: usize,
    pub fail: usize,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
}

pub enum SocksRunStart {
    Started { total: usize },
    AlreadyRunning,
    Empty,
}

pub struct SocksRunner {
    pub pool: PgPool,
    state: Mutex<SocksRunState>,
}

impl SocksRunner {
    pub fn new(pool: PgPool) -> Arc<Self> {
        Arc::new(Self {
            pool,
            state: Mutex::new(SocksRunState::default()),
        })
    }

    pub fn state(&self) -> SocksRunState {
        self.state.lock().unwrap().clone()
    }

    /// 按范围启动一轮测活；支持未测、失败复测与全部重测
    pub async fn start_run(self: &Arc<Self>, scope: &str, limit: i64) -> SocksRunStart {
        {
            let mut st = self.state.lock().unwrap();
            if st.running {
                return SocksRunStart::AlreadyRunning;
            }
            // 必须在第一次 await 前占位，否则两个并发请求都可能越过 running 检查
            st.running = true;
            st.scope = Some(scope.to_string());
        }

        let targets: Vec<(i64, String, i32, String, String, String)> = {
            let rows = match scope {
                "failed" => {
                    sqlx::query_as::<_, (i64, String, i32, String, String, String)>(
                        "SELECT id, host, port, protocol, username, password FROM socks_pool \
                         WHERE status = 'fail' ORDER BY id LIMIT $1",
                    )
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await
                }
                "all" => {
                    sqlx::query_as::<_, (i64, String, i32, String, String, String)>(
                        "SELECT id, host, port, protocol, username, password FROM socks_pool \
                         ORDER BY id LIMIT $1",
                    )
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await
                }
                _ => {
                    sqlx::query_as::<_, (i64, String, i32, String, String, String)>(
                        "SELECT id, host, port, protocol, username, password FROM socks_pool \
                         WHERE status = 'untested' ORDER BY id LIMIT $1",
                    )
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await
                }
            };
            match rows {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error = %e, "socks run: load targets failed");
                    let mut st = self.state.lock().unwrap();
                    st.running = false;
                    st.scope = None;
                    return SocksRunStart::Empty;
                }
            }
        };

        if targets.is_empty() {
            let mut st = self.state.lock().unwrap();
            st.running = false;
            st.scope = None;
            return SocksRunStart::Empty;
        }

        {
            let mut st = self.state.lock().unwrap();
            st.total = targets.len();
            st.done = 0;
            st.ok = 0;
            st.fail = 0;
            st.started_at = Some(chrono::Utc::now().to_rfc3339());
            st.finished_at = None;
        }

        let runner = self.clone();
        tokio::spawn(async move {
            let pool = runner.pool.clone();
            let runner_for_pool = runner.clone();
            run_pool(targets, 100, move |(id, host, port, protocol, username, password)| {
                let pool = pool.clone();
                let runner = runner_for_pool.clone();
                async move {
                    let auth = if username.is_empty() {
                        None
                    } else {
                        Some(ProxyAuth { username, password })
                    };
                    let r = check_proxy(&host, port as u16, &protocol, 8000, auth).await;
                    {
                        let mut st = runner.state.lock().unwrap();
                        if r.ok {
                            st.ok += 1;
                        } else {
                            st.fail += 1;
                        }
                        st.done += 1;
                    }
                    let res = sqlx::query(
                        "UPDATE socks_pool SET status = $1, latency_ms = $2, last_checked_at = now() \
                         WHERE id = $3",
                    )
                    .bind(if r.ok { "ok" } else { "fail" })
                    .bind(if r.ok { Some(r.latency_ms as i32) } else { None::<i32> })
                    .bind(id)
                    .execute(&pool)
                    .await;
                    if let Err(e) = res {
                        tracing::warn!(error = %e, id, "socks run: update failed");
                    }
                }
            })
            .await;
            let mut st = runner.state.lock().unwrap();
            st.running = false;
            st.finished_at = Some(chrono::Utc::now().to_rfc3339());
            tracing::info!(
                total = st.total,
                ok = st.ok,
                fail = st.fail,
                "socks run finished"
            );
        });

        SocksRunStart::Started {
            total: self.state.lock().unwrap().total,
        }
    }
}

pub static SOCKS_RUNNER: OnceCell<Arc<SocksRunner>> = OnceCell::const_new();
