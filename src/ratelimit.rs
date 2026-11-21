//! 进程内滑动窗口限流（单实例部署足够）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub struct RateLimiter {
    buckets: Mutex<HashMap<String, Vec<Instant>>>,
    max_keys: usize,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            max_keys: 10_000,
        }
    }

    /// 滑动窗口：窗口内超过 max 次返回 Err(重试秒数)
    pub fn check(&self, key: &str, max: usize, window: std::time::Duration) -> Result<(), u64> {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().unwrap();
        if buckets.len() > self.max_keys {
            let oldest: Vec<String> = buckets.keys().take(self.max_keys / 2).cloned().collect();
            for k in oldest {
                buckets.remove(&k);
            }
        }
        let arr = buckets.entry(key.to_string()).or_default();
        arr.retain(|t| now.duration_since(*t) < window);
        if arr.len() >= max {
            let retry = window
                .checked_sub(now.duration_since(arr[0]))
                .map(|d| d.as_secs().max(1))
                .unwrap_or(1);
            return Err(retry);
        }
        arr.push(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn sliding_window_blocks_after_limit() {
        let rl = RateLimiter::new();
        for _ in 0..3 {
            assert!(rl.check("k", 3, Duration::from_secs(60)).is_ok());
        }
        assert!(rl.check("k", 3, Duration::from_secs(60)).is_err());
        assert!(rl.check("other", 3, Duration::from_secs(60)).is_ok());
    }

    #[test]
    fn window_expires() {
        let rl = RateLimiter::new();
        assert!(rl.check("k", 1, Duration::from_millis(5)).is_ok());
        assert!(rl.check("k", 1, Duration::from_millis(5)).is_err());
        std::thread::sleep(Duration::from_millis(10));
        assert!(rl.check("k", 1, Duration::from_millis(5)).is_ok());
    }
}
