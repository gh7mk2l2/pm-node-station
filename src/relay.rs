//! Tier-2 relay: forces tier-2 (residential) traffic through the station.
//!
//! Why a relay exists at all: a tier-2 subscription's raw node credentials let
//! anyone connect directly to the upstream residential proxies, bypassing all
//! quotas. The station therefore only ever hands out relay URIs for tier 2
//! (`https://{sub_token}:n{pos}@relay.pmcat.top:443`), and this relay dials the
//! real upstream node on the user's behalf.
//!
//! Known deviation (relay.pmcat.top is DNS-only / grey cloud, so the relay
//! itself terminates TLS for relay.pmcat.top with a Let's Encrypt cert;
//! the tunnel ingress is `tcp://127.0.0.1:8890` and forwards raw TCP):
//! behind the tunnel the relay only ever sees 127.0.0.1 as the client IP, so
//! the per-user device limit (distinct source IPs) CANNOT be enforced here.
//! That limit stays enforced at subscription-pull level (subs.rs). The relay
//! enforces per-user byte quotas + burst ban + a connection-rate guard.
//! No fake IP check is implemented anywhere in this module.
//!
//! Auth: Proxy-Authorization Basic base64(sub_token:n<pos>), where pos is the
//! 1-based position of the node in the ACTIVE tier-2 batch's deduped node
//! array (same dedupe_nodes order subs.rs uses).
//!
//! The relay ONLY ever dials configured tier-2 upstream nodes, never arbitrary
//! hosts directly. Upstream credentials and sub_tokens are never logged.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Datelike, NaiveDate, Utc};
use sqlx::PgPool;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::nodes::{dedupe_nodes, parse_node_endpoint, read_node_name};

/// Settings keys for relay quota overrides (values are JSON numbers, bytes).
/// Absent/invalid/non-positive values fall back to the defaults below.
pub const KEY_RELAY_DAILY_LIMIT: &str = "relay_daily_limit_bytes";
pub const KEY_RELAY_MONTHLY_LIMIT: &str = "relay_monthly_limit_bytes";
pub const KEY_RELAY_BURST_LIMIT: &str = "relay_burst_limit_bytes";
pub const KEY_RELAY_BURST_WINDOW: &str = "relay_burst_window_seconds";

pub const DEFAULT_DAILY_LIMIT: i64 = 5_000_000_000; // 5 GB
pub const DEFAULT_MONTHLY_LIMIT: i64 = 50_000_000_000; // 50 GB
pub const DEFAULT_BURST_LIMIT: i64 = 1_000_000_000; // 1 GB
pub const DEFAULT_BURST_WINDOW_SECS: i64 = 60;

pub const MAX_NEW_CONNECTIONS_PER_MIN: usize = 60;
pub const MAX_CONNECTIONS: usize = 512;
pub const IDLE_TIMEOUT_SECS: u64 = 120;
pub const HEAD_MAX_BYTES: usize = 16 * 1024;
pub const CLIENT_HEAD_TIMEOUT: Duration = Duration::from_secs(15);
pub const UPSTREAM_HEAD_TIMEOUT: Duration = Duration::from_secs(10);
pub const UPSTREAM_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// Pure helpers: relay URIs, auth parsing, quota decisions, request building
// ---------------------------------------------------------------------------

/// Percent-encode a URI fragment the same way nodes.rs does (unreserved kept,
/// everything else %XX uppercase).
pub fn url_encode_fragment(s: &str) -> String {
    let mut out = String::new();
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build relay URIs for a tier-2 node list: one `https://{sub_token}:n{i}@host:port`
/// per node, i = 1-based array position, fragment = the node's existing name.
/// The output contains no upstream server, username or password.
pub fn relay_uris(nodes: &[String], sub_token: &str, host: &str, port: u16) -> Vec<String> {
    nodes
        .iter()
        .enumerate()
        .map(|(i, uri)| {
            let name = read_node_name(uri);
            format!(
                "https://{}:n{}@{}:{}#{}",
                sub_token,
                i + 1,
                host,
                port,
                url_encode_fragment(&name)
            )
        })
        .collect()
}

/// Parse a Proxy-Authorization header value: `Basic base64(uuid:n<pos>)`.
/// Returns (sub_token uuid, 1-based node position). Anything else -> None.
pub fn parse_proxy_auth(header: &str) -> Option<(Uuid, usize)> {
    let mut parts = header.splitn(2, ' ');
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let b64 = parts.next()?.trim();
    if b64.is_empty() {
        return None;
    }
    let decoded = decode_b64_lenient(b64)?;
    let (user, pass) = decoded.split_once(':')?;
    let uuid = Uuid::parse_str(user.trim()).ok()?;
    let pos_str = pass.strip_prefix('n')?;
    let pos: usize = pos_str.parse().ok()?;
    if pos == 0 {
        return None;
    }
    Some((uuid, pos))
}

fn decode_b64_lenient(s: &str) -> Option<String> {
    let bytes = STANDARD
        .decode(s)
        .or_else(|_| {
            let padded = format!("{}{}", s, "=".repeat((4 - s.len() % 4) % 4));
            STANDARD.decode(padded.as_bytes())
        })
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Relay quota limits (bytes; burst window in seconds).
#[derive(Debug, Clone, Copy)]
pub struct RelayLimits {
    pub daily: i64,
    pub monthly: i64,
    pub burst: i64,
    pub burst_window_secs: i64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            daily: DEFAULT_DAILY_LIMIT,
            monthly: DEFAULT_MONTHLY_LIMIT,
            burst: DEFAULT_BURST_LIMIT,
            burst_window_secs: DEFAULT_BURST_WINDOW_SECS,
        }
    }
}

/// Quota decision for a user's current usage totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaOutcome {
    Ok,
    DailyExceeded,
    MonthlyExceeded,
    BurstExceeded,
}

impl QuotaOutcome {
    pub fn as_outcome_str(&self) -> &'static str {
        match self {
            QuotaOutcome::Ok => "ok",
            QuotaOutcome::DailyExceeded => "quota_daily",
            QuotaOutcome::MonthlyExceeded => "quota_monthly",
            QuotaOutcome::BurstExceeded => "burst_ban",
        }
    }
}

/// Burst is checked first: a burst that also exceeds daily/monthly still bans.
pub fn evaluate_usage(daily: i64, monthly: i64, burst: i64, limits: &RelayLimits) -> QuotaOutcome {
    if burst > limits.burst {
        return QuotaOutcome::BurstExceeded;
    }
    if daily > limits.daily {
        return QuotaOutcome::DailyExceeded;
    }
    if monthly > limits.monthly {
        return QuotaOutcome::MonthlyExceeded;
    }
    QuotaOutcome::Ok
}

/// Load relay limits from the settings table (one query); fall back to
/// defaults per key when absent, invalid or non-positive.
pub async fn load_relay_limits(pool: &PgPool) -> RelayLimits {
    let mut limits = RelayLimits::default();
    let rows: Vec<(String, serde_json::Value)> =
        sqlx::query_as("SELECT key, value FROM settings WHERE key IN ($1, $2, $3, $4)")
            .bind(KEY_RELAY_DAILY_LIMIT)
            .bind(KEY_RELAY_MONTHLY_LIMIT)
            .bind(KEY_RELAY_BURST_LIMIT)
            .bind(KEY_RELAY_BURST_WINDOW)
            .fetch_all(pool)
            .await
            .unwrap_or_default();
    for (key, value) in rows {
        let n = match &value {
            serde_json::Value::Number(n) => n.as_i64(),
            serde_json::Value::String(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        };
        let Some(n) = n else { continue };
        if n <= 0 {
            continue;
        }
        match key.as_str() {
            KEY_RELAY_DAILY_LIMIT => limits.daily = n,
            KEY_RELAY_MONTHLY_LIMIT => limits.monthly = n,
            KEY_RELAY_BURST_LIMIT => limits.burst = n,
            KEY_RELAY_BURST_WINDOW => limits.burst_window_secs = n,
            _ => {}
        }
    }
    limits
}

/// Build the CONNECT request sent to the upstream HTTP proxy.
pub fn build_upstream_connect_request(
    target: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut s = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(u) = username {
        let p = password.unwrap_or("");
        let creds = STANDARD.encode(format!("{u}:{p}"));
        s.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    s.push_str("Proxy-Connection: Keep-Alive\r\n\r\n");
    s
}

/// Parse the status code out of an HTTP response head (`HTTP/1.1 200 ...`).
pub fn parse_http_status(head: &str) -> Option<u16> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    parts.next()?;
    parts.next()?.parse().ok()
}

/// Parse an HTTP request head into (request line, headers as (lowercase name, value)).
pub fn parse_head(head: &[u8]) -> Option<(String, Vec<(String, String)>)> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.lines();
    let request_line = lines.next()?.trim().to_string();
    if request_line.is_empty() {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
    }
    Some((request_line, headers))
}

pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Build the request head forwarded to the upstream proxy for an absolute-form
/// request: same method, origin-form path, all headers except Proxy-Authorization
/// (replaced with upstream creds) and Proxy-Connection (stripped), plus
/// `Connection: close` so the upstream closes after the response.
pub fn build_forwarded_request(
    method: &str,
    uri: &url::Url,
    headers: &[(String, String)],
    username: Option<&str>,
    password: Option<&str>,
) -> String {
    let mut path = uri.path().to_string();
    if path.is_empty() {
        path = "/".to_string();
    }
    if let Some(q) = uri.query() {
        path.push('?');
        path.push_str(q);
    }
    let mut out = format!("{method} {path} HTTP/1.1\r\n");
    for (k, v) in headers {
        if k == "proxy-authorization" || k == "proxy-connection" {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some(u) = username {
        let p = password.unwrap_or("");
        let creds = STANDARD.encode(format!("{u}:{p}"));
        out.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

// ---------------------------------------------------------------------------
// Live per-user usage tracking (in-memory; seeded lazily from DB aggregates)
// ---------------------------------------------------------------------------

struct SeedState {
    day: Option<NaiveDate>,
    month: Option<(i32, u32)>,
    burst_seeded: bool,
}

pub struct UsageTracker {
    pub daily_bytes: std::sync::atomic::AtomicU64,
    pub monthly_bytes: std::sync::atomic::AtomicU64,
    burst: Mutex<VecDeque<(Instant, u64)>>,
    conns: Mutex<VecDeque<Instant>>,
    seed: Mutex<SeedState>,
}

impl UsageTracker {
    pub fn new() -> Self {
        Self {
            daily_bytes: std::sync::atomic::AtomicU64::new(0),
            monthly_bytes: std::sync::atomic::AtomicU64::new(0),
            burst: Mutex::new(VecDeque::new()),
            conns: Mutex::new(VecDeque::new()),
            seed: Mutex::new(SeedState {
                day: None,
                month: None,
                burst_seeded: false,
            }),
        }
    }

    /// Add n bytes (either direction counts toward the quotas) and return the
    /// breach outcome, if any limit is now crossed.
    pub fn add(&self, n: u64, limits: &RelayLimits) -> Option<QuotaOutcome> {
        use std::sync::atomic::Ordering;
        let daily = self.daily_bytes.fetch_add(n, Ordering::Relaxed) + n;
        let monthly = self.monthly_bytes.fetch_add(n, Ordering::Relaxed) + n;
        let burst = {
            let now = Instant::now();
            let window = Duration::from_secs(limits.burst_window_secs.max(1) as u64);
            let mut q = self.burst.lock().unwrap();
            q.push_back((now, n));
            while let Some((t, _)) = q.front() {
                if now.duration_since(*t) > window {
                    q.pop_front();
                } else {
                    break;
                }
            }
            q.iter().map(|(_, b)| *b).sum::<u64>()
        };
        let outcome = evaluate_usage(daily as i64, monthly as i64, burst as i64, limits);
        if outcome == QuotaOutcome::Ok {
            None
        } else {
            Some(outcome)
        }
    }

    /// Burst bytes in the rolling window right now (for the start-of-connection check).
    pub fn burst_bytes_now(&self, window_secs: i64) -> u64 {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs.max(1) as u64);
        let mut q = self.burst.lock().unwrap();
        while let Some((t, _)) = q.front() {
            if now.duration_since(*t) > window {
                q.pop_front();
            } else {
                break;
            }
        }
        q.iter().map(|(_, b)| *b).sum()
    }

    /// New-connection rate guard: at most MAX_NEW_CONNECTIONS_PER_MIN starts
    /// per rolling minute. Returns false when the guard trips (and does not record).
    pub fn conn_allowed(&self) -> bool {
        let now = Instant::now();
        let mut q = self.conns.lock().unwrap();
        while let Some(t) = q.front() {
            if now.duration_since(*t) > Duration::from_secs(60) {
                q.pop_front();
            } else {
                break;
            }
        }
        if q.len() >= MAX_NEW_CONNECTIONS_PER_MIN {
            return false;
        }
        q.push_back(now);
        true
    }

    fn seed_state(&self) -> (Option<NaiveDate>, Option<(i32, u32)>, bool) {
        let s = self.seed.lock().unwrap();
        (s.day, s.month, s.burst_seeded)
    }

    fn set_seed(&self, day: NaiveDate, month: (i32, u32), burst_seeded: bool) {
        let mut s = self.seed.lock().unwrap();
        s.day = Some(day);
        s.month = Some(month);
        s.burst_seeded = burst_seeded;
    }
}

// ---------------------------------------------------------------------------
// Relay state + DB helpers
// ---------------------------------------------------------------------------

pub struct RelayState {
    pub pool: PgPool,
    pub trackers: Mutex<HashMap<i64, Arc<UsageTracker>>>,
    pub semaphore: Arc<Semaphore>,
}

impl RelayState {
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            trackers: Mutex::new(HashMap::new()),
            semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
        }
    }

    pub fn tracker_for(&self, user_id: i64) -> Arc<UsageTracker> {
        let mut map = self.trackers.lock().unwrap();
        map.entry(user_id)
            .or_insert_with(|| Arc::new(UsageTracker::new()))
            .clone()
    }

    /// Seed a tracker's counters from DB aggregates (Shanghai day/month, rolling
    /// burst window). Only re-seeds when the Shanghai day/month rolled over, or
    /// on first use; in-memory live bytes are never wiped by a re-seed.
    pub async fn ensure_seeded(
        &self,
        tracker: &UsageTracker,
        user_id: i64,
        burst_window_secs: i64,
    ) {
        let today = crate::timeutil::shanghai_today();
        let this_month = (today.year(), today.month());
        let (seeded_day, seeded_month, burst_seeded) = tracker.seed_state();
        if seeded_day == Some(today) && seeded_month == Some(this_month) && burst_seeded {
            return;
        }
        let row: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT \
               coalesce(sum(bytes_up + bytes_down) FILTER (WHERE started_at >= (date_trunc('day', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai')), 0)::bigint, \
               coalesce(sum(bytes_up + bytes_down) FILTER (WHERE started_at >= (date_trunc('month', now() AT TIME ZONE 'Asia/Shanghai') AT TIME ZONE 'Asia/Shanghai')), 0)::bigint, \
               coalesce(sum(bytes_up + bytes_down) FILTER (WHERE started_at >= now() - ($2::bigint * interval '1 second')), 0)::bigint \
             FROM relay_sessions WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(burst_window_secs)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        use std::sync::atomic::Ordering;
        if let Some((daily, monthly, burst)) = row {
            if seeded_day != Some(today) {
                tracker
                    .daily_bytes
                    .store(daily.max(0) as u64, Ordering::Relaxed);
            }
            if seeded_month != Some(this_month) {
                tracker
                    .monthly_bytes
                    .store(monthly.max(0) as u64, Ordering::Relaxed);
            }
            if !burst_seeded && burst > 0 {
                let mut q = tracker.burst.lock().unwrap();
                q.push_back((Instant::now(), burst.max(0) as u64));
            }
        }
        tracker.set_seed(today, this_month, true);
    }
}

/// Delete relay session rows older than 40 days (monthly quota needs 30).
pub async fn prune_old_sessions(pool: &PgPool) -> sqlx::Result<u64> {
    let r = sqlx::query("DELETE FROM relay_sessions WHERE started_at < now() - interval '40 days'")
        .execute(pool)
        .await?;
    Ok(r.rows_affected())
}

async fn record_session(
    pool: &PgPool,
    user_id: i64,
    node_index: i32,
    client_ip: &str,
    bytes_up: u64,
    bytes_down: u64,
    started_at: DateTime<Utc>,
    outcome: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO relay_sessions (user_id, node_index, client_ip, bytes_up, bytes_down, started_at, ended_at, outcome) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), $7)",
    )
    .bind(user_id)
    .bind(node_index)
    .bind(client_ip)
    .bind(bytes_up as i64)
    .bind(bytes_down as i64)
    .bind(started_at)
    .bind(outcome)
    .execute(pool)
    .await;
}

/// Silent burst ban: generic to the outside world, audit-logged inside.
async fn ban_for_burst(pool: &PgPool, user_id: i64) {
    let _ = sqlx::query(
        "UPDATE users SET is_banned = TRUE, ban_reason = $2, updated_at = now() WHERE id = $1",
    )
    .bind(user_id)
    .bind("relay_burst")
    .execute(pool)
    .await;
    crate::audit::write_audit(
        pool,
        None,
        "user.ban",
        Some("user"),
        Some(&user_id.to_string()),
        serde_json::json!({"reason": "relay_burst"}),
    )
    .await;
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

/// Read one HTTP head (up to and including \r\n\r\n), cap HEAD_MAX_BYTES.
/// Returns (head bytes, leftover bytes already read past the head).
/// Generic over the stream so the relay can sit behind TLS (TlsStream)
/// as well as plain TCP; the upstream side stays plain TcpStream.
async fn read_head<S: AsyncRead + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > HEAD_MAX_BYTES {
            anyhow::bail!("head too large");
        }
        let n = tokio::time::timeout(timeout, stream.read(&mut chunk))
            .await
            .map_err(|_| anyhow::anyhow!("head read timeout"))??;
        if n == 0 {
            anyhow::bail!("connection closed while reading head");
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = buf[..pos + 4].to_vec();
            let rest = buf[pos + 4..].to_vec();
            return Ok((head, rest));
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn write_error<S: AsyncWrite + Unpin>(stream: &mut S, code: u16, reason: &str, extra_headers: &str) {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\n{extra_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let _ = stream.write_all(resp.as_bytes()).await;
    let _ = stream.shutdown().await;
}

/// CONNECT exchange: send CONNECT to the upstream proxy, read its response
/// head; on 200 reply `200 Connection Established` to the client. On any
/// other status (or error) write 502 to the client and return Err.
pub async fn handle_connect_exchange<C: AsyncWrite + Unpin>(
    client: &mut C,
    upstream: &mut TcpStream,
    target: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let req = build_upstream_connect_request(target, username, password);
    upstream.write_all(req.as_bytes()).await?;
    let (head, _) = read_head(upstream, UPSTREAM_HEAD_TIMEOUT).await?;
    let status = parse_http_status(std::str::from_utf8(&head).unwrap_or("")).unwrap_or(0);
    if status == 200 {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        Ok(())
    } else {
        write_error(client, 502, "Bad Gateway", "").await;
        anyhow::bail!("upstream CONNECT rejected: {status}");
    }
}

fn transfer_idle_deadline() -> Instant {
    Instant::now() + Duration::from_secs(IDLE_TIMEOUT_SECS)
}

/// One direction of a tunnel: copy bytes, count them, kill the stream when a
/// live quota is crossed. Returns bytes transferred in this direction.
async fn transfer<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    tracker: Arc<UsageTracker>,
    limits: &RelayLimits,
    breach: Arc<Mutex<Option<QuotaOutcome>>>,
) -> u64 {
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    let mut deadline = transfer_idle_deadline();
    loop {
        if breach.lock().unwrap().is_some() {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        // Short slices so a breach/idle in the other direction ends us promptly.
        let slice = remaining.min(Duration::from_secs(5));
        match tokio::time::timeout(slice, reader.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                deadline = transfer_idle_deadline();
                total += n as u64;
                if let Some(outcome) = tracker.add(n as u64, limits) {
                    *breach.lock().unwrap() = Some(outcome);
                    break;
                }
                if writer.write_all(&buf[..n]).await.is_err() {
                    break;
                }
            }
            Ok(Err(_)) => break,
            Err(_) => {
                // Slice timeout: loop re-checks idle deadline + breach flag.
                continue;
            }
        }
    }
    let _ = writer.shutdown().await;
    total
}

/// Bidirectional piping after the tunnel is established. Returns
/// (bytes_up, bytes_down, breach outcome if a live limit was crossed).
/// The client side is generic (plain TcpStream or TlsStream<TcpStream>);
/// the upstream side is always plain TCP to the tier-2 node.
pub async fn run_tunnel<C: AsyncRead + AsyncWrite + Unpin>(
    client: C,
    upstream: TcpStream,
    tracker: Arc<UsageTracker>,
    limits: RelayLimits,
) -> (u64, u64, Option<QuotaOutcome>) {
    let (cr, cw) = tokio::io::split(client);
    let (ur, uw) = tokio::io::split(upstream);
    let breach: Arc<Mutex<Option<QuotaOutcome>>> = Arc::new(Mutex::new(None));
    let (up, down) = tokio::join!(
        transfer(cr, uw, tracker.clone(), &limits, breach.clone()),
        transfer(ur, cw, tracker.clone(), &limits, breach.clone()),
    );
    let result = (up, down, breach.lock().unwrap().take());
    result
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// Serve one relay connection. Never logs tokens or upstream credentials.
/// Returns (outcome, user_id, node_index, bytes_up, bytes_down) for the
/// session row; the caller records the row asynchronously.
/// The client stream is generic (plain TcpStream or TlsStream<TcpStream>).
/// TCP_NODELAY is set on the raw socket by the binary before the TLS wrap.
async fn serve<C: AsyncRead + AsyncWrite + Unpin>(
    state: &RelayState,
    mut stream: C,
) -> (String, Option<i64>, Option<i32>, u64, u64) {
    let (head, leftover) = match read_head(&mut stream, CLIENT_HEAD_TIMEOUT).await {
        Ok(v) => v,
        Err(_) => {
            write_error(&mut stream, 400, "Bad Request", "").await;
            return ("client_error".into(), None, None, 0, 0);
        }
    };
    let (request_line, headers) = match parse_head(&head) {
        Some(v) => v,
        None => {
            write_error(&mut stream, 400, "Bad Request", "").await;
            return ("client_error".into(), None, None, 0, 0);
        }
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_ascii_uppercase();
    let target_raw = parts.next().unwrap_or("").to_string();
    if method.is_empty() || target_raw.is_empty() {
        write_error(&mut stream, 400, "Bad Request", "").await;
        return ("client_error".into(), None, None, 0, 0);
    }

    // Target: CONNECT host:port, or absolute-form URI. Origin-form -> 400.
    enum Target {
        Connect(String),
        Absolute(url::Url),
    }
    let target = if method == "CONNECT" {
        match validate_connect_target(&target_raw) {
            Some(t) => Target::Connect(t),
            None => {
                write_error(&mut stream, 400, "Bad Request", "").await;
                return ("client_error".into(), None, None, 0, 0);
            }
        }
    } else if target_raw.starts_with("http://") || target_raw.starts_with("https://") {
        match url::Url::parse(&target_raw) {
            Ok(u) if u.host_str().is_some() => Target::Absolute(u),
            _ => {
                write_error(&mut stream, 400, "Bad Request", "").await;
                return ("client_error".into(), None, None, 0, 0);
            }
        }
    } else {
        write_error(&mut stream, 400, "Bad Request", "").await;
        return ("client_error".into(), None, None, 0, 0);
    };
    // For CONNECT the upstream dial target is the requested host:port; for
    // absolute-form it is the URI's host:port.
    let dial_target = match &target {
        Target::Connect(t) => t.clone(),
        Target::Absolute(u) => format!(
            "{}:{}",
            u.host_str().unwrap_or(""),
            u.port_or_known_default().unwrap_or(80)
        ),
    };

    // Auth (missing/invalid -> 407, never reveal which part failed).
    let auth_header = header_value(&headers, "proxy-authorization").unwrap_or("");
    let Some((sub_token, pos)) = parse_proxy_auth(auth_header) else {
        write_error(
            &mut stream,
            407,
            "Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"PM Node Relay\"\r\n",
        )
        .await;
        return ("client_error".into(), None, None, 0, 0);
    };

    // User lookup (unknown -> 407, banned -> 503 generic).
    let user: Option<(i64, bool)> =
        sqlx::query_as("SELECT id, is_banned FROM users WHERE sub_token = $1")
            .bind(sub_token.to_string())
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten();
    let Some((user_id, is_banned)) = user else {
        write_error(
            &mut stream,
            407,
            "Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"PM Node Relay\"\r\n",
        )
        .await;
        return ("client_error".into(), None, None, 0, 0);
    };
    if is_banned {
        write_error(&mut stream, 503, "Service Unavailable", "").await;
        return ("banned".into(), Some(user_id), None, 0, 0);
    }

    // Node resolution: active tier-2 batch -> dedupe -> pos -> endpoint.
    let batch_nodes: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT nodes FROM node_batches WHERE is_active = TRUE AND tier = 2 ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();
    let nodes: Vec<String> = batch_nodes
        .as_ref()
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let nodes = dedupe_nodes(&nodes);
    let Some(node_uri) = nodes.get(pos - 1) else {
        write_error(&mut stream, 502, "Bad Gateway", "").await;
        return (
            "upstream_error".into(),
            Some(user_id),
            Some(pos as i32),
            0,
            0,
        );
    };
    let node_index = pos as i32;
    let Some(ep) = parse_node_endpoint(node_uri) else {
        write_error(&mut stream, 502, "Bad Gateway", "").await;
        return (
            "upstream_error".into(),
            Some(user_id),
            Some(node_index),
            0,
            0,
        );
    };
    let upstream_addr = format!("{}:{}", ep.host, ep.port);

    // Limits + live usage (seeded from DB on first use / day-month rollover).
    let limits = load_relay_limits(&state.pool).await;
    let tracker = state.tracker_for(user_id);
    state
        .ensure_seeded(&tracker, user_id, limits.burst_window_secs)
        .await;
    {
        use std::sync::atomic::Ordering;
        let daily = tracker.daily_bytes.load(Ordering::Relaxed) as i64;
        let monthly = tracker.monthly_bytes.load(Ordering::Relaxed) as i64;
        let burst = tracker.burst_bytes_now(limits.burst_window_secs) as i64;
        match evaluate_usage(daily, monthly, burst, &limits) {
            QuotaOutcome::Ok => {}
            QuotaOutcome::BurstExceeded => {
                ban_for_burst(&state.pool, user_id).await;
                write_error(&mut stream, 503, "Service Unavailable", "").await;
                return ("burst_ban".into(), Some(user_id), Some(node_index), 0, 0);
            }
            QuotaOutcome::DailyExceeded => {
                write_error(&mut stream, 503, "Service Unavailable", "").await;
                return ("quota_daily".into(), Some(user_id), Some(node_index), 0, 0);
            }
            QuotaOutcome::MonthlyExceeded => {
                write_error(&mut stream, 503, "Service Unavailable", "").await;
                return (
                    "quota_monthly".into(),
                    Some(user_id),
                    Some(node_index),
                    0,
                    0,
                );
            }
        }
    }
    if !tracker.conn_allowed() {
        write_error(&mut stream, 503, "Service Unavailable", "").await;
        return ("rate_limited".into(), Some(user_id), Some(node_index), 0, 0);
    }

    // Dial the upstream node (only ever a configured tier-2 node).
    let upstream =
        match tokio::time::timeout(UPSTREAM_DIAL_TIMEOUT, TcpStream::connect(&upstream_addr)).await
        {
            Ok(Ok(s)) => s,
            _ => {
                write_error(&mut stream, 502, "Bad Gateway", "").await;
                return (
                    "upstream_error".into(),
                    Some(user_id),
                    Some(node_index),
                    0,
                    0,
                );
            }
        };
    let _ = upstream.set_nodelay(true);
    let mut upstream = upstream;

    // Bytes forwarded before run_tunnel starts (CONNECT pipelining /
    // absolute-form request head) still count as tunnel bytes.
    let mut pre_up: u64 = 0;

    match target {
        Target::Connect(_) => {
            if handle_connect_exchange(
                &mut stream,
                &mut upstream,
                &dial_target,
                ep.username.as_deref(),
                ep.password.as_deref(),
            )
            .await
            .is_err()
            {
                return (
                    "upstream_error".into(),
                    Some(user_id),
                    Some(node_index),
                    0,
                    0,
                );
            }
            // Any bytes pipelined after the CONNECT head belong to the tunnel.
            if !leftover.is_empty() {
                if upstream.write_all(&leftover).await.is_err() {
                    return (
                        "upstream_error".into(),
                        Some(user_id),
                        Some(node_index),
                        0,
                        0,
                    );
                }
                pre_up = leftover.len() as u64;
                tracker.add(pre_up, &limits);
            }
        }
        Target::Absolute(ref uri) => {
            let fwd = build_forwarded_request(
                &method,
                uri,
                &headers,
                ep.username.as_deref(),
                ep.password.as_deref(),
            );
            if upstream.write_all(fwd.as_bytes()).await.is_err()
                || (!leftover.is_empty() && upstream.write_all(&leftover).await.is_err())
            {
                return (
                    "upstream_error".into(),
                    Some(user_id),
                    Some(node_index),
                    0,
                    0,
                );
            }
            let sent = fwd.len() as u64 + leftover.len() as u64;
            pre_up = sent;
            if let Some(o) = tracker.add(sent, &limits) {
                if o == QuotaOutcome::BurstExceeded {
                    ban_for_burst(&state.pool, user_id).await;
                }
                write_error(&mut stream, 503, "Service Unavailable", "").await;
                return (
                    o.as_outcome_str().into(),
                    Some(user_id),
                    Some(node_index),
                    sent,
                    0,
                );
            }
        }
    }

    let (bytes_up, bytes_down, breach) =
        run_tunnel(stream, upstream, tracker.clone(), limits).await;
    let outcome = match breach {
        Some(QuotaOutcome::BurstExceeded) => {
            ban_for_burst(&state.pool, user_id).await;
            "burst_ban"
        }
        Some(QuotaOutcome::DailyExceeded) => "quota_daily",
        Some(QuotaOutcome::MonthlyExceeded) => "quota_monthly",
        Some(QuotaOutcome::Ok) | None => "ok",
    };
    (
        outcome.to_string(),
        Some(user_id),
        Some(node_index),
        bytes_up + pre_up,
        bytes_down,
    )
}

fn validate_connect_target(target: &str) -> Option<String> {
    // host:port, no brackets/paths, port 1..=65535.
    if target.contains('/') || target.contains('?') || target.contains('#') {
        return None;
    }
    let (host, port) = if let Some(stripped) = target.strip_prefix('[') {
        let end = stripped.find(']')?;
        let host = &stripped[..end];
        let rest = &stripped[end + 1..];
        (
            host.to_string(),
            rest.strip_prefix(':')?.parse::<u16>().ok()?,
        )
    } else {
        let colon = target.rfind(':')?;
        let host = &target[..colon];
        let port: u16 = target[colon + 1..].parse().ok()?;
        (host.to_string(), port)
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some(format!("{host}:{port}"))
}

/// Handle one accepted connection: global cap, serve, async session row.
/// client_ip is the peer address as seen (behind the tunnel: 127.0.0.1).
/// The stream is generic: plain TcpStream or TlsStream<TcpStream>.
pub async fn handle_connection<C: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    state: Arc<RelayState>,
    stream: C,
    client_ip: String,
) {
    let Ok(_permit) = state.semaphore.clone().try_acquire_owned() else {
        return; // over the global cap: drop silently
    };
    let started = Utc::now();
    let (outcome, user_id, node_index, bytes_up, bytes_down) = serve(&state, stream).await;
    if let (Some(uid), Some(nidx)) = (user_id, node_index) {
        let pool = state.pool.clone();
        let outcome_for_row = outcome.clone();
        tokio::spawn(async move {
            record_session(
                &pool,
                uid,
                nidx,
                &client_ip,
                bytes_up,
                bytes_down,
                started,
                &outcome_for_row,
            )
            .await;
        });
        tracing::info!(
            user_id = uid,
            node_index = nidx,
            bytes_up,
            bytes_down,
            outcome = %outcome,
            "relay session"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_token() -> String {
        "11111111-2222-3333-4444-555555555555".to_string()
    }

    #[test]
    fn relay_uris_positions_and_encoding() {
        let nodes = vec![
            "http://user1:pass1@203.0.113.213:62000#%F0%9F%87%BA%F0%9F%87%B8%E4%BA%8C%E7%BA%A7%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B91".to_string(),
            "http://user2:pass2@203.0.113.36:62001#%F0%9F%87%BA%F0%9F%87%B8%E4%BA%8C%E7%BA%A7%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B92".to_string(),
        ];
        let out = relay_uris(&nodes, &dummy_token(), "relay.pmcat.top", 443);
        assert_eq!(out.len(), 2);
        assert!(out[0].starts_with(&format!(
            "https://{}:n1@relay.pmcat.top:443#",
            dummy_token()
        )));
        assert!(out[1].starts_with(&format!(
            "https://{}:n2@relay.pmcat.top:443#",
            dummy_token()
        )));
        // Names survive round-trip through the fragment.
        assert_eq!(read_node_name(&out[0]), "🇺🇸二级美国节点1");
        assert_eq!(read_node_name(&out[1]), "🇺🇸二级美国节点2");
        // No upstream data anywhere in the output.
        for u in &out {
            assert!(!u.contains("203.0.113.213"));
            assert!(!u.contains("203.0.113.36"));
            assert!(!u.contains("user1"));
            assert!(!u.contains("pass1"));
        }
        // Relay URIs are valid http-proxy URIs for the Clash/sing-box builders.
        let p = crate::clash::uri_to_clash_proxy(&out[0], "🇺🇸二级美国节点1").unwrap();
        let get = |k: &str| {
            p.iter().find(|(key, _)| key == k).map(|(_, v)| match v {
                crate::clash::YamlValue::Scalar(s) => s.clone(),
                crate::clash::YamlValue::Int(n) => n.to_string(),
                crate::clash::YamlValue::Bool(b) => b.to_string(),
                _ => String::new(),
            })
        };
        assert_eq!(get("type").as_deref(), Some("http"));
        assert_eq!(get("server").as_deref(), Some("relay.pmcat.top"));
        assert_eq!(get("port").as_deref(), Some("443"));
        assert_eq!(get("tls").as_deref(), Some("true"));
        assert_eq!(get("username").as_deref(), Some(dummy_token()).as_deref());
        assert_eq!(get("password").as_deref(), Some("n1"));
        let ob = crate::singbox::uri_to_singbox_outbound(&out[1], "🇺🇸二级美国节点2").unwrap();
        assert_eq!(ob["type"], "http");
        assert_eq!(ob["server"], "relay.pmcat.top");
        assert_eq!(ob["server_port"], 443);
        assert_eq!(ob["tls"]["enabled"], true);
        assert_eq!(ob["username"], dummy_token());
        assert_eq!(ob["password"], "n2");
    }

    #[test]
    fn proxy_auth_parsing() {
        let good = format!("Basic {}", STANDARD.encode(format!("{}:n7", dummy_token())));
        assert_eq!(
            parse_proxy_auth(&good),
            Some((Uuid::parse_str(&dummy_token()).unwrap(), 7))
        );
        // Case-insensitive scheme, surrounding spaces tolerated.
        let lower = format!("basic {}", STANDARD.encode(format!("{}:n1", dummy_token())));
        assert_eq!(
            parse_proxy_auth(&lower),
            Some((Uuid::parse_str(&dummy_token()).unwrap(), 1))
        );
        assert!(parse_proxy_auth("Basic not-base64!!").is_none());
        assert!(parse_proxy_auth("Bearer abc").is_none());
        assert!(parse_proxy_auth("Basic").is_none());
        assert!(parse_proxy_auth("").is_none());
        // Non-UUID user.
        let bad_user = format!("Basic {}", STANDARD.encode("not-a-uuid:n1"));
        assert!(parse_proxy_auth(&bad_user).is_none());
        // Bad password forms: n0, n-1, nabc, bare number, empty.
        for bad_pass in ["n0", "n-1", "nabc", "1", "", "N1"] {
            let h = format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{bad_pass}", dummy_token()))
            );
            assert!(
                parse_proxy_auth(&h).is_none(),
                "pass {bad_pass} must be rejected"
            );
        }
        // Missing colon.
        let no_colon = format!("Basic {}", STANDARD.encode(dummy_token()));
        assert!(parse_proxy_auth(&no_colon).is_none());
    }

    #[test]
    fn quota_decisions() {
        let limits = RelayLimits::default();
        assert_eq!(evaluate_usage(1, 1, 1, &limits), QuotaOutcome::Ok);
        // Exactly at the limit is still OK; one byte over trips.
        assert_eq!(
            evaluate_usage(DEFAULT_DAILY_LIMIT, 1, 1, &limits),
            QuotaOutcome::Ok
        );
        assert_eq!(
            evaluate_usage(DEFAULT_DAILY_LIMIT + 1, 1, 1, &limits),
            QuotaOutcome::DailyExceeded
        );
        assert_eq!(
            evaluate_usage(1, DEFAULT_MONTHLY_LIMIT + 1, 1, &limits),
            QuotaOutcome::MonthlyExceeded
        );
        assert_eq!(
            evaluate_usage(1, 1, DEFAULT_BURST_LIMIT + 1, &limits),
            QuotaOutcome::BurstExceeded
        );
        // Burst wins over daily/monthly (ban is the stronger action).
        assert_eq!(
            evaluate_usage(
                DEFAULT_DAILY_LIMIT + 1,
                DEFAULT_MONTHLY_LIMIT + 1,
                DEFAULT_BURST_LIMIT + 1,
                &limits
            ),
            QuotaOutcome::BurstExceeded
        );
    }

    #[test]
    fn upstream_connect_request_shape() {
        let req = build_upstream_connect_request("example.com:443", Some("upuser"), Some("uppass"));
        assert!(req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(req.contains("Host: example.com:443\r\n"));
        let expect = STANDARD.encode("upuser:uppass");
        assert!(req.contains(&format!("Proxy-Authorization: Basic {expect}\r\n")));
        assert!(req.contains("Proxy-Connection: Keep-Alive\r\n"));
        assert!(req.ends_with("\r\n\r\n"));
        // No creds -> no auth line, still valid.
        let req2 = build_upstream_connect_request("example.com:80", None, None);
        assert!(!req2.contains("Proxy-Authorization"));
        assert_eq!(
            parse_http_status("HTTP/1.1 200 Connection Established\r\n\r\n"),
            Some(200)
        );
        assert_eq!(
            parse_http_status("HTTP/1.1 403 Forbidden\r\n\r\n"),
            Some(403)
        );
        assert_eq!(parse_http_status("garbage"), None);
    }

    #[test]
    fn forwarded_request_rewrites_auth_and_closes() {
        let uri = url::Url::parse("http://example.com/a/b?x=1").unwrap();
        let headers = vec![
            ("host".to_string(), "example.com".to_string()),
            (
                "proxy-authorization".to_string(),
                "Basic OLDCREDS".to_string(),
            ),
            ("proxy-connection".to_string(), "keep-alive".to_string()),
            ("user-agent".to_string(), "curl/8".to_string()),
        ];
        let out = build_forwarded_request("GET", &uri, &headers, Some("u"), Some("p"));
        assert!(out.starts_with("GET /a/b?x=1 HTTP/1.1\r\n"));
        assert!(out.contains("host: example.com\r\n"));
        assert!(out.contains("user-agent: curl/8\r\n"));
        assert!(!out.contains("OLDCREDS"));
        assert!(!out.contains("proxy-connection"));
        let expect = STANDARD.encode("u:p");
        assert!(out.contains(&format!("Proxy-Authorization: Basic {expect}\r\n")));
        assert!(out.contains("Connection: close\r\n"));
    }

    #[test]
    fn connect_target_validation() {
        assert_eq!(
            validate_connect_target("example.com:443"),
            Some("example.com:443".to_string())
        );
        assert_eq!(
            validate_connect_target("[::1]:8080"),
            Some("::1:8080".to_string())
        );
        assert!(validate_connect_target("example.com").is_none());
        assert!(validate_connect_target("example.com:0").is_none());
        assert!(validate_connect_target("example.com:99999").is_none());
        assert!(validate_connect_target("example.com:443/path").is_none());
        assert!(validate_connect_target(":443").is_none());
        assert!(validate_connect_target("").is_none());
    }

    #[test]
    fn tracker_rate_guard() {
        let t = UsageTracker::new();
        for _ in 0..MAX_NEW_CONNECTIONS_PER_MIN {
            assert!(t.conn_allowed());
        }
        assert!(!t.conn_allowed());
    }
}
