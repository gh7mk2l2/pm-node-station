//! Relay integration test (no database, no real nodes):
//! a LOCAL fake upstream (127.0.0.1) speaking enough HTTP-proxy protocol to
//! answer CONNECT 200 and echo bytes, driven through the relay's real
//! CONNECT-exchange + tunnel-piping code. Verifies chaining works and byte
//! counts are exact for a known payload.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use pm_node_station::relay::{handle_connect_exchange, run_tunnel, RelayLimits, UsageTracker};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn read_head(stream: &mut TcpStream) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await.expect("read head");
        assert!(n > 0, "connection closed while reading head");
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            return buf;
        }
    }
}

fn generous_limits() -> RelayLimits {
    RelayLimits {
        daily: i64::MAX / 2,
        monthly: i64::MAX / 2,
        burst: i64::MAX / 2,
        burst_window_secs: 60,
    }
}

/// Fake upstream: accept one connection, expect CONNECT + upstream creds,
/// answer 200, then echo every byte back until EOF.
async fn fake_upstream_echo(listener: TcpListener) -> Vec<u8> {
    let (mut conn, _) = listener.accept().await.expect("upstream accept");
    let head = read_head(&mut conn).await;
    let head_str = String::from_utf8_lossy(&head);
    assert!(
        head_str.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
        "unexpected CONNECT head: {head_str}"
    );
    let expect = STANDARD.encode("upuser:uppass");
    assert!(
        head_str.contains(&format!("Proxy-Authorization: Basic {expect}")),
        "upstream creds missing/wrong in: {head_str}"
    );
    conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .unwrap();
    let mut echoed = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match conn.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                echoed.extend_from_slice(&chunk[..n]);
                conn.write_all(&chunk[..n]).await.unwrap();
            }
            Err(_) => break,
        }
    }
    echoed
}

#[tokio::test]
async fn connect_chaining_echoes_with_exact_byte_counts() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let upstream_task = tokio::spawn(fake_upstream_echo(upstream_listener));

    // Client side: CONNECT, read 200, send a known payload, read the echo.
    let payload: &[u8] = b"hello-relay-payload-12345";
    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic dGVzdDp0ZXN0\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        assert!(
            String::from_utf8_lossy(&head).starts_with("HTTP/1.1 200"),
            "expected 200, got: {}",
            String::from_utf8_lossy(&head)
        );
        client.write_all(payload).await.unwrap();
        let mut echo = vec![0u8; payload.len()];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, payload);
        client.shutdown().await.unwrap();
        echo
    });

    // Relay side: accept, consume the client's CONNECT head (as serve() does
    // via read_head — otherwise the head would be forwarded as tunnel data),
    // dial the fake upstream, run the real exchange + tunnel.
    let (mut client_side, _) = relay_listener.accept().await.unwrap();
    let _client_head = read_head(&mut client_side).await;
    let mut upstream_side = TcpStream::connect(upstream_addr).await.unwrap();
    handle_connect_exchange(
        &mut client_side,
        &mut upstream_side,
        "example.com:443",
        Some("upuser"),
        Some("uppass"),
    )
    .await
    .expect("CONNECT exchange must succeed");
    let tracker = Arc::new(UsageTracker::new());
    let (up, down, breach) = run_tunnel(
        client_side,
        upstream_side,
        tracker.clone(),
        generous_limits(),
    )
    .await;

    let echo = client_task.await.unwrap();
    let echoed = upstream_task.await.unwrap();
    assert_eq!(echo, payload);
    assert_eq!(echoed, payload);
    assert_eq!(up, payload.len() as u64, "bytes_up must equal payload");
    assert_eq!(down, payload.len() as u64, "bytes_down must equal payload");
    assert!(breach.is_none());
    use std::sync::atomic::Ordering;
    assert_eq!(
        tracker.daily_bytes.load(Ordering::Relaxed),
        (payload.len() * 2) as u64
    );
    println!(
        "relay integration: payload={} up={} down={} exact",
        payload.len(),
        up,
        down
    );
}

#[tokio::test]
async fn upstream_rejection_becomes_502_to_client() {
    let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = upstream_listener.local_addr().unwrap();
    let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let upstream_task = tokio::spawn(async move {
        let (mut conn, _) = upstream_listener.accept().await.unwrap();
        let _head = read_head(&mut conn).await;
        conn.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
    });

    let client_task = tokio::spawn(async move {
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let head = read_head(&mut client).await;
        String::from_utf8_lossy(&head).into_owned()
    });

    let (mut client_side, _) = relay_listener.accept().await.unwrap();
    let mut upstream_side = TcpStream::connect(upstream_addr).await.unwrap();
    let res = handle_connect_exchange(
        &mut client_side,
        &mut upstream_side,
        "example.com:443",
        Some("upuser"),
        Some("uppass"),
    )
    .await;
    assert!(res.is_err(), "non-200 upstream must fail the exchange");
    let client_head = client_task.await.unwrap();
    assert!(
        client_head.starts_with("HTTP/1.1 502"),
        "client must get 502, got: {client_head}"
    );
    upstream_task.await.unwrap();
    println!("relay integration: upstream 403 -> client 502 confirmed");
}
