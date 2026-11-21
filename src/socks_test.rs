//! 零依赖代理测活：手写 SOCKS5 握手 + 经代理发 HTTP/1.1 204 探测（原创实现）。
//! - DNS 走代理（SOCKS5h 语义），测真实可用性
//! - 全程超时控制，单条失败不影响整体

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const PROBE_HOST: &str = "www.gstatic.com";
pub const PROBE_PORT: u16 = 80;

#[derive(Debug, Clone)]
pub struct SocksCheckResult {
    pub ok: bool,
    pub latency_ms: i64,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProxyAuth {
    pub username: String,
    pub password: String,
}

fn tls_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// 统一入口：按协议分派到 SOCKS5 握手或 HTTP CONNECT
pub async fn check_proxy(
    host: &str,
    port: u16,
    protocol: &str,
    timeout_ms: u64,
    auth: Option<ProxyAuth>,
) -> SocksCheckResult {
    let t0 = Instant::now();
    let fut = async {
        match protocol {
            "socks5" => check_socks5_inner(host, port, auth).await,
            "http" => check_http_connect_inner(host, port, false, auth).await,
            "https" => check_http_connect_inner(host, port, true, auth).await,
            _ => Err("unknown protocol".to_string()),
        }
    };
    match tokio::time::timeout(Duration::from_millis(timeout_ms), fut).await {
        Ok(Ok(())) => SocksCheckResult {
            ok: true,
            latency_ms: t0.elapsed().as_millis() as i64,
            error: None,
        },
        Ok(Err(e)) => SocksCheckResult {
            ok: false,
            latency_ms: t0.elapsed().as_millis() as i64,
            error: Some(e),
        },
        Err(_) => SocksCheckResult {
            ok: false,
            latency_ms: timeout_ms as i64,
            error: Some("timeout".to_string()),
        },
    }
}

async fn read_http_status<R>(stream: &mut R) -> io::Result<u16>
where
    R: AsyncReadExt + Unpin,
{
    // 读到第一个 \r\n，解析 HTTP/1.x NNN
    let mut buf: Vec<u8> = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed-early"));
        }
        buf.push(byte[0]);
        if buf.len() > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "headers-too-large"));
        }
        if buf.ends_with(b"\r\n") {
            break;
        }
    }
    let line = String::from_utf8_lossy(&buf);
    let code: u16 = line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad-http-response"))?;
    Ok(code)
}

async fn read_headers_end<R>(stream: &mut R) -> io::Result<()>
where
    R: AsyncReadExt + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed-early"));
        }
        buf.push(byte[0]);
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "headers-too-large"));
        }
        // 无额外头时剩余数据就是单独一个空行 "\r\n"
        if buf == b"\r\n" {
            return Ok(());
        }
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(());
        }
    }
}

/// HTTP(S) 代理探测：可选 TLS 连接代理，再建立 CONNECT 隧道并请求 204
async fn check_http_connect_inner(
    host: &str,
    port: u16,
    use_tls: bool,
    auth: Option<ProxyAuth>,
) -> Result<(), String> {
    let stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| e.to_string())?;
    if use_tls {
        let config = tls_config();
        let server_name = match host.parse::<IpAddr>() {
            Ok(ip) => rustls::pki_types::ServerName::IpAddress(ip.into()),
            Err(_) => rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|_| "invalid server name".to_string())?,
        };
        let connector = tokio_rustls::TlsConnector::from(config);
        let mut tls = connector
            .connect(server_name, stream)
            .await
            .map_err(|e| e.to_string())?;
        probe_via_connect(&mut tls, auth).await
    } else {
        let mut plain = stream;
        probe_via_connect(&mut plain, auth).await
    }
}

async fn probe_via_connect<S>(stream: &mut S, auth: Option<ProxyAuth>) -> Result<(), String>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let auth_header = match &auth {
        Some(a) => {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            format!(
                "Proxy-Authorization: Basic {}\r\n",
                STANDARD.encode(format!("{}:{}", a.username, a.password).as_bytes())
            )
        }
        None => String::new(),
    };
    stream
        .write_all(
            format!(
                "CONNECT {PROBE_HOST}:{PROBE_PORT} HTTP/1.1\r\nHost: {PROBE_HOST}:{PROBE_PORT}\r\n{auth_header}\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let code = read_http_status(stream).await.map_err(|e| e.to_string())?;
    if code != 200 {
        return Err(format!("connect-reject-{code}"));
    }
    // 读掉 CONNECT 响应的剩余头
    read_headers_end(stream).await.map_err(|e| e.to_string())?;
    stream
        .write_all(
            format!(
                "GET /generate_204 HTTP/1.1\r\nHost: {PROBE_HOST}\r\nUser-Agent: pm-node-check/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let code = read_http_status(stream).await.map_err(|e| e.to_string())?;
    if code == 204 || code == 200 {
        Ok(())
    } else {
        Err(format!("probe-status-{code}"))
    }
}

async fn check_socks5_inner(
    host: &str,
    port: u16,
    auth: Option<ProxyAuth>,
) -> Result<(), String> {
    let mut stream = TcpStream::connect((host, port))
        .await
        .map_err(|e| e.to_string())?;

    // 阶段 0：方法协商
    if let Some(a) = &auth {
        if a.username.len() > 255 || a.password.len() > 255 {
            return Err("invalid-auth-length".to_string());
        }
        stream
            .write_all(&[0x05, 0x02, 0x00, 0x02])
            .await
            .map_err(|e| e.to_string())?;
    } else {
        stream
            .write_all(&[0x05, 0x01, 0x00])
            .await
            .map_err(|e| e.to_string())?;
    }
    let mut resp = [0u8; 2];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| e.to_string())?;
    if resp[0] != 0x05 {
        return Err("not-socks5".to_string());
    }
    let method = resp[1];
    if method == 0xff {
        return Err("no-acceptable-auth".to_string());
    }
    if method == 0x02 {
        let Some(a) = &auth else {
            return Err("auth-required".to_string());
        };
        let user = a.username.as_bytes();
        let pass = a.password.as_bytes();
        let mut req = vec![0x01, user.len() as u8];
        req.extend_from_slice(user);
        req.push(pass.len() as u8);
        req.extend_from_slice(pass);
        stream.write_all(&req).await.map_err(|e| e.to_string())?;
        let mut aresp = [0u8; 2];
        stream
            .read_exact(&mut aresp)
            .await
            .map_err(|e| e.to_string())?;
        if aresp[0] != 0x01 || aresp[1] != 0x00 {
            return Err("auth-rejected".to_string());
        }
    } else if method != 0x00 {
        return Err("unsupported-auth-method".to_string());
    }

    // 阶段 2：CONNECT（域名走代理解析，SOCKS5h 语义）
    let host_bytes = PROBE_HOST.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
    req.extend_from_slice(host_bytes);
    req.extend_from_slice(&PROBE_PORT.to_be_bytes());
    stream.write_all(&req).await.map_err(|e| e.to_string())?;

    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| e.to_string())?;
    if head[0] != 0x05 {
        return Err("bad-connect-response".to_string());
    }
    if head[1] != 0x00 {
        return Err(format!("connect-reject-0x{:02x}", head[1]));
    }
    let remain = match head[3] {
        0x01 => 6, // IPv4: 4 字节地址 + 2 字节端口（已读 4 字节头，剩 6）
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(|e| e.to_string())?;
            (len[0] as usize) + 2
        }
        0x04 => 18, // IPv6
        _ => return Err("bad-address-type".to_string()),
    };
    let mut rest = vec![0u8; remain];
    stream
        .read_exact(&mut rest)
        .await
        .map_err(|e| e.to_string())?;

    // 阶段 3：经隧道发 HTTP 204 探测
    stream
        .write_all(
            format!(
                "GET /generate_204 HTTP/1.1\r\nHost: {PROBE_HOST}\r\nUser-Agent: pm-node-check/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .map_err(|e| e.to_string())?;
    let code = read_http_status(&mut stream).await.map_err(|e| e.to_string())?;
    if code == 204 || code == 200 {
        Ok(())
    } else {
        Err(format!("probe-status-{code}"))
    }
}

/// 简单并发池：逐个领取任务执行，worker 数固定
pub async fn run_pool<T, F, Fut>(items: Vec<T>, concurrency: usize, worker: F)
where
    F: Fn(T) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
    T: Send + 'static,
{
    use std::sync::Arc;
    use tokio::sync::Mutex;
    let items = Arc::new(Mutex::new(items.into_iter()));
    let worker = Arc::new(worker);
    let lanes = (0..concurrency.max(1)).map(|_| {
        let items = items.clone();
        let worker = worker.clone();
        tokio::spawn(async move {
            loop {
                let item = { items.lock().await.next() };
                let Some(item) = item else { break };
                worker(item).await;
            }
        })
    });
    futures_util::future::join_all(lanes).await;
}
