//! pm-node-relay: tier-2 HTTP proxy relay for the PM node station.
//! Listens on RELAY_BIND (default 127.0.0.1:8890) behind the Cloudflare tunnel
//! (tcp:// ingress at relay.pmcat.top). Reads DATABASE_URL from the
//! environment; never runs migrations (the station applies them on startup).
//!
//! TLS: relay.pmcat.top is DNS-only (grey cloud), so the Cloudflare edge no
//! longer terminates TLS. This relay terminates TLS itself with a Let's
//! Encrypt certificate for relay.pmcat.top (RELAY_TLS_CERT / RELAY_TLS_KEY,
//! defaults under /data/pm-node-station-prod/relay-cert/). The port is
//! TLS-only: a plaintext HTTP connection is rejected at the handshake.
//! rustls + rustls-pemfile only; no OpenSSL / system TLS dependency.

use pm_node_station::relay::{handle_connection, prune_old_sessions, RelayState};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tracing_subscriber::{fmt, EnvFilter};

/// Load the TLS server config from PEM files. Fails fast at startup so a
/// missing/expired certificate is caught immediately, not per-connection.
fn load_tls_config(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert_file = std::fs::File::open(cert_path)
        .map_err(|e| anyhow::anyhow!("cannot open TLS cert {cert_path}: {e}"))?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<_, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {cert_path}");
    }
    let key_file = std::fs::File::open(key_path)
        .map_err(|e| anyhow::anyhow!("cannot open TLS key {key_path}: {e}"))?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {key_path}"))?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(Arc::new(config))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    // rustls has TWO crypto providers compiled in (ring via sqlx, aws-lc-rs
    // via tokio-rustls's defaults) and refuses to pick one on its own.
    // Install ring explicitly as the process-wide default before any
    // rustls use; ignore the error if a default is already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let bind = std::env::var("RELAY_BIND").unwrap_or_else(|_| "127.0.0.1:8890".into());
    let database_url =
        std::env::var("DATABASE_URL").map_err(|_| anyhow::anyhow!("缺少环境变量 DATABASE_URL"))?;
    let cert_path = std::env::var("RELAY_TLS_CERT").unwrap_or_else(|_| {
        "/data/pm-node-station-prod/relay-cert/fullchain.pem".into()
    });
    let key_path = std::env::var("RELAY_TLS_KEY")
        .unwrap_or_else(|_| "/data/pm-node-station-prod/relay-cert/privkey.pem".into());

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await?;

    // Retention: monthly quota needs 30 days of sessions; keep 40.
    match prune_old_sessions(&pool).await {
        Ok(n) => tracing::info!(pruned = n, "relay session retention prune done"),
        Err(e) => tracing::warn!(error = %e, "relay session prune failed"),
    }
    {
        let pool = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 3600));
            loop {
                interval.tick().await;
                match prune_old_sessions(&pool).await {
                    Ok(n) if n > 0 => {
                        tracing::info!(pruned = n, "relay session retention prune done")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "relay session prune failed"),
                }
            }
        });
    }

    // TLS for relay.pmcat.top (terminated here, not by the Cloudflare edge).
    let tls_config = load_tls_config(&cert_path, &key_path)?;
    let acceptor = TlsAcceptor::from(tls_config);
    tracing::info!(cert = %cert_path, key = %key_path, "pm-node-relay TLS enabled");

    let state = Arc::new(RelayState::new(pool));
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("pm-node-relay listening on {} (TLS only)", bind);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();
        let client_ip = peer.ip().to_string();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    handle_connection(state, tls_stream, client_ip).await;
                }
                Err(e) => {
                    tracing::warn!(error = %e, peer = %client_ip, "TLS handshake failed");
                }
            }
        });
    }
}
