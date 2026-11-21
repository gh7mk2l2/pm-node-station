use rand::RngCore;
use sha2::{Digest, Sha256};

/// URL-safe 随机 token（会话、订阅 token、OAuth state 等共用）
pub fn random_token(bytes: usize) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

pub fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn sha256_hex(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn sanitize_next(next: &str) -> String {
    let value = next.trim();
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains("://")
        && !value.contains('\\')
    {
        value.to_string()
    } else {
        "/".to_string()
    }
}

/// 客户端真实 IP：优先 Cloudflare 头，其次 X-Real-IP / X-Forwarded-For
pub fn client_ip(headers: &axum::http::HeaderMap) -> String {
    if let Some(value) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        return value.trim().to_string();
    }
    if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        return value.trim().to_string();
    }
    if let Some(value) = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(first) = value.split(',').next() {
            return first.trim().to_string();
        }
    }
    String::new()
}

pub fn truncate_chars(value: &str, max: usize) -> String {
    let mut out: String = value.chars().take(max).collect();
    if value.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_path_is_restricted_to_local_paths() {
        assert_eq!(sanitize_next("/"), "/");
        assert_eq!(sanitize_next("/#/dashboard"), "/#/dashboard");
        assert_eq!(sanitize_next("//evil.example"), "/");
        assert_eq!(sanitize_next("https://evil.example"), "/");
        assert_eq!(sanitize_next("javascript:alert(1)"), "/");
    }

    #[test]
    fn tokens_are_unique_and_url_safe() {
        let a = random_token(32);
        let b = random_token(32);
        assert_ne!(a, b);
        assert!(a
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn sha256_hex_is_stable() {
        assert_eq!(sha256_hex("abc").len(), 64);
        assert_eq!(sha256_hex("abc"), sha256_hex("abc"));
        assert_ne!(sha256_hex("abc"), sha256_hex("abd"));
    }
}
