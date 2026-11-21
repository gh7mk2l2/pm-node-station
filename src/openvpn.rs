//! VPNGate OpenVPN 配置（.ovpn）解析。
//!
//! 只做解析，不做转换：转换在 clash.rs（mihomo `type: openvpn`）与
//! singbox.rs（`openvpn-client` endpoint）里按各自官方字段表做。
//! 依据：Mihomo Wiki OpenVPN 页（要求 mihomo ≥1.19.29）与 sing-box 1.14
//! openvpn-client 文档（自 sing-box 1.14.0 起）。
//!
//! 诚实原则：.ovpn 里没有对应字段的指令记入 `unmapped`（汇报用），
//! 绝不编默认值；缺关键字段（server/port/ca）时转换函数直接跳过该节点。

/// 解析后的 .ovpn 配置（字段名按 .ovpn 指令名）
#[derive(Debug, Clone, Default)]
pub struct OvpnConfig {
    pub server: String,
    pub port: u16,
    pub proto: String, // "udp" | "tcp"，缺省按 udp
    pub cipher: Option<String>,
    pub data_ciphers: Vec<String>,
    pub data_ciphers_fallback: Option<String>,
    pub auth: Option<String>,
    pub ca: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub tls_auth: Option<String>,
    pub key_direction: Option<String>, // "0" | "1"
    pub tls_crypt: Option<String>,
    pub tls_crypt_v2: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    /// auth-user-pass 指令本身（无内联账号时转换无法提供用户名密码）
    pub auth_user_pass: bool,
    pub comp_lzo: Option<String>,
    pub compress: Option<String>,
    pub topology: Option<String>,
    pub ping: Option<u32>,
    pub ping_restart: Option<u32>,
    pub reneg_sec: Option<u32>,
    pub explicit_exit_notify: Option<u32>,
    pub mssfix: Option<u32>,
    pub fragment: Option<u32>,
    pub remote_cert_tls: Option<String>,
    pub remote_cert_eku: Option<String>,
    pub verify_x509_name: Option<String>,
    pub tls_version_min: Option<String>,
    /// 本解析器认得、但两个目标格式都没有对应字段（或暂未映射）的指令原行。
    /// 注意：client/nobind/persist-key/persist-tun/resolv-retry/verb 等是
    /// OpenVPN 客户端进程行为选项，不是协议参数，两个目标都没有对应字段。
    pub unmapped: Vec<String>,
}

/// 解析 .ovpn 文本。`<ca>` / `<cert>` / `<key>` / `<tls-auth>` / `<tls-crypt>` /
/// `<tls-crypt-v2>` 块取块内原文（不含标签行）；其余指令按 `key value` 解析。
pub fn parse_ovpn_config(text: &str) -> OvpnConfig {
    let mut cfg = OvpnConfig {
        proto: "udp".to_string(),
        ..Default::default()
    };
    let mut block: Option<String> = None;
    let mut block_lines: Vec<String> = Vec::new();
    let flush_block = |cfg: &mut OvpnConfig, name: &str, lines: &[String]| {
        let content = lines.join("\n");
        match name {
            "ca" => cfg.ca = Some(content),
            "cert" => cfg.cert = Some(content),
            "key" => cfg.key = Some(content),
            "tls-auth" => cfg.tls_auth = Some(content),
            "tls-crypt" => cfg.tls_crypt = Some(content),
            "tls-crypt-v2" => cfg.tls_crypt_v2 = Some(content),
            _ => cfg.unmapped.push(format!("<{name}> 块（未识别）")),
        }
    };
    for raw in text.lines() {
        let line = raw.trim();
        // 本站 Clash→.ovpn 合成时写入的内联账号标记（非标准 .ovpn 指令，仅供内部转换读取；
        // 标准 .ovpn 的 auth-user-pass 指向外部文件，无法内联账号）
        if let Some(user) = line.strip_prefix("# pm-username ") {
            cfg.username = Some(user.trim().to_string());
            continue;
        }
        if let Some(pass) = line.strip_prefix("# pm-password ") {
            cfg.password = Some(pass.trim().to_string());
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
            .filter(|s| !s.starts_with('/'))
        {
            block = Some(name.to_string());
            block_lines.clear();
            continue;
        }
        if line.starts_with("</") {
            if let Some(name) = block.take() {
                flush_block(&mut cfg, &name, &block_lines);
                block_lines.clear();
            }
            continue;
        }
        if block.is_some() {
            block_lines.push(line.to_string());
            continue;
        }
        let mut it = line.splitn(2, char::is_whitespace);
        let key = it.next().unwrap_or("");
        let val = it.next().unwrap_or("").trim();
        match key {
            "remote" => {
                // remote <host> <port> [proto]；只取第一个 remote
                if cfg.server.is_empty() {
                    let mut parts = val.split_whitespace();
                    if let Some(host) = parts.next() {
                        cfg.server = host.to_string();
                    }
                    if let Some(p) = parts.next().and_then(|p| p.parse::<u16>().ok()) {
                        cfg.port = p;
                    }
                    if let Some(pr) = parts.next() {
                        cfg.proto = pr.to_ascii_lowercase();
                    }
                }
            }
            "proto" => cfg.proto = val.to_ascii_lowercase(),
            "port" => {
                if let Ok(p) = val.parse::<u16>() {
                    cfg.port = p;
                }
            }
            "cipher" => cfg.cipher = Some(val.to_string()),
            "data-ciphers" => {
                cfg.data_ciphers = val
                    .split([':', ' ', ','])
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
            }
            "data-ciphers-fallback" => cfg.data_ciphers_fallback = Some(val.to_string()),
            "auth" => cfg.auth = Some(val.to_string()),
            "auth-user-pass" => cfg.auth_user_pass = true,
            "comp-lzo" => cfg.comp_lzo = Some(val.to_string()),
            "compress" => cfg.compress = Some(val.to_string()),
            "topology" => cfg.topology = Some(val.to_string()),
            "ping" => cfg.ping = val.parse().ok(),
            "ping-restart" => cfg.ping_restart = val.parse().ok(),
            "reneg-sec" => cfg.reneg_sec = val.parse().ok(),
            "explicit-exit-notify" => cfg.explicit_exit_notify = val.parse().ok(),
            "mssfix" => cfg.mssfix = val.parse().ok(),
            "fragment" => cfg.fragment = val.parse().ok(),
            "remote-cert-tls" => cfg.remote_cert_tls = Some(val.to_string()),
            "remote-cert-eku" => cfg.remote_cert_eku = Some(val.to_string()),
            "verify-x509-name" => cfg.verify_x509_name = Some(val.to_string()),
            "tls-version-min" => cfg.tls_version_min = Some(val.to_string()),
            "key-direction" => cfg.key_direction = Some(val.to_string()),
            // 客户端进程行为选项：两个目标格式都没有对应字段，记入 unmapped
            "client" | "nobind" | "persist-key" | "persist-tun" | "resolv-retry"
            | "verb" | "mute" | "connect-retry" | "connect-timeout" | "float"
            | "fast-io" | "sndbuf" | "rcvbuf" | "tun-mtu" | "keysize" | "dev"
            | "tls-client" | "pull" | "redirect-gateway" | "route" | "dhcp-option"
            | "crl-verify" | "remote-cert-ku" | "ns-cert-type" | "auth-nocache"
            | "script-security" | "up" | "down" | "user" | "group" | "chroot"
            | "persist-local-ip" | "persist-remote-ip" | "single-session"
            | "disable-occ" | "allow-recursive-routing" => {
                cfg.unmapped.push(line.to_string());
            }
            _ => cfg.unmapped.push(line.to_string()),
        }
    }
    if let Some(name) = block.take() {
        flush_block(&mut cfg, &name, &block_lines);
    }
    cfg
}

/// mihomo 的 cipher 归一化（Wiki：`AES-CBC` 按 `AES-128-CBC` 处理）。
pub fn normalize_mihomo_cipher(cipher: &str) -> String {
    if cipher.eq_ignore_ascii_case("AES-CBC") {
        "AES-128-CBC".to_string()
    } else {
        cipher.to_string()
    }
}

/// .ovpn key-direction（"0"/"1"）→ sing-box control_wrap direction（"server"/"client"）。
/// OpenVPN 约定：客户端用方向 1，服务端用方向 0。
pub fn key_direction_to_singbox(dir: &str) -> Option<&'static str> {
    match dir {
        "0" => Some("server"),
        "1" => Some("client"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 一份与 VPNGate 真实配置结构相同的 .ovpn（字段齐全版）
    fn sample_ovpn() -> String {
        [
            "client",
            "dev tun",
            "proto tcp",
            "remote 203.0.113.10 1195",
            "resolv-retry infinite",
            "nobind",
            "persist-key",
            "persist-tun",
            "cipher AES-128-CBC",
            "data-ciphers AES-128-CBC",
            "auth SHA1",
            "verb 3",
            "<ca>",
            "-----BEGIN CERTIFICATE-----",
            "MIIBCA==",
            "-----END CERTIFICATE-----",
            "</ca>",
            "<cert>",
            "-----BEGIN CERTIFICATE-----",
            "MIIBCC==",
            "-----END CERTIFICATE-----",
            "</cert>",
            "<key>",
            "-----BEGIN PRIVATE KEY-----",
            "MIIBCK==",
            "-----END PRIVATE KEY-----",
            "</key>",
        ]
        .join("\n")
    }

    #[test]
    fn parses_vpngate_style_config() {
        let cfg = parse_ovpn_config(&sample_ovpn());
        assert_eq!(cfg.server, "203.0.113.10");
        assert_eq!(cfg.port, 1195);
        assert_eq!(cfg.proto, "tcp");
        assert_eq!(cfg.cipher.as_deref(), Some("AES-128-CBC"));
        assert_eq!(cfg.data_ciphers, vec!["AES-128-CBC"]);
        assert_eq!(cfg.auth.as_deref(), Some("SHA1"));
        assert!(cfg.ca.as_ref().unwrap().contains("MIIBCA=="));
        assert!(cfg.cert.as_ref().unwrap().contains("MIIBCC=="));
        assert!(cfg.key.as_ref().unwrap().contains("MIIBCK=="));
        assert!(cfg.tls_auth.is_none());
        assert!(!cfg.auth_user_pass);
        // 客户端进程选项进 unmapped，不丢也不瞎映射
        assert!(cfg.unmapped.iter().any(|l| l == "client"));
        assert!(cfg.unmapped.iter().any(|l| l == "verb 3"));
        assert!(cfg.unmapped.iter().any(|l| l == "resolv-retry infinite"));
    }

    #[test]
    fn parses_tls_auth_and_key_direction() {
        let text = [
            "proto udp",
            "remote 198.51.100.20 443",
            "key-direction 1",
            "<tls-auth>",
            "-----BEGIN OpenVPN Static key V1-----",
            "abcd",
            "-----END OpenVPN Static key V1-----",
            "</tls-auth>",
            "<ca>",
            "-----BEGIN CERTIFICATE-----",
            "CA==",
            "-----END CERTIFICATE-----",
            "</ca>",
        ]
        .join("\n");
        let cfg = parse_ovpn_config(&text);
        assert_eq!(cfg.proto, "udp");
        assert_eq!(cfg.key_direction.as_deref(), Some("1"));
        assert!(cfg.tls_auth.as_ref().unwrap().contains("abcd"));
        assert_eq!(key_direction_to_singbox("1"), Some("client"));
        assert_eq!(key_direction_to_singbox("0"), Some("server"));
        assert_eq!(key_direction_to_singbox("x"), None);
    }

    #[test]
    fn cipher_normalization() {
        assert_eq!(normalize_mihomo_cipher("AES-CBC"), "AES-128-CBC");
        assert_eq!(normalize_mihomo_cipher("AES-256-GCM"), "AES-256-GCM");
    }

    #[test]
    fn inline_auth_markers_parse() {
        // 本站合成标记：Clash openvpn 代理自带账号时写入，转换器据此输出 username/password
        let text = [
            "proto udp",
            "remote 198.51.100.20 443",
            "auth-user-pass",
            "# pm-username alice",
            "# pm-password s3cret",
            "<ca>",
            "CA==",
            "</ca>",
        ]
        .join("\n");
        let cfg = parse_ovpn_config(&text);
        assert!(cfg.auth_user_pass);
        assert_eq!(cfg.username.as_deref(), Some("alice"));
        assert_eq!(cfg.password.as_deref(), Some("s3cret"));
        // 普通注释仍忽略
        let cfg2 = parse_ovpn_config("# just a comment\nproto tcp\nremote 1.2.3.4 1194\n<ca>\nCA==\n</ca>");
        assert!(cfg2.username.is_none());
    }
}
