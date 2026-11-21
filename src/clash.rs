//! Clash / Mihomo YAML 订阅生成（原创实现）。
//! 订阅端按 User-Agent 分发：Clash 系客户端需要完整 YAML 配置。
//! 支持：vless、hysteria2、vmess、ss、trojan、socks5、http。

use crate::nodes::{is_known_utls_fingerprint, read_node_name, try_decode_base64};
use crate::rules::*;

/// YAML 键值对（保持顺序；值可以是标量或嵌套键值对列表）
pub type YamlPairs = Vec<(String, YamlValue)>;

#[derive(Debug, Clone)]
pub enum YamlValue {
    Scalar(String),
    Int(i64),
    Bool(bool),
    Pairs(YamlPairs),
    /// 流式列表，如 data-ciphers: [AES-256-GCM, AES-128-GCM]
    List(Vec<String>),
}

fn s(v: impl Into<String>) -> YamlValue {
    YamlValue::Scalar(v.into())
}

fn scalar(v: &YamlValue) -> String {
    match v {
        YamlValue::Scalar(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into()),
        YamlValue::Int(n) => n.to_string(),
        YamlValue::Bool(b) => b.to_string(),
        YamlValue::List(items) => format!(
            "[{}]",
            items
                .iter()
                .map(|i| serde_json::to_string(i).unwrap_or_else(|_| "\"\"".into()))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        YamlValue::Pairs(_) => unreachable!(),
    }
}

fn emit_pairs(pairs: &YamlPairs, indent: usize) -> Vec<String> {
    let sp = " ".repeat(indent);
    let mut lines = Vec::new();
    for (k, v) in pairs {
        match v {
            YamlValue::Pairs(inner) => {
                lines.push(format!("{sp}{k}:"));
                lines.extend(emit_pairs(inner, indent + 2));
            }
            _ => lines.push(format!("{sp}{k}: {}", scalar(v))),
        }
    }
    lines
}

fn emit_proxy(pairs: &YamlPairs) -> String {
    let mut lines = Vec::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        let prefix = if i == 0 { "  - " } else { "    " };
        match v {
            YamlValue::Pairs(inner) => {
                lines.push(format!("{prefix}{k}:"));
                lines.extend(emit_pairs(inner, 6));
            }
            _ => lines.push(format!("{prefix}{k}: {}", scalar(v))),
        }
    }
    lines.join("\n")
}

/// 单个节点 URI → Clash 代理对象；不认识的格式返回 None
pub fn uri_to_clash_proxy(uri: &str, name: &str) -> Option<YamlPairs> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("vless://") {
        return vless_to_clash(uri, name);
    }
    if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        return hysteria2_to_clash(uri, name);
    }
    if lower.starts_with("vmess://") {
        return vmess_to_clash(uri, name);
    }
    if lower.starts_with("ss://") {
        return ss_to_clash(uri, name);
    }
    if lower.starts_with("trojan://") {
        return trojan_to_clash(uri, name);
    }
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return socks5_to_clash(uri, name);
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return http_to_clash(uri, name);
    }
    None
}

fn safe_url(uri: &str) -> Option<url::Url> {
    url::Url::parse(uri).ok()
}

fn port_or_default(url: &url::Url, dft: u16) -> i64 {
    url.port().map(|p| p as i64).unwrap_or(dft as i64)
}

fn truthy_param(url: &url::Url, keys: &[&str]) -> bool {
    for k in keys {
        if let Some(v) = url.query_pairs().find(|(key, _)| key == *k).map(|(_, v)| v) {
            match v.as_ref() {
                "1" | "true" => return true,
                "0" | "false" => return false,
                _ => {}
            }
        }
    }
    false
}

fn query_param(url: &url::Url, key: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

fn userinfo(url: &url::Url) -> String {
    let user = url.username();
    let pass = url.password().unwrap_or("");
    let decoded_user = percent_decode(user);
    if pass.is_empty() {
        decoded_user
    } else {
        format!("{}:{}", decoded_user, percent_decode(pass))
    }
}

fn percent_decode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(hex) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn vless_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let url = safe_url(uri)?;
    let uuid = userinfo(&url);
    if uuid.is_empty() || url.host_str().is_none() {
        return None;
    }
    let security = query_param(&url, "security").to_ascii_lowercase();
    let network = query_param(&url, "type").to_ascii_lowercase();
    let sni = query_param(&url, "sni");
    let flow = query_param(&url, "flow");
    let fp = query_param(&url, "fp");
    let pbk = query_param(&url, "pbk");
    let sid = query_param(&url, "sid");

    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("vless")),
        ("server".into(), s(url.host_str().unwrap())),
        ("port".into(), YamlValue::Int(port_or_default(&url, 443))),
        ("uuid".into(), s(uuid)),
        ("udp".into(), YamlValue::Bool(true)),
    ];
    let network = if network.is_empty() {
        "tcp".to_string()
    } else {
        network
    };
    proxy.push(("network".into(), s(&network)));

    if security == "reality" || security == "tls" {
        proxy.push(("tls".into(), YamlValue::Bool(true)));
        if truthy_param(&url, &["insecure", "allowInsecure", "allow-insecure"]) {
            proxy.push(("skip-cert-verify".into(), YamlValue::Bool(true)));
        }
        if !sni.is_empty() {
            proxy.push(("servername".into(), s(sni)));
        }
        // 未知的 uTLS 指纹（如上游带来的 unsafe）直接丢弃，只保留 TLS 本身，
        // 否则整份配置过不了 `mihomo -t` / `sing-box check`
        if is_known_utls_fingerprint(&fp) {
            proxy.push(("client-fingerprint".into(), s(fp)));
        }
        if !flow.is_empty() {
            proxy.push(("flow".into(), s(flow)));
        }
        if security == "reality" && !pbk.is_empty() {
            let mut reality: YamlPairs = vec![("public-key".into(), s(pbk))];
            if !sid.is_empty() {
                reality.push(("short-id".into(), s(sid)));
            }
            proxy.push(("reality-opts".into(), YamlValue::Pairs(reality)));
        }
    } else if !flow.is_empty() {
        proxy.push(("flow".into(), s(flow)));
    }

    if network == "ws" {
        let mut ws: YamlPairs = vec![(
            "path".into(),
            s({
                let p = query_param(&url, "path");
                if p.is_empty() {
                    "/".to_string()
                } else {
                    p
                }
            }),
        )];
        let host = query_param(&url, "host");
        if !host.is_empty() {
            ws.push((
                "headers".into(),
                YamlValue::Pairs(vec![("Host".into(), s(host))]),
            ));
        }
        proxy.push(("ws-opts".into(), YamlValue::Pairs(ws)));
    } else if network == "grpc" {
        let svc = query_param(&url, "serviceName");
        if !svc.is_empty() {
            proxy.push((
                "grpc-opts".into(),
                YamlValue::Pairs(vec![("grpc-service-name".into(), s(svc))]),
            ));
        }
    }
    Some(proxy)
}

fn hysteria2_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let url = safe_url(uri)?;
    let password = userinfo(&url);
    if password.is_empty() || url.host_str().is_none() {
        return None;
    }
    let sni = {
        let a = query_param(&url, "sni");
        if a.is_empty() {
            query_param(&url, "peer")
        } else {
            a
        }
    };
    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("hysteria2")),
        ("server".into(), s(url.host_str().unwrap())),
        ("port".into(), YamlValue::Int(port_or_default(&url, 443))),
        ("password".into(), s(password)),
        ("udp".into(), YamlValue::Bool(true)),
    ];
    if !sni.is_empty() {
        proxy.push(("sni".into(), s(sni)));
    }
    if truthy_param(&url, &["insecure", "allowInsecure", "allow-insecure"]) {
        proxy.push(("skip-cert-verify".into(), YamlValue::Bool(true)));
    }
    let pinned = {
        let a = query_param(&url, "pinSHA256");
        if a.is_empty() {
            query_param(&url, "pinned-sha256")
        } else {
            a
        }
    };
    if !pinned.is_empty() {
        proxy.push(("pinned-sha256".into(), s(pinned)));
    }
    let obfs = query_param(&url, "obfs");
    if !obfs.is_empty() {
        let mut opts: YamlPairs = vec![("type".into(), s(obfs))];
        let pwd = query_param(&url, "obfs-password");
        if !pwd.is_empty() {
            opts.push(("password".into(), s(pwd)));
        }
        proxy.push(("obfs".into(), YamlValue::Pairs(opts)));
    }
    Some(proxy)
}

fn vmess_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let b64 = uri.split("://").nth(1)?;
    let json: serde_json::Value = serde_json::from_str(&try_decode_base64(b64)?).ok()?;
    let server = json.get("add")?.as_str()?.to_string();
    let uuid = json.get("id")?.as_str()?.to_string();
    let port = json.get("port").and_then(|p| {
        p.as_str()
            .and_then(|s| s.parse::<i64>().ok())
            .or_else(|| p.as_i64())
    })?;
    if server.is_empty() || uuid.is_empty() || port <= 0 {
        return None;
    }
    let network = json
        .get("net")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp")
        .to_ascii_lowercase();
    let tls = json.get("tls").and_then(|v| v.as_str()).unwrap_or("") == "tls";
    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("vmess")),
        ("server".into(), s(server)),
        ("port".into(), YamlValue::Int(port)),
        ("uuid".into(), s(uuid)),
        (
            "alterId".into(),
            YamlValue::Int(
                json.get("aid")
                    .and_then(|v| {
                        v.as_str()
                            .and_then(|s| s.parse().ok())
                            .or_else(|| v.as_i64())
                    })
                    .unwrap_or(0),
            ),
        ),
        (
            "cipher".into(),
            s(json
                .get("scy")
                .or_else(|| json.get("security"))
                .and_then(|v| v.as_str())
                .unwrap_or("auto")),
        ),
        ("udp".into(), YamlValue::Bool(true)),
    ];
    if network != "tcp" {
        proxy.push(("network".into(), s(&network)));
    }
    if tls {
        proxy.push(("tls".into(), YamlValue::Bool(true)));
        let sni = json
            .get("sni")
            .or_else(|| json.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !sni.is_empty() {
            proxy.push(("servername".into(), s(sni)));
        }
    }
    if network == "ws" {
        let mut ws: YamlPairs = vec![(
            "path".into(),
            s(json.get("path").and_then(|v| v.as_str()).unwrap_or("/")),
        )];
        if let Some(host) = json.get("host").and_then(|v| v.as_str()) {
            if !host.is_empty() {
                ws.push((
                    "headers".into(),
                    YamlValue::Pairs(vec![("Host".into(), s(host))]),
                ));
            }
        }
        proxy.push(("ws-opts".into(), YamlValue::Pairs(ws)));
    } else if network == "grpc" {
        if let Some(path) = json.get("path").and_then(|v| v.as_str()) {
            if !path.is_empty() {
                proxy.push((
                    "grpc-opts".into(),
                    YamlValue::Pairs(vec![("grpc-service-name".into(), s(path))]),
                ));
            }
        }
    }
    Some(proxy)
}

fn ss_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let body = uri.split('#').next()?;
    // SIP002: ss://base64(method:password)@host:port
    if let Ok(url) = url::Url::parse(body) {
        if !url.host_str().unwrap_or("").is_empty() && !url.username().is_empty() {
            let decoded = try_decode_base64(&percent_decode(url.username()))?;
            let idx = decoded.find(':')?;
            let method = &decoded[..idx];
            let password = &decoded[idx + 1..];
            if method.is_empty() {
                return None;
            }
            return Some(vec![
                ("name".into(), s(name)),
                ("type".into(), s("ss")),
                ("server".into(), s(url.host_str().unwrap())),
                ("port".into(), YamlValue::Int(port_or_default(&url, 443))),
                ("cipher".into(), s(method)),
                ("password".into(), s(password)),
                ("udp".into(), YamlValue::Bool(true)),
            ]);
        }
    }
    // 旧式：ss://base64(method:password@host:port)
    let decoded = try_decode_base64(&body["ss://".len()..])?;
    let at = decoded.rfind('@')?;
    let user_info = &decoded[..at];
    let host_port = &decoded[at + 1..];
    let colon = user_info.find(':')?;
    let host_colon = host_port.rfind(':')?;
    let server = &host_port[..host_colon];
    let port: i64 = host_port[host_colon + 1..].parse().ok()?;
    if server.is_empty() || port <= 0 {
        return None;
    }
    Some(vec![
        ("name".into(), s(name)),
        ("type".into(), s("ss")),
        ("server".into(), s(server)),
        ("port".into(), YamlValue::Int(port)),
        ("cipher".into(), s(&user_info[..colon])),
        ("password".into(), s(&user_info[colon + 1..])),
        ("udp".into(), YamlValue::Bool(true)),
    ])
}

fn trojan_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let url = safe_url(uri)?;
    let password = userinfo(&url);
    if password.is_empty() || url.host_str().is_none() {
        return None;
    }
    let sni = {
        let a = query_param(&url, "sni");
        if a.is_empty() {
            query_param(&url, "peer")
        } else {
            a
        }
    };
    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("trojan")),
        ("server".into(), s(url.host_str().unwrap())),
        ("port".into(), YamlValue::Int(port_or_default(&url, 443))),
        ("password".into(), s(password)),
        ("udp".into(), YamlValue::Bool(true)),
    ];
    if !sni.is_empty() {
        proxy.push(("sni".into(), s(sni)));
    }
    if truthy_param(&url, &["allowInsecure", "insecure"]) {
        proxy.push(("skip-cert-verify".into(), YamlValue::Bool(true)));
    }
    Some(proxy)
}

fn socks5_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let url = safe_url(uri)?;
    if url.host_str().is_none() {
        return None;
    }
    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("socks5")),
        ("server".into(), s(url.host_str().unwrap())),
        ("port".into(), YamlValue::Int(port_or_default(&url, 1080))),
        ("udp".into(), YamlValue::Bool(true)),
    ];
    if !url.username().is_empty() {
        proxy.push(("username".into(), s(percent_decode(url.username()))));
        proxy.push((
            "password".into(),
            s(percent_decode(url.password().unwrap_or(""))),
        ));
    }
    if truthy_param(&url, &["tls"]) {
        proxy.push(("tls".into(), YamlValue::Bool(true)));
        let sni = query_param(&url, "sni");
        if !sni.is_empty() {
            proxy.push(("servername".into(), s(sni)));
        }
    }
    Some(proxy)
}

fn http_to_clash(uri: &str, name: &str) -> Option<YamlPairs> {
    let url = safe_url(uri)?;
    if url.host_str().is_none() {
        return None;
    }
    let is_tls = url.scheme() == "https" || truthy_param(&url, &["tls"]);
    let mut proxy: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("http")),
        ("server".into(), s(url.host_str().unwrap())),
        (
            "port".into(),
            YamlValue::Int(port_or_default(&url, if is_tls { 443 } else { 80 })),
        ),
    ];
    if !url.username().is_empty() {
        proxy.push(("username".into(), s(percent_decode(url.username()))));
        proxy.push((
            "password".into(),
            s(percent_decode(url.password().unwrap_or(""))),
        ));
    }
    if is_tls {
        proxy.push(("tls".into(), YamlValue::Bool(true)));
    }
    Some(proxy)
}

fn rule(parts: &[&str]) -> String {
    format!("  - {}", parts.join(","))
}

/// 分流规则段（顺序即优先级）
fn build_rules() -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    for d in PRIVATE_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, "DIRECT"]));
    }
    for c in PRIVATE_CIDRS {
        lines.push(rule(&["IP-CIDR", c, "DIRECT", "no-resolve"]));
    }
    for d in AD_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_ADS]));
    }
    for d in TELEGRAM_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_TELEGRAM]));
    }
    for c in TELEGRAM_CIDRS {
        lines.push(rule(&["IP-CIDR", c, GROUP_TELEGRAM, "no-resolve"]));
    }
    for d in MICROSOFT_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_MICROSOFT]));
    }
    for d in APPLE_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_APPLE]));
    }
    for d in MEDIA_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_MEDIA]));
    }
    for d in PROXY_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, GROUP_MAIN]));
    }
    for d in CN_DOMAINS {
        lines.push(rule(&["DOMAIN-SUFFIX", d, "DIRECT"]));
    }
    lines.push(rule(&["GEOIP", "CN", "DIRECT", "no-resolve"]));
    lines.push(rule(&["MATCH", GROUP_FINAL]));
    lines
}

fn emit_group(name: &str, typ: &str, members: &[String], extra: &[String]) -> Vec<String> {
    let mut lines = vec![
        format!("  - name: {}", serde_json::to_string(name).unwrap()),
        format!("    type: {typ}"),
    ];
    for e in extra {
        lines.push(format!("    {e}"));
    }
    lines.push("    proxies:".to_string());
    for m in members {
        lines.push(format!("      - {}", serde_json::to_string(m).unwrap()));
    }
    lines
}

/// 生成完整 Clash YAML 配置；无可转换节点时返回 None。
/// mode="rules" 输出分流配置；mode="global" 为全量代理回退。
pub fn build_clash_yaml(nodes: &[String], group_name: &str, mode: &str) -> Option<String> {
    let mut proxies: Vec<YamlPairs> = Vec::new();
    let mut used_names = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut name = read_node_name(uri);
        if name.starts_with('(') {
            fallback += 1;
            name = format!("节点 {fallback}");
        }
        if used_names.contains(&name) {
            let mut n = 2;
            while used_names.contains(&format!("{name} {n}")) {
                n += 1;
            }
            name = format!("{name} {n}");
        }
        used_names.insert(name.clone());
        if let Some(p) = uri_to_clash_proxy(uri, &name) {
            proxies.push(p);
        }
    }
    if proxies.is_empty() {
        return None;
    }
    Some(emit_full_yaml(&proxies, group_name, mode))
}

/// 一级混合批次：普通节点 + OpenVPN 节点（.ovpn 配置在 configs_b64 里）合并输出。
/// 普通节点走 uri_to_clash_proxy，OpenVPN 节点走 openvpn_to_clash_proxy；
/// 哪个都转不出来就跳过该节点（不编默认值）。
pub fn build_clash_yaml_mixed(
    nodes: &[String],
    configs_b64: &std::collections::HashMap<String, String>,
    group_name: &str,
    mode: &str,
) -> Option<String> {
    let mut proxies: Vec<YamlPairs> = Vec::new();
    let mut used_names = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut name = read_node_name(uri);
        if name.starts_with('(') {
            fallback += 1;
            name = format!("节点 {fallback}");
        }
        if used_names.contains(&name) {
            let mut n = 2;
            while used_names.contains(&format!("{name} {n}")) {
                n += 1;
            }
            name = format!("{name} {n}");
        }
        used_names.insert(name.clone());
        if uri.to_ascii_lowercase().starts_with("openvpn://") {
            let Some(b64) = configs_b64.get(&name) else {
                continue;
            };
            let Some(text) = try_decode_base64(b64) else {
                continue;
            };
            let cfg = crate::openvpn::parse_ovpn_config(&text);
            if let Some(p) = openvpn_to_clash_proxy(&cfg, &name) {
                proxies.push(p);
            }
        } else if let Some(p) = uri_to_clash_proxy(uri, &name) {
            proxies.push(p);
        }
    }
    if proxies.is_empty() {
        return None;
    }
    Some(emit_full_yaml(&proxies, group_name, mode))
}

/// 三级 OpenVPN：把 .ovpn 配置转成 mihomo `type: openvpn` 代理
/// （要求 mihomo ≥1.19.29；老版 Clash 内核不认 openvpn 类型）。
/// configs：改名后节点名 → .ovpn 配置 base64。
/// 转换失败（缺 server/port/ca，或 auth-user-pass 却无账号）的节点跳过；全部失败返回 None。
pub fn build_clash_yaml_openvpn(
    nodes: &[String],
    configs_b64: &std::collections::HashMap<String, String>,
    group_name: &str,
    mode: &str,
) -> Option<String> {
    let mut proxies: Vec<YamlPairs> = Vec::new();
    let mut used_names = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut name = read_node_name(uri);
        if name.starts_with('(') {
            fallback += 1;
            name = format!("节点 {fallback}");
        }
        if used_names.contains(&name) {
            let mut n = 2;
            while used_names.contains(&format!("{name} {n}")) {
                n += 1;
            }
            name = format!("{name} {n}");
        }
        used_names.insert(name.clone());
        let Some(b64) = configs_b64.get(&name) else {
            continue;
        };
        let Some(text) = try_decode_base64(b64) else {
            continue;
        };
        let cfg = crate::openvpn::parse_ovpn_config(&text);
        if let Some(p) = openvpn_to_clash_proxy(&cfg, &name) {
            proxies.push(p);
        }
    }
    if proxies.is_empty() {
        return None;
    }
    Some(emit_full_yaml(&proxies, group_name, mode))
}

/// .ovpn → mihomo openvpn 代理（字段以 Mihomo Wiki OpenVPN 页为准）。
/// 缺 server/port/ca，或 auth-user-pass 却无账号 → None（跳过该节点，不编默认值）。
/// 未映射的 .ovpn 指令见 OvpnConfig.unmapped（client/nobind/persist-*/resolv-retry/verb 等
/// 客户端进程选项，mihomo 没有对应字段）。
fn openvpn_to_clash_proxy(cfg: &crate::openvpn::OvpnConfig, name: &str) -> Option<YamlPairs> {
    if cfg.server.is_empty() || cfg.port == 0 {
        return None;
    }
    let Some(ca) = &cfg.ca else {
        return None;
    };
    if cfg.auth_user_pass && (cfg.username.is_none() || cfg.password.is_none()) {
        return None;
    }
    let udp = cfg.proto != "tcp";
    let mut p: YamlPairs = vec![
        ("name".into(), s(name)),
        ("type".into(), s("openvpn")),
        ("server".into(), s(&cfg.server)),
        ("port".into(), YamlValue::Int(cfg.port as i64)),
        ("proto".into(), s(if udp { "udp" } else { "tcp" })),
        ("udp".into(), YamlValue::Bool(udp)),
        ("dev".into(), s("tun")),
        ("ca".into(), s(ca)),
    ];
    if let Some(cert) = &cfg.cert {
        p.push(("cert".into(), s(cert)));
    }
    if let Some(key) = &cfg.key {
        p.push(("key".into(), s(key)));
    }
    if let Some(u) = &cfg.username {
        p.push(("username".into(), s(u)));
    }
    if let Some(pw) = &cfg.password {
        p.push(("password".into(), s(pw)));
    }
    // tls-auth / tls-crypt / tls-crypt-v2 三者互斥（.ovpn 里本就互斥）
    if let Some(ta) = &cfg.tls_auth {
        p.push(("tls-auth".into(), s(ta)));
        if let Some(d) = &cfg.key_direction {
            p.push(("key-direction".into(), s(d)));
        }
    } else if let Some(tc) = &cfg.tls_crypt {
        p.push(("tls-crypt".into(), s(tc)));
    } else if let Some(tc2) = &cfg.tls_crypt_v2 {
        p.push(("tls-crypt-v2".into(), s(tc2)));
    }
    if let Some(cipher) = &cfg.cipher {
        p.push((
            "cipher".into(),
            s(crate::openvpn::normalize_mihomo_cipher(cipher)),
        ));
    }
    if !cfg.data_ciphers.is_empty() {
        p.push((
            "data-ciphers".into(),
            YamlValue::List(cfg.data_ciphers.clone()),
        ));
    }
    if let Some(fb) = &cfg.data_ciphers_fallback {
        p.push(("data-ciphers-fallback".into(), s(fb)));
    }
    if let Some(auth) = &cfg.auth {
        p.push(("auth".into(), s(auth)));
    }
    if let Some(lzo) = &cfg.comp_lzo {
        p.push(("comp-lzo".into(), s(lzo)));
    }
    Some(p)
}

/// 已转换好的代理列表 → 完整 Clash YAML 配置（头 + proxies + proxy-groups + rules）。
/// mode="rules" 输出分流配置；mode="global" 为全量代理回退。
fn emit_full_yaml(proxies: &[YamlPairs], group_name: &str, mode: &str) -> String {
    let names: Vec<String> = proxies
        .iter()
        .filter_map(|p| p.iter().find(|(k, _)| k == "name"))
        .filter_map(|(_, v)| match v {
            YamlValue::Scalar(s) => Some(s.clone()),
            _ => None,
        })
        .collect();

    let mut lines: Vec<String> = vec![
        "mixed-port: 7890".into(),
        "allow-lan: false".into(),
        "mode: rule".into(),
        "log-level: info".into(),
        "unified-delay: true".into(),
        "tcp-concurrent: true".into(),
        "dns:".into(),
        "  enable: true".into(),
        "  listen: 0.0.0.0:1053".into(),
        "  ipv6: false".into(),
        "  enhanced-mode: fake-ip".into(),
        "  fake-ip-range: 198.18.0.1/16".into(),
        "  fake-ip-filter:".into(),
        "    - \"*.lan\"".into(),
        "    - \"*.local\"".into(),
        "    - \"+.msftconnecttest.com\"".into(),
        "    - \"+.msftncsi.com\"".into(),
        "  default-nameserver:".into(),
        "    - 223.5.5.5".into(),
        "    - 8.8.8.8".into(),
        "  nameserver:".into(),
        "    - https://223.5.5.5/dns-query".into(),
        "    - https://1.1.1.1/dns-query".into(),
        "proxies:".into(),
    ];
    for p in proxies {
        lines.push(emit_proxy(p));
    }

    lines.push("proxy-groups:".into());

    if mode == "global" {
        let mut members = names.clone();
        members.push("DIRECT".into());
        lines.extend(emit_group(group_name, "select", &members, &[]));
        lines.push("rules:".into());
        lines.push(format!("  - MATCH,{group_name}"));
        return lines.join("\n") + "\n";
    }

    let mut main_members = vec![GROUP_AUTO.to_string()];
    main_members.extend(names.clone());
    main_members.push("DIRECT".into());
    lines.extend(emit_group(group_name, "select", &main_members, &[]));
    lines.extend(emit_group(
        GROUP_AUTO,
        "url-test",
        &names,
        &[
            "url: http://www.gstatic.com/generate_204".into(),
            "interval: 300".into(),
            "tolerance: 50".into(),
        ],
    ));
    let mut media_members = vec![group_name.to_string(), GROUP_AUTO.to_string()];
    media_members.extend(names.clone());
    media_members.push("DIRECT".into());
    lines.extend(emit_group(GROUP_MEDIA, "select", &media_members, &[]));
    lines.extend(emit_group(GROUP_TELEGRAM, "select", &media_members, &[]));
    lines.extend(emit_group(
        GROUP_MICROSOFT,
        "select",
        &[
            "DIRECT".to_string(),
            group_name.to_string(),
            GROUP_AUTO.to_string(),
        ],
        &[],
    ));
    lines.extend(emit_group(
        GROUP_APPLE,
        "select",
        &[
            "DIRECT".to_string(),
            group_name.to_string(),
            GROUP_AUTO.to_string(),
        ],
        &[],
    ));
    lines.extend(emit_group(
        GROUP_ADS,
        "select",
        &["REJECT".to_string(), "DIRECT".to_string()],
        &[],
    ));
    let mut final_members = vec![
        group_name.to_string(),
        GROUP_AUTO.to_string(),
        "DIRECT".to_string(),
    ];
    lines.extend(emit_group(GROUP_FINAL, "select", &final_members, &[]));
    final_members.clear();

    lines.push("rules:".into());
    lines.extend(build_rules());

    lines.join("\n") + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless() -> String {
        "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls&sni=hk.example.com&type=ws&path=%2Fws&host=hk.example.com#%E9%A6%99%E6%B8%AF-01".to_string()
    }

    #[test]
    fn vless_converts_with_ws_and_tls() {
        let p = uri_to_clash_proxy(&vless(), "香港-01").unwrap();
        let get = |k: &str| {
            p.iter().find(|(key, _)| key == k).map(|(_, v)| match v {
                YamlValue::Scalar(s) => s.clone(),
                YamlValue::Int(n) => n.to_string(),
                YamlValue::Bool(b) => b.to_string(),
                _ => String::new(),
            })
        };
        assert_eq!(get("type").as_deref(), Some("vless"));
        assert_eq!(get("server").as_deref(), Some("hk.example.com"));
        assert_eq!(get("port").as_deref(), Some("443"));
        assert_eq!(get("tls").as_deref(), Some("true"));
    }

    #[test]
    fn unknown_utls_fingerprint_is_dropped() {
        // 上游带来的 fp=unsafe 会让整份配置过不了校验：丢弃指纹，只保留 TLS
        let uri = "vless://550e8400-e29b-41d4-a716-446655440000@jp.example.com:443?security=tls&sni=jp.example.com&fp=unsafe#JP-01";
        let p = uri_to_clash_proxy(uri, "JP-01").unwrap();
        assert!(p.iter().find(|(k, _)| k == "client-fingerprint").is_none());
        assert!(p.iter().find(|(k, _)| k == "tls").is_some());
        // 已知指纹正常保留
        let ok = "vless://550e8400-e29b-41d4-a716-446655440000@jp.example.com:443?security=tls&sni=jp.example.com&fp=chrome#JP-01";
        let p2 = uri_to_clash_proxy(ok, "JP-01").unwrap();
        assert_eq!(
            p2.iter().find(|(k, _)| k == "client-fingerprint").map(|(_, v)| match v {
                YamlValue::Scalar(s) => s.as_str(),
                _ => "",
            }),
            Some("chrome")
        );
    }

    #[test]
    fn yaml_is_parseable_and_round_trips() {
        let nodes = vec![
            vless(),
            "trojan://pass123@jp.example.com:443?sni=jp.example.com#%E6%97%A5%E6%9C%AC-01"
                .to_string(),
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388#SS-01".to_string(),
            "socks5://user:pw@5.6.7.8:1080#SOCKS-01".to_string(),
        ];
        let yaml = build_clash_yaml(&nodes, GROUP_MAIN, "rules").unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxies = doc
            .get("proxies")
            .and_then(|v| v.as_sequence())
            .expect("proxies list");
        assert_eq!(proxies.len(), 4);
        assert_eq!(
            proxies[0].get("name").and_then(|v| v.as_str()),
            Some("香港-01")
        );
        let groups = doc
            .get("proxy-groups")
            .and_then(|v| v.as_sequence())
            .expect("groups");
        assert!(groups.len() >= 7);
        let rules = doc
            .get("rules")
            .and_then(|v| v.as_sequence())
            .expect("rules");
        assert!(rules.len() > 100);
        // 空节点返回 None
        assert!(build_clash_yaml(&[], GROUP_MAIN, "rules").is_none());
        // global 模式
        let g = build_clash_yaml(&nodes, GROUP_MAIN, "global").unwrap();
        let gdoc: serde_yaml::Value = serde_yaml::from_str(&g).unwrap();
        assert!(gdoc.get("rules").is_some());
    }

    #[test]
    fn http_proxy_converts_with_auth() {
        let p = uri_to_clash_proxy(
            "http://user1:pass1@203.0.113.213:62000#%E7%BE%8E%E5%9B%BD-001",
            "🇺🇸二级美国节点1",
        )
        .unwrap();
        let get = |k: &str| {
            p.iter().find(|(key, _)| key == k).map(|(_, v)| match v {
                YamlValue::Scalar(s) => s.clone(),
                YamlValue::Int(n) => n.to_string(),
                YamlValue::Bool(b) => b.to_string(),
                _ => String::new(),
            })
        };
        assert_eq!(get("type").as_deref(), Some("http"));
        assert_eq!(get("server").as_deref(), Some("203.0.113.213"));
        assert_eq!(get("port").as_deref(), Some("62000"));
        assert_eq!(get("username").as_deref(), Some("user1"));
        assert_eq!(get("password").as_deref(), Some("pass1"));
        // 无账号的 http 代理不带账号字段
        let p2 = uri_to_clash_proxy("http://1.2.3.4:8080#n", "n").unwrap();
        assert!(p2.iter().find(|(k, _)| k == "username").is_none());
    }

    #[test]
    fn duplicate_names_are_numbered() {
        let nodes = vec![
            "trojan://p1@h1:443#同名".to_string(),
            "trojan://p2@h2:443#%E5%90%8C%E5%90%8D".to_string(),
        ];
        let yaml = build_clash_yaml(&nodes, GROUP_MAIN, "rules").unwrap();
        assert!(yaml.contains("同名 2"));
    }

    #[test]
    fn mixed_normal_and_openvpn_convert_together() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(vpngate_ovpn());
        let mut configs = std::collections::HashMap::new();
        configs.insert("🇯🇵一级日本节点1".to_string(), b64);
        let nodes = vec![
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls#%E9%A6%99%E6%B8%AF-01".to_string(),
            "openvpn://203.0.113.10:1195?proto=tcp#%F0%9F%87%AF%F0%9F%87%B5%E4%B8%80%E7%BA%A7%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B91".to_string(),
        ];
        let yaml = build_clash_yaml_mixed(&nodes, &configs, GROUP_MAIN, "rules").unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxies = doc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].get("type").and_then(|v| v.as_str()), Some("vless"));
        assert_eq!(proxies[1].get("type").and_then(|v| v.as_str()), Some("openvpn"));
        // 没有 .ovpn 配置的 openvpn 节点跳过，只剩普通节点
        let yaml2 = build_clash_yaml_mixed(&nodes, &std::collections::HashMap::new(), GROUP_MAIN, "rules").unwrap();
        let doc2: serde_yaml::Value = serde_yaml::from_str(&yaml2).unwrap();
        assert_eq!(doc2.get("proxies").and_then(|v| v.as_sequence()).unwrap().len(), 1);
        // 全是 openvpn 且无配置 → None
        assert!(build_clash_yaml_mixed(&nodes[1..], &std::collections::HashMap::new(), GROUP_MAIN, "rules").is_none());
    }

    /// VPNGate 真实 .ovpn 结构（取自 CSV 里的 base64 配置解码后）转 mihomo openvpn
    fn vpngate_ovpn() -> String {
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
    fn openvpn_converts_to_mihomo_proxy() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(vpngate_ovpn());
        let mut configs = std::collections::HashMap::new();
        configs.insert("🇯🇵三级日本节点1".to_string(), b64);
        let nodes = vec!["openvpn://203.0.113.10:1195?proto=tcp#%F0%9F%87%AF%F0%9F%87%B5%E4%B8%89%E7%BA%A7%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B91".to_string()];
        let yaml = build_clash_yaml_openvpn(&nodes, &configs, GROUP_MAIN, "rules").unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let proxies = doc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(proxies.len(), 1);
        let p = &proxies[0];
        assert_eq!(p.get("type").and_then(|v| v.as_str()), Some("openvpn"));
        assert_eq!(
            p.get("server").and_then(|v| v.as_str()),
            Some("203.0.113.10")
        );
        assert_eq!(p.get("port").and_then(|v| v.as_i64()), Some(1195));
        assert_eq!(p.get("proto").and_then(|v| v.as_str()), Some("tcp"));
        assert_eq!(p.get("udp").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            p.get("cipher").and_then(|v| v.as_str()),
            Some("AES-128-CBC")
        );
        assert_eq!(p.get("auth").and_then(|v| v.as_str()), Some("SHA1"));
        assert!(p
            .get("ca")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("MIIBCA=="));
        assert!(p
            .get("cert")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("MIIBCC=="));
        assert!(p
            .get("key")
            .and_then(|v| v.as_str())
            .unwrap()
            .contains("MIIBCK=="));
        // data-ciphers 是流式列表
        let dc = p.get("data-ciphers").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(dc.len(), 1);
        assert_eq!(dc[0].as_str(), Some("AES-128-CBC"));
        // 无 username/password（VPNGate 是证书认证）
        assert!(p.get("username").is_none());
        // 缺 ca 的配置跳过；全部失败返回 None
        let mut bad = std::collections::HashMap::new();
        bad.insert(
            "🇯🇵三级日本节点1".to_string(),
            STANDARD.encode("proto udp\nremote 198.51.100.20 443\n"),
        );
        assert!(build_clash_yaml_openvpn(&nodes, &bad, GROUP_MAIN, "rules").is_none());
        // 通用构造器仍不认 openvpn://（回归保护）
        assert!(build_clash_yaml(&nodes, GROUP_MAIN, "rules").is_none());
    }
}
