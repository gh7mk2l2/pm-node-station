//! sing-box 订阅生成（JSON 配置，原创实现）。
//! 订阅端按 User-Agent 分发：sing-box / SFI / SFA / Hiddify 等客户端。
//! tag 沿用节点备注。广告拦截只在 Clash 侧做（sing-box 的 block 写法跨版本断裂）。

use crate::nodes::{is_known_utls_fingerprint, read_node_name, try_decode_base64};
use crate::rules::*;
use serde_json::{json, Value};

type Outbound = Value;

fn safe_url(uri: &str) -> Option<url::Url> {
    url::Url::parse(uri).ok()
}

fn port_or_default(url: &url::Url, dft: u16) -> u16 {
    url.port().unwrap_or(dft)
}

fn userinfo(url: &url::Url) -> String {
    let user = percent_decode(url.username());
    match url.password() {
        Some(p) if !p.is_empty() => format!("{user}:{}", percent_decode(p)),
        _ => user,
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

fn query_param(url: &url::Url, key: &str) -> String {
    url.query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

pub fn uri_to_singbox_outbound(uri: &str, tag: &str) -> Option<Outbound> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("vless://") {
        return vless(uri, tag);
    }
    if lower.starts_with("hysteria2://") || lower.starts_with("hy2://") {
        return hysteria2(uri, tag);
    }
    if lower.starts_with("vmess://") {
        return vmess(uri, tag);
    }
    if lower.starts_with("ss://") {
        return ss(uri, tag);
    }
    if lower.starts_with("trojan://") {
        return trojan(uri, tag);
    }
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return socks5(uri, tag);
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return http_out(uri, tag);
    }
    None
}

fn http_out(uri: &str, tag: &str) -> Option<Outbound> {
    let url = safe_url(uri)?;
    if url.host_str().is_none() {
        return None;
    }
    let mut ob = json!({
        "type": "http",
        "tag": tag,
        "server": url.host_str().unwrap(),
        "server_port": port_or_default(&url, if url.scheme() == "https" { 443 } else { 80 }),
    });
    if !url.username().is_empty() {
        ob["username"] = json!(percent_decode(url.username()));
        ob["password"] = json!(percent_decode(url.password().unwrap_or("")));
    }
    if url.scheme() == "https" || query_param(&url, "tls") == "1" {
        ob["tls"] = json!({ "enabled": true });
    }
    Some(ob)
}

fn vless(uri: &str, tag: &str) -> Option<Outbound> {
    let url = safe_url(uri)?;
    let uuid = userinfo(&url);
    if uuid.is_empty() || url.host_str().is_none() {
        return None;
    }
    let security = query_param(&url, "security").to_ascii_lowercase();
    let network = query_param(&url, "type").to_ascii_lowercase();
    let flow = query_param(&url, "flow");
    let fp = query_param(&url, "fp");
    let mut ob = json!({
        "type": "vless",
        "tag": tag,
        "server": url.host_str().unwrap(),
        "server_port": port_or_default(&url, 443),
        "uuid": uuid,
    });
    if !flow.is_empty() {
        ob["flow"] = json!(flow);
    }
    if security == "reality" || security == "tls" {
        let insecure =
            query_param(&url, "insecure") == "1" || query_param(&url, "allowInsecure") == "1";
        let sni = query_param(&url, "sni");
        let mut tls = json!({ "enabled": true, "insecure": insecure });
        if !sni.is_empty() {
            tls["server_name"] = json!(sni);
        }
        // 未知的 uTLS 指纹（如上游带来的 unsafe）直接丢弃，只保留 TLS 本身，
        // 否则整份配置过不了 `sing-box check`
        if is_known_utls_fingerprint(&fp) {
            tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
        }
        if security == "reality" {
            let mut reality = json!({ "enabled": true });
            let pbk = query_param(&url, "pbk");
            let sid = query_param(&url, "sid");
            if !pbk.is_empty() {
                reality["public_key"] = json!(pbk);
            }
            if !sid.is_empty() {
                reality["short_id"] = json!(sid);
            }
            tls["reality"] = reality;
        }
        ob["tls"] = tls;
    }
    if network == "ws" {
        let ws_path = {
            let p = query_param(&url, "path");
            if p.is_empty() {
                "/".to_string()
            } else {
                p
            }
        };
        let mut ws = json!({ "type": "ws", "path": ws_path });
        let host = query_param(&url, "host");
        if !host.is_empty() {
            ws["headers"] = json!({ "Host": host });
        }
        ob["transport"] = ws;
    } else if network == "grpc" {
        let svc = query_param(&url, "serviceName");
        if !svc.is_empty() {
            ob["transport"] = json!({ "type": "grpc", "service_name": svc });
        }
    }
    Some(ob)
}

fn hysteria2(uri: &str, tag: &str) -> Option<Outbound> {
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
    let insecure =
        query_param(&url, "insecure") == "1" || query_param(&url, "allowInsecure") == "1";
    let pinned = {
        let a = query_param(&url, "pinSHA256");
        if a.is_empty() {
            query_param(&url, "pinned-sha256")
        } else {
            a
        }
    };
    let mut tls = json!({ "enabled": true, "insecure": insecure });
    if !sni.is_empty() {
        tls["server_name"] = json!(sni);
    }
    if !pinned.is_empty() {
        tls["certificate_public_key_sha256"] = json!([pinned]);
    }
    // obfs 直接拼到出站字段上（sing-box 1.8+ 的 hysteria2 支持 obfs）
    let mut ob = json!({
        "type": "hysteria2",
        "tag": tag,
        "server": url.host_str().unwrap(),
        "server_port": port_or_default(&url, 443),
        "password": password,
        "tls": tls,
    });
    let obfs = query_param(&url, "obfs");
    if !obfs.is_empty() {
        ob["obfs"] = json!({ "type": obfs, "password": query_param(&url, "obfs-password") });
    }
    Some(ob)
}

fn vmess(uri: &str, tag: &str) -> Option<Outbound> {
    let b64 = uri.split("://").nth(1)?;
    let json: Value = serde_json::from_str(&try_decode_base64(b64)?).ok()?;
    let server = json.get("add")?.as_str()?.to_string();
    let uuid = json.get("id")?.as_str()?.to_string();
    let port = json.get("port").and_then(|p| {
        p.as_str()
            .and_then(|s| s.parse::<u16>().ok())
            .or_else(|| p.as_u64().map(|v| v as u16))
    })?;
    if server.is_empty() || uuid.is_empty() || port == 0 {
        return None;
    }
    let mut ob = json!({
        "type": "vmess",
        "tag": tag,
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "security": json.get("scy").or_else(|| json.get("security")).and_then(|v| v.as_str()).unwrap_or("auto"),
        "alter_id": json.get("aid").and_then(|v| v.as_str().and_then(|s| s.parse::<i64>().ok()).or_else(|| v.as_i64())).unwrap_or(0),
    });
    if json.get("tls").and_then(|v| v.as_str()) == Some("tls") {
        let sni = json
            .get("sni")
            .or_else(|| json.get("host"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut tls = json!({ "enabled": true });
        if !sni.is_empty() {
            tls["server_name"] = json!(sni);
        }
        ob["tls"] = tls;
    }
    if json.get("net").and_then(|v| v.as_str()) == Some("ws") {
        let mut ws = json!({ "type": "ws", "path": json.get("path").and_then(|v| v.as_str()).unwrap_or("/") });
        if let Some(host) = json.get("host").and_then(|v| v.as_str()) {
            if !host.is_empty() {
                ws["headers"] = json!({ "Host": host });
            }
        }
        ob["transport"] = ws;
    }
    Some(ob)
}

fn ss(uri: &str, tag: &str) -> Option<Outbound> {
    let body = uri.split('#').next()?;
    if let Ok(url) = url::Url::parse(body) {
        if !url.host_str().unwrap_or("").is_empty() && !url.username().is_empty() {
            let decoded = try_decode_base64(&percent_decode(url.username()))?;
            let idx = decoded.find(':')?;
            return Some(json!({
                "type": "shadowsocks",
                "tag": tag,
                "server": url.host_str().unwrap(),
                "server_port": port_or_default(&url, 443),
                "method": &decoded[..idx],
                "password": &decoded[idx + 1..],
            }));
        }
    }
    let decoded = try_decode_base64(&body["ss://".len()..])?;
    let at = decoded.rfind('@')?;
    let (user_info, host_port) = (&decoded[..at], &decoded[at + 1..]);
    let colon = user_info.find(':')?;
    let host_colon = host_port.rfind(':')?;
    let port: u16 = host_port[host_colon + 1..].parse().ok()?;
    Some(json!({
        "type": "shadowsocks",
        "tag": tag,
        "server": &host_port[..host_colon],
        "server_port": port,
        "method": &user_info[..colon],
        "password": &user_info[colon + 1..],
    }))
}

fn trojan(uri: &str, tag: &str) -> Option<Outbound> {
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
    let insecure =
        query_param(&url, "allowInsecure") == "1" || query_param(&url, "insecure") == "1";
    let mut tls = json!({ "enabled": true, "insecure": insecure });
    if !sni.is_empty() {
        tls["server_name"] = json!(sni);
    }
    Some(json!({
        "type": "trojan",
        "tag": tag,
        "server": url.host_str().unwrap(),
        "server_port": port_or_default(&url, 443),
        "password": password,
        "tls": tls,
    }))
}

fn socks5(uri: &str, tag: &str) -> Option<Outbound> {
    let url = safe_url(uri)?;
    if url.host_str().is_none() {
        return None;
    }
    let mut ob = json!({
        "type": "socks",
        "tag": tag,
        "server": url.host_str().unwrap(),
        "server_port": port_or_default(&url, 1080),
        "version": "5",
    });
    if !url.username().is_empty() {
        ob["username"] = json!(percent_decode(url.username()));
        ob["password"] = json!(percent_decode(url.password().unwrap_or("")));
    }
    Some(ob)
}

/// 域名列表 → sing-box 匹配字段。
/// sing-box 的 domain_suffix 是纯字符串后缀匹配，直接写 google.com 会把
/// notgoogle.com 一并匹配进去，所以拆成两组：domain 精确匹配裸域，
/// domain_suffix 用带前导点的形式匹配子域。
fn domain_match(suffixes: &[&str]) -> (Vec<String>, Vec<String>) {
    (
        suffixes.iter().map(|s| s.to_string()).collect(),
        suffixes.iter().map(|s| format!(".{s}")).collect(),
    )
}

fn selector(tag: &str, members: Vec<String>) -> Outbound {
    json!({ "type": "selector", "tag": tag, "outbounds": members })
}

/// 生成完整 sing-box JSON；无可转换节点返回 None。
/// mode="rules" 输出分流配置；mode="global" 为全量代理回退。
pub fn build_singbox_config(nodes: &[String], selector_tag: &str, mode: &str) -> Option<String> {
    let mut outbounds: Vec<Outbound> = Vec::new();
    let mut seen_tags = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut tag = read_node_name(uri);
        if tag.starts_with('(') {
            fallback += 1;
            tag = format!("节点 {fallback}");
        }
        if seen_tags.contains(&tag) {
            let mut n = 2;
            while seen_tags.contains(&format!("{tag} {n}")) {
                n += 1;
            }
            tag = format!("{tag} {n}");
        }
        seen_tags.insert(tag.clone());
        if let Some(ob) = uri_to_singbox_outbound(uri, &tag) {
            outbounds.push(ob);
        }
    }
    if outbounds.is_empty() {
        return None;
    }
    let tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(|s| s.to_string()))
        .collect();
    Some(emit_singbox_config(
        &tags,
        outbounds,
        Vec::new(),
        selector_tag,
        mode,
    ))
}

/// 一级混合批次：普通节点进 outbounds，OpenVPN 节点进顶层 endpoints
///（openvpn-client），合并输出。哪个都转不出来就跳过该节点。
pub fn build_singbox_config_mixed(
    nodes: &[String],
    configs_b64: &std::collections::HashMap<String, String>,
    selector_tag: &str,
    mode: &str,
) -> Option<String> {
    let mut outbounds: Vec<Outbound> = Vec::new();
    let mut endpoints: Vec<Outbound> = Vec::new();
    let mut seen_tags = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut tag = read_node_name(uri);
        if tag.starts_with('(') {
            fallback += 1;
            tag = format!("节点 {fallback}");
        }
        if seen_tags.contains(&tag) {
            let mut n = 2;
            while seen_tags.contains(&format!("{tag} {n}")) {
                n += 1;
            }
            tag = format!("{tag} {n}");
        }
        seen_tags.insert(tag.clone());
        if uri.to_ascii_lowercase().starts_with("openvpn://") {
            let Some(b64) = configs_b64.get(&tag) else {
                continue;
            };
            let Some(text) = try_decode_base64(b64) else {
                continue;
            };
            let cfg = crate::openvpn::parse_ovpn_config(&text);
            if let Some(ep) = openvpn_to_singbox_endpoint(&cfg, &tag) {
                endpoints.push(ep);
            }
        } else if let Some(ob) = uri_to_singbox_outbound(uri, &tag) {
            outbounds.push(ob);
        }
    }
    if outbounds.is_empty() && endpoints.is_empty() {
        return None;
    }
    let mut tags: Vec<String> = outbounds
        .iter()
        .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(|s| s.to_string()))
        .collect();
    tags.extend(
        endpoints
            .iter()
            .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(|s| s.to_string())),
    );
    Some(emit_singbox_config(
        &tags,
        outbounds,
        endpoints,
        selector_tag,
        mode,
    ))
}

/// 三级 OpenVPN：把 .ovpn 配置转成 sing-box `openvpn-client` endpoint
/// （要求 sing-box ≥1.14；老版没有 openvpn endpoint 类型）。
/// configs：改名后节点名 → .ovpn 配置 base64。
/// 转换失败（缺 server/port/ca，或 auth-user-pass 却无账号）的节点跳过；全部失败返回 None。
pub fn build_singbox_config_openvpn(
    nodes: &[String],
    configs_b64: &std::collections::HashMap<String, String>,
    selector_tag: &str,
    mode: &str,
) -> Option<String> {
    let mut endpoints: Vec<Outbound> = Vec::new();
    let mut seen_tags = std::collections::HashSet::new();
    let mut fallback = 0;
    for uri in nodes {
        let mut tag = read_node_name(uri);
        if tag.starts_with('(') {
            fallback += 1;
            tag = format!("节点 {fallback}");
        }
        if seen_tags.contains(&tag) {
            let mut n = 2;
            while seen_tags.contains(&format!("{tag} {n}")) {
                n += 1;
            }
            tag = format!("{tag} {n}");
        }
        seen_tags.insert(tag.clone());
        let Some(b64) = configs_b64.get(&tag) else {
            continue;
        };
        let Some(text) = try_decode_base64(b64) else {
            continue;
        };
        let cfg = crate::openvpn::parse_ovpn_config(&text);
        if let Some(ep) = openvpn_to_singbox_endpoint(&cfg, &tag) {
            endpoints.push(ep);
        }
    }
    if endpoints.is_empty() {
        return None;
    }
    let tags: Vec<String> = endpoints
        .iter()
        .filter_map(|o| o.get("tag").and_then(|t| t.as_str()).map(|s| s.to_string()))
        .collect();
    Some(emit_singbox_config(
        &tags,
        Vec::new(),
        endpoints,
        selector_tag,
        mode,
    ))
}

/// .ovpn → sing-box openvpn-client endpoint（字段以 sing-box 1.14 openvpn-client 文档为准）。
/// 缺 server/port/ca，或 auth-user-pass 却无账号 → None（跳过该节点，不编默认值）。
/// 未映射的 .ovpn 指令见 OvpnConfig.unmapped（client/nobind/persist-*/resolv-retry/verb 等
/// 客户端进程选项，sing-box 没有对应字段；verify-x509-name 也没有对应字段）。
fn openvpn_to_singbox_endpoint(cfg: &crate::openvpn::OvpnConfig, tag: &str) -> Option<Outbound> {
    if cfg.server.is_empty() || cfg.port == 0 {
        return None;
    }
    let Some(ca) = &cfg.ca else {
        return None;
    };
    if cfg.auth_user_pass && (cfg.username.is_none() || cfg.password.is_none()) {
        return None;
    }
    let network = if cfg.proto == "tcp" { "tcp" } else { "udp" };
    let mut tls = json!({
        "certificate": [ca],
        "remote_certificate_tls": "server",
    });
    if let Some(cert) = &cfg.cert {
        tls["client_certificate"] = json!([cert]);
    }
    if let Some(key) = &cfg.key {
        tls["client_key"] = json!([key]);
    }
    if let Some(eku) = &cfg.remote_cert_eku {
        tls["remote_certificate_eku"] = json!(eku);
    }
    if let Some(vmin) = &cfg.tls_version_min {
        tls["version_min"] = json!(vmin);
    }
    // tls-auth / tls-crypt / tls-crypt-v2 → control_wrap（三者互斥）
    if let Some(ta) = &cfg.tls_auth {
        let mut wrap = json!({ "type": "tls_auth", "key": [ta] });
        if let Some(d) = cfg
            .key_direction
            .as_deref()
            .and_then(crate::openvpn::key_direction_to_singbox)
        {
            wrap["direction"] = json!(d);
        }
        tls["control_wrap"] = wrap;
    } else if let Some(tc) = &cfg.tls_crypt {
        tls["control_wrap"] = json!({ "type": "tls_crypt", "key": [tc] });
    } else if let Some(tc2) = &cfg.tls_crypt_v2 {
        tls["control_wrap"] = json!({ "type": "tls_crypt_v2", "key": [tc2] });
    }
    let mut ep = json!({
        "type": "openvpn-client",
        "tag": tag,
        "server": cfg.server,
        "server_port": cfg.port,
        "network": network,
        "tls": tls,
    });
    if let Some(u) = &cfg.username {
        ep["username"] = json!(u);
    }
    if let Some(p) = &cfg.password {
        ep["password"] = json!(p);
    }
    if !cfg.data_ciphers.is_empty() {
        ep["data_ciphers"] = json!(cfg.data_ciphers);
    }
    if let Some(fb) = &cfg.data_ciphers_fallback {
        ep["data_ciphers_fallback"] = json!(fb);
    }
    if let Some(auth) = &cfg.auth {
        ep["auth"] = json!(auth);
    }
    if let Some(t) = &cfg.topology {
        ep["topology"] = json!(t);
    }
    if let Some(lzo) = &cfg.comp_lzo {
        ep["compression_lzo"] = json!(lzo);
    }
    if let Some(c) = &cfg.compress {
        ep["compression"] = json!(c);
    }
    if let Some(p) = cfg.ping {
        ep["ping_interval"] = json!(format!("{p}s"));
    }
    if let Some(pr) = cfg.ping_restart {
        ep["ping_restart"] = json!(format!("{pr}s"));
    }
    if let Some(r) = cfg.reneg_sec {
        ep["renegotiate_interval"] = json!(format!("{r}s"));
    }
    if let Some(e) = cfg.explicit_exit_notify {
        ep["explicit_exit_notify"] = json!(e);
    }
    if let Some(m) = cfg.mssfix {
        ep["mss_fix"] = json!(m);
    }
    // fragment 与 TCP 传输冲突，只在 UDP 时发
    if let Some(f) = cfg.fragment {
        if network == "udp" {
            ep["fragment"] = json!(f);
        }
    }
    if let Some(rct) = &cfg.remote_cert_tls {
        if rct == "client" {
            ep["tls"]["remote_certificate_tls"] = json!("client");
        }
    }
    Some(ep)
}

/// 节点（outbounds 或 endpoints）→ 完整 sing-box JSON 配置。
/// endpoints 非空时输出顶层 "endpoints"（三级 OpenVPN 用）；其余结构与原来一致。
fn emit_singbox_config(
    tags: &[String],
    node_outbounds: Vec<Outbound>,
    endpoints: Vec<Outbound>,
    selector_tag: &str,
    mode: &str,
) -> String {
    let direct: Outbound = json!({ "type": "direct", "tag": "direct" });

    if mode == "global" {
        let mut members = tags.to_vec();
        members.push("direct".to_string());
        let mut all = vec![selector(selector_tag, members)];
        all.extend(node_outbounds);
        all.push(direct);
        let mut doc = json!({
            "log": { "level": "warn" },
            "outbounds": all,
            "route": { "final": selector_tag },
        });
        if !endpoints.is_empty() {
            doc["endpoints"] = json!(endpoints);
        }
        return serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into());
    }

    let auto: Outbound = json!({
        "type": "urltest",
        "tag": GROUP_AUTO,
        "outbounds": tags,
        "url": "http://www.gstatic.com/generate_204",
        "interval": "5m",
        "tolerance": 50,
    });

    let mut main_members = vec![GROUP_AUTO.to_string()];
    main_members.extend(tags.iter().cloned());
    main_members.push("direct".to_string());
    let mut media_members = vec![selector_tag.to_string(), GROUP_AUTO.to_string()];
    media_members.extend(tags.iter().cloned());
    media_members.push("direct".to_string());

    let groups: Vec<Outbound> = vec![
        selector(selector_tag, main_members),
        auto,
        selector(GROUP_MEDIA, media_members.clone()),
        selector(GROUP_TELEGRAM, media_members),
        selector(
            GROUP_MICROSOFT,
            vec!["direct".into(), selector_tag.into(), GROUP_AUTO.into()],
        ),
        selector(
            GROUP_APPLE,
            vec!["direct".into(), selector_tag.into(), GROUP_AUTO.into()],
        ),
        selector(
            GROUP_FINAL,
            vec![selector_tag.into(), GROUP_AUTO.into(), "direct".into()],
        ),
    ];

    let (priv_dom, priv_suf) = domain_match(PRIVATE_DOMAINS);
    let (tg_dom, tg_suf) = domain_match(TELEGRAM_DOMAINS);
    let (ms_dom, ms_suf) = domain_match(MICROSOFT_DOMAINS);
    let (ap_dom, ap_suf) = domain_match(APPLE_DOMAINS);
    let (md_dom, md_suf) = domain_match(MEDIA_DOMAINS);
    let (px_dom, px_suf) = domain_match(PROXY_DOMAINS);
    let (cn_dom, cn_suf) = domain_match(CN_DOMAINS);

    let rules: Vec<Outbound> = vec![
        json!({ "ip_cidr": PRIVATE_CIDRS, "outbound": "direct" }),
        json!({ "domain": priv_dom, "domain_suffix": priv_suf, "outbound": "direct" }),
        json!({ "domain": tg_dom, "domain_suffix": tg_suf, "outbound": GROUP_TELEGRAM }),
        json!({ "ip_cidr": TELEGRAM_CIDRS, "outbound": GROUP_TELEGRAM }),
        json!({ "domain": ms_dom, "domain_suffix": ms_suf, "outbound": GROUP_MICROSOFT }),
        json!({ "domain": ap_dom, "domain_suffix": ap_suf, "outbound": GROUP_APPLE }),
        json!({ "domain": md_dom, "domain_suffix": md_suf, "outbound": GROUP_MEDIA }),
        json!({ "domain": px_dom, "domain_suffix": px_suf, "outbound": selector_tag }),
        json!({ "domain": cn_dom, "domain_suffix": cn_suf, "outbound": "direct" }),
    ];

    let mut all_outbounds = groups;
    all_outbounds.extend(node_outbounds);
    all_outbounds.push(direct);

    let mut doc = json!({
        "log": { "level": "warn" },
        "outbounds": all_outbounds,
        "route": { "rules": rules, "final": GROUP_FINAL },
    });
    if !endpoints.is_empty() {
        doc["endpoints"] = json!(endpoints);
    }
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nodes() -> Vec<String> {
        vec![
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls&sni=hk.example.com&type=ws&path=%2Fws&host=hk.example.com#%E9%A6%99%E6%B8%AF-01".to_string(),
            "trojan://pass123@jp.example.com:443?sni=jp.example.com#%E6%97%A5%E6%9C%AC-01".to_string(),
            "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388#SS-01".to_string(),
            "socks5://user:pw@5.6.7.8:1080#SOCKS-01".to_string(),
            "hysteria2://secret@hy.example.com:443?sni=hy.example.com#HY-01".to_string(),
        ]
    }

    #[test]
    fn singbox_json_is_valid_and_complete() {
        let json = build_singbox_config(&nodes(), GROUP_MAIN, "rules").unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        let outbounds = doc["outbounds"].as_array().unwrap();
        // 7 个组 + 5 个节点 + 1 个 direct
        assert_eq!(outbounds.len(), 13);
        let tags: Vec<&str> = outbounds
            .iter()
            .filter_map(|o| o.get("tag").and_then(|t| t.as_str()))
            .collect();
        assert!(tags.contains(&"香港-01"));
        assert!(tags.contains(&"自动选择"));
        let rules = doc["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 9);
        assert_eq!(doc["route"]["final"], GROUP_FINAL);
        // global 模式
        let g = build_singbox_config(&nodes(), GROUP_MAIN, "global").unwrap();
        let gdoc: Value = serde_json::from_str(&g).unwrap();
        assert_eq!(gdoc["route"]["final"], GROUP_MAIN);
        // 空节点返回 None
        assert!(build_singbox_config(&[], GROUP_MAIN, "rules").is_none());
    }

    #[test]
    fn http_outbound_converts_with_auth() {
        let ob = uri_to_singbox_outbound(
            "http://user1:pass1@203.0.113.213:62000#%E7%BE%8E%E5%9B%BD-001",
            "🇺🇸二级美国节点1",
        )
        .unwrap();
        assert_eq!(ob["type"], "http");
        assert_eq!(ob["server"], "203.0.113.213");
        assert_eq!(ob["server_port"], 62000);
        assert_eq!(ob["username"], "user1");
        assert_eq!(ob["password"], "pass1");
    }

    #[test]
    fn unknown_utls_fingerprint_is_dropped() {
        // 上游带来的 fp=unsafe 会让 `sing-box check` 直接 FATAL：丢弃指纹，只保留 TLS
        let ob = uri_to_singbox_outbound(
            "vless://550e8400-e29b-41d4-a716-446655440000@jp.example.com:443?security=tls&sni=jp.example.com&fp=unsafe#JP-01",
            "JP-01",
        )
        .unwrap();
        assert_eq!(ob["tls"]["enabled"], true);
        assert!(ob["tls"].get("utls").is_none());
        // 已知指纹正常保留
        let ob2 = uri_to_singbox_outbound(
            "vless://550e8400-e29b-41d4-a716-446655440000@jp.example.com:443?security=tls&sni=jp.example.com&fp=chrome#JP-01",
            "JP-01",
        )
        .unwrap();
        assert_eq!(ob2["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn vmess_converts() {
        let payload = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.encode(
                r#"{"v":"2","ps":"VMESS-01","add":"vm.example.com","port":"443","id":"550e8400-e29b-41d4-a716-446655440000","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/ws","tls":"tls","sni":"vm.example.com"}"#.as_bytes(),
            )
        };
        let ob = uri_to_singbox_outbound(&format!("vmess://{payload}"), "VMESS-01").unwrap();
        assert_eq!(ob["type"], "vmess");
        assert_eq!(ob["server"], "vm.example.com");
        assert_eq!(ob["transport"]["type"], "ws");
    }

    #[test]
    fn mixed_normal_and_openvpn_convert_together() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(vpngate_ovpn());
        let mut configs = std::collections::HashMap::new();
        configs.insert("🇯🇵一级日本节点1".to_string(), b64);
        let nodes = vec![
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls#%E9%A6%99%E6%B8%AF-01".to_string(),
            "openvpn://203.0.113.10:1195?proto=udp#%F0%9F%87%AF%F0%9F%87%B5%E4%B8%80%E7%BA%A7%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B91".to_string(),
        ];
        let json = build_singbox_config_mixed(&nodes, &configs, GROUP_MAIN, "rules").unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        let outbounds = doc["outbounds"].as_array().unwrap();
        assert!(outbounds
            .iter()
            .any(|o| o.get("type").and_then(|t| t.as_str()) == Some("vless")));
        let endpoints = doc["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["type"], "openvpn-client");
        assert_eq!(endpoints[0]["tag"], "🇯🇵一级日本节点1");
        // 分组里能引用 endpoint 的 tag
        let tags: Vec<&str> = outbounds
            .iter()
            .filter_map(|o| o.get("outbounds"))
            .flat_map(|v| v.as_array().unwrap().iter())
            .filter_map(|t| t.as_str())
            .collect();
        assert!(tags.contains(&"🇯🇵一级日本节点1"));
        // 无配置时 openvpn 节点跳过，只剩普通节点，且无 endpoints 段
        let json2 =
            build_singbox_config_mixed(&nodes, &std::collections::HashMap::new(), GROUP_MAIN, "rules").unwrap();
        let doc2: Value = serde_json::from_str(&json2).unwrap();
        assert!(doc2.get("endpoints").is_none());
        assert!(build_singbox_config_mixed(&nodes[1..], &std::collections::HashMap::new(), GROUP_MAIN, "rules").is_none());
    }

    /// VPNGate 真实 .ovpn 结构（取自 CSV 里的 base64 配置解码后）转 sing-box openvpn-client
    fn vpngate_ovpn() -> String {
        [
            "client",
            "dev tun",
            "proto udp",
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
    fn openvpn_converts_to_singbox_endpoint() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let b64 = STANDARD.encode(vpngate_ovpn());
        let mut configs = std::collections::HashMap::new();
        configs.insert("🇯🇵三级日本节点1".to_string(), b64);
        let nodes = vec!["openvpn://203.0.113.10:1195?proto=udp#%F0%9F%87%AF%F0%9F%87%B5%E4%B8%89%E7%BA%A7%E6%97%A5%E6%9C%AC%E8%8A%82%E7%82%B91".to_string()];
        let json = build_singbox_config_openvpn(&nodes, &configs, GROUP_MAIN, "rules").unwrap();
        let doc: Value = serde_json::from_str(&json).unwrap();
        // endpoints 在顶层，不在 outbounds 里
        let endpoints = doc["endpoints"].as_array().unwrap();
        assert_eq!(endpoints.len(), 1);
        let ep = &endpoints[0];
        assert_eq!(ep["type"], "openvpn-client");
        assert_eq!(ep["tag"], "🇯🇵三级日本节点1");
        assert_eq!(ep["server"], "203.0.113.10");
        assert_eq!(ep["server_port"], 1195);
        assert_eq!(ep["network"], "udp");
        assert_eq!(
            ep["tls"]["certificate"][0]
                .as_str()
                .unwrap()
                .contains("MIIBCA=="),
            true
        );
        assert_eq!(
            ep["tls"]["client_certificate"][0]
                .as_str()
                .unwrap()
                .contains("MIIBCC=="),
            true
        );
        assert_eq!(
            ep["tls"]["client_key"][0]
                .as_str()
                .unwrap()
                .contains("MIIBCK=="),
            true
        );
        assert_eq!(ep["data_ciphers"][0], "AES-128-CBC");
        assert_eq!(ep["auth"], "SHA1");
        // cipher 是 static_key 模式才有的字段，TLS 模式不能发
        assert!(ep.get("cipher").is_none());
        // 分组里能引用 endpoint 的 tag
        let tags: Vec<&str> = doc["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.get("outbounds"))
            .flat_map(|v| v.as_array().unwrap().iter())
            .filter_map(|t| t.as_str())
            .collect();
        assert!(tags.contains(&"🇯🇵三级日本节点1"));
        // 缺 ca 的配置跳过；全部失败返回 None
        let mut bad = std::collections::HashMap::new();
        bad.insert(
            "🇯🇵三级日本节点1".to_string(),
            STANDARD.encode("proto udp\nremote 198.51.100.20 443\n"),
        );
        assert!(build_singbox_config_openvpn(&nodes, &bad, GROUP_MAIN, "rules").is_none());
        // 通用构造器仍不认 openvpn://（回归保护）
        assert!(build_singbox_config(&nodes, GROUP_MAIN, "rules").is_none());
    }
}
