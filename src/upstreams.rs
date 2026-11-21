//! 一级多上游解析（原创实现）。
//!
//! 上游 URL 只存在 tier1_upstreams 表里（服务端配置），这里只有格式解析，
//! 绝不出现任何上游地址。支持的格式：
//! - clash：Clash YAML（只取顶层 proxies，忽略 proxy-groups；type=openvpn 的
//!   代理单独合成 .ovpn 文本，走三级同款转换路径）
//! - base64：整段 Base64 链接串（标准 + URL-safe 解码，按行解析）
//! - json_scdn / json_geonode / json_fineproxy：三个代理列表 JSON API
//! - txt_proxora：纯文本 ip:port 列表
//! - html_proxyhub / html_remproxy：两个 HTML 表格（轻量解析；解析失败只记
//!   0 节点 + error，不拖垮整批）
//!
//! 不支持的类型直接跳过并计数，不硬编：ssr、anytls、wireguard、hysteria v1、
//! socks4（以及 snell / juicity / ssh 等本站转换器不认的类型）。

use crate::nodes::{
    clash_proxy_to_uri, dedupe_nodes, endpoint_key, parse_node_endpoint, protocol_of,
    try_decode_base64, yaml_port, yaml_text,
};
use chrono::{Datelike, NaiveDate};
use std::collections::HashMap;

/// 上游格式（与 tier1_upstreams.format 的取值一一对应）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpstreamFormat {
    Clash,
    Base64,
    JsonScdn,
    JsonGeonode,
    JsonFineproxy,
    TxtProxora,
    HtmlProxyhub,
    HtmlRemproxy,
}

pub fn parse_format(s: &str) -> Option<UpstreamFormat> {
    match s {
        "clash" => Some(UpstreamFormat::Clash),
        "base64" => Some(UpstreamFormat::Base64),
        "json_scdn" => Some(UpstreamFormat::JsonScdn),
        "json_geonode" => Some(UpstreamFormat::JsonGeonode),
        "json_fineproxy" => Some(UpstreamFormat::JsonFineproxy),
        "txt_proxora" => Some(UpstreamFormat::TxtProxora),
        "html_proxyhub" => Some(UpstreamFormat::HtmlProxyhub),
        "html_remproxy" => Some(UpstreamFormat::HtmlRemproxy),
        _ => None,
    }
}

/// tier1_upstreams 表的一行（URL 只存库里，不进代码）
#[derive(Debug, Clone)]
pub struct Tier1Upstream {
    pub id: i64,
    pub label: String,
    pub url_template: String,
    pub format: UpstreamFormat,
    pub kind: String,
    pub enabled: bool,
}

/// 一个上游的解析结果。
/// - nodes：解析出的节点 URI（openvpn 节点也在内，URI 形如 openvpn://host:port?proto=x#改名前节点名）
/// - openvpn：与 nodes 一一对应的 .ovpn 配置（改名前节点名 → .ovpn 文本），
///   只有 Clash 里 type=openvpn 的代理才有；同步时按改名映射入库 openvpn_configs
/// - skipped：跳过的类型统计（类型 → 个数），如 ("ssr", 57)、("socks4", 58)
#[derive(Debug, Clone, Default)]
pub struct ParsedUpstream {
    pub nodes: Vec<String>,
    pub openvpn: Vec<(String, String)>,
    pub skipped: Vec<(String, usize)>,
}

impl ParsedUpstream {
    fn add_skipped(map: &mut HashMap<String, usize>, kind: &str) {
        *map.entry(kind.to_string()).or_insert(0) += 1;
    }

    fn finish(nodes: Vec<String>, openvpn: Vec<(String, String)>, map: HashMap<String, usize>) -> Self {
        let mut skipped: Vec<(String, usize)> = map.into_iter().collect();
        skipped.sort();
        Self {
            nodes,
            openvpn,
            skipped,
        }
    }
}

/// 站内转换器支持的节点协议（与 clash.rs / singbox.rs 的 uri 转换一致）。
/// 不在此列的协议（ssr、anytls、wireguard、hysteria v1、socks4 等）只跳过计数。
pub fn is_supported_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "vless" | "vmess" | "ss" | "trojan" | "hysteria2" | "hy2" | "tuic" | "socks5"
            | "socks" | "http" | "https" | "openvpn"
    )
}

/// 过滤节点：只留转换器支持的协议，其余按 scheme 计数跳过。
/// 返回（保留的节点，跳过统计）。
pub fn filter_supported(nodes: &[String]) -> (Vec<String>, Vec<(String, usize)>) {
    let mut kept = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    for n in nodes {
        let scheme = protocol_of(n);
        if is_supported_scheme(&scheme) {
            kept.push(n.clone());
        } else {
            ParsedUpstream::add_skipped(&mut skipped, &scheme);
        }
    }
    let mut skipped: Vec<(String, usize)> = skipped.into_iter().collect();
    skipped.sort();
    (kept, skipped)
}

/// 按 server+port+类型去重（保持首次出现顺序）。
/// 端点解析不到的节点退回整条 URI 去重。
pub fn dedupe_by_endpoint(nodes: &[String]) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for n in nodes {
        let key = match parse_node_endpoint(n) {
            Some(ep) => {
                // hy2 与 hysteria2、socks 与 socks5 是同一类型，去重时归一
                let scheme = match ep.scheme.as_str() {
                    "hy2" => "hysteria2".to_string(),
                    "socks" => "socks5".to_string(),
                    other => other.to_string(),
                };
                format!(
                    "{}://{}:{}",
                    scheme,
                    ep.host.to_ascii_lowercase(),
                    ep.port
                )
            }
            None => n.clone(),
        };
        if seen.insert(key) {
            out.push(n.clone());
        }
    }
    out
}

/// 解析单个上游的原始内容（按格式分发）。
pub fn parse_upstream_content(raw: &str, format: UpstreamFormat) -> ParsedUpstream {
    match format {
        UpstreamFormat::Clash => parse_clash(raw),
        UpstreamFormat::Base64 => parse_base64(raw),
        UpstreamFormat::JsonScdn => parse_json_scdn(raw),
        UpstreamFormat::JsonGeonode => parse_json_geonode(raw),
        UpstreamFormat::JsonFineproxy => parse_json_fineproxy(raw),
        UpstreamFormat::TxtProxora => parse_txt_ip_ports(raw),
        UpstreamFormat::HtmlProxyhub => parse_html_proxyhub(raw),
        UpstreamFormat::HtmlRemproxy => parse_html_remproxy(raw),
    }
}

// ---------------------------------------------------------------------------
// Clash YAML
// ---------------------------------------------------------------------------

fn parse_clash(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut openvpn = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    let document: serde_yaml::Value = match serde_yaml::from_str(raw) {
        Ok(v) => v,
        Err(_) => return ParsedUpstream::default(),
    };
    let Some(root) = document.as_mapping() else {
        return ParsedUpstream::default();
    };
    let Some(proxies) = root
        .get(serde_yaml::Value::String("proxies".to_string()))
        .and_then(|v| v.as_sequence())
    else {
        return ParsedUpstream::default();
    };
    for proxy in proxies {
        let Some(mapping) = proxy.as_mapping() else {
            continue;
        };
        let get = |k: &str| mapping.get(serde_yaml::Value::String(k.to_string()));
        let typ = get("type")
            .and_then(yaml_text)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if typ == "openvpn" {
            match clash_openvpn_parts(mapping) {
                Some((uri, pre_name, ovpn_text)) => {
                    nodes.push(uri);
                    openvpn.push((pre_name, ovpn_text));
                }
                None => ParsedUpstream::add_skipped(&mut skipped, "openvpn"),
            }
            continue;
        }
        match clash_proxy_to_uri(proxy) {
            Some(uri) => nodes.push(uri),
            None => ParsedUpstream::add_skipped(&mut skipped, typ.as_str()),
        }
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), openvpn, skipped)
}

/// Clash openvpn 代理 →（openvpn:// URI，改名前节点名，.ovpn 文本）。
/// 缺 server/port/ca 时返回 None（转换路径同样会跳过，不编默认值）。
/// .ovpn 文本按 src/openvpn.rs 的解析器字段合成；Clash 自带的 username/password
/// 记为 `# pm-username / # pm-password` 内联标记（本站合成标记，非标准 .ovpn
/// 指令，仅供 openvpn.rs 解析器读取，转换时不原样输出）。
fn clash_openvpn_parts(
    mapping: &serde_yaml::Mapping,
) -> Option<(String, String, String)> {
    let get = |k: &str| mapping.get(serde_yaml::Value::String(k.to_string()));
    let server = get("server").and_then(yaml_text)?;
    let port = get("port").and_then(yaml_port)?;
    let name = get("name")
        .and_then(yaml_text)
        .unwrap_or_else(|| format!("openvpn-{server}:{port}"));
    let ca = get("ca").and_then(yaml_text)?;
    if server.is_empty() || ca.trim().is_empty() {
        return None;
    }
    let proto = get("proto")
        .and_then(yaml_text)
        .unwrap_or_else(|| "udp".to_string())
        .to_ascii_lowercase();
    let proto = if proto == "tcp" { "tcp" } else { "udp" }.to_string();
    let uri = format!(
        "openvpn://{}:{}?proto={}#{}",
        format_host(&server),
        port,
        proto,
        urlencoding(&name)
    );

    let mut lines: Vec<String> = vec![
        "client".to_string(),
        "dev tun".to_string(),
        format!("proto {proto}"),
        format!("remote {server} {port}"),
    ];
    if let Some(cipher) = get("cipher").and_then(yaml_text) {
        if !cipher.is_empty() {
            lines.push(format!("cipher {cipher}"));
        }
    }
    if let Some(dc) = get("data-ciphers") {
        let joined = match dc {
            serde_yaml::Value::Sequence(seq) => seq
                .iter()
                .filter_map(yaml_text)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(":"),
            other => yaml_text(other).unwrap_or_default(),
        };
        if !joined.is_empty() {
            lines.push(format!("data-ciphers {joined}"));
        }
    }
    if let Some(fb) = get("data-ciphers-fallback").and_then(yaml_text) {
        if !fb.is_empty() {
            lines.push(format!("data-ciphers-fallback {fb}"));
        }
    }
    if let Some(auth) = get("auth").and_then(yaml_text) {
        if !auth.is_empty() {
            lines.push(format!("auth {auth}"));
        }
    }
    if let Some(lzo) = get("comp-lzo").and_then(yaml_text) {
        if !lzo.is_empty() {
            lines.push(format!("comp-lzo {lzo}"));
        }
    }
    let username = get("username").and_then(yaml_text).unwrap_or_default();
    let password = get("password").and_then(yaml_text).unwrap_or_default();
    if !username.is_empty() {
        lines.push("auth-user-pass".to_string());
        lines.push(format!("# pm-username {username}"));
        if !password.is_empty() {
            lines.push(format!("# pm-password {password}"));
        }
    }
    for (key, tag) in [
        ("ca", "ca"),
        ("cert", "cert"),
        ("key", "key"),
        ("tls-auth", "tls-auth"),
        ("tls-crypt", "tls-crypt"),
        ("tls-crypt-v2", "tls-crypt-v2"),
    ] {
        if let Some(content) = get(key).and_then(yaml_text) {
            if content.trim().is_empty() {
                continue;
            }
            lines.push(format!("<{tag}>"));
            lines.push(content.trim().to_string());
            lines.push(format!("</{tag}>"));
        }
    }
    if let Some(dir) = get("key-direction").and_then(yaml_text) {
        if !dir.is_empty() {
            lines.push(format!("key-direction {dir}"));
        }
    }
    Some((uri, name, lines.join("\n")))
}

fn format_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn urlencoding(s: &str) -> String {
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

// ---------------------------------------------------------------------------
// Base64 链接串
// ---------------------------------------------------------------------------

fn parse_base64(raw: &str) -> ParsedUpstream {
    let nodes = crate::nodes::parse_subscription_nodes(raw);
    let (kept, mut skipped) = filter_supported(&nodes);
    // 解析层的协议白名单直接丢弃 anytls / socks4 这类行（连 filter_supported
    // 都见不到），这里从原文里补数；白名单内的行已由 filter_supported 计数，
    // 不重复算。
    let mut text = raw.to_string();
    if !raw.contains("://") {
        let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        if let Some(decoded) = try_decode_base64(&compact) {
            text = decoded;
        }
    }
    let mut extra: HashMap<String, usize> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(idx) = line.find("://") else {
            continue;
        };
        let scheme = line[..idx].to_ascii_lowercase();
        if matches!(scheme.as_str(), "anytls" | "socks4") {
            *extra.entry(scheme).or_insert(0) += 1;
        }
    }
    for (k, v) in extra {
        if let Some(slot) = skipped.iter_mut().find(|(s, _)| *s == k) {
            slot.1 += v;
        } else {
            skipped.push((k, v));
        }
    }
    skipped.sort();
    ParsedUpstream {
        nodes: dedupe_nodes(&kept),
        openvpn: Vec::new(),
        skipped,
    }
}

// ---------------------------------------------------------------------------
// JSON 代理列表
// ---------------------------------------------------------------------------

/// scdn：{"data": {"proxies": ["ip:port", ...]}}，未标注协议，按 http 导入。
fn parse_json_scdn(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    let doc: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return ParsedUpstream::default(),
    };
    let Some(proxies) = doc
        .get("data")
        .and_then(|d| d.get("proxies"))
        .and_then(|p| p.as_array())
    else {
        return ParsedUpstream::default();
    };
    for item in proxies {
        let Some(addr) = item.as_str() else {
            ParsedUpstream::add_skipped(&mut skipped, "malformed");
            continue;
        };
        match parse_ip_port(addr) {
            Some((ip, port)) => {
                nodes.push(format!("http://{ip}:{port}#{ip}:{port}"));
            }
            None => ParsedUpstream::add_skipped(&mut skipped, "malformed"),
        }
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

/// geonode：{"data": [{"ip", "port", "protocols": [...], "country": "US"}]}。
/// 多协议只取一个节点，优先 http，其次 https，再 socks5；只剩 socks4 的跳过计数。
fn parse_json_geonode(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    let doc: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return ParsedUpstream::default(),
    };
    let Some(data) = doc.get("data").and_then(|d| d.as_array()) else {
        return ParsedUpstream::default();
    };
    for item in data {
        let Some(ip) = item.get("ip").and_then(|v| v.as_str()) else {
            ParsedUpstream::add_skipped(&mut skipped, "malformed");
            continue;
        };
        let port = match item.get("port") {
            Some(serde_json::Value::String(s)) => s.trim().parse::<u16>().ok(),
            Some(serde_json::Value::Number(n)) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
            _ => None,
        };
        let Some(port) = port.filter(|p| *p > 0) else {
            ParsedUpstream::add_skipped(&mut skipped, "malformed");
            continue;
        };
        let protocols: Vec<String> = item
            .get("protocols")
            .and_then(|p| p.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let country = item
            .get("country")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let scheme = if protocols.iter().any(|p| p == "http") {
            "http"
        } else if protocols.iter().any(|p| p == "https") {
            "https"
        } else if protocols.iter().any(|p| p == "socks5") {
            "socks5"
        } else {
            let first = protocols.first().cloned().unwrap_or_else(|| "unknown".to_string());
            ParsedUpstream::add_skipped(&mut skipped, &first);
            continue;
        };
        let label = if country.is_empty() {
            format!("{ip}:{port}")
        } else {
            format!("{country}-{ip}:{port}")
        };
        nodes.push(format!("{scheme}://{ip}:{port}#{label}"));
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

/// fineproxy：{"rows": [{"ip", "port", "protos": ["HTTP", ...], "country": "France"}]}。
/// 单行多协议只取一个节点，优先 HTTP 其次 SOCKS5；country 为空时只用 ip:port 作备注
/// （改名时识别不到国家，保留原名）。
fn parse_json_fineproxy(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    let doc: serde_json::Value = match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(_) => return ParsedUpstream::default(),
    };
    let Some(rows) = doc.get("rows").and_then(|r| r.as_array()) else {
        return ParsedUpstream::default();
    };
    for item in rows {
        let Some(ip) = item.get("ip").and_then(|v| v.as_str()) else {
            ParsedUpstream::add_skipped(&mut skipped, "malformed");
            continue;
        };
        let port = match item.get("port") {
            Some(serde_json::Value::Number(n)) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
            Some(serde_json::Value::String(s)) => s.trim().parse::<u16>().ok(),
            _ => None,
        };
        let Some(port) = port.filter(|p| *p > 0) else {
            ParsedUpstream::add_skipped(&mut skipped, "malformed");
            continue;
        };
        let protos: Vec<String> = item
            .get("protos")
            .and_then(|p| p.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_lowercase()))
                    .collect()
            })
            .unwrap_or_default();
        let country = item
            .get("country")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let scheme = if protos.iter().any(|p| p == "http") {
            "http"
        } else if protos.iter().any(|p| p == "socks5") {
            "socks5"
        } else {
            let first = protos.first().cloned().unwrap_or_else(|| "unknown".to_string());
            ParsedUpstream::add_skipped(&mut skipped, &first);
            continue;
        };
        let label = if country.is_empty() {
            format!("{ip}:{port}")
        } else {
            format!("{country} {ip}:{port}")
        };
        nodes.push(format!("{scheme}://{ip}:{port}#{label}"));
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

// ---------------------------------------------------------------------------
// 纯文本 ip:port
// ---------------------------------------------------------------------------

/// proxora：每行一个 ip:port，未标注协议，按 http 导入。
fn parse_txt_ip_ports(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_ip_port(line) {
            Some((ip, port)) => {
                nodes.push(format!("http://{ip}:{port}#{ip}:{port}"));
            }
            None => ParsedUpstream::add_skipped(&mut skipped, "malformed"),
        }
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

/// 解析 "ip:port"（IPv4 或 [IPv6]:port）；非法返回 None
fn parse_ip_port(addr: &str) -> Option<(String, u16)> {
    let addr = addr.trim();
    if let Some(stripped) = addr.strip_prefix('[') {
        let end = stripped.find(']')?;
        let ip = &stripped[..end];
        let port: u16 = stripped[end + 1..].strip_prefix(':')?.parse().ok()?;
        if port == 0 || ip.parse::<std::net::IpAddr>().is_err() {
            return None;
        }
        return Some((ip.to_string(), port));
    }
    let colon = addr.rfind(':')?;
    let (ip, port) = (&addr[..colon], &addr[colon + 1..]);
    let port: u16 = port.parse().ok()?;
    if port == 0 || ip.parse::<std::net::IpAddr>().is_err() {
        return None;
    }
    Some((ip.to_string(), port))
}

// ---------------------------------------------------------------------------
// HTML 表格（轻量解析；失败只返回空结果，调用方记 0 节点 + error）
// ---------------------------------------------------------------------------

/// 去掉一格里的全部标签并解码少量实体
fn strip_tags(cell: &str) -> String {
    let mut out = String::with_capacity(cell.len());
    let mut in_tag = false;
    for c in cell.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&nbsp;", " ")
        .trim()
        .to_string()
}

/// 提取 <tr>…</tr> 行，每行取 <td>…</td> 格（表头 <th> 行不含 td，自动跳过）
fn html_table_rows(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for part in text.split("<tr") {
        let Some(end) = part.find("</tr>") else {
            continue;
        };
        let row_html = &part[..end];
        let mut cells = Vec::new();
        for cell_part in row_html.split("<td") {
            let Some(gt) = cell_part.find('>') else {
                continue;
            };
            let Some(close) = cell_part.find("</td>") else {
                continue;
            };
            cells.push(strip_tags(&cell_part[gt + 1..close]));
        }
        if !cells.is_empty() {
            rows.push(cells);
        }
    }
    rows
}

/// proxyhub：行 = [国家, IP, 端口, 协议, 匿名级, 时间]，协议 HTTP。
fn parse_html_proxyhub(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    for cells in html_table_rows(raw) {
        if cells.len() < 4 {
            continue;
        }
        let (country, ip, port_s, proto) = (&cells[0], &cells[1], &cells[2], &cells[3]);
        let Ok(port) = port_s.trim().parse::<u16>() else {
            continue;
        };
        if port == 0 || ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        let proto_l = proto.to_ascii_lowercase();
        let scheme = if proto_l.contains("http") {
            "http"
        } else if proto_l.contains("socks5") {
            "socks5"
        } else {
            ParsedUpstream::add_skipped(&mut skipped, &proto_l);
            continue;
        };
        let label = format!("{country} {ip}:{port}");
        nodes.push(format!("{scheme}://{ip}:{port}#{label}"));
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

/// remproxy：行 = [地址 ip:port, 协议, 国家, 匿名度, 延迟, 检测, 复制]。
fn parse_html_remproxy(raw: &str) -> ParsedUpstream {
    let mut nodes = Vec::new();
    let mut skipped: HashMap<String, usize> = HashMap::new();
    for cells in html_table_rows(raw) {
        if cells.len() < 3 {
            continue;
        }
        let (addr, proto, country) = (&cells[0], &cells[1], &cells[2]);
        let Some((ip, port)) = parse_ip_port(addr) else {
            continue;
        };
        let proto_l = proto.to_ascii_lowercase();
        let scheme = if proto_l.contains("http") {
            "http"
        } else if proto_l.contains("socks5") {
            "socks5"
        } else {
            ParsedUpstream::add_skipped(&mut skipped, &proto_l);
            continue;
        };
        let label = format!("{country} {ip}:{port}");
        nodes.push(format!("{scheme}://{ip}:{port}#{label}"));
    }
    ParsedUpstream::finish(dedupe_nodes(&nodes), Vec::new(), skipped)
}

/// URL 模板里的日期占位按上海日期替换：{YYYY} / {MM} / {DD}。
/// 无占位时原样返回。
pub fn resolve_url_template(template: &str, date: NaiveDate) -> String {
    template
        .replace("{YYYY}", &format!("{:04}", date.year()))
        .replace("{MM}", &format!("{:02}", date.month()))
        .replace("{DD}", &format!("{:02}", date.day()))
}

/// endpoint_key 的别名导出（供同步流程做 server+port+类型去重时复用同一格式）
pub fn node_endpoint_key(uri: &str) -> Option<String> {
    parse_node_endpoint(uri).map(|ep| endpoint_key(&ep))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date_2026_11_14() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, 14).unwrap()
    }

    #[test]
    fn date_template_resolves_fixed_date() {
        let tpl = "https://example.invalid/{YYYY}/{MM}/{DD}-node.yaml";
        assert_eq!(
            resolve_url_template(tpl, date_2026_11_14()),
            "https://example.invalid/2026/11/14-node.yaml"
        );
        // 无占位原样返回
        assert_eq!(
            resolve_url_template("https://example.invalid/static.yaml", date_2026_11_14()),
            "https://example.invalid/static.yaml"
        );
        // 月/日补零
        let d = NaiveDate::from_ymd_opt(2026, 1, 5).unwrap();
        assert_eq!(
            resolve_url_template(tpl, d),
            "https://example.invalid/2026/01/05-node.yaml"
        );
    }

    #[test]
    fn geonode_picks_one_protocol_and_skips_socks4() {
        let raw = r#"{"data":[
          {"ip":"1.1.1.1","port":"8080","protocols":["http"],"country":"US"},
          {"ip":"2.2.2.2","port":1080,"protocols":["socks5"],"country":"JP"},
          {"ip":"3.3.3.3","port":"3128","protocols":["https","http"],"country":"DE"},
          {"ip":"4.4.4.4","port":"1080","protocols":["socks4"],"country":"FR"},
          {"ip":"5.5.5.5","port":"1080","protocols":[],"country":"GB"}
        ],"total":5}"#;
        let p = parse_upstream_content(raw, UpstreamFormat::JsonGeonode);
        assert_eq!(p.nodes.len(), 3);
        assert!(p.nodes[0].starts_with("http://1.1.1.1:8080#US-"));
        assert!(p.nodes[1].starts_with("socks5://2.2.2.2:1080#JP-"));
        // http 优先于 https
        assert!(p.nodes[2].starts_with("http://3.3.3.3:3128#DE-"));
        assert_eq!(p.skipped, vec![("socks4".to_string(), 1), ("unknown".to_string(), 1)]);
    }

    #[test]
    fn scdn_and_proxora_txt_parse() {
        let raw = r#"{"code":200,"data":{"proxies":["52.1.1.1:15290","bad-line","18.1.1.1:8090"],"count":3}}"#;
        let p = parse_upstream_content(raw, UpstreamFormat::JsonScdn);
        assert_eq!(p.nodes.len(), 2);
        assert!(p.nodes[0].starts_with("http://52.1.1.1:15290#"));
        assert_eq!(p.skipped, vec![("malformed".to_string(), 1)]);

        let txt = "69.1.1.1:7989\n130.1.1.1:3128\nnot-an-ip\n";
        let p2 = parse_upstream_content(txt, UpstreamFormat::TxtProxora);
        assert_eq!(p2.nodes.len(), 2);
        assert_eq!(p2.skipped, vec![("malformed".to_string(), 1)]);
    }

    #[test]
    fn fineproxy_prefers_http_then_socks5() {
        let raw = r#"{"rows":[
          {"ip":"202.1.1.1","port":80,"protos":["HTTP","SOCKS4","SOCKS5"],"country":"France"},
          {"ip":"66.1.1.1","port":41679,"protos":["SOCKS4","SOCKS5"],"country":"United States"},
          {"ip":"47.1.1.1","port":3128,"protos":["SOCKS4"],"country":""},
          {"ip":"208.1.1.1","port":58208,"protos":["HTTP"],"country":""}
        ]}"#;
        let p = parse_upstream_content(raw, UpstreamFormat::JsonFineproxy);
        assert_eq!(p.nodes.len(), 3);
        assert!(p.nodes[0].starts_with("http://202.1.1.1:80#France "));
        assert!(p.nodes[1].starts_with("socks5://66.1.1.1:41679#United States "));
        assert!(p.nodes[2].starts_with("http://208.1.1.1:58208#208.1.1.1:58208"));
        assert_eq!(p.skipped, vec![("socks4".to_string(), 1)]);
    }

    #[test]
    fn html_tables_parse_and_fail_soft() {
        let proxyhub = r#"<table><tr><th>国家</th><th>IP</th><th>端口</th><th>协议</th><th>匿名</th><th>时间</th></tr>
          <tr><td>马来西亚</td><td>203.0.113.63</td><td>80</td><td>HTTP</td><td>匿名</td><td>2026-11-14</td></tr>
          <tr><td>法国</td><td>202.133.88.173</td><td>80</td><td>HTTP</td><td>高匿名</td><td>2026-11-14</td></tr></table>"#;
        let p = parse_upstream_content(proxyhub, UpstreamFormat::HtmlProxyhub);
        assert_eq!(p.nodes.len(), 2);
        assert!(p.nodes[0].starts_with("http://203.0.113.63:80#马来西亚 "));

        let remproxy = r#"<table><tr><th>地址</th><th>协议</th><th>国家</th></tr>
          <tr><td>203.0.113.96:8085</td><td>http</td><td>中国</td></tr>
          <tr><td>bad-addr</td><td>http</td><td>中国</td></tr></table>"#;
        let p2 = parse_upstream_content(remproxy, UpstreamFormat::HtmlRemproxy);
        assert_eq!(p2.nodes.len(), 1);
        assert!(p2.nodes[0].starts_with("http://203.0.113.96:8085#中国 "));

        // 解析失败 fail-soft：0 节点，不 panic
        let p3 = parse_upstream_content("<html>no table here</html>", UpstreamFormat::HtmlProxyhub);
        assert!(p3.nodes.is_empty());
        let p4 = parse_upstream_content("not json", UpstreamFormat::JsonGeonode);
        assert!(p4.nodes.is_empty());
    }

    #[test]
    fn base64_skips_unsupported_types_and_counts() {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let raw = [
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls#HK",
            "ssr://abc123@1.2.3.4:8388",
            "ssr://def456@5.6.7.8:8388",
            "wireguard://key@9.9.9.9:51820#wg",
            "hysteria://pass@10.0.0.1:443#h1",
            "trojan://pass123@jp.example.com:443#JP",
            "anytls://user@11.0.0.1:443#at",
        ]
        .join("\n");
        let b64 = STANDARD.encode(raw.as_bytes());
        let p = parse_upstream_content(&b64, UpstreamFormat::Base64);
        assert_eq!(p.nodes.len(), 2);
        assert_eq!(
            p.skipped,
            vec![
                ("anytls".to_string(), 1),
                ("hysteria".to_string(), 1),
                ("ssr".to_string(), 2),
                ("wireguard".to_string(), 1),
            ]
        );
    }

    #[test]
    fn clash_skips_hysteria_v1_and_ssr() {
        let yaml = r#"
proxies:
  - name: "VL-01"
    type: vless
    server: hk.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    tls: true
  - name: "HY1-01"
    type: hysteria
    server: h1.example.com
    port: 443
    auth_str: pass
  - name: "SSR-01"
    type: ssr
    server: s1.example.com
    port: 8388
    password: pass
    cipher: aes-128-cfb
    protocol: auth_aes128_md5
  - name: "SS-01"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: pass123
"#;
        let p = parse_upstream_content(yaml, UpstreamFormat::Clash);
        assert_eq!(p.nodes.len(), 2);
        assert_eq!(
            p.skipped,
            vec![
                ("hysteria".to_string(), 1),
                ("ssr".to_string(), 1),
            ]
        );
    }

    #[test]
    fn clash_openvpn_synthesizes_ovpn() {
        let yaml = r#"
proxies:
  - name: "JP-vpn272453069"
    type: openvpn
    server: 203.0.113.54
    port: 1764
    proto: tcp
    udp: true
    cipher: AES-128-CBC
    auth: SHA1
    data-ciphers: [AES-128-CBC]
    ca: |
      -----BEGIN CERTIFICATE-----
      MIIFazCA==
      -----END CERTIFICATE-----
    cert: |
      -----BEGIN CERTIFICATE-----
      MIIFczCA==
      -----END CERTIFICATE-----
    key: |
      -----BEGIN PRIVATE KEY-----
      MIIFdzCA==
      -----END PRIVATE KEY-----
"#;
        let p = parse_upstream_content(yaml, UpstreamFormat::Clash);
        assert_eq!(p.nodes.len(), 1);
        assert!(p.nodes[0].starts_with("openvpn://203.0.113.54:1764?proto=tcp#"));
        assert_eq!(p.openvpn.len(), 1);
        assert_eq!(p.openvpn[0].0, "JP-vpn272453069");
        let ovpn = &p.openvpn[0].1;
        assert!(ovpn.contains("remote 203.0.113.54 1764"));
        assert!(ovpn.contains("proto tcp"));
        assert!(ovpn.contains("cipher AES-128-CBC"));
        assert!(ovpn.contains("auth SHA1"));
        assert!(ovpn.contains("<ca>"));
        assert!(ovpn.contains("MIIFazCA=="));
        // 合成的 .ovpn 能过三级同款解析
        let cfg = crate::openvpn::parse_ovpn_config(ovpn);
        assert_eq!(cfg.server, "203.0.113.54");
        assert_eq!(cfg.port, 1764);
        assert_eq!(cfg.proto, "tcp");
        assert!(cfg.ca.as_ref().unwrap().contains("MIIFazCA=="));
        // 缺 ca 的 openvpn 代理跳过
        let bad = yaml.replace("    ca: |\n      -----BEGIN CERTIFICATE-----\n      MIIFazCA==\n      -----END CERTIFICATE-----\n", "");
        let p2 = parse_upstream_content(&bad, UpstreamFormat::Clash);
        assert!(p2.nodes.is_empty());
        assert_eq!(p2.skipped, vec![("openvpn".to_string(), 1)]);
    }

    #[test]
    fn endpoint_dedupe_merges_same_server_port_type() {
        let nodes = vec![
            "http://1.2.3.4:8080#US-a".to_string(),
            "http://1.2.3.4:8080#US-b".to_string(),
            "https://1.2.3.4:8080#US-c".to_string(),
            "socks5://1.2.3.4:8080#US-d".to_string(),
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls#HK1".to_string(),
            "vless://550e8400-e29b-41d4-a716-446655440000@HK.EXAMPLE.COM:443?security=tls#HK2".to_string(),
        ];
        let out = dedupe_by_endpoint(&nodes);
        // http 去重剩 1；https 不同类型留 1；socks5 留 1；vless（host 大小写归一）留 1
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], nodes[0]);
    }
}
