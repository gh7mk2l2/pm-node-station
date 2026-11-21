//! 节点 URI 解析与上游订阅解析。
//! 支持四种上游格式：Raw URI（一行一个）、整段 Base64、Clash YAML（顶层 proxies）、
//! VPNGate CSV（OpenVPN 服务器列表，三级专用，见 parse_vpngate_csv）。
//! 全部为原创实现（参考 Arkadia 的功能模型，不复制其代码）。

use crate::util::sha256_hex;

/// 常见代理协议白名单；https:// 等普通网址不算节点
// openvpn 在列：三级 VPNGate 节点是 openvpn:// URI，去重/下发时必须认作有效节点。
// 注意 Clash / sing-box 生成器不支持 openvpn，转换时会跳过（见 subs.rs 的三级说明）。
const NODE_PROTOCOLS: &[&str] = &[
    "vless",
    "vmess",
    "ss",
    "ssr",
    "trojan",
    "hysteria",
    "hysteria2",
    "hy2",
    "tuic",
    "socks",
    "socks5",
    "snell",
    "juicity",
    "wireguard",
    "ssh",
    "openvpn",
];

/// 识别节点行（白名单协议 + :// 开头）
pub fn is_node_line(line: &str) -> bool {
    let Some(idx) = line.find("://") else {
        return false;
    };
    let scheme = &line[..idx];
    if scheme.is_empty() || !scheme.chars().next().unwrap().is_ascii_alphabetic() {
        return false;
    }
    if !scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        return false;
    }
    NODE_PROTOCOLS.contains(&scheme.to_ascii_lowercase().as_str())
}

pub fn try_decode_base64(s: &str) -> Option<String> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    if s.is_empty()
        || !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'))
    {
        return None;
    }
    let normalized = s.replace('-', "+").replace('_', "/");
    let padded = format!(
        "{}{}",
        normalized,
        "=".repeat((4 - normalized.len() % 4) % 4)
    );
    STANDARD
        .decode(padded.as_bytes())
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
}

/// 清理粘贴的原始文本：一行一个节点；支持整段 base64 自动解码；去空行与重复
pub fn normalize_node_input(raw: &str) -> Vec<String> {
    let mut text = raw.replace("\r\n", "\n").replace('\r', "\n");
    text = text.trim().to_string();
    if text.is_empty() {
        return vec![];
    }
    if !text.contains("://") {
        if let Some(decoded) = try_decode_base64(&text.replace(|c: char| c.is_whitespace(), "")) {
            if decoded.contains("://") {
                text = decoded;
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || !is_node_line(line) {
            continue;
        }
        if seen.insert(line.to_string()) {
            out.push(line.to_string());
        }
    }
    out
}

/// 去重（保持首次出现顺序），同时过滤非节点/代理 URI
pub fn dedupe_nodes(nodes: &[String]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for raw in nodes {
        let node = raw.trim();
        if node.is_empty() || seen.contains(node) {
            continue;
        }
        if !is_proxy_uri(node) {
            continue;
        }
        seen.insert(node.to_string());
        out.push(node.to_string());
    }
    out
}

/// 节点或福利代理 URI（socks5/http(s) 代理也算）
pub fn is_proxy_uri(value: &str) -> bool {
    if is_node_line(value) {
        return true;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("socks5://") || lower.starts_with("socks://") {
        return true;
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        // 普通网页地址不是代理；HTTP 代理至少应有显式端口或认证信息
        if let Ok(url) = url::Url::parse(value) {
            let authority = value
                .split("://")
                .nth(1)
                .unwrap_or("")
                .split(['/', '?', '#'])
                .next()
                .unwrap_or("");
            let host_port = authority.rsplit('@').next().unwrap_or("");
            let has_port = host_port.contains(':')
                && host_port
                    .rsplit(':')
                    .next()
                    .map(|p| p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty())
                    .unwrap_or(false);
            return has_port || !url.username().is_empty() || url.password().is_some();
        }
        return false;
    }
    false
}

/// 解析节点备注（下发/转换时保留的节点名）
pub fn read_node_name(uri: &str) -> String {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("vmess://") {
        if let Some(decoded) = try_decode_base64(&uri["vmess://".len()..]) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&decoded) {
                if let Some(ps) = json.get("ps").and_then(|v| v.as_str()) {
                    let ps = ps.trim();
                    if !ps.is_empty() {
                        return ps.to_string();
                    }
                }
            }
        }
        return "(vmess 无备注)".to_string();
    }
    if let Some(idx) = uri.find('#') {
        if idx + 1 < uri.len() {
            let name = percent_decode(&uri[idx + 1..]);
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    "(无备注)".to_string()
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(b) = u8::from_str_radix(hex, 16) {
                    out.push(b);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 国家/地区表：国旗 emoji、中文名、识别关键词。
/// 识别顺序：国旗优先，其次中文名，最后英文/代码，避免短代码误匹配。
pub const COUNTRY_TABLE: &[(&str, &str, &[&str])] = &[
    ("\u{1f1ed}\u{1f1f0}", "香港", &["香港", "HK", "Hong Kong"]),
    ("\u{1f1f9}\u{1f1fc}", "台湾", &["台湾", "TW", "Taiwan"]),
    (
        "\u{1f1ef}\u{1f1f5}",
        "日本",
        &["日本", "JP", "Japan", "东京", "大阪"],
    ),
    (
        "\u{1f1f0}\u{1f1f7}",
        "韩国",
        &["韩国", "KR", "Korea", "South Korea", "首尔"],
    ),
    (
        "\u{1f1f8}\u{1f1ec}",
        "新加坡",
        &["新加坡", "SG", "Singapore"],
    ),
    (
        "\u{1f1fa}\u{1f1f8}",
        "美国",
        &["美国", "US", "USA", "United States", "洛杉矶", "纽约"],
    ),
    ("\u{1f1ec}\u{1f1e7}", "英国", &["英国", "UK", "United Kingdom", "England", "伦敦"]),
    ("\u{1f1e9}\u{1f1ea}", "德国", &["德国", "DE", "Germany", "法兰克福"]),
    ("\u{1f1eb}\u{1f1f7}", "法国", &["法国", "FR", "France", "巴黎"]),
    ("\u{1f1e8}\u{1f1e6}", "加拿大", &["加拿大", "CA", "Canada"]),
    (
        "\u{1f1e6}\u{1f1fa}",
        "澳大利亚",
        &["澳大利亚", "AU", "Australia", "悉尼"],
    ),
    ("\u{1f1f3}\u{1f1f1}", "荷兰", &["荷兰", "NL", "Netherlands"]),
    ("\u{1f1f7}\u{1f1fa}", "俄罗斯", &["俄罗斯", "RU", "Russia"]),
    ("\u{1f1ee}\u{1f1f3}", "印度", &["印度", "IN", "India"]),
    ("\u{1f1f9}\u{1f1f7}", "土耳其", &["土耳其", "TR", "Turkey"]),
    ("\u{1f1e7}\u{1f1f7}", "巴西", &["巴西", "BR", "Brazil"]),
    ("\u{1f1f9}\u{1f1ed}", "泰国", &["泰国", "TH", "Thailand"]),
    ("\u{1f1fb}\u{1f1f3}", "越南", &["越南", "VN", "Vietnam"]),
    (
        "\u{1f1f2}\u{1f1fe}",
        "马来西亚",
        &["马来西亚", "MY", "Malaysia"],
    ),
    ("\u{1f1ee}\u{1f1e9}", "印尼", &["印尼", "ID", "Indonesia"]),
    (
        "\u{1f1f5}\u{1f1ed}",
        "菲律宾",
        &["菲律宾", "PH", "Philippines"],
    ),
    ("\u{1f1f2}\u{1f1fd}", "墨西哥", &["墨西哥", "MX", "Mexico"]),
    ("\u{1f1ee}\u{1f1f9}", "意大利", &["意大利", "IT", "Italy"]),
    ("\u{1f1ea}\u{1f1f8}", "西班牙", &["西班牙", "ES", "Spain"]),
    ("\u{1f1e8}\u{1f1ed}", "瑞士", &["瑞士", "CH", "Switzerland"]),
    ("\u{1f1ee}\u{1f1ea}", "爱尔兰", &["爱尔兰", "IE", "Ireland"]),
    ("\u{1f1e6}\u{1f1f9}", "奥地利", &["奥地利", "AT", "Austria"]),
    (
        "\u{1f1f7}\u{1f1f4}",
        "罗马尼亚",
        &["罗马尼亚", "RO", "Romania"],
    ),
    (
        "\u{1f1e7}\u{1f1ec}",
        "保加利亚",
        &["保加利亚", "BG", "Bulgaria"],
    ),
    ("\u{1f1e8}\u{1f1f1}", "智利", &["智利", "CL", "Chile"]),
    (
        "\u{1f1f1}\u{1f1f9}",
        "立陶宛",
        &["立陶宛", "LT", "Lithuania"],
    ),
    (
        "\u{1f1e7}\u{1f1fe}",
        "白俄罗斯",
        &["白俄罗斯", "BY", "Belarus"],
    ),
    ("\u{1f1e8}\u{1f1f3}", "中国", &["中国", "CN", "China"]),
    ("🇬🇩", "格林纳达", &["格林纳达", "GD", "Grenada"]),
    ("🇦🇷", "阿根廷", &["阿根廷", "AR", "Argentina"]),
    ("🇸🇪", "瑞典", &["瑞典", "SE", "Sweden"]),
    ("🇿🇦", "南非", &["南非", "ZA", "South Africa"]),
    ("🇮🇷", "伊朗", &["伊朗", "IR", "Iran"]),
];

/// 从节点名识别地区，返回（国旗，中文名）；识别不到返回 None（不编造）
pub fn detect_country(name: &str) -> Option<(&'static str, &'static str)> {
    for (flag, region, _) in COUNTRY_TABLE {
        if name.contains(flag) {
            return Some((flag, region));
        }
    }
    for (flag, region, _) in COUNTRY_TABLE {
        if name.contains(region) {
            return Some((flag, region));
        }
    }
    for (flag, region, kws) in COUNTRY_TABLE {
        for kw in *kws {
            if name.contains(kw) {
                return Some((flag, region));
            }
        }
    }
    None
}

/// 从节点名里提取地区（关键词匹配；匹配不到返回空串，不编造）
pub fn extract_region(name: &str) -> String {
    detect_country(name)
        .map(|(_, r)| r.to_string())
        .unwrap_or_default()
}

/// 给单个节点 URI 改名：vmess 改 JSON 里的 ps，其余协议改 #fragment
pub fn rename_node_uri(uri: &str, new_name: &str) -> String {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("vmess://") {
        if let Some(decoded) = try_decode_base64(&uri["vmess://".len()..]) {
            if let Ok(mut json) = serde_json::from_str::<serde_json::Value>(&decoded) {
                if let Some(obj) = json.as_object_mut() {
                    obj.insert(
                        "ps".to_string(),
                        serde_json::Value::String(new_name.to_string()),
                    );
                    use base64::{engine::general_purpose::STANDARD, Engine as _};
                    return format!("vmess://{}", STANDARD.encode(json.to_string().as_bytes()));
                }
            }
        }
        return uri.to_string();
    }
    let base = match uri.find('#') {
        Some(idx) => &uri[..idx],
        None => uri,
    };
    format!("{}#{}", base, urlencoding(new_name))
}

/// 批量改名：按地区识别，同一地区按出现顺序编号为「[国旗][级别]xx国节点n」，
/// 级别文案 1→一级、2→二级、3→三级。
/// 返回（改名后的节点 URI，无法识别地区的原名列表——原名保留不动）。
pub fn rename_nodes(nodes: &[String], tier: i16) -> (Vec<String>, Vec<String>) {
    let tier_label = match tier {
        1 => "一级",
        2 => "二级",
        3 => "三级",
        _ => "",
    };
    let mut counters: std::collections::HashMap<&'static str, usize> =
        std::collections::HashMap::new();
    let mut unrecognized = Vec::new();
    let mut out = Vec::with_capacity(nodes.len());
    for uri in nodes {
        let name = read_node_name(uri);
        match detect_country(&name) {
            Some((flag, region)) => {
                let n = counters.entry(region).or_insert(0);
                *n += 1;
                let new_name = format!("{flag}{tier_label}{region}节点{n}");
                out.push(rename_node_uri(uri, &new_name));
            }
            None => {
                unrecognized.push(name);
                out.push(uri.clone());
            }
        }
    }
    (out, unrecognized)
}

/// 节点 URI → 测速端点（协议、主机、端口、认证）
#[derive(Debug, Clone)]
pub struct NodeEndpoint {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub fn parse_node_endpoint(uri: &str) -> Option<NodeEndpoint> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("vmess://") {
        let decoded = try_decode_base64(&uri["vmess://".len()..])?;
        let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;
        let host = json.get("add")?.as_str()?.to_string();
        let port = json
            .get("port")?
            .as_str()
            .and_then(|p| p.parse::<u16>().ok())
            .or_else(|| json.get("port")?.as_u64().map(|p| p as u16))?;
        return Some(NodeEndpoint {
            scheme: "vmess".into(),
            host,
            port,
            username: None,
            password: None,
        });
    }
    // 其余协议均为 scheme://[userinfo@]host:port[?query][#frag]
    let scheme_end = uri.find("://")?;
    let scheme = uri[..scheme_end].to_ascii_lowercase();
    let rest = &uri[scheme_end + 3..];
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(at) => (Some(&authority[..at]), &authority[at + 1..]),
        None => (None, authority),
    };
    let (host, port) = parse_host_port(hostport)?;
    let (username, password) = match userinfo {
        Some(u) => {
            let mut parts = u.splitn(2, ':');
            let user = percent_decode(parts.next().unwrap_or(""));
            let pass = parts.next().map(percent_decode);
            (Some(user), pass)
        }
        None => (None, None),
    };
    Some(NodeEndpoint {
        scheme,
        host,
        port,
        username,
        password,
    })
}

fn parse_host_port(hostport: &str) -> Option<(String, u16)> {
    if let Some(stripped) = hostport.strip_prefix('[') {
        // [ipv6]:port
        let end = stripped.find(']')?;
        let host = stripped[..end].to_string();
        let rest = &stripped[end + 1..];
        let port: u16 = rest.strip_prefix(':')?.parse().ok()?;
        return Some((host, port));
    }
    let colon = hostport.rfind(':')?;
    let host = hostport[..colon].to_string();
    let port: u16 = hostport[colon + 1..].parse().ok()?;
    if host.is_empty() {
        return None;
    }
    Some((host, port))
}

/// 测速入口使用的别名
pub fn endpoint_of_node(uri: &str) -> Option<NodeEndpoint> {
    parse_node_endpoint(uri)
}

/// 测速端点键：scheme://host:port（小写），外部探测器写回 node_availability 时用同一格式。
/// 多个节点共用同一端点时共享一行可用性结果。
pub fn endpoint_key(ep: &NodeEndpoint) -> String {
    format!(
        "{}://{}:{}",
        ep.scheme,
        ep.host.to_ascii_lowercase(),
        ep.port
    )
}

/// OpenVPN URI 里的 proto 查询参数（udp/tcp），仅 openvpn 有意义。
/// TCP 探测只能测 proto=tcp 的端点；udp 的 OpenVPN 端点无法用 TCP 连接判断。
pub fn openvpn_proto(uri: &str) -> Option<String> {
    if !uri.to_ascii_lowercase().starts_with("openvpn://") {
        return None;
    }
    // 先去掉 #fragment（否则 proto 值会粘上节点名，如 "udp#JP-vpn1001"）
    let no_frag = uri.split('#').next().unwrap_or(uri);
    no_frag.split('?').nth(1).and_then(|q| {
        q.split('&').find_map(|kv| {
            let mut it = kv.splitn(2, '=');
            if it
                .next()
                .map(|k| k.eq_ignore_ascii_case("proto"))
                .unwrap_or(false)
            {
                it.next().map(|v| v.to_ascii_lowercase())
            } else {
                None
            }
        })
    })
}

/// sing-box / mihomo 认识的 uTLS 指纹；上游带来的未知值（如 unsafe）直接丢弃，
/// 只保留 TLS 本身，不让单个节点拖垮整份配置的 `sing-box check` / `mihomo -t`。
pub fn is_known_utls_fingerprint(fp: &str) -> bool {
    matches!(
        fp.to_ascii_lowercase().as_str(),
        "chrome"
            | "firefox"
            | "safari"
            | "ios"
            | "android"
            | "edge"
            | "360"
            | "qq"
            | "random"
            | "randomkey"
    )
}

/// 协议名（小写 scheme，如 vless / trojan / ss）
pub fn protocol_of(uri: &str) -> String {
    match uri.find("://") {
        Some(i) => uri[..i].to_ascii_lowercase(),
        None => "unknown".to_string(),
    }
}

/// 地区：从节点备注名提取（香港/日本/美国…），无匹配时返回空串
pub fn region_of(uri: &str) -> String {
    extract_region(&read_node_name(uri))
}

/// 解析上游订阅：Raw URI、整段 Base64，或完整 Clash YAML 顶层 proxies
pub fn parse_subscription_nodes(raw: &str) -> Vec<String> {
    // 必须先识别整段 Base64：节点协议白名单不含 HTTP/SOCKS5，
    // 若先按行解析，会在混合订阅里拿到部分节点后提前返回，静默漏掉其余协议。
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    if !raw.contains("://") {
        if let Some(decoded) = try_decode_base64(&compact) {
            if decoded != raw {
                let nodes = parse_subscription_nodes(&decoded);
                if !nodes.is_empty() {
                    return nodes;
                }
            }
        }
    }

    let direct = dedupe_nodes(&normalize_node_input(raw));
    let line_candidates: Vec<String> = raw
        .replace("\r\n", "\n")
        .lines()
        .map(|l| l.trim().to_string())
        .collect();
    let raw_nodes = dedupe_nodes(&{
        let mut v = direct.clone();
        v.extend(line_candidates);
        v
    });
    if !raw_nodes.is_empty() {
        return raw_nodes;
    }

    // Clash YAML
    let document: serde_yaml::Value = match serde_yaml::from_str(raw) {
        Ok(v) => v,
        Err(_) => return vec![],
    };
    let Some(root) = document.as_mapping() else {
        return vec![];
    };
    let Some(proxies) = root.get("proxies").and_then(|v| v.as_sequence()) else {
        return vec![];
    };
    dedupe_nodes(
        &proxies
            .iter()
            .filter_map(clash_proxy_to_uri)
            .collect::<Vec<_>>(),
    )
}

/// 解析 VPNGate 的 OpenVPN 服务器 CSV（https://www.vpngate.net/api/iphone/）。
/// 每行 15 列：HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,
/// Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64。
/// 返回（节点 URI 列表，[(改名前节点名, .ovpn 配置 Base64)]）。
/// 节点 URI 为 openvpn://IP:PORT?proto=udp|tcp#CC-HostName（国家代码写进备注，
/// 供后续 rename_nodes 按「[国旗][级别]xx国节点n」改名）；.ovpn 配置另存，供下载端点使用。
/// 解析 VPNGate CSV（https://www.vpngate.net/api/iphone/）。
/// 返回：(节点 URI 列表，与 URI 一一对应的 (改名前节点名, .ovpn 配置 base64)，
/// 与 URI 一一对应的 (改名前节点名, Ping 毫秒, Speed bps))。
/// Ping/Speed 是 VPNGate 自己测的数字（CSV 第 4/5 列），直接展示用，绝不从本站测。
pub fn parse_vpngate_csv(
    raw: &str,
) -> (Vec<String>, Vec<(String, String)>, Vec<(String, i32, i64)>) {
    let mut pairs: Vec<(String, (String, String), (String, i32, i64))> = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() || line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let cols = split_csv_line(line);
        if cols.len() < 15 {
            continue;
        }
        let host = cols[0].trim();
        let ip = cols[1].trim();
        let ping_ms: i32 = cols[3].trim().parse().unwrap_or(0);
        let speed_bps: i64 = cols[4].trim().parse().unwrap_or(0);
        let cc = cols[6].trim();
        let config_b64 = cols[14].trim();
        if host.is_empty() || ip.is_empty() || config_b64.is_empty() {
            continue;
        }
        let config = match try_decode_base64(config_b64) {
            Some(c) => c,
            None => continue,
        };
        let (port, proto) = match vpngate_remote(&config) {
            Some(v) => v,
            None => continue,
        };
        let pre_name = if cc.is_empty() {
            host.to_string()
        } else {
            format!("{cc}-{host}")
        };
        pairs.push((
            format!(
                "openvpn://{ip}:{port}?proto={proto}#{}",
                urlencoding(&pre_name)
            ),
            (pre_name.clone(), config_b64.to_string()),
            (pre_name, ping_ms, speed_bps),
        ));
    }
    // 按 URI 去重（同一服务器只留一行），配置与 Ping/Speed 与 URI 保持一一对应
    let mut seen = std::collections::HashSet::new();
    let mut uris = Vec::new();
    let mut configs = Vec::new();
    let mut metas = Vec::new();
    for (uri, cfg, meta) in pairs {
        if seen.insert(uri.clone()) {
            uris.push(uri);
            configs.push(cfg);
            metas.push(meta);
        }
    }
    (uris, configs, metas)
}

/// 从 OpenVPN 配置文本里提取 remote 端口与 proto（udp/tcp，默认 udp）
fn vpngate_remote(config: &str) -> Option<(u16, String)> {
    let mut port: Option<u16> = None;
    let mut proto = "udp".to_string();
    for line in config.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("remote ") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
        } else if let Some(rest) = t.strip_prefix("proto ") {
            let p = rest.trim().to_ascii_lowercase();
            if p == "udp" || p == "tcp" {
                proto = p;
            }
        }
    }
    port.map(|p| (p, proto))
}

/// 最小 CSV 行解析：按逗号切分，支持双引号包裹字段（引号内逗号不切分，"" 转义为 "）
fn split_csv_line(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut in_quotes = false;
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                if in_quotes && chars.peek() == Some(&'"') {
                    cur.push('"');
                    chars.next();
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

/// Clash YAML 里单个 proxy 对象 → 节点 URI；不支持的类型返回 None
pub fn clash_proxy_to_uri(value: &serde_yaml::Value) -> Option<String> {
    let proxy = value.as_mapping()?;
    let get = |k: &str| proxy.get(serde_yaml::Value::String(k.to_string()));
    let text = |k: &str| get(k).and_then(yaml_text);
    let typ = text("type")?.to_ascii_lowercase();
    let server = text("server")?;
    let port = get("port").and_then(yaml_port)?;
    let name = text("name").unwrap_or_else(|| format!("{typ}-{server}"));
    let endpoint = format!("{}:{}", format_host(&server), port);
    let fragment = format!("#{}", urlencoding(&name));

    match typ.as_str() {
        "vless" => {
            let uuid = text("uuid")?;
            let mut params: Vec<(String, String)> = vec![
                (
                    "encryption".into(),
                    text("encryption").unwrap_or_else(|| "none".into()),
                ),
                (
                    "type".into(),
                    text("network").unwrap_or_else(|| "tcp".into()),
                ),
            ];
            let network = text("network").unwrap_or_else(|| "tcp".into());
            let reality = get("reality-opts").and_then(|v| v.as_mapping());
            let tls = get("tls").and_then(yaml_bool).unwrap_or(false);
            params.push((
                "security".into(),
                if reality.is_some() {
                    "reality".into()
                } else if tls {
                    "tls".into()
                } else {
                    "none".into()
                },
            ));
            if get("skip-cert-verify").and_then(yaml_bool).unwrap_or(false) {
                params.push(("allowInsecure".into(), "1".into()));
            }
            push_param(
                &mut params,
                "sni",
                text("servername").or_else(|| text("sni")),
            );
            push_param(&mut params, "fp", text("client-fingerprint"));
            push_param(&mut params, "flow", text("flow"));
            if let Some(r) = reality {
                let rget = |k: &str| r.get(serde_yaml::Value::String(k.to_string()));
                push_param(&mut params, "pbk", rget("public-key").and_then(yaml_text));
                push_param(&mut params, "sid", rget("short-id").and_then(yaml_text));
            }
            if network == "ws" {
                let ws = get("ws-opts").and_then(|v| v.as_mapping());
                let path = ws
                    .and_then(|m| m.get(serde_yaml::Value::String("path".into())))
                    .and_then(yaml_text)
                    .unwrap_or_else(|| "/".into());
                params.push(("path".into(), path));
                let host = ws
                    .and_then(|m| m.get(serde_yaml::Value::String("headers".into())))
                    .and_then(|v| v.as_mapping())
                    .and_then(|h| {
                        h.get(serde_yaml::Value::String("Host".into()))
                            .or_else(|| h.get(serde_yaml::Value::String("host".into())))
                    })
                    .and_then(yaml_text);
                push_param(&mut params, "host", host);
            } else if network == "grpc" {
                let grpc = get("grpc-opts").and_then(|v| v.as_mapping());
                let svc = grpc
                    .and_then(|m| m.get(serde_yaml::Value::String("grpc-service-name".into())))
                    .and_then(yaml_text);
                push_param(&mut params, "serviceName", svc);
            }
            Some(format!(
                "vless://{}@{}?{}{}",
                urlencoding(&uuid),
                endpoint,
                join_params(&params),
                fragment
            ))
        }
        "vmess" => {
            let uuid = text("uuid")?;
            let ws = get("ws-opts").and_then(|v| v.as_mapping());
            let headers = ws.and_then(|m| {
                m.get(serde_yaml::Value::String("headers".into()))
                    .and_then(|v| v.as_mapping())
            });
            let host = headers
                .and_then(|h| {
                    h.get(serde_yaml::Value::String("Host".into()))
                        .or_else(|| h.get(serde_yaml::Value::String("host".into())))
                })
                .and_then(yaml_text)
                .unwrap_or_default();
            let payload = serde_json::json!({
                "v": "2",
                "ps": name,
                "add": server,
                "port": port.to_string(),
                "id": uuid,
                "aid": get("alterId").and_then(yaml_int).or_else(|| get("alter-id").and_then(yaml_int)).unwrap_or(0).to_string(),
                "scy": text("cipher").unwrap_or_else(|| "auto".into()),
                "net": text("network").unwrap_or_else(|| "tcp".into()),
                "type": "none",
                "host": host,
                "path": ws.and_then(|m| m.get(serde_yaml::Value::String("path".into()))).and_then(yaml_text).unwrap_or_default(),
                "tls": if get("tls").and_then(yaml_bool).unwrap_or(false) { "tls" } else { "" },
                "sni": text("servername").unwrap_or_default(),
            });
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            Some(format!(
                "vmess://{}",
                STANDARD.encode(payload.to_string().as_bytes())
            ))
        }
        "ss" => {
            let method = text("cipher")?;
            let password = text("password")?;
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            let auth = URL_SAFE_NO_PAD.encode(format!("{method}:{password}").as_bytes());
            Some(format!("ss://{auth}@{endpoint}{fragment}"))
        }
        "trojan" => {
            let password = text("password")?;
            let mut params: Vec<(String, String)> = vec![("security".into(), "tls".into())];
            push_param(
                &mut params,
                "sni",
                text("sni").or_else(|| text("servername")),
            );
            if get("skip-cert-verify").and_then(yaml_bool).unwrap_or(false) {
                params.push(("allowInsecure".into(), "1".into()));
            }
            Some(format!(
                "trojan://{}@{}?{}{}",
                urlencoding(&password),
                endpoint,
                join_params(&params),
                fragment
            ))
        }
        "hysteria2" | "hy2" => {
            let password = text("password").or_else(|| text("auth"))?;
            let mut params: Vec<(String, String)> = vec![];
            push_param(
                &mut params,
                "sni",
                text("sni").or_else(|| text("servername")),
            );
            if get("skip-cert-verify").and_then(yaml_bool).unwrap_or(false) {
                params.push(("insecure".into(), "1".into()));
            }
            push_param(&mut params, "pinSHA256", text("pinned-sha256"));
            let obfs = get("obfs").and_then(|v| v.as_mapping());
            if let Some(o) = obfs {
                let oget = |k: &str| o.get(serde_yaml::Value::String(k.to_string()));
                push_param(&mut params, "obfs", oget("type").and_then(yaml_text));
                push_param(
                    &mut params,
                    "obfs-password",
                    oget("password").and_then(yaml_text),
                );
            } else if let Some(o) = text("obfs") {
                push_param(&mut params, "obfs", Some(o));
                push_param(&mut params, "obfs-password", text("obfs-password"));
            }
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", join_params(&params))
            };
            Some(format!(
                "hysteria2://{}@{endpoint}{query}{fragment}",
                urlencoding(&password)
            ))
        }
        "socks5" | "socks" => Some(build_auth_uri("socks5", proxy, &endpoint, &fragment)),
        "http" => {
            let scheme = if get("tls").and_then(yaml_bool).unwrap_or(false) {
                "https"
            } else {
                "http"
            };
            Some(build_auth_uri(scheme, proxy, &endpoint, &fragment))
        }
        "tuic" => {
            let uuid = text("uuid").or_else(|| text("token"))?;
            let password = text("password");
            let auth = match password {
                Some(p) => format!("{}:{}", urlencoding(&uuid), urlencoding(&p)),
                None => urlencoding(&uuid),
            };
            let mut params: Vec<(String, String)> = vec![];
            push_param(&mut params, "sni", text("sni"));
            push_param(
                &mut params,
                "congestion_control",
                text("congestion-controller"),
            );
            let query = if params.is_empty() {
                String::new()
            } else {
                format!("?{}", join_params(&params))
            };
            Some(format!("tuic://{auth}@{endpoint}{query}{fragment}"))
        }
        _ => None,
    }
}

fn build_auth_uri(
    scheme: &str,
    proxy: &serde_yaml::Mapping,
    endpoint: &str,
    fragment: &str,
) -> String {
    let get = |k: &str| proxy.get(serde_yaml::Value::String(k.to_string()));
    let username = get("username").and_then(yaml_text);
    let password = get("password").and_then(yaml_text);
    let auth = match username {
        Some(u) => format!(
            "{}{}@",
            urlencoding(&u),
            password
                .map(|p| format!(":{}", urlencoding(&p)))
                .unwrap_or_default()
        ),
        None => String::new(),
    };
    format!("{scheme}://{auth}{endpoint}{fragment}")
}

fn push_param(params: &mut Vec<(String, String)>, key: &str, value: Option<String>) {
    if let Some(v) = value {
        if !v.is_empty() {
            params.push((key.to_string(), v));
        }
    }
}

fn join_params(params: &[(String, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&")
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

fn format_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

pub fn yaml_text(v: &serde_yaml::Value) -> Option<String> {
    match v {
        serde_yaml::Value::String(s) => Some(s.trim().to_string()),
        serde_yaml::Value::Number(n) => Some(n.to_string()),
        serde_yaml::Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

pub fn yaml_int(v: &serde_yaml::Value) -> Option<i64> {
    match v {
        serde_yaml::Value::Number(n) => n.as_i64(),
        serde_yaml::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

pub fn yaml_port(v: &serde_yaml::Value) -> Option<u16> {
    yaml_int(v).and_then(|p| {
        if (1..=65535).contains(&p) {
            Some(p as u16)
        } else {
            None
        }
    })
}

pub fn yaml_bool(v: &serde_yaml::Value) -> Option<bool> {
    match v {
        serde_yaml::Value::Bool(b) => Some(*b),
        serde_yaml::Value::Number(n) => n.as_i64().map(|i| i != 0),
        serde_yaml::Value::String(s) => match s.trim() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

/// 节点集合哈希（排序后去重再哈希，用于判断上游内容是否变化）
pub fn hash_nodes(nodes: &[String]) -> String {
    let mut uniq: Vec<String> = {
        let mut seen = std::collections::HashSet::new();
        nodes
            .iter()
            .filter(|n| seen.insert(n.to_string()))
            .cloned()
            .collect()
    };
    uniq.sort();
    sha256_hex(&uniq.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_line_whitelist() {
        assert!(is_node_line("vless://uuid@host:443?security=tls#HK"));
        assert!(is_node_line("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@host:8388#n"));
        assert!(!is_node_line("https://example.com/sub"));
        assert!(!is_node_line("not a node"));
    }

    #[test]
    fn base64_roundtrip() {
        let raw = "vless://a@b:1#x\nvmess://e30=#y";
        let b64 = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.encode(raw.as_bytes())
        };
        let nodes = normalize_node_input(&b64);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn node_names_are_read() {
        assert_eq!(read_node_name("vless://u@h:443#%E9%A6%99%E6%B8%AF"), "香港");
        assert_eq!(read_node_name("trojan://p@h:443"), "(无备注)");
        let vmess = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            format!(
                "vmess://{}",
                STANDARD.encode(r#"{"ps":"东京节点","add":"h","port":"1","id":"x"}"#.as_bytes())
            )
        };
        assert_eq!(read_node_name(&vmess), "东京节点");
    }

    #[test]
    fn endpoints_parse() {
        let ep = parse_node_endpoint(
            "vless://550e8400-e29b-41d4-a716-446655440000@hk.example.com:443?security=tls#HK",
        )
        .unwrap();
        assert_eq!(ep.host, "hk.example.com");
        assert_eq!(ep.port, 443);
        assert_eq!(ep.scheme, "vless");
        let ep2 = parse_node_endpoint("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@1.2.3.4:8388#n").unwrap();
        assert_eq!(ep2.host, "1.2.3.4");
        assert_eq!(ep2.port, 8388);
        let ep3 = parse_node_endpoint("socks5://user:p%40ss@10.0.0.1:1080").unwrap();
        assert_eq!(ep3.username.as_deref(), Some("user"));
        assert_eq!(ep3.password.as_deref(), Some("p@ss"));
    }

    #[test]
    fn region_extraction() {
        assert_eq!(extract_region("香港-01"), "香港");
        assert_eq!(extract_region("JP Tokyo 02"), "日本");
        assert_eq!(extract_region("plain node"), "");
        // 代理列表 JSON 里的英文全名也要能识别（fineproxy 的 country 字段）
        assert_eq!(extract_region("France 202.1.1.1:80"), "法国");
        assert_eq!(extract_region("United States 66.1.1.1:41679"), "美国");
        assert_eq!(extract_region("Germany 47.1.1.1:3128"), "德国");
        assert_eq!(extract_region("United Kingdom 1.1.1.1:8080"), "英国");
        assert_eq!(extract_region("South Korea 2.2.2.2:1080"), "韩国");
    }

    #[test]
    fn utls_fingerprint_allowlist() {
        assert!(is_known_utls_fingerprint("chrome"));
        assert!(is_known_utls_fingerprint("Chrome"));
        assert!(is_known_utls_fingerprint("random"));
        assert!(is_known_utls_fingerprint("qq"));
        // 上游带来的未知值必须判为未知，转换器据此丢弃 utls 指纹
        assert!(!is_known_utls_fingerprint("unsafe"));
        assert!(!is_known_utls_fingerprint(""));
    }

    #[test]
    fn country_detect_flag_first() {
        assert_eq!(
            detect_country("\u{1f1fa}\u{1f1f8} \u{2728}\u{fe0f}\u{2764}\u{fe0f}\u{2747}\u{fe0f}Fast\u{7f8e}\u{56fd}_1_USAI_NF_D+"),
            Some(("\u{1f1fa}\u{1f1f8}", "美国"))
        );
        assert_eq!(
            detect_country("\u{1f1f2}\u{1f1fd} \u{2747}\u{fe0f}Fast\u{58a8}\u{897f}\u{54e5}_1_D+"),
            Some(("\u{1f1f2}\u{1f1fd}", "墨西哥"))
        );
        assert_eq!(
            detect_country("JP Tokyo 02"),
            Some(("\u{1f1ef}\u{1f1f5}", "日本"))
        );
        assert_eq!(detect_country("plain node"), None);
    }

    #[test]
    fn rename_fragment_and_vmess() {
        let renamed = rename_node_uri(
            "vless://550e8400-e29b-41d4-a716-446655440000@us.example.com:443?security=tls#old",
            "\u{1f1fa}\u{1f1f8}\u{7f8e}\u{56fd}\u{8282}\u{70b9}1",
        );
        assert!(renamed.starts_with(
            "vless://550e8400-e29b-41d4-a716-446655440000@us.example.com:443?security=tls#"
        ));
        assert_eq!(
            read_node_name(&renamed),
            "\u{1f1fa}\u{1f1f8}\u{7f8e}\u{56fd}\u{8282}\u{70b9}1"
        );

        let vmess = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            format!(
                "vmess://{}",
                STANDARD.encode(r#"{"ps":"old name","add":"h","port":"1","id":"x"}"#.as_bytes())
            )
        };
        let renamed2 = rename_node_uri(
            &vmess,
            "\u{1f1ef}\u{1f1f5}\u{65e5}\u{672c}\u{8282}\u{70b9}1",
        );
        assert_eq!(
            read_node_name(&renamed2),
            "\u{1f1ef}\u{1f1f5}\u{65e5}\u{672c}\u{8282}\u{70b9}1"
        );
    }

    #[test]
    fn rename_nodes_numbers_per_country() {
        let nodes = vec![
            "vless://u1@us1.example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20Fast%E7%BE%8E%E5%9B%BD_1"
                .to_string(),
            "vless://u2@us2.example.com:443#%F0%9F%87%BA%F0%9F%87%B8%20Fast%E7%BE%8E%E5%9B%BD_2"
                .to_string(),
            "trojan://p@jp.example.com:443#%F0%9F%87%AF%F0%9F%87%B5%20Key%E6%97%A5%E6%9C%AC_1"
                .to_string(),
            "vless://u3@xx.example.com:443#mystery-node".to_string(),
        ];
        let (renamed, unrecognized) = rename_nodes(&nodes, 1);
        assert_eq!(
            read_node_name(&renamed[0]),
            "\u{1f1fa}\u{1f1f8}\u{4e00}\u{7ea7}\u{7f8e}\u{56fd}\u{8282}\u{70b9}1"
        );
        assert_eq!(
            read_node_name(&renamed[1]),
            "\u{1f1fa}\u{1f1f8}\u{4e00}\u{7ea7}\u{7f8e}\u{56fd}\u{8282}\u{70b9}2"
        );
        assert_eq!(
            read_node_name(&renamed[2]),
            "\u{1f1ef}\u{1f1f5}\u{4e00}\u{7ea7}\u{65e5}\u{672c}\u{8282}\u{70b9}1"
        );
        assert_eq!(renamed[3], nodes[3]);
        assert_eq!(unrecognized, vec!["mystery-node".to_string()]);
        // 级别文案随 tier 变：二级 / 三级
        let (renamed2, _) = rename_nodes(&nodes, 2);
        assert_eq!(
            read_node_name(&renamed2[0]),
            "\u{1f1fa}\u{1f1f8}\u{4e8c}\u{7ea7}\u{7f8e}\u{56fd}\u{8282}\u{70b9}1"
        );
        let (renamed3, _) = rename_nodes(&nodes, 3);
        assert_eq!(
            read_node_name(&renamed3[0]),
            "\u{1f1fa}\u{1f1f8}\u{4e09}\u{7ea7}\u{7f8e}\u{56fd}\u{8282}\u{70b9}1"
        );
        // 后补的国家（瑞典 / 南非 / 伊朗）也要能识别改名
        let extra = vec![
            "vless://u@se.example.com:443#🇸🇪 Fast瑞典_1_Lnd_D+".to_string(),
            "vless://u@za.example.com:443#🇿🇦 ❇️Fast南非_1_Lnd_D+".to_string(),
            "vless://u@ir.example.com:443#🇮🇷 Fast伊朗_2_Lnd".to_string(),
        ];
        let (renamed_extra, unrec_extra) = rename_nodes(&extra, 1);
        assert!(unrec_extra.is_empty(), "新增国家未识别: {unrec_extra:?}");
        assert_eq!(read_node_name(&renamed_extra[0]), "🇸🇪一级瑞典节点1");
        assert_eq!(read_node_name(&renamed_extra[1]), "🇿🇦一级南非节点1");
        assert_eq!(read_node_name(&renamed_extra[2]), "🇮🇷一级伊朗节点1");
    }

    #[test]
    fn clash_yaml_parses() {
        let yaml = r#"
proxies:
  - name: "HK-01"
    type: vless
    server: hk.example.com
    port: 443
    uuid: 550e8400-e29b-41d4-a716-446655440000
    tls: true
    servername: hk.example.com
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: hk.example.com
  - name: "SS-01"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-128-gcm
    password: pass123
"#;
        let nodes = parse_subscription_nodes(yaml);
        assert_eq!(nodes.len(), 2);
        assert!(nodes[0].starts_with("vless://"));
        assert!(nodes[1].starts_with("ss://"));
    }

    #[test]
    fn pigeonw_clash_yaml_parses_http_proxies_only() {
        // PigeonW 订阅结构：完整 Clash 配置，proxies 里是 type=http 的住宅代理，
        // proxy-groups（select/url-test）不是节点，必须忽略
        let yaml = r#"
"port": 7890
"socks-port": 7891
"proxies":
  -
    "name": "United States美国 - 家宽 - 001"
    "type": "http"
    "server": "203.0.113.213"
    "port": 62000
    "username": "user1"
    "password": "pass1"
    "udp": false
  -
    "name": "United States美国 - 家宽 - 002"
    "type": "http"
    "server": "203.0.113.36"
    "port": 62001
    "username": "user2"
    "password": "pass2"
    "udp": false
"proxy-groups":
  -
    "name": "前置机房代理"
    "type": "select"
    "proxies":
      - "DIRECT"
  -
    "name": "自动选择"
    "type": "url-test"
    "url": "http://www.gstatic.com/generate_204"
    "proxies":
      - "United States美国 - 家宽 - 001"
"#;
        let nodes = parse_subscription_nodes(yaml);
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.starts_with("http://")));
        assert_eq!(read_node_name(&nodes[0]), "United States美国 - 家宽 - 001");
        assert!(nodes[0].contains("user1:pass1@203.0.113.213:62000"));
        // 改名：全是美国，按 [国旗]二级xx国节点n（PigeonW 是二级）
        let (renamed, unrecognized) = rename_nodes(&nodes, 2);
        assert!(unrecognized.is_empty());
        assert_eq!(read_node_name(&renamed[0]), "🇺🇸二级美国节点1");
        assert_eq!(read_node_name(&renamed[1]), "🇺🇸二级美国节点2");
    }

    #[test]
    fn raw_and_base64_upstream_parse() {
        let raw = "vless://u@h:443#HK\ntrojan://p@h2:443#JP\nvless://u@h:443#HK\n";
        let nodes = parse_subscription_nodes(raw);
        assert_eq!(nodes.len(), 2);
        let b64 = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.encode(raw.as_bytes())
        };
        assert_eq!(parse_subscription_nodes(&b64).len(), 2);
    }

    #[test]
    fn hash_is_order_independent() {
        let a = vec!["b".to_string(), "a".to_string()];
        let b = vec!["a".to_string(), "b".to_string()];
        assert_eq!(hash_nodes(&a), hash_nodes(&b));
        assert_ne!(hash_nodes(&a), hash_nodes(&["a".to_string()]));
    }

    #[test]
    fn vpngate_csv_parses_to_openvpn_uris() {
        let cfg = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.encode("remote 203.0.113.10 1195\nproto udp\ndev tun\n".as_bytes())
        };
        let cfg2 = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            STANDARD.encode("remote 198.51.100.20 443\nproto tcp\ndev tun\n".as_bytes())
        };
        let csv = format!(
            "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\nvpn1001,203.0.113.10,100,10,1000000,Japan,JP,5,100,10,1000,2weeks,op,,{cfg}\nvpn1002,198.51.100.20,90,20,2000000,United States,US,3,200,20,2000,2weeks,op,,{cfg2}\nbadrow,only,three,cols\n"
        );
        let (uris, configs, metas) = parse_vpngate_csv(&csv);
        assert_eq!(uris.len(), 2);
        assert_eq!(configs.len(), 2);
        // Ping/Speed 是 CSV 自带数字（第 4/5 列），直接存、直接展示
        assert_eq!(metas.len(), 2);
        assert_eq!(metas[0], ("JP-vpn1001".to_string(), 10, 1_000_000));
        assert_eq!(metas[1], ("US-vpn1002".to_string(), 20, 2_000_000));
        assert!(uris[0].starts_with("openvpn://203.0.113.10:1195?proto=udp#"));
        assert!(uris[1].starts_with("openvpn://198.51.100.20:443?proto=tcp#"));
        assert_eq!(read_node_name(&uris[0]), "JP-vpn1001");
        assert_eq!(read_node_name(&uris[1]), "US-vpn1002");
        // 改名后按 [国旗]三级xx国节点n
        let (renamed, unrecognized) = rename_nodes(&uris, 3);
        assert!(unrecognized.is_empty());
        assert_eq!(read_node_name(&renamed[0]), "🇯🇵三级日本节点1");
        assert_eq!(read_node_name(&renamed[1]), "🇺🇸三级美国节点1");
        // 配置与节点一一对应且可解码
        assert_eq!(configs[0].0, "JP-vpn1001");
        let decoded = try_decode_base64(&configs[0].1).unwrap();
        assert!(decoded.contains("remote 203.0.113.10 1195"));
        // openvpn URI 必须能过白名单（去重/下发不过滤它），且端点可解析
        assert!(is_proxy_uri(&uris[0]));
        let ep = parse_node_endpoint(&uris[0]).unwrap();
        assert_eq!(ep.host, "203.0.113.10");
        assert_eq!(ep.port, 1195);
    }

    #[test]
    fn vpngate_csv_split_handles_quotes() {
        assert_eq!(
            split_csv_line("a,\"b,c\",d"),
            vec!["a".to_string(), "b,c".to_string(), "d".to_string()]
        );
        assert_eq!(
            split_csv_line("a,\"b\"\"c\",d"),
            vec!["a".to_string(), "b\"c".to_string(), "d".to_string()]
        );
    }

    #[test]
    fn endpoint_key_format() {
        let ep = parse_node_endpoint(
            "vless://11111111-2222-3333-4444-555555555555@Example.COM:443?security=tls#x",
        )
        .unwrap();
        assert_eq!(endpoint_key(&ep), "vless://example.com:443");
        let ep2 = parse_node_endpoint("ss://YWVzLTEyOC1nY206cGFzc3dvcmQ@host:8388#n").unwrap();
        assert_eq!(endpoint_key(&ep2), "ss://host:8388");
        // vmess（base64 JSON）同样能取端点
        let vmess = {
            use base64::{engine::general_purpose::STANDARD, Engine as _};
            format!(
                "vmess://{}",
                STANDARD.encode(r#"{"v":"2","ps":"n","add":"203.0.113.9","port":"8443","id":"x"}"#)
            )
        };
        let ep3 = parse_node_endpoint(&vmess).unwrap();
        assert_eq!(endpoint_key(&ep3), "vmess://203.0.113.9:8443");
        assert_eq!(openvpn_proto(&vmess), None);
    }

    #[test]
    fn openvpn_proto_parsed() {
        assert_eq!(
            openvpn_proto("openvpn://203.0.113.10:1195?proto=udp#JP-vpn1001"),
            Some("udp".to_string())
        );
        assert_eq!(
            openvpn_proto("openvpn://198.51.100.20:443?proto=tcp#US-vpn1002"),
            Some("tcp".to_string())
        );
        assert_eq!(
            openvpn_proto("openvpn://198.51.100.20:443#US-vpn1002"),
            None
        );
        assert_eq!(openvpn_proto("vless://uuid@host:443#x"), None);
    }
}
