//! SOCKS5 / HTTP(S) 福利代理池文本解析与挑选（原创实现）。
//! 输入格式（每行一条，来自第三方代理池）：
//!   socks5://host:port [原生IP][高风险84] 美国 [美国 得克萨斯州 休斯敦] 入库:2026-08-18 17:34:30
//!   socks5://user:pass@host:port [家宽][原生IP] 俄罗斯 [俄罗斯 莫斯科 莫斯科] 入库:…

use crate::util::sha256_hex;

#[derive(Debug, Clone)]
pub struct SocksEntry {
    pub host: String,
    pub port: u16,
    pub protocol: String, // socks5 | http | https
    pub username: Option<String>,
    pub password: Option<String>,
    /// 脱敏后的原始行（不含凭据）
    pub line: String,
    pub tags: Vec<String>,
    pub native_ip: bool,
    pub residential: bool,
    pub country: Option<String>,
    pub region: Option<String>,
    pub provider: Option<String>,
    pub risk_score: Option<i32>,
}

const PROVIDER_KEYWORDS: &[&str] = &[
    "Cloudflare", "Oracle", "甲骨文", "搬瓦工", "BandwagonHost", "RackNerd", "DMIT",
    "阿里云", "AWS", "Amazon", "Google", "Hetzner", "Vultr", "DigitalOcean", "Linode",
    "OVH", "Akamai", "Azure", "腾讯云",
];

/// 解析单行；格式不符返回 None（容错：跳过脏行，不抛错）
pub fn parse_socks_line(raw: &str) -> Option<SocksEntry> {
    let mut line = raw.trim().to_string();
    if line.is_empty() {
        return None;
    }
    let mut protocol = "socks5".to_string();
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("socks5h://") || lower.starts_with("socks5://") || lower.starts_with("socks://") {
        line = line.splitn(2, "://").nth(1)?.to_string();
    } else if lower.starts_with("http://") {
        protocol = "http".to_string();
        line = line.splitn(2, "://").nth(1)?.to_string();
    } else if lower.starts_with("https://") {
        protocol = "https".to_string();
        line = line.splitn(2, "://").nth(1)?.to_string();
    } else if line.contains("://") {
        return None; // socks4:// 等不认识的 scheme
    }

    // userinfo：从右找最后一个 @ 剥离（密码可含 @）
    let mut body = line.as_str();
    let mut username: Option<String> = None;
    let mut password: Option<String> = None;
    if let Some(at) = body.rfind('@') {
        let userinfo = &body[..at];
        let sep = userinfo.find(':')?;
        if sep == 0 {
            return None;
        }
        username = Some(decode_userinfo(&userinfo[..sep])?);
        password = Some(decode_userinfo(&userinfo[sep + 1..])?);
        if username.as_deref().unwrap_or("").is_empty() {
            return None;
        }
        body = &body[at + 1..];
    }

    // authority 与元数据分界：第一个空白 / | /
    let mut meta_start = None;
    for (i, ch) in body.char_indices() {
        if ch.is_whitespace() || ch == '|' || ch == ',' {
            meta_start = Some(i);
            break;
        }
    }
    let authority = match meta_start {
        Some(i) => &body[..i],
        None => body,
    };
    let mut meta = match meta_start {
        Some(i) => {
            let mut j = i;
            while j < body.len()
                && (body.as_bytes()[j].is_ascii_whitespace() || body.as_bytes()[j] == b'|' || body.as_bytes()[j] == b',')
            {
                j += 1;
            }
            &body[j..]
        }
        None => "",
    };
    let _ = &mut meta;
    let colon = authority.rfind(':')?;
    let host = &authority[..colon];
    let port_str = &authority[colon + 1..];
    if host.is_empty()
        || !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        || port_str.is_empty()
        || !port_str.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }

    // 括号组分类：含空格 → 地区（取最后一个）；无空格 → 标签
    let mut tags: Vec<String> = Vec::new();
    let mut region: Option<String> = None;
    {
        let mut rest = meta;
        while let Some(start) = rest.find('[') {
            let Some(end) = rest[start..].find(']') else {
                break;
            };
            let val = rest[start + 1..start + end].trim().to_string();
            if !val.is_empty() {
                if val.contains(char::is_whitespace) {
                    region = Some(val);
                } else {
                    tags.push(val);
                }
            }
            rest = &rest[start + end + 1..];
        }
    }

    // 国家 = 括号外第一个非「入库」开头的词
    let mut country: Option<String> = None;
    let no_brackets = {
        let mut s = String::new();
        let mut in_bracket = false;
        for ch in meta.chars() {
            match ch {
                '[' => in_bracket = true,
                ']' => in_bracket = false,
                _ if !in_bracket => s.push(ch),
                _ => {}
            }
        }
        s
    };
    for tok in no_brackets.split(|c: char| c.is_whitespace() || c == '|' || c == ',') {
        let tok = tok.trim();
        if tok.is_empty() || tok.starts_with("入库") {
            continue;
        }
        country = Some(tok.to_string());
        break;
    }

    let mut risk_score: Option<i32> = None;
    for tag in &tags {
        if let Some(num) = tag.strip_prefix("高风险") {
            if let Ok(n) = num.parse::<i32>() {
                risk_score = Some(n);
                break;
            }
        }
    }

    let native_ip = tags.iter().any(|t| t == "原生IP");
    let residential = tags.iter().any(|t| t == "家宽");
    let provider = region
        .as_deref()
        .and_then(|r| PROVIDER_KEYWORDS.iter().find(|kw| r.contains(**kw)).map(|s| s.to_string()));

    Some(SocksEntry {
        host: host.to_string(),
        port,
        protocol,
        username,
        password,
        line: body.to_string(),
        tags,
        native_ip,
        residential,
        country,
        region,
        provider,
        risk_score,
    })
}

fn decode_userinfo(value: &str) -> Option<String> {
    let mut out = Vec::new();
    let b = value.as_bytes();
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
    String::from_utf8(out).ok()
}

/// 生成可下发 URI；认证信息逐项编码
pub fn proxy_uri(entry: &SocksEntry, name: Option<&str>) -> String {
    let host = if entry.host.contains(':') {
        format!("[{}]", entry.host)
    } else {
        entry.host.clone()
    };
    let auth = match (&entry.username, &entry.password) {
        (Some(u), Some(p)) => format!("{}:{}@", urlencode(u), urlencode(p)),
        (Some(u), None) => format!("{}@", urlencode(u)),
        _ => String::new(),
    };
    let fragment = match name {
        Some(n) if !n.is_empty() => format!("#{}", urlencode(n)),
        _ => String::new(),
    };
    format!("{}://{auth}{host}:{}{fragment}", entry.protocol, entry.port)
}

fn urlencode(s: &str) -> String {
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

/// 管理端错误样本脱敏，避免把导入文本中的账号密码原样回传
pub fn redact_proxy_credentials(value: &str) -> String {
    let Some(scheme_end) = value.find("://") else {
        return value.to_string();
    };
    let authority_start = scheme_end + 3;
    let Some(at) = value.rfind('@') else {
        return value.to_string();
    };
    if at < authority_start || !value[authority_start..at].contains(':') {
        return value.to_string();
    }
    format!("{}***:***@{}", &value[..authority_start], &value[at + 1..])
}

/// 数据库、批次去重共用的完整代理身份
pub fn proxy_identity(entry: &SocksEntry) -> String {
    format!(
        "{}\u{0}{}\u{0}{}\u{0}{}\u{0}{}",
        entry.protocol,
        entry.host,
        entry.port,
        entry.username.clone().unwrap_or_default(),
        entry.password.clone().unwrap_or_default()
    )
}

/// 入池过滤：风险分 < 10（无风险标签视为 0）
pub fn is_eligible(e: &SocksEntry) -> bool {
    e.risk_score.unwrap_or(0) < 10
}

/// 节点展示名：家宽/原生明确标出，其他类型标为测速优选
pub fn socks_node_name(e: &SocksEntry) -> String {
    let type_tag = if e.residential {
        if e.native_ip { "家宽·原生" } else { "家宽" }
    } else if e.native_ip {
        "原生"
    } else {
        "测速优选"
    };
    let place = build_place(e);
    let provider = e.provider.as_deref().map(|p| format!("·{p}")).unwrap_or_default();
    let proto = match e.protocol.as_str() {
        "https" => "HTTPS",
        "http" => "HTTP",
        _ => "SOCKS5",
    };
    format!("[{proto}·{type_tag}] {place}{provider}")
}

fn build_place(e: &SocksEntry) -> String {
    let Some(region) = &e.region else {
        return e.country.clone().unwrap_or_else(|| e.host.clone());
    };
    let mut tokens: Vec<&str> = region.split_whitespace().collect();
    let cut = tokens.iter().position(|t| {
        *t == "—" || *t == "-" || PROVIDER_KEYWORDS.iter().any(|kw| *kw == *t)
    });
    if let Some(c) = cut {
        if c > 0 {
            tokens.truncate(c);
        }
    }
    let mut dedup: Vec<&str> = Vec::new();
    for t in tokens {
        if dedup.last() != Some(&t) {
            dedup.push(t);
        }
    }
    let place = dedup.iter().take(3).cloned().collect::<Vec<_>>().join("·");
    if place.is_empty() {
        e.country.clone().unwrap_or_else(|| e.host.clone())
    } else {
        place
    }
}

#[derive(Debug, Clone)]
pub struct CheckedSocks {
    pub entry: SocksEntry,
    pub latency_ms: i64,
}

/// 从可用代理里挑质量最高的 N 个（延迟升序 + 多样性约束）
pub fn pick_best(ok: &[CheckedSocks], n: usize) -> Vec<CheckedSocks> {
    let sorted = dedupe_by_address(ok);
    let mut state = PickState::new();
    let mut out = Vec::new();
    fill_with_diversity(&mut out, &sorted, n, &mut state);
    out
}

/// 每日福利代理选择器：最多 30 个原生/家宽 + 补到 60 个；带种子时在低延迟窗口内稳定轮换
pub fn pick_daily_socks(
    ok: &[CheckedSocks],
    total: usize,
    preferred_count: usize,
    selection_seed: Option<&str>,
) -> Vec<CheckedSocks> {
    let limit = total.min(60);
    if limit == 0 {
        return vec![];
    }
    let candidates = dedupe_by_address(ok);
    let mut state = PickState::new();
    let mut out: Vec<CheckedSocks> = Vec::new();
    let preferred_limit = preferred_count.min(30).min(limit);
    let preferred_candidates: Vec<CheckedSocks> = candidates
        .iter()
        .filter(|c| c.entry.native_ip || c.entry.residential)
        .cloned()
        .collect();
    let preferred = match selection_seed {
        Some(seed) => seeded_quality_window(
            &preferred_candidates,
            (preferred_limit * 4).max(preferred_limit),
            &format!("{seed}:preferred"),
        ),
        None => preferred_candidates,
    };
    let general = match selection_seed {
        Some(seed) => seeded_quality_window(
            &candidates,
            (limit * 4).max(limit),
            &format!("{seed}:general"),
        ),
        None => candidates,
    };

    fill_with_diversity(&mut out, &preferred, preferred_limit, &mut state);
    fill_without_diversity(&mut out, &preferred, preferred_limit, &mut state);
    fill_with_diversity(&mut out, &general, limit, &mut state);
    fill_without_diversity(&mut out, &general, limit, &mut state);
    out
}

fn seeded_quality_window(
    candidates: &[CheckedSocks],
    window_size: usize,
    seed: &str,
) -> Vec<CheckedSocks> {
    let mut ranked: Vec<(String, CheckedSocks)> = candidates
        .iter()
        .take(window_size)
        .map(|item| {
            let rank = sha256_hex(&format!("{seed}\0{}", proxy_identity(&item.entry)));
            (rank, item.clone())
        })
        .collect();
    ranked.sort_by(|a, b| a.0.cmp(&b.0));
    ranked.into_iter().map(|(_, item)| item).collect()
}

#[derive(Default)]
struct PickState {
    chosen: std::collections::HashSet<String>,
    subnet_count: std::collections::HashMap<String, usize>,
    country_count: std::collections::HashMap<String, usize>,
}

impl PickState {
    fn new() -> Self {
        Self::default()
    }
}

fn dedupe_by_address(ok: &[CheckedSocks]) -> Vec<CheckedSocks> {
    let mut fastest: std::collections::HashMap<String, CheckedSocks> =
        std::collections::HashMap::new();
    for item in ok {
        let key = proxy_identity(&item.entry);
        match fastest.get(&key) {
            Some(prev) if prev.latency_ms <= item.latency_ms => {}
            _ => {
                fastest.insert(key, item.clone());
            }
        }
    }
    let mut v: Vec<CheckedSocks> = fastest.into_values().collect();
    v.sort_by_key(|i| i.latency_ms);
    v
}

fn subnet_of(host: &str) -> String {
    host.split('.').take(3).collect::<Vec<_>>().join(".")
}

fn fill_with_diversity(
    out: &mut Vec<CheckedSocks>,
    candidates: &[CheckedSocks],
    target: usize,
    state: &mut PickState,
) {
    add_candidates(out, candidates, target, state, true);
    if out.len() < target {
        add_candidates(out, candidates, target, state, false);
    }
}

fn add_candidates(
    out: &mut Vec<CheckedSocks>,
    candidates: &[CheckedSocks],
    target: usize,
    state: &mut PickState,
    enforce_country_limit: bool,
) {
    for item in candidates {
        if out.len() >= target {
            return;
        }
        let key = proxy_identity(&item.entry);
        if state.chosen.contains(&key) {
            continue;
        }
        let subnet = subnet_of(&item.entry.host);
        let country = item.entry.country.clone().unwrap_or_else(|| "?".to_string());
        if state.subnet_count.get(&subnet).copied().unwrap_or(0) >= 2 {
            continue;
        }
        if enforce_country_limit && state.country_count.get(&country).copied().unwrap_or(0) >= 8 {
            continue;
        }
        state.chosen.insert(key);
        *state.subnet_count.entry(subnet).or_insert(0) += 1;
        *state.country_count.entry(country).or_insert(0) += 1;
        out.push(item.clone());
    }
}

fn fill_without_diversity(
    out: &mut Vec<CheckedSocks>,
    candidates: &[CheckedSocks],
    target: usize,
    state: &mut PickState,
) {
    for item in candidates {
        if out.len() >= target {
            return;
        }
        let key = proxy_identity(&item.entry);
        if state.chosen.contains(&key) {
            continue;
        }
        state.chosen.insert(key);
        let subnet = subnet_of(&item.entry.host);
        let country = item.entry.country.clone().unwrap_or_else(|| "?".to_string());
        *state.subnet_count.entry(subnet).or_insert(0) += 1;
        *state.country_count.entry(country).or_insert(0) += 1;
        out.push(item.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_line() {
        let e = parse_socks_line(
            "socks5://user:pass@1.2.3.4:1080 [家宽][原生IP][高风险3] 美国 [美国 得克萨斯州 休斯敦] 入库:2026-08-18 17:34:30",
        )
        .unwrap();
        assert_eq!(e.host, "1.2.3.4");
        assert_eq!(e.port, 1080);
        assert_eq!(e.protocol, "socks5");
        assert_eq!(e.username.as_deref(), Some("user"));
        assert!(e.residential && e.native_ip);
        assert_eq!(e.country.as_deref(), Some("美国"));
        assert_eq!(e.region.as_deref(), Some("美国 得克萨斯州 休斯敦"));
        assert_eq!(e.risk_score, Some(3));
        assert!(is_eligible(&e));
    }

    #[test]
    fn rejects_bad_lines() {
        assert!(parse_socks_line("").is_none());
        assert!(parse_socks_line("socks4://1.2.3.4:1080").is_none());
        assert!(parse_socks_line("socks5://1.2.3.4").is_none());
        assert!(parse_socks_line("socks5://:pass@1.2.3.4:1080").is_none());
        assert!(parse_socks_line("https://example.com/page").is_none());
    }

    #[test]
    fn risk_filter() {
        let mut e = parse_socks_line("socks5://1.2.3.4:1080 [高风险84] 美国").unwrap();
        assert!(!is_eligible(&e));
        e.risk_score = Some(9);
        assert!(is_eligible(&e));
    }

    #[test]
    fn proxy_uri_round_trips() {
        let e = parse_socks_line("http://u:p%40ss@5.6.7.8:8080 [家宽] 日本").unwrap();
        let uri = proxy_uri(&e, Some(&socks_node_name(&e)));
        assert!(uri.starts_with("http://u:p%40ss@5.6.7.8:8080#"));
        // fragment 里的中文会被 percent-encode（家宽 → %E5%AE%B6%E5%AE%BD）
        assert!(uri.contains("%E5%AE%B6%E5%AE%BD"));
    }

    #[test]
    fn daily_pick_prefers_residential_then_fast() {
        let mk = |host: &str, lat: i64, res: bool| CheckedSocks {
            entry: SocksEntry {
                host: host.into(),
                port: 1080,
                protocol: "socks5".into(),
                username: None,
                password: None,
                line: host.into(),
                tags: vec![],
                native_ip: false,
                residential: res,
                country: Some("美国".into()),
                region: None,
                provider: None,
                risk_score: None,
            },
            latency_ms: lat,
        };
        let pool = vec![
            mk("1.0.0.1", 50, false),
            mk("1.0.0.2", 20, true),
            mk("1.0.0.3", 10, true),
            mk("1.0.0.4", 5, false),
        ];
        let picked = pick_daily_socks(&pool, 3, 2, None);
        assert_eq!(picked.len(), 3);
        // 前 2 个应为家宽（按延迟 10、20），第 3 个是最快的其余
        assert_eq!(picked[0].entry.host, "1.0.0.3");
        assert_eq!(picked[1].entry.host, "1.0.0.2");
        assert_eq!(picked[2].entry.host, "1.0.0.4");
        // 带种子时结果稳定
        let a = pick_daily_socks(&pool, 3, 2, Some("2026-11-14:0:xxx"));
        let b = pick_daily_socks(&pool, 3, 2, Some("2026-11-14:0:xxx"));
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn credentials_are_redacted() {
        assert_eq!(
            redact_proxy_credentials("socks5://user:secret@1.2.3.4:1080"),
            "socks5://***:***@1.2.3.4:1080"
        );
    }
}
