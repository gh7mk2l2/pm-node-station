//! 首次分级同步验证（ignored 测试，需手动跑）：
//! - 一级多上游同步：tier1_upstreams 表须已 seed（12 个 enabled 公共源 +
//!   9 个 disabled token 源）；跑一次真实同步，校验多源合并、去重、改名、
//!   OpenVPN 配置入库与各源贡献统计
//! - 确认服务端测速已停用（retest 返回 0，不连节点）
//! - 二级是快照导入（只拉一次 PigeonW，不写同步配置、不开定时同步），
//!   校验改名、建批次并激活、同步见证、中继形式转换与无泄漏
//! - 二级无配置时自动同步跳过（tier2_auto_sync_skipped_without_config，只读）
//! - 给三级配好 VPNGate CSV 上游并跑一次真实同步，校验改名、.ovpn 配置入库、
//!   Ping/Speed 入库、Clash（mihomo openvpn）与 sing-box（openvpn-client）转换与测速跳过
//! 跑法（在机器上）：
//!   set -a; source /data/pm-node-station-prod/.env; set +a
//!   cargo test --test seed_tier1_sync -- --ignored --nocapture
use pm_node_station::latency::retest_batch;
use pm_node_station::nodes::read_node_name;
use pm_node_station::sync::{run_sync, tier_sync_configured, SyncTrigger};
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

/// 三级实际数据源：VPNGate 机器可读的 OpenVPN 服务器 CSV
/// （Wing 给的是 https://www.vpngate.net/cn/ 列表页，该页的机器可读 feed 就是这个 CSV）
const TIER3_UPSTREAM: &str = "https://www.vpngate.net/api/iphone/";
/// 二级实际数据源：PigeonW 住宅代理订阅（完整 Clash 配置：
/// type=http 的住宅代理节点 + 4 个策略组，策略组不是节点）。
/// 订阅链接是敏感信息，不进代码库、不进 settings：跑本测试前在部署机器上
/// export TIER2_UPSTREAM=<二级订阅链接>。
/// 二级是快照导入：只拉一次，不写同步配置，不开定时同步。

/// 二级订阅链接取自环境变量 TIER2_UPSTREAM（敏感，不进代码库）。
fn tier2_upstream() -> String {
    std::env::var("TIER2_UPSTREAM").expect("TIER2_UPSTREAM 未设置：先在部署机器上 export TIER2_UPSTREAM=<二级订阅链接>")
}

#[tokio::test]
#[ignore]
async fn seed_tier1_and_verify() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL 未设置");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db)
        .await
        .expect("连不上数据库");

    // 一级多上游须已 seed（部署时写入 tier1_upstreams 表）：
    // 12 个 enabled 公共源 + 9 个 disabled token 源（token 源只进配置不等许可，
    // 同步绝不跑它们）。未 seed 时本测试直接失败，不在这里写 URL。
    let enabled_upstreams: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tier1_upstreams WHERE enabled = TRUE",
    )
    .fetch_one(&pool)
    .await
    .expect("读 tier1_upstreams 失败（migration 0008 是否已应用？）");
    assert!(
        enabled_upstreams >= 11,
        "一级 enabled 上游应 >= 11 个，实际 {enabled_upstreams}（先 seed tier1_upstreams）"
    );
    let disabled_upstreams: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM tier1_upstreams WHERE enabled = FALSE AND kind = 'token'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        disabled_upstreams, 9,
        "token 类上游应为 9 行 disabled，实际 {disabled_upstreams}"
    );
    println!(
        "tier1 upstreams seeded: enabled={} disabled_token={}",
        enabled_upstreams, disabled_upstreams
    );

    // 二级由 seed_tier2_and_verify 覆盖（本测试不再断言二级未配置）

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("PM-Node-Station/1.0")
        .build()
        .unwrap();

    // 一级真实同步（多上游合并）
    let r = run_sync(&pool, &http, SyncTrigger::Manual, None, "", None, 1, None)
        .await
        .expect("一级同步失败");
    println!(
        "tier1 sync: outcome={} batch_id={:?} upstream={} extra={} total={} unrecognized={} skipped={:?}",
        r.outcome, r.batch_id, r.upstream_node_count, r.extra_node_count, r.total_node_count,
        r.unrecognized_count, r.skipped
    );
    for s in &r.sources {
        println!(
            "  source {}: nodes={} error={:?} skipped={:?}",
            s.label, s.nodes, s.error, s.skipped
        );
    }
    assert!(
        r.outcome == "created" || r.outcome == "unchanged",
        "一级同步 outcome 异常: {}",
        r.outcome
    );
    // 多源合并后应远多于旧单源的 279；只断言下限（上游会轮换、个别源会挂）
    assert!(
        r.total_node_count > 1000,
        "一级节点数异常少: {}",
        r.total_node_count
    );
    // 各源贡献数之和（去重前）应 >= 合并后上游数
    let contrib_sum: i64 = r.sources.iter().map(|s| s.nodes).sum();
    assert!(
        contrib_sum >= r.upstream_node_count,
        "各源贡献之和 {} 应 >= 合并后上游数 {}",
        contrib_sum,
        r.upstream_node_count
    );
    // 启用的源里至少 10 个成功（yoyapai 日期文件 404 是已知失败，允许挂）
    let ok_sources = r.sources.iter().filter(|s| s.error.is_none()).count();
    assert!(
        ok_sources >= 10,
        "成功的一级上游太少: {}/{}",
        ok_sources,
        r.sources.len()
    );
    let batch_id = r.batch_id.expect("没有 batch_id");

    // 校验批次与改名
    let row: (i32, serde_json::Value, i16) =
        sqlx::query_as("SELECT node_count, nodes, tier FROM node_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_one(&pool)
            .await
            .expect("读批次失败");
    assert_eq!(row.2, 1);
    assert_eq!(row.0 as i64, r.total_node_count);
    let uris: Vec<String> = row
        .1
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(uris.len() as i64, r.total_node_count);
    let names: Vec<String> = uris.iter().map(|u| read_node_name(u)).collect();
    println!("sample renamed names: {:?}", &names[..5.min(names.len())]);
    // 代理列表类上游（无国家信息）会保留原名，所以不再要求全部节点都含“一级”；
    // 要求：能识别国家的节点全部按新格式改名（实测约 1200+，代理列表无国家信息
    // 的节点占多数是符合预期的），且未识别数与同步结果一致。
    let renamed: Vec<&String> = names.iter().filter(|n| n.contains("一级")).collect();
    assert!(
        renamed.len() as i64 >= 1000,
        "按新格式改名的节点应 >= 1000，实际 {}/{}",
        renamed.len(),
        r.total_node_count
    );
    let unrecognized: Vec<&String> = names.iter().filter(|n| !n.contains("一级")).collect();
    assert_eq!(
        unrecognized.len() as i64,
        r.unrecognized_count,
        "未识别节点数应与同步结果一致"
    );
    println!(
        "unrecognized (kept original name): {} e.g. {:?}",
        unrecognized.len(),
        unrecognized.iter().take(5).collect::<Vec<_>>()
    );
    // 改名格式：[国旗]xx国节点n，且同一国家编号连续（以美国为例）
    let us: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("🇺🇸一级美国节点"))
        .collect();
    assert!(!us.is_empty(), "没找到改名后的美国节点");
    assert_eq!(us[0].as_str(), "🇺🇸一级美国节点1");
    let mut us_nums: Vec<usize> = us
        .iter()
        .map(|n| n.trim_start_matches("🇺🇸一级美国节点").parse().unwrap())
        .collect();
    us_nums.sort_unstable();
    assert_eq!(
        us_nums,
        (1..=us_nums.len()).collect::<Vec<_>>(),
        "美国节点编号不连续"
    );
    // 全批次名唯一
    let mut uniq = names.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), names.len(), "改名后有重名节点");
    // 一级是唯一激活的一级批次
    let active1: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_batches WHERE is_active = TRUE AND tier = 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active1, 1);

    // OpenVPN 节点（pdd 的 81 个）应有 .ovpn 配置入库，且数量与批次里 openvpn:// 节点一致
    let ovpn_uris: Vec<&String> = uris
        .iter()
        .filter(|u| u.to_ascii_lowercase().starts_with("openvpn://"))
        .collect();
    let cfg_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM openvpn_configs WHERE batch_id = $1")
            .bind(batch_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        cfg_count,
        ovpn_uris.len() as i64,
        "openvpn_configs 行数应等于批次里 openvpn:// 节点数"
    );
    println!("tier1 openvpn nodes: {} (configs stored: {})", ovpn_uris.len(), cfg_count);
    if !ovpn_uris.is_empty() {
        // 混合转换：Clash 里有 openvpn 代理，sing-box 里有 openvpn-client endpoint
        let configs: Vec<(String, String)> =
            sqlx::query_as("SELECT node_name, config_b64 FROM openvpn_configs WHERE batch_id = $1")
                .bind(batch_id)
                .fetch_all(&pool)
                .await
                .unwrap();
        let configs_map: std::collections::HashMap<String, String> = configs.into_iter().collect();
        let yaml = pm_node_station::clash::build_clash_yaml_mixed(
            &uris,
            &configs_map,
            "PM节点公益站",
            "rules",
        )
        .expect("一级混合 Clash 转换返回 None");
        let ydoc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        let yproxies = ydoc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
        let yovpn = yproxies
            .iter()
            .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("openvpn"))
            .count();
        assert_eq!(yovpn, ovpn_uris.len(), "Clash 里 openvpn 代理数应等于批次内数");
        let sjson = pm_node_station::singbox::build_singbox_config_mixed(
            &uris,
            &configs_map,
            "PM节点公益站",
            "rules",
        )
        .expect("一级混合 sing-box 转换返回 None");
        let sdoc: serde_json::Value = serde_json::from_str(&sjson).unwrap();
        let endpoints = sdoc.get("endpoints").and_then(|v| v.as_array()).unwrap();
        assert_eq!(endpoints.len(), ovpn_uris.len(), "sing-box endpoints 数应等于批次内数");
        println!(
            "tier1 mixed conversion: clash openvpn={} singbox endpoints={}",
            yovpn,
            endpoints.len()
        );
    }

    // 同步见证：新批次节点全部记为“本次可见”（misses=0）
    let pres1: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_presence WHERE tier = 1 AND misses = 0")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pres1, r.total_node_count, "一级同步见证行数应等于节点数");
    println!("presence: tier1 visible={}", pres1);

    // 服务端测速已停用（2026-11-14 Wing 紧急要求：禁止从服务器 IP 探测节点）：
    // retest 应直接返回 0，不连接任何节点
    let tested = retest_batch(&pool, batch_id)
        .await
        .expect("retest 调用失败");
    assert_eq!(tested, 0, "服务端测速已停用，retest 应返回 0");
    println!("latency disabled: retest returned 0 (no probing)");
}

#[tokio::test]
#[ignore]
async fn seed_tier2_and_verify() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL 未设置");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db)
        .await
        .expect("连不上数据库");

    // 二级是快照导入（Wing 2026-11-14 ~19:17 定）：只拉一次上游，不写
    // subscription_sync_config_tier2，不开定时同步。导入前确认配置行不存在。
    let cfg_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settings WHERE key = 'subscription_sync_config_tier2'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cfg_rows, 0, "二级不应有同步配置行（快照导入不写配置）");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("PM-Node-Station/1.0")
        .build()
        .unwrap();

    // 二级快照导入（只手动跑）
    let r = pm_node_station::sync::import_tier2_snapshot(&pool, &http, &tier2_upstream())
        .await
        .expect("二级快照导入失败");
    println!(
        "tier2 snapshot import: outcome={} batch_id={:?} upstream={} extra={} total={}",
        r.outcome, r.batch_id, r.upstream_node_count, r.extra_node_count, r.total_node_count
    );
    // 重复导入应幂等：内容不变 → unchanged，同一批次
    let r2 = pm_node_station::sync::import_tier2_snapshot(&pool, &http, &tier2_upstream())
        .await
        .expect("二级快照重复导入失败");
    assert_eq!(
        r2.outcome, "unchanged",
        "重复快照导入应为 unchanged，实际 {}",
        r2.outcome
    );
    assert_eq!(r2.batch_id, r.batch_id, "重复快照导入应返回同一批次");
    assert!(
        r.outcome == "created" || r.outcome == "unchanged",
        "二级同步 outcome 异常: {}",
        r.outcome
    );
    // 上游是 http 住宅节点（2026-11-14 快照为 130 个；上游会轮换，只断言下限）；
    // 代理池为空，不应混入额外节点
    assert!(
        r.upstream_node_count >= 100,
        "二级上游节点数异常少: {}",
        r.upstream_node_count
    );
    assert_eq!(r.extra_node_count, 0, "二级不应混入代理池节点");
    assert_eq!(
        r.total_node_count, r.upstream_node_count,
        "二级节点总数应等于上游数"
    );
    let batch_id = r.batch_id.expect("没有 batch_id");

    // 校验批次与改名
    let row: (i32, serde_json::Value, i16) =
        sqlx::query_as("SELECT node_count, nodes, tier FROM node_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_one(&pool)
            .await
            .expect("读批次失败");
    assert_eq!(row.2, 2);
    assert_eq!(row.0 as i64, r.total_node_count);
    // 快照批次 source 必须是 'snapshot'
    let src: String = sqlx::query_scalar("SELECT source FROM node_batches WHERE id = $1")
        .bind(batch_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(src, "snapshot", "二级批次 source 应为 snapshot，实际 {src}");
    let uris: Vec<String> = row
        .1
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(uris.len() as i64, r.total_node_count);
    let names: Vec<String> = uris.iter().map(|u| read_node_name(u)).collect();
    println!("sample renamed names: {:?}", &names[..5.min(names.len())]);
    // 全部是 http://，且全部已按 [国旗]二级xx国节点n 改名（无原名残留）
    assert!(uris
        .iter()
        .all(|u| u.to_ascii_lowercase().starts_with("http://")));
    assert!(
        names
            .iter()
            .all(|n| n.contains("二级") && n.contains("节点")),
        "有节点未按新格式改名: {:?}",
        names
            .iter()
            .filter(|n| !(n.contains("二级") && n.contains("节点")))
            .collect::<Vec<_>>()
    );
    // 上游已轮换为多国（2026-11-14 快照：泰国 54 / 美国 33 / 墨西哥 15 / 印尼 9 /
    // 越南 6 / 日本 4 / 巴西 3 / 菲律宾 3 / 新加坡 1 / 法国 1 / 德国 1），
    // 不再假设全是美国：按国家分组，组内编号连续 1..=n。
    let mut groups: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for n in &names {
        let prefix: String = n.trim_end_matches(|c: char| c.is_ascii_digit()).to_string();
        let num: usize = n[prefix.len()..]
            .parse()
            .unwrap_or_else(|_| panic!("节点名尾部应为数字: {n}"));
        groups.entry(prefix).or_default().push(num);
    }
    let mut dist: Vec<(String, usize)> = groups.iter().map(|(k, v)| (k.clone(), v.len())).collect();
    dist.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    println!("tier2 countries: {:?}", dist);
    assert!(!groups.is_empty(), "没有识别出任何国家分组");
    for (prefix, mut nums) in groups {
        nums.sort_unstable();
        assert_eq!(
            nums,
            (1..=nums.len()).collect::<Vec<_>>(),
            "{prefix} 编号不连续: {:?}",
            nums
        );
    }
    // 全批次名唯一
    let mut uniq = names.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), names.len(), "改名后有重名节点");
    // 二级是唯一激活的二级批次
    let active2: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_batches WHERE is_active = TRUE AND tier = 2")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active2, 1);

    // 同步见证：二级节点全部记为“本次可见”
    let pres2: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_presence WHERE tier = 2 AND misses = 0")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pres2, r.total_node_count, "二级同步见证行数应等于节点数");

    // 转换：二级只下发中继 URI（https://{sub_token}:n{pos}@relay.pmcat.top:443），
    // Clash / sing-box / Base64 三种格式全部走中继，输出里不得出现任何上游
    // 服务器、账号或密码。
    const DUMMY_TOKEN: &str = "11111111-2222-3333-4444-555555555555";
    let relay_nodes =
        pm_node_station::relay::relay_uris(&uris, DUMMY_TOKEN, "relay.pmcat.top", 443);
    assert_eq!(relay_nodes.len() as i64, r.total_node_count);
    assert!(relay_nodes
        .iter()
        .all(|u| u.contains("@relay.pmcat.top:443#")
            && u.starts_with(&format!("https://{DUMMY_TOKEN}:n"))));
    // 上游敏感值清单（host / username / password），用于三格式泄漏检查
    let mut upstream_secrets: Vec<String> = Vec::new();
    for u in &uris {
        if let Some(ep) = pm_node_station::nodes::parse_node_endpoint(u) {
            upstream_secrets.push(ep.host);
            if let Some(user) = ep.username {
                if user.len() >= 4 {
                    upstream_secrets.push(user);
                }
            }
            if let Some(pass) = ep.password {
                if pass.len() >= 4 {
                    upstream_secrets.push(pass);
                }
            }
        }
    }
    upstream_secrets.sort();
    upstream_secrets.dedup();
    assert!(
        !upstream_secrets.is_empty(),
        "上游敏感值清单为空，解析可能失效"
    );
    println!(
        "upstream secrets to grep ({} distinct): hosts/users/passes",
        upstream_secrets.len()
    );

    let yaml = pm_node_station::clash::build_clash_yaml(&relay_nodes, "PM节点公益站", "rules")
        .expect("二级 Clash 转换返回 None");
    let ydoc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let yproxies = ydoc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
    assert_eq!(yproxies.len() as i64, r.total_node_count);
    assert!(yproxies
        .iter()
        .all(|p| p.get("type").and_then(|t| t.as_str()) == Some("http")));
    assert!(yproxies
        .iter()
        .all(|p| p.get("server").and_then(|s| s.as_str()) == Some("relay.pmcat.top")));
    assert!(yproxies
        .iter()
        .all(|p| p.get("port").and_then(|n| n.as_i64()) == Some(443)));
    assert!(yproxies
        .iter()
        .all(|p| p.get("tls").and_then(|t| t.as_bool()) == Some(true)));
    assert!(yproxies
        .iter()
        .all(|p| p.get("username").and_then(|s| s.as_str()) == Some(DUMMY_TOKEN)));
    for (i, p) in yproxies.iter().enumerate() {
        assert_eq!(
            p.get("password").and_then(|s| s.as_str()),
            Some(format!("n{}", i + 1)).as_deref(),
            "Clash 第 {} 个节点 password 应为 n{}",
            i + 1,
            i + 1
        );
        assert_eq!(
            p.get("name").and_then(|s| s.as_str()),
            Some(names[i].as_str()),
            "Clash 第 {} 个节点名应与批次一致（{}）",
            i + 1,
            names[i]
        );
    }
    println!(
        "tier2 clash relay: proxies={} all http relay.pmcat.top:443 tls",
        yproxies.len()
    );

    let sjson =
        pm_node_station::singbox::build_singbox_config(&relay_nodes, "PM节点公益站", "rules")
            .expect("二级 sing-box 转换返回 None");
    let sdoc: serde_json::Value = serde_json::from_str(&sjson).unwrap();
    let outbounds = sdoc.get("outbounds").and_then(|v| v.as_array()).unwrap();
    let node_obs: Vec<&serde_json::Value> = outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("http"))
        .collect();
    assert_eq!(node_obs.len() as i64, r.total_node_count);
    assert!(node_obs
        .iter()
        .all(|o| o.get("server").and_then(|s| s.as_str()) == Some("relay.pmcat.top")));
    assert!(node_obs
        .iter()
        .all(|o| o.get("server_port").and_then(|n| n.as_i64()) == Some(443)));
    assert!(node_obs.iter().all(|o| o
        .get("tls")
        .and_then(|t| t.get("enabled"))
        .and_then(|e| e.as_bool())
        == Some(true)));
    assert!(node_obs
        .iter()
        .all(|o| o.get("username").and_then(|s| s.as_str()) == Some(DUMMY_TOKEN)));
    for (i, o) in node_obs.iter().enumerate() {
        assert_eq!(
            o.get("password").and_then(|s| s.as_str()),
            Some(format!("n{}", i + 1)).as_deref(),
            "sing-box 第 {} 个节点 password 应为 n{}",
            i + 1,
            i + 1
        );
    }
    println!("tier2 singbox relay: http outbounds={}", node_obs.len());

    let b64 = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(relay_nodes.join("\n").as_bytes())
    };
    let decoded = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        String::from_utf8(STANDARD.decode(&b64).unwrap()).unwrap()
    };
    let lines: Vec<&str> = decoded.lines().collect();
    assert_eq!(lines.len() as i64, r.total_node_count);
    assert!(lines.iter().all(|l| l.contains("@relay.pmcat.top:443#")
        && l.starts_with(&format!("https://{DUMMY_TOKEN}:n"))));
    println!(
        "tier2 base64 relay: lines={} all https://relay.pmcat.top",
        lines.len()
    );

    // 三格式输出里不得出现任何上游 host / username / password。
    for secret in &upstream_secrets {
        assert!(
            !yaml.contains(secret.as_str()),
            "Clash 输出泄漏上游值: {secret}"
        );
        assert!(
            !sjson.contains(secret.as_str()),
            "sing-box 输出泄漏上游值: {secret}"
        );
        assert!(
            !decoded.contains(secret.as_str()),
            "Base64 输出泄漏上游值: {secret}"
        );
    }
    // 也不得出现任何一条原始上游 URI。
    for u in &uris {
        assert!(!yaml.contains(u.as_str()));
        assert!(!sjson.contains(u.as_str()));
        assert!(!decoded.contains(u.as_str()));
    }
    println!(
        "tier2 no-leak: {} upstream secrets absent from all 3 formats",
        upstream_secrets.len()
    );

    // 服务端测速已停用（2026-11-14）：retest 返回 0，不写 latency 行
    let tested = retest_batch(&pool, batch_id)
        .await
        .expect("二级 retest 调用失败");
    assert_eq!(tested, 0);
    let lat_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM node_latency WHERE batch_id = $1")
        .bind(batch_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lat_rows, 0);
    println!("tier2 verified: total={}", r.total_node_count);
}

#[tokio::test]
#[ignore]
async fn seed_tier3_and_verify() {
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL 未设置");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db)
        .await
        .expect("连不上数据库");

    // 三级上游配置（不存在才插；已存在则改回 enabled=true，让自动同步也跑三级）
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES ('subscription_sync_config_tier3', $1) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(serde_json::json!({"source_url": TIER3_UPSTREAM, "enabled": true}))
    .execute(&pool)
    .await
    .expect("写三级同步配置失败");

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("PM-Node-Station/1.0")
        .build()
        .unwrap();

    // 三级真实同步
    let r = run_sync(&pool, &http, SyncTrigger::Manual, None, "", None, 3, None)
        .await
        .expect("三级同步失败");
    println!(
        "tier3 sync: outcome={} batch_id={:?} upstream={} extra={} total={}",
        r.outcome, r.batch_id, r.upstream_node_count, r.extra_node_count, r.total_node_count
    );
    assert!(
        r.outcome == "created" || r.outcome == "unchanged",
        "三级同步 outcome 异常: {}",
        r.outcome
    );
    assert!(
        r.total_node_count > 50,
        "三级节点数异常少: {}",
        r.total_node_count
    );
    assert_eq!(r.extra_node_count, 0, "三级不应混入代理池节点");
    let batch_id = r.batch_id.expect("没有 batch_id");

    // 校验批次与改名
    let row: (i32, serde_json::Value, i16) =
        sqlx::query_as("SELECT node_count, nodes, tier FROM node_batches WHERE id = $1")
            .bind(batch_id)
            .fetch_one(&pool)
            .await
            .expect("读批次失败");
    assert_eq!(row.2, 3);
    assert_eq!(row.0 as i64, r.total_node_count);
    let uris: Vec<String> = row
        .1
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();
    assert_eq!(uris.len() as i64, r.total_node_count);
    let names: Vec<String> = uris.iter().map(|u| read_node_name(u)).collect();
    println!("sample renamed names: {:?}", &names[..5.min(names.len())]);
    // 全部是 openvpn://，且全部已按 [国旗]xx国节点n 改名（无原名残留）
    assert!(uris
        .iter()
        .all(|u| u.to_ascii_lowercase().starts_with("openvpn://")));
    assert!(
        names
            .iter()
            .all(|n| n.contains("三级") && n.contains("节点")),
        "有节点未按新格式改名: {:?}",
        names
            .iter()
            .filter(|n| !(n.contains("三级") && n.contains("节点")))
            .collect::<Vec<_>>()
    );
    // 每个国家编号连续（以日本为例）
    let jp: Vec<&String> = names
        .iter()
        .filter(|n| n.starts_with("🇯🇵三级日本节点"))
        .collect();
    assert!(!jp.is_empty(), "没找到改名后的日本节点");
    let mut jp_nums: Vec<usize> = jp
        .iter()
        .map(|n| n.trim_start_matches("🇯🇵三级日本节点").parse().unwrap())
        .collect();
    jp_nums.sort_unstable();
    assert_eq!(
        jp_nums,
        (1..=jp_nums.len()).collect::<Vec<_>>(),
        "日本节点编号不连续"
    );
    // 全批次名唯一
    let mut uniq = names.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), names.len(), "改名后有重名节点");
    // 三级是唯一激活的三级批次
    let active3: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_batches WHERE is_active = TRUE AND tier = 3")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active3, 1);

    // 同步见证：三级节点全部记为“本次可见”
    let pres3: i64 =
        sqlx::query_scalar("SELECT count(*) FROM node_presence WHERE tier = 3 AND misses = 0")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(pres3, r.total_node_count, "三级同步见证行数应等于节点数");

    // .ovpn 配置入库数量与节点数一致，且可解码出 remote 行
    let cfg_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM vpngate_configs WHERE batch_id = $1")
            .bind(batch_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(cfg_count, r.total_node_count);
    let sample_cfg: Option<String> =
        sqlx::query_scalar("SELECT config_b64 FROM vpngate_configs WHERE batch_id = $1 LIMIT 1")
            .bind(batch_id)
            .fetch_optional(&pool)
            .await
            .unwrap();
    let decoded = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD
            .decode(sample_cfg.expect("没有存入任何 .ovpn 配置"))
            .unwrap()
    };
    assert!(
        String::from_utf8_lossy(&decoded).contains("remote "),
        "存入的 .ovpn 配置里没有 remote 行"
    );

    // 转换：.ovpn → Clash YAML（mihomo openvpn）与 sing-box JSON（openvpn-client endpoint）
    let configs: Vec<(String, String)> =
        sqlx::query_as("SELECT node_name, config_b64 FROM vpngate_configs WHERE batch_id = $1")
            .bind(batch_id)
            .fetch_all(&pool)
            .await
            .unwrap();
    let configs_map: std::collections::HashMap<String, String> = configs.into_iter().collect();
    assert_eq!(configs_map.len() as i64, r.total_node_count);
    // Ping/Speed 入库（CSV 自带数字；个别服务器 Ping 为 "-" 时存 0，不展示）
    let meta_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vpngate_configs WHERE batch_id = $1 AND ping_ms > 0 AND speed_bps > 0",
    )
    .bind(batch_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let speed_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM vpngate_configs WHERE batch_id = $1 AND speed_bps > 0",
    )
    .bind(batch_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(speed_count, r.total_node_count, "Speed 应全部入库");
    assert!(
        meta_count >= r.total_node_count - 5,
        "Ping 缺失过多: {}/{}",
        meta_count,
        r.total_node_count
    );
    let zero_ping: Vec<String> = sqlx::query_scalar(
        "SELECT node_name FROM vpngate_configs WHERE batch_id = $1 AND ping_ms <= 0",
    )
    .bind(batch_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    println!("tier3 ping missing (CSV Ping=\"-\"): {:?}", zero_ping);

    let yaml = pm_node_station::clash::build_clash_yaml_openvpn(
        &uris,
        &configs_map,
        "PM节点公益站",
        "rules",
    )
    .expect("三级 Clash 转换返回 None");
    let ydoc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let yproxies = ydoc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
    assert_eq!(yproxies.len() as i64, r.total_node_count);
    assert!(yproxies
        .iter()
        .all(|p| p.get("type").and_then(|t| t.as_str()) == Some("openvpn")));
    assert!(yproxies
        .iter()
        .all(|p| p.get("server").is_some() && p.get("port").is_some() && p.get("ca").is_some()));
    // 字段抽查：cipher AES-128-CBC、auth SHA1
    let first = &yproxies[0];
    assert_eq!(
        first.get("cipher").and_then(|v| v.as_str()),
        Some("AES-128-CBC")
    );
    assert_eq!(first.get("auth").and_then(|v| v.as_str()), Some("SHA1"));

    let sjson = pm_node_station::singbox::build_singbox_config_openvpn(
        &uris,
        &configs_map,
        "PM节点公益站",
        "rules",
    )
    .expect("三级 sing-box 转换返回 None");
    let sdoc: serde_json::Value = serde_json::from_str(&sjson).unwrap();
    let endpoints = sdoc.get("endpoints").and_then(|v| v.as_array()).unwrap();
    assert_eq!(endpoints.len() as i64, r.total_node_count);
    assert!(endpoints
        .iter()
        .all(|e| e.get("type").and_then(|t| t.as_str()) == Some("openvpn-client")));
    assert!(endpoints.iter().all(|e| e.get("server").is_some()
        && e.get("server_port").is_some()
        && e.get("tls").and_then(|t| t.get("certificate")).is_some()));
    // 通用构造器仍不认 openvpn://（回归保护）
    assert!(pm_node_station::clash::build_clash_yaml(&uris, "PM节点公益站", "rules").is_none());
    assert!(
        pm_node_station::singbox::build_singbox_config(&uris, "PM节点公益站", "rules").is_none()
    );
    println!(
        "tier3 conversion: yaml_proxies={} singbox_endpoints={} ping_speed_rows={}",
        yproxies.len(),
        endpoints.len(),
        meta_count
    );

    // 服务端测速已停用（2026-11-14）：retest 返回 0，不写 latency 行
    let tested = retest_batch(&pool, batch_id)
        .await
        .expect("三级 retest 调用失败");
    assert_eq!(tested, 0);
    let lat_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM node_latency WHERE batch_id = $1")
        .bind(batch_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(lat_rows, 0);
    println!(
        "tier3 verified: total={} configs={} jp={}",
        r.total_node_count,
        cfg_count,
        jp.len()
    );
}

#[tokio::test]
#[ignore]
async fn tier2_auto_sync_skipped_without_config() {
    // 自动同步跳过判定（用生产库实测）：二级无上游配置 → 跳过；
    // 一级、三级有配置 → 正常跑。只读 settings，不写任何东西。
    let db = std::env::var("DATABASE_URL").expect("DATABASE_URL 未设置");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&db)
        .await
        .expect("连不上数据库");
    assert!(
        !tier_sync_configured(&pool, 2, "").await,
        "二级无配置时自动同步必须跳过"
    );
    assert!(
        tier_sync_configured(&pool, 1, "").await,
        "一级有配置时自动同步应跑"
    );
    assert!(
        tier_sync_configured(&pool, 3, "").await,
        "三级有配置时自动同步应跑"
    );
    let cfg_rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM settings WHERE key = 'subscription_sync_config_tier2'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(cfg_rows, 0, "二级不应有同步配置行");
    println!("auto-sync skip decision: tier2=skip tier1=run tier3=run (prod DB)");
}
