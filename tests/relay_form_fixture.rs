//! Relay-form verification with FIXTURE data only (no database, no real sync):
//! tier-2 sync is on hold, so the relay URI form + all three subscription
//! formats are verified against fake PigeonW-style http nodes (TEST-NET IPs,
//! obviously fake credentials). Proves the relay form carries no upstream
//! server, username or password in any output format.
use pm_node_station::relay::relay_uris;

const DUMMY_TOKEN: &str = "11111111-2222-3333-4444-555555555555";

/// Fake tier-2 nodes in the new name format (🇺🇸二级美国节点N).
/// Hosts are TEST-NET (203.0.113.0/24), credentials are obviously fake.
fn fixture_nodes() -> Vec<String> {
    (1..=5)
        .map(|i| {
            let octet = 10 + i;
            format!(
                "http://fixture-user-{i}:fixture-pass-{i}@203.0.113.{octet}:6200{i}#%F0%9F%87%BA%F0%9F%87%B8%E4%BA%8C%E7%BA%A7%E7%BE%8E%E5%9B%BD%E8%8A%82%E7%82%B9{i}"
            )
        })
        .collect()
}

#[test]
fn relay_form_three_formats_no_upstream_leak() {
    let uris = fixture_nodes();
    let relay_nodes = relay_uris(&uris, DUMMY_TOKEN, "relay.pmcat.top", 443);
    assert_eq!(relay_nodes.len(), 5);
    for (i, u) in relay_nodes.iter().enumerate() {
        assert!(
            u.starts_with(&format!(
                "https://{DUMMY_TOKEN}:n{}@relay.pmcat.top:443#",
                i + 1
            )),
            "relay URI {i} wrong: {u}"
        );
        assert_eq!(
            pm_node_station::nodes::read_node_name(u),
            format!("🇺🇸二级美国节点{}", i + 1)
        );
    }

    let yaml = pm_node_station::clash::build_clash_yaml(&relay_nodes, "PM节点公益站", "rules")
        .expect("Clash build returned None");
    let ydoc: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
    let yproxies = ydoc.get("proxies").and_then(|v| v.as_sequence()).unwrap();
    assert_eq!(yproxies.len(), 5);
    for (i, p) in yproxies.iter().enumerate() {
        assert_eq!(p.get("type").and_then(|t| t.as_str()), Some("http"));
        assert_eq!(
            p.get("server").and_then(|s| s.as_str()),
            Some("relay.pmcat.top")
        );
        assert_eq!(p.get("port").and_then(|n| n.as_i64()), Some(443));
        assert_eq!(p.get("tls").and_then(|t| t.as_bool()), Some(true));
        assert_eq!(
            p.get("username").and_then(|s| s.as_str()),
            Some(DUMMY_TOKEN)
        );
        assert_eq!(
            p.get("password").and_then(|s| s.as_str()),
            Some(format!("n{}", i + 1)).as_deref()
        );
        assert_eq!(
            p.get("name").and_then(|s| s.as_str()),
            Some(format!("🇺🇸二级美国节点{}", i + 1)).as_deref()
        );
    }

    let sjson =
        pm_node_station::singbox::build_singbox_config(&relay_nodes, "PM节点公益站", "rules")
            .expect("sing-box build returned None");
    let sdoc: serde_json::Value = serde_json::from_str(&sjson).unwrap();
    let outbounds = sdoc.get("outbounds").and_then(|v| v.as_array()).unwrap();
    let node_obs: Vec<&serde_json::Value> = outbounds
        .iter()
        .filter(|o| o.get("type").and_then(|t| t.as_str()) == Some("http"))
        .collect();
    assert_eq!(node_obs.len(), 5);
    for (i, o) in node_obs.iter().enumerate() {
        assert_eq!(
            o.get("server").and_then(|s| s.as_str()),
            Some("relay.pmcat.top")
        );
        assert_eq!(o.get("server_port").and_then(|n| n.as_i64()), Some(443));
        assert_eq!(
            o.get("tls")
                .and_then(|t| t.get("enabled"))
                .and_then(|e| e.as_bool()),
            Some(true)
        );
        assert_eq!(
            o.get("username").and_then(|s| s.as_str()),
            Some(DUMMY_TOKEN)
        );
        assert_eq!(
            o.get("password").and_then(|s| s.as_str()),
            Some(format!("n{}", i + 1)).as_deref()
        );
    }

    let b64 = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        STANDARD.encode(relay_nodes.join("\n").as_bytes())
    };
    let decoded = {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        String::from_utf8(STANDARD.decode(&b64).unwrap()).unwrap()
    };
    let lines: Vec<&str> = decoded.lines().collect();
    assert_eq!(lines.len(), 5);
    assert!(lines.iter().all(|l| l.contains("@relay.pmcat.top:443#")));

    // No upstream host / username / password anywhere in the three outputs.
    for i in 1..=5 {
        for secret in [
            format!("203.0.113.{}", 10 + i),
            format!("fixture-user-{i}"),
            format!("fixture-pass-{i}"),
        ] {
            assert!(!yaml.contains(&secret), "Clash leaks {secret}");
            assert!(!sjson.contains(&secret), "sing-box leaks {secret}");
            assert!(!decoded.contains(&secret), "Base64 leaks {secret}");
        }
    }
    for u in &uris {
        assert!(!yaml.contains(u.as_str()));
        assert!(!sjson.contains(u.as_str()));
        assert!(!decoded.contains(u.as_str()));
    }
    println!("relay form fixture: 5 nodes, 3 formats, no upstream leak");
}
