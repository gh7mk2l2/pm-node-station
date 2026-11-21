-- 三级：VPNGate 志愿者节点（OpenVPN 协议），不限流、不反分发
INSERT INTO node_tiers (tier, name, description, ip_type, rate_limited, anti_redistribution, daily_limit_gb, monthly_limit_gb, sort_order) VALUES
    (3, '三级 · VPNGate', 'VPNGate 志愿者节点 · 不限流 · 不反分发 · OpenVPN 协议', 'volunteer', FALSE, FALSE, NULL, NULL, 3)
ON CONFLICT (tier) DO NOTHING;

-- VPNGate 节点的完整 .ovpn 配置（CSV 里每行自带的 OpenVPN_ConfigData_Base64）
CREATE TABLE IF NOT EXISTS vpngate_configs (
    batch_id BIGINT NOT NULL,
    node_name TEXT NOT NULL,
    config_b64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (batch_id, node_name)
);
