-- 三级转换上线：VPNGate CSV 自带的 Ping/Speed（只展示，不探测）
ALTER TABLE vpngate_configs ADD COLUMN IF NOT EXISTS ping_ms INT NOT NULL DEFAULT 0;
ALTER TABLE vpngate_configs ADD COLUMN IF NOT EXISTS speed_bps BIGINT NOT NULL DEFAULT 0;

-- 三级描述写明转换后的客户端版本要求（老版 Clash 内核不认 openvpn）
UPDATE node_tiers
SET description = 'VPNGate 志愿者节点 · 不限流 · 不反分发 · OpenVPN 协议 · 需 mihomo ≥1.19.29 / sing-box ≥1.14'
WHERE tier = 3;
