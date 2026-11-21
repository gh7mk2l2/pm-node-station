-- 节点列表页（#/nodes）与外部探测器的数据基础（2026-11-14）
-- 可用性改由主 Agent 沙箱探测器检测后写回：禁止从服务器 IP 探测节点（Wing 17:23 紧急要求）

-- 外部探测结果：按测速端点（scheme://host:port）存，多个节点共用同一端点时共享一行。
-- 写回 SQL（探测器用）：
--   INSERT INTO node_availability (endpoint, online, latency_ms, checked_at, updated_at)
--   VALUES ('vless://1.2.3.4:443', TRUE, 87, now(), now())
--   ON CONFLICT (endpoint) DO UPDATE SET online = EXCLUDED.online,
--     latency_ms = EXCLUDED.latency_ms, checked_at = EXCLUDED.checked_at, updated_at = now();
CREATE TABLE IF NOT EXISTS node_availability (
    endpoint TEXT PRIMARY KEY,
    online BOOLEAN NOT NULL,
    latency_ms INT,
    checked_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 上游同步见证：同步时更新；连续缺席的节点在列表页标“已下线”
CREATE TABLE IF NOT EXISTS node_presence (
    node_uri TEXT PRIMARY KEY,
    tier SMALLINT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_batch_id BIGINT,
    misses INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_node_presence_tier_misses ON node_presence (tier, misses, last_seen_at DESC);

-- 回填：当前各生效批次里的节点视为“本次同步可见”
INSERT INTO node_presence (node_uri, tier, last_seen_at, last_seen_batch_id, misses)
SELECT uri_text, b.tier, now(), b.id, 0
FROM node_batches b, LATERAL jsonb_array_elements_text(b.nodes) AS uri_text
WHERE b.is_active = TRUE
ON CONFLICT (node_uri) DO NOTHING;

-- teleapi 纯净度缓存：按解析出的 IP 存，分数变化慢，7 天复查一次
CREATE TABLE IF NOT EXISTS ip_purity (
    ip TEXT PRIMARY KEY,
    coefficient INT NOT NULL,
    band TEXT NOT NULL,
    ip_type TEXT,
    verdict TEXT,
    raw JSONB NOT NULL DEFAULT '{}'::jsonb,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 节点端点 → 解析出的 IP（后台纯净度刷新器维护，列表页据此 join 纯净度）
CREATE TABLE IF NOT EXISTS node_ip (
    endpoint TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
