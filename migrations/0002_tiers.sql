-- 节点分级：一级机房 IP（不限流、不反分发）、二级住宅 IP（限流 5G/天、50G/月、反分发）
CREATE TABLE IF NOT EXISTS node_tiers (
    tier SMALLINT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    ip_type TEXT NOT NULL DEFAULT '',
    rate_limited BOOLEAN NOT NULL DEFAULT FALSE,
    anti_redistribution BOOLEAN NOT NULL DEFAULT FALSE,
    daily_limit_gb INT,
    monthly_limit_gb INT,
    sort_order SMALLINT NOT NULL DEFAULT 0
);

INSERT INTO node_tiers (tier, name, description, ip_type, rate_limited, anti_redistribution, daily_limit_gb, monthly_limit_gb, sort_order) VALUES
    (1, '一级 · 机房 IP', '机房 IP 组 · 不限流 · 不反分发', 'datacenter', FALSE, FALSE, NULL, NULL, 1),
    (2, '二级 · 住宅 IP', '住宅 IP 组 · 限流 5G/天 · 50G/月 · 反分发', 'residential', TRUE, TRUE, 5, 50, 2)
ON CONFLICT (tier) DO NOTHING;

ALTER TABLE node_batches ADD COLUMN IF NOT EXISTS tier SMALLINT NOT NULL DEFAULT 1;
CREATE UNIQUE INDEX IF NOT EXISTS node_batches_one_active_per_tier ON node_batches (tier) WHERE is_active;
