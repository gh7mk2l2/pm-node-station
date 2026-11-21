-- 订阅拉取记录加分级列，用于二级反分发检测（按分级统计拉取 IP）
ALTER TABLE sub_pulls ADD COLUMN IF NOT EXISTS tier SMALLINT NOT NULL DEFAULT 1;
CREATE INDEX IF NOT EXISTS sub_pulls_user_tier_time_idx ON sub_pulls (user_id, tier, pulled_at DESC);
