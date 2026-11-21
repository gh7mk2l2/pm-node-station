-- 一级多上游同步（migration 0008）。
-- tier1_upstreams：一级全部上游（URL 只存这一张表，绝不写进代码、订阅输出、前端或报错）。
--   url_template 可含 {YYYY}/{MM}/{DD} 日期占位（按上海日期现拼，如 yoyapai 的日更文件）。
--   format：clash / base64 / json_scdn / json_geonode / json_fineproxy /
--           txt_proxora / html_proxyhub / html_remproxy。
--   kind：public（公共免费源，可并入）/ token（token 订阅，凭证即限量池入口，
--         默认 disabled，只进配置不等许可绝不并入）。
--   last_sync_at / last_nodes / last_error：每次同步后由同步流程回写（只记标签与数量，
--         绝不记 URL）。
-- openvpn_configs：一级批次里 OpenVPN 节点的 .ovpn 配置（改名后节点名 → 配置 base64），
--   与三级的 vpngate_configs 同构、按分级分表；订阅下发时走同一转换路径。

CREATE TABLE IF NOT EXISTS tier1_upstreams (
    id BIGSERIAL PRIMARY KEY,
    label TEXT NOT NULL UNIQUE,
    url_template TEXT NOT NULL,
    format TEXT NOT NULL CHECK (format IN (
        'clash', 'base64', 'json_scdn', 'json_geonode', 'json_fineproxy',
        'txt_proxora', 'html_proxyhub', 'html_remproxy'
    )),
    kind TEXT NOT NULL DEFAULT 'public' CHECK (kind IN ('public', 'token')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_sync_at TIMESTAMPTZ,
    last_nodes INT NOT NULL DEFAULT 0,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS tier1_upstreams_enabled_idx ON tier1_upstreams (enabled);

CREATE TABLE IF NOT EXISTS openvpn_configs (
    batch_id BIGINT NOT NULL REFERENCES node_batches (id) ON DELETE CASCADE,
    node_name TEXT NOT NULL,
    config_b64 TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (batch_id, node_name)
);

-- 一级含 OpenVPN 节点：订阅页须提示客户端版本（与三级同一要求）
UPDATE node_tiers
SET description = '机房 IP 组 · 不限流 · 不反分发 · 含 OpenVPN 节点，需 mihomo ≥1.19.29 / sing-box ≥1.14'
WHERE tier = 1;
