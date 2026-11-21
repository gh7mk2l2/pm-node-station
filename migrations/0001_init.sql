-- PM Node Station 初始结构（公益节点站，免费模式，无付费/订单表）
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    linuxdo_id BIGINT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    trust_level INT NOT NULL DEFAULT 0,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin', 'root')),
    is_banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    sub_token TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
);
-- 站长唯一
CREATE UNIQUE INDEX IF NOT EXISTS users_one_root ON users (role) WHERE role = 'root';
CREATE INDEX IF NOT EXISTS users_username_idx ON users (username);

CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    ip TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

CREATE TABLE IF NOT EXISTS oauth_states (
    id BIGSERIAL PRIMARY KEY,
    state_hash BYTEA NOT NULL,
    bind_hash BYTEA NOT NULL,
    code_verifier TEXT NOT NULL,
    next_path TEXT NOT NULL DEFAULT '/',
 
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS oauth_states_hash_idx ON oauth_states (state_hash);

CREATE TABLE IF NOT EXISTS node_batches (
    id BIGSERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    nodes JSONB NOT NULL DEFAULT '[]'::jsonb,
    batch_date DATE NOT NULL,
    node_count INT NOT NULL DEFAULT 0,
    is_active BOOLEAN NOT NULL DEFAULT FALSE,
    source TEXT NOT NULL DEFAULT 'manual',
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS node_batches_active_idx ON node_batches (is_active, created_at DESC);

CREATE TABLE IF NOT EXISTS announcements (
    id BIGSERIAL PRIMARY KEY,
    content TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info', 'warning', 'alert')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_by BIGINT REFERENCES users (id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS announcements_active_idx ON announcements (is_active, created_at DESC);

CREATE TABLE IF NOT EXISTS socks_pool (
    id BIGSERIAL PRIMARY KEY,
    host TEXT NOT NULL,
    port INT NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'socks5' CHECK (protocol IN ('socks5', 'http', 'https')),
    username TEXT NOT NULL DEFAULT '',
    password TEXT NOT NULL DEFAULT '',
    line TEXT NOT NULL,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    country TEXT,
    region TEXT,
    provider TEXT,
    risk_score INT,
    identity_hash TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'untested' CHECK (status IN ('untested', 'ok', 'fail')),
    latency_ms INT,
    last_checked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS socks_pool_identity_uq ON socks_pool (identity_hash);
CREATE INDEX IF NOT EXISTS socks_pool_status_idx ON socks_pool (status, latency_ms);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users (id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target_type TEXT,
    target TEXT,
    detail JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_logs_created_idx ON audit_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB
);

CREATE TABLE IF NOT EXISTS sub_pulls (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    format TEXT NOT NULL DEFAULT 'base64',
    user_agent TEXT,
    ip TEXT,
    pulled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sub_pulls_user_idx ON sub_pulls (user_id, pulled_at DESC);
CREATE INDEX IF NOT EXISTS sub_pulls_created_idx ON sub_pulls (pulled_at DESC);

CREATE TABLE IF NOT EXISTS node_latency (
    id BIGSERIAL PRIMARY KEY,
    batch_id BIGINT NOT NULL REFERENCES node_batches (id) ON DELETE CASCADE,
    node_uri TEXT NOT NULL,
    latency_ms INT,
    online BOOLEAN NOT NULL DEFAULT FALSE,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS node_latency_batch_idx ON node_latency (batch_id);
