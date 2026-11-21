-- Tier-2 relay session metering (migration 0007).
-- One row per relayed connection, written on close (spawned, never blocking).
-- Monthly quota needs 30 days of history; the relay prunes rows older than 40 days.
CREATE TABLE IF NOT EXISTS relay_sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_index INT NOT NULL,
    client_ip TEXT,
    bytes_up BIGINT NOT NULL DEFAULT 0,
    bytes_down BIGINT NOT NULL DEFAULT 0,
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at TIMESTAMPTZ,
    outcome TEXT
);
CREATE INDEX IF NOT EXISTS relay_sessions_user_started_idx ON relay_sessions (user_id, started_at);
CREATE INDEX IF NOT EXISTS relay_sessions_user_node_idx ON relay_sessions (user_id, node_index);
