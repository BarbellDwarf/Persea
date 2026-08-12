-- Password reuse history (R108): last N Argon2id hashes per user.
-- Mirrored in src/password.rs (legacy rusqlite lazy DDL) with the SQLite
-- timestamp format 'YYYY-MM-DD HH24:MI:SS'.

CREATE TABLE IF NOT EXISTS password_history (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id);
