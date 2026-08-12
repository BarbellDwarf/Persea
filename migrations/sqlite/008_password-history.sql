-- Password reuse history (R108): last N Argon2id hashes per user.
-- Mirrored in src/password.rs (legacy rusqlite lazy DDL). No foreign key:
-- the legacy rusqlite path creates the same table lazily and must stay
-- schema-identical.

CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id);
