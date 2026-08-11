-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- SQLite backend. Mirrors src/providers_db.rs::migrate.

CREATE TABLE IF NOT EXISTS auth_providers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL DEFAULT 0,
    config     TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_name ON auth_providers(name);
