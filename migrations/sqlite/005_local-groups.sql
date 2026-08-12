-- Local groups + provider-group mappings (ticket #029) — SQLite backend.
-- Mirrors src/db.rs::init_db. `auto_provisioned` (ticket F38) is folded in
-- here so the three backends stay in sync.

CREATE TABLE IF NOT EXISTS local_groups (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL UNIQUE,
    description      TEXT NOT NULL DEFAULT '',
    auto_provisioned INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS group_mappings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id       INTEGER NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
    provider_group TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
