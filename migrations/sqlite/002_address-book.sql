-- Address book tables for DB-backed storage — SQLite backend.
-- Mirrors src/db.rs::init_db (includes the folder-ACL columns added by
-- tickets 022/027 so all three backends stay in sync).

CREATE TABLE IF NOT EXISTS address_book_folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scope       TEXT NOT NULL DEFAULT 'shared',
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    allowed_groups TEXT NOT NULL DEFAULT '',
    inherit_from_parent INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scope, name)
);

CREATE TABLE IF NOT EXISTS address_book_entries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id       INTEGER NOT NULL REFERENCES address_book_folders(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    display_name    TEXT DEFAULT '',
    protocol        TEXT NOT NULL,
    hostname        TEXT NOT NULL,
    port            INTEGER,
    username        TEXT DEFAULT '',
    protocol_config TEXT DEFAULT '{}',
    allowed_groups  TEXT DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(folder_id, name)
);

CREATE TABLE IF NOT EXISTS address_book_credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id        INTEGER NOT NULL REFERENCES address_book_entries(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,
    credential_data TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(entry_id, credential_type)
);

CREATE INDEX IF NOT EXISTS idx_ab_entries_folder ON address_book_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_ab_creds_entry ON address_book_credentials(entry_id);
