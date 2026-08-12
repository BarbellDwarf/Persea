-- Address book tables for DB-backed storage — PostgreSQL variant.
-- Mirrors src/db.rs::init_db (includes the folder-ACL columns added by
-- tickets 022/027 so all three backends stay in sync).

CREATE TABLE IF NOT EXISTS address_book_folders (
    id          BIGSERIAL PRIMARY KEY,
    scope       TEXT NOT NULL DEFAULT 'shared',
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    allowed_groups TEXT NOT NULL DEFAULT '',
    inherit_from_parent BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    updated_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(scope, name)
);

CREATE TABLE IF NOT EXISTS address_book_entries (
    id              BIGSERIAL PRIMARY KEY,
    folder_id       BIGINT NOT NULL REFERENCES address_book_folders(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    display_name    TEXT DEFAULT '',
    protocol        TEXT NOT NULL,
    hostname        TEXT NOT NULL,
    port            BIGINT,
    username        TEXT DEFAULT '',
    protocol_config TEXT DEFAULT '{}',
    allowed_groups  TEXT DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    updated_at      TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(folder_id, name)
);

CREATE TABLE IF NOT EXISTS address_book_credentials (
    id              BIGSERIAL PRIMARY KEY,
    entry_id        BIGINT NOT NULL REFERENCES address_book_entries(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,
    credential_data TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    updated_at      TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(entry_id, credential_type)
);

CREATE INDEX IF NOT EXISTS idx_ab_entries_folder ON address_book_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_ab_creds_entry ON address_book_credentials(entry_id);
