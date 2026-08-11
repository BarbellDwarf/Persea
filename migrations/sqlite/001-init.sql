-- persea core schema — SQLite backend (SQLx pool variant).
--
-- Mirrors the schema created by src/db.rs::init_db so the SQLx pool can
-- serve as the real store when `db_url` is set. The legacy rusqlite file
-- keeps its own inline DDL; this migration covers the SQLx pool path only.

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL UNIQUE,
    api_key_hash  TEXT NOT NULL,
    allowed_ips   TEXT,
    expires_at    TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at  TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    oidc_subject  TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer',
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT,
    oidc_groups   TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    auth_source   TEXT NOT NULL DEFAULT 'database'
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_role_mappings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    oidc_group TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS seen_groups (
    name       TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS user_api_tokens (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    max_role      TEXT,
    expires_at    TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at  TEXT,
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS token_audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id   INTEGER,
    token_name TEXT,
    user_email TEXT NOT NULL,
    action     TEXT NOT NULL,
    ip_addr    TEXT,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_history (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT NOT NULL,
    session_type        TEXT NOT NULL,
    hostname            TEXT NOT NULL,
    port                INTEGER,
    username            TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL,
    address_book_entry  TEXT,
    address_book_folder TEXT,
    entry_display_name  TEXT,
    started_at          TEXT NOT NULL DEFAULT (datetime('now')),
    ended_at            TEXT,
    duration_secs       INTEGER,
    recording_file      TEXT,
    status              TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_sh_created_by ON session_history(created_by);
CREATE INDEX IF NOT EXISTS idx_sh_entry ON session_history(address_book_entry);
CREATE INDEX IF NOT EXISTS idx_sh_started ON session_history(started_at);

CREATE TABLE IF NOT EXISTS addressbook_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email  TEXT NOT NULL,
    action      TEXT NOT NULL,
    scope       TEXT NOT NULL,
    folder_path TEXT NOT NULL,
    entry_name  TEXT,
    ip_addr     TEXT,
    details     TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ab_audit_created ON addressbook_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ab_audit_user ON addressbook_audit_log(user_email);

CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    user_id         TEXT,
    source_ip       TEXT,
    outcome         TEXT NOT NULL,
    details         TEXT,
    session_id      TEXT,
    prev_hash       TEXT NOT NULL,
    event_hash      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS audit_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jump_hosts (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    hostname    TEXT NOT NULL,
    port        INTEGER NOT NULL DEFAULT 22,
    username    TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'password',
    key_path    TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS auth_pending_mfa (
    token_hash    TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    user_email    TEXT NOT NULL,
    user_name     TEXT NOT NULL DEFAULT '',
    user_role     TEXT NOT NULL DEFAULT 'viewer',
    oidc_subject  TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id       INTEGER PRIMARY KEY REFERENCES users(id),
    secret_b32    TEXT NOT NULL,
    algorithm     TEXT NOT NULL DEFAULT 'SHA1',
    digits        INTEGER NOT NULL DEFAULT 6,
    period        INTEGER NOT NULL DEFAULT 30,
    enabled       INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    username    TEXT NOT NULL,
    ip_address  TEXT NOT NULL,
    attempted_at TEXT DEFAULT (datetime('now')),
    success     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_failed_login_username ON failed_login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_failed_login_ip ON failed_login_attempts(ip_address);

CREATE TABLE IF NOT EXISTS user_preset_credentials (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS login_credentials (
    user_id     INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT '',
    expires_at  TEXT NOT NULL
);

-- RBAC (connection groups, user-group membership, permissions) — mirrors
-- src/rbac.rs::migrate.
CREATE TABLE IF NOT EXISTS rbac_groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    parent_id   TEXT REFERENCES rbac_groups(id),
    description TEXT,
    scope       TEXT NOT NULL DEFAULT 'shared',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rbac_user_groups (
    user_id     INTEGER NOT NULL REFERENCES users(id),
    group_id    TEXT NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS rbac_permissions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL CHECK(entity_type IN ('user', 'group')),
    object_type   TEXT NOT NULL CHECK(object_type IN ('connection', 'connection_group')),
    object_id     TEXT NOT NULL,
    permission    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(entity_id, entity_type, object_type, object_id, permission)
);
CREATE INDEX IF NOT EXISTS idx_rbac_perm_entity ON rbac_permissions(entity_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_rbac_perm_object ON rbac_permissions(object_type, object_id);

-- Vault→DB migration target (db-migrate-from-vault user credential variables).
CREATE TABLE IF NOT EXISTS user_credentials (
    user_key    TEXT NOT NULL,
    var_name    TEXT NOT NULL,
    var_value   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_key, var_name)
);
