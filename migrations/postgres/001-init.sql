-- persea core schema — PostgreSQL backend (SQLx pool).
--
-- Mirrors the schema created by src/db.rs::init_db so the SQLx pool can
-- serve as the real store when `db_url` is set. Timestamps are TEXT in the
-- SQLite format 'YYYY-MM-DD HH24:MI:SS' so string comparisons behave the
-- same on every backend.

CREATE TABLE IF NOT EXISTS admins (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    api_key_hash  TEXT NOT NULL,
    allowed_ips   TEXT,
    expires_at    TEXT,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    last_used_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_admin_api_key_hash ON admins(api_key_hash);

CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    username      TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    oidc_subject  TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer',
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    last_login_at TEXT,
    oidc_groups   TEXT NOT NULL DEFAULT '',
    password_hash TEXT,
    auth_source   TEXT NOT NULL DEFAULT 'database'
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_role_mappings (
    id         BIGSERIAL PRIMARY KEY,
    oidc_group TEXT NOT NULL UNIQUE,
    role       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS seen_groups (
    name       TEXT PRIMARY KEY,
    first_seen TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    last_seen  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS user_api_tokens (
    id            BIGSERIAL PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    max_role      TEXT,
    expires_at    TEXT,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    last_used_at  TEXT,
    UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_admin_token_hash ON user_api_tokens(token_hash);

CREATE TABLE IF NOT EXISTS token_audit_log (
    id         BIGSERIAL PRIMARY KEY,
    token_id   BIGINT,
    token_name TEXT,
    user_email TEXT NOT NULL,
    action     TEXT NOT NULL,
    ip_addr    TEXT,
    details    TEXT,
    created_at TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS session_history (
    id                  BIGSERIAL PRIMARY KEY,
    session_id          TEXT NOT NULL,
    session_type        TEXT NOT NULL,
    hostname            TEXT NOT NULL,
    port                BIGINT,
    username            TEXT NOT NULL DEFAULT '',
    created_by          TEXT NOT NULL,
    address_book_entry  TEXT,
    address_book_folder TEXT,
    entry_display_name  TEXT,
    started_at          TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    ended_at            TEXT,
    duration_secs       BIGINT,
    recording_file      TEXT,
    status              TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_sh_created_by ON session_history(created_by);
CREATE INDEX IF NOT EXISTS idx_sh_entry ON session_history(address_book_entry);
CREATE INDEX IF NOT EXISTS idx_sh_started ON session_history(started_at);

CREATE TABLE IF NOT EXISTS addressbook_audit_log (
    id          BIGSERIAL PRIMARY KEY,
    user_email  TEXT NOT NULL,
    action      TEXT NOT NULL,
    scope       TEXT NOT NULL,
    folder_path TEXT NOT NULL,
    entry_name  TEXT,
    ip_addr     TEXT,
    details     TEXT,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);
CREATE INDEX IF NOT EXISTS idx_ab_audit_created ON addressbook_audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ab_audit_user ON addressbook_audit_log(user_email);

CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGSERIAL PRIMARY KEY,
    event_type      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    user_id         TEXT,
    source_ip       TEXT,
    outcome         TEXT NOT NULL,
    details         TEXT,
    session_id      TEXT,
    prev_hash       TEXT NOT NULL,
    event_hash      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
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
    port        BIGINT NOT NULL DEFAULT 22,
    username    TEXT NOT NULL,
    auth_method TEXT NOT NULL DEFAULT 'password',
    key_path    TEXT,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS auth_pending_mfa (
    token_hash    TEXT PRIMARY KEY,
    user_id       BIGINT NOT NULL REFERENCES users(id),
    user_email    TEXT NOT NULL,
    user_name     TEXT NOT NULL DEFAULT '',
    user_role     TEXT NOT NULL DEFAULT 'viewer',
    oidc_subject  TEXT,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id       BIGINT PRIMARY KEY REFERENCES users(id),
    secret_b32    TEXT NOT NULL,
    algorithm     TEXT NOT NULL DEFAULT 'SHA1',
    digits        BIGINT NOT NULL DEFAULT 6,
    period        BIGINT NOT NULL DEFAULT 30,
    enabled       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id           BIGSERIAL PRIMARY KEY,
    username     TEXT NOT NULL,
    ip_address   TEXT NOT NULL,
    attempted_at TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    success      BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_failed_login_username ON failed_login_attempts(username);
CREATE INDEX IF NOT EXISTS idx_failed_login_ip ON failed_login_attempts(ip_address);

CREATE TABLE IF NOT EXISTS user_preset_credentials (
    user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username    TEXT NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS login_credentials (
    user_id     BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
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
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);

CREATE TABLE IF NOT EXISTS rbac_user_groups (
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    PRIMARY KEY (user_id, group_id)
);

CREATE TABLE IF NOT EXISTS rbac_permissions (
    id            BIGSERIAL PRIMARY KEY,
    entity_id     TEXT NOT NULL,
    entity_type   TEXT NOT NULL CHECK(entity_type IN ('user', 'group')),
    object_type   TEXT NOT NULL CHECK(object_type IN ('connection', 'connection_group')),
    object_id     TEXT NOT NULL,
    permission    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(entity_id, entity_type, object_type, object_id, permission)
);
CREATE INDEX IF NOT EXISTS idx_rbac_perm_entity ON rbac_permissions(entity_id, entity_type);
CREATE INDEX IF NOT EXISTS idx_rbac_perm_object ON rbac_permissions(object_type, object_id);

-- Vault→DB migration target (db-migrate-from-vault user credential variables).
CREATE TABLE IF NOT EXISTS user_credentials (
    user_key    TEXT NOT NULL,
    var_name    TEXT NOT NULL,
    var_value   TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    PRIMARY KEY (user_key, var_name)
);
