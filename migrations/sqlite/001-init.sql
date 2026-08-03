-- rustguac multi-auth schema v1
-- SQLite backend

-- Unified users table across all auth sources
CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    username        TEXT NOT NULL UNIQUE,
    email           TEXT,
    display_name    TEXT NOT NULL DEFAULT '',
    auth_source     TEXT NOT NULL,              -- 'oidc', 'ldap', 'database', 'saml', 'radius', 'api_key'
    external_id     TEXT,                       -- provider-specific ID (OIDC sub, SAML NameID, LDAP DN)
    password_hash   TEXT,                       -- Argon2id PHC string (NULL for SSO-only users)
    totp_secret     BLOB,                      -- encrypted TOTP secret (NULL if not enrolled)
    disabled        INTEGER NOT NULL DEFAULT 0,
    expired         INTEGER NOT NULL DEFAULT 0,
    expiry_date     TEXT,                       -- ISO 8601
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,                       -- ISO 8601, NULL if not locked
    can_change_password INTEGER NOT NULL DEFAULT 1,  -- 0 for LDAP users
    oidc_groups     TEXT NOT NULL DEFAULT '',   -- comma-separated groups from last login
    role            TEXT NOT NULL DEFAULT 'viewer',  -- admin/poweruser/operator/viewer
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login_at   TEXT,
    metadata        TEXT NOT NULL DEFAULT '{}'  -- JSON blob for provider-specific attrs
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_auth_source ON users(auth_source, external_id);

-- Connection groups (hierarchical, organizational)
CREATE TABLE IF NOT EXISTS connection_groups (
    id          TEXT PRIMARY KEY,               -- UUIDv7
    name        TEXT NOT NULL,
    parent_id   TEXT REFERENCES connection_groups(id) ON DELETE SET NULL,
    description TEXT NOT NULL DEFAULT '',
    scope       TEXT NOT NULL DEFAULT 'shared', -- 'shared' or 'instance/<name>'
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT,
    UNIQUE(name, parent_id)
);

-- Connections with JSON params
CREATE TABLE IF NOT EXISTS connections (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    name            TEXT NOT NULL,
    group_id        TEXT REFERENCES connection_groups(id) ON DELETE SET NULL,
    protocol        TEXT NOT NULL,              -- 'ssh', 'rdp', 'vnc', 'spice', 'proxmox', 'vmware', 'web', 'vdi'
    params          TEXT NOT NULL DEFAULT '{}', -- JSON: hostname, port, protocol-specific params
    display_name    TEXT NOT NULL DEFAULT '',
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT
);
CREATE INDEX IF NOT EXISTS idx_connections_group ON connections(group_id);
CREATE INDEX IF NOT EXISTS idx_connections_protocol ON connections(protocol);

-- Connection permissions (per user or group)
CREATE TABLE IF NOT EXISTS connection_permissions (
    entity_id       TEXT NOT NULL,              -- user UUID or group UUID
    connection_id   TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    permission      TEXT NOT NULL,              -- 'read', 'connect', 'update', 'delete', 'administer'
    PRIMARY KEY (entity_id, connection_id, permission)
);

-- Connection group permissions
CREATE TABLE IF NOT EXISTS connection_group_permissions (
    entity_id       TEXT NOT NULL,              -- user UUID or group UUID
    group_id        TEXT NOT NULL REFERENCES connection_groups(id) ON DELETE CASCADE,
    permission      TEXT NOT NULL,              -- 'read', 'connect', 'update', 'delete', 'administer'
    PRIMARY KEY (entity_id, group_id, permission)
);

-- TOTP secrets (multiple per user for phone + hardware token)
CREATE TABLE IF NOT EXISTS totp_secrets (
    id          TEXT PRIMARY KEY,               -- UUIDv7
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label       TEXT NOT NULL DEFAULT '',        -- "Phone", "Hardware Token", etc.
    secret      BLOB NOT NULL,                  -- raw TOTP secret bytes
    algorithm   TEXT NOT NULL DEFAULT 'SHA1',
    digits      INTEGER NOT NULL DEFAULT 6,
    period      INTEGER NOT NULL DEFAULT 30,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_totp_user ON totp_secrets(user_id);

-- Recovery codes (one-time use, SHA-256 hashed)
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          TEXT PRIMARY KEY,               -- UUIDv7
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash   TEXT NOT NULL,                  -- hex SHA-256 of plaintext code
    used_at     TEXT,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

-- Password history (prevent reuse)
CREATE TABLE IF NOT EXISTS password_history (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,              -- Argon2id PHC string
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_password_history_user ON password_history(user_id);

-- Auth sessions (bridging primary auth → TOTP verification)
CREATE TABLE IF NOT EXISTS auth_pending_mfa (
    token           TEXT PRIMARY KEY,           -- random token set as cookie
    user_id         TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    groups_json     TEXT NOT NULL DEFAULT '[]',
    role            TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at      TEXT NOT NULL               -- ISO 8601, short TTL (5 min)
);

-- Auth provider configuration (Tier 1 config, managed via admin UI)
CREATE TABLE IF NOT EXISTS auth_providers (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    provider_type   TEXT NOT NULL,              -- 'oidc', 'ldap', 'database', 'api_key', 'radius', 'saml', 'totp'
    name            TEXT NOT NULL,              -- display name
    enabled         INTEGER NOT NULL DEFAULT 1,
    priority        INTEGER NOT NULL DEFAULT 0, -- lower = higher priority
    config          TEXT NOT NULL DEFAULT '{}', -- JSON: provider-specific settings
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT
);

-- Group mappings (external groups → rustguac roles)
CREATE TABLE IF NOT EXISTS group_mappings (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    auth_source     TEXT NOT NULL,              -- 'oidc', 'ldap', 'saml'
    source_group    TEXT NOT NULL,              -- external group name/DN
    target_role     TEXT NOT NULL,              -- rustguac role
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(auth_source, source_group)
);

-- Session history (metadata persisted for audit trail)
CREATE TABLE IF NOT EXISTS session_history (
    id              TEXT PRIMARY KEY,           -- UUIDv7
    user_id         TEXT,
    protocol        TEXT NOT NULL,
    source_ip       TEXT,
    target_host     TEXT,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    duration_secs   INTEGER,
    status          TEXT NOT NULL DEFAULT 'active', -- 'active', 'completed', 'error', 'idle_timeout', 'max_duration'
    recording_path  TEXT,
    terminated_reason TEXT,
    user_agent      TEXT
);
CREATE INDEX IF NOT EXISTS idx_session_history_user ON session_history(user_id);
CREATE INDEX IF NOT EXISTS idx_session_history_started ON session_history(started_at);

-- Audit events with hash chain for tamper evidence
CREATE TABLE IF NOT EXISTS audit_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    user_id         TEXT,
    source_ip       TEXT,
    outcome         TEXT NOT NULL,              -- 'success', 'failure', 'error', 'info'
    details         TEXT,                       -- JSON blob
    session_id      TEXT,
    prev_hash       TEXT NOT NULL,              -- hex SHA-256 of previous event
    event_hash      TEXT NOT NULL,              -- hex SHA-256 of this event
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);

-- Audit chain metadata
CREATE TABLE IF NOT EXISTS audit_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

-- Feature flags (admin-toggleable optional features)
CREATE TABLE IF NOT EXISTS feature_flags (
    name        TEXT PRIMARY KEY,
    enabled     INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT
);
