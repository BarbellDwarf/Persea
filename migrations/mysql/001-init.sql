-- rustguac multi-auth schema v1
-- MySQL backend

-- Unified users table across all auth sources
CREATE TABLE IF NOT EXISTS users (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    username        VARCHAR(255) NOT NULL UNIQUE,
    email           VARCHAR(255),
    display_name    VARCHAR(255) NOT NULL DEFAULT '',
    auth_source     VARCHAR(32) NOT NULL,       -- 'oidc', 'ldap', 'database', 'saml', 'radius', 'api_key'
    external_id     VARCHAR(255),               -- provider-specific ID
    password_hash   VARCHAR(255),               -- Argon2id PHC string (NULL for SSO-only users)
    totp_secret     LONGBLOB,                  -- encrypted TOTP secret (NULL if not enrolled)
    disabled        TINYINT(1) NOT NULL DEFAULT 0,
    expired         TINYINT(1) NOT NULL DEFAULT 0,
    expiry_date     VARCHAR(32),                -- ISO 8601
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until    VARCHAR(32),                -- ISO 8601, NULL if not locked
    can_change_password TINYINT(1) NOT NULL DEFAULT 1,
    oidc_groups     TEXT NOT NULL,              -- comma-separated groups from last login
    role            VARCHAR(16) NOT NULL DEFAULT 'viewer',
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    last_login_at   VARCHAR(32),
    metadata        TEXT NOT NULL               -- JSON blob for provider-specific attrs
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_auth_source ON users(auth_source, external_id);

-- Connection groups (hierarchical, organizational)
CREATE TABLE IF NOT EXISTS connection_groups (
    id          VARCHAR(36) PRIMARY KEY,        -- UUIDv7
    name        VARCHAR(255) NOT NULL,
    parent_id   VARCHAR(36),
    description TEXT NOT NULL,
    scope       VARCHAR(64) NOT NULL DEFAULT 'shared',
    created_at  VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    updated_at  VARCHAR(32),
    UNIQUE KEY uk_cg_name_parent (name, parent_id),
    FOREIGN KEY (parent_id) REFERENCES connection_groups(id) ON DELETE SET NULL
);

-- Connections with JSON params
CREATE TABLE IF NOT EXISTS connections (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    name            VARCHAR(255) NOT NULL,
    group_id        VARCHAR(36),
    protocol        VARCHAR(16) NOT NULL,
    params          TEXT NOT NULL,              -- JSON: hostname, port, protocol-specific params
    display_name    VARCHAR(255) NOT NULL DEFAULT '',
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    updated_at      VARCHAR(32),
    INDEX idx_conn_group (group_id),
    INDEX idx_conn_protocol (protocol),
    FOREIGN KEY (group_id) REFERENCES connection_groups(id) ON DELETE SET NULL
);

-- Connection permissions (per user or group)
CREATE TABLE IF NOT EXISTS connection_permissions (
    entity_id       VARCHAR(36) NOT NULL,
    connection_id   VARCHAR(36) NOT NULL,
    permission      VARCHAR(32) NOT NULL,
    PRIMARY KEY (entity_id, connection_id, permission),
    FOREIGN KEY (connection_id) REFERENCES connections(id) ON DELETE CASCADE
);

-- Connection group permissions
CREATE TABLE IF NOT EXISTS connection_group_permissions (
    entity_id       VARCHAR(36) NOT NULL,
    group_id        VARCHAR(36) NOT NULL,
    permission      VARCHAR(32) NOT NULL,
    PRIMARY KEY (entity_id, group_id, permission),
    FOREIGN KEY (group_id) REFERENCES connection_groups(id) ON DELETE CASCADE
);

-- TOTP secrets (multiple per user for phone + hardware token)
CREATE TABLE IF NOT EXISTS totp_secrets (
    id          VARCHAR(36) PRIMARY KEY,        -- UUIDv7
    user_id     VARCHAR(36) NOT NULL,
    label       VARCHAR(255) NOT NULL DEFAULT '',
    secret      LONGBLOB NOT NULL,             -- raw TOTP secret bytes
    algorithm   VARCHAR(8) NOT NULL DEFAULT 'SHA1',
    digits      INT NOT NULL DEFAULT 6,
    period      INT NOT NULL DEFAULT 30,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    created_at  VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    last_used_at VARCHAR(32),
    INDEX idx_ts_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Recovery codes (one-time use, SHA-256 hashed)
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          VARCHAR(36) PRIMARY KEY,        -- UUIDv7
    user_id     VARCHAR(36) NOT NULL,
    code_hash   VARCHAR(64) NOT NULL,           -- hex SHA-256 of plaintext code
    used_at     VARCHAR(32),
    created_at  VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    INDEX idx_rc_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Password history (prevent reuse)
CREATE TABLE IF NOT EXISTS password_history (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    user_id         VARCHAR(36) NOT NULL,
    password_hash   VARCHAR(255) NOT NULL,      -- Argon2id PHC string
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    INDEX idx_ph_user (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Auth sessions (bridging primary auth → TOTP verification)
CREATE TABLE IF NOT EXISTS auth_pending_mfa (
    token           VARCHAR(64) PRIMARY KEY,    -- random token set as cookie
    user_id         VARCHAR(36) NOT NULL,
    display_name    VARCHAR(255) NOT NULL,
    groups_json     TEXT NOT NULL,
    role            VARCHAR(16),
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    expires_at      VARCHAR(32) NOT NULL        -- ISO 8601, short TTL (5 min)
);

-- Auth provider configuration (Tier 1 config, managed via admin UI)
CREATE TABLE IF NOT EXISTS auth_providers (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    provider_type   VARCHAR(32) NOT NULL,
    name            VARCHAR(255) NOT NULL,
    enabled         TINYINT(1) NOT NULL DEFAULT 1,
    priority        INT NOT NULL DEFAULT 0,
    config          TEXT NOT NULL,              -- JSON: provider-specific settings
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    updated_at      VARCHAR(32)
);

-- Group mappings (external groups → rustguac roles)
CREATE TABLE IF NOT EXISTS group_mappings (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    auth_source     VARCHAR(32) NOT NULL,
    source_group    VARCHAR(255) NOT NULL,
    target_role     VARCHAR(16) NOT NULL,
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    UNIQUE KEY uk_gm_source (auth_source, source_group)
);

-- Session history (metadata persisted for audit trail)
CREATE TABLE IF NOT EXISTS session_history (
    id              VARCHAR(36) PRIMARY KEY,    -- UUIDv7
    user_id         VARCHAR(36),
    protocol        VARCHAR(16) NOT NULL,
    source_ip       VARCHAR(45),
    target_host     VARCHAR(255),
    started_at      VARCHAR(32) NOT NULL,
    ended_at        VARCHAR(32),
    duration_secs   INT,
    status          VARCHAR(32) NOT NULL DEFAULT 'active',
    recording_path  VARCHAR(512),
    terminated_reason VARCHAR(255),
    user_agent      VARCHAR(255),
    INDEX idx_sh_user (user_id),
    INDEX idx_sh_started (started_at)
);

-- Audit events with hash chain for tamper evidence
CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    timestamp       VARCHAR(32) NOT NULL,
    user_id         VARCHAR(36),
    source_ip       VARCHAR(45),
    outcome         VARCHAR(16) NOT NULL,
    details         TEXT,                       -- JSON blob
    session_id      VARCHAR(36),
    prev_hash       CHAR(64) NOT NULL,          -- hex SHA-256 of previous event
    event_hash      CHAR(64) NOT NULL,          -- hex SHA-256 of this event
    created_at      VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP()),
    INDEX idx_ae_timestamp (timestamp),
    INDEX idx_ae_user (user_id),
    INDEX idx_ae_event_type (event_type)
);

-- Audit chain metadata
CREATE TABLE IF NOT EXISTS audit_meta (
    key     VARCHAR(64) PRIMARY KEY,
    value   TEXT NOT NULL
);

-- Feature flags (admin-toggleable optional features)
CREATE TABLE IF NOT EXISTS feature_flags (
    name        VARCHAR(64) PRIMARY KEY,
    enabled     TINYINT(1) NOT NULL DEFAULT 0,
    updated_at  VARCHAR(32)
);
