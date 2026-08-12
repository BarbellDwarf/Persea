-- persea core schema — MySQL backend (SQLx pool).
--
-- Mirrors the schema created by src/db.rs::init_db so the SQLx pool can
-- serve as the real store when `db_url` is set. Timestamps are VARCHAR in
-- the SQLite format 'YYYY-MM-DD HH:MM:SS' so string comparisons behave the
-- same on every backend. Indexed columns are VARCHAR (MySQL cannot index
-- TEXT without a prefix length); `key`/`role`/`type`/`status` are reserved
-- words and are backtick-quoted.

CREATE TABLE IF NOT EXISTS admins (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(255) NOT NULL UNIQUE,
    api_key_hash  VARCHAR(128) NOT NULL,
    allowed_ips   TEXT,
    expires_at    TEXT,
    disabled      TINYINT(1) NOT NULL DEFAULT 0,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    last_used_at  TEXT
);
CREATE INDEX idx_admin_api_key_hash ON admins(api_key_hash);

CREATE TABLE IF NOT EXISTS users (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    username      VARCHAR(255) NOT NULL DEFAULT '',
    name          VARCHAR(255) NOT NULL DEFAULT '',
    oidc_subject  VARCHAR(512),
    `role`        VARCHAR(32) NOT NULL DEFAULT 'viewer',
    disabled      TINYINT(1) NOT NULL DEFAULT 0,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    last_login_at TEXT,
    oidc_groups   TEXT NOT NULL DEFAULT (''),
    password_hash TEXT,
    auth_source   VARCHAR(32) NOT NULL DEFAULT 'database'
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    token_hash    VARCHAR(64) PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    expires_at    VARCHAR(64) NOT NULL,
    CONSTRAINT fk_auth_sessions_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS group_role_mappings (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    oidc_group VARCHAR(255) NOT NULL UNIQUE,
    `role`     VARCHAR(32) NOT NULL,
    created_at VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE TABLE IF NOT EXISTS seen_groups (
    name       VARCHAR(255) PRIMARY KEY,
    first_seen VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    last_seen  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE TABLE IF NOT EXISTS user_api_tokens (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    name          VARCHAR(255) NOT NULL,
    token_hash    VARCHAR(64) NOT NULL UNIQUE,
    max_role      VARCHAR(32),
    expires_at    TEXT,
    disabled      TINYINT(1) NOT NULL DEFAULT 0,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    last_used_at  TEXT,
    UNIQUE KEY uq_token_user_name (user_id, name),
    CONSTRAINT fk_user_tokens_user FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX idx_admin_token_hash ON user_api_tokens(token_hash);

CREATE TABLE IF NOT EXISTS token_audit_log (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    token_id   BIGINT,
    token_name VARCHAR(255),
    user_email VARCHAR(512) NOT NULL,
    action     VARCHAR(64) NOT NULL,
    ip_addr    VARCHAR(64),
    details    TEXT,
    created_at VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE TABLE IF NOT EXISTS session_history (
    id                  BIGINT AUTO_INCREMENT PRIMARY KEY,
    session_id          VARCHAR(64) NOT NULL,
    session_type        VARCHAR(32) NOT NULL,
    hostname            VARCHAR(512) NOT NULL,
    port                BIGINT,
    username            VARCHAR(512) NOT NULL DEFAULT '',
    created_by          VARCHAR(512) NOT NULL,
    address_book_entry  VARCHAR(512),
    address_book_folder VARCHAR(512),
    entry_display_name  VARCHAR(512),
    started_at          VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    ended_at            VARCHAR(64),
    duration_secs       BIGINT,
    recording_file      VARCHAR(512),
    `status`            VARCHAR(16) NOT NULL DEFAULT 'active'
);
CREATE INDEX idx_sh_created_by ON session_history(created_by);
CREATE INDEX idx_sh_entry ON session_history(address_book_entry);
CREATE INDEX idx_sh_started ON session_history(started_at);

CREATE TABLE IF NOT EXISTS addressbook_audit_log (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_email  VARCHAR(512) NOT NULL,
    action      VARCHAR(64) NOT NULL,
    scope       VARCHAR(64) NOT NULL,
    folder_path VARCHAR(512) NOT NULL,
    entry_name  VARCHAR(512),
    ip_addr     VARCHAR(64),
    details     TEXT,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);
CREATE INDEX idx_ab_audit_created ON addressbook_audit_log(created_at);
CREATE INDEX idx_ab_audit_user ON addressbook_audit_log(user_email);

CREATE TABLE IF NOT EXISTS audit_events (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    `timestamp`     VARCHAR(40) NOT NULL,
    user_id         VARCHAR(512),
    source_ip       VARCHAR(64),
    outcome         VARCHAR(32) NOT NULL,
    details         TEXT,
    session_id      VARCHAR(64),
    prev_hash       VARCHAR(64) NOT NULL,
    event_hash      VARCHAR(64) NOT NULL,
    created_at      VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);
CREATE INDEX idx_audit_timestamp ON audit_events(`timestamp`);
CREATE INDEX idx_audit_user ON audit_events(user_id);
CREATE INDEX idx_audit_event_type ON audit_events(event_type);

CREATE TABLE IF NOT EXISTS audit_meta (
    `key`   VARCHAR(64) PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jump_hosts (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    hostname    VARCHAR(512) NOT NULL,
    port        BIGINT NOT NULL DEFAULT 22,
    username    VARCHAR(512) NOT NULL,
    auth_method VARCHAR(32) NOT NULL DEFAULT 'password',
    key_path    VARCHAR(512),
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    updated_at  VARCHAR(64)
);

CREATE TABLE IF NOT EXISTS auth_pending_mfa (
    token_hash    VARCHAR(64) PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    user_email    VARCHAR(512) NOT NULL,
    user_name     VARCHAR(512) NOT NULL DEFAULT '',
    user_role     VARCHAR(32) NOT NULL DEFAULT 'viewer',
    oidc_subject  VARCHAR(512),
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    expires_at    VARCHAR(64) NOT NULL,
    CONSTRAINT fk_pending_mfa_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS totp_secrets (
    user_id       BIGINT PRIMARY KEY,
    secret_b32    VARCHAR(255) NOT NULL,
    algorithm     VARCHAR(16) NOT NULL DEFAULT 'SHA1',
    digits        BIGINT NOT NULL DEFAULT 6,
    period        BIGINT NOT NULL DEFAULT 30,
    enabled       TINYINT(1) NOT NULL DEFAULT 0,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    CONSTRAINT fk_totp_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS failed_login_attempts (
    id           BIGINT AUTO_INCREMENT PRIMARY KEY,
    username     VARCHAR(512) NOT NULL,
    ip_address   VARCHAR(64) NOT NULL,
    attempted_at VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    success      TINYINT(1) NOT NULL DEFAULT 0
);
CREATE INDEX idx_failed_login_username ON failed_login_attempts(username);
CREATE INDEX idx_failed_login_ip ON failed_login_attempts(ip_address);

CREATE TABLE IF NOT EXISTS user_preset_credentials (
    user_id      BIGINT PRIMARY KEY,
    username     VARCHAR(512) NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT (''),
    updated_at   VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    CONSTRAINT fk_preset_creds_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_credentials (
    user_id      BIGINT PRIMARY KEY,
    username     VARCHAR(512) NOT NULL DEFAULT '',
    password_enc TEXT NOT NULL DEFAULT (''),
    expires_at   VARCHAR(40) NOT NULL,
    CONSTRAINT fk_login_creds_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- RBAC (connection groups, user-group membership, permissions) — mirrors
-- src/rbac.rs::migrate.
CREATE TABLE IF NOT EXISTS rbac_groups (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    parent_id   VARCHAR(64),
    description TEXT,
    scope       VARCHAR(64) NOT NULL DEFAULT 'shared',
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    CONSTRAINT fk_rbac_parent FOREIGN KEY (parent_id) REFERENCES rbac_groups(id)
);

CREATE TABLE IF NOT EXISTS rbac_user_groups (
    user_id     BIGINT NOT NULL,
    group_id    VARCHAR(64) NOT NULL,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    PRIMARY KEY (user_id, group_id),
    CONSTRAINT fk_rug_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_rug_group FOREIGN KEY (group_id) REFERENCES rbac_groups(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rbac_permissions (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    entity_id     VARCHAR(255) NOT NULL,
    entity_type   VARCHAR(16) NOT NULL,
    object_type   VARCHAR(32) NOT NULL,
    object_id     VARCHAR(255) NOT NULL,
    permission    VARCHAR(32) NOT NULL,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_rbac_perm (entity_id, entity_type, object_type, object_id, permission)
);
CREATE INDEX idx_rbac_perm_entity ON rbac_permissions(entity_id, entity_type);
CREATE INDEX idx_rbac_perm_object ON rbac_permissions(object_type, object_id);

-- Vault→DB migration target (db-migrate-from-vault user credential variables).
CREATE TABLE IF NOT EXISTS user_credentials (
    user_key    VARCHAR(255) NOT NULL,
    var_name    VARCHAR(255) NOT NULL,
    var_value   TEXT NOT NULL,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    PRIMARY KEY (user_key, var_name)
);
