# Auth Database Schema Research

wayfinder:research
Blocked by: 001 (Multi-DB Backend), 002 (Auth Provider Architecture)

## Current State

persea has 8 SQLite tables: `admins`, `users`, `auth_sessions`, `group_role_mappings`, `seen_groups`, `user_api_tokens`, `token_audit_log`, `session_history`, `addressbook_audit_log`. Connections live in Vault KV v2.

## Apache Guacamole Schema Analysis

Guacamole's JDBC auth module uses **23 tables** across MySQL/PostgreSQL/SQLite. Here's what's essential vs. what persea can skip:

### Essential from Guacamole (adapted)

| Guacamole Table | persea Equivalent | Notes |
|---|---|---|
| `guacamole_connection_group` | `connection_groups` | Hierarchical, types: ORGANIZATIONAL/BALANCING |
| `guacamole_connection` | `connections` | Protocol + parent group |
| `guacamole_connection_parameter` | `connection_params` | Name/value pairs OR JSON blob (see decision below) |
| `guacamole_entity` | `users` (unified) | Guacamole uses entity→user split; persea simplifies |
| `guacamole_user` | `users` | Password hash, salt, disabled/expired, access windows |
| `guacamole_user_password_history` | `password_history` | For password reuse prevention |
| `guacamole_connection_permission` | `connection_permissions` | READ/UPDATE/DELETE/ADMINISTER per entity |
| `guacamole_connection_group_permission` | `connection_group_permissions` | Same pattern |
| `guacamole_connection_history` | `session_history` | Already exists, enhanced |
| `guacamole_user_history` | `auth_history` | Login/logout tracking |

### Skipped from Guacamole (not needed)

| Table | Why Skip |
|---|---|
| `guacamole_user_group` / `guacamole_user_group_member` | Overkill — persea uses flat group membership from auth providers |
| `guacamole_sharing_profile*` | No sharing profile feature planned |
| `guacamole_*_attribute` (5 tables) | Extension attributes — use JSON columns instead |
| `guacamole_system_permission` | Role hierarchy replaces fine-grained system perms |
| `guacamole_user_permission` / `guacamole_user_group_permission` | No user-to-user permission model |

### persea-specific tables (not in Guacamole)

| Table | Purpose |
|---|---|
| `auth_sessions` | Web session tokens (cookie-based) |
| `auth_pending_mfa` | Two-phase MFA bridging |
| `user_api_tokens` | API key management |
| `group_mappings` | External groups → persea roles |
| `audit_events` | Hash-chain tamper-evident audit log |
| `feature_flags` | Runtime feature toggles |
| `auth_providers` | Auth source configuration (LDAP, SAML, OIDC, DB, RADIUS) |
| `user_totp` | TOTP secrets (local regardless of auth source) |

---

## Design Decisions

### Decision 1: Connection Parameters — JSON vs Normalized

**Guacamole approach**: Separate `connection_parameter` table with name/value rows (one row per param).

**persea approach**: JSON column on `connections` table.

**Rationale**: Guacamole's normalized approach enables SQL-level param queries but adds JOIN complexity. persea never queries by param value — it reads all params to pass to guacd. JSON is simpler, portable (all 3 DBs support JSON columns), and matches the Vault KV model being replaced.

**Trade-off**: Lose ability to find "all connections with hostname=X" via SQL. Acceptable — the admin UI searches by connection name, not param values.

### Decision 2: Entity Model — Simplified vs Guacamole's Entity Split

**Guacamole**: `guacamole_entity` (type+name) → `guacamole_user` (entity_id FK) → permissions reference entity_id. This enables user groups with inherited permissions.

**persea**: Single `users` table with `auth_source` + `external_id`. No user groups in DB — group membership comes from auth providers at login time. Permissions reference `user_id` directly.

**Rationale**: persea doesn't need DB-stored user groups because LDAP/SAML/OIDC provide group membership dynamically. The `group_mappings` table maps external group names → persea roles. This avoids the entity group nesting complexity.

### Decision 3: Password Storage — Argon2id vs bcrypt

**Choice**: Argon2id (via `argon2` crate). NIST SP 800-63B recommends memory-hard functions. All 3 DBs store the hash as `TEXT` (hex-encoded).

**Format**: `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` — standard PHC string format.

### Decision 4: Timestamps — TEXT vs Native

**Choice**: Store as ISO 8601 TEXT (`2026-01-15T10:30:00Z`). Portable across all 3 DBs without timezone ambiguity. MySQL's `DATETIME` loses timezone; PostgreSQL's `TIMESTAMPTZ` is better but SQLite has no native datetime. TEXT is the common denominator.

### Decision 5: Primary Keys — TEXT UUIDs vs Auto-Increment

**Choice**: `TEXT` primary keys containing UUIDs for user-facing IDs (connections, groups). `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite) / `SERIAL` (PG) / `INT AUTO_INCREMENT` (MySQL) for internal tables (sessions, audit events) where sequence ordering matters.

For the portable DDL, we'll use `TEXT PRIMARY KEY` for entity tables and handle the auto-increment differences via application-level ID generation (UUIDv7 for time-ordered IDs).

### Decision 6: Enums — TEXT vs Native

**Choice**: Store as `TEXT` with application-level validation. MySQL supports `ENUM()` but PostgreSQL and SQLite don't share the syntax. `CHECK` constraints work on all 3 but add DDL complexity. Application validation is simpler and more portable.

---

## Complete Schema — 15 Tables

### Table 1: `users`

Unified user table across all auth sources.

```sql
CREATE TABLE users (
    id                TEXT PRIMARY KEY,           -- UUIDv7
    username          TEXT NOT NULL,              -- Login name (unique per auth_source)
    email             TEXT,                       -- May be null for RADIUS/LDAP-only
    display_name      TEXT NOT NULL DEFAULT '',
    auth_source       TEXT NOT NULL DEFAULT 'database',  -- database|oidc|ldap|saml|radius
    external_id       TEXT,                       -- Provider-specific ID (OIDC sub, LDAP DN, etc.)
    password_hash     TEXT,                       -- Argon2id PHC string (database auth only)
    totp_secret      TEXT,                       -- Base32 TOTP secret (local, regardless of auth_source)
    totp_enabled     INTEGER NOT NULL DEFAULT 0, -- Whether MFA is enrolled
    role             TEXT NOT NULL DEFAULT 'viewer',  -- admin|poweruser|operator|viewer
    disabled         INTEGER NOT NULL DEFAULT 0,
    expired          INTEGER NOT NULL DEFAULT 0,
    expiry_date      TEXT,                       -- ISO 8601 or NULL
    locked_until     TEXT,                       -- Account locked until this time
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    last_login_at    TEXT,
    last_password_change TEXT,
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (auth_source, external_id),
    UNIQUE (auth_source, username)
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_auth_source ON users(auth_source);
CREATE INDEX idx_users_role ON users(role);
```

**Key columns explained**:
- `auth_source + external_id`: Composite unique constraint enables multi-provider linking. A user can have separate entries for OIDC and LDAP if they authenticate via both, but share the same `email` for correlation.
- `password_hash`: Argon2id PHC string. Only populated for `auth_source = 'database'`.
- `totp_secret`: Base32-encoded TOTP secret. Stored locally regardless of auth source because MFA enrollment is a persea concern, not an IdP concern.
- `failed_attempts` + `locked_until`: Brute-force protection. Reset on successful login.
- `last_password_change`: For password age policy enforcement.

### Table 2: `password_history`

Prevent password reuse. Guacamole stores salted hashes here.

```sql
CREATE TABLE password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,               -- Argon2id PHC string
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_password_history_user ON password_history(user_id, created_at DESC);
```

**Usage**: On password change, insert new hash. Query last N entries to check reuse. Periodically prune entries older than policy window.

### Table 3: `connection_groups`

Hierarchical folder structure for connections. Mirrors Guacamole's `guacamole_connection_group`.

```sql
CREATE TABLE connection_groups (
    id                    TEXT PRIMARY KEY,       -- UUIDv7
    parent_id             TEXT REFERENCES connection_groups(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    type                  TEXT NOT NULL DEFAULT 'organizational',  -- organizational|balancing
    description           TEXT,
    max_connections       INTEGER,
    max_connections_per_user INTEGER,
    enable_session_affinity INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (parent_id, name)
);
CREATE INDEX idx_conn_groups_parent ON connection_groups(parent_id);
```

**Notes**: `parent_id` is NULL for root groups. `type = 'balancing'` enables round-robin across child connections.

### Table 4: `connections`

Individual connection definitions. Protocol + JSON params replace Vault storage.

```sql
CREATE TABLE connections (
    id                    TEXT PRIMARY KEY,       -- UUIDv7
    parent_id             TEXT REFERENCES connection_groups(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    protocol              TEXT NOT NULL,          -- ssh|rdp|vnc|spice|web|vdi|proxmox
    params                TEXT NOT NULL DEFAULT '{}',  -- JSON: hostname, port, username, etc.
    proxy_port            INTEGER,
    proxy_hostname        TEXT,
    proxy_encryption_method TEXT DEFAULT 'none',  -- none|ssl
    max_connections       INTEGER,
    max_connections_per_user INTEGER,
    connection_weight     INTEGER,
    failover_only         INTEGER NOT NULL DEFAULT 0,
    description           TEXT,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (parent_id, name)
);
CREATE INDEX idx_connections_parent ON connections(parent_id);
CREATE INDEX idx_connections_protocol ON connections(protocol);
```

**`params` JSON structure by protocol**:

```json
// SSH
{"hostname": "10.0.0.1", "port": "22", "username": "admin", "private-key": "...", "passphrase": "..."}

// RDP
{"hostname": "10.0.0.2", "port": "3389", "username": "admin", "password": "...", "domain": "CORP", "security": "tls"}

// VNC
{"hostname": "10.0.0.3", "port": "5900", "password": "..."}

// Web (Xvnc + Chromium)
{"hostname": "127.0.0.1", "port": "5900", "display": ":100"}

// VDI (Docker)
{"image": "persea/vdi:latest", "cpu_limit": "2", "memory_limit": "2g"}
```

**Security note**: `params` contains secrets (passwords, private keys). Must be encrypted at rest in future. For now, DB access control is the only protection.

### Table 5: `connection_permissions`

Who can access what. Maps users to connections with a permission level.

```sql
CREATE TABLE connection_permissions (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL DEFAULT 'read',  -- read|update|delete|administer
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (user_id, connection_id, permission)
);
CREATE INDEX idx_conn_perm_connection ON connection_permissions(connection_id);
```

### Table 6: `connection_group_permissions`

Same pattern for connection groups.

```sql
CREATE TABLE connection_group_permissions (
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_group_id  TEXT NOT NULL REFERENCES connection_groups(id) ON DELETE CASCADE,
    permission           TEXT NOT NULL DEFAULT 'read',  -- read|update|delete|administer
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (user_id, connection_group_id, permission)
);
CREATE INDEX idx_conn_grp_perm_group ON connection_group_permissions(connection_group_id);
```

### Table 7: `auth_sessions`

Web session tokens. Enhanced from current schema with multi-DB portability.

```sql
CREATE TABLE auth_sessions (
    token_hash    TEXT PRIMARY KEY,              -- SHA-256 hex of session token
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_addr       TEXT,
    user_agent    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at    TEXT NOT NULL
);
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at);
```

**Changes from current**: Added `ip_addr` and `user_agent` for session tracking. `user_id` is now TEXT (UUID).

### Table 8: `auth_pending_mfa`

Two-phase authentication bridging. After primary auth succeeds but before MFA is verified.

```sql
CREATE TABLE auth_pending_mfa (
    id            TEXT PRIMARY KEY,              -- UUIDv7
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_method    TEXT NOT NULL DEFAULT 'totp',  -- totp|webauthn
    ip_addr       TEXT,
    user_agent    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at    TEXT NOT NULL,                 -- Short TTL (5 minutes)
    verified      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_pending_mfa_user ON auth_pending_mfa(user_id);
CREATE INDEX idx_pending_mfa_expires ON auth_pending_mfa(expires_at);
```

**Flow**: Primary auth succeeds → insert row with short TTL → redirect to MFA page → verify TOTP → create auth_session → delete pending_mfa row.

### Table 9: `group_mappings`

External group → persea role mapping. Replaces `group_role_mappings` with multi-provider support.

```sql
CREATE TABLE group_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_source     TEXT NOT NULL,               -- oidc|ldap|saml (which provider's groups)
    external_group  TEXT NOT NULL,               -- Group name/DN/claim from the provider
    role            TEXT NOT NULL,               -- admin|poweruser|operator|viewer
    description     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (auth_source, external_group)
);
```

**Examples**:
- `auth_source='oidc', external_group='admin-group', role='admin'`
- `auth_source='ldap', external_group='cn=ops,ou=groups,dc=example,dc=com', role='operator'`
- `auth_source='saml', external_group='urn:edu:mit:groups:sysadmin', role='poweruser'`

### Table 10: `user_api_tokens`

API key management. Enhanced from current with multi-DB portability.

```sql
CREATE TABLE user_api_tokens (
    id            TEXT PRIMARY KEY,              -- UUIDv7
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL,                 -- SHA-256 hex of rgu_<key>
    max_role      TEXT,                          -- Cap on effective role
    expires_at    TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at  TEXT,

    UNIQUE (user_id, name)
);
CREATE INDEX idx_api_tokens_user ON user_api_tokens(user_id);
CREATE INDEX idx_api_tokens_hash ON user_api_tokens(token_hash);
```

### Table 11: `audit_events`

Structured, hash-chain audit log for tamper evidence. Each event references the previous event's hash.

```sql
CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type    TEXT NOT NULL,                 -- login_success|login_failure|logout|session_start|session_end|password_change|user_create|user_delete|connection_connect|permission_change|mfa_enroll|mfa_verify|config_change
    user_id       TEXT,                          -- NULL for system events
    user_email    TEXT,                          -- Denormalized for audit readability
    ip_addr       TEXT,
    user_agent    TEXT,
    details       TEXT,                          -- JSON: event-specific data (no secrets)
    prev_hash     TEXT,                          -- SHA-256 hash of previous event (chain)
    event_hash    TEXT NOT NULL,                 -- SHA-256 hash of this event's data
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_audit_events_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_user ON audit_events(user_id);
CREATE INDEX idx_audit_events_created ON audit_events(created_at DESC);
CREATE INDEX idx_audit_events_hash ON audit_events(event_hash);
```

**Hash chain formula**:
```
event_hash = SHA256(event_type || user_id || ip_addr || details || created_at || prev_hash)
```

To verify chain integrity: iterate events in order, recompute each hash, check it matches `event_hash` and that `prev_hash` matches the previous event's `event_hash`.

**NIST AU-2/AU-3 compliance**: `event_type` covers audit event categories. `user_id`, `ip_addr`, `user_agent`, `details`, `created_at` provide what/who/when/where. Hash chain provides tamper evidence.

### Table 12: `session_history`

Connection session history. Enhanced from current with connection_id FK.

```sql
CREATE TABLE session_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT NOT NULL,             -- Unique session identifier
    connection_id      TEXT,                      -- FK to connections (nullable for ad-hoc)
    connection_name    TEXT NOT NULL,             -- Denormalized for display
    session_type       TEXT NOT NULL,             -- ssh|rdp|vnc|spice|web|vdi|proxmox
    hostname           TEXT NOT NULL,
    port               INTEGER,
    username           TEXT NOT NULL DEFAULT '',
    created_by         TEXT NOT NULL,             -- user email or admin name
    started_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ended_at           TEXT,
    duration_secs      INTEGER,
    recording_file     TEXT,
    status             TEXT NOT NULL DEFAULT 'active'  -- active|completed|disconnected|error
);
CREATE INDEX idx_sh_connection ON session_history(connection_id);
CREATE INDEX idx_sh_created_by ON session_history(created_by);
CREATE INDEX idx_sh_started ON session_history(started_at DESC);
CREATE INDEX idx_sh_status ON session_history(status);
```

**Changes from current**: Added `connection_id` FK. Removed `address_book_entry`/`address_book_folder`/`entry_display_name` (replaced by `connection_id` → `connections` table).

### Table 13: `auth_history`

Login/logout history. Separated from session_history (Guacamole pattern).

```sql
CREATE TABLE auth_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT,                          -- NULL if user deleted
    username      TEXT NOT NULL,
    event_type    TEXT NOT NULL,                 -- login|logout|mfa_verify
    auth_source   TEXT,                          -- database|oidc|ldap|saml|radius
    ip_addr       TEXT,
    user_agent    TEXT,
    started_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ended_at      TEXT
);
CREATE INDEX idx_auth_history_user ON auth_history(user_id);
CREATE INDEX idx_auth_history_started ON auth_history(started_at DESC);
```

### Table 14: `feature_flags`

Runtime feature toggles. Admin-managed.

```sql
CREATE TABLE feature_flags (
    flag_key      TEXT PRIMARY KEY,              -- e.g. 'vdi_enabled', 'web_browser_enabled', 'recording_enabled'
    enabled       INTEGER NOT NULL DEFAULT 0,
    description   TEXT,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_by    TEXT                           -- user who toggled
);
```

**Default flags**:
- `vdi_enabled` — Docker VDI container spawning
- `web_browser_enabled` — Xvnc + Chromium sessions
- `recording_enabled` — Session recording to disk
- `mfa_required` — Require MFA for all users
- `ldap_sync_enabled` — Periodic LDAP group sync

### Table 15: `auth_providers`

Auth source configuration stored in DB (Tier 1 config). Secrets stored encrypted.

```sql
CREATE TABLE auth_providers (
    id              TEXT PRIMARY KEY,            -- UUIDv7
    name            TEXT NOT NULL UNIQUE,        -- Display name: "Corporate LDAP"
    provider_type   TEXT NOT NULL,               -- oidc|ldap|saml|database|radius
    enabled         INTEGER NOT NULL DEFAULT 1,
    config          TEXT NOT NULL DEFAULT '{}',  -- JSON: provider-specific settings
    priority        INTEGER NOT NULL DEFAULT 0,  -- Higher = checked first for login
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_auth_providers_type ON auth_providers(provider_type);
```

**`config` JSON structure by type**:

```json
// OIDC
{"issuer_url": "https://...", "client_id": "...", "client_secret": "encrypted...", "redirect_uri": "...", "groups_claim": "groups", "extra_scopes": ["groups"]}

// LDAP
{"server_url": "ldaps://ldap.example.com", "bind_dn": "cn=admin,dc=example,dc=com", "bind_password": "encrypted...", "user_search_base": "ou=users,dc=example,dc=com", "user_search_filter": "(uid={input})", "group_search_base": "ou=groups,dc=example,dc=com", "group_search_filter": "(member={dn})", "start_tls": false, "ca_cert": "..."}

// SAML
{"metadata_url": "https://idp.example.com/metadata", "entity_id": "persea", "acs_url": "https://persea.example.com/saml/acs", "certificate": "..."}

// Database
{}  // No external config needed — users table IS the database

// RADIUS
{"server": "10.0.0.1", "port": 1812, "secret": "encrypted...", "nas_identifier": "persea"}
```

**Migration from config.toml**: On first startup with new schema, migrate `[oidc]` section to an `auth_providers` row with `provider_type = 'oidc'`. TOML config becomes read-only fallback.

---

## Portable DDL — Complete

The following DDL works on PostgreSQL, MySQL, and SQLite with these adaptations:

- **PostgreSQL**: Replace `INTEGER PRIMARY KEY AUTOINCREMENT` with `SERIAL PRIMARY KEY`. Use `BOOLEAN` instead of `INTEGER` for true/false. Use `TIMESTAMPTZ` instead of `TEXT` for timestamps (optional).
- **MySQL**: Replace `INTEGER PRIMARY KEY AUTOINCREMENT` with `INT AUTO_INCREMENT PRIMARY KEY`. Use `ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`.
- **SQLite**: As written. `INTEGER PRIMARY KEY AUTOINCREMENT` works natively.

### Universal DDL (SQLite-optimized, portable patterns)

```sql
-- ============================================================
-- persea Database Schema v2.0
-- Portable: PostgreSQL, MySQL, SQLite
-- ============================================================

-- Table 1: Unified users across all auth sources
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL,
    email               TEXT,
    display_name        TEXT NOT NULL DEFAULT '',
    auth_source         TEXT NOT NULL DEFAULT 'database',
    external_id         TEXT,
    password_hash       TEXT,
    totp_secret         TEXT,
    totp_enabled        INTEGER NOT NULL DEFAULT 0,
    role                TEXT NOT NULL DEFAULT 'viewer',
    disabled            INTEGER NOT NULL DEFAULT 0,
    expired             INTEGER NOT NULL DEFAULT 0,
    expiry_date         TEXT,
    locked_until        TEXT,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    last_login_at       TEXT,
    last_password_change TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (auth_source, external_id),
    UNIQUE (auth_source, username)
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_auth_source ON users(auth_source);
CREATE INDEX idx_users_role ON users(role);

-- Table 2: Password history for reuse prevention
CREATE TABLE password_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_password_history_user ON password_history(user_id, created_at DESC);

-- Table 3: Connection groups (hierarchical folders)
CREATE TABLE connection_groups (
    id                    TEXT PRIMARY KEY,
    parent_id             TEXT REFERENCES connection_groups(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    type                  TEXT NOT NULL DEFAULT 'organizational',
    description           TEXT,
    max_connections       INTEGER,
    max_connections_per_user INTEGER,
    enable_session_affinity INTEGER NOT NULL DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (parent_id, name)
);
CREATE INDEX idx_conn_groups_parent ON connection_groups(parent_id);

-- Table 4: Connections (protocol + JSON params)
CREATE TABLE connections (
    id                    TEXT PRIMARY KEY,
    parent_id             TEXT REFERENCES connection_groups(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    protocol              TEXT NOT NULL,
    params                TEXT NOT NULL DEFAULT '{}',
    proxy_port            INTEGER,
    proxy_hostname        TEXT,
    proxy_encryption_method TEXT DEFAULT 'none',
    max_connections       INTEGER,
    max_connections_per_user INTEGER,
    connection_weight     INTEGER,
    failover_only         INTEGER NOT NULL DEFAULT 0,
    description           TEXT,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (parent_id, name)
);
CREATE INDEX idx_connections_parent ON connections(parent_id);
CREATE INDEX idx_connections_protocol ON connections(protocol);

-- Table 5: Connection permissions
CREATE TABLE connection_permissions (
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id TEXT NOT NULL REFERENCES connections(id) ON DELETE CASCADE,
    permission    TEXT NOT NULL DEFAULT 'read',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (user_id, connection_id, permission)
);
CREATE INDEX idx_conn_perm_connection ON connection_permissions(connection_id);

-- Table 6: Connection group permissions
CREATE TABLE connection_group_permissions (
    user_id              TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_group_id  TEXT NOT NULL REFERENCES connection_groups(id) ON DELETE CASCADE,
    permission           TEXT NOT NULL DEFAULT 'read',
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    PRIMARY KEY (user_id, connection_group_id, permission)
);
CREATE INDEX idx_conn_grp_perm_group ON connection_group_permissions(connection_group_id);

-- Table 7: Auth sessions (web cookies)
CREATE TABLE auth_sessions (
    token_hash    TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ip_addr       TEXT,
    user_agent    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at    TEXT NOT NULL
);
CREATE INDEX idx_auth_sessions_user ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires ON auth_sessions(expires_at);

-- Table 8: Pending MFA (two-phase auth bridging)
CREATE TABLE auth_pending_mfa (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mfa_method    TEXT NOT NULL DEFAULT 'totp',
    ip_addr       TEXT,
    user_agent    TEXT,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    expires_at    TEXT NOT NULL,
    verified      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_pending_mfa_user ON auth_pending_mfa(user_id);
CREATE INDEX idx_pending_mfa_expires ON auth_pending_mfa(expires_at);

-- Table 9: Group mappings (external groups → roles)
CREATE TABLE group_mappings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    auth_source     TEXT NOT NULL,
    external_group  TEXT NOT NULL,
    role            TEXT NOT NULL,
    description     TEXT,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

    UNIQUE (auth_source, external_group)
);

-- Table 10: User API tokens
CREATE TABLE user_api_tokens (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL,
    max_role      TEXT,
    expires_at    TEXT,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at  TEXT,

    UNIQUE (user_id, name)
);
CREATE INDEX idx_api_tokens_user ON user_api_tokens(user_id);
CREATE INDEX idx_api_tokens_hash ON user_api_tokens(token_hash);

-- Table 11: Audit events (hash chain)
CREATE TABLE audit_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type    TEXT NOT NULL,
    user_id       TEXT,
    user_email    TEXT,
    ip_addr       TEXT,
    user_agent    TEXT,
    details       TEXT,
    prev_hash     TEXT,
    event_hash    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_audit_events_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_user ON audit_events(user_id);
CREATE INDEX idx_audit_events_created ON audit_events(created_at DESC);
CREATE INDEX idx_audit_events_hash ON audit_events(event_hash);

-- Table 12: Session history (connection sessions)
CREATE TABLE session_history (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         TEXT NOT NULL,
    connection_id      TEXT,
    connection_name    TEXT NOT NULL,
    session_type       TEXT NOT NULL,
    hostname           TEXT NOT NULL,
    port               INTEGER,
    username           TEXT NOT NULL DEFAULT '',
    created_by         TEXT NOT NULL,
    started_at         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ended_at           TEXT,
    duration_secs      INTEGER,
    recording_file     TEXT,
    status             TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX idx_sh_connection ON session_history(connection_id);
CREATE INDEX idx_sh_created_by ON session_history(created_by);
CREATE INDEX idx_sh_started ON session_history(started_at DESC);
CREATE INDEX idx_sh_status ON session_history(status);

-- Table 13: Auth history (login/logout)
CREATE TABLE auth_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT,
    username      TEXT NOT NULL,
    event_type    TEXT NOT NULL,
    auth_source   TEXT,
    ip_addr       TEXT,
    user_agent    TEXT,
    started_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ended_at      TEXT
);
CREATE INDEX idx_auth_history_user ON auth_history(user_id);
CREATE INDEX idx_auth_history_started ON auth_history(started_at DESC);

-- Table 14: Feature flags
CREATE TABLE feature_flags (
    flag_key      TEXT PRIMARY KEY,
    enabled       INTEGER NOT NULL DEFAULT 0,
    description   TEXT,
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_by    TEXT
);

-- Table 15: Auth providers (multi-source config)
CREATE TABLE auth_providers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    provider_type   TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    config          TEXT NOT NULL DEFAULT '{}',
    priority        INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
CREATE INDEX idx_auth_providers_type ON auth_providers(provider_type);
```

---

## PostgreSQL Adaptations

```sql
-- Replace AUTOINCREMENT with SERIAL
-- Replace strftime with now()
-- Replace INTEGER boolean with BOOLEAN

-- Example for users table:
CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    username            TEXT NOT NULL,
    email               TEXT,
    display_name        TEXT NOT NULL DEFAULT '',
    auth_source         TEXT NOT NULL DEFAULT 'database',
    external_id         TEXT,
    password_hash       TEXT,
    totp_secret         TEXT,
    totp_enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    role                TEXT NOT NULL DEFAULT 'viewer',
    disabled            BOOLEAN NOT NULL DEFAULT FALSE,
    expired             BOOLEAN NOT NULL DEFAULT FALSE,
    expiry_date         TEXT,
    locked_until        TEXT,
    failed_attempts     INTEGER NOT NULL DEFAULT 0,
    last_login_at       TEXT,
    last_password_change TEXT,
    created_at          TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
    updated_at          TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),

    UNIQUE (auth_source, external_id),
    UNIQUE (auth_source, username)
);

-- password_history:
CREATE TABLE password_history (
    id              SERIAL PRIMARY KEY,
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash   TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);

-- audit_events:
CREATE TABLE audit_events (
    id            SERIAL PRIMARY KEY,
    event_type    TEXT NOT NULL,
    user_id       TEXT,
    user_email    TEXT,
    ip_addr       TEXT,
    user_agent    TEXT,
    details       TEXT,
    prev_hash     TEXT,
    event_hash    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (now() AT TIME ZONE 'UTC')
);
```

## MySQL Adaptations

```sql
-- Replace AUTO_INCREMENT syntax
-- Use backtick quoting
-- ENGINE=InnoDB DEFAULT CHARSET=utf8mb4

-- Example for users table:
CREATE TABLE `users` (
    `id`                  VARCHAR(36) PRIMARY KEY,
    `username`            VARCHAR(255) NOT NULL,
    `email`               VARCHAR(255),
    `display_name`        VARCHAR(255) NOT NULL DEFAULT '',
    `auth_source`         VARCHAR(32) NOT NULL DEFAULT 'database',
    `external_id`         VARCHAR(512),
    `password_hash`       VARCHAR(512),
    `totp_secret`         VARCHAR(128),
    `totp_enabled`        TINYINT(1) NOT NULL DEFAULT 0,
    `role`                VARCHAR(32) NOT NULL DEFAULT 'viewer',
    `disabled`            TINYINT(1) NOT NULL DEFAULT 0,
    `expired`             TINYINT(1) NOT NULL DEFAULT 0,
    `expiry_date`         VARCHAR(32),
    `locked_until`        VARCHAR(32),
    `failed_attempts`     INT NOT NULL DEFAULT 0,
    `last_login_at`       VARCHAR(32),
    `last_password_change` VARCHAR(32),
    `created_at`          VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ')),
    `updated_at`          VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ')),

    UNIQUE KEY `uk_users_auth_ext` (`auth_source`, `external_id`),
    UNIQUE KEY `uk_users_auth_user` (`auth_source`, `username`),
    INDEX `idx_users_email` (`email`),
    INDEX `idx_users_auth_source` (`auth_source`),
    INDEX `idx_users_role` (`role`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- password_history:
CREATE TABLE `password_history` (
    `id`              INT AUTO_INCREMENT PRIMARY KEY,
    `user_id`         VARCHAR(36) NOT NULL,
    `password_hash`   VARCHAR(512) NOT NULL,
    `created_at`      VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ')),

    INDEX `idx_password_history_user` (`user_id`, `created_at` DESC),
    CONSTRAINT `fk_pwdhist_user` FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- audit_events:
CREATE TABLE `audit_events` (
    `id`            INT AUTO_INCREMENT PRIMARY KEY,
    `event_type`    VARCHAR(64) NOT NULL,
    `user_id`       VARCHAR(36),
    `user_email`    VARCHAR(255),
    `ip_addr`       VARCHAR(45),
    `user_agent`    VARCHAR(512),
    `details`       TEXT,
    `prev_hash`     VARCHAR(64),
    `event_hash`    VARCHAR(64) NOT NULL,
    `created_at`    VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%dT%H:%i:%SZ')),

    INDEX `idx_audit_events_type` (`event_type`),
    INDEX `idx_audit_events_user` (`user_id`),
    INDEX `idx_audit_events_created` (`created_at` DESC),
    INDEX `idx_audit_events_hash` (`event_hash`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
```

---

## Migration from Current Schema

### Step 1: Rename old tables

```sql
ALTER TABLE users RENAME TO _old_users;
ALTER TABLE auth_sessions RENAME TO _old_auth_sessions;
ALTER TABLE group_role_mappings RENAME TO _old_group_role_mappings;
ALTER TABLE user_api_tokens RENAME TO _old_user_api_tokens;
ALTER TABLE token_audit_log RENAME TO _old_token_audit_log;
ALTER TABLE session_history RENAME TO _old_session_history;
ALTER TABLE addressbook_audit_log RENAME TO _old_addressbook_audit_log;
```

### Step 2: Create new tables (DDL above)

### Step 3: Migrate data

```sql
-- Users: map old OIDC-only users to unified table
INSERT INTO users (id, username, email, display_name, auth_source, external_id, role, disabled, created_at, last_login_at)
SELECT
    lower(hex(randomblob(16))),  -- Generate UUID
    email,
    email,
    name,
    'oidc',
    oidc_subject,
    role,
    disabled,
    created_at,
    last_login_at
FROM _old_users;

-- Auth sessions: regenerate with new schema
-- (tokens must be reissued — old hashes are compatible but metadata is new)

-- Group mappings: adapt oidc_group → external_group
INSERT INTO group_mappings (auth_source, external_group, role)
SELECT 'oidc', oidc_group, role FROM _old_group_role_mappings;

-- Session history: map to new columns
INSERT INTO session_history (session_id, connection_name, session_type, hostname, port, username, created_by, started_at, ended_at, duration_secs, recording_file, status)
SELECT session_id, COALESCE(address_book_entry, hostname), session_type, hostname, port, username, created_by, started_at, ended_at, duration_secs, recording_file, status
FROM _old_session_history;
```

### Step 4: Drop old tables

```sql
DROP TABLE _old_users;
DROP TABLE _old_auth_sessions;
DROP TABLE _old_group_role_mappings;
DROP TABLE _old_user_api_tokens;
DROP TABLE _old_token_audit_log;
DROP TABLE _old_session_history;
DROP TABLE _old_addressbook_audit_log;
DROP TABLE seen_groups;  -- Replaced by group_mappings
```

---

## Table Count Summary

| # | Table | Purpose | Guacamole Equivalent |
|---|---|---|---|
| 1 | `users` | Unified user identity | `guacamole_entity` + `guacamole_user` |
| 2 | `password_history` | Password reuse prevention | `guacamole_user_password_history` |
| 3 | `connection_groups` | Hierarchical folder structure | `guacamole_connection_group` |
| 4 | `connections` | Protocol + params | `guacamole_connection` |
| 5 | `connection_permissions` | User → connection access | `guacamole_connection_permission` |
| 6 | `connection_group_permissions` | User → group access | `guacamole_connection_group_permission` |
| 7 | `auth_sessions` | Web session cookies | — (Guacamole uses JSESSIONID) |
| 8 | `auth_pending_mfa` | Two-phase MFA bridging | — (Guacamole handles in-app) |
| 9 | `group_mappings` | External groups → roles | — (Guacamole uses LDAP group search) |
| 10 | `user_api_tokens` | API key management | — |
| 11 | `audit_events` | Hash-chain audit log | — (Guacamole uses separate audit module) |
| 12 | `session_history` | Connection session history | `guacamole_connection_history` |
| 13 | `auth_history` | Login/logout history | `guacamole_user_history` |
| 14 | `feature_flags` | Runtime feature toggles | — |
| 15 | `auth_providers` | Multi-source auth config | — (Guacamole uses guacamole.properties) |

**Total: 15 tables** (vs Guacamole's 23). Eliminated: entity group nesting, sharing profiles, 5 attribute tables, fine-grained system/user permissions.
