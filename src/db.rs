//! SQLite database layer for admin/API key management.

use crate::audit::{compute_event_hash, AuditEvent, AuditFilters};
use crate::db_pool::DbPool;
use crate::providers_db::{DbProvider, MoveDirection};
use crate::rbac::{ConnectionGroup, CustomRole, EntityType, ObjectPermission, PermissionEntry};
use crate::role::role_level;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use rand::RngExt;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Shared handle to the SQLite `Connection`. Every store function in this
/// module takes `&Db`, locks the mutex for the duration of its query, and
/// drops the lock when it returns; callers never touch the lock directly.
pub type Db = Arc<Mutex<Connection>>;

/// Route a store call to the SQLx pool store when one is active (db_url configured).
/// Usage at the top of each store function:
/// `db_route!(db, some_fn_pool, arg1, arg2.to_string());`
/// Arguments are evaluated into an owned tuple BEFORE the 'static pool
/// closure, so borrowed inputs (&str params) never leak into the worker
/// thread's 'static future.
macro_rules! db_route {
    ($db:expr, $pool_fn:path $(, $arg:expr)* $(,)?) => {{
        if pool_store().is_some() {
            let _cap = ($($arg,)* ());
            return pool_call(move |pool: &'static DbPool| {
                db_route_dispatch!($pool_fn, pool, _cap $(, $arg)*)
            });
        }
    }};
}

/// Positional dispatch: expands the captured tuple back into call args.
macro_rules! db_route_dispatch {
    ($fn:path, $pool:ident, $cap:ident) => {
        $fn($pool)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr) => {
        $fn($pool, $cap.0)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr) => {
        $fn($pool, $cap.0, $cap.1)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr) => {
        $fn($pool, $cap.0, $cap.1, $cap.2)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr) => {
        $fn($pool, $cap.0, $cap.1, $cap.2, $cap.3)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        $fn($pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => {
        $fn($pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5)
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6,
        )
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6, $cap.7,
        )
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6, $cap.7, $cap.8,
        )
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6, $cap.7, $cap.8, $cap.9,
        )
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6, $cap.7, $cap.8, $cap.9,
            $cap.10,
        )
    };
    ($fn:path, $pool:ident, $cap:ident, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr, $l:expr) => {
        $fn(
            $pool, $cap.0, $cap.1, $cap.2, $cap.3, $cap.4, $cap.5, $cap.6, $cap.7, $cap.8, $cap.9,
            $cap.10, $cap.11,
        )
    };
}

/// SQL that differs only in placeholder syntax: Postgres uses `$n`,
/// MySQL and SQLite use `?`.
macro_rules! qsql {
    ($pool:expr, $pg:expr, $q:expr) => {
        match $pool {
            $crate::db_pool::DbPool::Postgres(_) => $pg,
            _ => $q,
        }
    };
}

/// Admin record (safe to display — no key material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminInfo {
    /// Primary key.
    pub id: i64,
    /// Admin name, and the lookup key for the admin management functions.
    pub name: String,
    /// Comma-separated CIDR allowlist; `None` means any client IP is accepted.
    pub allowed_ips: Option<String>,
    /// Optional key expiry. An unparseable stored value is treated as expired (fail closed).
    pub expires_at: Option<String>,
    /// Whether the key is disabled; a disabled key fails validation even with the right hash.
    pub disabled: bool,
    /// When the row was created (UTC).
    pub created_at: String,
    /// When the key last passed validation, if ever.
    pub last_used_at: Option<String>,
}

/// User record from OIDC login.
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    /// Primary key.
    pub id: i64,
    /// Login email, and the lookup key for the user management functions.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Subject claim from the identity provider; `None` for logins that have no subject.
    pub oidc_subject: Option<String>,
    /// Fixed 4-tier role: `admin`, `poweruser`, `operator`, or `viewer`.
    pub role: String,
    /// Assigned custom role id (T05); NULL when the user only has a fixed
    /// 4-tier role. Custom roles are additive on top of the role floor.
    #[serde(default)]
    pub custom_role_id: Option<String>,
    /// Whether the account is disabled; disabled users cannot log in.
    pub disabled: bool,
    /// When the row was created (UTC).
    pub created_at: String,
    /// When the user last logged in, if ever.
    pub last_login_at: Option<String>,
    /// Comma-separated OIDC group memberships (updated on each login).
    #[serde(default)]
    pub oidc_groups: String,
}

impl User {
    /// Return OIDC groups as a Vec, splitting the comma-separated string.
    pub fn groups_vec(&self) -> Vec<String> {
        if self.oidc_groups.is_empty() {
            Vec::new()
        } else {
            self.oidc_groups.split(',').map(|s| s.to_string()).collect()
        }
    }
}

/// User API token record (safe to display — no key material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct UserApiToken {
    /// Primary key.
    pub id: i64,
    /// Owning user's `users.id`.
    pub user_id: i64,
    /// Human-readable token name, shown in the account UI.
    pub name: String,
    /// Role ceiling: the effective role is the lower of this and the owner's role.
    pub max_role: Option<String>,
    /// Optional expiry; an expired token is rejected.
    pub expires_at: Option<String>,
    /// Whether the token is disabled.
    pub disabled: bool,
    /// When the token was created (UTC).
    pub created_at: String,
    /// When the token was last used, if ever.
    pub last_used_at: Option<String>,
}

/// Token audit log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenAuditEntry {
    /// Primary key.
    pub id: i64,
    /// The `user_api_tokens` row this entry refers to; `None` when that row is gone.
    pub token_id: Option<i64>,
    /// Token name at audit time, kept after the token is deleted.
    pub token_name: Option<String>,
    /// Email of the token owner.
    pub user_email: String,
    /// What happened: `created`, `revoked`, or `shadow_session`.
    pub action: String,
    /// Client IP the action came from.
    pub ip_addr: Option<String>,
    /// Free-form details; create events carry the requested role cap and expiry as JSON.
    pub details: Option<String>,
    /// When the entry was written (UTC).
    pub created_at: String,
}

/// Connections (address book) audit log entry. Persisted in SQLite, never in
/// Vault, so only headline metadata goes here: action name, target path, and
/// small counts. Entry field values (passwords, keys, usernames) must never
/// be written to `details` — see feedback_audit_log_scope.md.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddressbookAuditEntry {
    /// Primary key.
    pub id: i64,
    /// Email of the user who performed the action.
    pub user_email: String,
    /// What happened: `create_folder`, `update_folder`, `delete_folder`, `update_entry`, or `delete_entry`.
    pub action: String,
    /// Address book the action targeted (`shared`, or an instance-scoped book).
    pub scope: String,
    /// Path of the folder the action targeted.
    pub folder_path: String,
    /// Name of the entry, for entry-level actions.
    pub entry_name: Option<String>,
    /// Client IP the action came from.
    pub ip_addr: Option<String>,
    /// Free-form details; entry values (passwords, keys, usernames) must never land here.
    pub details: Option<String>,
    /// When the entry was written (UTC).
    pub created_at: String,
}

/// If we're running as root and the db's parent directory is owned by a non-root
/// user (the typical `/opt/persea/data` owned by `persea:persea` case),
/// chown the db file and any `-wal` / `-shm` sidecars to match the parent dir.
///
/// Why: CLI commands like `add-admin` are often run under `sudo`, which would
/// otherwise create a root-owned db that the systemd service (running as the
/// unprivileged `persea` user) can't write to — surfacing later as
/// "attempt to write a readonly database" on the first OIDC login.
fn repair_db_ownership(path: &Path) {
    // Unix-only: Windows has no root/chown semantics (the service runs as
    // LocalSystem and manages its own ACLs).
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        // Only act when running as root — otherwise chown(2) would fail anyway.
        // SAFETY: geteuid is always safe, takes no args.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let Some(parent) = path.parent() else { return };
        let Ok(parent_meta) = std::fs::metadata(parent) else {
            return;
        };
        let target_uid = parent_meta.uid();
        let target_gid = parent_meta.gid();
        if target_uid == 0 && target_gid == 0 {
            return;
        }

        let stem = path.as_os_str().to_os_string();
        let mut wal = stem.clone();
        wal.push("-wal");
        let mut shm = stem.clone();
        shm.push("-shm");

        for candidate in [path.as_os_str(), wal.as_os_str(), shm.as_os_str()] {
            let p = Path::new(candidate);
            let Ok(meta) = std::fs::metadata(p) else {
                continue;
            };
            if meta.uid() == target_uid && meta.gid() == target_gid {
                continue;
            }
            let c_path = match std::ffi::CString::new(candidate.as_encoded_bytes()) {
                Ok(s) => s,
                Err(_) => continue,
            };
            // SAFETY: c_path is a valid NUL-terminated C string pointing to an existing file.
            let rc = unsafe { libc::chown(c_path.as_ptr(), target_uid, target_gid) };
            if rc != 0 {
                eprintln!(
                    "warning: failed to chown {} to {}:{}: {}",
                    p.display(),
                    target_uid,
                    target_gid,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Open (or create) the database and run migrations.
pub fn init_db(path: &Path) -> rusqlite::Result<Db> {
    let conn = Connection::open(path)?;
    repair_db_ownership(path);
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS admins (
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
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            email          TEXT NOT NULL UNIQUE,
            name           TEXT NOT NULL DEFAULT '',
            oidc_subject   TEXT,
            role           TEXT NOT NULL DEFAULT 'viewer',
            custom_role_id TEXT,
            disabled       INTEGER NOT NULL DEFAULT 0,
            created_at     TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at  TEXT
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
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id         TEXT NOT NULL,
            session_type       TEXT NOT NULL,
            hostname           TEXT NOT NULL,
            port               INTEGER,
            username           TEXT NOT NULL DEFAULT '',
            created_by         TEXT NOT NULL,
            address_book_entry TEXT,
            address_book_folder TEXT,
            entry_display_name TEXT,
            reason             TEXT,
            started_at         TEXT NOT NULL DEFAULT (datetime('now')),
            ended_at           TEXT,
            duration_secs      INTEGER,
            recording_file     TEXT,
            status             TEXT NOT NULL DEFAULT 'active'
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
        CREATE INDEX IF NOT EXISTS idx_admin_api_key_hash ON admins(api_key_hash);
        CREATE INDEX IF NOT EXISTS idx_admin_token_hash ON user_api_tokens(token_hash);

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
        );",
    )?;

    // Migration: add oidc_groups column if it doesn't exist
    let has_oidc_groups: bool = conn
        .prepare("SELECT oidc_groups FROM users LIMIT 0")
        .is_ok();
    if !has_oidc_groups {
        conn.execute_batch("ALTER TABLE users ADD COLUMN oidc_groups TEXT NOT NULL DEFAULT ''")?;
    }

    // Migration: custom role assignment column (T05). The custom_roles
    // tables themselves are created by rbac::migrate below; the FK is
    // declared on the SQLx backends, while legacy SQLite (no
    // PRAGMA foreign_keys) clears the reference explicitly on role delete.
    let has_custom_role_id: bool = conn
        .prepare("SELECT custom_role_id FROM users LIMIT 0")
        .is_ok();
    if !has_custom_role_id {
        conn.execute_batch("ALTER TABLE users ADD COLUMN custom_role_id TEXT")?;
    }

    // Migration: connection reason column (V09). Fresh databases get the
    // column from the CREATE TABLE above; existing databases are ALTERed
    // here, idempotent-guarded like the other column migrations.
    if let Err(e) = conn.execute("ALTER TABLE session_history ADD COLUMN reason TEXT", []) {
        if !e.to_string().contains("duplicate column") {
            return Err(e);
        }
    }

    // Migration: auth_sessions token → token_hash (v1.0.0 security hardening)
    let has_old_token_col: bool = conn
        .prepare("SELECT token FROM auth_sessions LIMIT 0")
        .is_ok();
    if has_old_token_col {
        conn.execute_batch(
            "DROP TABLE auth_sessions;
             CREATE TABLE auth_sessions (
                 token_hash    TEXT PRIMARY KEY,
                 user_id       INTEGER NOT NULL REFERENCES users(id),
                 created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                 expires_at    TEXT NOT NULL
             );",
        )?;
    }

    // Migration: TOTP secrets table
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS totp_secrets (
            user_id       INTEGER PRIMARY KEY REFERENCES users(id),
            secret_b32    TEXT NOT NULL,
            algorithm     TEXT NOT NULL DEFAULT 'SHA1',
            digits        INTEGER NOT NULL DEFAULT 6,
            period        INTEGER NOT NULL DEFAULT 30,
            enabled       INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    // Migration: address book tables
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS address_book_folders (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scope       TEXT NOT NULL DEFAULT 'shared',
            name        TEXT NOT NULL,
            description TEXT DEFAULT '',
            allowed_groups TEXT NOT NULL DEFAULT '',
            inherit_from_parent INTEGER NOT NULL DEFAULT 0,
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
        );",
    )?;

    // Folder-level ACLs: columns added after the
    // original address book schema. ALTER is idempotent-guarded — existing
    // databases get the columns, fresh ones already have them.
    for ddl in [
        "ALTER TABLE address_book_folders ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE address_book_folders ADD COLUMN inherit_from_parent INTEGER NOT NULL DEFAULT 0",
    ] {
        if let Err(e) = conn.execute(ddl, []) {
            if !e.to_string().contains("duplicate column") {
                return Err(e);
            }
        }
    }

    // Migration: local groups + provider-group mappings.
    // Local groups are admin-defined named groups that folders/connections
    // can grant access to. `group_mappings` links an auth-provider group name
    // (from OIDC/LDAP claims, see list_known_groups) to a local group; one
    // provider group maps to at most one local group (UNIQUE). The FK cascade
    // is declared for postgres/mysql parity — SQLite runs without
    // `PRAGMA foreign_keys`, so delete_local_group removes mappings explicitly.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_groups (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT NOT NULL UNIQUE,
            description     TEXT NOT NULL DEFAULT '',
            auto_provisioned INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS group_mappings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id       INTEGER NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
            provider_group TEXT NOT NULL UNIQUE,
            created_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );",
    )?;

    // Migration: failed login attempt tracking
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS failed_login_attempts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT NOT NULL,
            ip_address  TEXT NOT NULL,
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            success     BOOLEAN DEFAULT FALSE
        );
        CREATE INDEX IF NOT EXISTS idx_failed_login_username ON failed_login_attempts(username);
        CREATE INDEX IF NOT EXISTS idx_failed_login_ip ON failed_login_attempts(ip_address);",
    )?;

    let db = Arc::new(Mutex::new(conn));

    // Migration: RBAC tables (connection groups, user-group membership, permissions)
    crate::rbac::migrate(&db)?;

    Ok(db)
}

/// Hash an API key with SHA-256 and return hex (unsalted, legacy).
fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a salted API key hash: `hex(salt):hex(hash)`.
/// Salt is 16 bytes of cryptographic randomness.
fn hash_key_salt(key: &str) -> String {
    let mut salt = [0u8; 16];
    rand::rng().fill(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(key.as_bytes());
    format!("{}:{}", hex::encode(salt), hex::encode(hasher.finalize()))
}

/// Validate a key against a stored hash.
/// Handles both salted (`hex:hex`) and legacy unsalted (bare hex) formats.
fn validate_stored_hash(key: &str, stored: &str) -> bool {
    use subtle::ConstantTimeEq;

    if let Some((salt_hex, hash_hex)) = stored.split_once(':') {
        // Salted format: recompute with extracted salt.
        if let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(hash_hex)) {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(key.as_bytes());
            let computed = hasher.finalize();
            computed.as_slice().ct_eq(&expected).into()
        } else {
            false
        }
    } else {
        // Legacy unsalted: compare raw SHA-256.
        hash_key(key).as_bytes().ct_eq(stored.as_bytes()).into()
    }
}

/// Generate a 256-bit random API key as hex (64 chars).
fn generate_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Create a new admin. Returns the plaintext API key (shown once).
/// Parse a stored `expires_at` value for expiry enforcement.
///
/// Accepts RFC 3339 (with offset), ISO without a zone and SQLite
/// `datetime('now')` format (both treated as UTC), and a bare `YYYY-MM-DD`
/// date (treated as end-of-day UTC). Returns `None` for anything unparseable
/// so callers can **fail closed** (treat an unparseable expiry as expired)
/// rather than the previous behaviour of silently ignoring it, which let a
/// malformed value authenticate forever.
fn parse_expires_at(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(Utc.from_utc_datetime(&ndt));
        }
    }
    if let Ok(nd) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(Utc.from_utc_datetime(&nd.and_hms_opt(23, 59, 59)?));
    }
    None
}

/// Create a new admin and return the plaintext API key, shown exactly once;
/// only the salted hash is stored. `allowed_ips` is a comma-separated CIDR
/// allowlist and `expires_at` an optional expiry. Fails with a unique
/// constraint error when the name is already taken.
pub fn add_admin(
    db: &Db,
    name: &str,
    allowed_ips: Option<&str>,
    expires_at: Option<&str>,
) -> rusqlite::Result<String> {
    db_route!(
        db,
        add_admin_pool,
        name.to_string(),
        allowed_ips.map(str::to_string),
        expires_at.map(str::to_string)
    );
    let key = generate_key();
    let key_hash = hash_key_salt(&key);
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO admins (name, api_key_hash, allowed_ips, expires_at) VALUES (?1, ?2, ?3, ?4)",
        params![name, key_hash, allowed_ips, expires_at],
    )?;
    Ok(key)
}

/// List all admins (no key material).
pub fn list_admins(db: &Db) -> rusqlite::Result<Vec<AdminInfo>> {
    db_route!(db, list_admins_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at FROM admins ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(AdminInfo {
            id: row.get(0)?,
            name: row.get(1)?,
            allowed_ips: row.get(2)?,
            expires_at: row.get(3)?,
            disabled: row.get::<_, i32>(4)? != 0,
            created_at: row.get(5)?,
            last_used_at: row.get(6)?,
        })
    })?;
    rows.collect()
}

/// Validate an API key against the database.
/// Checks: exists, not disabled, not expired, IP allowed.
/// On success, updates last_used_at and returns the admin info.
/// Uses constant-time hash comparison (defence-in-depth against timing attacks).
pub fn validate_api_key(
    db: &Db,
    key: &str,
    client_ip: Option<IpAddr>,
) -> Result<AdminInfo, AuthError> {
    db_route!(db, validate_api_key_pool, key.to_string(), client_ip);
    let conn = db.lock().unwrap();

    // Fetch all admins and compare hashes (supports salted + legacy unsalted)
    let mut stmt = conn
        .prepare(
            "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at, api_key_hash
             FROM admins",
        )
        .map_err(|_| AuthError::InvalidKey)?;
    let admin = stmt
        .query_map([], |row| {
            let stored_hash: String = row.get(7)?;
            Ok((
                AdminInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    allowed_ips: row.get(2)?,
                    expires_at: row.get(3)?,
                    disabled: row.get::<_, i32>(4)? != 0,
                    created_at: row.get(5)?,
                    last_used_at: row.get(6)?,
                },
                stored_hash,
            ))
        })
        .map_err(|_| AuthError::InvalidKey)?
        .filter_map(|r| r.ok())
        .find(|(_, stored_hash)| validate_stored_hash(key, stored_hash))
        .map(|(admin, _)| admin)
        .ok_or(AuthError::InvalidKey)?;

    if admin.disabled {
        return Err(AuthError::Disabled);
    }

    if let Some(ref exp) = admin.expires_at {
        // Fail closed: an unparseable expiry is treated as expired rather than
        // ignored, so a malformed value cannot authenticate indefinitely.
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
        }
    }

    if let (Some(ref cidrs), Some(ip)) = (&admin.allowed_ips, client_ip) {
        let allowed = cidrs.split(',').any(|cidr| {
            cidr.trim()
                .parse::<ipnetwork::IpNetwork>()
                .map(|net| net.contains(ip))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(AuthError::IpNotAllowed);
        }
    }

    // Update last_used_at
    let _ = conn.execute(
        "UPDATE admins SET last_used_at = datetime('now') WHERE id = ?1",
        params![admin.id],
    );

    Ok(admin)
}

/// Disable an admin by name.
pub fn disable_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    db_route!(db, set_admin_disabled_pool, name.to_string(), true);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 1 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Enable an admin by name.
pub fn enable_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    db_route!(db, set_admin_disabled_pool, name.to_string(), false);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 0 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Delete an admin by name.
pub fn delete_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    db_route!(db, delete_admin_pool, name.to_string());
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM admins WHERE name = ?1", params![name])?;
    Ok(changed > 0)
}

/// Rotate an admin's API key. Returns the new plaintext key.
pub fn rotate_key(db: &Db, name: &str) -> rusqlite::Result<Option<String>> {
    db_route!(db, rotate_key_pool, name.to_string());
    let key = generate_key();
    let key_hash = hash_key_salt(&key);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET api_key_hash = ?1 WHERE name = ?2",
        params![key_hash, name],
    )?;
    if changed > 0 {
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

#[derive(Debug)]
#[must_use]
/// Why an API key or session failed validation, returned by
/// `validate_api_key` and the session checks in `src/auth.rs`. Callers map
/// each variant to an HTTP 401 response and use the `Display` message as
/// the body.
pub enum AuthError {
    /// The presented key matched no stored hash.
    InvalidKey,
    /// The admin account is disabled.
    Disabled,
    /// The key is past its expiry; an unparseable stored expiry also lands here (fail closed).
    Expired,
    /// The client IP is not in the admin's allowlist.
    IpNotAllowed,
    /// The session token is invalid or expired.
    InvalidSession,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid API key"),
            Self::Disabled => write!(f, "admin account is disabled"),
            Self::Expired => write!(f, "API key has expired"),
            Self::IpNotAllowed => write!(f, "client IP not in allowed list"),
            Self::InvalidSession => write!(f, "invalid or expired session"),
        }
    }
}

// ── User management ──

/// Upsert a user from OIDC login. Creates on first login, updates last_login_at on subsequent.
pub fn upsert_user(
    db: &Db,
    email: &str,
    name: &str,
    oidc_subject: Option<&str>,
    default_role: &str,
    groups: &[String],
) -> rusqlite::Result<User> {
    let groups_str = groups.join(",");
    db_route!(
        db,
        upsert_user_pool,
        email.to_string(),
        name.to_string(),
        oidc_subject.map(str::to_string),
        default_role.to_string(),
        groups_str
    );
    let groups_str = groups.join(",");
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO users (email, name, oidc_subject, role, oidc_groups)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(email) DO UPDATE SET
             name = excluded.name,
             oidc_subject = COALESCE(excluded.oidc_subject, users.oidc_subject),
             oidc_groups = excluded.oidc_groups,
             last_login_at = datetime('now')",
        params![email, name, oidc_subject, default_role, groups_str],
    )?;
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id
         FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
                custom_role_id: row.get(9)?,
            })
        },
    )
}

/// Create an auth session for a user. Returns the plaintext session token
/// (256-bit hex). Only the SHA-256 hash is stored in the database.
pub fn create_auth_session(db: &Db, user_id: i64, ttl_secs: u64) -> rusqlite::Result<String> {
    db_route!(db, create_auth_session_pool, user_id, ttl_secs);
    let token = generate_key();
    let token_hash = hash_key(&token);
    let conn = db.lock().unwrap();
    let ttl_modifier = format!("+{} seconds", ttl_secs);
    conn.execute(
        "INSERT INTO auth_sessions (token_hash, user_id, expires_at)
         VALUES (?1, ?2, datetime('now', ?3))",
        params![token_hash, user_id, ttl_modifier],
    )?;
    Ok(token)
}

/// Delete all auth sessions for a user (force logout).
pub fn delete_user_sessions(db: &Db, user_id: i64) -> rusqlite::Result<usize> {
    db_route!(db, delete_user_sessions_pool, user_id);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE user_id = ?1",
        params![user_id],
    )
}

/// Look up a user by email.
pub fn get_user_by_email(db: &Db, email: &str) -> rusqlite::Result<User> {
    db_route!(db, get_user_by_email_pool, email.to_string());
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id
         FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
                custom_role_id: row.get(9)?,
            })
        },
    )
}

/// Get the auth_source for a user by email.
pub fn get_user_auth_source(db: &Db, email: &str) -> rusqlite::Result<String> {
    db_route!(db, get_user_auth_source_pool, email.to_string());
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT auth_source FROM users WHERE email = ?1",
        params![email],
        |row| row.get(0),
    )
}

/// Per-user preset credentials (username + encrypted password) used as a
/// fallback for address book entries without their own credentials.
pub fn upsert_user_preset_credentials(
    db: &Db,
    user_id: i64,
    username: &str,
    password_enc: &str,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        upsert_user_preset_credentials_pool,
        user_id,
        username.to_string(),
        password_enc.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO user_preset_credentials (user_id, username, password_enc, updated_at)
         VALUES (?1, ?2, ?3, datetime('now'))
         ON CONFLICT(user_id) DO UPDATE SET
            username = excluded.username,
            password_enc = excluded.password_enc,
            updated_at = datetime('now')",
        params![user_id, username, password_enc],
    )?;
    Ok(())
}

/// Fetch a user's preset credentials: (username, password_enc).
pub fn get_user_preset_credentials(
    db: &Db,
    user_id: i64,
) -> rusqlite::Result<Option<(String, String)>> {
    db_route!(db, get_user_preset_credentials_pool, user_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT username, password_enc FROM user_preset_credentials WHERE user_id = ?1")?;
    let mut rows = stmt.query_map(params![user_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    match rows.next() {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Remove a user's preset credentials.
pub fn clear_user_preset_credentials(db: &Db, user_id: i64) -> rusqlite::Result<()> {
    db_route!(db, clear_user_preset_credentials_pool, user_id);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_preset_credentials WHERE user_id = ?1",
        params![user_id],
    )?;
    Ok(())
}

/// Store the credentials from a password-based login for pass-through reuse
/// (config `[auth] pass_login_credentials`). Encrypted password, TTL-bounded.
pub fn upsert_login_credentials(
    db: &Db,
    user_id: i64,
    username: &str,
    password_enc: &str,
    expires_at: &str,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        upsert_login_credentials_pool,
        user_id,
        username.to_string(),
        password_enc.to_string(),
        expires_at.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO login_credentials (user_id, username, password_enc, expires_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(user_id) DO UPDATE SET
            username = excluded.username,
            password_enc = excluded.password_enc,
            expires_at = excluded.expires_at",
        params![user_id, username, password_enc, expires_at],
    )?;
    Ok(())
}

/// Fetch a user's stored login credentials: (username, password_enc, expires_at).
pub fn get_login_credentials(
    db: &Db,
    user_id: i64,
) -> rusqlite::Result<Option<(String, String, String)>> {
    db_route!(db, get_login_credentials_pool, user_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT username, password_enc, expires_at FROM login_credentials WHERE user_id = ?1",
    )?;
    let mut rows = stmt.query_map(params![user_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    match rows.next() {
        Some(Ok(v)) => Ok(Some(v)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Validate an auth session token. Returns the user if valid and not expired/disabled.
/// The token is hashed before lookup — only hashes are stored in the database.
pub fn validate_auth_session(db: &Db, token: &str) -> Result<User, AuthError> {
    db_route!(db, validate_auth_session_pool, token.to_string());
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups, u.custom_role_id
         FROM auth_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?1 AND s.expires_at > datetime('now')",
        params![token_hash],
        |row| {
            Ok(User {
                id: row.get(0)?,
                email: row.get(1)?,
                name: row.get(2)?,
                oidc_subject: row.get(3)?,
                role: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_login_at: row.get(7)?,
                oidc_groups: row.get(8)?,
                custom_role_id: row.get(9)?,
            })
        },
    )
    .map_err(|_| AuthError::InvalidSession)
    .and_then(|user| {
        if user.disabled {
            Err(AuthError::Disabled)
        } else {
            Ok(user)
        }
    })
}

/// Delete an auth session (logout). Token is hashed before lookup.
pub fn delete_auth_session(db: &Db, token: &str) -> rusqlite::Result<bool> {
    db_route!(db, delete_auth_session_pool, token.to_string());
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM auth_sessions WHERE token_hash = ?1",
        params![token_hash],
    )?;
    Ok(changed > 0)
}

/// Clean up expired auth sessions.
pub fn cleanup_expired_sessions(db: &Db) -> rusqlite::Result<usize> {
    db_route!(db, cleanup_expired_sessions_pool);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE expires_at <= datetime('now')",
        [],
    )
}

/// Record a failed login attempt.
pub fn record_failed_login_attempt(db: &Db, username: &str, ip: &str) -> rusqlite::Result<()> {
    db_route!(
        db,
        record_failed_login_attempt_pool,
        username.to_string(),
        ip.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO failed_login_attempts (username, ip_address, success) VALUES (?1, ?2, FALSE)",
        params![username, ip],
    )?;
    Ok(())
}

/// Record a successful login — marks recent failures for the same user+IP as success.
pub fn record_successful_login(db: &Db, username: &str, ip: &str) -> rusqlite::Result<()> {
    db_route!(
        db,
        record_successful_login_pool,
        username.to_string(),
        ip.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE failed_login_attempts SET success = TRUE
         WHERE username = ?1 AND ip_address = ?2 AND success = FALSE",
        params![username, ip],
    )?;
    Ok(())
}

/// Count failed login attempts for a user+IP within the given time window (seconds).
pub fn count_recent_failures(
    db: &Db,
    username: &str,
    ip: &str,
    window_secs: u64,
) -> rusqlite::Result<u32> {
    db_route!(
        db,
        count_recent_failures_pool,
        username.to_string(),
        ip.to_string(),
        window_secs
    );
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) FROM failed_login_attempts
         WHERE username = ?1 AND ip_address = ?2 AND success = FALSE
           AND attempted_at >= datetime('now', ?3)",
    )?;
    let window_param = format!("-{} seconds", window_secs);
    let count: u32 = stmt.query_row(params![username, ip, window_param], |row| row.get(0))?;
    Ok(count)
}

/// Check if a user+IP is locked out (>5 failures in the last 15 minutes).
pub fn is_locked_out(db: &Db, username: &str, ip: &str) -> rusqlite::Result<bool> {
    let failures = count_recent_failures(db, username, ip, 15 * 60)?;
    Ok(failures > 5)
}

/// List all users.
pub fn list_users(db: &Db) -> rusqlite::Result<Vec<User>> {
    db_route!(db, list_users_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id
         FROM users ORDER BY id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(User {
            id: row.get(0)?,
            email: row.get(1)?,
            name: row.get(2)?,
            oidc_subject: row.get(3)?,
            role: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_login_at: row.get(7)?,
            oidc_groups: row.get(8)?,
            custom_role_id: row.get(9)?,
        })
    })?;
    rows.collect()
}

/// Set a user's role by email.
pub fn set_user_role(db: &Db, email: &str, role: &str) -> rusqlite::Result<bool> {
    db_route!(db, set_user_role_pool, email.to_string(), role.to_string());
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET role = ?1 WHERE email = ?2",
        params![role, email],
    )?;
    Ok(changed > 0)
}

/// Update a user's display name by email.
pub fn update_user_name(db: &Db, email: &str, name: &str) -> rusqlite::Result<bool> {
    db_route!(
        db,
        update_user_name_pool,
        email.to_string(),
        name.to_string()
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET name = ?1 WHERE email = ?2",
        params![name, email],
    )?;
    Ok(changed > 0)
}

/// Disable a user by email.
pub fn disable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    db_route!(db, set_user_disabled_pool, email.to_string(), true);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 1 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Enable a user by email.
pub fn enable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    db_route!(db, set_user_disabled_pool, email.to_string(), false);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 0 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Delete a user by email (also deletes their auth sessions and API tokens).
pub fn delete_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    db_route!(db, delete_user_pool, email.to_string());
    let conn = db.lock().unwrap();
    // Delete auth sessions first
    conn.execute(
        "DELETE FROM auth_sessions WHERE user_id IN (SELECT id FROM users WHERE email = ?1)",
        params![email],
    )?;
    // Delete user API tokens
    conn.execute(
        "DELETE FROM user_api_tokens WHERE user_id IN (SELECT id FROM users WHERE email = ?1)",
        params![email],
    )?;
    let changed = conn.execute("DELETE FROM users WHERE email = ?1", params![email])?;
    Ok(changed > 0)
}

// ── Group-to-role mappings ──

/// A mapping from an OIDC group name to a role.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GroupRoleMapping {
    /// Primary key.
    pub id: i64,
    /// The OIDC group name being mapped.
    pub oidc_group: String,
    /// Role granted to members of that group.
    pub role: String,
    /// When the mapping was created (UTC).
    pub created_at: String,
}

/// List all group-to-role mappings.
pub fn list_group_mappings(db: &Db) -> rusqlite::Result<Vec<GroupRoleMapping>> {
    db_route!(db, list_group_mappings_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, oidc_group, role, created_at FROM group_role_mappings ORDER BY id")?;
    let rows = stmt.query_map([], |row| {
        Ok(GroupRoleMapping {
            id: row.get(0)?,
            oidc_group: row.get(1)?,
            role: row.get(2)?,
            created_at: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// Create a group-to-role mapping. Returns the new mapping.
pub fn create_group_mapping(
    db: &Db,
    oidc_group: &str,
    role: &str,
) -> rusqlite::Result<GroupRoleMapping> {
    db_route!(
        db,
        create_group_mapping_pool,
        oidc_group.to_string(),
        role.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO group_role_mappings (oidc_group, role) VALUES (?1, ?2)",
        params![oidc_group, role],
    )?;
    let id = conn.last_insert_rowid();
    conn.query_row(
        "SELECT id, oidc_group, role, created_at FROM group_role_mappings WHERE id = ?1",
        params![id],
        |row| {
            Ok(GroupRoleMapping {
                id: row.get(0)?,
                oidc_group: row.get(1)?,
                role: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    )
}

/// Update a group-to-role mapping by id.
pub fn update_group_mapping(
    db: &Db,
    id: i64,
    oidc_group: &str,
    role: &str,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        update_group_mapping_pool,
        id,
        oidc_group.to_string(),
        role.to_string()
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE group_role_mappings SET oidc_group = ?1, role = ?2 WHERE id = ?3",
        params![oidc_group, role, id],
    )?;
    Ok(changed > 0)
}

/// Delete a group-to-role mapping by id.
pub fn delete_group_mapping(db: &Db, id: i64) -> rusqlite::Result<bool> {
    db_route!(db, delete_group_mapping_pool, id);
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM group_role_mappings WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

/// Upsert OIDC groups observed in a login token, updating last_seen.
pub fn upsert_seen_groups(db: &Db, groups: &[String]) -> rusqlite::Result<()> {
    db_route!(db, upsert_seen_groups_pool, groups.to_vec());
    if groups.is_empty() {
        return Ok(());
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "INSERT INTO seen_groups (name) VALUES (?1)
             ON CONFLICT(name) DO UPDATE SET last_seen = datetime('now')",
        )?;
        for g in groups {
            let trimmed = g.trim();
            if !trimmed.is_empty() {
                stmt.execute(params![trimmed])?;
            }
        }
    }
    tx.commit()?;
    Ok(())
}

/// Auto-provision `local_groups` for the given provider groups, mapping
/// OIDC groups to local groups without manual mapping. Folder
/// ACLs reference local group names, so a provider group that shows up in
/// login claims becomes usable in the connections page immediately. Groups
/// already created (or mapped) are left untouched.
pub fn ensure_local_groups(db: &Db, groups: &[String]) -> rusqlite::Result<usize> {
    db_route!(db, ensure_local_groups_pool, groups.to_vec());
    if groups.is_empty() {
        return Ok(0);
    }
    let conn = db.lock().unwrap();
    let mut created = 0usize;
    {
        let mut stmt = conn.prepare(
            "INSERT OR IGNORE INTO local_groups (name, description, auto_provisioned)
             VALUES (?1, 'Auto-provisioned from auth provider groups', 1)",
        )?;
        for g in groups {
            let trimmed = g.trim();
            if !trimmed.is_empty() && !trimmed.contains(',') {
                created += stmt.execute(params![trimmed])?;
            }
        }
    }
    Ok(created)
}

/// List all known OIDC groups — union of configured role-mappings and groups
/// ever seen in a user's login claims. Sorted case-insensitively.
pub fn list_known_groups(db: &Db) -> rusqlite::Result<Vec<String>> {
    db_route!(db, list_known_groups_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT g FROM (
            SELECT oidc_group AS g FROM group_role_mappings
            UNION
            SELECT name AS g FROM seen_groups
         )
         WHERE g IS NOT NULL AND g <> ''
         ORDER BY g COLLATE NOCASE",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    rows.collect()
}

// ── User API tokens ──

/// Create a user API token. Returns the plaintext token (shown once).
/// The token is prefixed with `rgu_` to distinguish from admin keys.
pub fn create_user_token(
    db: &Db,
    user_id: i64,
    name: &str,
    max_role: Option<&str>,
    expires_at: Option<&str>,
) -> rusqlite::Result<(i64, String)> {
    db_route!(
        db,
        create_user_token_pool,
        user_id,
        name.to_string(),
        max_role.map(str::to_string),
        expires_at.map(str::to_string)
    );
    let raw_key = generate_key();
    let token = format!("rgu_{}", raw_key);
    let token_hash = hash_key(&token);
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO user_api_tokens (user_id, name, token_hash, max_role, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![user_id, name, token_hash, max_role, expires_at],
    )?;
    let id = conn.last_insert_rowid();
    Ok((id, token))
}

/// List all tokens for a specific user (no key material).
pub fn list_user_tokens(db: &Db, user_id: i64) -> rusqlite::Result<Vec<UserApiToken>> {
    db_route!(db, list_user_tokens_pool, user_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, user_id, name, max_role, expires_at, disabled, created_at, last_used_at
         FROM user_api_tokens WHERE user_id = ?1 ORDER BY id",
    )?;
    let rows = stmt.query_map(params![user_id], |row| {
        Ok(UserApiToken {
            id: row.get(0)?,
            user_id: row.get(1)?,
            name: row.get(2)?,
            max_role: row.get(3)?,
            expires_at: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_used_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Admin view: list all user tokens with the user's email.
pub fn list_all_user_tokens(db: &Db) -> rusqlite::Result<Vec<(UserApiToken, String)>> {
    db_route!(db, list_all_user_tokens_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, u.email
         FROM user_api_tokens t
         JOIN users u ON u.id = t.user_id
         ORDER BY t.id",
    )?;
    let rows = stmt.query_map([], |row| {
        let token = UserApiToken {
            id: row.get(0)?,
            user_id: row.get(1)?,
            name: row.get(2)?,
            max_role: row.get(3)?,
            expires_at: row.get(4)?,
            disabled: row.get::<_, i32>(5)? != 0,
            created_at: row.get(6)?,
            last_used_at: row.get(7)?,
        };
        let email: String = row.get(8)?;
        Ok((token, email))
    })?;
    rows.collect()
}

/// Validate a user API token. Returns the user and token metadata.
/// Checks: exists, not disabled, not expired, user not disabled.
/// Updates last_used_at on success.
/// Uses constant-time hash comparison (defence-in-depth against timing attacks).
pub fn validate_user_token(db: &Db, token: &str) -> Result<(User, UserApiToken), AuthError> {
    db_route!(db, validate_user_token_pool, token.to_string());
    use subtle::ConstantTimeEq;

    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();

    // Fetch all tokens with their users and compare hashes in constant time
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at,
                    u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups,
                    t.token_hash, u.custom_role_id
             FROM user_api_tokens t
             JOIN users u ON u.id = t.user_id",
        )
        .map_err(|_| AuthError::InvalidKey)?;
    let (user, token_info) = stmt
        .query_map([], |row| {
            let stored_hash: String = row.get(17)?;
            let token_info = UserApiToken {
                id: row.get(0)?,
                user_id: row.get(1)?,
                name: row.get(2)?,
                max_role: row.get(3)?,
                expires_at: row.get(4)?,
                disabled: row.get::<_, i32>(5)? != 0,
                created_at: row.get(6)?,
                last_used_at: row.get(7)?,
            };
            let user = User {
                id: row.get(8)?,
                email: row.get(9)?,
                name: row.get(10)?,
                oidc_subject: row.get(11)?,
                role: row.get(12)?,
                disabled: row.get::<_, i32>(13)? != 0,
                created_at: row.get(14)?,
                last_login_at: row.get(15)?,
                oidc_groups: row.get(16)?,
                custom_role_id: row.get(18)?,
            };
            Ok((user, token_info, stored_hash))
        })
        .map_err(|_| AuthError::InvalidKey)?
        .filter_map(|r| r.ok())
        .find(|(_, _, stored_hash)| token_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into())
        .map(|(user, token_info, _)| (user, token_info))
        .ok_or(AuthError::InvalidKey)?;

    if token_info.disabled {
        return Err(AuthError::Disabled);
    }

    if user.disabled {
        return Err(AuthError::Disabled);
    }

    if let Some(ref exp) = token_info.expires_at {
        // Fail closed: an unparseable expiry is treated as expired rather than
        // ignored, so a malformed value cannot authenticate indefinitely.
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
        }
    }

    // Update last_used_at
    let _ = conn.execute(
        "UPDATE user_api_tokens SET last_used_at = datetime('now') WHERE id = ?1",
        params![token_info.id],
    );

    Ok((user, token_info))
}

/// Revoke (delete) a specific token. Ownership check: user_id must match.
pub fn revoke_user_token(db: &Db, user_id: i64, token_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, revoke_user_token_pool, user_id, token_id);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM user_api_tokens WHERE id = ?1 AND user_id = ?2",
        params![token_id, user_id],
    )?;
    Ok(changed > 0)
}

/// Admin: revoke any user's token by ID (no ownership check).
pub fn admin_revoke_user_token(db: &Db, token_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, admin_revoke_user_token_pool, token_id);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM user_api_tokens WHERE id = ?1",
        params![token_id],
    )?;
    Ok(changed > 0)
}

/// Revoke all tokens for a user.
#[allow(dead_code)]
pub fn revoke_all_user_tokens(db: &Db, user_id: i64) -> rusqlite::Result<usize> {
    db_route!(db, revoke_all_user_tokens_pool, user_id);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_api_tokens WHERE user_id = ?1",
        params![user_id],
    )
}

/// Clean up expired user API tokens.
pub fn cleanup_expired_user_tokens(db: &Db) -> rusqlite::Result<usize> {
    db_route!(db, cleanup_expired_user_tokens_pool);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_api_tokens WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
        [],
    )
}

// ── Token audit log ──

/// Log a token lifecycle event.
pub fn log_token_event(
    db: &Db,
    token_id: Option<i64>,
    token_name: Option<&str>,
    user_email: &str,
    action: &str,
    ip_addr: Option<&str>,
    details: Option<&str>,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        log_token_event_pool,
        token_id,
        token_name.map(str::to_string),
        user_email.to_string(),
        action.to_string(),
        ip_addr.map(str::to_string),
        details.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO token_audit_log (token_id, token_name, user_email, action, ip_addr, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![token_id, token_name, user_email, action, ip_addr, details],
    )?;
    Ok(())
}

/// List token audit log entries, most recent first, with optional limit.
pub fn list_token_audit_log(
    db: &Db,
    limit: u32,
    user_email: Option<&str>,
) -> rusqlite::Result<Vec<TokenAuditEntry>> {
    db_route!(
        db,
        list_token_audit_log_pool,
        limit,
        user_email.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
        if let Some(email) = user_email {
            (
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at
             FROM token_audit_log WHERE user_email = ?1 ORDER BY id DESC LIMIT ?2",
                vec![Box::new(email.to_string()), Box::new(limit)],
            )
        } else {
            (
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at
             FROM token_audit_log ORDER BY id DESC LIMIT ?1",
                vec![Box::new(limit)],
            )
        };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok(TokenAuditEntry {
            id: row.get(0)?,
            token_id: row.get(1)?,
            token_name: row.get(2)?,
            user_email: row.get(3)?,
            action: row.get(4)?,
            ip_addr: row.get(5)?,
            details: row.get(6)?,
            created_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Clean up old audit log entries (retain last N days).
pub fn cleanup_old_audit_log(db: &Db, retain_days: u32) -> rusqlite::Result<usize> {
    db_route!(db, cleanup_old_audit_log_pool, retain_days);
    let conn = db.lock().unwrap();
    let modifier = format!("-{} days", retain_days);
    let tok = conn.execute(
        "DELETE FROM token_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    let ab = conn.execute(
        "DELETE FROM addressbook_audit_log WHERE created_at < datetime('now', ?1)",
        params![&modifier],
    )?;
    Ok(tok + ab)
}

// ── Connections (address book) audit log ──

/// Log a destructive or mutating connections action. Persisted in SQLite.
///
/// `details` is a free-form text blob (callers typically write JSON) but must
/// never contain entry field values or full request bodies (see
/// feedback_audit_log_scope.md). Counts, booleans, field-name lists are fine.
#[allow(clippy::too_many_arguments)]
pub fn log_addressbook_event(
    db: &Db,
    user_email: &str,
    action: &str,
    scope: &str,
    folder_path: &str,
    entry_name: Option<&str>,
    ip_addr: Option<&str>,
    details: Option<&str>,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        log_addressbook_event_pool,
        user_email.to_string(),
        action.to_string(),
        scope.to_string(),
        folder_path.to_string(),
        entry_name.map(str::to_string),
        ip_addr.map(str::to_string),
        details.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO addressbook_audit_log
            (user_email, action, scope, folder_path, entry_name, ip_addr, details)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            user_email,
            action,
            scope,
            folder_path,
            entry_name,
            ip_addr,
            details
        ],
    )?;
    Ok(())
}

/// List connections audit log entries, most recent first, with optional
/// filters for limit and user_email.
pub fn list_addressbook_audit_log(
    db: &Db,
    limit: u32,
    user_email: Option<&str>,
) -> rusqlite::Result<Vec<AddressbookAuditEntry>> {
    db_route!(
        db,
        list_addressbook_audit_log_pool,
        limit,
        user_email.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) =
        if let Some(email) = user_email {
            (
                "SELECT id, user_email, action, scope, folder_path, entry_name,
                        ip_addr, details, created_at
                 FROM addressbook_audit_log WHERE user_email = ?1
                 ORDER BY id DESC LIMIT ?2",
                vec![Box::new(email.to_string()), Box::new(limit)],
            )
        } else {
            (
                "SELECT id, user_email, action, scope, folder_path, entry_name,
                        ip_addr, details, created_at
                 FROM addressbook_audit_log ORDER BY id DESC LIMIT ?1",
                vec![Box::new(limit)],
            )
        };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok(AddressbookAuditEntry {
            id: row.get(0)?,
            user_email: row.get(1)?,
            action: row.get(2)?,
            scope: row.get(3)?,
            folder_path: row.get(4)?,
            entry_name: row.get(5)?,
            ip_addr: row.get(6)?,
            details: row.get(7)?,
            created_at: row.get(8)?,
        })
    })?;
    rows.collect()
}

// ── Session history ──

/// Record a new session in the history table.
#[allow(clippy::too_many_arguments)]
pub fn insert_session_history(
    db: &Db,
    session_id: &str,
    session_type: &str,
    hostname: &str,
    port: Option<u16>,
    username: &str,
    created_by: &str,
    address_book_entry: Option<&str>,
    address_book_folder: Option<&str>,
    entry_display_name: Option<&str>,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        insert_session_history_pool,
        session_id.to_string(),
        session_type.to_string(),
        hostname.to_string(),
        port.map(|p| p as i64),
        username.to_string(),
        created_by.to_string(),
        address_book_entry.map(str::to_string),
        address_book_folder.map(str::to_string),
        entry_display_name.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO session_history
         (session_id, session_type, hostname, port, username, created_by,
          address_book_entry, address_book_folder, entry_display_name)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            session_id,
            session_type,
            hostname,
            port.map(|p| p as i64),
            username,
            created_by,
            address_book_entry,
            address_book_folder,
            entry_display_name,
        ],
    )?;
    Ok(())
}

/// Mark a session as ended in the history table.
pub fn end_session_history(
    db: &Db,
    session_id: &str,
    status: &str,
    duration_secs: u64,
    recording_file: Option<&str>,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        end_session_history_pool,
        session_id.to_string(),
        status.to_string(),
        duration_secs as i64,
        recording_file.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE session_history
         SET ended_at = datetime('now'), duration_secs = ?2, status = ?3, recording_file = ?4
         WHERE session_id = ?1 AND ended_at IS NULL",
        params![session_id, duration_secs as i64, status, recording_file],
    )?;
    Ok(())
}

/// Attach the connection reason to a session-history row (V09). Called
/// right after `insert_session_history`; the guarded WHERE keeps the
/// first reason written (never overwrites a user-supplied one).
pub fn update_session_history_reason(
    db: &Db,
    session_id: &str,
    reason: &str,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        update_session_history_reason_pool,
        session_id.to_string(),
        reason.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE session_history SET reason = ?1 WHERE session_id = ?2 AND reason IS NULL",
        params![reason, session_id],
    )?;
    Ok(())
}

// ── Session registry (enterprise HA) ──────────────────────────────

/// One live-session record in the shared registry. Mirrors the in-memory
/// `Session` on the owning instance; every other instance reads it to see,
/// join, and shadow sessions it does not host.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SessionRegistryRow {
    /// Session UUID, primary key of the registry table.
    pub session_id: String,
    /// Instance id of the instance that hosts the session.
    pub owner_instance: String,
    /// Base URL of that instance, used to route join and shadow requests back to it.
    pub owner_base_url: String,
    /// Protocol type: `ssh`, `rdp`, `vnc`, `spice`, `web`, `vdi`, or `proxmox`.
    pub session_type: String,
    /// Lifecycle status: `active`, `idle`, `disconnected`, `completed`, or `expired`.
    pub status: String,
    /// Target host the session connects to.
    pub hostname: String,
    /// Target username the session logs in as.
    pub username: String,
    /// Email of the user who created the session.
    pub created_by: String,
    /// When the session started (UTC).
    pub created_at: String,
    /// Last reported activity (UTC); other instances use this to spot idle sessions.
    pub last_active_at: String,
    /// Address-book entry the session came from, when it came from one.
    pub connection_id: String,
    /// Hash of the active shadow token; `None` when no shadow is outstanding.
    pub shadow_token_hash: Option<String>,
    /// Instance id that issued the shadow token.
    pub shadow_issued_by: Option<String>,
    /// When the shadow token expires (UTC).
    pub shadow_expires_at: Option<String>,
}

/// Fixed-width UTC timestamp used by the registry (all backends, all
/// columns). Lexicographic comparison is time-ordered.
pub fn registry_ts(when: chrono::DateTime<chrono::Utc>) -> String {
    when.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Upsert a live-session registry row. Single-instance mode (no `db_url`
/// pool) writes nothing — the registry only exists on shared backends.
#[allow(clippy::too_many_arguments)]
pub fn registry_upsert_session(
    _db: &Db,
    session_id: &str,
    owner_instance: &str,
    owner_base_url: &str,
    session_type: &str,
    status: &str,
    hostname: &str,
    username: &str,
    created_by: &str,
    created_at: &str,
    last_active_at: &str,
    connection_id: &str,
) -> rusqlite::Result<()> {
    if pool_store().is_none() {
        return Ok(());
    }
    db_route!(
        db,
        registry_upsert_session_pool,
        session_id.to_string(),
        owner_instance.to_string(),
        owner_base_url.to_string(),
        session_type.to_string(),
        status.to_string(),
        hostname.to_string(),
        username.to_string(),
        created_by.to_string(),
        created_at.to_string(),
        last_active_at.to_string(),
        connection_id.to_string()
    );
    Ok(())
}

/// Update a registry row's status (and last_active_at). No-op when no pool.
pub fn registry_set_status(
    _db: &Db,
    session_id: &str,
    status: &str,
    last_active_at: &str,
) -> rusqlite::Result<()> {
    if pool_store().is_none() {
        return Ok(());
    }
    db_route!(
        db,
        registry_set_status_pool,
        session_id.to_string(),
        status.to_string(),
        last_active_at.to_string()
    );
    Ok(())
}

/// Store an admin-minted shadow token on a remote session's registry row so
/// any instance can validate it (the in-memory copy lives on the owner).
/// No-op when no pool.
pub fn registry_set_shadow_token(
    _db: &Db,
    session_id: &str,
    token_hash: &str,
    issued_by: &str,
    expires_at: &str,
) -> rusqlite::Result<()> {
    if pool_store().is_none() {
        return Ok(());
    }
    db_route!(
        db,
        registry_set_shadow_token_pool,
        session_id.to_string(),
        token_hash.to_string(),
        issued_by.to_string(),
        expires_at.to_string()
    );
    Ok(())
}

/// Remove a session from the registry (session left the owner's map).
/// No-op when no pool.
pub fn registry_delete_session(_db: &Db, session_id: &str) -> rusqlite::Result<()> {
    if pool_store().is_none() {
        return Ok(());
    }
    db_route!(db, registry_delete_session_pool, session_id.to_string());
    Ok(())
}

/// Fetch one registry row. No pool → `Ok(None)`.
pub fn registry_get_session(
    _db: &Db,
    session_id: &str,
) -> rusqlite::Result<Option<SessionRegistryRow>> {
    if pool_store().is_none() {
        return Ok(None);
    }
    db_route!(db, registry_get_session_pool, session_id.to_string());
    Ok(None)
}

/// List every live-session registry row. No pool → empty.
pub fn registry_list_sessions(_db: &Db) -> rusqlite::Result<Vec<SessionRegistryRow>> {
    if pool_store().is_none() {
        return Ok(Vec::new());
    }
    db_route!(db, registry_list_sessions_pool);
    Ok(Vec::new())
}

/// Session ids in the registry owned by `owner_instance` (recording
/// rotation filters by this). No pool → empty.
pub fn registry_list_owned(_db: &Db, owner_instance: &str) -> rusqlite::Result<Vec<String>> {
    if pool_store().is_none() {
        return Ok(Vec::new());
    }
    db_route!(db, registry_list_owned_pool, owner_instance.to_string());
    Ok(Vec::new())
}

/// Delete registry rows that can no longer be live, using three cutoffs
/// (fixed-width timestamps):
/// - `pending_cutoff`: rows still in `pending` — the owner would have
///   marked them `expired` within the pending window.
/// - `terminal_cutoff`: rows in a terminal status (`completed`/`error`/
///   `expired`) — kept this long after creation so the owning instance's
///   recording rotation can still attribute the recording file, then
///   removed (any instance may delete terminal rows; deletes are
///   idempotent).
/// - `live_cutoff`: `Some` — live rows (pending/active/disconnected) owned
///   by OTHER instances whose owner must be dead (it would have reaped the
///   session at max duration). `None` disables the live sweep (unlimited
///   max duration: no age proves death).
///
/// Own live rows are never touched (this instance is alive and owns them).
/// Returns the number of rows deleted. No pool → 0.
pub fn registry_delete_stale(
    _db: &Db,
    owner_instance: &str,
    pending_cutoff: &str,
    terminal_cutoff: &str,
    live_cutoff: Option<&str>,
) -> rusqlite::Result<usize> {
    if pool_store().is_none() {
        return Ok(0);
    }
    db_route!(
        db,
        registry_delete_stale_pool,
        owner_instance.to_string(),
        pending_cutoff.to_string(),
        terminal_cutoff.to_string(),
        live_cutoff.map(str::to_string)
    );
    Ok(0)
}

/// Delete every registry row owned by this instance (graceful shutdown).
/// No pool → 0.
pub fn registry_delete_all_owned(_db: &Db, owner_instance: &str) -> rusqlite::Result<usize> {
    if pool_store().is_none() {
        return Ok(0);
    }
    db_route!(
        db,
        registry_delete_all_owned_pool,
        owner_instance.to_string()
    );
    Ok(0)
}

// ── WS ticket persistence (enterprise HA) ─────────────────────────

/// Persist a WebSocket ticket so any instance sharing the backend can
/// validate it. Only the SHA-256 hash of the raw ticket is stored. No-op
/// when no pool.
pub fn ws_ticket_insert(
    _db: &Db,
    ticket_hash: &str,
    identity_json: &str,
    session_id: Option<&str>,
    issued_by: &str,
    expires_at: &str,
) -> rusqlite::Result<()> {
    if pool_store().is_none() {
        return Ok(());
    }
    db_route!(
        db,
        ws_ticket_insert_pool,
        ticket_hash.to_string(),
        identity_json.to_string(),
        session_id.map(str::to_string),
        issued_by.to_string(),
        expires_at.to_string()
    );
    Ok(())
}

/// Fetch a persisted ticket: `(identity_json, expires_at)`. No pool → None.
pub fn ws_ticket_get(_db: &Db, ticket_hash: &str) -> rusqlite::Result<Option<(String, String)>> {
    if pool_store().is_none() {
        return Ok(None);
    }
    db_route!(db, ws_ticket_get_pool, ticket_hash.to_string());
    Ok(None)
}

/// Delete a persisted ticket (single-use consumption). Returns whether a
/// row was removed. No pool → false.
pub fn ws_ticket_delete(_db: &Db, ticket_hash: &str) -> rusqlite::Result<bool> {
    if pool_store().is_none() {
        return Ok(false);
    }
    db_route!(db, ws_ticket_delete_pool, ticket_hash.to_string());
    Ok(false)
}

/// Delete expired persisted tickets. Returns the number removed. No pool → 0.
pub fn ws_ticket_cleanup_expired(_db: &Db, cutoff: &str) -> rusqlite::Result<usize> {
    if pool_store().is_none() {
        return Ok(0);
    }
    db_route!(db, ws_ticket_cleanup_expired_pool, cutoff.to_string());
    Ok(0)
}

/// Query session history with optional filters. Returns JSON-ready rows.
#[allow(clippy::too_many_arguments)]
pub fn query_session_history(
    db: &Db,
    user: Option<&str>,
    entry: Option<&str>,
    session_type: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
    limit: u32,
    offset: u32,
) -> rusqlite::Result<(Vec<serde_json::Value>, u32)> {
    db_route!(
        db,
        query_session_history_pool,
        user.map(str::to_string),
        entry.map(str::to_string),
        session_type.map(str::to_string),
        from.map(str::to_string),
        to.map(str::to_string),
        limit,
        offset
    );
    let conn = db.lock().unwrap();
    let mut conditions = vec!["1=1".to_string()];
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(u) = user {
        conditions.push(format!("created_by LIKE ?{}", idx));
        params_vec.push(Box::new(format!("%{}%", u)));
        idx += 1;
    }
    if let Some(e) = entry {
        conditions.push(format!(
            "(address_book_entry LIKE ?{} OR entry_display_name LIKE ?{})",
            idx, idx
        ));
        params_vec.push(Box::new(format!("%{}%", e)));
        idx += 1;
    }
    if let Some(t) = session_type {
        conditions.push(format!("session_type = ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
        idx += 1;
    }
    if let Some(f) = from {
        conditions.push(format!("started_at >= ?{}", idx));
        params_vec.push(Box::new(f.to_string()));
        idx += 1;
    }
    if let Some(t) = to {
        conditions.push(format!("started_at <= ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
        idx += 1;
    }

    let where_clause = conditions.join(" AND ");

    // Count total matching rows
    let count_sql = format!(
        "SELECT COUNT(*) FROM session_history WHERE {}",
        where_clause
    );
    let total: u32 = {
        let mut stmt = conn.prepare(&count_sql)?;
        stmt.query_row(rusqlite::params_from_iter(params_vec.iter()), |row| {
            row.get(0)
        })?
    };

    // Fetch page
    let query_sql = format!(
        "SELECT session_id, session_type, hostname, port, username, created_by,
                address_book_entry, address_book_folder, entry_display_name,
                reason, started_at, ended_at, duration_secs, recording_file, status
         FROM session_history WHERE {} ORDER BY started_at DESC LIMIT ?{} OFFSET ?{}",
        where_clause,
        idx,
        idx + 1
    );
    params_vec.push(Box::new(limit));
    params_vec.push(Box::new(offset));

    let mut stmt = conn.prepare(&query_sql)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
            Ok(serde_json::json!({
                "session_id": row.get::<_, String>(0)?,
                "session_type": row.get::<_, String>(1)?,
                "hostname": row.get::<_, String>(2)?,
                "port": row.get::<_, Option<i64>>(3)?,
                "username": row.get::<_, String>(4)?,
                "created_by": row.get::<_, String>(5)?,
                "address_book_entry": row.get::<_, Option<String>>(6)?,
                "address_book_folder": row.get::<_, Option<String>>(7)?,
                "entry_display_name": row.get::<_, Option<String>>(8)?,
                "reason": row.get::<_, Option<String>>(9)?,
                "started_at": row.get::<_, String>(10)?,
                "ended_at": row.get::<_, Option<String>>(11)?,
                "duration_secs": row.get::<_, Option<i64>>(12)?,
                "recording_file": row.get::<_, Option<String>>(13)?,
                "status": row.get::<_, String>(14)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();

    Ok((rows, total))
}

/// Stream session history rows directly into a CSV writer, avoiding the
/// intermediate Vec allocation of query_session_history.
pub fn stream_session_history_csv(
    db: &Db,
    writer: &mut dyn std::io::Write,
    user: Option<&str>,
    entry: Option<&str>,
    session_type: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    if pool_store().is_some() {
        let user_s = user.map(str::to_string);
        let entry_s = entry.map(str::to_string);
        let session_type_s = session_type.map(str::to_string);
        let from_s = from.map(str::to_string);
        let to_s = to.map(str::to_string);
        let rows = pool_call(move |pool: &'static DbPool| {
            stream_session_history_csv_pool(pool, user_s, entry_s, session_type_s, from_s, to_s)
        })?;
        let mut count = 0usize;
        for (
            session_id,
            session_type,
            hostname,
            _port,
            username,
            created_by,
            entry_name,
            folder,
            started_at,
            ended_at,
            duration_secs,
            status,
            _recording,
            raw_entry_display_name,
        ) in rows
        {
            let fields = [
                &session_id,
                &session_type,
                &hostname,
                &username,
                &created_by,
                &entry_name,
                &folder,
                &started_at,
            ];
            for (i, f) in fields.iter().enumerate() {
                if i > 0 {
                    write!(writer, ",")?;
                }
                csv_escape_field(writer, f)?;
            }
            write!(writer, ",")?;
            csv_escape_field(writer, ended_at.as_deref().unwrap_or(""))?;
            write!(writer, ",")?;
            if let Some(d) = duration_secs {
                write!(writer, "{}", d)?;
            }
            write!(writer, ",")?;
            csv_escape_field(writer, &status)?;
            write!(writer, ",")?;
            csv_escape_field(
                writer,
                &recording_display_name(
                    &session_id,
                    &hostname,
                    &created_by,
                    raw_entry_display_name.as_deref(),
                    &started_at,
                ),
            )?;
            writeln!(writer)?;
            count += 1;
        }
        return Ok(count);
    }

    let conn = db.lock().unwrap();
    let mut conditions = vec!["1=1".to_string()];
    let mut params_vec: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    let mut idx = 1;

    if let Some(u) = user {
        conditions.push(format!("created_by LIKE ?{}", idx));
        params_vec.push(Box::new(format!("%{}%", u)));
        idx += 1;
    }
    if let Some(e) = entry {
        conditions.push(format!(
            "(address_book_entry LIKE ?{} OR entry_display_name LIKE ?{})",
            idx, idx
        ));
        params_vec.push(Box::new(format!("%{}%", e)));
        idx += 1;
    }
    if let Some(t) = session_type {
        conditions.push(format!("session_type = ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
        idx += 1;
    }
    if let Some(f) = from {
        conditions.push(format!("started_at >= ?{}", idx));
        params_vec.push(Box::new(f.to_string()));
        idx += 1;
    }
    if let Some(t) = to {
        conditions.push(format!("started_at <= ?{}", idx));
        params_vec.push(Box::new(t.to_string()));
    }

    let where_clause = conditions.join(" AND ");
    let sql = format!(
        "SELECT session_id, session_type, hostname, port, username, created_by,
                COALESCE(entry_display_name, address_book_entry, \'\'),
                COALESCE(address_book_folder, \'\'),
                started_at, ended_at, duration_secs, status, recording_file,
                entry_display_name
         FROM session_history WHERE {} ORDER BY started_at DESC",
        where_clause
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut count = 0usize;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<i64>>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, String>(8)?,
            row.get::<_, Option<String>>(9)?,
            row.get::<_, Option<i64>>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, Option<String>>(12)?,
            row.get::<_, Option<String>>(13)?,
        ))
    })?;

    for row in rows {
        let (
            session_id,
            session_type,
            hostname,
            _port,
            username,
            created_by,
            entry,
            folder,
            started_at,
            ended_at,
            duration_secs,
            status,
            _recording,
            raw_entry_display_name,
        ) = row?;
        let fields = [
            &session_id,
            &session_type,
            &hostname,
            &username,
            &created_by,
            &entry,
            &folder,
            &started_at,
        ];
        for (i, f) in fields.iter().enumerate() {
            if i > 0 {
                write!(writer, ",")?;
            }
            csv_escape_field(writer, f)?;
        }
        write!(writer, ",")?;
        csv_escape_field(writer, ended_at.as_deref().unwrap_or(""))?;
        write!(writer, ",")?;
        if let Some(d) = duration_secs {
            write!(writer, "{}", d)?;
        }
        write!(writer, ",")?;
        csv_escape_field(writer, &status)?;
        write!(writer, ",")?;
        csv_escape_field(
            writer,
            &recording_display_name(
                &session_id,
                &hostname,
                &created_by,
                raw_entry_display_name.as_deref(),
                &started_at,
            ),
        )?;
        writeln!(writer)?;
        count += 1;
    }
    Ok(count)
}

/// Format a `YYYY-MM-DD HH:MM:SS` UTC timestamp (all backends store
/// `started_at` in this shape) as server-local `YYYY-MM-DD HH:MM`.
fn local_display_datetime(started_at: &str) -> Option<String> {
    let naive = chrono::NaiveDateTime::parse_from_str(started_at, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(
        Utc.from_utc_datetime(&naive)
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
    )
}

/// Human-readable "Recording" column value for CSV export:
/// `YYYY-MM-DD HH:MM — <entry> — <user>` where `<entry>` falls back from
/// `entry_display_name` to `hostname` to `session_id` and `<user>` falls
/// back to `unknown`. Display-only — the on-disk filename (`recording_file`)
/// is unchanged.
fn recording_display_name(
    session_id: &str,
    hostname: &str,
    created_by: &str,
    entry_display_name: Option<&str>,
    started_at: &str,
) -> String {
    let entry = entry_display_name
        .filter(|e| !e.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            if hostname.is_empty() {
                session_id.to_string()
            } else {
                hostname.to_string()
            }
        });
    let user = if created_by.is_empty() {
        "unknown".to_string()
    } else {
        created_by.to_string()
    };
    match local_display_datetime(started_at) {
        Some(d) => format!("{d} — {entry} — {user}"),
        None => format!("{entry} — {user}"),
    }
}

/// OWASP CSV-injection escaping for a single field — `pub` so regression
/// tests in `tests/security_regression.rs` exercise the real implementation
/// instead of a hand-maintained copy that could silently diverge from it.
pub fn csv_escape_field(w: &mut dyn std::io::Write, field: &str) -> std::io::Result<()> {
    // OWASP CSV injection prevention: prefix formula-triggering characters
    let safe_field = if let Some(first) = field.chars().next() {
        if matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r') {
            format!("'{}", field)
        } else {
            field.to_string()
        }
    } else {
        field.to_string()
    };

    if safe_field.contains(',')
        || safe_field.contains('"')
        || safe_field.contains('\n')
        || safe_field.contains('\r')
    {
        write!(w, "\"")?;
        for ch in safe_field.chars() {
            if ch == '"' {
                write!(w, "\"\"")?;
            } else {
                write!(w, "{}", ch)?;
            }
        }
        write!(w, "\"")?;
    } else {
        write!(w, "{}", safe_field)?;
    }
    Ok(())
}

/// Top connections by session count and total hours.
pub fn top_connections(db: &Db, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
    db_route!(db, top_connections_pool, limit);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT COALESCE(entry_display_name, hostname) AS name,
                address_book_entry, address_book_folder, session_type,
                COUNT(*) AS session_count,
                COALESCE(SUM(duration_secs), 0) AS total_secs
         FROM session_history
         GROUP BY COALESCE(address_book_entry, hostname || ':' || COALESCE(port, 0))
         ORDER BY session_count DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "name": row.get::<_, String>(0)?,
                "address_book_entry": row.get::<_, Option<String>>(1)?,
                "folder": row.get::<_, Option<String>>(2)?,
                "session_type": row.get::<_, Option<String>>(3)?,
                "session_count": row.get::<_, i64>(4)?,
                "total_hours": row.get::<_, i64>(5)? as f64 / 3600.0,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Top users by session count and total hours.
pub fn top_users(db: &Db, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
    db_route!(db, top_users_pool, limit);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT created_by,
                COUNT(*) AS session_count,
                COALESCE(SUM(duration_secs), 0) AS total_secs,
                MAX(started_at) AS last_session
         FROM session_history
         GROUP BY created_by
         ORDER BY session_count DESC
         LIMIT ?1",
    )?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(serde_json::json!({
                "user": row.get::<_, String>(0)?,
                "session_count": row.get::<_, i64>(1)?,
                "total_hours": row.get::<_, i64>(2)? as f64 / 3600.0,
                "last_session": row.get::<_, String>(3)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Summary statistics.
pub fn session_summary(db: &Db) -> rusqlite::Result<serde_json::Value> {
    db_route!(db, session_summary_pool);
    let conn = db.lock().unwrap();
    let total_sessions: i64 =
        conn.query_row("SELECT COUNT(*) FROM session_history", [], |row| row.get(0))?;
    let active_sessions: i64 = conn.query_row(
        "SELECT COUNT(*) FROM session_history WHERE status = 'active'",
        [],
        |row| row.get(0),
    )?;
    let total_users: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
        .unwrap_or(0);
    let uptime_secs = crate::metrics::uptime_seconds();
    Ok(serde_json::json!({
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "total_users": total_users,
        "uptime_secs": uptime_secs,
    }))
}

/// Return session counts grouped by hour for the last N hours.
pub fn session_activity_by_hour(db: &Db, hours: i32) -> rusqlite::Result<Vec<serde_json::Value>> {
    db_route!(db, session_activity_by_hour_pool, hours);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT strftime('%Y-%m-%d %H:00:00', started_at) AS hour,
                COUNT(*) AS count
         FROM session_history
         WHERE started_at >= datetime('now', ?1)
         GROUP BY hour
         ORDER BY hour ASC",
    )?;
    let modifier = format!("-{} hours", hours);
    let rows = stmt
        .query_map(rusqlite::params![modifier], |row| {
            Ok(serde_json::json!({
                "hour": row.get::<_, String>(0)?,
                "count": row.get::<_, i64>(1)?,
            }))
        })?
        .filter_map(|r| r.ok())
        .collect();
    Ok(rows)
}

/// Clean up old session history entries (retain last N days). Returns rows deleted.
pub fn cleanup_session_history(db: &Db, retain_days: u32) -> rusqlite::Result<usize> {
    db_route!(db, cleanup_session_history_pool, retain_days);
    if retain_days == 0 {
        return Ok(0); // 0 = keep forever
    }
    let conn = db.lock().unwrap();
    let modifier = format!("-{} days", retain_days);
    conn.execute(
        "DELETE FROM session_history WHERE started_at < datetime('now', ?1)",
        params![modifier],
    )
}

// ── TOTP secrets ──

/// TOTP secret record for a user.
#[derive(Debug, Clone)]
pub struct TotpSecret {
    /// Owning user's `users.id`, primary key of the table.
    pub user_id: i64,
    /// Shared secret, base32-encoded for the authenticator app.
    pub secret_b32: String,
    /// HMAC algorithm the token uses: `SHA1`, `SHA256`, or `SHA512`.
    pub algorithm: String,
    /// Token length in digits.
    pub digits: u8,
    /// Token rotation period in seconds.
    pub period: u16,
    /// Whether the user's TOTP factor is enforced.
    pub enabled: bool,
}

/// Store a TOTP secret for a user (upsert).
pub fn store_totp_secret(
    db: &Db,
    user_id: i64,
    secret_b32: &str,
    algorithm: &str,
    digits: u8,
    period: u16,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        store_totp_secret_pool,
        user_id,
        secret_b32.to_string(),
        algorithm.to_string(),
        digits,
        period
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO totp_secrets (user_id, secret_b32, algorithm, digits, period, enabled)
         VALUES (?1, ?2, ?3, ?4, ?5, 1)
         ON CONFLICT(user_id) DO UPDATE SET
             secret_b32 = excluded.secret_b32,
             algorithm = excluded.algorithm,
             digits = excluded.digits,
             period = excluded.period,
             enabled = 1",
        params![user_id, secret_b32, algorithm, digits as i64, period as i64],
    )?;
    Ok(())
}

/// Retrieve a TOTP secret by user_id.
pub fn get_totp_secret(db: &Db, user_id: i64) -> rusqlite::Result<Option<TotpSecret>> {
    db_route!(db, get_totp_secret_pool, user_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT user_id, secret_b32, algorithm, digits, period, enabled
         FROM totp_secrets WHERE user_id = ?1",
    )?;
    let mut rows = stmt.query_map(params![user_id], |row| {
        Ok(TotpSecret {
            user_id: row.get(0)?,
            secret_b32: row.get(1)?,
            algorithm: row.get(2)?,
            digits: row.get::<_, i64>(3)? as u8,
            period: row.get::<_, i64>(4)? as u16,
            enabled: row.get::<_, i64>(5)? != 0,
        })
    })?;
    rows.next().transpose()
}

/// Enable or disable TOTP for a user.
pub fn set_totp_enabled(db: &Db, user_id: i64, enabled: bool) -> rusqlite::Result<bool> {
    db_route!(db, set_totp_enabled_pool, user_id, enabled);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE totp_secrets SET enabled = ?1 WHERE user_id = ?2",
        params![enabled as i64, user_id],
    )?;
    Ok(changed > 0)
}

/// Delete a user's TOTP secret.
pub fn delete_totp_secret(db: &Db, user_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, delete_totp_secret_pool, user_id);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM totp_secrets WHERE user_id = ?1",
        params![user_id],
    )?;
    Ok(changed > 0)
}

/// Check if a user has TOTP enabled.
pub fn user_totp_enabled(db: &Db, user_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, user_totp_enabled_pool, user_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare("SELECT enabled FROM totp_secrets WHERE user_id = ?1")?;
    let mut rows = stmt.query_map(params![user_id], |row| row.get::<_, i64>(0).map(|v| v != 0))?;
    rows.next().transpose().map(|opt| opt.unwrap_or(false))
}

/// Resolve the best role for a user based on their OIDC groups and the group-to-role mappings.
/// Returns `Some(role)` if at least one group matched a mapping (highest wins),
/// or `None` if no mappings matched (caller should preserve the existing role).
pub fn resolve_role_from_groups(db: &Db, groups: &[String]) -> rusqlite::Result<Option<String>> {
    if groups.is_empty() {
        return Ok(None);
    }

    let mappings = list_group_mappings(db)?;
    if mappings.is_empty() {
        return Ok(None);
    }

    let mut best_level = 0u8;
    let mut best_role: Option<String> = None;

    for mapping in &mappings {
        if groups.iter().any(|g| g == &mapping.oidc_group) {
            let level = role_level(&mapping.role);
            if level > best_level {
                best_level = level;
                best_role = Some(mapping.role.clone());
            }
        }
    }

    Ok(best_role)
}

// ── Pending MFA (auth_pending_mfa) ──

/// Pending MFA record for a user mid-login.
#[derive(Debug, Clone)]
pub struct PendingMfa {
    /// Owning user's `users.id`.
    pub user_id: i64,
    /// Email for the MFA prompt.
    pub user_email: String,
    /// Display name for the MFA prompt.
    pub user_name: String,
    /// Role granted once MFA completes.
    pub user_role: String,
    /// OIDC subject carried through the pending login, so the post-MFA upsert matches the right user.
    pub oidc_subject: Option<String>,
    /// When the record was created (UTC).
    pub created_at: String,
    /// When the record expires; lookups ignore expired rows.
    pub expires_at: String,
}

/// Create a pending MFA record. Returns the raw token (set as cookie).
pub fn create_pending_mfa(
    db: &Db,
    user_id: i64,
    user_email: &str,
    user_name: &str,
    user_role: &str,
    oidc_subject: Option<&str>,
    ttl_secs: u64,
) -> rusqlite::Result<String> {
    db_route!(
        db,
        create_pending_mfa_pool,
        user_id,
        user_email.to_string(),
        user_name.to_string(),
        user_role.to_string(),
        oidc_subject.map(str::to_string),
        ttl_secs
    );
    let token = generate_key();
    let token_hash = hash_key(&token);
    let conn = db.lock().unwrap();
    let ttl_modifier = format!("+{} seconds", ttl_secs);
    conn.execute(
        "INSERT INTO auth_pending_mfa (token_hash, user_id, user_email, user_name, user_role, oidc_subject, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now', ?7))",
        params![token_hash, user_id, user_email, user_name, user_role, oidc_subject, ttl_modifier],
    )?;
    Ok(token)
}

/// Look up a pending MFA record by raw token.
pub fn get_pending_mfa(db: &Db, token: &str) -> rusqlite::Result<Option<PendingMfa>> {
    db_route!(db, get_pending_mfa_pool, token.to_string());
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT user_id, user_email, user_name, user_role, oidc_subject, created_at, expires_at
         FROM auth_pending_mfa WHERE token_hash = ?1 AND expires_at > datetime('now')",
    )?;
    let mut rows = stmt.query_map(params![token_hash], |row| {
        Ok(PendingMfa {
            user_id: row.get(0)?,
            user_email: row.get(1)?,
            user_name: row.get(2)?,
            user_role: row.get(3)?,
            oidc_subject: row.get(4)?,
            created_at: row.get(5)?,
            expires_at: row.get(6)?,
        })
    })?;
    rows.next().transpose()
}

/// Delete a pending MFA record by raw token.
pub fn delete_pending_mfa(db: &Db, token: &str) -> rusqlite::Result<bool> {
    db_route!(db, delete_pending_mfa_pool, token.to_string());
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM auth_pending_mfa WHERE token_hash = ?1",
        params![token_hash],
    )?;
    Ok(changed > 0)
}

/// Clean up expired pending MFA records.
pub fn cleanup_expired_pending_mfa(db: &Db) -> rusqlite::Result<usize> {
    db_route!(db, cleanup_expired_pending_mfa_pool);
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_pending_mfa WHERE expires_at <= datetime('now')",
        [],
    )
}

// ── Jump hosts (SSH tunnel management) ──

/// Jump host record for API responses.
#[derive(Debug, Clone, serde::Serialize)]
pub struct JumpHostRecord {
    /// Jump host UUID, primary key.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Jump host address.
    pub hostname: String,
    /// SSH port.
    pub port: u16,
    /// SSH login user.
    pub username: String,
    /// How the jump host authenticates: `key` or `password`.
    pub auth_method: String,
    /// Path to the private key on the server, when `auth_method` is `key`.
    pub key_path: Option<String>,
    /// When the record was created (UTC).
    pub created_at: String,
    /// When the record was last updated, if ever.
    pub updated_at: Option<String>,
}

/// Create a new jump host. Returns the generated ID.
pub fn create_jump_host(
    db: &Db,
    name: &str,
    hostname: &str,
    port: u16,
    username: &str,
    auth_method: &str,
    key_path: Option<&str>,
) -> rusqlite::Result<String> {
    db_route!(
        db,
        create_jump_host_pool,
        name.to_string(),
        hostname.to_string(),
        port,
        username.to_string(),
        auth_method.to_string(),
        key_path.map(str::to_string)
    );
    let id = generate_key();
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO jump_hosts (id, name, hostname, port, username, auth_method, key_path)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            name,
            hostname,
            port as i64,
            username,
            auth_method,
            key_path
        ],
    )?;
    Ok(id)
}

/// List all jump hosts.
pub fn list_jump_hosts(db: &Db) -> rusqlite::Result<Vec<JumpHostRecord>> {
    db_route!(db, list_jump_hosts_pool);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at
         FROM jump_hosts ORDER BY name",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(JumpHostRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            hostname: row.get(2)?,
            port: row.get::<_, i64>(3)? as u16,
            username: row.get(4)?,
            auth_method: row.get(5)?,
            key_path: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    })?;
    rows.collect()
}

/// Get a single jump host by ID.
pub fn get_jump_host(db: &Db, id: &str) -> rusqlite::Result<Option<JumpHostRecord>> {
    db_route!(db, get_jump_host_pool, id.to_string());
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at
         FROM jump_hosts WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id], |row| {
        Ok(JumpHostRecord {
            id: row.get(0)?,
            name: row.get(1)?,
            hostname: row.get(2)?,
            port: row.get::<_, i64>(3)? as u16,
            username: row.get(4)?,
            auth_method: row.get(5)?,
            key_path: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    })?;
    rows.next().transpose()
}

/// Update a jump host by ID.
#[allow(clippy::too_many_arguments)]
pub fn update_jump_host(
    db: &Db,
    id: &str,
    name: &str,
    hostname: &str,
    port: u16,
    username: &str,
    auth_method: &str,
    key_path: Option<&str>,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        update_jump_host_pool,
        id.to_string(),
        name.to_string(),
        hostname.to_string(),
        port,
        username.to_string(),
        auth_method.to_string(),
        key_path.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE jump_hosts SET name = ?1, hostname = ?2, port = ?3, username = ?4,
         auth_method = ?5, key_path = ?6, updated_at = datetime('now') WHERE id = ?7",
        params![
            name,
            hostname,
            port as i64,
            username,
            auth_method,
            key_path,
            id
        ],
    )?;
    Ok(changed > 0)
}

/// Delete a jump host by ID.
pub fn delete_jump_host(db: &Db, id: &str) -> rusqlite::Result<bool> {
    db_route!(db, delete_jump_host_pool, id.to_string());
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM jump_hosts WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ── Address book (DB-backed storage) ──

/// DB record for an address book folder.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AbFolder {
    /// Primary key.
    pub id: i64,
    /// Address book the folder lives in: `shared` for the cross-instance book, other values scope it to one instance.
    pub scope: String,
    /// Folder name, unique within its parent scope and path.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Comma-separated group names allowed to use this folder (empty = open).
    pub allowed_groups: String,
    /// Whether subfolders inherit this folder's allowed_groups.
    pub inherit_from_parent: bool,
    /// When the folder was created (UTC).
    pub created_at: String,
    /// When the folder was last modified (UTC).
    pub updated_at: String,
}

/// DB record for an address book entry (metadata only, no credentials).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AbEntry {
    /// Primary key.
    pub id: i64,
    /// Parent folder's `address_book_folders.id`.
    pub folder_id: i64,
    /// Entry name, unique within its folder.
    pub name: String,
    /// Name shown in the UI; falls back to `name` when empty.
    pub display_name: String,
    /// Connection protocol: `ssh`, `rdp`, `vnc`, `spice`, `web`, `vdi`, or `proxmox`.
    pub protocol: String,
    /// Target host.
    pub hostname: String,
    /// Target port; `None` uses the protocol default.
    pub port: Option<u16>,
    /// Login username.
    pub username: String,
    /// Protocol-specific parameters as JSON: custom fields, jump hosts, domain, and so on.
    pub protocol_config: String,
    /// Comma-separated local group names allowed to connect; empty means open to everyone.
    pub allowed_groups: String,
    /// When the entry was created (UTC).
    pub created_at: String,
    /// When the entry was last modified (UTC).
    pub updated_at: String,
}

/// DB record for an encrypted credential.
#[derive(Debug, Clone)]
pub struct AbCredential {
    /// Primary key.
    pub id: i64,
    /// Owning entry's `address_book_entries.id`.
    pub entry_id: i64,
    /// Credential kind: `password` or `private_key`.
    pub credential_type: String,
    /// AES-256-GCM encrypted payload: `enc:v1:` plus base64 nonce, ciphertext, and tag.
    pub credential_data: String,
}

/// Create a new address book folder. Returns the folder ID.
pub fn create_ab_folder(
    db: &Db,
    scope: &str,
    name: &str,
    description: &str,
    allowed_groups: &str,
    inherit_from_parent: bool,
) -> rusqlite::Result<i64> {
    db_route!(
        db,
        create_ab_folder_pool,
        scope.to_string(),
        name.to_string(),
        description.to_string(),
        allowed_groups.to_string(),
        inherit_from_parent
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO address_book_folders (scope, name, description, allowed_groups, inherit_from_parent)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![scope, name, description, allowed_groups, inherit_from_parent as i64],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Update folder metadata (description / ACLs). Returns false if the folder
/// does not exist.
pub fn update_ab_folder(
    db: &Db,
    scope: &str,
    name: &str,
    description: &str,
    allowed_groups: &str,
    inherit_from_parent: bool,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        update_ab_folder_pool,
        scope.to_string(),
        name.to_string(),
        description.to_string(),
        allowed_groups.to_string(),
        inherit_from_parent
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE address_book_folders
         SET description = ?3, allowed_groups = ?4, inherit_from_parent = ?5, updated_at = datetime('now')
         WHERE scope = ?1 AND name = ?2",
        params![scope, name, description, allowed_groups, inherit_from_parent as i64],
    )?;
    Ok(changed > 0)
}

/// List all address book folders, optionally filtered by scope.
pub fn list_ab_folders(db: &Db, scope: Option<&str>) -> rusqlite::Result<Vec<AbFolder>> {
    db_route!(db, list_ab_folders_pool, scope.map(str::to_string));
    let conn = db.lock().unwrap();
    let (sql, params_vec): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match scope {
        Some(s) => (
            "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at
             FROM address_book_folders WHERE scope = ?1 ORDER BY name",
            vec![Box::new(s.to_string())],
        ),
        None => (
            "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at
             FROM address_book_folders ORDER BY scope, name",
            vec![],
        ),
    };
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
        Ok(AbFolder {
            id: row.get(0)?,
            scope: row.get(1)?,
            name: row.get(2)?,
            description: row.get(3)?,
            allowed_groups: row.get(4)?,
            inherit_from_parent: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        })
    })?;
    rows.collect()
}

/// Get a folder by scope and name.
pub fn get_ab_folder(db: &Db, scope: &str, name: &str) -> rusqlite::Result<AbFolder> {
    db_route!(db, get_ab_folder_pool, scope.to_string(), name.to_string());
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at
         FROM address_book_folders WHERE scope = ?1 AND name = ?2",
        params![scope, name],
        |row| {
            Ok(AbFolder {
                id: row.get(0)?,
                scope: row.get(1)?,
                name: row.get(2)?,
                description: row.get(3)?,
                allowed_groups: row.get(4)?,
                inherit_from_parent: row.get(5)?,
                created_at: row.get(6)?,
                updated_at: row.get(7)?,
            })
        },
    )
}

/// Delete a folder and cascade-delete its entries/credentials.
pub fn delete_ab_folder(db: &Db, scope: &str, name: &str) -> rusqlite::Result<bool> {
    db_route!(
        db,
        delete_ab_folder_pool,
        scope.to_string(),
        name.to_string()
    );
    let mut conn = db.lock().unwrap();
    // SQLite runs without PRAGMA foreign_keys, so the FK cascade never
    // fires — delete entries + credentials explicitly, in one transaction.
    let tx = conn.transaction()?;
    let entry_ids: Vec<i64> = {
        let mut stmt = tx.prepare(
            "SELECT id FROM address_book_entries WHERE folder_id IN
             (SELECT id FROM address_book_folders WHERE scope = ?1 AND name = ?2)",
        )?;
        let rows = stmt.query_map(params![scope, name], |r| r.get::<_, i64>(0))?;
        rows.filter_map(|r| r.ok()).collect()
    };
    for id in &entry_ids {
        tx.execute(
            "DELETE FROM address_book_credentials WHERE entry_id = ?1",
            params![id],
        )?;
    }
    tx.execute(
        "DELETE FROM address_book_entries WHERE folder_id IN
         (SELECT id FROM address_book_folders WHERE scope = ?1 AND name = ?2)",
        params![scope, name],
    )?;
    let changed = tx.execute(
        "DELETE FROM address_book_folders WHERE scope = ?1 AND name = ?2",
        params![scope, name],
    )?;
    tx.commit()?;
    Ok(changed > 0)
}

/// Create an address book entry. Returns the entry ID.
#[allow(clippy::too_many_arguments)]
pub fn create_ab_entry(
    db: &Db,
    folder_id: i64,
    name: &str,
    display_name: &str,
    protocol: &str,
    hostname: &str,
    port: Option<u16>,
    username: &str,
    protocol_config: &str,
    allowed_groups: &str,
) -> rusqlite::Result<i64> {
    db_route!(
        db,
        create_ab_entry_pool,
        folder_id,
        name.to_string(),
        display_name.to_string(),
        protocol.to_string(),
        hostname.to_string(),
        port.map(|p| p as i64),
        username.to_string(),
        protocol_config.to_string(),
        allowed_groups.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO address_book_entries
         (folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![folder_id, name, display_name, protocol, hostname, port.map(|p| p as i64), username, protocol_config, allowed_groups],
    )?;
    Ok(conn.last_insert_rowid())
}

/// List entries in a folder.
pub fn list_ab_entries(db: &Db, folder_id: i64) -> rusqlite::Result<Vec<AbEntry>> {
    db_route!(db, list_ab_entries_pool, folder_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, folder_id, name, display_name, protocol, hostname, port,
                username, protocol_config, allowed_groups, created_at, updated_at
         FROM address_book_entries WHERE folder_id = ?1 ORDER BY name",
    )?;
    let rows = stmt.query_map(params![folder_id], |row| {
        Ok(AbEntry {
            id: row.get(0)?,
            folder_id: row.get(1)?,
            name: row.get(2)?,
            display_name: row.get(3)?,
            protocol: row.get(4)?,
            hostname: row.get(5)?,
            port: row.get::<_, Option<i64>>(6)?.map(|p| p as u16),
            username: row.get(7)?,
            protocol_config: row.get(8)?,
            allowed_groups: row.get(9)?,
            created_at: row.get(10)?,
            updated_at: row.get(11)?,
        })
    })?;
    rows.collect()
}

/// Get a single entry by folder_id and name.
pub fn get_ab_entry(db: &Db, folder_id: i64, name: &str) -> rusqlite::Result<AbEntry> {
    db_route!(db, get_ab_entry_pool, folder_id, name.to_string());
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, folder_id, name, display_name, protocol, hostname, port,
                username, protocol_config, allowed_groups, created_at, updated_at
         FROM address_book_entries WHERE folder_id = ?1 AND name = ?2",
        params![folder_id, name],
        |row| {
            Ok(AbEntry {
                id: row.get(0)?,
                folder_id: row.get(1)?,
                name: row.get(2)?,
                display_name: row.get(3)?,
                protocol: row.get(4)?,
                hostname: row.get(5)?,
                port: row.get::<_, Option<i64>>(6)?.map(|p| p as u16),
                username: row.get(7)?,
                protocol_config: row.get(8)?,
                allowed_groups: row.get(9)?,
                created_at: row.get(10)?,
                updated_at: row.get(11)?,
            })
        },
    )
}

/// Update an address book entry.
#[allow(clippy::too_many_arguments)]
pub fn update_ab_entry(
    db: &Db,
    entry_id: i64,
    display_name: &str,
    protocol: &str,
    hostname: &str,
    port: Option<u16>,
    username: &str,
    protocol_config: &str,
    allowed_groups: &str,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        update_ab_entry_pool,
        entry_id,
        display_name.to_string(),
        protocol.to_string(),
        hostname.to_string(),
        port.map(|p| p as i64),
        username.to_string(),
        protocol_config.to_string(),
        allowed_groups.to_string()
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE address_book_entries SET
         display_name = ?2, protocol = ?3, hostname = ?4, port = ?5,
         username = ?6, protocol_config = ?7, allowed_groups = ?8,
         updated_at = datetime('now')
         WHERE id = ?1",
        params![
            entry_id,
            display_name,
            protocol,
            hostname,
            port.map(|p| p as i64),
            username,
            protocol_config,
            allowed_groups
        ],
    )?;
    Ok(changed > 0)
}

/// Delete an entry and cascade-delete its credentials.
pub fn delete_ab_entry(db: &Db, entry_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, delete_ab_entry_pool, entry_id);
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    tx.execute(
        "DELETE FROM address_book_credentials WHERE entry_id = ?1",
        params![entry_id],
    )?;
    let changed = tx.execute(
        "DELETE FROM address_book_entries WHERE id = ?1",
        params![entry_id],
    )?;
    tx.commit()?;
    Ok(changed > 0)
}

/// Store (upsert) an encrypted credential for an entry.
pub fn store_ab_credential(
    db: &Db,
    entry_id: i64,
    credential_type: &str,
    credential_data: &str,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        store_ab_credential_pool,
        entry_id,
        credential_type.to_string(),
        credential_data.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO address_book_credentials (entry_id, credential_type, credential_data)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(entry_id, credential_type) DO UPDATE SET
         credential_data = excluded.credential_data, updated_at = datetime('now')",
        params![entry_id, credential_type, credential_data],
    )?;
    Ok(())
}

/// Get a credential by entry ID and type.
pub fn get_ab_credential(
    db: &Db,
    entry_id: i64,
    credential_type: &str,
) -> rusqlite::Result<AbCredential> {
    db_route!(
        db,
        get_ab_credential_pool,
        entry_id,
        credential_type.to_string()
    );
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, entry_id, credential_type, credential_data
         FROM address_book_credentials WHERE entry_id = ?1 AND credential_type = ?2",
        params![entry_id, credential_type],
        |row| {
            Ok(AbCredential {
                id: row.get(0)?,
                entry_id: row.get(1)?,
                credential_type: row.get(2)?,
                credential_data: row.get(3)?,
            })
        },
    )
}

/// List all credential types for an entry.
pub fn list_ab_credentials(db: &Db, entry_id: i64) -> rusqlite::Result<Vec<AbCredential>> {
    db_route!(db, list_ab_credentials_pool, entry_id);
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, entry_id, credential_type, credential_data
         FROM address_book_credentials WHERE entry_id = ?1 ORDER BY credential_type",
    )?;
    let rows = stmt.query_map(params![entry_id], |row| {
        Ok(AbCredential {
            id: row.get(0)?,
            entry_id: row.get(1)?,
            credential_type: row.get(2)?,
            credential_data: row.get(3)?,
        })
    })?;
    rows.collect()
}

/// Delete a credential by entry ID and type.
pub fn delete_ab_credential(
    db: &Db,
    entry_id: i64,
    credential_type: &str,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        delete_ab_credential_pool,
        entry_id,
        credential_type.to_string()
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM address_book_credentials WHERE entry_id = ?1 AND credential_type = ?2",
        params![entry_id, credential_type],
    )?;
    Ok(changed > 0)
}

/// Check if a folder has entries that match allowed_groups.
pub fn folder_has_allowed_groups(
    db: &Db,
    scope: &str,
    folder_name: &str,
) -> rusqlite::Result<bool> {
    db_route!(
        db,
        folder_has_allowed_groups_pool,
        scope.to_string(),
        folder_name.to_string()
    );
    let conn = db.lock().unwrap();
    let folder_id: i64 = conn
        .query_row(
            "SELECT id FROM address_book_folders WHERE scope = ?1 AND name = ?2",
            params![scope, folder_name],
            |row| row.get(0),
        )
        .map_err(|_| rusqlite::Error::QueryReturnedNoRows)?;
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM address_book_entries
         WHERE folder_id = ?1 AND allowed_groups != ''",
        params![folder_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_key_sha256() {
        let hash = hash_key("test-api-key");
        assert_eq!(hash.len(), 64); // SHA-256 = 64 hex chars
                                    // Deterministic
        assert_eq!(hash, hash_key("test-api-key"));
    }

    #[test]
    fn test_hash_key_different_inputs() {
        assert_ne!(hash_key("key-a"), hash_key("key-b"));
    }

    #[test]
    fn test_hash_key_salt_format_and_validation() {
        let stored = hash_key_salt("test-api-key");
        // Format: hex(16 bytes):hex(32 bytes) = 32:64 hex chars
        let (salt_hex, hash_hex) = stored.split_once(':').unwrap();
        assert_eq!(salt_hex.len(), 32);
        assert_eq!(hash_hex.len(), 64);
        // Correct key validates
        assert!(validate_stored_hash("test-api-key", &stored));
        // Wrong key does not
        assert!(!validate_stored_hash("wrong-key", &stored));
        // Two calls produce different salts (non-deterministic)
        let stored2 = hash_key_salt("test-api-key");
        assert_ne!(stored, stored2);
        assert!(validate_stored_hash("test-api-key", &stored2));
    }

    #[test]
    fn test_validate_stored_hash_legacy_unsalted() {
        let legacy = hash_key("legacy-key");
        assert!(validate_stored_hash("legacy-key", &legacy));
        assert!(!validate_stored_hash("wrong", &legacy));
    }

    #[test]
    fn test_generate_key_format() {
        let key = generate_key();
        assert_eq!(key.len(), 64); // 32 bytes = 64 hex chars
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_key_unique() {
        let a = generate_key();
        let b = generate_key();
        assert_ne!(a, b);
    }

    #[test]
    fn test_user_groups_vec() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            custom_role_id: None,
            disabled: false,
            oidc_groups: "admins,developers,ops".into(),
        };
        assert_eq!(user.groups_vec(), vec!["admins", "developers", "ops"]);
    }

    #[test]
    fn test_user_groups_vec_empty() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            custom_role_id: None,
            disabled: false,
            oidc_groups: String::new(),
        };
        assert!(user.groups_vec().is_empty());
    }

    #[test]
    fn test_user_groups_vec_single() {
        let user = User {
            id: 1,
            oidc_subject: None,
            created_at: "2025-01-01".into(),
            last_login_at: None,
            email: "test@test.com".into(),
            name: "test".into(),
            role: "viewer".into(),
            custom_role_id: None,
            disabled: false,
            oidc_groups: "solo-group".into(),
        };
        assert_eq!(user.groups_vec(), vec!["solo-group"]);
    }

    fn test_db() -> Db {
        init_db(std::path::Path::new(":memory:")).unwrap()
    }

    #[test]
    fn test_session_history_insert_and_query() {
        let db = test_db();
        insert_session_history(
            &db,
            "sess-1",
            "rdp",
            "10.0.0.1",
            Some(3389),
            "bench01",
            "dave@example.com",
            Some("shared/prod/rdp-host-1"),
            Some("prod"),
            Some("RDP Host 1"),
        )
        .unwrap();
        insert_session_history(
            &db,
            "sess-2",
            "ssh",
            "10.0.0.2",
            Some(22),
            "bench02",
            "andy@example.com",
            None,
            None,
            None,
        )
        .unwrap();

        let (rows, total) =
            query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 2);
        assert_eq!(rows.len(), 2);
        // Most recent first
        assert_eq!(rows[0]["session_id"], "sess-2");
        assert_eq!(rows[1]["session_id"], "sess-1");
    }

    #[test]
    fn test_session_history_filter_by_user() {
        let db = test_db();
        insert_session_history(
            &db,
            "s1",
            "rdp",
            "h1",
            None,
            "",
            "dave@example.com",
            None,
            None,
            None,
        )
        .unwrap();
        insert_session_history(
            &db,
            "s2",
            "ssh",
            "h2",
            None,
            "",
            "andy@example.com",
            None,
            None,
            None,
        )
        .unwrap();

        let (rows, total) =
            query_session_history(&db, Some("dave"), None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["created_by"], "dave@example.com");
    }

    #[test]
    fn test_session_history_filter_by_type() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h1", None, "", "user1", None, None, None)
            .unwrap();
        insert_session_history(&db, "s2", "ssh", "h2", None, "", "user2", None, None, None)
            .unwrap();

        let (rows, total) =
            query_session_history(&db, None, None, Some("ssh"), None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["session_type"], "ssh");
    }

    #[test]
    fn test_session_history_end() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h1", None, "", "user1", None, None, None)
            .unwrap();
        end_session_history(&db, "s1", "completed", 3600, Some("s1.guac")).unwrap();

        let (rows, _) = query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(rows[0]["status"], "completed");
        assert_eq!(rows[0]["duration_secs"], 3600);
        assert_eq!(rows[0]["recording_file"], "s1.guac");
    }

    #[test]
    fn test_top_connections() {
        let db = test_db();
        for i in 0..5 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "rdp",
                "host-a",
                None,
                "",
                "user1",
                Some("shared/prod/host-a"),
                Some("prod"),
                Some("Host A"),
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 600, None).unwrap();
        }
        for i in 5..7 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "ssh",
                "host-b",
                None,
                "",
                "user2",
                Some("shared/dev/host-b"),
                Some("dev"),
                Some("Host B"),
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 300, None).unwrap();
        }

        let top = top_connections(&db, 10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["name"], "Host A");
        assert_eq!(top[0]["session_count"], 5);
        assert_eq!(top[1]["name"], "Host B");
        assert_eq!(top[1]["session_count"], 2);
    }

    #[test]
    fn test_top_users() {
        let db = test_db();
        for i in 0..3 {
            insert_session_history(
                &db,
                &format!("s{}", i),
                "rdp",
                "h",
                None,
                "",
                "alice@co.com",
                None,
                None,
                None,
            )
            .unwrap();
            end_session_history(&db, &format!("s{}", i), "completed", 1800, None).unwrap();
        }
        insert_session_history(
            &db,
            "s9",
            "ssh",
            "h",
            None,
            "",
            "bob@co.com",
            None,
            None,
            None,
        )
        .unwrap();
        end_session_history(&db, "s9", "completed", 3600, None).unwrap();

        let top = top_users(&db, 10).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0]["user"], "alice@co.com");
        assert_eq!(top[0]["session_count"], 3);
        assert_eq!(top[1]["user"], "bob@co.com");
        assert_eq!(top[1]["session_count"], 1);
    }

    #[test]
    fn test_session_summary() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h", None, "", "alice", None, None, None).unwrap();
        end_session_history(&db, "s1", "completed", 7200, None).unwrap();
        insert_session_history(&db, "s2", "ssh", "h", None, "", "bob", None, None, None).unwrap();
        // s2 still active
        upsert_user(&db, "alice@co.com", "alice", None, "admin", &[]).unwrap();
        upsert_user(&db, "bob@co.com", "bob", None, "viewer", &[]).unwrap();

        let summary = session_summary(&db).unwrap();
        assert_eq!(summary["total_sessions"], 2);
        assert_eq!(summary["total_users"], 2);
        assert_eq!(summary["active_sessions"], 1);
        assert_eq!(summary["uptime_secs"], crate::metrics::uptime_seconds());
    }

    #[test]
    fn test_cleanup_session_history_zero_keeps_all() {
        let db = test_db();
        insert_session_history(&db, "s1", "rdp", "h", None, "", "u", None, None, None).unwrap();
        let deleted = cleanup_session_history(&db, 0).unwrap();
        assert_eq!(deleted, 0);
        let (_, total) = query_session_history(&db, None, None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
    }

    #[test]
    fn test_session_history_pagination() {
        let db = test_db();
        for i in 0..25 {
            insert_session_history(
                &db,
                &format!("s{:02}", i),
                "rdp",
                "h",
                None,
                "",
                "u",
                None,
                None,
                None,
            )
            .unwrap();
        }

        let (rows, total) =
            query_session_history(&db, None, None, None, None, None, 10, 0).unwrap();
        assert_eq!(total, 25);
        assert_eq!(rows.len(), 10);

        let (rows2, _) = query_session_history(&db, None, None, None, None, None, 10, 10).unwrap();
        assert_eq!(rows2.len(), 10);

        let (rows3, _) = query_session_history(&db, None, None, None, None, None, 10, 20).unwrap();
        assert_eq!(rows3.len(), 5);
    }

    // ── OIDC groups bounds (end-to-end) ─────────────────────────────────
    // Verifies the pipeline: a large input list passes through
    // upsert_seen_groups into the DB without growing unbounded. The
    // front-end cap lives in oidc::extract_groups_from_jwt; this test
    // covers the DB side — it must accept any input without blowing up
    // and de-duplicate on repeat logins.

    #[test]
    fn seen_groups_upsert_deduplicates() {
        let db = test_db();
        upsert_seen_groups(&db, &["admins".into(), "ops".into(), "admins".into()]).unwrap();
        // Second login with overlapping groups.
        upsert_seen_groups(&db, &["admins".into(), "new".into()]).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert!(groups.contains(&"admins".into()));
        assert!(groups.contains(&"ops".into()));
        assert!(groups.contains(&"new".into()));
        // No duplicates.
        let mut sorted = groups.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(groups.len(), sorted.len());
    }

    #[test]
    fn seen_groups_upsert_skips_empty() {
        let db = test_db();
        upsert_seen_groups(&db, &["".into(), " ".into(), "\t".into(), "valid".into()]).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert_eq!(groups, vec!["valid".to_string()]);
    }

    #[test]
    fn seen_groups_upsert_accepts_large_batch_without_panic() {
        // The OIDC layer caps arrays at 64 entries, but the DB must accept
        // whatever is passed without integer/row overflow.
        let db = test_db();
        let many: Vec<String> = (0..500).map(|i| format!("group-{i:04}")).collect();
        upsert_seen_groups(&db, &many).unwrap();
        let groups = list_known_groups(&db).unwrap();
        assert_eq!(groups.len(), 500);
    }

    #[test]
    fn seen_groups_tolerates_special_characters() {
        // Group names from arbitrary IdPs may contain `'`, spaces, etc.
        // Parameterised query must bind them safely (regression test vs
        // any future refactor that concatenates names into SQL).
        let db = test_db();
        let names = vec![
            "DROP TABLE seen_groups;--".into(),
            "ops; SELECT * FROM users".into(),
            "alice's-group".into(),
            "Domain Admins".into(),
        ];
        upsert_seen_groups(&db, &names).unwrap();
        let got = list_known_groups(&db).unwrap();
        for n in &names {
            assert!(got.contains(n), "missing: {n:?}");
        }
    }

    #[test]
    fn ensure_local_groups_provisions_once_and_skips_invalid() {
        let db = test_db();
        let created = ensure_local_groups(&db, &["ops".into(), "platform".into()]).unwrap();
        assert_eq!(created, 2);
        // Second call is a no-op.
        let created = ensure_local_groups(&db, &["ops".into()]).unwrap();
        assert_eq!(created, 0);
        // Commas are rejected (would corrupt the folder ACL column format).
        let created = ensure_local_groups(&db, &["a,b".into()]).unwrap();
        assert_eq!(created, 0);
        // The groups are visible to the group API.
        let rows = list_local_groups(&db).unwrap();
        assert!(rows.iter().any(|g| g.name == "ops"));
    }

    #[test]
    fn parse_expires_at_accepts_expected_formats() {
        assert!(parse_expires_at("2030-01-01T00:00:00Z").is_some()); // RFC 3339
        assert!(parse_expires_at("2030-01-01 00:00:00").is_some()); // SQLite datetime
        assert!(parse_expires_at("2030-01-01T00:00:00").is_some()); // ISO, no zone
        assert!(parse_expires_at("2030-12-31").is_some()); // bare date
                                                           // Garbage / empty must be None so the caller fails closed.
        assert!(parse_expires_at("not-a-date").is_none());
        assert!(parse_expires_at("").is_none());
        assert!(parse_expires_at("2026-13-40").is_none());
        // Bare date resolves to end-of-day UTC, not midnight.
        assert_eq!(
            parse_expires_at("2030-06-15").unwrap(),
            Utc.with_ymd_and_hms(2030, 6, 15, 23, 59, 59).unwrap()
        );
    }

    #[test]
    fn admin_key_expiry_fails_closed() {
        let db = test_db();
        // Past expiry -> expired.
        let k = add_admin(&db, "past", None, Some("2000-01-01T00:00:00Z")).unwrap();
        assert!(matches!(
            validate_api_key(&db, &k, None),
            Err(AuthError::Expired)
        ));
        // Malformed expiry -> expired (fail closed; previously authenticated forever).
        let k = add_admin(&db, "garbage", None, Some("whenever")).unwrap();
        assert!(matches!(
            validate_api_key(&db, &k, None),
            Err(AuthError::Expired)
        ));
        // Future expiry and no expiry -> valid.
        let k = add_admin(&db, "future", None, Some("2999-01-01T00:00:00Z")).unwrap();
        assert!(validate_api_key(&db, &k, None).is_ok());
        let k = add_admin(&db, "none", None, None).unwrap();
        assert!(validate_api_key(&db, &k, None).is_ok());
    }
}

// ── Local groups + provider-group mappings ────────────────────────────
// This block was appended at the end of the file because parallel workstreams
// may be editing db.rs.
//
// Local groups are admin-defined named groups that folders/connections can
// grant access to. Auth-provider groups (OIDC/LDAP claim groups, see
// `list_known_groups`) are mapped onto them via `group_mappings`; one
// provider group maps to at most one local group.
//
// NOTE: group names remain free-form strings — folder `allowed_groups`
// reference a local group by its *name*, not its id. Renaming a local group
// does not rewrite folder references, and deleting one leaves folder
// `allowed_groups` untouched (anyone whose claims carry that name keeps
// access).

/// A local group with usage counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalGroup {
    /// Primary key.
    pub id: i64,
    /// Group name. Folder and entry `allowed_groups` reference groups by this name, so renaming breaks those references.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Whether the group came from a provider-group mapping rather than an admin.
    pub auto_provisioned: bool,
    /// When the group was created (UTC).
    pub created_at: String,
    /// Number of auth-provider groups mapped to this local group.
    pub provider_group_count: i64,
    /// Number of address-book folders whose own `allowed_groups` or entries'
    /// `allowed_groups` reference this group name (vault-side folder configs
    /// are not scanned).
    pub folder_count: i64,
}

/// A mapping from an auth-provider group name to a local group.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderGroupMapping {
    /// Primary key.
    pub id: i64,
    /// The local group this mapping feeds.
    pub group_id: i64,
    /// Auth-provider (OIDC or LDAP claim) group name.
    pub provider_group: String,
    /// When the mapping was created (UTC).
    pub created_at: String,
}

fn local_group_row(row: &rusqlite::Row) -> rusqlite::Result<LocalGroup> {
    Ok(LocalGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        auto_provisioned: row.get::<_, i64>(3)? != 0,
        created_at: row.get(4)?,
        provider_group_count: row.get(5)?,
        folder_count: row.get(6)?,
    })
}

/// COUNTs computed for every local group listing. `folder_count` counts
/// distinct address-book folders referenced by both the folder's own
/// `allowed_groups` and its entries' `allowed_groups` (INSTR is
/// case-sensitive, matching the exact-match semantics of
/// `resolve_folder_access`).
const LOCAL_GROUP_COLUMNS: &str =
    "lg.id, lg.name, lg.description, lg.auto_provisioned, lg.created_at, \
     (SELECT COUNT(*) FROM group_mappings gm WHERE gm.group_id = lg.id), \
     (SELECT COUNT(DISTINCT x.id) FROM (\
       SELECT f.id FROM address_book_folders f \
         WHERE INSTR(',' || f.allowed_groups || ',', ',' || lg.name || ',') > 0 \
       UNION \
       SELECT e.folder_id FROM address_book_entries e \
         WHERE INSTR(',' || e.allowed_groups || ',', ',' || lg.name || ',') > 0 \
     ) x)";

/// List all local groups with usage counts, ordered by name.
pub fn list_local_groups(db: &Db) -> rusqlite::Result<Vec<LocalGroup>> {
    db_route!(db, list_local_groups_pool);
    let conn = db.lock().unwrap();
    let sql = format!(
        "SELECT {} FROM local_groups lg ORDER BY lg.name COLLATE NOCASE",
        LOCAL_GROUP_COLUMNS
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], local_group_row)?;
    rows.collect()
}

/// Fetch a single local group by id (with usage counts), or `None`.
pub fn get_local_group(db: &Db, id: i64) -> rusqlite::Result<Option<LocalGroup>> {
    db_route!(db, get_local_group_pool, id);
    let conn = db.lock().unwrap();
    let sql = format!(
        "SELECT {} FROM local_groups lg WHERE lg.id = ?1",
        LOCAL_GROUP_COLUMNS
    );
    match conn.query_row(&sql, params![id], local_group_row) {
        Ok(g) => Ok(Some(g)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Create a local group. Returns the new group (with usage counts).
/// The UNIQUE name constraint is enforced by the schema; callers surface
/// UNIQUE violations as 409 conflicts.
pub fn create_local_group(db: &Db, name: &str, description: &str) -> rusqlite::Result<LocalGroup> {
    db_route!(
        db,
        create_local_group_pool,
        name.to_string(),
        description.to_string()
    );
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO local_groups (name, description) VALUES (?1, ?2)",
        params![name, description],
    )?;
    let id = conn.last_insert_rowid();
    let sql = format!(
        "SELECT {} FROM local_groups lg WHERE lg.id = ?1",
        LOCAL_GROUP_COLUMNS
    );
    conn.query_row(&sql, params![id], local_group_row)
}

/// Count how many address_book_folders and address_book_entries reference
/// `group_name` in their `allowed_groups` column. Used to block renames
/// that would leave stale ACL references.
pub fn count_group_name_references(db: &Db, group_name: &str) -> rusqlite::Result<i64> {
    db_route!(db, count_group_name_references_pool, group_name.to_string());
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT
           (SELECT COUNT(*) FROM address_book_folders
              WHERE INSTR(',' || allowed_groups || ',', ',' || ?1 || ',') > 0)
         + (SELECT COUNT(*) FROM address_book_entries
              WHERE INSTR(',' || allowed_groups || ',', ',' || ?1 || ',') > 0)",
        params![group_name],
        |row| row.get(0),
    )
}

/// Update a local group (rename / re-describe). `None` fields keep their
/// current value. Returns the updated group (with usage counts), or `None`
/// if the id is unknown.
pub fn update_local_group(
    db: &Db,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
) -> rusqlite::Result<Option<LocalGroup>> {
    db_route!(
        db,
        update_local_group_pool,
        id,
        name.map(str::to_string),
        description.map(str::to_string)
    );
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE local_groups
         SET name = COALESCE(?2, name), description = COALESCE(?3, description)
         WHERE id = ?1",
        params![id, name, description],
    )?;
    if changed == 0 {
        return Ok(None);
    }
    let sql = format!(
        "SELECT {} FROM local_groups lg WHERE lg.id = ?1",
        LOCAL_GROUP_COLUMNS
    );
    conn.query_row(&sql, params![id], local_group_row).map(Some)
}

/// Delete a local group and all of its provider-group mappings. Returns
/// `Some(mappings_removed)` on success, `None` if the group is unknown.
/// Folder `allowed_groups` referencing the group name are NOT touched (group
/// names are free-form strings; see the module note above).
pub fn delete_local_group(db: &Db, id: i64) -> rusqlite::Result<Option<usize>> {
    db_route!(db, delete_local_group_pool, id);
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    let mappings: i64 = tx.query_row(
        "SELECT COUNT(*) FROM group_mappings WHERE group_id = ?1",
        params![id],
        |row| row.get(0),
    )?;
    let changed = tx.execute("DELETE FROM local_groups WHERE id = ?1", params![id])?;
    if changed == 0 {
        return Ok(None);
    }
    // SQLite runs without `PRAGMA foreign_keys`, so the ON DELETE CASCADE
    // declared on group_mappings.group_id never fires — delete explicitly.
    tx.execute(
        "DELETE FROM group_mappings WHERE group_id = ?1",
        params![id],
    )?;
    tx.commit()?;
    Ok(Some(mappings as usize))
}

/// List provider-group mappings, optionally filtered to one local group.
pub fn list_provider_group_mappings(
    db: &Db,
    group_id: Option<i64>,
) -> rusqlite::Result<Vec<ProviderGroupMapping>> {
    db_route!(db, list_provider_group_mappings_pool, group_id);
    let conn = db.lock().unwrap();
    let mut stmt = match group_id {
        Some(_) => conn.prepare(
            "SELECT id, group_id, provider_group, created_at FROM group_mappings
             WHERE group_id = ?1 ORDER BY provider_group COLLATE NOCASE",
        )?,
        None => conn.prepare(
            "SELECT id, group_id, provider_group, created_at FROM group_mappings
             ORDER BY group_id, provider_group COLLATE NOCASE",
        )?,
    };
    let mapper = |row: &rusqlite::Row| {
        Ok(ProviderGroupMapping {
            id: row.get(0)?,
            group_id: row.get(1)?,
            provider_group: row.get(2)?,
            created_at: row.get(3)?,
        })
    };
    let rows = match group_id {
        Some(gid) => stmt.query_map(params![gid], mapper)?,
        None => stmt.query_map([], mapper)?,
    };
    rows.collect()
}

/// Map an auth-provider group to a local group. Any existing mapping for the
/// same provider group is replaced — one provider group maps to one local
/// group. The caller must verify the local group exists first
/// (`get_local_group`); SQLite does not enforce the FK.
pub fn create_provider_group_mapping(
    db: &Db,
    group_id: i64,
    provider_group: &str,
) -> rusqlite::Result<ProviderGroupMapping> {
    db_route!(
        db,
        create_provider_group_mapping_pool,
        group_id,
        provider_group.to_string()
    );
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    // Verify the group still exists inside the same transaction (the API's
    // pre-check can race a concurrent delete, which would leave a dangling
    // mapping on backends without FK enforcement).
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_groups WHERE id = ?1)",
        params![group_id],
        |r| r.get(0),
    )?;
    if !exists {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    tx.execute(
        "DELETE FROM group_mappings WHERE provider_group = ?1",
        params![provider_group],
    )?;
    tx.execute(
        "INSERT INTO group_mappings (group_id, provider_group) VALUES (?1, ?2)",
        params![group_id, provider_group],
    )?;
    let id = tx.last_insert_rowid();
    let mapping = tx.query_row(
        "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE id = ?1",
        params![id],
        |row| {
            Ok(ProviderGroupMapping {
                id: row.get(0)?,
                group_id: row.get(1)?,
                provider_group: row.get(2)?,
                created_at: row.get(3)?,
            })
        },
    )?;
    tx.commit()?;
    Ok(mapping)
}

/// Remove a provider-group mapping by id.
pub fn delete_provider_group_mapping(db: &Db, mapping_id: i64) -> rusqlite::Result<bool> {
    db_route!(db, delete_provider_group_mapping_pool, mapping_id);
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM group_mappings WHERE id = ?1",
        params![mapping_id],
    )?;
    Ok(changed > 0)
}

// ══════════════════════════════════════════════════════════════════════
// SQLx pool store — real multi-backend storage when db_url is set.
//
// Every store function above has a `_pool` twin below that runs the same
// operation against the SQLx pool (PostgreSQL / MySQL / SQLite). The
// existing rusqlite implementations remain the no-db_url fast path; the
// `db_route!` preamble in each function sends the call to the pool store
// whenever one is active. The pool store is process-global: `main()` calls
// `set_active_pool` once at startup when `db_url` is configured, so no code
// path can silently fall back to the SQLite file.
//
// SQLx queries are async but the store surface is synchronous, and store
// functions are called from async handlers, spawn_blocking threads and the
// CLI alike — none of which may call `block_on` on their own thread. A
// dedicated worker thread therefore owns a private current-thread Tokio
// runtime and executes every pool query on it; callers block on a plain
// std channel, which is safe from any context.
// ══════════════════════════════════════════════════════════════════════

use sqlx::mysql::{MySql, MySqlArguments, MySqlPool, MySqlRow};
use sqlx::postgres::{PgArguments, PgPool, PgRow, Postgres};
use sqlx::sqlite::{Sqlite, SqliteArguments, SqlitePool, SqliteRow};
use sqlx::{Arguments as SqlxArguments, Decode, Row as SqlxRow, Type};

/// Backend-agnostic argument list for dynamically-built SQLx queries.
#[derive(Clone, Debug)]
enum Arg {
    Str(String),
    OptStr(Option<String>),
    I64(i64),
    OptI64(Option<i64>),
    Bool(bool),
}

fn push_pg(args: &mut PgArguments, a: &Arg) {
    match a {
        Arg::Str(v) => args.add(v).expect("encode pg str"),
        Arg::OptStr(v) => args.add(v.as_deref()).expect("encode pg opt str"),
        Arg::I64(v) => args.add(*v).expect("encode pg i64"),
        Arg::OptI64(v) => args.add(*v).expect("encode pg opt i64"),
        Arg::Bool(v) => args.add(*v).expect("encode pg bool"),
    }
}

fn push_mysql(args: &mut MySqlArguments, a: &Arg) {
    match a {
        Arg::Str(v) => args.add(v).expect("encode mysql str"),
        Arg::OptStr(v) => args.add(v.as_deref()).expect("encode mysql opt str"),
        Arg::I64(v) => args.add(*v).expect("encode mysql i64"),
        Arg::OptI64(v) => args.add(*v).expect("encode mysql opt i64"),
        Arg::Bool(v) => args.add(*v).expect("encode mysql bool"),
    }
}

fn push_sqlite(args: &mut SqliteArguments, a: &Arg) {
    match a {
        Arg::Str(v) => args.add(v).expect("encode sqlite str"),
        Arg::OptStr(v) => args.add(v.as_deref()).expect("encode sqlite opt str"),
        Arg::I64(v) => args.add(*v).expect("encode sqlite i64"),
        Arg::OptI64(v) => args.add(*v).expect("encode sqlite opt i64"),
        Arg::Bool(v) => args.add(*v).expect("encode sqlite bool"),
    }
}

/// A row from any backend, so store functions can map columns uniformly.
/// Every store reads only these column types, which implement `Decode` +
/// `Type` for all three backends.
pub enum RowProxy {
    /// Row from the Postgres backend.
    Pg(PgRow),
    /// Row from the MySQL backend.
    My(MySqlRow),
    /// Row from the SQLite backend.
    Sqlite(SqliteRow),
}

impl RowProxy {
    /// Read column `index` as `T`. Only types that implement `Decode` and
    /// `Type` for all three backends work here, which covers what the store
    /// functions read: `String`, `i64`, `bool`, and their `Option` forms.
    /// Panics when the column is missing or does not convert, matching
    /// `sqlx::Row::get`.
    pub fn get<'r, T>(&'r self, index: usize) -> T
    where
        T: Decode<'r, Postgres>
            + Type<Postgres>
            + Decode<'r, MySql>
            + Type<MySql>
            + Decode<'r, Sqlite>
            + Type<Sqlite>,
    {
        match self {
            RowProxy::Pg(r) => r.get(index),
            RowProxy::My(r) => r.get(index),
            RowProxy::Sqlite(r) => r.get(index),
        }
    }
}

async fn pg_exec(pool: &PgPool, sql: &str, args: &[Arg]) -> Result<u64, sqlx::Error> {
    let mut a = PgArguments::default();
    for arg in args {
        push_pg(&mut a, arg);
    }
    Ok(sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .execute(pool)
        .await?
        .rows_affected())
}

async fn pg_fetch(pool: &PgPool, sql: &str, args: &[Arg]) -> Result<Vec<RowProxy>, sqlx::Error> {
    let mut a = PgArguments::default();
    for arg in args {
        push_pg(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(RowProxy::Pg).collect())
}

async fn pg_fetch_opt(
    pool: &PgPool,
    sql: &str,
    args: &[Arg],
) -> Result<Option<RowProxy>, sqlx::Error> {
    let mut a = PgArguments::default();
    for arg in args {
        push_pg(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_optional(pool)
        .await
        .map(|r| r.map(RowProxy::Pg))
}

async fn mysql_exec(pool: &MySqlPool, sql: &str, args: &[Arg]) -> Result<u64, sqlx::Error> {
    let mut a = MySqlArguments::default();
    for arg in args {
        push_mysql(&mut a, arg);
    }
    Ok(sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .execute(pool)
        .await?
        .rows_affected())
}

async fn mysql_fetch(
    pool: &MySqlPool,
    sql: &str,
    args: &[Arg],
) -> Result<Vec<RowProxy>, sqlx::Error> {
    let mut a = MySqlArguments::default();
    for arg in args {
        push_mysql(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(RowProxy::My).collect())
}

async fn mysql_fetch_opt(
    pool: &MySqlPool,
    sql: &str,
    args: &[Arg],
) -> Result<Option<RowProxy>, sqlx::Error> {
    let mut a = MySqlArguments::default();
    for arg in args {
        push_mysql(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_optional(pool)
        .await
        .map(|r| r.map(RowProxy::My))
}

async fn sqlite_exec(pool: &SqlitePool, sql: &str, args: &[Arg]) -> Result<u64, sqlx::Error> {
    let mut a = SqliteArguments::default();
    for arg in args {
        push_sqlite(&mut a, arg);
    }
    Ok(sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .execute(pool)
        .await?
        .rows_affected())
}

async fn sqlite_fetch(
    pool: &SqlitePool,
    sql: &str,
    args: &[Arg],
) -> Result<Vec<RowProxy>, sqlx::Error> {
    let mut a = SqliteArguments::default();
    for arg in args {
        push_sqlite(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(RowProxy::Sqlite).collect())
}

async fn sqlite_fetch_opt(
    pool: &SqlitePool,
    sql: &str,
    args: &[Arg],
) -> Result<Option<RowProxy>, sqlx::Error> {
    let mut a = SqliteArguments::default();
    for arg in args {
        push_sqlite(&mut a, arg);
    }
    sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
        .fetch_optional(pool)
        .await
        .map(|r| r.map(RowProxy::Sqlite))
}

async fn exec_returning_id(pool: &DbPool, sql: &str, args: &[Arg]) -> Result<i64, sqlx::Error> {
    match pool {
        DbPool::Postgres(p) => {
            let mut a = PgArguments::default();
            for arg in args {
                push_pg(&mut a, arg);
            }
            let row = sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
                .fetch_one(p)
                .await?;
            Ok(row.get(0))
        }
        DbPool::MySQL(p) => {
            let mut a = MySqlArguments::default();
            for arg in args {
                push_mysql(&mut a, arg);
            }
            Ok(sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
                .execute(p)
                .await?
                .last_insert_id() as i64)
        }
        DbPool::SQLite(p) => {
            let mut a = SqliteArguments::default();
            for arg in args {
                push_sqlite(&mut a, arg);
            }
            Ok(sqlx::query_with(sqlx::AssertSqlSafe(sql), a)
                .execute(p)
                .await?
                .last_insert_rowid())
        }
        DbPool::None => Err(sqlx::Error::Configuration(
            "No database pool configured".into(),
        )),
    }
}

fn map_sqlx_err(e: sqlx::Error) -> rusqlite::Error {
    match e {
        sqlx::Error::RowNotFound => rusqlite::Error::QueryReturnedNoRows,
        sqlx::Error::Database(db_err) => {
            // Handlers map duplicate-name conflicts with
            // `msg.contains("UNIQUE constraint")` (tokens, address book,
            // imports). Translate the backend-native unique-violation
            // codes to the same message shape so that behavior is
            // identical on Postgres (23505), MySQL (1062) and SQLite
            // (2067/1555).
            let code = db_err.code().map(|c| c.to_string()).unwrap_or_default();
            if matches!(code.as_str(), "23505" | "1062" | "2067" | "1555") {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some("UNIQUE constraint failed (duplicate key)".into()),
                )
            } else {
                rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(1),
                    Some(db_err.to_string()),
                )
            }
        }
        other => {
            rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(other.to_string()))
        }
    }
}

type PoolBoxed = Box<dyn std::any::Any + Send>;
type PoolJobResult = Result<PoolBoxed, PoolBoxed>;

/// Store-call error types must be constructible when the worker thread is
/// unreachable so fail-closed behavior is possible in every caller.
pub trait StoreErr: Send + 'static {
    /// Convert a store-failure message into this error type.
    fn from_store_failure(msg: &str) -> Self;
}

impl StoreErr for rusqlite::Error {
    fn from_store_failure(msg: &str) -> Self {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(msg.into()))
    }
}

impl StoreErr for AuthError {
    fn from_store_failure(_msg: &str) -> Self {
        AuthError::InvalidKey
    }
}

struct PoolJob {
    #[allow(clippy::type_complexity)]
    run: Box<
        dyn FnOnce(
                &'static DbPool,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = PoolJobResult> + Send>>
            + Send,
    >,
    done: std::sync::mpsc::Sender<PoolJobResult>,
}

fn no_pool_err() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(1),
        Some("no active database pool configured (db_url not set)".into()),
    )
}

/// The process-global SQLx store. `main()` installs it when `db_url` is
/// set; every store function checks it first, so a configured backend can
/// never be bypassed.
struct PoolStore {
    pool: DbPool,
    tx: std::sync::mpsc::Sender<PoolJob>,
}

static POOL_STORE: std::sync::OnceLock<PoolStore> = std::sync::OnceLock::new();

fn pool_store() -> Option<&'static PoolStore> {
    POOL_STORE.get()
}

/// Return the active pool, if one is installed (used by the health check
/// and the router's `Extension<DbPool>` layer).
pub fn active_pool() -> Option<&'static DbPool> {
    pool_store().map(|s| &s.pool)
}

/// Install the SQLx pool as the real store. Called once from `main()` when
/// `db_url` is configured. Spawns a dedicated worker thread owning a private
/// Tokio runtime; all store queries run there so synchronous callers from
/// any thread context (async handlers, spawn_blocking, CLI) can await them.
pub fn set_active_pool(pool: DbPool) -> Result<(), DbPool> {
    let (tx, rx) = std::sync::mpsc::channel::<PoolJob>();
    // The pool lives for the process lifetime (installed once at startup);
    // leaking a clone gives the worker a 'static handle so jobs can borrow
    // it across the mpsc channel. The original is kept for POOL_STORE.
    let leaked_pool: &'static DbPool = Box::leak(Box::new(pool.clone()));
    let worker = std::thread::Builder::new()
        .name("persea-db-worker".to_string())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("FATAL: persea db worker runtime failed to start: {e}");
                    return;
                }
            };
            while let Ok(job) = rx.recv() {
                let result = rt.block_on(async move { (job.run)(leaked_pool).await });
                let _ = job.done.send(result);
            }
        });
    match worker {
        Ok(_) => {
            let _ = POOL_STORE.set(PoolStore { pool, tx });
            Ok(())
        }
        Err(e) => {
            eprintln!("FATAL: persea db worker thread failed to start: {e}");
            Err(pool)
        }
    }
}

/// Run `f` on the pool store's worker thread and return its result.
/// Safe to call from any thread: async contexts, spawn_blocking threads,
/// and the CLI. When no pool store is active this returns an error — store
/// functions only call it after a positive `pool_store()` check.
pub fn pool_call<F, Fut, T, E>(f: F) -> Result<T, E>
where
    F: FnOnce(&'static DbPool) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, E>> + Send + 'static,
    T: Send + 'static,
    E: StoreErr,
{
    let store = pool_store().ok_or_else(|| {
        E::from_store_failure("no active database pool configured (db_url not set)")
    })?;
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    #[allow(clippy::type_complexity)]
    let run: Box<
        dyn FnOnce(
                &'static DbPool,
            )
                -> std::pin::Pin<Box<dyn std::future::Future<Output = PoolJobResult> + Send>>
            + Send,
    > = Box::new(move |pool: &'static DbPool| {
        Box::pin(async move {
            match f(pool).await {
                Ok(v) => Ok(Box::new(v) as PoolBoxed),
                Err(e) => Err(Box::new(e) as PoolBoxed),
            }
        })
    });
    store
        .tx
        .send(PoolJob { run, done: done_tx })
        .map_err(|_| E::from_store_failure("database worker thread is not running"))?;
    let result = done_rx.recv().map_err(|_| {
        E::from_store_failure("database worker thread stopped while handling a query")
    })?;
    match result {
        Ok(boxed) => Ok(*boxed
            .downcast::<T>()
            .expect("db worker result type mismatch (store bug)")),
        Err(boxed) => Err(*boxed
            .downcast::<E>()
            .expect("db worker error type mismatch (store bug)")),
    }
}

/// WHERE-free query dispatch: run `sql` (already backend-appropriate) with
/// the given args and return rows affected.
async fn pool_exec(pool: &DbPool, sql: &str, args: &[Arg]) -> Result<u64, sqlx::Error> {
    match pool {
        DbPool::Postgres(p) => pg_exec(p, sql, args).await,
        DbPool::MySQL(p) => mysql_exec(p, sql, args).await,
        DbPool::SQLite(p) => sqlite_exec(p, sql, args).await,
        DbPool::None => Err(sqlx::Error::Configuration(
            "No database pool configured".into(),
        )),
    }
}

/// Fetch rows as serde_json values using the session_history row shape.
macro_rules! session_history_json_row {
    ($row:expr) => {
        serde_json::json!({
            "session_id": $row.get::<String>(0),
            "session_type": $row.get::<String>(1),
            "hostname": $row.get::<String>(2),
            "port": $row.get::<Option<i64>>(3),
            "username": $row.get::<String>(4),
            "created_by": $row.get::<String>(5),
            "address_book_entry": $row.get::<Option<String>>(6),
            "address_book_folder": $row.get::<Option<String>>(7),
            "entry_display_name": $row.get::<Option<String>>(8),
            "reason": $row.get::<Option<String>>(9),
            "started_at": $row.get::<String>(10),
            "ended_at": $row.get::<Option<String>>(11),
            "duration_secs": $row.get::<Option<i64>>(12),
            "recording_file": $row.get::<Option<String>>(13),
            "status": $row.get::<String>(14),
        })
    };
}

// ── Admins ────────────────────────────────────────────────────────────

async fn add_admin_pool(
    pool: &DbPool,
    name: String,
    allowed_ips: Option<String>,
    expires_at: Option<String>,
) -> rusqlite::Result<String> {
    let key = generate_key();
    let key_hash = hash_key_salt(&key);
    let args = vec![
        Arg::Str(name),
        Arg::Str(key_hash),
        Arg::OptStr(allowed_ips),
        Arg::OptStr(expires_at),
    ];
    pool_exec(pool, qsql!(pool, "INSERT INTO admins (name, api_key_hash, allowed_ips, expires_at) VALUES ($1, $2, $3, $4)", "INSERT INTO admins (name, api_key_hash, allowed_ips, expires_at) VALUES (?, ?, ?, ?)"), &args)
        .await
        .map_err(map_sqlx_err)?;
    Ok(key)
}

async fn list_admins_pool(pool: &DbPool) -> rusqlite::Result<Vec<AdminInfo>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at FROM admins ORDER BY id", &[]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at FROM admins ORDER BY id", &[]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at FROM admins ORDER BY id", &[]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| AdminInfo {
            id: row.get(0),
            name: row.get(1),
            allowed_ips: row.get(2),
            expires_at: row.get(3),
            disabled: row.get(4),
            created_at: row.get(5),
            last_used_at: row.get(6),
        })
        .collect())
}

async fn validate_api_key_pool(
    pool: &DbPool,
    key: String,
    client_ip: Option<IpAddr>,
) -> Result<AdminInfo, AuthError> {
    let sql = qsql!(
        pool,
        "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at, api_key_hash FROM admins",
        "SELECT id, name, allowed_ips, expires_at, disabled, created_at, last_used_at, api_key_hash FROM admins"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[]).await,
        DbPool::None => return Err(AuthError::InvalidKey),
    }
    .map_err(|_| AuthError::InvalidKey)?;

    let admin = rows
        .iter()
        .filter_map(|row| {
            let stored_hash: String = row.get(7);
            if !validate_stored_hash(&key, &stored_hash) {
                return None;
            }
            Some(AdminInfo {
                id: row.get(0),
                name: row.get(1),
                allowed_ips: row.get(2),
                expires_at: row.get(3),
                disabled: row.get(4),
                created_at: row.get(5),
                last_used_at: row.get(6),
            })
        })
        .next();

    let Some(admin) = admin else {
        return Err(AuthError::InvalidKey);
    };

    if admin.disabled {
        return Err(AuthError::Disabled);
    }

    if let Some(ref exp) = admin.expires_at {
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
        }
    }

    if let (Some(ref cidrs), Some(ip)) = (&admin.allowed_ips, client_ip) {
        let allowed = cidrs.split(',').any(|cidr| {
            cidr.trim()
                .parse::<ipnetwork::IpNetwork>()
                .map(|net| net.contains(ip))
                .unwrap_or(false)
        });
        if !allowed {
            return Err(AuthError::IpNotAllowed);
        }
    }

    let _ = pool_exec(
        pool,
        &format!(
            "UPDATE admins SET last_used_at = {} WHERE id = {}",
            ts_now(pool),
            ph1(pool)
        ),
        &[Arg::I64(admin.id)],
    )
    .await;

    Ok(admin)
}

async fn set_admin_disabled_pool(
    pool: &DbPool,
    name: String,
    disabled: bool,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE admins SET disabled = $1 WHERE name = $2",
            "UPDATE admins SET disabled = ? WHERE name = ?"
        ),
        &[Arg::Bool(disabled), Arg::Str(name)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_admin_pool(pool: &DbPool, name: String) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM admins WHERE name = $1",
            "DELETE FROM admins WHERE name = ?"
        ),
        &[Arg::Str(name)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn rotate_key_pool(pool: &DbPool, name: String) -> rusqlite::Result<Option<String>> {
    let key = generate_key();
    let key_hash = hash_key_salt(&key);
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE admins SET api_key_hash = $1 WHERE name = $2",
            "UPDATE admins SET api_key_hash = ? WHERE name = ?"
        ),
        &[Arg::Str(key_hash), Arg::Str(name)],
    )
    .await
    .map_err(map_sqlx_err)?;
    if changed > 0 {
        Ok(Some(key))
    } else {
        Ok(None)
    }
}

// ── Users ─────────────────────────────────────────────────────────────

macro_rules! user_row {
    ($row:expr) => {
        User {
            id: $row.get(0),
            email: $row.get(1),
            name: $row.get(2),
            oidc_subject: $row.get(3),
            role: $row.get(4),
            disabled: $row.get(5),
            created_at: $row.get(6),
            last_login_at: $row.get(7),
            oidc_groups: $row.get(8),
            custom_role_id: $row.get(9),
        }
    };
}

async fn upsert_user_pool(
    pool: &DbPool,
    email: String,
    name: String,
    oidc_subject: Option<String>,
    default_role: String,
    groups_str: String,
) -> rusqlite::Result<User> {
    let sql = qsql!(
        pool,
        "INSERT INTO users (email, username, name, oidc_subject, role, oidc_groups) \
         VALUES ($1, $1, $2, $3, $4, $5) \
         ON CONFLICT (email) DO UPDATE SET \
             name = excluded.name, \
             username = excluded.username, \
             oidc_subject = COALESCE(excluded.oidc_subject, users.oidc_subject), \
             oidc_groups = excluded.oidc_groups, \
             last_login_at = to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')",
        "INSERT INTO users (email, username, name, oidc_subject, role, oidc_groups) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (email) DO UPDATE SET \
             name = excluded.name, \
             username = excluded.username, \
             oidc_subject = COALESCE(excluded.oidc_subject, users.oidc_subject), \
             oidc_groups = excluded.oidc_groups, \
             last_login_at = datetime('now')"
    );
    let mysql_sql = "INSERT INTO users (email, username, name, oidc_subject, `role`, oidc_groups) \
         VALUES (?, ?, ?, ?, ?, ?) AS new \
         ON DUPLICATE KEY UPDATE \
             name = new.name, \
             username = new.username, \
             oidc_subject = COALESCE(new.oidc_subject, users.oidc_subject), \
             oidc_groups = new.oidc_groups, \
             last_login_at = DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    let args = match pool {
        // MySQL has no $n reuse: the email placeholder appears twice
        // (email + username columns), so it needs two binds.
        DbPool::MySQL(_) => vec![
            Arg::Str(email.clone()),
            Arg::Str(email.clone()),
            Arg::Str(name),
            Arg::OptStr(oidc_subject),
            Arg::Str(default_role),
            Arg::Str(groups_str),
        ],
        _ => vec![
            Arg::Str(email.clone()),
            Arg::Str(name),
            Arg::OptStr(oidc_subject),
            Arg::Str(default_role),
            Arg::Str(groups_str),
        ],
    };
    pool_exec(pool, sql, &args).await.map_err(map_sqlx_err)?;

    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = $1", &[Arg::Str(email)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, email, name, oidc_subject, `role`, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = ?", &[Arg::Str(email)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = ?", &[Arg::Str(email)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    rows.first().map(|row| user_row!(row)).ok_or_else(|| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("upsert_user: user not found after write".into()),
        )
    })
}

/// Shared by the `create-user` CLI, the admin users API and the setup
/// wizard: insert a password-authenticated user. `username` mirrors
/// `email` on the SQLx backends (schema parity with the legacy rusqlite
/// `users` table, which only has `email`).
pub fn create_user_with_password(
    db: &Db,
    email: &str,
    name: &str,
    password_hash: &str,
    role: &str,
    auth_source: &str,
) -> rusqlite::Result<()> {
    db_route!(
        db,
        create_user_with_password_pool,
        email.to_string(),
        name.to_string(),
        password_hash.to_string(),
        role.to_string(),
        auth_source.to_string()
    );
    let now = chrono::Utc::now().to_rfc3339();
    let conn = db.lock().unwrap();
    // Ensure password_hash and auth_source columns exist (migrate old schema)
    let _ = conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT", []);
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''",
        [],
    );
    conn.execute(
        "INSERT INTO users (email, name, auth_source, password_hash, role, disabled, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)",
        params![email, name, auth_source, password_hash, role, now],
    )?;
    Ok(())
}

async fn create_user_with_password_pool(
    pool: &DbPool,
    email: String,
    name: String,
    password_hash: String,
    role: String,
    auth_source: String,
) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let args = match pool {
        // MySQL needs the email bound twice (email + username columns).
        DbPool::MySQL(_) => vec![
            Arg::Str(email.clone()),
            Arg::Str(email.clone()),
            Arg::Str(name),
            Arg::Str(auth_source),
            Arg::Str(password_hash),
            Arg::Str(role),
            Arg::Str(now),
        ],
        _ => vec![
            Arg::Str(email.clone()),
            Arg::Str(name),
            Arg::Str(auth_source),
            Arg::Str(password_hash),
            Arg::Str(role),
            Arg::Str(now),
        ],
    };
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO users (email, username, name, auth_source, password_hash, role, disabled, created_at) VALUES ($1, $1, $2, $3, $4, $5, FALSE, $6)",
            "INSERT INTO users (email, username, name, auth_source, password_hash, `role`, disabled, created_at) VALUES (?, ?, ?, ?, ?, ?, 0, ?)"
        ),
        &args,
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn get_user_by_email_pool(pool: &DbPool, email: String) -> rusqlite::Result<User> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = $1", &[Arg::Str(email)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT id, email, name, oidc_subject, `role`, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = ?", &[Arg::Str(email)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users WHERE email = ?", &[Arg::Str(email)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| user_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn get_user_auth_source_pool(pool: &DbPool, email: String) -> rusqlite::Result<String> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT auth_source FROM users WHERE email = $1",
                &[Arg::Str(email)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT auth_source FROM users WHERE email = ?",
                &[Arg::Str(email)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT auth_source FROM users WHERE email = ?",
                &[Arg::Str(email)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| r.get::<String>(0))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn list_users_pool(pool: &DbPool) -> rusqlite::Result<Vec<User>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users ORDER BY id", &[]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, email, name, oidc_subject, `role`, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users ORDER BY id", &[]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups, custom_role_id FROM users ORDER BY id", &[]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| user_row!(row)).collect())
}

async fn set_user_role_pool(pool: &DbPool, email: String, role: String) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE users SET role = $1 WHERE email = $2",
            "UPDATE users SET `role` = ? WHERE email = ?"
        ),
        &[Arg::Str(role), Arg::Str(email)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn update_user_name_pool(
    pool: &DbPool,
    email: String,
    name: String,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE users SET name = $1 WHERE email = $2",
            "UPDATE users SET name = ? WHERE email = ?"
        ),
        &[Arg::Str(name), Arg::Str(email)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn set_user_disabled_pool(
    pool: &DbPool,
    email: String,
    disabled: bool,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE users SET disabled = $1 WHERE email = $2",
            "UPDATE users SET disabled = ? WHERE email = ?"
        ),
        &[Arg::Bool(disabled), Arg::Str(email)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_user_pool(pool: &DbPool, email: String) -> rusqlite::Result<bool> {
    // The rusqlite path only clears auth_sessions + user_api_tokens; the
    // SQLx backends enforce the foreign keys declared in the migrations, so
    // every dependent table must be emptied before the user row goes.
    let user_id = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT id FROM users WHERE email = $1",
                &[Arg::Str(email.clone())],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT id FROM users WHERE email = ?",
                &[Arg::Str(email.clone())],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT id FROM users WHERE email = ?",
                &[Arg::Str(email.clone())],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(row) = user_id else {
        return Ok(false);
    };
    let uid = row.get::<i64>(0);
    let id_arg = [Arg::I64(uid)];
    for sql in [
        qsql!(
            pool,
            "DELETE FROM auth_sessions WHERE user_id = $1",
            "DELETE FROM auth_sessions WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM user_api_tokens WHERE user_id = $1",
            "DELETE FROM user_api_tokens WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM totp_secrets WHERE user_id = $1",
            "DELETE FROM totp_secrets WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM user_preset_credentials WHERE user_id = $1",
            "DELETE FROM user_preset_credentials WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM login_credentials WHERE user_id = $1",
            "DELETE FROM login_credentials WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM auth_pending_mfa WHERE user_id = $1",
            "DELETE FROM auth_pending_mfa WHERE user_id = ?"
        ),
        qsql!(
            pool,
            "DELETE FROM rbac_user_groups WHERE user_id = $1",
            "DELETE FROM rbac_user_groups WHERE user_id = ?"
        ),
    ] {
        pool_exec(pool, sql, &id_arg).await.map_err(map_sqlx_err)?;
    }
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM users WHERE email = $1",
            "DELETE FROM users WHERE email = ?"
        ),
        &[Arg::Str(email)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

// ── Preset + login credentials ─────────────────────────────────────────

async fn upsert_user_preset_credentials_pool(
    pool: &DbPool,
    user_id: i64,
    username: String,
    password_enc: String,
) -> rusqlite::Result<()> {
    let sql = match pool {
        DbPool::MySQL(_) => format!(
            "INSERT INTO user_preset_credentials (user_id, username, password_enc, updated_at) \
             VALUES (?, ?, ?, {}) AS new \
             ON DUPLICATE KEY UPDATE \
                 username = new.username, \
                 password_enc = new.password_enc, \
                 updated_at = {}",
            ts_now(pool),
            ts_now(pool)
        ),
        _ => qsql!(
            pool,
            "INSERT INTO user_preset_credentials (user_id, username, password_enc, updated_at) \
             VALUES ($1, $2, $3, to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 username = excluded.username, \
                 password_enc = excluded.password_enc, \
                 updated_at = to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')",
            "INSERT INTO user_preset_credentials (user_id, username, password_enc, updated_at) \
             VALUES (?, ?, ?, datetime('now')) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 username = excluded.username, \
                 password_enc = excluded.password_enc, \
                 updated_at = datetime('now')"
        )
        .to_string(),
    }
    .to_string();
    pool_exec(
        pool,
        &sql,
        &[
            Arg::I64(user_id),
            Arg::Str(username),
            Arg::Str(password_enc),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn get_user_preset_credentials_pool(
    pool: &DbPool,
    user_id: i64,
) -> rusqlite::Result<Option<(String, String)>> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT username, password_enc FROM user_preset_credentials WHERE user_id = $1",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT username, password_enc FROM user_preset_credentials WHERE user_id = ?",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT username, password_enc FROM user_preset_credentials WHERE user_id = ?",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| (r.get(0), r.get(1))))
}

async fn clear_user_preset_credentials_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM user_preset_credentials WHERE user_id = $1",
            "DELETE FROM user_preset_credentials WHERE user_id = ?"
        ),
        &[Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn upsert_login_credentials_pool(
    pool: &DbPool,
    user_id: i64,
    username: String,
    password_enc: String,
    expires_at: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO login_credentials (user_id, username, password_enc, expires_at) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 username = excluded.username, \
                 password_enc = excluded.password_enc, \
                 expires_at = excluded.expires_at",
            "INSERT INTO login_credentials (user_id, username, password_enc, expires_at) \
             VALUES (?, ?, ?, ?) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 username = excluded.username, \
                 password_enc = excluded.password_enc, \
                 expires_at = excluded.expires_at"
        ),
        &[
            Arg::I64(user_id),
            Arg::Str(username),
            Arg::Str(password_enc),
            Arg::Str(expires_at),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn get_login_credentials_pool(
    pool: &DbPool,
    user_id: i64,
) -> rusqlite::Result<Option<(String, String, String)>> {
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(
            p,
            "SELECT username, password_enc, expires_at FROM login_credentials WHERE user_id = $1",
            &[Arg::I64(user_id)],
        )
        .await,
        DbPool::MySQL(p) => mysql_fetch_opt(
            p,
            "SELECT username, password_enc, expires_at FROM login_credentials WHERE user_id = ?",
            &[Arg::I64(user_id)],
        )
        .await,
        DbPool::SQLite(p) => sqlite_fetch_opt(
            p,
            "SELECT username, password_enc, expires_at FROM login_credentials WHERE user_id = ?",
            &[Arg::I64(user_id)],
        )
        .await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
}

/// Login-path lookup for the database auth provider: id, email, name, role,
/// disabled, password_hash. `Ok(None)` when the user does not exist.
#[allow(clippy::type_complexity)]
pub fn get_user_login_info(
    db: &Db,
    email: &str,
) -> rusqlite::Result<Option<(i64, String, String, String, bool, Option<String>)>> {
    db_route!(db, get_user_login_info_pool, email.to_string());
    let conn = db.lock().unwrap();
    match conn.query_row(
        "SELECT id, email, name, role, disabled, password_hash
         FROM users WHERE email = ?1",
        params![email],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i32>(4)? != 0,
                row.get::<_, Option<String>>(5)?,
            ))
        },
    ) {
        Ok(v) => Ok(Some(v)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e),
    }
}

async fn get_user_login_info_pool(
    pool: &DbPool,
    email: String,
) -> rusqlite::Result<Option<(i64, String, String, String, bool, Option<String>)>> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT id, email, name, role, disabled, password_hash FROM users WHERE email = $1",
                &[Arg::Str(email)],
            )
            .await
        }
        DbPool::MySQL(p) => mysql_fetch_opt(
            p,
            "SELECT id, email, name, `role`, disabled, password_hash FROM users WHERE email = ?",
            &[Arg::Str(email)],
        )
        .await,
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT id, email, name, role, disabled, password_hash FROM users WHERE email = ?",
                &[Arg::Str(email)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4), r.get(5))))
}

/// Record a successful login (updates `last_login_at`).
pub fn touch_user_last_login(db: &Db, user_id: i64) -> rusqlite::Result<()> {
    db_route!(db, touch_user_last_login_pool, user_id);
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE users SET last_login_at = datetime('now') WHERE id = ?1",
        params![user_id],
    )?;
    Ok(())
}

async fn touch_user_last_login_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        &format!(
            "UPDATE users SET last_login_at = {} WHERE id = {}",
            ts_now(pool),
            ph1(pool)
        ),
        &[Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

/// Count users (admin system status / setup wizard).
pub fn count_users(db: &Db) -> rusqlite::Result<i64> {
    db_route!(db, count_users_pool);
    let conn = db.lock().unwrap();
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
}

async fn count_users_pool(pool: &DbPool) -> rusqlite::Result<i64> {
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<i64>(0)).unwrap_or(0))
}

/// Count session history rows (admin system status).
pub fn count_session_history(db: &Db) -> rusqlite::Result<i64> {
    db_route!(db, count_session_history_pool);
    let conn = db.lock().unwrap();
    conn.query_row("SELECT COUNT(*) FROM session_history", [], |row| row.get(0))
}

async fn count_session_history_pool(pool: &DbPool) -> rusqlite::Result<i64> {
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<i64>(0)).unwrap_or(0))
}

// ── Auth sessions ──────────────────────────────────────────────────────

async fn create_auth_session_pool(
    pool: &DbPool,
    user_id: i64,
    ttl_secs: u64,
) -> rusqlite::Result<String> {
    let token = generate_key();
    let token_hash = hash_key(&token);
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (
            format!(
                "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, {})",
                ts_now_plus_secs(pool, "$3")
            ),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::I64(ttl_secs as i64),
            ],
        ),
        DbPool::MySQL(_) => (
            format!(
                "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, {})",
                ts_now_plus_secs(pool, "?")
            ),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::I64(ttl_secs as i64),
            ],
        ),
        _ => (
            "INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES (?, ?, datetime('now', ?))"
                .to_string(),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::Str(format!("+{} seconds", ttl_secs)),
            ],
        ),
    };
    pool_exec(pool, &sql, &args).await.map_err(map_sqlx_err)?;
    Ok(token)
}

async fn delete_user_sessions_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM auth_sessions WHERE user_id = $1",
            "DELETE FROM auth_sessions WHERE user_id = ?"
        ),
        &[Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

async fn validate_auth_session_pool(pool: &DbPool, token: String) -> Result<User, AuthError> {
    let token_hash = hash_key(&token);
    let sql = format!(
        "SELECT u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups, u.custom_role_id \
         FROM auth_sessions s JOIN users u ON u.id = s.user_id \
         WHERE s.token_hash = {} AND s.expires_at > {}",
        ph1(pool),
        ts_now(pool)
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::None => return Err(AuthError::InvalidSession),
    }
    .map_err(|_| AuthError::InvalidSession)?;
    let Some(row) = row else {
        return Err(AuthError::InvalidSession);
    };
    let user = user_row!(&row);
    if user.disabled {
        return Err(AuthError::Disabled);
    }
    Ok(user)
}

async fn delete_auth_session_pool(pool: &DbPool, token: String) -> rusqlite::Result<bool> {
    let token_hash = hash_key(&token);
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM auth_sessions WHERE token_hash = $1",
            "DELETE FROM auth_sessions WHERE token_hash = ?"
        ),
        &[Arg::Str(token_hash)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn cleanup_expired_sessions_pool(pool: &DbPool) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        &format!(
            "DELETE FROM auth_sessions WHERE expires_at <= {}",
            ts_now(pool)
        ),
        &[],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

// ── Failed login attempts ──────────────────────────────────────────────

async fn record_failed_login_attempt_pool(
    pool: &DbPool,
    username: String,
    ip: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO failed_login_attempts (username, ip_address, success) VALUES ($1, $2, FALSE)",
            "INSERT INTO failed_login_attempts (username, ip_address, success) VALUES (?, ?, 0)"
        ),
        &[Arg::Str(username), Arg::Str(ip)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn record_successful_login_pool(
    pool: &DbPool,
    username: String,
    ip: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE failed_login_attempts SET success = TRUE WHERE username = $1 AND ip_address = $2 AND success = FALSE",
            "UPDATE failed_login_attempts SET success = 1 WHERE username = ? AND ip_address = ? AND success = 0"
        ),
        &[Arg::Str(username), Arg::Str(ip)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn count_recent_failures_pool(
    pool: &DbPool,
    username: String,
    ip: String,
    window_secs: u64,
) -> rusqlite::Result<u32> {
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (
            format!(
                "SELECT COUNT(*) FROM failed_login_attempts \
                 WHERE username = $1 AND ip_address = $2 AND success = FALSE \
                   AND attempted_at >= {}",
                ts_now_minus_secs(pool, "$3")
            ),
            vec![
                Arg::Str(username),
                Arg::Str(ip),
                Arg::I64(window_secs as i64),
            ],
        ),
        DbPool::MySQL(_) => (
            format!(
                "SELECT COUNT(*) FROM failed_login_attempts \
                 WHERE username = ? AND ip_address = ? AND success = 0 \
                   AND attempted_at >= {}",
                ts_now_minus_secs(pool, "?")
            ),
            vec![
                Arg::Str(username),
                Arg::Str(ip),
                Arg::I64(window_secs as i64),
            ],
        ),
        _ => (
            "SELECT COUNT(*) FROM failed_login_attempts \
             WHERE username = ? AND ip_address = ? AND success = 0 \
               AND attempted_at >= datetime('now', ?)"
                .to_string(),
            vec![
                Arg::Str(username),
                Arg::Str(ip),
                Arg::Str(format!("-{} seconds", window_secs)),
            ],
        ),
    };
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<i64>(0) as u32).unwrap_or(0))
}

// ── Group-to-role mappings ─────────────────────────────────────────────

macro_rules! group_mapping_row {
    ($row:expr) => {
        GroupRoleMapping {
            id: $row.get(0),
            oidc_group: $row.get(1),
            role: $row.get(2),
            created_at: $row.get(3),
        }
    };
}

async fn list_group_mappings_pool(pool: &DbPool) -> rusqlite::Result<Vec<GroupRoleMapping>> {
    let rows =
        match pool {
            DbPool::Postgres(p) => {
                pg_fetch(
                    p,
                    "SELECT id, oidc_group, role, created_at FROM group_role_mappings ORDER BY id",
                    &[],
                )
                .await
            }
            DbPool::MySQL(p) => mysql_fetch(
                p,
                "SELECT id, oidc_group, `role`, created_at FROM group_role_mappings ORDER BY id",
                &[],
            )
            .await,
            DbPool::SQLite(p) => {
                sqlite_fetch(
                    p,
                    "SELECT id, oidc_group, role, created_at FROM group_role_mappings ORDER BY id",
                    &[],
                )
                .await
            }
            DbPool::None => return Err(no_pool_err()),
        }
        .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| group_mapping_row!(row)).collect())
}

async fn create_group_mapping_pool(
    pool: &DbPool,
    oidc_group: String,
    role: String,
) -> rusqlite::Result<GroupRoleMapping> {
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO group_role_mappings (oidc_group, role) VALUES ($1, $2) RETURNING id",
            "INSERT INTO group_role_mappings (oidc_group, `role`) VALUES (?, ?)"
        ),
        &[Arg::Str(oidc_group), Arg::Str(role)],
    )
    .await
    .map_err(map_sqlx_err)?;
    let rows =
        match pool {
            DbPool::Postgres(p) => pg_fetch(
                p,
                "SELECT id, oidc_group, role, created_at FROM group_role_mappings WHERE id = $1",
                &[Arg::I64(id)],
            )
            .await,
            DbPool::MySQL(p) => mysql_fetch(
                p,
                "SELECT id, oidc_group, `role`, created_at FROM group_role_mappings WHERE id = ?",
                &[Arg::I64(id)],
            )
            .await,
            DbPool::SQLite(p) => {
                sqlite_fetch(
                    p,
                    "SELECT id, oidc_group, role, created_at FROM group_role_mappings WHERE id = ?",
                    &[Arg::I64(id)],
                )
                .await
            }
            DbPool::None => return Err(no_pool_err()),
        }
        .map_err(map_sqlx_err)?;
    rows.first()
        .map(|row| group_mapping_row!(row))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn update_group_mapping_pool(
    pool: &DbPool,
    id: i64,
    oidc_group: String,
    role: String,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE group_role_mappings SET oidc_group = $1, role = $2 WHERE id = $3",
            "UPDATE group_role_mappings SET oidc_group = ?, `role` = ? WHERE id = ?"
        ),
        &[Arg::Str(oidc_group), Arg::Str(role), Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_group_mapping_pool(pool: &DbPool, id: i64) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM group_role_mappings WHERE id = $1",
            "DELETE FROM group_role_mappings WHERE id = ?"
        ),
        &[Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn upsert_seen_groups_pool(pool: &DbPool, groups: Vec<String>) -> rusqlite::Result<()> {
    for g in groups {
        let trimmed = g.trim();
        if trimmed.is_empty() {
            continue;
        }
        pool_exec(
            pool,
            &format!(
                "INSERT INTO seen_groups (name) VALUES ({}) \
                 ON CONFLICT (name) DO UPDATE SET last_seen = {}",
                ph1(pool),
                ts_now(pool)
            ),
            &[Arg::Str(trimmed.to_string())],
        )
        .await
        .map_err(map_sqlx_err)?;
    }
    Ok(())
}

async fn ensure_local_groups_pool(pool: &DbPool, groups: Vec<String>) -> rusqlite::Result<usize> {
    let mut created = 0usize;
    for g in groups {
        let trimmed = g.trim();
        if trimmed.is_empty() || trimmed.contains(',') {
            continue;
        }
        let sql = qsql!(
            pool,
            "INSERT INTO local_groups (name, description, auto_provisioned) VALUES ($1, 'Auto-provisioned from auth provider groups', TRUE) ON CONFLICT (name) DO NOTHING",
            "INSERT OR IGNORE INTO local_groups (name, description, auto_provisioned) VALUES (?, 'Auto-provisioned from auth provider groups', 1)"
        );
        let mysql_sql = "INSERT IGNORE INTO local_groups (name, description, auto_provisioned) VALUES (?, 'Auto-provisioned from auth provider groups', 1)";
        let sql = match pool {
            DbPool::MySQL(_) => mysql_sql,
            _ => sql,
        };
        let n = pool_exec(pool, sql, &[Arg::Str(trimmed.to_string())])
            .await
            .map_err(map_sqlx_err)?;
        created += n as usize;
    }
    Ok(created)
}

async fn list_known_groups_pool(pool: &DbPool) -> rusqlite::Result<Vec<String>> {
    let sql = qsql!(
        pool,
        "SELECT g FROM (
            SELECT oidc_group AS g FROM group_role_mappings
            UNION
            SELECT name AS g FROM seen_groups
         ) sub
         WHERE g IS NOT NULL AND g <> ''
         ORDER BY LOWER(g)",
        "SELECT g FROM (
            SELECT oidc_group AS g FROM group_role_mappings
            UNION
            SELECT name AS g FROM seen_groups
         )
         WHERE g IS NOT NULL AND g <> ''
         ORDER BY g COLLATE NOCASE"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|r| r.get::<String>(0)).collect())
}

// ── User API tokens ────────────────────────────────────────────────────

macro_rules! user_token_row {
    ($row:expr) => {
        UserApiToken {
            id: $row.get(0),
            user_id: $row.get(1),
            name: $row.get(2),
            max_role: $row.get(3),
            expires_at: $row.get(4),
            disabled: $row.get(5),
            created_at: $row.get(6),
            last_used_at: $row.get(7),
        }
    };
}

async fn create_user_token_pool(
    pool: &DbPool,
    user_id: i64,
    name: String,
    max_role: Option<String>,
    expires_at: Option<String>,
) -> rusqlite::Result<(i64, String)> {
    let raw_key = generate_key();
    let token = format!("rgu_{}", raw_key);
    let token_hash = hash_key(&token);
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO user_api_tokens (user_id, name, token_hash, max_role, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            "INSERT INTO user_api_tokens (user_id, name, token_hash, max_role, expires_at) VALUES (?, ?, ?, ?, ?)"
        ),
        &[
            Arg::I64(user_id),
            Arg::Str(name),
            Arg::Str(token_hash),
            Arg::OptStr(max_role),
            Arg::OptStr(expires_at),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok((id, token))
}

async fn list_user_tokens_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<Vec<UserApiToken>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, user_id, name, max_role, expires_at, disabled, created_at, last_used_at FROM user_api_tokens WHERE user_id = $1 ORDER BY id", &[Arg::I64(user_id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, user_id, name, max_role, expires_at, disabled, created_at, last_used_at FROM user_api_tokens WHERE user_id = ? ORDER BY id", &[Arg::I64(user_id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, user_id, name, max_role, expires_at, disabled, created_at, last_used_at FROM user_api_tokens WHERE user_id = ? ORDER BY id", &[Arg::I64(user_id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| user_token_row!(row)).collect())
}

async fn list_all_user_tokens_pool(pool: &DbPool) -> rusqlite::Result<Vec<(UserApiToken, String)>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, u.email FROM user_api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.id", &[]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, u.email FROM user_api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.id", &[]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, u.email FROM user_api_tokens t JOIN users u ON u.id = t.user_id ORDER BY t.id", &[]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| (user_token_row!(row), row.get::<String>(8)))
        .collect())
}

async fn validate_user_token_pool(
    pool: &DbPool,
    token: String,
) -> Result<(User, UserApiToken), AuthError> {
    use subtle::ConstantTimeEq;
    let token_hash = hash_key(&token);
    let sql = qsql!(
        pool,
        "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, \
                u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups, \
                t.token_hash, u.custom_role_id \
         FROM user_api_tokens t JOIN users u ON u.id = t.user_id",
        "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at, \
                u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups, \
                t.token_hash, u.custom_role_id \
         FROM user_api_tokens t JOIN users u ON u.id = t.user_id"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[]).await,
        DbPool::None => return Err(AuthError::InvalidKey),
    }
    .map_err(|_| AuthError::InvalidKey)?;

    let found = rows.iter().find(|row| {
        let stored_hash: String = row.get(17);
        token_hash.as_bytes().ct_eq(stored_hash.as_bytes()).into()
    });
    let Some(row) = found else {
        return Err(AuthError::InvalidKey);
    };

    let token_info = UserApiToken {
        id: row.get(0),
        user_id: row.get(1),
        name: row.get(2),
        max_role: row.get(3),
        expires_at: row.get(4),
        disabled: row.get(5),
        created_at: row.get(6),
        last_used_at: row.get(7),
    };
    let user = User {
        id: row.get(8),
        email: row.get(9),
        name: row.get(10),
        oidc_subject: row.get(11),
        role: row.get(12),
        disabled: row.get(13),
        created_at: row.get(14),
        last_login_at: row.get(15),
        oidc_groups: row.get(16),
        custom_role_id: row.get(18),
    };

    if token_info.disabled {
        return Err(AuthError::Disabled);
    }
    if user.disabled {
        return Err(AuthError::Disabled);
    }
    if let Some(ref exp) = token_info.expires_at {
        match parse_expires_at(exp) {
            Some(expires) if Utc::now() <= expires => {}
            _ => return Err(AuthError::Expired),
        }
    }

    let _ = pool_exec(
        pool,
        &format!(
            "UPDATE user_api_tokens SET last_used_at = {} WHERE id = {}",
            ts_now(pool),
            ph1(pool)
        ),
        &[Arg::I64(token_info.id)],
    )
    .await;

    Ok((user, token_info))
}

async fn revoke_user_token_pool(
    pool: &DbPool,
    user_id: i64,
    token_id: i64,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM user_api_tokens WHERE id = $1 AND user_id = $2",
            "DELETE FROM user_api_tokens WHERE id = ? AND user_id = ?"
        ),
        &[Arg::I64(token_id), Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn admin_revoke_user_token_pool(pool: &DbPool, token_id: i64) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM user_api_tokens WHERE id = $1",
            "DELETE FROM user_api_tokens WHERE id = ?"
        ),
        &[Arg::I64(token_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn revoke_all_user_tokens_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM user_api_tokens WHERE user_id = $1",
            "DELETE FROM user_api_tokens WHERE user_id = ?"
        ),
        &[Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

async fn cleanup_expired_user_tokens_pool(pool: &DbPool) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        &format!(
            "DELETE FROM user_api_tokens WHERE expires_at IS NOT NULL AND expires_at <= {}",
            ts_now(pool)
        ),
        &[],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

// ── Token audit log ────────────────────────────────────────────────────

async fn log_token_event_pool(
    pool: &DbPool,
    token_id: Option<i64>,
    token_name: Option<String>,
    user_email: String,
    action: String,
    ip_addr: Option<String>,
    details: Option<String>,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO token_audit_log (token_id, token_name, user_email, action, ip_addr, details) VALUES ($1, $2, $3, $4, $5, $6)",
            "INSERT INTO token_audit_log (token_id, token_name, user_email, action, ip_addr, details) VALUES (?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::OptI64(token_id),
            Arg::OptStr(token_name),
            Arg::Str(user_email),
            Arg::Str(action),
            Arg::OptStr(ip_addr),
            Arg::OptStr(details),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn list_token_audit_log_pool(
    pool: &DbPool,
    limit: u32,
    user_email: Option<String>,
) -> rusqlite::Result<Vec<TokenAuditEntry>> {
    let (sql, args) = match user_email {
        Some(email) => (
            qsql!(
                pool,
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at FROM token_audit_log WHERE user_email = $1 ORDER BY id DESC LIMIT $2",
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at FROM token_audit_log WHERE user_email = ? ORDER BY id DESC LIMIT ?"
            ),
            vec![Arg::Str(email), Arg::I64(limit as i64)],
        ),
        None => (
            qsql!(
                pool,
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at FROM token_audit_log ORDER BY id DESC LIMIT $1",
                "SELECT id, token_id, token_name, user_email, action, ip_addr, details, created_at FROM token_audit_log ORDER BY id DESC LIMIT ?"
            ),
            vec![Arg::I64(limit as i64)],
        ),
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| TokenAuditEntry {
            id: row.get(0),
            token_id: row.get(1),
            token_name: row.get(2),
            user_email: row.get(3),
            action: row.get(4),
            ip_addr: row.get(5),
            details: row.get(6),
            created_at: row.get(7),
        })
        .collect())
}

async fn cleanup_old_audit_log_pool(pool: &DbPool, retain_days: u32) -> rusqlite::Result<usize> {
    let sql = match pool {
        DbPool::MySQL(_) => format!(
            "DELETE FROM token_audit_log WHERE created_at < {}",
            ts_now_minus_days(pool, "?")
        ),
        _ => qsql!(
            pool,
            "DELETE FROM token_audit_log WHERE created_at < to_char((now() at time zone 'utc') - make_interval(days => $1::int), 'YYYY-MM-DD HH24:MI:SS')",
            "DELETE FROM token_audit_log WHERE created_at < datetime('now', ?)"
        ).to_string(),
    }
    .to_string();
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (sql, vec![Arg::I64(retain_days as i64)]),
        DbPool::MySQL(_) => (sql, vec![Arg::I64(retain_days as i64)]),
        _ => (sql, vec![Arg::Str(format!("-{} days", retain_days))]),
    };
    let tok = pool_exec(pool, &sql, &args).await.map_err(map_sqlx_err)?;
    let sql2 = match pool {
        DbPool::MySQL(_) => format!(
            "DELETE FROM addressbook_audit_log WHERE created_at < {}",
            ts_now_minus_days(pool, "?")
        ),
        _ => qsql!(
            pool,
            "DELETE FROM addressbook_audit_log WHERE created_at < to_char((now() at time zone 'utc') - make_interval(days => $1::int), 'YYYY-MM-DD HH24:MI:SS')",
            "DELETE FROM addressbook_audit_log WHERE created_at < datetime('now', ?)"
        ).to_string(),
    }
    .to_string();
    let (sql2, args2) = match pool {
        DbPool::Postgres(_) => (sql2, vec![Arg::I64(retain_days as i64)]),
        DbPool::MySQL(_) => (sql2, vec![Arg::I64(retain_days as i64)]),
        _ => (sql2, vec![Arg::Str(format!("-{} days", retain_days))]),
    };
    let ab = pool_exec(pool, &sql2, &args2).await.map_err(map_sqlx_err)?;
    Ok((tok + ab) as usize)
}

// ── Connections (address book) audit log ───────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn log_addressbook_event_pool(
    pool: &DbPool,
    user_email: String,
    action: String,
    scope: String,
    folder_path: String,
    entry_name: Option<String>,
    ip_addr: Option<String>,
    details: Option<String>,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO addressbook_audit_log (user_email, action, scope, folder_path, entry_name, ip_addr, details) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            "INSERT INTO addressbook_audit_log (user_email, action, scope, folder_path, entry_name, ip_addr, details) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(user_email),
            Arg::Str(action),
            Arg::Str(scope),
            Arg::Str(folder_path),
            Arg::OptStr(entry_name),
            Arg::OptStr(ip_addr),
            Arg::OptStr(details),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn list_addressbook_audit_log_pool(
    pool: &DbPool,
    limit: u32,
    user_email: Option<String>,
) -> rusqlite::Result<Vec<AddressbookAuditEntry>> {
    let (sql, args) = match user_email {
        Some(email) => (
            qsql!(
                pool,
                "SELECT id, user_email, action, scope, folder_path, entry_name, ip_addr, details, created_at FROM addressbook_audit_log WHERE user_email = $1 ORDER BY id DESC LIMIT $2",
                "SELECT id, user_email, action, scope, folder_path, entry_name, ip_addr, details, created_at FROM addressbook_audit_log WHERE user_email = ? ORDER BY id DESC LIMIT ?"
            ),
            vec![Arg::Str(email), Arg::I64(limit as i64)],
        ),
        None => (
            qsql!(
                pool,
                "SELECT id, user_email, action, scope, folder_path, entry_name, ip_addr, details, created_at FROM addressbook_audit_log ORDER BY id DESC LIMIT $1",
                "SELECT id, user_email, action, scope, folder_path, entry_name, ip_addr, details, created_at FROM addressbook_audit_log ORDER BY id DESC LIMIT ?"
            ),
            vec![Arg::I64(limit as i64)],
        ),
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| AddressbookAuditEntry {
            id: row.get(0),
            user_email: row.get(1),
            action: row.get(2),
            scope: row.get(3),
            folder_path: row.get(4),
            entry_name: row.get(5),
            ip_addr: row.get(6),
            details: row.get(7),
            created_at: row.get(8),
        })
        .collect())
}

// ── Session history ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn insert_session_history_pool(
    pool: &DbPool,
    session_id: String,
    session_type: String,
    hostname: String,
    port: Option<i64>,
    username: String,
    created_by: String,
    address_book_entry: Option<String>,
    address_book_folder: Option<String>,
    entry_display_name: Option<String>,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO session_history \
             (session_id, session_type, hostname, port, username, created_by, address_book_entry, address_book_folder, entry_display_name) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            "INSERT INTO session_history \
             (session_id, session_type, hostname, port, username, created_by, address_book_entry, address_book_folder, entry_display_name) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(session_id),
            Arg::Str(session_type),
            Arg::Str(hostname),
            Arg::OptI64(port),
            Arg::Str(username),
            Arg::Str(created_by),
            Arg::OptStr(address_book_entry),
            Arg::OptStr(address_book_folder),
            Arg::OptStr(entry_display_name),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn end_session_history_pool(
    pool: &DbPool,
    session_id: String,
    status: String,
    duration_secs: i64,
    recording_file: Option<String>,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        &format!(
            "UPDATE session_history SET ended_at = {}, duration_secs = {}, status = {}, recording_file = {} WHERE session_id = {} AND ended_at IS NULL",
            ts_now(pool), ph2(pool), ph3(pool), ph4(pool), ph1(pool)
        ),
        &[
            Arg::Str(session_id),
            Arg::I64(duration_secs),
            Arg::Str(status),
            Arg::OptStr(recording_file),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn update_session_history_reason_pool(
    pool: &DbPool,
    session_id: String,
    reason: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        &format!(
            "UPDATE session_history SET reason = {ph1} WHERE session_id = {ph2} AND reason IS NULL",
            ph1 = ph1(pool),
            ph2 = ph2(pool)
        ),
        &[Arg::Str(reason), Arg::Str(session_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

// ── Session registry (enterprise HA) ───────────────────────────────

/// Upsert differs only in the conflict clause: Postgres and SQLite share
/// `ON CONFLICT (session_id) DO UPDATE SET`, MySQL uses
/// `ON DUPLICATE KEY UPDATE`. Placeholder syntax differs too (`$n` on
/// Postgres, `?` elsewhere) — selected by backend.
fn registry_upsert_sql(pool: &DbPool) -> String {
    match pool {
        DbPool::Postgres(_) => "INSERT INTO session_registry \
             (session_id, owner_instance, owner_base_url, session_type, status, \
              hostname, username, created_by, created_at, last_active_at, connection_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
             ON CONFLICT (session_id) DO UPDATE SET \
              owner_instance = excluded.owner_instance, \
              owner_base_url = excluded.owner_base_url, \
              session_type = excluded.session_type, \
              status = excluded.status, \
              hostname = excluded.hostname, \
              username = excluded.username, \
              created_by = excluded.created_by, \
              created_at = excluded.created_at, \
              last_active_at = excluded.last_active_at, \
              connection_id = excluded.connection_id"
            .to_string(),
        DbPool::MySQL(_) => "INSERT INTO session_registry \
             (session_id, owner_instance, owner_base_url, session_type, status, \
              hostname, username, created_by, created_at, last_active_at, connection_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
              owner_instance = VALUES(owner_instance), \
              owner_base_url = VALUES(owner_base_url), \
              session_type = VALUES(session_type), \
              status = VALUES(status), \
              hostname = VALUES(hostname), \
              username = VALUES(username), \
              created_by = VALUES(created_by), \
              created_at = VALUES(created_at), \
              last_active_at = VALUES(last_active_at), \
              connection_id = VALUES(connection_id)"
            .to_string(),
        _ => "INSERT INTO session_registry \
             (session_id, owner_instance, owner_base_url, session_type, status, \
              hostname, username, created_by, created_at, last_active_at, connection_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (session_id) DO UPDATE SET \
              owner_instance = excluded.owner_instance, \
              owner_base_url = excluded.owner_base_url, \
              session_type = excluded.session_type, \
              status = excluded.status, \
              hostname = excluded.hostname, \
              username = excluded.username, \
              created_by = excluded.created_by, \
              created_at = excluded.created_at, \
              last_active_at = excluded.last_active_at, \
              connection_id = excluded.connection_id"
            .to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn registry_upsert_session_pool(
    pool: &DbPool,
    session_id: String,
    owner_instance: String,
    owner_base_url: String,
    session_type: String,
    status: String,
    hostname: String,
    username: String,
    created_by: String,
    created_at: String,
    last_active_at: String,
    connection_id: String,
) -> rusqlite::Result<()> {
    let sql = registry_upsert_sql(pool);
    pool_exec(
        pool,
        &sql,
        &[
            Arg::Str(session_id),
            Arg::Str(owner_instance),
            Arg::Str(owner_base_url),
            Arg::Str(session_type),
            Arg::Str(status),
            Arg::Str(hostname),
            Arg::Str(username),
            Arg::Str(created_by),
            Arg::Str(created_at),
            Arg::Str(last_active_at),
            Arg::Str(connection_id),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn registry_set_status_pool(
    pool: &DbPool,
    session_id: String,
    status: String,
    last_active_at: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE session_registry SET status = $1, last_active_at = $2 WHERE session_id = $3",
            "UPDATE session_registry SET status = ?, last_active_at = ? WHERE session_id = ?"
        ),
        &[
            Arg::Str(status),
            Arg::Str(last_active_at),
            Arg::Str(session_id),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn registry_set_shadow_token_pool(
    pool: &DbPool,
    session_id: String,
    token_hash: String,
    issued_by: String,
    expires_at: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE session_registry SET shadow_token_hash = $1, shadow_issued_by = $2, shadow_expires_at = $3 WHERE session_id = $4",
            "UPDATE session_registry SET shadow_token_hash = ?, shadow_issued_by = ?, shadow_expires_at = ? WHERE session_id = ?"
        ),
        &[
            Arg::Str(token_hash),
            Arg::Str(issued_by),
            Arg::Str(expires_at),
            Arg::Str(session_id),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn registry_delete_session_pool(pool: &DbPool, session_id: String) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM session_registry WHERE session_id = $1",
            "DELETE FROM session_registry WHERE session_id = ?"
        ),
        &[Arg::Str(session_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

const REGISTRY_COLUMNS: &str = "session_id, owner_instance, owner_base_url, session_type, status, \
     hostname, username, created_by, created_at, last_active_at, connection_id, \
     shadow_token_hash, shadow_issued_by, shadow_expires_at";

fn registry_row_from(r: &RowProxy) -> SessionRegistryRow {
    SessionRegistryRow {
        session_id: r.get(0),
        owner_instance: r.get(1),
        owner_base_url: r.get(2),
        session_type: r.get(3),
        status: r.get(4),
        hostname: r.get(5),
        username: r.get(6),
        created_by: r.get(7),
        created_at: r.get(8),
        last_active_at: r.get(9),
        connection_id: r.get(10),
        shadow_token_hash: r.get(11),
        shadow_issued_by: r.get(12),
        shadow_expires_at: r.get(13),
    }
}

async fn registry_get_session_pool(
    pool: &DbPool,
    session_id: String,
) -> rusqlite::Result<Option<SessionRegistryRow>> {
    let sql = format!(
        "SELECT {REGISTRY_COLUMNS} FROM session_registry WHERE session_id = {}",
        match pool {
            DbPool::Postgres(_) => "$1",
            _ => "?",
        }
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::Str(session_id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::Str(session_id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::Str(session_id)]).await,
        DbPool::None => return Ok(None),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| registry_row_from(&r)))
}

async fn registry_list_sessions_pool(pool: &DbPool) -> rusqlite::Result<Vec<SessionRegistryRow>> {
    let sql = format!("SELECT {REGISTRY_COLUMNS} FROM session_registry ORDER BY created_at");
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, &sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &sql, &[]).await,
        DbPool::None => return Ok(Vec::new()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(registry_row_from).collect())
}

async fn registry_list_owned_pool(
    pool: &DbPool,
    owner_instance: String,
) -> rusqlite::Result<Vec<String>> {
    let sql = match pool {
        DbPool::Postgres(_) => "SELECT session_id FROM session_registry WHERE owner_instance = $1",
        _ => "SELECT session_id FROM session_registry WHERE owner_instance = ?",
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[Arg::Str(owner_instance)]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[Arg::Str(owner_instance)]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[Arg::Str(owner_instance)]).await,
        DbPool::None => return Ok(Vec::new()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|r| r.get::<String>(0)).collect())
}

async fn registry_delete_stale_pool(
    pool: &DbPool,
    owner_instance: String,
    pending_cutoff: String,
    terminal_cutoff: String,
    live_cutoff: Option<String>,
) -> rusqlite::Result<usize> {
    // Terminal rows: any instance may delete them (idempotent). Live rows of
    // other instances: only when the live sweep is enabled.
    let (sql, args) = match (pool, live_cutoff) {
        // Postgres: numbered placeholders — the live clause binds AFTER the
        // first two, so its `$n` must reflect that.
        (DbPool::Postgres(_), Some(cutoff)) => (
            "DELETE FROM session_registry WHERE \
               (status = 'pending' AND created_at < $1) \
             OR (status IN ('completed','error','expired') AND created_at < $2) \
             OR (status NOT IN ('pending','completed','error','expired') \
                 AND owner_instance <> $3 AND created_at < $4)"
                .to_string(),
            vec![
                Arg::Str(pending_cutoff),
                Arg::Str(terminal_cutoff),
                Arg::Str(owner_instance),
                Arg::Str(cutoff),
            ],
        ),
        (_, Some(cutoff)) => (
            "DELETE FROM session_registry WHERE \
               (status = 'pending' AND created_at < ?) \
             OR (status IN ('completed','error','expired') AND created_at < ?) \
             OR (status NOT IN ('pending','completed','error','expired') \
                 AND owner_instance <> ? AND created_at < ?)"
                .to_string(),
            vec![
                Arg::Str(pending_cutoff),
                Arg::Str(terminal_cutoff),
                Arg::Str(owner_instance),
                Arg::Str(cutoff),
            ],
        ),
        (DbPool::Postgres(_), None) => (
            "DELETE FROM session_registry WHERE \
               (status = 'pending' AND created_at < $1) \
             OR (status IN ('completed','error','expired') AND created_at < $2)"
                .to_string(),
            vec![Arg::Str(pending_cutoff), Arg::Str(terminal_cutoff)],
        ),
        (_, None) => (
            "DELETE FROM session_registry WHERE \
               (status = 'pending' AND created_at < ?) \
             OR (status IN ('completed','error','expired') AND created_at < ?)"
                .to_string(),
            vec![Arg::Str(pending_cutoff), Arg::Str(terminal_cutoff)],
        ),
    };
    let n = pool_exec(pool, &sql, &args).await.map_err(map_sqlx_err)?;
    Ok(n as usize)
}

async fn registry_delete_all_owned_pool(
    pool: &DbPool,
    owner_instance: String,
) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM session_registry WHERE owner_instance = $1",
            "DELETE FROM session_registry WHERE owner_instance = ?"
        ),
        &[Arg::Str(owner_instance)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

// ── WS ticket persistence (enterprise HA) ──────────────────────────

async fn ws_ticket_insert_pool(
    pool: &DbPool,
    ticket_hash: String,
    identity_json: String,
    session_id: Option<String>,
    issued_by: String,
    expires_at: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO ws_tickets (ticket_hash, identity_json, session_id, issued_by, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
            "INSERT INTO ws_tickets (ticket_hash, identity_json, session_id, issued_by, expires_at) \
             VALUES (?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(ticket_hash),
            Arg::Str(identity_json),
            Arg::OptStr(session_id),
            Arg::Str(issued_by),
            Arg::Str(expires_at),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn ws_ticket_get_pool(
    pool: &DbPool,
    ticket_hash: String,
) -> rusqlite::Result<Option<(String, String)>> {
    let sql = match pool {
        DbPool::Postgres(_) => {
            "SELECT identity_json, expires_at FROM ws_tickets WHERE ticket_hash = $1"
        }
        _ => "SELECT identity_json, expires_at FROM ws_tickets WHERE ticket_hash = ?",
    };
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &[Arg::Str(ticket_hash)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &[Arg::Str(ticket_hash)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &[Arg::Str(ticket_hash)]).await,
        DbPool::None => return Ok(None),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| (r.get::<String>(0), r.get::<String>(1))))
}

async fn ws_ticket_delete_pool(pool: &DbPool, ticket_hash: String) -> rusqlite::Result<bool> {
    let n = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM ws_tickets WHERE ticket_hash = $1",
            "DELETE FROM ws_tickets WHERE ticket_hash = ?"
        ),
        &[Arg::Str(ticket_hash)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n > 0)
}

async fn ws_ticket_cleanup_expired_pool(pool: &DbPool, cutoff: String) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM ws_tickets WHERE expires_at < $1",
            "DELETE FROM ws_tickets WHERE expires_at < ?"
        ),
        &[Arg::Str(cutoff)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

/// Build the WHERE conditions and bind args for the dynamic
/// session-history queries. Placeholders are backend-correct: `$n` for
/// Postgres (reused for the entry LIKE pair), `?` for MySQL/SQLite (one
/// bind per marker).
fn session_history_conditions(
    is_pg: bool,
    user: Option<&str>,
    entry: Option<&str>,
    session_type: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
) -> (Vec<String>, Vec<Arg>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Arg> = Vec::new();
    if let Some(u) = user {
        conditions.push(format!(
            "created_by LIKE {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(format!("%{}%", u)));
    }
    if let Some(e) = entry {
        if is_pg {
            let ph = placeholder(true, args.len() + 1);
            conditions.push(format!(
                "(address_book_entry LIKE {ph} OR entry_display_name LIKE {ph})"
            ));
            args.push(Arg::Str(format!("%{}%", e)));
        } else {
            conditions.push("(address_book_entry LIKE ? OR entry_display_name LIKE ?)".to_string());
            let v = format!("%{}%", e);
            args.push(Arg::Str(v.clone()));
            args.push(Arg::Str(v));
        }
    }
    if let Some(t) = session_type {
        conditions.push(format!(
            "session_type = {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(t.to_string()));
    }
    if let Some(f) = from {
        conditions.push(format!(
            "started_at >= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(f.to_string()));
    }
    if let Some(t) = to {
        conditions.push(format!(
            "started_at <= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(t.to_string()));
    }
    if conditions.is_empty() {
        conditions.push("1=1".to_string());
    }
    (conditions, args)
}

/// `$n` for Postgres, `?` for MySQL/SQLite.
fn placeholder(is_pg: bool, n: usize) -> String {
    if is_pg {
        format!("${}", n)
    } else {
        "?".to_string()
    }
}

/// Placeholder helpers for the common argument positions (Postgres $n,
/// MySQL/SQLite ?).
fn ph1(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 1)
}
fn ph2(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 2)
}
fn ph3(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 3)
}
fn ph4(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 4)
}
fn ph5(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 5)
}
fn ph6(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 6)
}
fn ph7(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 7)
}
fn ph8(pool: &DbPool) -> String {
    placeholder(matches!(pool, DbPool::Postgres(_)), 8)
}

/// Backend "now" expression producing a text timestamp in the SQLite
/// format ('YYYY-MM-DD HH:MM:SS') so string comparisons behave the same on
/// every backend.
fn ts_now(pool: &DbPool) -> &'static str {
    match pool {
        DbPool::Postgres(_) => "to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')",
        DbPool::MySQL(_) => "DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')",
        _ => "datetime('now')",
    }
}

/// Backend "now + N seconds" expression; `param` is the placeholder text
/// for the bound interval value.
fn ts_now_plus_secs(pool: &DbPool, param: &str) -> String {
    match pool {
        DbPool::Postgres(_) => format!(
            "to_char((now() at time zone 'utc') + make_interval(secs => {param}), 'YYYY-MM-DD HH24:MI:SS')"
        ),
        DbPool::MySQL(_) => format!(
            "DATE_FORMAT(UTC_TIMESTAMP() + INTERVAL {param} SECOND, '%Y-%m-%d %H:%i:%s')"
        ),
        _ => format!("datetime('now', {param})"),
    }
}

/// Backend "now - N days" expression; `param` is the placeholder text.
fn ts_now_minus_days(pool: &DbPool, param: &str) -> String {
    match pool {
        DbPool::Postgres(_) => format!(
            "to_char((now() at time zone 'utc') - make_interval(days => {param}), 'YYYY-MM-DD HH24:MI:SS')"
        ),
        DbPool::MySQL(_) => format!(
            "DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL {param} DAY, '%Y-%m-%d %H:%i:%s')"
        ),
        _ => format!("datetime('now', {param})"),
    }
}

/// Backend "now - N seconds" expression; `param` is the placeholder text.
fn ts_now_minus_secs(pool: &DbPool, param: &str) -> String {
    match pool {
        DbPool::Postgres(_) => format!(
            "to_char((now() at time zone 'utc') - make_interval(secs => {param}), 'YYYY-MM-DD HH24:MI:SS')"
        ),
        DbPool::MySQL(_) => format!(
            "DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL {param} SECOND, '%Y-%m-%d %H:%i:%s')"
        ),
        _ => format!("datetime('now', {param})"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn query_session_history_pool(
    pool: &DbPool,
    user: Option<String>,
    entry: Option<String>,
    session_type: Option<String>,
    from: Option<String>,
    to: Option<String>,
    limit: u32,
    offset: u32,
) -> rusqlite::Result<(Vec<serde_json::Value>, u32)> {
    let is_pg = matches!(pool, DbPool::Postgres(_));
    let (conditions, mut args) = session_history_conditions(
        is_pg,
        user.as_deref(),
        entry.as_deref(),
        session_type.as_deref(),
        from.as_deref(),
        to.as_deref(),
    );
    let where_clause = conditions.join(" AND ");
    let count_sql = format!("SELECT COUNT(*) FROM session_history WHERE {where_clause}");
    let count_args = args.clone();
    let total_row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &count_sql, &count_args).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &count_sql, &count_args).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &count_sql, &count_args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let total: i64 = total_row.map(|r| r.get(0)).unwrap_or(0);

    let limit_ph = placeholder(is_pg, args.len() + 1);
    let offset_ph = placeholder(is_pg, args.len() + 2);
    let query_sql = format!(
        "SELECT session_id, session_type, hostname, port, username, created_by, \
                address_book_entry, address_book_folder, entry_display_name, \
                reason, started_at, ended_at, duration_secs, recording_file, status \
         FROM session_history WHERE {where_clause} ORDER BY started_at DESC LIMIT {limit_ph} OFFSET {offset_ph}"
    );
    args.push(Arg::I64(limit as i64));
    args.push(Arg::I64(offset as i64));
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &query_sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, &query_sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &query_sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok((
        rows.iter()
            .map(|row| session_history_json_row!(row))
            .collect(),
        total as u32,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn stream_session_history_csv_pool(
    pool: &DbPool,
    user: Option<String>,
    entry: Option<String>,
    session_type: Option<String>,
    from: Option<String>,
    to: Option<String>,
) -> Result<
    Vec<(
        String,
        String,
        String,
        Option<i64>,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        String,
        Option<String>,
        Option<String>,
    )>,
    rusqlite::Error,
> {
    let is_pg = matches!(pool, DbPool::Postgres(_));
    let (conditions, args) = session_history_conditions(
        is_pg,
        user.as_deref(),
        entry.as_deref(),
        session_type.as_deref(),
        from.as_deref(),
        to.as_deref(),
    );
    let where_clause = conditions.join(" AND ");
    let sql = format!(
        "SELECT session_id, session_type, hostname, port, username, created_by, \
                COALESCE(entry_display_name, address_book_entry, ''), \
                COALESCE(address_book_folder, ''), \
                started_at, ended_at, duration_secs, status, recording_file, \
                entry_display_name \
         FROM session_history WHERE {where_clause} ORDER BY started_at DESC"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, &sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            (
                row.get::<String>(0),
                row.get::<String>(1),
                row.get::<String>(2),
                row.get::<Option<i64>>(3),
                row.get::<String>(4),
                row.get::<String>(5),
                row.get::<String>(6),
                row.get::<String>(7),
                row.get::<String>(8),
                row.get::<Option<String>>(9),
                row.get::<Option<i64>>(10),
                row.get::<String>(11),
                row.get::<Option<String>>(12),
                row.get::<Option<String>>(13),
            )
        })
        .collect())
}

async fn top_connections_pool(
    pool: &DbPool,
    limit: u32,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let sql = qsql!(
        pool,
        "SELECT COALESCE(entry_display_name, hostname) AS name, \
                address_book_entry, address_book_folder, session_type, \
                COUNT(*) AS session_count, \
                COALESCE(SUM(duration_secs), 0) AS total_secs \
         FROM session_history \
         GROUP BY COALESCE(address_book_entry, hostname || ':' || COALESCE(port::text, '0')) \
         ORDER BY session_count DESC \
         LIMIT $1",
        "SELECT COALESCE(entry_display_name, hostname) AS name, \
                address_book_entry, address_book_folder, session_type, \
                COUNT(*) AS session_count, \
                COALESCE(SUM(duration_secs), 0) AS total_secs \
         FROM session_history \
         GROUP BY COALESCE(address_book_entry, hostname || ':' || COALESCE(port, 0)) \
         ORDER BY session_count DESC \
         LIMIT ?"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[Arg::I64(limit as i64)]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[Arg::I64(limit as i64)]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[Arg::I64(limit as i64)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "name": row.get::<String>(0),
                "address_book_entry": row.get::<Option<String>>(1),
                "folder": row.get::<Option<String>>(2),
                "session_type": row.get::<Option<String>>(3),
                "session_count": row.get::<i64>(4),
                "total_hours": row.get::<i64>(5) as f64 / 3600.0,
            })
        })
        .collect())
}

async fn top_users_pool(pool: &DbPool, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT created_by, COUNT(*) AS session_count, COALESCE(SUM(duration_secs), 0) AS total_secs, MAX(started_at) AS last_session FROM session_history GROUP BY created_by ORDER BY session_count DESC LIMIT $1", &[Arg::I64(limit as i64)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT created_by, COUNT(*) AS session_count, COALESCE(SUM(duration_secs), 0) AS total_secs, MAX(started_at) AS last_session FROM session_history GROUP BY created_by ORDER BY session_count DESC LIMIT ?", &[Arg::I64(limit as i64)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT created_by, COUNT(*) AS session_count, COALESCE(SUM(duration_secs), 0) AS total_secs, MAX(started_at) AS last_session FROM session_history GROUP BY created_by ORDER BY session_count DESC LIMIT ?", &[Arg::I64(limit as i64)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "user": row.get::<String>(0),
                "session_count": row.get::<i64>(1),
                "total_hours": row.get::<i64>(2) as f64 / 3600.0,
                "last_session": row.get::<String>(3),
            })
        })
        .collect())
}

async fn session_summary_pool(pool: &DbPool) -> rusqlite::Result<serde_json::Value> {
    let total_sessions = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, "SELECT COUNT(*) FROM session_history", &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .map(|r| r.get::<i64>(0))
    .unwrap_or(0);
    let active_sessions = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT COUNT(*) FROM session_history WHERE status = 'active'",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT COUNT(*) FROM session_history WHERE status = 'active'",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT COUNT(*) FROM session_history WHERE status = 'active'",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .map(|r| r.get::<i64>(0))
    .unwrap_or(0);
    let total_users = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, "SELECT COUNT(*) FROM users", &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .map(|r| r.get::<i64>(0))
    .unwrap_or(0);
    let uptime_secs = crate::metrics::uptime_seconds();
    Ok(serde_json::json!({
        "total_sessions": total_sessions,
        "active_sessions": active_sessions,
        "total_users": total_users,
        "uptime_secs": uptime_secs,
    }))
}

async fn session_activity_by_hour_pool(
    pool: &DbPool,
    hours: i32,
) -> rusqlite::Result<Vec<serde_json::Value>> {
    let sql = qsql!(
        pool,
        "SELECT to_char(started_at, 'YYYY-MM-DD HH24:00:00') AS hour, COUNT(*) AS count \
         FROM session_history \
         WHERE started_at >= to_char((now() at time zone 'utc') - make_interval(hours => $1::int), 'YYYY-MM-DD HH24:MI:SS') \
         GROUP BY hour ORDER BY hour ASC",
        "SELECT strftime('%Y-%m-%d %H:00:00', started_at) AS hour, COUNT(*) AS count \
         FROM session_history \
         WHERE started_at >= datetime('now', ?) \
         GROUP BY hour ORDER BY hour ASC"
    );
    let mysql_sql =
        "SELECT DATE_FORMAT(started_at, '%Y-%m-%d %H:00:00') AS hour, COUNT(*) AS count \
         FROM session_history \
         WHERE started_at >= DATE_FORMAT(UTC_TIMESTAMP() - INTERVAL ? HOUR, '%Y-%m-%d %H:%i:%s') \
         GROUP BY hour ORDER BY hour ASC";
    let (sql, args) = match pool {
        DbPool::MySQL(_) => (mysql_sql, vec![Arg::I64(hours as i64)]),
        DbPool::Postgres(_) => (sql, vec![Arg::I64(hours as i64)]),
        _ => (sql, vec![Arg::Str(format!("-{} hours", hours))]),
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "hour": row.get::<String>(0),
                "count": row.get::<i64>(1),
            })
        })
        .collect())
}

async fn cleanup_session_history_pool(pool: &DbPool, retain_days: u32) -> rusqlite::Result<usize> {
    if retain_days == 0 {
        return Ok(0);
    }
    let sql = match pool {
        DbPool::MySQL(_) => format!(
            "DELETE FROM session_history WHERE started_at < {}",
            ts_now_minus_days(pool, "?")
        ),
        _ => qsql!(
            pool,
            "DELETE FROM session_history WHERE started_at < to_char((now() at time zone 'utc') - make_interval(days => $1::int), 'YYYY-MM-DD HH24:MI:SS')",
            "DELETE FROM session_history WHERE started_at < datetime('now', ?)"
        ).to_string(),
    }
    .to_string();
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (sql, vec![Arg::I64(retain_days as i64)]),
        DbPool::MySQL(_) => (sql, vec![Arg::I64(retain_days as i64)]),
        _ => (sql, vec![Arg::Str(format!("-{} days", retain_days))]),
    };
    let n = pool_exec(pool, &sql, &args).await.map_err(map_sqlx_err)?;
    Ok(n as usize)
}

// ── TOTP secrets ───────────────────────────────────────────────────────

macro_rules! totp_row {
    ($row:expr) => {
        TotpSecret {
            user_id: $row.get(0),
            secret_b32: $row.get(1),
            algorithm: $row.get(2),
            digits: $row.get::<i64>(3) as u8,
            period: $row.get::<i64>(4) as u16,
            enabled: $row.get(5),
        }
    };
}

async fn store_totp_secret_pool(
    pool: &DbPool,
    user_id: i64,
    secret_b32: String,
    algorithm: String,
    digits: u8,
    period: u16,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO totp_secrets (user_id, secret_b32, algorithm, digits, period, enabled) \
             VALUES ($1, $2, $3, $4, $5, TRUE) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 secret_b32 = excluded.secret_b32, \
                 algorithm = excluded.algorithm, \
                 digits = excluded.digits, \
                 period = excluded.period, \
                 enabled = TRUE",
            "INSERT INTO totp_secrets (user_id, secret_b32, algorithm, digits, period, enabled) \
             VALUES (?, ?, ?, ?, ?, 1) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 secret_b32 = excluded.secret_b32, \
                 algorithm = excluded.algorithm, \
                 digits = excluded.digits, \
                 period = excluded.period, \
                 enabled = 1"
        ),
        &[
            Arg::I64(user_id),
            Arg::Str(secret_b32),
            Arg::Str(algorithm),
            Arg::I64(digits as i64),
            Arg::I64(period as i64),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn get_totp_secret_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<Option<TotpSecret>> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT user_id, secret_b32, algorithm, digits, period, enabled FROM totp_secrets WHERE user_id = $1", &[Arg::I64(user_id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT user_id, secret_b32, algorithm, digits, period, enabled FROM totp_secrets WHERE user_id = ?", &[Arg::I64(user_id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT user_id, secret_b32, algorithm, digits, period, enabled FROM totp_secrets WHERE user_id = ?", &[Arg::I64(user_id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| totp_row!(&r)))
}

async fn set_totp_enabled_pool(
    pool: &DbPool,
    user_id: i64,
    enabled: bool,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE totp_secrets SET enabled = $1 WHERE user_id = $2",
            "UPDATE totp_secrets SET enabled = ? WHERE user_id = ?"
        ),
        &[Arg::Bool(enabled), Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_totp_secret_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM totp_secrets WHERE user_id = $1",
            "DELETE FROM totp_secrets WHERE user_id = ?"
        ),
        &[Arg::I64(user_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn user_totp_enabled_pool(pool: &DbPool, user_id: i64) -> rusqlite::Result<bool> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT enabled FROM totp_secrets WHERE user_id = $1",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT enabled FROM totp_secrets WHERE user_id = ?",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT enabled FROM totp_secrets WHERE user_id = ?",
                &[Arg::I64(user_id)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<bool>(0)).unwrap_or(false))
}

// ── Pending MFA ────────────────────────────────────────────────────────

macro_rules! pending_mfa_row {
    ($row:expr) => {
        PendingMfa {
            user_id: $row.get(0),
            user_email: $row.get(1),
            user_name: $row.get(2),
            user_role: $row.get(3),
            oidc_subject: $row.get(4),
            created_at: $row.get(5),
            expires_at: $row.get(6),
        }
    };
}

async fn create_pending_mfa_pool(
    pool: &DbPool,
    user_id: i64,
    user_email: String,
    user_name: String,
    user_role: String,
    oidc_subject: Option<String>,
    ttl_secs: u64,
) -> rusqlite::Result<String> {
    let token = generate_key();
    let token_hash = hash_key(&token);
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (
            format!(
                "INSERT INTO auth_pending_mfa (token_hash, user_id, user_email, user_name, user_role, oidc_subject, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, {})",
                ts_now_plus_secs(pool, "$7")
            ),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::Str(user_email),
                Arg::Str(user_name),
                Arg::Str(user_role),
                Arg::OptStr(oidc_subject),
                Arg::I64(ttl_secs as i64),
            ],
        ),
        DbPool::MySQL(_) => (
            format!(
                "INSERT INTO auth_pending_mfa (token_hash, user_id, user_email, user_name, user_role, oidc_subject, expires_at) \
                 VALUES (?, ?, ?, ?, ?, ?, {})",
                ts_now_plus_secs(pool, "?")
            ),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::Str(user_email),
                Arg::Str(user_name),
                Arg::Str(user_role),
                Arg::OptStr(oidc_subject),
                Arg::I64(ttl_secs as i64),
            ],
        ),
        _ => (
            "INSERT INTO auth_pending_mfa (token_hash, user_id, user_email, user_name, user_role, oidc_subject, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, datetime('now', ?))"
                .to_string(),
            vec![
                Arg::Str(token_hash),
                Arg::I64(user_id),
                Arg::Str(user_email),
                Arg::Str(user_name),
                Arg::Str(user_role),
                Arg::OptStr(oidc_subject),
                Arg::Str(format!("+{} seconds", ttl_secs)),
            ],
        ),
    };
    pool_exec(pool, &sql, &args).await.map_err(map_sqlx_err)?;
    Ok(token)
}

async fn get_pending_mfa_pool(
    pool: &DbPool,
    token: String,
) -> rusqlite::Result<Option<PendingMfa>> {
    let token_hash = hash_key(&token);
    let sql = format!(
        "SELECT user_id, user_email, user_name, user_role, oidc_subject, created_at, expires_at \
         FROM auth_pending_mfa WHERE token_hash = {} AND expires_at > {}",
        ph1(pool),
        ts_now(pool)
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::Str(token_hash)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| pending_mfa_row!(&r)))
}

async fn delete_pending_mfa_pool(pool: &DbPool, token: String) -> rusqlite::Result<bool> {
    let token_hash = hash_key(&token);
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM auth_pending_mfa WHERE token_hash = $1",
            "DELETE FROM auth_pending_mfa WHERE token_hash = ?"
        ),
        &[Arg::Str(token_hash)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn cleanup_expired_pending_mfa_pool(pool: &DbPool) -> rusqlite::Result<usize> {
    let n = pool_exec(
        pool,
        &format!(
            "DELETE FROM auth_pending_mfa WHERE expires_at <= {}",
            ts_now(pool)
        ),
        &[],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(n as usize)
}

// ── Jump hosts ─────────────────────────────────────────────────────────

macro_rules! jump_host_row {
    ($row:expr) => {
        JumpHostRecord {
            id: $row.get(0),
            name: $row.get(1),
            hostname: $row.get(2),
            port: $row.get::<i64>(3) as u16,
            username: $row.get(4),
            auth_method: $row.get(5),
            key_path: $row.get(6),
            created_at: $row.get(7),
            updated_at: $row.get(8),
        }
    };
}

async fn create_jump_host_pool(
    pool: &DbPool,
    name: String,
    hostname: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: Option<String>,
) -> rusqlite::Result<String> {
    let id = generate_key();
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO jump_hosts (id, name, hostname, port, username, auth_method, key_path) VALUES ($1, $2, $3, $4, $5, $6, $7)",
            "INSERT INTO jump_hosts (id, name, hostname, port, username, auth_method, key_path) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(id.clone()),
            Arg::Str(name),
            Arg::Str(hostname),
            Arg::I64(port as i64),
            Arg::Str(username),
            Arg::Str(auth_method),
            Arg::OptStr(key_path),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

async fn list_jump_hosts_pool(pool: &DbPool) -> rusqlite::Result<Vec<JumpHostRecord>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts ORDER BY name", &[]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts ORDER BY name", &[]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts ORDER BY name", &[]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| jump_host_row!(row)).collect())
}

async fn get_jump_host_pool(pool: &DbPool, id: String) -> rusqlite::Result<Option<JumpHostRecord>> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts WHERE id = $1", &[Arg::Str(id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts WHERE id = ?", &[Arg::Str(id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT id, name, hostname, port, username, auth_method, key_path, created_at, updated_at FROM jump_hosts WHERE id = ?", &[Arg::Str(id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| jump_host_row!(&r)))
}

#[allow(clippy::too_many_arguments)]
async fn update_jump_host_pool(
    pool: &DbPool,
    id: String,
    name: String,
    hostname: String,
    port: u16,
    username: String,
    auth_method: String,
    key_path: Option<String>,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        &format!(
            "UPDATE jump_hosts SET name = {}, hostname = {}, port = {}, username = {}, auth_method = {}, key_path = {}, updated_at = {} WHERE id = {}",
            ph1(pool), ph2(pool), ph3(pool), ph4(pool), ph5(pool), ph6(pool), ts_now(pool), ph7(pool)
        ),
        &[
            Arg::Str(name),
            Arg::Str(hostname),
            Arg::I64(port as i64),
            Arg::Str(username),
            Arg::Str(auth_method),
            Arg::OptStr(key_path),
            Arg::Str(id),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_jump_host_pool(pool: &DbPool, id: String) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM jump_hosts WHERE id = $1",
            "DELETE FROM jump_hosts WHERE id = ?"
        ),
        &[Arg::Str(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

// ── Address book (DB-backed storage) ───────────────────────────────────

macro_rules! ab_folder_row {
    ($row:expr) => {
        AbFolder {
            id: $row.get(0),
            scope: $row.get(1),
            name: $row.get(2),
            description: $row.get(3),
            allowed_groups: $row.get(4),
            inherit_from_parent: $row.get(5),
            created_at: $row.get(6),
            updated_at: $row.get(7),
        }
    };
}

macro_rules! ab_entry_row {
    ($row:expr) => {
        AbEntry {
            id: $row.get(0),
            folder_id: $row.get(1),
            name: $row.get(2),
            display_name: $row.get(3),
            protocol: $row.get(4),
            hostname: $row.get(5),
            port: $row.get::<Option<i64>>(6).map(|p| p as u16),
            username: $row.get(7),
            protocol_config: $row.get(8),
            allowed_groups: $row.get(9),
            created_at: $row.get(10),
            updated_at: $row.get(11),
        }
    };
}

macro_rules! ab_cred_row {
    ($row:expr) => {
        AbCredential {
            id: $row.get(0),
            entry_id: $row.get(1),
            credential_type: $row.get(2),
            credential_data: $row.get(3),
        }
    };
}

async fn create_ab_folder_pool(
    pool: &DbPool,
    scope: String,
    name: String,
    description: String,
    allowed_groups: String,
    inherit_from_parent: bool,
) -> rusqlite::Result<i64> {
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO address_book_folders (scope, name, description, allowed_groups, inherit_from_parent) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            "INSERT INTO address_book_folders (scope, name, description, allowed_groups, inherit_from_parent) VALUES (?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(scope),
            Arg::Str(name),
            Arg::Str(description),
            Arg::Str(allowed_groups),
            Arg::Bool(inherit_from_parent),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

async fn update_ab_folder_pool(
    pool: &DbPool,
    scope: String,
    name: String,
    description: String,
    allowed_groups: String,
    inherit_from_parent: bool,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        &format!(
            "UPDATE address_book_folders SET description = {}, allowed_groups = {}, inherit_from_parent = {}, updated_at = {} WHERE scope = {} AND name = {}",
            ph3(pool), ph4(pool), ph5(pool), ts_now(pool), ph1(pool), ph2(pool)
        ),
        &[
            Arg::Str(scope),
            Arg::Str(name),
            Arg::Str(description),
            Arg::Str(allowed_groups),
            Arg::Bool(inherit_from_parent),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn list_ab_folders_pool(
    pool: &DbPool,
    scope: Option<String>,
) -> rusqlite::Result<Vec<AbFolder>> {
    let (sql, args) = match scope {
        Some(s) => (
            qsql!(
                pool,
                "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders WHERE scope = $1 ORDER BY name",
                "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders WHERE scope = ? ORDER BY name"
            ),
            vec![Arg::Str(s)],
        ),
        None => (
            qsql!(
                pool,
                "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders ORDER BY scope, name",
                "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders ORDER BY scope, name"
            ),
            vec![],
        ),
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| ab_folder_row!(row)).collect())
}

async fn get_ab_folder_pool(
    pool: &DbPool,
    scope: String,
    name: String,
) -> rusqlite::Result<AbFolder> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders WHERE scope = $1 AND name = $2", &[Arg::Str(scope), Arg::Str(name)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders WHERE scope = ? AND name = ?", &[Arg::Str(scope), Arg::Str(name)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT id, scope, name, description, allowed_groups, inherit_from_parent, created_at, updated_at FROM address_book_folders WHERE scope = ? AND name = ?", &[Arg::Str(scope), Arg::Str(name)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| ab_folder_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn delete_ab_folder_pool(
    pool: &DbPool,
    scope: String,
    name: String,
) -> rusqlite::Result<bool> {
    // SQLite runs without PRAGMA foreign_keys, so the FK cascade never
    // fires — delete entries + credentials explicitly. The SQLx backends
    // cascade on their own, but the explicit deletes keep behavior
    // identical everywhere.
    let folder_id = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = $1 AND name = $2",
                &[Arg::Str(scope.clone()), Arg::Str(name.clone())],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = ? AND name = ?",
                &[Arg::Str(scope.clone()), Arg::Str(name.clone())],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = ? AND name = ?",
                &[Arg::Str(scope.clone()), Arg::Str(name.clone())],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(row) = folder_id else {
        return Ok(false);
    };
    let fid = row.get::<i64>(0);

    let entry_ids: Vec<i64> = {
        let rows = match pool {
            DbPool::Postgres(p) => {
                pg_fetch(
                    p,
                    "SELECT id FROM address_book_entries WHERE folder_id = $1",
                    &[Arg::I64(fid)],
                )
                .await
            }
            DbPool::MySQL(p) => {
                mysql_fetch(
                    p,
                    "SELECT id FROM address_book_entries WHERE folder_id = ?",
                    &[Arg::I64(fid)],
                )
                .await
            }
            DbPool::SQLite(p) => {
                sqlite_fetch(
                    p,
                    "SELECT id FROM address_book_entries WHERE folder_id = ?",
                    &[Arg::I64(fid)],
                )
                .await
            }
            DbPool::None => return Err(no_pool_err()),
        }
        .map_err(map_sqlx_err)?;
        rows.iter().map(|r| r.get::<i64>(0)).collect()
    };
    for id in &entry_ids {
        pool_exec(
            pool,
            qsql!(
                pool,
                "DELETE FROM address_book_credentials WHERE entry_id = $1",
                "DELETE FROM address_book_credentials WHERE entry_id = ?"
            ),
            &[Arg::I64(*id)],
        )
        .await
        .map_err(map_sqlx_err)?;
    }
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM address_book_entries WHERE folder_id = $1",
            "DELETE FROM address_book_entries WHERE folder_id = ?"
        ),
        &[Arg::I64(fid)],
    )
    .await
    .map_err(map_sqlx_err)?;
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM address_book_folders WHERE scope = $1 AND name = $2",
            "DELETE FROM address_book_folders WHERE scope = ? AND name = ?"
        ),
        &[Arg::Str(scope), Arg::Str(name)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

#[allow(clippy::too_many_arguments)]
async fn create_ab_entry_pool(
    pool: &DbPool,
    folder_id: i64,
    name: String,
    display_name: String,
    protocol: String,
    hostname: String,
    port: Option<i64>,
    username: String,
    protocol_config: String,
    allowed_groups: String,
) -> rusqlite::Result<i64> {
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO address_book_entries \
             (folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
            "INSERT INTO address_book_entries \
             (folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::I64(folder_id),
            Arg::Str(name),
            Arg::Str(display_name),
            Arg::Str(protocol),
            Arg::Str(hostname),
            Arg::OptI64(port),
            Arg::Str(username),
            Arg::Str(protocol_config),
            Arg::Str(allowed_groups),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

async fn list_ab_entries_pool(pool: &DbPool, folder_id: i64) -> rusqlite::Result<Vec<AbEntry>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = $1 ORDER BY name", &[Arg::I64(folder_id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = ? ORDER BY name", &[Arg::I64(folder_id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = ? ORDER BY name", &[Arg::I64(folder_id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| ab_entry_row!(row)).collect())
}

async fn get_ab_entry_pool(
    pool: &DbPool,
    folder_id: i64,
    name: String,
) -> rusqlite::Result<AbEntry> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = $1 AND name = $2", &[Arg::I64(folder_id), Arg::Str(name)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = ? AND name = ?", &[Arg::I64(folder_id), Arg::Str(name)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT id, folder_id, name, display_name, protocol, hostname, port, username, protocol_config, allowed_groups, created_at, updated_at FROM address_book_entries WHERE folder_id = ? AND name = ?", &[Arg::I64(folder_id), Arg::Str(name)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| ab_entry_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

#[allow(clippy::too_many_arguments)]
async fn update_ab_entry_pool(
    pool: &DbPool,
    entry_id: i64,
    display_name: String,
    protocol: String,
    hostname: String,
    port: Option<i64>,
    username: String,
    protocol_config: String,
    allowed_groups: String,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        &format!(
            "UPDATE address_book_entries SET \
             display_name = {}, protocol = {}, hostname = {}, port = {}, \
             username = {}, protocol_config = {}, allowed_groups = {}, \
             updated_at = {} \
             WHERE id = {}",
            ph2(pool),
            ph3(pool),
            ph4(pool),
            ph5(pool),
            ph6(pool),
            ph7(pool),
            ph8(pool),
            ts_now(pool),
            ph1(pool)
        ),
        &[
            Arg::I64(entry_id),
            Arg::Str(display_name),
            Arg::Str(protocol),
            Arg::Str(hostname),
            Arg::OptI64(port),
            Arg::Str(username),
            Arg::Str(protocol_config),
            Arg::Str(allowed_groups),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn delete_ab_entry_pool(pool: &DbPool, entry_id: i64) -> rusqlite::Result<bool> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM address_book_credentials WHERE entry_id = $1",
            "DELETE FROM address_book_credentials WHERE entry_id = ?"
        ),
        &[Arg::I64(entry_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM address_book_entries WHERE id = $1",
            "DELETE FROM address_book_entries WHERE id = ?"
        ),
        &[Arg::I64(entry_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn store_ab_credential_pool(
    pool: &DbPool,
    entry_id: i64,
    credential_type: String,
    credential_data: String,
) -> rusqlite::Result<()> {
    let sql = match pool {
        DbPool::MySQL(_) => format!(
            "INSERT INTO address_book_credentials (entry_id, credential_type, credential_data) \
             VALUES (?, ?, ?) AS new \
             ON DUPLICATE KEY UPDATE \
             credential_data = new.credential_data, updated_at = {}",
            ts_now(pool)
        ),
        _ => qsql!(
            pool,
            "INSERT INTO address_book_credentials (entry_id, credential_type, credential_data) \
             VALUES ($1, $2, $3) \
             ON CONFLICT (entry_id, credential_type) DO UPDATE SET \
             credential_data = excluded.credential_data, updated_at = to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')",
            "INSERT INTO address_book_credentials (entry_id, credential_type, credential_data) \
             VALUES (?, ?, ?) \
             ON CONFLICT (entry_id, credential_type) DO UPDATE SET \
             credential_data = excluded.credential_data, updated_at = datetime('now')"
        ).to_string(),
    }
    .to_string();
    pool_exec(
        pool,
        &sql,
        &[
            Arg::I64(entry_id),
            Arg::Str(credential_type),
            Arg::Str(credential_data),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

async fn get_ab_credential_pool(
    pool: &DbPool,
    entry_id: i64,
    credential_type: String,
) -> rusqlite::Result<AbCredential> {
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = $1 AND credential_type = $2", &[Arg::I64(entry_id), Arg::Str(credential_type)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = ? AND credential_type = ?", &[Arg::I64(entry_id), Arg::Str(credential_type)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = ? AND credential_type = ?", &[Arg::I64(entry_id), Arg::Str(credential_type)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| ab_cred_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn list_ab_credentials_pool(
    pool: &DbPool,
    entry_id: i64,
) -> rusqlite::Result<Vec<AbCredential>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = $1 ORDER BY credential_type", &[Arg::I64(entry_id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = ? ORDER BY credential_type", &[Arg::I64(entry_id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT id, entry_id, credential_type, credential_data FROM address_book_credentials WHERE entry_id = ? ORDER BY credential_type", &[Arg::I64(entry_id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| ab_cred_row!(row)).collect())
}

async fn delete_ab_credential_pool(
    pool: &DbPool,
    entry_id: i64,
    credential_type: String,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM address_book_credentials WHERE entry_id = $1 AND credential_type = $2",
            "DELETE FROM address_book_credentials WHERE entry_id = ? AND credential_type = ?"
        ),
        &[Arg::I64(entry_id), Arg::Str(credential_type)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

async fn folder_has_allowed_groups_pool(
    pool: &DbPool,
    scope: String,
    folder_name: String,
) -> rusqlite::Result<bool> {
    let folder = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = $1 AND name = $2",
                &[Arg::Str(scope), Arg::Str(folder_name)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = ? AND name = ?",
                &[Arg::Str(scope), Arg::Str(folder_name)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT id FROM address_book_folders WHERE scope = ? AND name = ?",
                &[Arg::Str(scope), Arg::Str(folder_name)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(folder) = folder else {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    };
    let fid = folder.get::<i64>(0);
    let count = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, "SELECT COUNT(*) FROM address_book_entries WHERE folder_id = $1 AND allowed_groups != ''", &[Arg::I64(fid)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, "SELECT COUNT(*) FROM address_book_entries WHERE folder_id = ? AND allowed_groups != ''", &[Arg::I64(fid)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, "SELECT COUNT(*) FROM address_book_entries WHERE folder_id = ? AND allowed_groups != ''", &[Arg::I64(fid)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(count.map(|r| r.get::<i64>(0) > 0).unwrap_or(false))
}

// ── Local groups + provider-group mappings ─────────────────────────────

macro_rules! local_group_row {
    ($row:expr) => {
        LocalGroup {
            id: $row.get(0),
            name: $row.get(1),
            description: $row.get(2),
            auto_provisioned: $row.get(3),
            created_at: $row.get(4),
            provider_group_count: $row.get(5),
            folder_count: $row.get(6),
        }
    };
}

macro_rules! provider_mapping_row {
    ($row:expr) => {
        ProviderGroupMapping {
            id: $row.get(0),
            group_id: $row.get(1),
            provider_group: $row.get(2),
            created_at: $row.get(3),
        }
    };
}

/// The local-group listing columns with usage counts, per backend.
fn local_group_columns(pool: &DbPool) -> String {
    match pool {
        DbPool::Postgres(_) => {
            "lg.id, lg.name, lg.description, lg.auto_provisioned, lg.created_at, \
             (SELECT COUNT(*) FROM group_mappings gm WHERE gm.group_id = lg.id), \
             (SELECT COUNT(DISTINCT x.id) FROM (\
               SELECT f.id FROM address_book_folders f \
                 WHERE POSITION(',' || lg.name || ',' IN ',' || f.allowed_groups || ',') > 0 \
               UNION \
               SELECT e.folder_id FROM address_book_entries e \
                 WHERE POSITION(',' || lg.name || ',' IN ',' || e.allowed_groups || ',') > 0 \
             ) x)"
                .to_string()
        }
        _ => "lg.id, lg.name, lg.description, lg.auto_provisioned, lg.created_at, \
             (SELECT COUNT(*) FROM group_mappings gm WHERE gm.group_id = lg.id), \
             (SELECT COUNT(DISTINCT x.id) FROM (\
               SELECT f.id FROM address_book_folders f \
                 WHERE INSTR(',' || f.allowed_groups || ',', ',' || lg.name || ',') > 0 \
               UNION \
               SELECT e.folder_id FROM address_book_entries e \
                 WHERE INSTR(',' || e.allowed_groups || ',', ',' || lg.name || ',') > 0 \
             ) x)"
            .to_string(),
    }
}

async fn list_local_groups_pool(pool: &DbPool) -> rusqlite::Result<Vec<LocalGroup>> {
    let cols = local_group_columns(pool);
    let order = if matches!(pool, DbPool::Postgres(_)) {
        "ORDER BY lg.name"
    } else {
        "ORDER BY lg.name COLLATE NOCASE"
    };
    let sql = format!("SELECT {cols} FROM local_groups lg {order}");
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, &sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &sql, &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| local_group_row!(row)).collect())
}

async fn get_local_group_pool(pool: &DbPool, id: i64) -> rusqlite::Result<Option<LocalGroup>> {
    let cols = local_group_columns(pool);
    let sql = format!(
        "SELECT {cols} FROM local_groups lg WHERE lg.id = {}",
        placeholder(matches!(pool, DbPool::Postgres(_)), 1)
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| local_group_row!(&r)))
}

async fn create_local_group_pool(
    pool: &DbPool,
    name: String,
    description: String,
) -> rusqlite::Result<LocalGroup> {
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO local_groups (name, description) VALUES ($1, $2) RETURNING id",
            "INSERT INTO local_groups (name, description) VALUES (?, ?)"
        ),
        &[Arg::Str(name), Arg::Str(description)],
    )
    .await
    .map_err(map_sqlx_err)?;
    let cols = local_group_columns(pool);
    let sql = format!(
        "SELECT {cols} FROM local_groups lg WHERE lg.id = {}",
        placeholder(matches!(pool, DbPool::Postgres(_)), 1)
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    row.map(|r| local_group_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn count_group_name_references_pool(
    pool: &DbPool,
    group_name: String,
) -> rusqlite::Result<i64> {
    let sql = qsql!(
        pool,
        "SELECT \
           (SELECT COUNT(*) FROM address_book_folders \
              WHERE POSITION(',' || $1 || ',' IN ',' || allowed_groups || ',') > 0) \
         + (SELECT COUNT(*) FROM address_book_entries \
              WHERE POSITION(',' || $1 || ',' IN ',' || allowed_groups || ',') > 0)",
        "SELECT \
           (SELECT COUNT(*) FROM address_book_folders \
              WHERE INSTR(',' || allowed_groups || ',', ',' || ? || ',') > 0) \
         + (SELECT COUNT(*) FROM address_book_entries \
              WHERE INSTR(',' || allowed_groups || ',', ',' || ? || ',') > 0)"
    );
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (
            sql,
            vec![Arg::Str(group_name.clone()), Arg::Str(group_name)],
        ),
        _ => {
            let v = group_name;
            (sql, vec![Arg::Str(v.clone()), Arg::Str(v)])
        }
    };
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<i64>(0)).unwrap_or(0))
}

async fn update_local_group_pool(
    pool: &DbPool,
    id: i64,
    name: Option<String>,
    description: Option<String>,
) -> rusqlite::Result<Option<LocalGroup>> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE local_groups SET name = COALESCE($2, name), description = COALESCE($3, description) WHERE id = $1",
            "UPDATE local_groups SET name = COALESCE(?, name), description = COALESCE(?, description) WHERE id = ?"
        ),
        &[Arg::I64(id), Arg::OptStr(name), Arg::OptStr(description)],
    )
    .await
    .map_err(map_sqlx_err)?;
    if changed == 0 {
        return Ok(None);
    }
    let cols = local_group_columns(pool);
    let sql = format!(
        "SELECT {cols} FROM local_groups lg WHERE lg.id = {}",
        placeholder(matches!(pool, DbPool::Postgres(_)), 1)
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &[Arg::I64(id)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| local_group_row!(&r)))
}

async fn delete_local_group_pool(pool: &DbPool, id: i64) -> rusqlite::Result<Option<usize>> {
    let count = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT COUNT(*) FROM group_mappings WHERE group_id = $1",
                &[Arg::I64(id)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT COUNT(*) FROM group_mappings WHERE group_id = ?",
                &[Arg::I64(id)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT COUNT(*) FROM group_mappings WHERE group_id = ?",
                &[Arg::I64(id)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let mappings: i64 = count.map(|r| r.get(0)).unwrap_or(0);
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM local_groups WHERE id = $1",
            "DELETE FROM local_groups WHERE id = ?"
        ),
        &[Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    if changed == 0 {
        return Ok(None);
    }
    // SQLite runs without `PRAGMA foreign_keys`, so the ON DELETE CASCADE
    // declared on group_mappings.group_id never fires — delete explicitly.
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM group_mappings WHERE group_id = $1",
            "DELETE FROM group_mappings WHERE group_id = ?"
        ),
        &[Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(Some(mappings as usize))
}

async fn list_provider_group_mappings_pool(
    pool: &DbPool,
    group_id: Option<i64>,
) -> rusqlite::Result<Vec<ProviderGroupMapping>> {
    let (sql, args) = match group_id {
        Some(gid) => (
            qsql!(
                pool,
                "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE group_id = $1 ORDER BY provider_group",
                "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE group_id = ? ORDER BY provider_group COLLATE NOCASE"
            ),
            vec![Arg::I64(gid)],
        ),
        None => (
            qsql!(
                pool,
                "SELECT id, group_id, provider_group, created_at FROM group_mappings ORDER BY group_id, provider_group",
                "SELECT id, group_id, provider_group, created_at FROM group_mappings ORDER BY group_id, provider_group COLLATE NOCASE"
            ),
            vec![],
        ),
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| provider_mapping_row!(row)).collect())
}

async fn create_provider_group_mapping_pool(
    pool: &DbPool,
    group_id: i64,
    provider_group: String,
) -> rusqlite::Result<ProviderGroupMapping> {
    // Verify the group still exists (the API's pre-check can race a
    // concurrent delete, which would leave a dangling mapping on backends
    // without FK enforcement).
    let exists = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT EXISTS(SELECT 1 FROM local_groups WHERE id = $1)",
                &[Arg::I64(group_id)],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT EXISTS(SELECT 1 FROM local_groups WHERE id = ?)",
                &[Arg::I64(group_id)],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT EXISTS(SELECT 1 FROM local_groups WHERE id = ?)",
                &[Arg::I64(group_id)],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let exists: bool = exists.map(|r| r.get(0)).unwrap_or(false);
    if !exists {
        return Err(rusqlite::Error::QueryReturnedNoRows);
    }
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM group_mappings WHERE provider_group = $1",
            "DELETE FROM group_mappings WHERE provider_group = ?"
        ),
        &[Arg::Str(provider_group.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO group_mappings (group_id, provider_group) VALUES ($1, $2) RETURNING id",
            "INSERT INTO group_mappings (group_id, provider_group) VALUES (?, ?)"
        ),
        &[Arg::I64(group_id), Arg::Str(provider_group)],
    )
    .await
    .map_err(map_sqlx_err)?;
    let row =
        match pool {
            DbPool::Postgres(p) => pg_fetch_opt(
                p,
                "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE id = $1",
                &[Arg::I64(id)],
            )
            .await,
            DbPool::MySQL(p) => mysql_fetch_opt(
                p,
                "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE id = ?",
                &[Arg::I64(id)],
            )
            .await,
            DbPool::SQLite(p) => sqlite_fetch_opt(
                p,
                "SELECT id, group_id, provider_group, created_at FROM group_mappings WHERE id = ?",
                &[Arg::I64(id)],
            )
            .await,
            DbPool::None => return Err(no_pool_err()),
        }
        .map_err(map_sqlx_err)?;
    row.map(|r| provider_mapping_row!(&r))
        .ok_or(rusqlite::Error::QueryReturnedNoRows)
}

async fn delete_provider_group_mapping_pool(
    pool: &DbPool,
    mapping_id: i64,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM group_mappings WHERE id = $1",
            "DELETE FROM group_mappings WHERE id = ?"
        ),
        &[Arg::I64(mapping_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

// ── Vault→DB migration (user credential variables) ─────────────────────

/// Store one user's credential variables (full replace, Vault→DB migration).
pub fn store_user_credentials(
    db: &Db,
    user_key: &str,
    creds: &std::collections::HashMap<String, String>,
    encrypt: impl Fn(&str) -> String,
) -> rusqlite::Result<()> {
    if pool_store().is_some() {
        let entries: Vec<(String, String)> = creds
            .iter()
            .map(|(k, v)| {
                let enc = if v.is_empty() {
                    String::new()
                } else {
                    encrypt(v)
                };
                (k.clone(), enc)
            })
            .collect();
        let user_key = user_key.to_string();
        return pool_call(move |pool: &'static DbPool| {
            store_user_credentials_pool(pool, user_key, entries)
        });
    }
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_credentials (
            user_key    TEXT NOT NULL,
            var_name    TEXT NOT NULL,
            var_value   TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            PRIMARY KEY (user_key, var_name)
        );",
    )?;
    conn.execute(
        "DELETE FROM user_credentials WHERE user_key = ?1",
        params![user_key],
    )?;
    for (var_name, var_value) in creds {
        let enc_value = if var_value.is_empty() {
            String::new()
        } else {
            encrypt(var_value)
        };
        conn.execute(
            "INSERT INTO user_credentials (user_key, var_name, var_value) VALUES (?1, ?2, ?3)",
            params![user_key, var_name, enc_value],
        )?;
    }
    Ok(())
}

async fn store_user_credentials_pool(
    pool: &DbPool,
    user_key: String,
    entries: Vec<(String, String)>,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM user_credentials WHERE user_key = $1",
            "DELETE FROM user_credentials WHERE user_key = ?"
        ),
        &[Arg::Str(user_key.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    for (var_name, var_value) in entries {
        pool_exec(
            pool,
            qsql!(
                pool,
                "INSERT INTO user_credentials (user_key, var_name, var_value) VALUES ($1, $2, $3)",
                "INSERT INTO user_credentials (user_key, var_name, var_value) VALUES (?, ?, ?)"
            ),
            &[
                Arg::Str(user_key.clone()),
                Arg::Str(var_name),
                Arg::Str(var_value),
            ],
        )
        .await
        .map_err(map_sqlx_err)?;
    }
    Ok(())
}

// ── Cross-module pool stores (RBAC, audit, auth providers, settings) ──
//
// These back the store functions in src/rbac.rs, src/audit.rs,
// src/providers_db.rs, src/settings_merge.rs and src/api/settings.rs. They
// live here so they share the SQLx helpers above; the owning modules route
// through `pool_call`/`pool_active` when the pool store is active.

/// Whether the SQLx pool store is active (db_url configured at startup).
pub fn pool_active() -> bool {
    pool_store().is_some()
}

/// Deep-ping the active pool THROUGH the worker thread. The health check
/// must not touch the pool from the axum runtime: pool connections returned
/// by the worker's own runtime can race with the axum runtime's acquire
/// waiter (sqlx cross-runtime lost-wakeup, observed as a full 30s
/// acquire_timeout on the deep health ping).
pub fn ping_active_pool() -> rusqlite::Result<()> {
    if !pool_active() {
        return Ok(());
    }
    pool_call(move |pool: &'static DbPool| async move { pool.ping().await.map_err(map_sqlx_err) })
}

// ── RBAC ───────────────────────────────────────────────────────────────

pub(crate) async fn rbac_create_group_pool(
    pool: &DbPool,
    name: String,
    parent_id: Option<String>,
    description: Option<String>,
) -> rusqlite::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO rbac_groups (id, name, parent_id, description) VALUES ($1, $2, $3, $4)",
            "INSERT INTO rbac_groups (id, name, parent_id, description) VALUES (?, ?, ?, ?)"
        ),
        &[
            Arg::Str(id.clone()),
            Arg::Str(name),
            Arg::OptStr(parent_id),
            Arg::OptStr(description),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

pub(crate) async fn rbac_delete_group_pool(
    pool: &DbPool,
    group_id: String,
) -> rusqlite::Result<bool> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE rbac_groups SET parent_id = NULL WHERE parent_id = $1",
            "UPDATE rbac_groups SET parent_id = NULL WHERE parent_id = ?"
        ),
        &[Arg::Str(group_id.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM rbac_groups WHERE id = $1",
            "DELETE FROM rbac_groups WHERE id = ?"
        ),
        &[Arg::Str(group_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn rbac_list_groups_pool(pool: &DbPool) -> rusqlite::Result<Vec<ConnectionGroup>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(
                p,
                "SELECT id, name, parent_id, description, scope FROM rbac_groups ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(
                p,
                "SELECT id, name, parent_id, description, scope FROM rbac_groups ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(
                p,
                "SELECT id, name, parent_id, description, scope FROM rbac_groups ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| ConnectionGroup {
            id: row.get(0),
            name: row.get(1),
            parent_id: row.get(2),
            description: row.get(3),
            scope: row.get(4),
        })
        .collect())
}

pub(crate) async fn rbac_add_user_to_group_pool(
    pool: &DbPool,
    user_id: i64,
    group_id: String,
) -> rusqlite::Result<()> {
    let sql = qsql!(
        pool,
        "INSERT INTO rbac_user_groups (user_id, group_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        "INSERT OR IGNORE INTO rbac_user_groups (user_id, group_id) VALUES (?, ?)"
    );
    let mysql_sql = "INSERT IGNORE INTO rbac_user_groups (user_id, group_id) VALUES (?, ?)";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    pool_exec(pool, sql, &[Arg::I64(user_id), Arg::Str(group_id)])
        .await
        .map_err(map_sqlx_err)?;
    Ok(())
}

pub(crate) async fn rbac_remove_user_from_group_pool(
    pool: &DbPool,
    user_id: i64,
    group_id: String,
) -> rusqlite::Result<()> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM rbac_user_groups WHERE user_id = $1 AND group_id = $2",
            "DELETE FROM rbac_user_groups WHERE user_id = ? AND group_id = ?"
        ),
        &[Arg::I64(user_id), Arg::Str(group_id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

/// `object_type` is 'connection' or 'connection_group' (callers pass the
/// constant; no user input reaches this parameter).
pub(crate) async fn rbac_grant_permission_pool(
    pool: &DbPool,
    entity_id: String,
    object_type: &'static str,
    object_id: String,
    permission: String,
) -> rusqlite::Result<()> {
    let (entity_type, bare_id) = rbac_parse_entity_ref(&entity_id);
    let sql = qsql!(
        pool,
        "INSERT INTO rbac_permissions (entity_id, entity_type, object_type, object_id, permission) \
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING",
        "INSERT OR IGNORE INTO rbac_permissions (entity_id, entity_type, object_type, object_id, permission) \
         VALUES (?, ?, ?, ?, ?)"
    );
    let mysql_sql = "INSERT IGNORE INTO rbac_permissions (entity_id, entity_type, object_type, object_id, permission) \
         VALUES (?, ?, ?, ?, ?)";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    pool_exec(
        pool,
        sql,
        &[
            Arg::Str(bare_id.to_string()),
            Arg::Str(entity_type.to_string()),
            Arg::Str(object_type.to_string()),
            Arg::Str(object_id),
            Arg::Str(permission),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

pub(crate) async fn rbac_revoke_permission_pool(
    pool: &DbPool,
    entity_id: String,
    object_type: &'static str,
    object_id: String,
    permission: String,
) -> rusqlite::Result<bool> {
    let (entity_type, bare_id) = rbac_parse_entity_ref(&entity_id);
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM rbac_permissions \
             WHERE entity_id = $1 AND entity_type = $2 AND object_type = $3 AND object_id = $4 AND permission = $5",
            "DELETE FROM rbac_permissions \
             WHERE entity_id = ? AND entity_type = ? AND object_type = ? AND object_id = ? AND permission = ?"
        ),
        &[
            Arg::Str(bare_id.to_string()),
            Arg::Str(entity_type.to_string()),
            Arg::Str(object_type.to_string()),
            Arg::Str(object_id),
            Arg::Str(permission),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

fn rbac_parse_entity_ref(entity_id: &str) -> (&'static str, &str) {
    if let Some(rest) = entity_id.strip_prefix("u:") {
        ("user", rest)
    } else if let Some(rest) = entity_id.strip_prefix("g:") {
        ("group", rest)
    } else {
        ("user", entity_id)
    }
}

pub(crate) async fn rbac_check_connection_permission_pool(
    pool: &DbPool,
    user_id: i64,
    connection_id: String,
    permission: String,
) -> rusqlite::Result<bool> {
    // Same recursive-CTE walk as the rusqlite path (src/rbac.rs). Postgres
    // reuses $2/$3; MySQL/SQLite bind each `?` once.
    let sql = qsql!(
        pool,
        "WITH RECURSIVE group_ancestors(group_id) AS (
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection'
              AND object_id = $2 AND permission = $3
            UNION
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
            UNION
            SELECT DISTINCT p.entity_id
            FROM rbac_permissions p
            JOIN group_ancestors ga ON p.object_id = ga.group_id
            WHERE p.entity_type = 'group' AND p.object_type = 'connection_group'
              AND p.permission = $3
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = $1
        )",
        "WITH RECURSIVE group_ancestors(group_id) AS (
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection'
              AND object_id = ? AND permission = ?
            UNION
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
            UNION
            SELECT DISTINCT p.entity_id
            FROM rbac_permissions p
            JOIN group_ancestors ga ON p.object_id = ga.group_id
            WHERE p.entity_type = 'group' AND p.object_type = 'connection_group'
              AND p.permission = ?
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = ?
        )"
    );
    let (sql, args) = match pool {
        DbPool::Postgres(_) => (
            sql,
            vec![
                Arg::I64(user_id),
                Arg::Str(connection_id),
                Arg::Str(permission),
            ],
        ),
        // MySQL/SQLite bind each `?` once, in order: the base CTE takes
        // (connection_id, permission), the group-grant CTE takes permission,
        // and the final membership check takes user_id. Binding five args to
        // four placeholders (with user_id first) made every connection
        // permission check error out — fail-closed, so group-granted
        // Connect silently never worked on pool backends.
        _ => (
            sql,
            vec![
                Arg::Str(connection_id.clone()),
                Arg::Str(permission.clone()),
                Arg::Str(permission),
                Arg::I64(user_id),
            ],
        ),
    };
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<bool>(0)).unwrap_or(false))
}

pub(crate) async fn rbac_list_connection_permissions_pool(
    pool: &DbPool,
    connection_id: String,
) -> rusqlite::Result<Vec<PermissionEntry>> {
    let rows = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(p, "SELECT entity_id, entity_type, permission FROM rbac_permissions WHERE object_type = 'connection' AND object_id = $1 ORDER BY entity_type, entity_id", &[Arg::Str(connection_id)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(p, "SELECT entity_id, entity_type, permission FROM rbac_permissions WHERE object_type = 'connection' AND object_id = ? ORDER BY entity_type, entity_id", &[Arg::Str(connection_id)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(p, "SELECT entity_id, entity_type, permission FROM rbac_permissions WHERE object_type = 'connection' AND object_id = ? ORDER BY entity_type, entity_id", &[Arg::Str(connection_id)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            let etype: String = row.get(1);
            let perm: String = row.get(2);
            PermissionEntry {
                entity_id: row.get(0),
                entity_type: if etype == "group" {
                    EntityType::Group
                } else {
                    EntityType::User
                },
                permission: ObjectPermission::parse(&perm).unwrap_or(ObjectPermission::Read),
            }
        })
        .collect())
}

// ── Custom roles (src/rbac.rs) ─────────────────────────────────────────

pub(crate) async fn rbac_list_custom_roles_pool(
    pool: &DbPool,
) -> rusqlite::Result<Vec<CustomRole>> {
    let mut roles: Vec<CustomRole> = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(
                p,
                "SELECT id, name, description, created_at FROM custom_roles ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(
                p,
                "SELECT id, name, description, created_at FROM custom_roles ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(
                p,
                "SELECT id, name, description, created_at FROM custom_roles ORDER BY name",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .iter()
    .map(|row| CustomRole {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        permissions: Vec::new(),
        created_at: row.get(3),
    })
    .collect();
    let perms: Vec<(String, String)> = match pool {
        DbPool::Postgres(p) => {
            pg_fetch(
                p,
                "SELECT role_id, permission FROM custom_role_permissions ORDER BY permission",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch(
                p,
                "SELECT role_id, permission FROM custom_role_permissions ORDER BY permission",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch(
                p,
                "SELECT role_id, permission FROM custom_role_permissions ORDER BY permission",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .iter()
    .map(|row| (row.get::<String>(0), row.get::<String>(1)))
    .collect();
    for (role_id, permission) in perms {
        if let Some(role) = roles.iter_mut().find(|r| r.id == role_id) {
            role.permissions.push(permission);
        }
    }
    Ok(roles)
}

pub(crate) async fn rbac_get_custom_role_pool(
    pool: &DbPool,
    id: String,
) -> rusqlite::Result<Option<CustomRole>> {
    let sql = qsql!(
        pool,
        "SELECT id, name, description, created_at FROM custom_roles WHERE id = $1",
        "SELECT id, name, description, created_at FROM custom_roles WHERE id = ?"
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &[Arg::Str(id.clone())]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &[Arg::Str(id.clone())]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &[Arg::Str(id.clone())]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(row) = row else { return Ok(None) };
    let mut role = CustomRole {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        permissions: Vec::new(),
        created_at: row.get(3),
    };
    rbac_load_role_permissions_pool(pool, &mut role).await?;
    Ok(Some(role))
}

pub(crate) async fn rbac_get_custom_role_by_name_pool(
    pool: &DbPool,
    name: String,
) -> rusqlite::Result<Option<CustomRole>> {
    let sql = qsql!(
        pool,
        "SELECT id, name, description, created_at FROM custom_roles WHERE name = $1",
        "SELECT id, name, description, created_at FROM custom_roles WHERE name = ?"
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &[Arg::Str(name)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &[Arg::Str(name)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &[Arg::Str(name)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(row) = row else { return Ok(None) };
    let mut role = CustomRole {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        permissions: Vec::new(),
        created_at: row.get(3),
    };
    rbac_load_role_permissions_pool(pool, &mut role).await?;
    Ok(Some(role))
}

pub(crate) async fn rbac_create_custom_role_pool(
    pool: &DbPool,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
) -> rusqlite::Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    pool_exec(
        pool,
        qsql!(
            pool,
            "INSERT INTO custom_roles (id, name, description) VALUES ($1, $2, $3)",
            "INSERT INTO custom_roles (id, name, description) VALUES (?, ?, ?)"
        ),
        &[
            Arg::Str(id.clone()),
            Arg::Str(name),
            Arg::OptStr(description),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    rbac_insert_role_permissions_pool(pool, &id, &permissions).await?;
    Ok(id)
}

pub(crate) async fn rbac_update_custom_role_pool(
    pool: &DbPool,
    id: String,
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE custom_roles SET name = $1, description = $2 WHERE id = $3",
            "UPDATE custom_roles SET name = ?, description = ? WHERE id = ?"
        ),
        &[
            Arg::Str(name),
            Arg::OptStr(description),
            Arg::Str(id.clone()),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    if changed == 0 {
        return Ok(false);
    }
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM custom_role_permissions WHERE role_id = $1",
            "DELETE FROM custom_role_permissions WHERE role_id = ?"
        ),
        &[Arg::Str(id.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    rbac_insert_role_permissions_pool(pool, &id, &permissions).await?;
    Ok(true)
}

pub(crate) async fn rbac_delete_custom_role_pool(
    pool: &DbPool,
    id: String,
) -> rusqlite::Result<bool> {
    pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM custom_role_permissions WHERE role_id = $1",
            "DELETE FROM custom_role_permissions WHERE role_id = ?"
        ),
        &[Arg::Str(id.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE users SET custom_role_id = NULL WHERE custom_role_id = $1",
            "UPDATE users SET custom_role_id = NULL WHERE custom_role_id = ?"
        ),
        &[Arg::Str(id.clone())],
    )
    .await
    .map_err(map_sqlx_err)?;
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM custom_roles WHERE id = $1",
            "DELETE FROM custom_roles WHERE id = ?"
        ),
        &[Arg::Str(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn rbac_set_user_custom_role_pool(
    pool: &DbPool,
    email: String,
    role_id: Option<String>,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "UPDATE users SET custom_role_id = $1 WHERE email = $2",
            "UPDATE users SET custom_role_id = ? WHERE email = ?"
        ),
        &[Arg::OptStr(role_id), Arg::Str(email)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn rbac_user_custom_role_pool(
    pool: &DbPool,
    user_id: i64,
) -> rusqlite::Result<Option<CustomRole>> {
    let sql = qsql!(
        pool,
        "SELECT cr.id, cr.name, cr.description, cr.created_at
         FROM custom_roles cr
         JOIN users u ON u.custom_role_id = cr.id
         WHERE u.id = $1",
        "SELECT cr.id, cr.name, cr.description, cr.created_at
         FROM custom_roles cr
         JOIN users u ON u.custom_role_id = cr.id
         WHERE u.id = ?"
    );
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &[Arg::I64(user_id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &[Arg::I64(user_id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &[Arg::I64(user_id)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let Some(row) = row else { return Ok(None) };
    let mut role = CustomRole {
        id: row.get(0),
        name: row.get(1),
        description: row.get(2),
        permissions: Vec::new(),
        created_at: row.get(3),
    };
    rbac_load_role_permissions_pool(pool, &mut role).await?;
    Ok(Some(role))
}

pub(crate) async fn rbac_user_has_custom_permission_pool(
    pool: &DbPool,
    user_id: i64,
    permission: String,
) -> rusqlite::Result<bool> {
    let sql = qsql!(
        pool,
        "SELECT EXISTS(
            SELECT 1 FROM custom_role_permissions crp
            JOIN users u ON u.custom_role_id = crp.role_id
            WHERE u.id = $1 AND crp.permission = $2
        )",
        "SELECT EXISTS(
            SELECT 1 FROM custom_role_permissions crp
            JOIN users u ON u.custom_role_id = crp.role_id
            WHERE u.id = ? AND crp.permission = ?
        )"
    );
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(p, sql, &[Arg::I64(user_id), Arg::Str(permission)]).await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(p, sql, &[Arg::I64(user_id), Arg::Str(permission)]).await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(p, sql, &[Arg::I64(user_id), Arg::Str(permission)]).await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<bool>(0)).unwrap_or(false))
}

/// Group-object (folder-level) permission check: direct user grant on the
/// object, or a group the user belongs to granted on the object or on an
/// ancestor rbac group. Mirrors the rusqlite path in src/rbac.rs
/// (`check_group_object_permission`).
pub(crate) async fn rbac_check_group_object_permission_pool(
    pool: &DbPool,
    user_id: i64,
    object_id: String,
    permission: String,
) -> rusqlite::Result<bool> {
    // 1. Direct user grant on the object
    let direct_sql = qsql!(
        pool,
        "SELECT EXISTS(
            SELECT 1 FROM rbac_permissions
            WHERE entity_id = $1 AND entity_type = 'user'
              AND object_type = 'connection_group' AND object_id = $2
              AND permission = $3
        )",
        "SELECT EXISTS(
            SELECT 1 FROM rbac_permissions
            WHERE entity_id = ? AND entity_type = 'user'
              AND object_type = 'connection_group' AND object_id = ?
              AND permission = ?
        )"
    );
    let direct = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                direct_sql,
                &[
                    Arg::I64(user_id),
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                ],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                direct_sql,
                &[
                    Arg::I64(user_id),
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                ],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                direct_sql,
                &[
                    Arg::I64(user_id),
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                ],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    if direct.map(|r| r.get::<bool>(0)).unwrap_or(false) {
        return Ok(true);
    }

    // 2. Group grants on the object or on ancestor rbac groups (recursive CTE)
    let cte_sql = qsql!(
        pool,
        "WITH RECURSIVE group_ancestors(group_id) AS (
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection_group'
              AND object_id = $1 AND permission = $2
            UNION
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = $3
        )",
        "WITH RECURSIVE group_ancestors(group_id) AS (
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection_group'
              AND object_id = ? AND permission = ?
            UNION
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = ?
        )"
    );
    let row = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                cte_sql,
                &[
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                    Arg::I64(user_id),
                ],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                cte_sql,
                &[
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                    Arg::I64(user_id),
                ],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                cte_sql,
                &[
                    Arg::Str(object_id.clone()),
                    Arg::Str(permission.clone()),
                    Arg::I64(user_id),
                ],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<bool>(0)).unwrap_or(false))
}

async fn rbac_insert_role_permissions_pool(
    pool: &DbPool,
    role_id: &str,
    permissions: &[String],
) -> rusqlite::Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    let sql = qsql!(
        pool,
        "INSERT INTO custom_role_permissions (role_id, permission) VALUES ($1, $2)",
        "INSERT INTO custom_role_permissions (role_id, permission) VALUES (?, ?)"
    );
    for permission in permissions {
        if seen.contains(&permission.as_str()) {
            continue;
        }
        seen.push(permission.as_str());
        pool_exec(
            pool,
            sql,
            &[Arg::Str(role_id.to_string()), Arg::Str(permission.clone())],
        )
        .await
        .map_err(map_sqlx_err)?;
    }
    Ok(())
}

async fn rbac_load_role_permissions_pool(
    pool: &DbPool,
    role: &mut CustomRole,
) -> rusqlite::Result<()> {
    let sql = qsql!(
        pool,
        "SELECT permission FROM custom_role_permissions WHERE role_id = $1 ORDER BY permission",
        "SELECT permission FROM custom_role_permissions WHERE role_id = ? ORDER BY permission"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[Arg::Str(role.id.clone())]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[Arg::Str(role.id.clone())]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[Arg::Str(role.id.clone())]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    for row in rows {
        role.permissions.push(row.get::<String>(0));
    }
    Ok(())
}

// ── Audit hash chain (src/audit.rs) ────────────────────────────────────

pub(crate) async fn audit_log_event_pool(
    pool: &DbPool,
    mut event: AuditEvent,
) -> rusqlite::Result<i64> {
    let prev_hash: String = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?
    .map(|r| r.get::<String>(0))
    .unwrap_or_else(|| "0".repeat(64));

    event.prev_hash = prev_hash;
    event.event_hash = compute_event_hash(&event);

    let details_str = if event.details.is_null() {
        None
    } else {
        Some(event.details.to_string())
    };
    let id = exec_returning_id(
        pool,
        qsql!(
            pool,
            "INSERT INTO audit_events (event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
            "INSERT INTO audit_events (event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ),
        &[
            Arg::Str(event.event_type.clone()),
            Arg::Str(event.timestamp.to_rfc3339()),
            Arg::OptStr(event.user_id.clone()),
            Arg::OptStr(event.source_ip.clone()),
            Arg::Str(event.outcome.clone()),
            Arg::OptStr(details_str),
            Arg::OptStr(event.session_id.clone()),
            Arg::Str(event.prev_hash.clone()),
            Arg::Str(event.event_hash.clone()),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(id)
}

/// Fetch audit events in chain order (id ASC) within the optional
/// timestamp range, as (id, event) pairs.
pub(crate) async fn audit_events_pool(
    pool: &DbPool,
    from: Option<String>,
    to: Option<String>,
) -> rusqlite::Result<Vec<(i64, AuditEvent)>> {
    let is_pg = matches!(pool, DbPool::Postgres(_));
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Arg> = Vec::new();
    if let Some(f) = from {
        conditions.push(format!(
            "timestamp >= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(f));
    }
    if let Some(t) = to {
        conditions.push(format!(
            "timestamp <= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(t));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    let sql = format!(
        "SELECT id, event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash \
         FROM audit_events {where_clause} ORDER BY id ASC"
    );
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, &sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|row| {
            let id: i64 = row.get(0);
            let details_str: Option<String> = row.get(6);
            let details: serde_json::Value = match details_str {
                Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
                None => serde_json::Value::Null,
            };
            (
                id,
                AuditEvent {
                    id,
                    event_type: row.get(1),
                    timestamp: chrono::DateTime::parse_from_rfc3339(&row.get::<String>(2))
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    user_id: row.get(3),
                    source_ip: row.get(4),
                    outcome: row.get(5),
                    details,
                    session_id: row.get(7),
                    prev_hash: row.get(8),
                    event_hash: row.get(9),
                },
            )
        })
        .collect())
}

pub(crate) async fn audit_first_id_pool(pool: &DbPool) -> rusqlite::Result<Option<i64>> {
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, "SELECT MIN(id) FROM audit_events", &[]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, "SELECT MIN(id) FROM audit_events", &[]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, "SELECT MIN(id) FROM audit_events", &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.and_then(|r| r.get::<Option<i64>>(0)))
}

/// Build the audit filter WHERE clause; returns (clause, args). Placeholder
/// syntax follows the backend.
fn audit_filter_clause(pool: &DbPool, filters: &AuditFilters) -> (String, Vec<Arg>) {
    let is_pg = matches!(pool, DbPool::Postgres(_));
    let mut conditions: Vec<String> = Vec::new();
    let mut args: Vec<Arg> = Vec::new();
    if let Some(ref user_id) = filters.user_id {
        conditions.push(format!("user_id = {}", placeholder(is_pg, args.len() + 1)));
        args.push(Arg::Str(user_id.clone()));
    }
    if let Some(ref event_type) = filters.event_type {
        conditions.push(format!(
            "event_type = {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(event_type.clone()));
    }
    if let Some(ref outcome) = filters.outcome {
        conditions.push(format!("outcome = {}", placeholder(is_pg, args.len() + 1)));
        args.push(Arg::Str(outcome.clone()));
    }
    if let Some(ref from) = filters.from {
        conditions.push(format!(
            "timestamp >= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(from.clone()));
    }
    if let Some(ref to) = filters.to {
        conditions.push(format!(
            "timestamp <= {}",
            placeholder(is_pg, args.len() + 1)
        ));
        args.push(Arg::Str(to.clone()));
    }
    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };
    (where_clause, args)
}

macro_rules! audit_event_row {
    ($row:expr) => {{
        let details_str: Option<String> = $row.get(6);
        let details: serde_json::Value = match details_str {
            Some(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
            None => serde_json::Value::Null,
        };
        AuditEvent {
            id: $row.get(0),
            event_type: $row.get(1),
            timestamp: chrono::DateTime::parse_from_rfc3339(&$row.get::<String>(2))
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now()),
            user_id: $row.get(3),
            source_ip: $row.get(4),
            outcome: $row.get(5),
            details,
            session_id: $row.get(7),
            prev_hash: $row.get(8),
            event_hash: $row.get(9),
        }
    }};
}

pub(crate) async fn audit_list_events_pool(
    pool: &DbPool,
    limit: u64,
    offset: u64,
    filters: AuditFilters,
) -> rusqlite::Result<Vec<AuditEvent>> {
    let (where_clause, mut args) = audit_filter_clause(pool, &filters);
    let is_pg = matches!(pool, DbPool::Postgres(_));
    let limit_ph = placeholder(is_pg, args.len() + 1);
    let offset_ph = placeholder(is_pg, args.len() + 2);
    let sql = format!(
        "SELECT id, event_type, timestamp, user_id, source_ip, outcome, details, session_id, prev_hash, event_hash \
         FROM audit_events {where_clause} ORDER BY id DESC LIMIT {limit_ph} OFFSET {offset_ph}"
    );
    args.push(Arg::I64(limit as i64));
    args.push(Arg::I64(offset as i64));
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, &sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch(p, &sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch(p, &sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| audit_event_row!(row)).collect())
}

pub(crate) async fn audit_count_events_pool(
    pool: &DbPool,
    filters: AuditFilters,
) -> rusqlite::Result<u64> {
    let (where_clause, args) = audit_filter_clause(pool, &filters);
    let sql = format!("SELECT COUNT(*) FROM audit_events {where_clause}");
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, &sql, &args).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, &sql, &args).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, &sql, &args).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| r.get::<i64>(0) as u64).unwrap_or(0))
}

macro_rules! provider_row {
    ($row:expr) => {{
        DbProvider {
            id: $row.get(0),
            name: $row.get(1),
            provider_type: $row.get(2),
            enabled: $row.get(3),
            position: $row.get(4),
            config: serde_json::from_str(&$row.get::<String>(5))
                .unwrap_or_else(|_| serde_json::Value::Null),
            created_at: $row.get(6),
            updated_at: $row.get(7),
        }
    }};
}
// ── Auth providers (src/providers_db.rs) ───────────────────────────────

pub(crate) async fn providers_load_pool(pool: &DbPool) -> rusqlite::Result<Vec<DbProvider>> {
    let sql = qsql!(
        pool,
        "SELECT id, name, type, enabled, position, config, created_at, updated_at FROM auth_providers ORDER BY position, id",
        "SELECT id, name, type, enabled, position, config, created_at, updated_at FROM auth_providers ORDER BY position, id"
    );
    let mysql_sql = "SELECT id, name, `type`, enabled, position, config, created_at, updated_at FROM auth_providers ORDER BY position, id";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows.iter().map(|row| provider_row!(row)).collect())
}

pub(crate) async fn providers_get_pool(
    pool: &DbPool,
    id: i64,
) -> rusqlite::Result<Option<DbProvider>> {
    let sql = qsql!(
        pool,
        "SELECT id, name, type, enabled, position, config, created_at, updated_at FROM auth_providers WHERE id = $1",
        "SELECT id, name, type, enabled, position, config, created_at, updated_at FROM auth_providers WHERE id = ?"
    );
    let mysql_sql = "SELECT id, name, `type`, enabled, position, config, created_at, updated_at FROM auth_providers WHERE id = ?";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    let row = match pool {
        DbPool::Postgres(p) => pg_fetch_opt(p, sql, &[Arg::I64(id)]).await,
        DbPool::MySQL(p) => mysql_fetch_opt(p, sql, &[Arg::I64(id)]).await,
        DbPool::SQLite(p) => sqlite_fetch_opt(p, sql, &[Arg::I64(id)]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(row.map(|r| provider_row!(&r)))
}

pub(crate) async fn providers_insert_pool(
    pool: &DbPool,
    name: String,
    provider_type: String,
    config: String,
) -> rusqlite::Result<DbProvider> {
    let next_position = match pool {
        DbPool::Postgres(p) => {
            pg_fetch_opt(
                p,
                "SELECT COALESCE(MAX(position), -1) + 1 FROM auth_providers",
                &[],
            )
            .await
        }
        DbPool::MySQL(p) => {
            mysql_fetch_opt(
                p,
                "SELECT COALESCE(MAX(position), -1) + 1 FROM auth_providers",
                &[],
            )
            .await
        }
        DbPool::SQLite(p) => {
            sqlite_fetch_opt(
                p,
                "SELECT COALESCE(MAX(position), -1) + 1 FROM auth_providers",
                &[],
            )
            .await
        }
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    let next_position: i64 = next_position.map(|r| r.get(0)).unwrap_or(0);
    let sql = qsql!(
        pool,
        "INSERT INTO auth_providers (name, type, enabled, position, config) VALUES ($1, $2, TRUE, $3, $4) RETURNING id",
        "INSERT INTO auth_providers (name, type, enabled, position, config) VALUES (?, ?, 1, ?, ?)"
    );
    let mysql_sql = "INSERT INTO auth_providers (name, `type`, enabled, position, config) VALUES (?, ?, 1, ?, ?)";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    let id = exec_returning_id(
        pool,
        sql,
        &[
            Arg::Str(name),
            Arg::Str(provider_type),
            Arg::I64(next_position),
            Arg::Str(config),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    providers_get_pool(pool, id).await?.ok_or_else(|| {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("inserted provider not found".into()),
        )
    })
}

pub(crate) async fn providers_update_config_pool(
    pool: &DbPool,
    id: i64,
    config: String,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        &format!(
            "UPDATE auth_providers SET config = {}, updated_at = {} WHERE id = {}",
            ph1(pool),
            ts_now(pool),
            ph2(pool)
        ),
        &[Arg::Str(config), Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn providers_set_enabled_pool(
    pool: &DbPool,
    id: i64,
    enabled: bool,
) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        &format!(
            "UPDATE auth_providers SET enabled = {}, updated_at = {} WHERE id = {}",
            ph1(pool),
            ts_now(pool),
            ph2(pool)
        ),
        &[Arg::Bool(enabled), Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn providers_delete_pool(pool: &DbPool, id: i64) -> rusqlite::Result<bool> {
    let changed = pool_exec(
        pool,
        qsql!(
            pool,
            "DELETE FROM auth_providers WHERE id = $1",
            "DELETE FROM auth_providers WHERE id = ?"
        ),
        &[Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    Ok(changed > 0)
}

pub(crate) async fn providers_move_pool(
    pool: &DbPool,
    id: i64,
    direction: MoveDirection,
) -> rusqlite::Result<Option<DbProvider>> {
    let providers = providers_load_pool(pool).await?;
    let idx = match providers.iter().position(|p| p.id == id) {
        Some(i) => i,
        None => return Ok(None),
    };
    let neighbor_idx = match direction {
        MoveDirection::Up => {
            if idx == 0 {
                return Ok(Some(providers[idx].clone()));
            }
            idx - 1
        }
        MoveDirection::Down => {
            if idx + 1 >= providers.len() {
                return Ok(Some(providers[idx].clone()));
            }
            idx + 1
        }
    };
    pool_exec(
        pool,
        &format!(
            "UPDATE auth_providers SET position = {}, updated_at = {} WHERE id = {}",
            ph1(pool),
            ts_now(pool),
            ph2(pool)
        ),
        &[Arg::I64(providers[neighbor_idx].position), Arg::I64(id)],
    )
    .await
    .map_err(map_sqlx_err)?;
    pool_exec(
        pool,
        &format!(
            "UPDATE auth_providers SET position = {}, updated_at = {} WHERE id = {}",
            ph1(pool),
            ts_now(pool),
            ph2(pool)
        ),
        &[
            Arg::I64(providers[idx].position),
            Arg::I64(providers[neighbor_idx].id),
        ],
    )
    .await
    .map_err(map_sqlx_err)?;
    providers_get_pool(pool, id).await
}

// ── System settings (src/settings_merge.rs, src/api/settings.rs) ──────

/// Read every system setting as `(key, value)` pairs, in table order.
/// Backs the admin settings API and the settings overlay applied at
/// startup. Returns an error when no SQLx pool is configured, and maps
/// backend failures onto `rusqlite::Error` so callers can handle both
/// store flavors uniformly.
pub async fn settings_load_all_pool(pool: &DbPool) -> rusqlite::Result<Vec<(String, String)>> {
    let sql = qsql!(
        pool,
        "SELECT key, value FROM system_settings",
        "SELECT key, value FROM system_settings"
    );
    let mysql_sql = "SELECT `key`, value FROM system_settings";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    let rows = match pool {
        DbPool::Postgres(p) => pg_fetch(p, sql, &[]).await,
        DbPool::MySQL(p) => mysql_fetch(p, sql, &[]).await,
        DbPool::SQLite(p) => sqlite_fetch(p, sql, &[]).await,
        DbPool::None => return Err(no_pool_err()),
    }
    .map_err(map_sqlx_err)?;
    Ok(rows
        .iter()
        .map(|r| (r.get::<String>(0), r.get::<String>(1)))
        .collect())
}

/// Upsert system settings, one statement per pair. A failure partway
/// through leaves the earlier pairs applied, which the settings API
/// tolerates. Returns an error when no SQLx pool is configured.
pub async fn settings_put_pool(
    pool: &DbPool,
    entries: Vec<(String, String)>,
) -> rusqlite::Result<()> {
    let sql = qsql!(
        pool,
        "INSERT INTO system_settings (key, value, updated_at) \
         VALUES ($1, $2, CURRENT_TIMESTAMP) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        "INSERT INTO system_settings (key, value, updated_at) \
         VALUES (?, ?, CURRENT_TIMESTAMP) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP"
    );
    let mysql_sql = "INSERT INTO system_settings (`key`, value, updated_at) \
         VALUES (?, ?, CURRENT_TIMESTAMP) AS new \
         ON DUPLICATE KEY UPDATE value = new.value, updated_at = CURRENT_TIMESTAMP";
    let sql = match pool {
        DbPool::MySQL(_) => mysql_sql,
        _ => sql,
    };
    for (key, value) in entries {
        pool_exec(pool, sql, &[Arg::Str(key), Arg::Str(value)])
            .await
            .map_err(map_sqlx_err)?;
    }
    Ok(())
}
