//! SQLite database layer for admin/API key management.

use crate::role::role_level;
use chrono::{DateTime, NaiveDate, NaiveDateTime, TimeZone, Utc};
use rand::RngExt;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};
use std::net::IpAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type Db = Arc<Mutex<Connection>>;

/// Admin record (safe to display — no key material).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AdminInfo {
    pub id: i64,
    pub name: String,
    pub allowed_ips: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// User record from OIDC login.
#[derive(Debug, Clone, serde::Serialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub name: String,
    pub oidc_subject: Option<String>,
    pub role: String,
    pub disabled: bool,
    pub created_at: String,
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
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub max_role: Option<String>,
    pub expires_at: Option<String>,
    pub disabled: bool,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

/// Token audit log entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenAuditEntry {
    pub id: i64,
    pub token_id: Option<i64>,
    pub token_name: Option<String>,
    pub user_email: String,
    pub action: String,
    pub ip_addr: Option<String>,
    pub details: Option<String>,
    pub created_at: String,
}

/// Connections (address book) audit log entry. Persisted in SQLite, never in
/// Vault, so only headline metadata goes here: action name, target path, and
/// small counts. Entry field values (passwords, keys, usernames) must never
/// be written to `details` — see feedback_audit_log_scope.md.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AddressbookAuditEntry {
    pub id: i64,
    pub user_email: String,
    pub action: String,
    pub scope: String,
    pub folder_path: String,
    pub entry_name: Option<String>,
    pub ip_addr: Option<String>,
    pub details: Option<String>,
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
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT NOT NULL UNIQUE,
            name          TEXT NOT NULL DEFAULT '',
            oidc_subject  TEXT,
            role          TEXT NOT NULL DEFAULT 'viewer',
            disabled      INTEGER NOT NULL DEFAULT 0,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            last_login_at TEXT
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

    // Migration: address book tables (ticket #022)
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
        CREATE INDEX IF NOT EXISTS idx_ab_creds_entry ON address_book_credentials(entry_id);",
    )?;

    // Folder-level ACLs (wayfinder ticket 027): columns added after the
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

    // Migration: local groups + provider-group mappings (ticket #029).
    // Local groups are admin-defined named groups that folders/connections
    // can grant access to. `group_mappings` links an auth-provider group name
    // (from OIDC/LDAP claims, see list_known_groups) to a local group; one
    // provider group maps to at most one local group (UNIQUE). The FK cascade
    // is declared for postgres/mysql parity — SQLite runs without
    // `PRAGMA foreign_keys`, so delete_local_group removes mappings explicitly.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS local_groups (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE,
            description TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS group_mappings (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id       INTEGER NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
            provider_group TEXT NOT NULL UNIQUE,
            created_at     TEXT NOT NULL DEFAULT (datetime('now'))
        );",
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

pub fn add_admin(
    db: &Db,
    name: &str,
    allowed_ips: Option<&str>,
    expires_at: Option<&str>,
) -> rusqlite::Result<String> {
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
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 1 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Enable an admin by name.
pub fn enable_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE admins SET disabled = 0 WHERE name = ?1",
        params![name],
    )?;
    Ok(changed > 0)
}

/// Delete an admin by name.
pub fn delete_admin(db: &Db, name: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM admins WHERE name = ?1", params![name])?;
    Ok(changed > 0)
}

/// Rotate an admin's API key. Returns the new plaintext key.
pub fn rotate_key(db: &Db, name: &str) -> rusqlite::Result<Option<String>> {
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
pub enum AuthError {
    InvalidKey,
    Disabled,
    Expired,
    IpNotAllowed,
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
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
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
            })
        },
    )
}

/// Create an auth session for a user. Returns the plaintext session token
/// (256-bit hex). Only the SHA-256 hash is stored in the database.
pub fn create_auth_session(db: &Db, user_id: i64, ttl_secs: u64) -> rusqlite::Result<String> {
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
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE user_id = ?1",
        params![user_id],
    )
}

/// Look up a user by email.
pub fn get_user_by_email(db: &Db, email: &str) -> rusqlite::Result<User> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
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
            })
        },
    )
}

/// Get the auth_source for a user by email.
pub fn get_user_auth_source(db: &Db, email: &str) -> rusqlite::Result<String> {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT auth_source FROM users WHERE email = ?1",
        params![email],
        |row| row.get(0),
    )
}

/// Validate an auth session token. Returns the user if valid and not expired/disabled.
/// The token is hashed before lookup — only hashes are stored in the database.
pub fn validate_auth_session(db: &Db, token: &str) -> Result<User, AuthError> {
    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups
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
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM auth_sessions WHERE expires_at <= datetime('now')",
        [],
    )
}

/// List all users.
pub fn list_users(db: &Db) -> rusqlite::Result<Vec<User>> {
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT id, email, name, oidc_subject, role, disabled, created_at, last_login_at, oidc_groups
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
        })
    })?;
    rows.collect()
}

/// Set a user's role by email.
pub fn set_user_role(db: &Db, email: &str, role: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET role = ?1 WHERE email = ?2",
        params![role, email],
    )?;
    Ok(changed > 0)
}

/// Disable a user by email.
pub fn disable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 1 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Enable a user by email.
pub fn enable_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET disabled = 0 WHERE email = ?1",
        params![email],
    )?;
    Ok(changed > 0)
}

/// Delete a user by email (also deletes their auth sessions and API tokens).
pub fn delete_user(db: &Db, email: &str) -> rusqlite::Result<bool> {
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
    pub id: i64,
    pub oidc_group: String,
    pub role: String,
    pub created_at: String,
}

/// List all group-to-role mappings.
pub fn list_group_mappings(db: &Db) -> rusqlite::Result<Vec<GroupRoleMapping>> {
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
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE group_role_mappings SET oidc_group = ?1, role = ?2 WHERE id = ?3",
        params![oidc_group, role, id],
    )?;
    Ok(changed > 0)
}

/// Delete a group-to-role mapping by id.
pub fn delete_group_mapping(db: &Db, id: i64) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM group_role_mappings WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

/// Upsert OIDC groups observed in a login token, updating last_seen.
pub fn upsert_seen_groups(db: &Db, groups: &[String]) -> rusqlite::Result<()> {
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

/// Auto-provision `local_groups` for the given provider groups (wayfinder fog
/// item: "map OIDC groups to local groups without manual mapping"). Folder
/// ACLs reference local group names, so a provider group that shows up in
/// login claims becomes usable in the connections page immediately. Groups
/// already created (or mapped) are left untouched.
pub fn ensure_local_groups(db: &Db, groups: &[String]) -> rusqlite::Result<usize> {
    if groups.is_empty() {
        return Ok(0);
    }
    let mut conn = db.lock().unwrap();
    let mut created = 0usize;
    {
        let mut stmt = conn.prepare(
            "INSERT OR IGNORE INTO local_groups (name, description)
             VALUES (?1, 'Auto-provisioned from auth provider groups')",
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
    use subtle::ConstantTimeEq;

    let token_hash = hash_key(token);
    let conn = db.lock().unwrap();

    // Fetch all tokens with their users and compare hashes in constant time
    let mut stmt = conn
        .prepare(
            "SELECT t.id, t.user_id, t.name, t.max_role, t.expires_at, t.disabled, t.created_at, t.last_used_at,
                    u.id, u.email, u.name, u.oidc_subject, u.role, u.disabled, u.created_at, u.last_login_at, u.oidc_groups,
                    t.token_hash
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
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM user_api_tokens WHERE id = ?1 AND user_id = ?2",
        params![token_id, user_id],
    )?;
    Ok(changed > 0)
}

/// Admin: revoke any user's token by ID (no ownership check).
pub fn admin_revoke_user_token(db: &Db, token_id: i64) -> rusqlite::Result<bool> {
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
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM user_api_tokens WHERE user_id = ?1",
        params![user_id],
    )
}

/// Clean up expired user API tokens.
pub fn cleanup_expired_user_tokens(db: &Db) -> rusqlite::Result<usize> {
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
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE session_history
         SET ended_at = datetime('now'), duration_secs = ?2, status = ?3, recording_file = ?4
         WHERE session_id = ?1 AND ended_at IS NULL",
        params![session_id, duration_secs as i64, status, recording_file],
    )?;
    Ok(())
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
                started_at, ended_at, duration_secs, recording_file, status
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
                "started_at": row.get::<_, String>(9)?,
                "ended_at": row.get::<_, Option<String>>(10)?,
                "duration_secs": row.get::<_, Option<i64>>(11)?,
                "recording_file": row.get::<_, Option<String>>(12)?,
                "status": row.get::<_, String>(13)?,
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
                started_at, ended_at, duration_secs, status, recording_file
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
            recording,
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
        csv_escape_field(writer, recording.as_deref().unwrap_or(""))?;
        writeln!(writer)?;
        count += 1;
    }
    Ok(count)
}

fn csv_escape_field(w: &mut dyn std::io::Write, field: &str) -> std::io::Result<()> {
    if field.contains(',') || field.contains('"') || field.contains('\n') {
        write!(w, "\"")?;
        for ch in field.chars() {
            if ch == '"' {
                write!(w, "\"\"")?;
            } else {
                write!(w, "{}", ch)?;
            }
        }
        write!(w, "\"")?;
    } else {
        write!(w, "{}", field)?;
    }
    Ok(())
}

/// Top connections by session count and total hours.
pub fn top_connections(db: &Db, limit: u32) -> rusqlite::Result<Vec<serde_json::Value>> {
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
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT COUNT(*) AS total_sessions,
                COALESCE(SUM(duration_secs), 0) AS total_secs,
                COUNT(DISTINCT created_by) AS unique_users,
                COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) AS active_now
         FROM session_history",
    )?;
    stmt.query_row([], |row| {
        Ok(serde_json::json!({
            "total_sessions": row.get::<_, i64>(0)?,
            "total_hours": row.get::<_, i64>(1)? as f64 / 3600.0,
            "unique_users": row.get::<_, i64>(2)?,
            "active_now": row.get::<_, i64>(3)?,
        }))
    })
}

/// Clean up old session history entries (retain last N days). Returns rows deleted.
pub fn cleanup_session_history(db: &Db, retain_days: u32) -> rusqlite::Result<usize> {
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
    pub user_id: i64,
    pub secret_b32: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u16,
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
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE totp_secrets SET enabled = ?1 WHERE user_id = ?2",
        params![enabled as i64, user_id],
    )?;
    Ok(changed > 0)
}

/// Delete a user's TOTP secret.
pub fn delete_totp_secret(db: &Db, user_id: i64) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM totp_secrets WHERE user_id = ?1",
        params![user_id],
    )?;
    Ok(changed > 0)
}

/// Check if a user has TOTP enabled.
pub fn user_totp_enabled(db: &Db, user_id: i64) -> rusqlite::Result<bool> {
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
    pub user_id: i64,
    pub user_email: String,
    pub user_name: String,
    pub user_role: String,
    pub oidc_subject: Option<String>,
    pub created_at: String,
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
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_path: Option<String>,
    pub created_at: String,
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
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM jump_hosts WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

// ── Address book (DB-backed storage) ──

/// DB record for an address book folder.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AbFolder {
    pub id: i64,
    pub scope: String,
    pub name: String,
    pub description: String,
    /// Comma-separated group names allowed to use this folder (empty = open).
    pub allowed_groups: String,
    /// Whether subfolders inherit this folder's allowed_groups.
    pub inherit_from_parent: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// DB record for an address book entry (metadata only, no credentials).
#[derive(Debug, Clone, serde::Serialize)]
pub struct AbEntry {
    pub id: i64,
    pub folder_id: i64,
    pub name: String,
    pub display_name: String,
    pub protocol: String,
    pub hostname: String,
    pub port: Option<u16>,
    pub username: String,
    pub protocol_config: String,
    pub allowed_groups: String,
    pub created_at: String,
    pub updated_at: String,
}

/// DB record for an encrypted credential.
#[derive(Debug, Clone)]
pub struct AbCredential {
    pub id: i64,
    pub entry_id: i64,
    pub credential_type: String,
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
            "dave@sol1.com.au",
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
            "andy@sol1.com.au",
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
            "dave@sol1.com.au",
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
            "andy@sol1.com.au",
            None,
            None,
            None,
        )
        .unwrap();

        let (rows, total) =
            query_session_history(&db, Some("dave"), None, None, None, None, 100, 0).unwrap();
        assert_eq!(total, 1);
        assert_eq!(rows[0]["created_by"], "dave@sol1.com.au");
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

        let summary = session_summary(&db).unwrap();
        assert_eq!(summary["total_sessions"], 2);
        assert_eq!(summary["unique_users"], 2);
        assert_eq!(summary["active_now"], 1);
        assert_eq!(summary["total_hours"], 7200.0 / 3600.0);
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

// ── Local groups + provider-group mappings (ticket #029) ────────────────────
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
    pub id: i64,
    pub name: String,
    pub description: String,
    pub created_at: String,
    /// Number of auth-provider groups mapped to this local group.
    pub provider_group_count: i64,
    /// Number of address-book folders whose entries list this group name in
    /// `allowed_groups` (vault-side folder configs are not scanned).
    pub folder_count: i64,
}

/// A mapping from an auth-provider group name to a local group.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProviderGroupMapping {
    pub id: i64,
    pub group_id: i64,
    pub provider_group: String,
    pub created_at: String,
}

fn local_group_row(row: &rusqlite::Row) -> rusqlite::Result<LocalGroup> {
    Ok(LocalGroup {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        created_at: row.get(3)?,
        provider_group_count: row.get(4)?,
        folder_count: row.get(5)?,
    })
}

/// COUNTs computed for every local group listing. `folder_count` counts
/// address-book folders whose entries carry the group name in their
/// comma-separated `allowed_groups` (INSTR is case-sensitive, matching the
/// exact-match semantics of `resolve_folder_access`).
const LOCAL_GROUP_COLUMNS: &str = "lg.id, lg.name, lg.description, lg.created_at, \
     (SELECT COUNT(*) FROM group_mappings gm WHERE gm.group_id = lg.id), \
     (SELECT COUNT(DISTINCT e.folder_id) FROM address_book_entries e \
       WHERE INSTR(',' || e.allowed_groups || ',', ',' || lg.name || ',') > 0)";

/// List all local groups with usage counts, ordered by name.
pub fn list_local_groups(db: &Db) -> rusqlite::Result<Vec<LocalGroup>> {
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

/// Update a local group (rename / re-describe). `None` fields keep their
/// current value. Returns the updated group (with usage counts), or `None`
/// if the id is unknown.
pub fn update_local_group(
    db: &Db,
    id: i64,
    name: Option<&str>,
    description: Option<&str>,
) -> rusqlite::Result<Option<LocalGroup>> {
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
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "DELETE FROM group_mappings WHERE id = ?1",
        params![mapping_id],
    )?;
    Ok(changed > 0)
}
