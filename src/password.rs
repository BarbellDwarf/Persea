//! Password hashing utilities — Argon2id with OWASP-recommended parameters.
//!
//! Default: 46 MiB memory, 3 iterations, 1 parallelism, 32-byte output.
//!
//! Also implements the password policy surface: minimum length
//! enforcement and per-user reuse history (last N hashes, DB-backed). The
//! history table lives in the per-backend migrations (`008_password-history`)
//! for the SQLx backends and is created lazily here for the legacy rusqlite
//! path (the CLI `create-user` command runs before any provider schema
//! bootstrap).

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use rusqlite::params;
use sqlx::Row;

/// OWASP-recommended Argon2id parameters.
const OWASP_MEMORY_KIB: u32 = 46 * 1024; // 46 MiB
const OWASP_ITERATIONS: u32 = 3;
const OWASP_PARALLELISM: u32 = 1;

/// The password policy in effect (built from `[password]` config in
/// `main.rs` and passed to handlers via an axum `Extension`). Falling back
/// to `PasswordPolicy::default()` when the extension is absent keeps
/// hand-rolled test routers working with the documented defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordPolicy {
    /// Minimum password length in characters (default 15).
    pub min_length: usize,
    /// Number of recent password hashes kept per user for reuse rejection
    /// (default 5; 0 = reuse checking disabled).
    pub history: usize,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 15,
            history: 5,
        }
    }
}

impl PasswordPolicy {
    /// Build the policy from the `[password]` config section.
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            min_length: config.password_min_length(),
            history: config.password_history_len(),
        }
    }

    /// Reject passwords shorter than the configured minimum with a clear
    /// message; `Ok(())` when the length is acceptable.
    pub fn check_length(&self, password: &str) -> Result<(), String> {
        if password.chars().count() < self.min_length {
            return Err(format!(
                "password must be at least {} characters long",
                self.min_length
            ));
        }
        Ok(())
    }
}

/// Hash a plaintext password using Argon2id with OWASP parameters.
///
/// Returns a PHC-encoded string containing the hash and all parameters.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(OWASP_MEMORY_KIB, OWASP_ITERATIONS, OWASP_PARALLELISM, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC hash string.
///
/// Parameters are auto-detected from the stored hash — no need to supply
/// the same OWASP params at verify time.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

/// Map an SQLx error to a rusqlite error so the pool path can reuse the
/// same `rusqlite::Result` return type as the legacy file path.
#[allow(clippy::needless_pass_by_value)] // duplicate of db.rs helper, kept local for the pool path
fn map_sqlx_err(e: sqlx::Error) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(1), Some(e.to_string()))
}

/// DDL for the reuse-history table on the legacy rusqlite path. The SQLx
/// backends get the identical schema from `migrations/*/008_password-history`.
/// No foreign key: the legacy `users` table predates it and `CREATE TABLE
/// IF NOT EXISTS` must succeed on every bootstrap path (CLI included).
const HISTORY_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS password_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
)";

/// Ensure the `password_history` table exists (legacy rusqlite path; no-op
/// on the SQLx backends where migrations already ran).
pub(crate) fn ensure_history_table(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    conn.execute_batch(HISTORY_TABLE_SQL)
}

/// Return the most recent `keep` password hashes for `user_id` (newest
/// first). `keep == 0` returns an empty list (reuse checking disabled).
pub fn recent_password_hashes(
    db: &crate::db::Db,
    user_id: i64,
    keep: usize,
) -> rusqlite::Result<Vec<String>> {
    if keep == 0 {
        return Ok(Vec::new());
    }
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| async move {
            pool_recent_hashes(pool, user_id, keep).await
        });
    }
    let conn = db.lock().unwrap();
    ensure_history_table(&conn)?;
    let mut stmt = conn.prepare(
        "SELECT password_hash FROM password_history
         WHERE user_id = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![user_id, keep as i64], |row| row.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

async fn pool_recent_hashes(
    pool: &crate::db_pool::DbPool,
    user_id: i64,
    keep: usize,
) -> rusqlite::Result<Vec<String>> {
    let sql = match pool {
        crate::db_pool::DbPool::Postgres(_) => {
            "SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY id DESC LIMIT $2"
        }
        _ => {
            "SELECT password_hash FROM password_history WHERE user_id = ? ORDER BY id DESC LIMIT ?"
        }
    };
    let rows: Vec<String> = match pool {
        crate::db_pool::DbPool::Postgres(p) => sqlx::query(sql)
            .bind(user_id)
            .bind(keep as i64)
            .fetch_all(p)
            .await
            .map_err(map_sqlx_err)?
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect(),
        crate::db_pool::DbPool::MySQL(p) => sqlx::query(sql)
            .bind(user_id)
            .bind(keep as i64)
            .fetch_all(p)
            .await
            .map_err(map_sqlx_err)?
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect(),
        crate::db_pool::DbPool::SQLite(p) => sqlx::query(sql)
            .bind(user_id)
            .bind(keep as i64)
            .fetch_all(p)
            .await
            .map_err(map_sqlx_err)?
            .iter()
            .map(|r| r.get::<String, _>(0))
            .collect(),
        crate::db_pool::DbPool::None => return Err(no_pool_err()),
    };
    Ok(rows)
}

/// `true` when `password` matches any of the user's last `keep` stored
/// hashes (i.e. the password has been used recently and must be rejected).
/// Argon2id verification is expensive (46 MiB per hash); callers run in
/// spawn_blocking contexts.
pub fn password_is_recent(
    db: &crate::db::Db,
    user_id: i64,
    password: &str,
    keep: usize,
) -> rusqlite::Result<bool> {
    let hashes = recent_password_hashes(db, user_id, keep)?;
    for hash in &hashes {
        if verify_password(password, hash).unwrap_or(false) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Record a new password hash in the user's history, keeping at most
/// `keep` entries (newest wins). `keep == 0` disables history (no-op).
pub fn record_password_history(
    db: &crate::db::Db,
    user_id: i64,
    password_hash: &str,
    keep: usize,
) -> rusqlite::Result<()> {
    if keep == 0 {
        return Ok(());
    }
    let hash = password_hash.to_string();
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| async move {
            pool_record_history(pool, user_id, hash, keep).await
        });
    }
    let conn = db.lock().unwrap();
    ensure_history_table(&conn)?;
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO password_history (user_id, password_hash, created_at)
         VALUES (?1, ?2, ?3)",
        params![user_id, password_hash, now],
    )?;
    conn.execute(
        "DELETE FROM password_history
         WHERE user_id = ?1 AND id NOT IN (
             SELECT id FROM (
                 SELECT id FROM password_history
                 WHERE user_id = ?1 ORDER BY id DESC LIMIT ?2
             )
         )",
        params![user_id, keep as i64],
    )?;
    Ok(())
}

async fn pool_record_history(
    pool: &crate::db_pool::DbPool,
    user_id: i64,
    password_hash: String,
    keep: usize,
) -> rusqlite::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let insert_sql = match pool {
        crate::db_pool::DbPool::Postgres(_) => {
            "INSERT INTO password_history (user_id, password_hash, created_at) VALUES ($1, $2, $3)"
        }
        _ => "INSERT INTO password_history (user_id, password_hash, created_at) VALUES (?, ?, ?)",
    };
    let trim_sql = match pool {
        crate::db_pool::DbPool::Postgres(_) => {
            "DELETE FROM password_history WHERE user_id = $1 AND id NOT IN (
                 SELECT id FROM (
                     SELECT id FROM password_history
                     WHERE user_id = $1 ORDER BY id DESC LIMIT $2
                 ) AS keep
             )"
        }
        _ => {
            "DELETE FROM password_history WHERE user_id = ? AND id NOT IN (
                 SELECT id FROM (
                     SELECT id FROM password_history
                     WHERE user_id = ? ORDER BY id DESC LIMIT ?
                 ) AS keep
             )"
        }
    };
    match pool {
        crate::db_pool::DbPool::Postgres(p) => {
            sqlx::query(insert_sql)
                .bind(user_id)
                .bind(password_hash.clone())
                .bind(now.clone())
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
            sqlx::query(trim_sql)
                .bind(user_id)
                .bind(keep as i64)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::MySQL(p) => {
            sqlx::query(insert_sql)
                .bind(user_id)
                .bind(password_hash.clone())
                .bind(now.clone())
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
            sqlx::query(trim_sql)
                .bind(user_id)
                .bind(keep as i64)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::SQLite(p) => {
            sqlx::query(insert_sql)
                .bind(user_id)
                .bind(password_hash)
                .bind(now)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
            sqlx::query(trim_sql)
                .bind(user_id)
                .bind(keep as i64)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::None => return Err(no_pool_err()),
    }
    Ok(())
}

fn no_pool_err() -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(1),
        Some("no active database pool configured (db_url not set)".into()),
    )
}

/// Replace a user's stored password hash (password change / admin reset).
/// Works on the active store (SQLx pool or legacy rusqlite file).
pub fn update_user_password_hash(
    db: &crate::db::Db,
    user_id: i64,
    password_hash: &str,
) -> rusqlite::Result<()> {
    let hash = password_hash.to_string();
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| async move {
            pool_update_password_hash(pool, user_id, hash).await
        });
    }
    let conn = db.lock().unwrap();
    conn.execute(
        "UPDATE users SET password_hash = ?1 WHERE id = ?2",
        params![password_hash, user_id],
    )?;
    Ok(())
}

async fn pool_update_password_hash(
    pool: &crate::db_pool::DbPool,
    user_id: i64,
    password_hash: String,
) -> rusqlite::Result<()> {
    let sql = match pool {
        crate::db_pool::DbPool::Postgres(_) => "UPDATE users SET password_hash = $2 WHERE id = $1",
        _ => "UPDATE users SET password_hash = ? WHERE id = ?",
    };
    match pool {
        crate::db_pool::DbPool::Postgres(p) => {
            sqlx::query(sql)
                .bind(user_id)
                .bind(&password_hash)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::MySQL(p) => {
            sqlx::query(sql)
                .bind(&password_hash)
                .bind(user_id)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::SQLite(p) => {
            sqlx::query(sql)
                .bind(&password_hash)
                .bind(user_id)
                .execute(p)
                .await
                .map_err(map_sqlx_err)?;
        }
        crate::db_pool::DbPool::None => return Err(no_pool_err()),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_db() -> crate::db::Db {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT NOT NULL UNIQUE,
                name          TEXT NOT NULL DEFAULT '',
                role          TEXT NOT NULL DEFAULT 'viewer',
                disabled      INTEGER NOT NULL DEFAULT 0,
                created_at    TEXT NOT NULL DEFAULT (datetime('now')),
                last_login_at TEXT,
                oidc_groups   TEXT NOT NULL DEFAULT '',
                password_hash TEXT
            );",
        )
        .unwrap();
        std::sync::Arc::new(std::sync::Mutex::new(conn))
    }

    fn insert_user(db: &crate::db::Db, email: &str, hash: &str) -> i64 {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES (?1, 'u', ?2)",
            params![email, hash],
        )
        .unwrap();
        conn.last_insert_rowid()
    }

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn different_hashes_for_same_password() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        // Different salts → different hash strings
        assert_ne!(h1, h2);
        // But both verify
        assert!(verify_password("same", &h1).unwrap());
        assert!(verify_password("same", &h2).unwrap());
    }

    #[test]
    fn hash_contains_argon2id_marker() {
        let h = hash_password("test").unwrap();
        assert!(h.starts_with("$argon2id$"));
    }

    #[test]
    fn reject_invalid_hash_string() {
        assert!(verify_password("pw", "not-a-hash").is_err());
    }

    #[test]
    fn policy_length_check() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length, 15);
        assert!(policy.check_length("short").is_err());
        assert!(policy.check_length(&"x".repeat(14)).is_err());
        assert!(policy.check_length(&"x".repeat(15)).is_ok());
        assert!(policy.check_length("a-very-long-password").is_ok());
    }

    #[test]
    fn history_roundtrip_and_trim() {
        let db = test_db();
        let uid = insert_user(&db, "a@example.com", "h0");

        record_password_history(&db, uid, "h1", 5).unwrap();
        record_password_history(&db, uid, "h2", 5).unwrap();
        record_password_history(&db, uid, "h3", 5).unwrap();
        record_password_history(&db, uid, "h4", 5).unwrap();
        record_password_history(&db, uid, "h5", 5).unwrap();
        record_password_history(&db, uid, "h6", 5).unwrap();

        let hashes = recent_password_hashes(&db, uid, 5).unwrap();
        assert_eq!(hashes.len(), 5);
        assert_eq!(hashes[0], "h6");
        assert!(!hashes.contains(&"h1".to_string()), "oldest entry trimmed");
    }

    #[test]
    fn history_reuse_detection() {
        let db = test_db();
        let uid = insert_user(&db, "b@example.com", "h0");
        // The history stores Argon2id hashes; reuse is detected by verifying
        // the candidate against each stored hash.
        // codeql[rust/hard-coded-cryptographic-value] — #[test] vectors, not secrets
        let h1 = hash_password("h1").unwrap();
        // codeql[rust/hard-coded-cryptographic-value] — #[test] vectors, not secrets
        let h2 = hash_password("h2").unwrap();
        record_password_history(&db, uid, &h1, 5).unwrap();
        record_password_history(&db, uid, &h2, 5).unwrap();

        assert!(password_is_recent(&db, uid, "h1", 5).unwrap());
        assert!(password_is_recent(&db, uid, "h2", 5).unwrap());
        assert!(!password_is_recent(&db, uid, "h3", 5).unwrap());
        // keep = 0 disables reuse checking entirely
        assert!(!password_is_recent(&db, uid, "h1", 0).unwrap());
    }

    #[test]
    fn history_isolated_per_user() {
        let db = test_db();
        let uid_a = insert_user(&db, "a@example.com", "h0");
        let uid_b = insert_user(&db, "b@example.com", "h0");
        record_password_history(&db, uid_a, "secret-a", 5).unwrap();
        assert!(!password_is_recent(&db, uid_b, "secret-a", 5).unwrap());
    }

    #[test]
    fn update_password_hash_changes_stored_hash() {
        let db = test_db();
        let uid = insert_user(&db, "c@example.com", "old-hash");
        update_user_password_hash(&db, uid, "new-hash").unwrap();
        let conn = db.lock().unwrap();
        let stored: String = conn
            .query_row(
                "SELECT password_hash FROM users WHERE id = ?1",
                params![uid],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored, "new-hash");
    }
}
