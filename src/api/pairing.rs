//! Device-code pairing flow for the desktop shell (S04).
//!
//! OAuth-style device-code flow, persea-native:
//!
//! - `POST /api/desktop/pair` (anonymous, rate-limited 5/min/IP) creates a
//!   pending pairing record and returns an 8-char code. Only the SHA-256
//!   hash of the code is stored, never the plaintext.
//! - `POST /api/desktop/confirm` (logged-in cookie session, under the CSRF
//!   layer) binds the pairing to the confirming user's identity. The code
//!   is single-use: one confirm wins, every later confirm fails.
//! - `GET /api/desktop/pair/status?code=...` (anonymous, rate-limited
//!   10/min/code) returns `pending` until a user confirms, then
//!   `approved` plus the minted user token plaintext exactly once.
//!
//! The minted token is an ordinary user token (same table as
//! `/api/me/tokens`): role-capped at the user's current role, no expiry by
//! default, stamped `token_type = 'scoped'` (the desktop bridge type, see
//! `mint_login_scoped_token` for the interactive-login sibling with a 12h
//! TTL), and revocable through the existing `DELETE /api/me/tokens/{id}`.
//! The plaintext is handed out only by the status endpoint, so the desktop
//! shell never needs the webview's cookies.

use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::db_pool::DbPool;
use crate::error::AppError;
use axum::{
    extract::{ConnectInfo, Query},
    http::{HeaderMap, StatusCode},
    Extension, Json,
};
use rand::RngExt;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Lifetime of a pending pairing record, in seconds.
const PAIR_TTL_SECS: i64 = 600;
/// Pending pairings created per IP per minute.
const PAIR_CREATE_PER_MIN: usize = 5;
/// Status polls per code per minute.
const PAIR_STATUS_PER_MIN: usize = 10;
/// Code alphabet: 32 unambiguous uppercase chars (I, L, O, 0, 1 omitted).
/// `byte % 32` over a uniform byte is unbiased because 256 % 32 == 0.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
/// Length of the pairing code (before separators).
const CODE_LEN: usize = 8;
/// Hostname length kept for the token label (token names cap at 100 chars).
const HOSTNAME_MAX_LEN: usize = 64;

/// Error surface for the pairing endpoints: a 429 for rate limiting, a 410
/// for expired or already-consumed codes, and the ordinary [`AppError`]
/// surface for everything else.
pub enum PairingError {
    /// Sliding-window rate limit exceeded; 429.
    RateLimited,
    /// The code is expired or already used; 410.
    Gone(String),
    /// Any regular application error.
    App(AppError),
}

impl From<AppError> for PairingError {
    fn from(e: AppError) -> Self {
        PairingError::App(e)
    }
}

impl axum::response::IntoResponse for PairingError {
    fn into_response(self) -> axum::response::Response {
        match self {
            PairingError::RateLimited => AppError::error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "too many requests, try again later",
            ),
            PairingError::Gone(msg) => AppError::error_response(StatusCode::GONE, msg),
            PairingError::App(e) => e.into_response(),
        }
    }
}

/// Body for `POST /api/desktop/pair`.
#[derive(Deserialize)]
pub struct PairRequest {
    /// Device hostname, used to label the minted token. Optional.
    pub hostname: Option<String>,
}

/// Body for `POST /api/desktop/confirm`.
#[derive(Deserialize)]
pub struct ConfirmRequest {
    /// The 8-char code shown by the desktop shell.
    pub code: String,
}

/// Query parameters for `GET /api/desktop/pair/status`.
#[derive(Deserialize)]
pub struct StatusQuery {
    /// The 8-char code being polled.
    pub code: String,
}

// ── Rate limiting ───────────────────────────────────────────────────────

/// Fixed-window rate limiter, one bucket per key. Buckets are pruned
/// lazily; entries untouched for two windows are dropped.
pub struct WindowLimiter {
    window: Duration,
    max: usize,
    hits: Mutex<std::collections::HashMap<String, Vec<Instant>>>,
}

impl WindowLimiter {
    /// Build a sliding-window limiter: at most `max` hits per `window`
    /// per key. Not `const` because the hit map allocates.
    pub fn new(window: Duration, max: usize) -> Self {
        Self {
            window,
            max,
            hits: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Record a hit for `key`. Returns `false` when the current window
    /// already holds `max` hits for that key.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut hits = self.hits.lock().unwrap();
        let window = self.window;
        let hits_for_key = hits.entry(key.to_string()).or_default();
        hits_for_key.retain(|t| now.duration_since(*t) < window);
        if hits_for_key.len() >= self.max {
            return false;
        }
        hits_for_key.push(now);
        if hits.len() > 512 {
            let cutoff = window.saturating_mul(2);
            hits.retain(|_, v| v.last().is_some_and(|t| now.duration_since(*t) < cutoff));
        }
        true
    }
}

fn pair_create_limiter() -> &'static WindowLimiter {
    static LIMITER: std::sync::OnceLock<WindowLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| WindowLimiter::new(Duration::from_secs(60), PAIR_CREATE_PER_MIN))
}

fn pair_status_limiter() -> &'static WindowLimiter {
    static LIMITER: std::sync::OnceLock<WindowLimiter> = std::sync::OnceLock::new();
    LIMITER.get_or_init(|| WindowLimiter::new(Duration::from_secs(60), PAIR_STATUS_PER_MIN))
}

// ── Code helpers ────────────────────────────────────────────────────────

/// SHA-256 of the normalized code, hex-encoded. The only representation of
/// the code ever stored.
pub fn sha256_hex(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate an 8-char code from the unambiguous alphabet.
pub fn generate_code() -> String {
    let mut bytes = [0u8; CODE_LEN];
    rand::rng().fill(&mut bytes);
    bytes
        .iter()
        .map(|b| CODE_ALPHABET[*b as usize % CODE_ALPHABET.len()] as char)
        .collect()
}

/// Normalize a code as typed: strip whitespace and hyphen separators,
/// uppercase.
pub fn normalize_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_uppercase()
}

/// Shape check for a normalized code: exactly [`CODE_LEN`] alphabet chars.
pub fn valid_code_shape(code: &str) -> bool {
    code.len() == CODE_LEN && code.bytes().all(|b| CODE_ALPHABET.contains(&b))
}

/// Device label for the minted token: `Persea Desktop (hostname)`, or just
/// `Persea Desktop` when no hostname was provided.
pub fn token_name(hostname: &str) -> String {
    let hostname = sanitize_hostname(hostname);
    if hostname.is_empty() {
        "Persea Desktop".to_string()
    } else {
        format!("Persea Desktop ({hostname})")
    }
}

/// Keep only hostname-safe characters, capped at [`HOSTNAME_MAX_LEN`].
pub fn sanitize_hostname(raw: &str) -> String {
    raw.chars()
        .filter(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | ':' | ' ' | '(' | ')' | '[' | ']')
        })
        .take(HOSTNAME_MAX_LEN)
        .collect::<String>()
        .trim()
        .to_string()
}

/// Fixed-width UTC timestamp, same format as every other table.
fn db_ts(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Parse a stored timestamp. An unparseable value counts as expired (fail
/// closed).
fn is_expired(expires_at: &str, now: chrono::DateTime<chrono::Utc>) -> bool {
    match chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S") {
        Ok(ndt) => {
            let dt: chrono::DateTime<chrono::Utc> =
                chrono::DateTime::from_naive_utc_and_offset(ndt, chrono::Utc);
            dt <= now
        }
        Err(_) => true,
    }
}

fn db_err(e: &sqlx::Error) -> AppError {
    AppError::Internal(format!("database error: {e}"))
}

fn no_pool_err() -> AppError {
    AppError::Internal("no active database pool configured".into())
}

// ── Storage ─────────────────────────────────────────────────────────────

/// A pending pairing record as stored.
pub struct PairingRow {
    /// User bound by confirmation; `None` while pending.
    pub user_id: Option<i64>,
    /// Device hostname from the pair request (token label).
    pub hostname: String,
    /// Fixed-width UTC expiry timestamp.
    pub expires_at: String,
    /// When the token was handed out; `None` while pending/approved.
    pub consumed_at: Option<String>,
}

/// Create the pairing table on the legacy rusqlite path. The SQLx backends
/// get it from `migrations/*/011_desktop_pairings.sql` at startup; this is
/// the same "migration files are reference DDL" fallback the settings and
/// provider tables use.
fn ensure_pairing_table(db: &Db) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS desktop_pairings (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash    TEXT NOT NULL UNIQUE,
            user_id      INTEGER REFERENCES users(id),
            hostname     TEXT NOT NULL DEFAULT '',
            created_at   TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at   TEXT NOT NULL,
            consumed_at  TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_desktop_pairings_expires ON desktop_pairings(expires_at);
        CREATE INDEX IF NOT EXISTS idx_desktop_pairings_user ON desktop_pairings(user_id);",
    )
}

/// Insert a pending pairing record.
pub async fn insert_pairing(
    db: &Db,
    code_hash: String,
    hostname: String,
    expires_at: String,
) -> Result<(), AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_insert_pairing(pool, &code_hash, &hostname, &expires_at).await;
    }
    let db = db.clone();
    tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
        ensure_pairing_table(&db)?;
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO desktop_pairings (code_hash, hostname, expires_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![code_hash, hostname, expires_at],
        )?;
        Ok(())
    })
    .await
    .map_err(AppError::from)??;
    Ok(())
}

/// Look up a pairing record by code hash.
pub async fn lookup_pairing(db: &Db, code_hash: String) -> Result<Option<PairingRow>, AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_lookup_pairing(pool, &code_hash).await;
    }
    let db = db.clone();
    let result: rusqlite::Result<Option<PairingRow>> =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<PairingRow>> {
            ensure_pairing_table(&db)?;
            let conn = db.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT user_id, hostname, expires_at, consumed_at
             FROM desktop_pairings WHERE code_hash = ?1",
            )?;
            let mut rows = stmt.query_map(rusqlite::params![code_hash], |row| {
                Ok(PairingRow {
                    user_id: row.get(0)?,
                    hostname: row.get(1)?,
                    expires_at: row.get(2)?,
                    consumed_at: row.get(3)?,
                })
            })?;
            rows.next().transpose()
        })
        .await
        .map_err(AppError::from)?;
    result.map_err(AppError::from)
}

/// Bind a pending pairing to the confirming user. Returns `false` when the
/// record is already bound or consumed (single-use under races). Only the
/// `user_id` is stamped here; the token is minted by the status poll, which
/// claims the record by setting `consumed_at`.
pub async fn bind_pairing(
    db: &Db,
    code_hash: String,
    user_id: i64,
    now_db: String,
) -> Result<bool, AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_bind_pairing(pool, &code_hash, user_id, &now_db).await;
    }
    let db = db.clone();
    let result: rusqlite::Result<bool> =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
            ensure_pairing_table(&db)?;
            let conn = db.lock().unwrap();
            let n = conn.execute(
                "UPDATE desktop_pairings SET user_id = ?1
             WHERE code_hash = ?2 AND user_id IS NULL AND consumed_at IS NULL AND expires_at > ?3",
                rusqlite::params![user_id, code_hash, now_db],
            )?;
            Ok(n > 0)
        })
        .await
        .map_err(AppError::from)?;
    result.map_err(AppError::from)
}

/// Claim an approved pairing so the token plaintext is handed out exactly
/// once. Returns `false` when another poll already claimed it.
pub async fn claim_pairing(db: &Db, code_hash: String, now_db: String) -> Result<bool, AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_claim_pairing(pool, &code_hash, &now_db).await;
    }
    let db = db.clone();
    let result: rusqlite::Result<bool> =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
        ensure_pairing_table(&db)?;
        let conn = db.lock().unwrap();
        let n = conn.execute(
            "UPDATE desktop_pairings SET consumed_at = ?1
             WHERE code_hash = ?2 AND user_id IS NOT NULL AND consumed_at IS NULL AND expires_at > ?1",
            rusqlite::params![now_db, code_hash],
        )?;
        Ok(n > 0)
    })
    .await
    .map_err(AppError::from)?;
    result.map_err(AppError::from)
}

/// Delete the caller's token(s) with the given name. Used to replace a
/// previous paired token on re-pair (refresh semantics: pairing again
/// invalidates the old device token).
pub async fn revoke_tokens_named(db: &Db, user_id: i64, name: String) -> Result<usize, AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_revoke_tokens_named(pool, user_id, &name).await;
    }
    let db = db.clone();
    let result: rusqlite::Result<usize> =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<usize> {
            let conn = db.lock().unwrap();
            let n = conn.execute(
                "DELETE FROM user_api_tokens WHERE user_id = ?1 AND name = ?2",
                rusqlite::params![user_id, name],
            )?;
            Ok(n)
        })
        .await
        .map_err(AppError::from)?;
    result.map_err(AppError::from)
}

/// Fetch a user's email and role by id.
pub async fn user_identity_by_id(
    db: &Db,
    user_id: i64,
) -> Result<Option<(String, String)>, AppError> {
    if let Some(pool) = db::active_pool() {
        return pool_user_identity_by_id(pool, user_id).await;
    }
    let db = db.clone();
    let result: rusqlite::Result<Option<(String, String)>> =
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<(String, String)>> {
            let conn = db.lock().unwrap();
            let mut stmt = conn.prepare("SELECT email, role FROM users WHERE id = ?1")?;
            let mut rows = stmt.query_map(rusqlite::params![user_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            rows.next().transpose()
        })
        .await
        .map_err(AppError::from)?;
    result.map_err(AppError::from)
}

// ── SQLx pool storage ───────────────────────────────────────────────────

async fn pool_insert_pairing(
    pool: &DbPool,
    code_hash: &str,
    hostname: &str,
    expires_at: &str,
) -> Result<(), AppError> {
    let n = match pool {
        DbPool::Postgres(p) => sqlx::query(
            "INSERT INTO desktop_pairings (code_hash, hostname, expires_at) VALUES ($1, $2, $3)",
        )
        .bind(code_hash)
        .bind(hostname)
        .bind(expires_at)
        .execute(p)
        .await
        .map(|r| r.rows_affected()),
        DbPool::MySQL(p) => sqlx::query(
            "INSERT INTO desktop_pairings (code_hash, hostname, expires_at) VALUES (?, ?, ?)",
        )
        .bind(code_hash)
        .bind(hostname)
        .bind(expires_at)
        .execute(p)
        .await
        .map(|r| r.rows_affected()),
        DbPool::SQLite(p) => sqlx::query(
            "INSERT INTO desktop_pairings (code_hash, hostname, expires_at) VALUES (?, ?, ?)",
        )
        .bind(code_hash)
        .bind(hostname)
        .bind(expires_at)
        .execute(p)
        .await
        .map(|r| r.rows_affected()),
        DbPool::None => return Err(no_pool_err()),
    };
    if n.map_err(|e| db_err(&e))? == 0 {
        return Err(AppError::Internal("failed to insert pairing record".into()));
    }
    Ok(())
}

async fn pool_lookup_pairing(
    pool: &DbPool,
    code_hash: &str,
) -> Result<Option<PairingRow>, AppError> {
    use sqlx::Row as _;
    let row = match pool {
        DbPool::Postgres(p) => sqlx::query(
            "SELECT user_id, hostname, expires_at, consumed_at
                 FROM desktop_pairings WHERE code_hash = $1",
        )
        .bind(code_hash)
        .fetch_optional(p)
        .await
        .map(|opt| {
            opt.map(|r| {
                (
                    r.get::<Option<i64>, _>(0),
                    r.get::<String, _>(1),
                    r.get::<String, _>(2),
                    r.get::<Option<String>, _>(3),
                )
            })
        }),
        DbPool::MySQL(p) => sqlx::query(
            "SELECT user_id, hostname, expires_at, consumed_at
                 FROM desktop_pairings WHERE code_hash = ?",
        )
        .bind(code_hash)
        .fetch_optional(p)
        .await
        .map(|opt| {
            opt.map(|r| {
                (
                    r.get::<Option<i64>, _>(0),
                    r.get::<String, _>(1),
                    r.get::<String, _>(2),
                    r.get::<Option<String>, _>(3),
                )
            })
        }),
        DbPool::SQLite(p) => sqlx::query(
            "SELECT user_id, hostname, expires_at, consumed_at
                 FROM desktop_pairings WHERE code_hash = ?",
        )
        .bind(code_hash)
        .fetch_optional(p)
        .await
        .map(|opt| {
            opt.map(|r| {
                (
                    r.get::<Option<i64>, _>(0),
                    r.get::<String, _>(1),
                    r.get::<String, _>(2),
                    r.get::<Option<String>, _>(3),
                )
            })
        }),
        DbPool::None => return Err(no_pool_err()),
    };
    let row = row.map_err(|e| db_err(&e))?;
    Ok(
        row.map(|(user_id, hostname, expires_at, consumed_at)| PairingRow {
            user_id,
            hostname,
            expires_at,
            consumed_at,
        }),
    )
}

async fn pool_bind_pairing(
    pool: &DbPool,
    code_hash: &str,
    user_id: i64,
    now_db: &str,
) -> Result<bool, AppError> {
    let n = match pool {
        DbPool::Postgres(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET user_id = $1
                 WHERE code_hash = $2 AND user_id IS NULL AND consumed_at IS NULL AND expires_at > $3",
            )
            .bind(user_id)
            .bind(code_hash)
            .bind(now_db)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::MySQL(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET user_id = ?
                 WHERE code_hash = ? AND user_id IS NULL AND consumed_at IS NULL AND expires_at > ?",
            )
            .bind(user_id)
            .bind(code_hash)
            .bind(now_db)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::SQLite(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET user_id = ?
                 WHERE code_hash = ? AND user_id IS NULL AND consumed_at IS NULL AND expires_at > ?",
            )
            .bind(user_id)
            .bind(code_hash)
            .bind(now_db)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::None => return Err(no_pool_err()),
    };
    let n = n.map_err(|e| db_err(&e))?;
    Ok(n > 0)
}

async fn pool_claim_pairing(
    pool: &DbPool,
    code_hash: &str,
    now_db: &str,
) -> Result<bool, AppError> {
    let n = match pool {
        DbPool::Postgres(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET consumed_at = $1
                 WHERE code_hash = $2 AND user_id IS NOT NULL AND consumed_at IS NULL AND expires_at > $1",
            )
            .bind(now_db)
            .bind(code_hash)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::MySQL(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET consumed_at = ?
                 WHERE code_hash = ? AND user_id IS NOT NULL AND consumed_at IS NULL AND expires_at > ?",
            )
            .bind(now_db)
            .bind(code_hash)
            .bind(now_db)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::SQLite(p) => {
            sqlx::query(
                "UPDATE desktop_pairings SET consumed_at = ?
                 WHERE code_hash = ? AND user_id IS NOT NULL AND consumed_at IS NULL AND expires_at > ?",
            )
            .bind(now_db)
            .bind(code_hash)
            .bind(now_db)
            .execute(p)
            .await
            .map(|r| r.rows_affected())
        }
        DbPool::None => return Err(no_pool_err()),
    };
    let n = n.map_err(|e| db_err(&e))?;
    Ok(n > 0)
}

async fn pool_revoke_tokens_named(
    pool: &DbPool,
    user_id: i64,
    name: &str,
) -> Result<usize, AppError> {
    let n = match pool {
        DbPool::Postgres(p) => {
            sqlx::query("DELETE FROM user_api_tokens WHERE user_id = $1 AND name = $2")
                .bind(user_id)
                .bind(name)
                .execute(p)
                .await
                .map(|r| r.rows_affected())
        }
        DbPool::MySQL(p) => {
            sqlx::query("DELETE FROM user_api_tokens WHERE user_id = ? AND name = ?")
                .bind(user_id)
                .bind(name)
                .execute(p)
                .await
                .map(|r| r.rows_affected())
        }
        DbPool::SQLite(p) => {
            sqlx::query("DELETE FROM user_api_tokens WHERE user_id = ? AND name = ?")
                .bind(user_id)
                .bind(name)
                .execute(p)
                .await
                .map(|r| r.rows_affected())
        }
        DbPool::None => return Err(no_pool_err()),
    };
    let n = n.map_err(|e| db_err(&e))?;
    Ok(n as usize)
}

async fn pool_user_identity_by_id(
    pool: &DbPool,
    user_id: i64,
) -> Result<Option<(String, String)>, AppError> {
    use sqlx::Row as _;
    let row = match pool {
        DbPool::Postgres(p) => sqlx::query("SELECT email, role FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(p)
            .await
            .map(|opt| opt.map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))),
        DbPool::MySQL(p) => sqlx::query("SELECT email, role FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(p)
            .await
            .map(|opt| opt.map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))),
        DbPool::SQLite(p) => sqlx::query("SELECT email, role FROM users WHERE id = ?")
            .bind(user_id)
            .fetch_optional(p)
            .await
            .map(|opt| opt.map(|r| (r.get::<String, _>(0), r.get::<String, _>(1)))),
        DbPool::None => return Err(no_pool_err()),
    };
    row.map_err(|e| db_err(&e))
}

// ── Handlers ────────────────────────────────────────────────────────────

/// `POST /api/desktop/pair`: create a pending device pairing. Anonymous;
/// rate-limited to [`PAIR_CREATE_PER_MIN`] per IP. Returns the 8-char code
/// and its expiry.
pub async fn create_pairing(
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    body: Option<Json<PairRequest>>,
) -> Result<Json<serde_json::Value>, PairingError> {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    if !pair_create_limiter().allow(&ip.to_string()) {
        return Err(PairingError::RateLimited);
    }
    let hostname = body
        .and_then(|Json(b)| b.hostname)
        .map(|h| sanitize_hostname(&h))
        .unwrap_or_default();
    let code = generate_code();
    let code_hash = sha256_hex(&code);
    let expires = chrono::Utc::now() + chrono::Duration::seconds(PAIR_TTL_SECS);
    insert_pairing(&database, code_hash, hostname, db_ts(expires)).await?;
    Ok(Json(json!({
        "code": code,
        "expires_at": expires.to_rfc3339(),
    })))
}

/// `POST /api/desktop/confirm`: bind a pending pairing to the logged-in
/// user. Requires a cookie-session identity with poweruser or higher (same
/// gate as token creation) and rides the CSRF layer with every other
/// state-changing API call. Expired or already-used codes return 410 Gone.
pub async fn confirm_pairing(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<serde_json::Value>, PairingError> {
    let id = match identity {
        Some(Extension(id)) => id,
        None => {
            return Err(AppError::Auth("authentication required".into()).into());
        }
    };
    if !id.has_role("poweruser") {
        return Err(AppError::Forbidden(
            "poweruser role or higher required to approve device pairing".into(),
        )
        .into());
    }
    let email = match &id {
        AuthIdentity::User { email, .. } => email.clone(),
        AuthIdentity::ApiKey(_) => {
            return Err(AppError::Internal(
                "API key identities cannot approve device pairing".into(),
            )
            .into());
        }
    };
    let code = normalize_code(&req.code);
    if !valid_code_shape(&code) {
        return Err(AppError::Validation("invalid pairing code".into()).into());
    }
    let code_hash = sha256_hex(&code);
    let now = chrono::Utc::now();
    let now_db = db_ts(now);

    let user = {
        let db = database.clone();
        let email_clone = email.clone();
        tokio::task::spawn_blocking(move || db::get_user_by_email(&db, &email_clone))
            .await
            .map_err(AppError::from)?
            .map_err(|_| AppError::Internal("failed to look up user".into()))?
    };

    match lookup_pairing(&database, code_hash.clone()).await? {
        None => Err(AppError::NotFound("pairing code not found".into()).into()),
        Some(row) if is_expired(&row.expires_at, now) => {
            Err(PairingError::Gone("pairing code expired".into()))
        }
        Some(row) if row.user_id.is_some() || row.consumed_at.is_some() => {
            Err(PairingError::Gone("pairing code already used".into()))
        }
        Some(row) => {
            if !bind_pairing(&database, code_hash, user.id, now_db).await? {
                return Err(PairingError::Gone("pairing code already used".into()));
            }
            Ok(Json(json!({
                "ok": true,
                "device_name": row.hostname,
            })))
        }
    }
}

/// `GET /api/desktop/pair/status?code=...`: the shell's poll loop.
/// Anonymous; rate-limited to [`PAIR_STATUS_PER_MIN`] per code. Returns
/// `{"status":"pending"}` until a user confirms, then `approved` plus the
/// minted token plaintext exactly once. Expired and already-consumed codes
/// return 410 Gone.
pub async fn pairing_status(
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Query(query): Query<StatusQuery>,
) -> Result<Json<serde_json::Value>, PairingError> {
    let code = normalize_code(&query.code);
    if !valid_code_shape(&code) {
        return Err(AppError::NotFound("pairing code not found".into()).into());
    }
    let code_hash = sha256_hex(&code);
    if !pair_status_limiter().allow(&code_hash) {
        return Err(PairingError::RateLimited);
    }
    let now = chrono::Utc::now();
    let row = match lookup_pairing(&database, code_hash.clone()).await? {
        None => return Err(AppError::NotFound("pairing code not found".into()).into()),
        Some(row) => row,
    };
    if is_expired(&row.expires_at, now) {
        return Err(PairingError::Gone("pairing code expired".into()));
    }
    if row.consumed_at.is_some() {
        return Err(PairingError::Gone("pairing code already used".into()));
    }
    let Some(user_id) = row.user_id else {
        return Ok(Json(json!({ "status": "pending" })));
    };

    // Approved: claim the record first so the plaintext is handed out
    // exactly once, then mint the token.
    if !claim_pairing(&database, code_hash, db_ts(chrono::Utc::now())).await? {
        return Err(PairingError::Gone("pairing code already used".into()));
    }
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    let (token_id, plaintext, name, max_role) =
        mint_paired_token(&database, user_id, &row.hostname, &ip).await?;
    Ok(Json(json!({
        "status": "approved",
        "token": plaintext,
        "token_id": token_id,
        "name": name,
        "max_role": max_role,
        "expires_at": None::<String>,
        "device_name": row.hostname,
    })))
}

/// TTL of a login-issued scoped desktop token, in hours (persea#227).
pub const SCOPED_TOKEN_TTL_HOURS: i64 = 12;
/// Name of the scoped token minted by an interactive desktop login.
/// Distinct from the pairing token name (`Persea Desktop (hostname)`) so
/// re-pairing and re-login never revoke each other's token.
pub const LOGIN_TOKEN_NAME: &str = "Persea Desktop (login)";

/// Mint the paired user token: role-capped at the user's current role, no
/// expiry, named `Persea Desktop (hostname)`. A previous token with the
/// same name is revoked first, so re-pairing refreshes the device token.
async fn mint_paired_token(
    database: &Db,
    user_id: i64,
    hostname: &str,
    ip: &std::net::IpAddr,
) -> Result<(i64, String, String, String), AppError> {
    let name = token_name(hostname);
    mint_desktop_token(database, user_id, name, None, ip, "device pairing (desktop shell)").await
}

/// Mint the scoped token issued by an interactive desktop login
/// (persea#227): bound to the user, role-capped at the user's current
/// role, `token_type = 'scoped'`, 12-hour TTL. A previous login-issued
/// token is revoked first (refresh semantics: a new login invalidates the
/// old desktop token). Returns (token_id, plaintext, name, max_role,
/// expires_db, expires_rfc3339).
pub async fn mint_login_scoped_token(
    database: &Db,
    user_id: i64,
    ip: &std::net::IpAddr,
) -> Result<(i64, String, String, String, String, String), AppError> {
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(SCOPED_TOKEN_TTL_HOURS);
    let expires_db = db_ts(expires);
    let expires_rfc = expires.to_rfc3339();
    let (token_id, plaintext, name, max_role) = mint_desktop_token(
        database,
        user_id,
        LOGIN_TOKEN_NAME.to_string(),
        Some(expires_db.clone()),
        ip,
        "interactive login (desktop shell)",
    )
    .await?;
    Ok((token_id, plaintext, name, max_role, expires_db, expires_rfc))
}

/// Mint a desktop user token: role-capped at the user's current role,
/// `token_type = 'scoped'`, optionally expiring, named `name`. A previous
/// token with the same name is revoked first (refresh semantics: a new
/// desktop login/pairing invalidates the old desktop token).
async fn mint_desktop_token(
    database: &Db,
    user_id: i64,
    name: String,
    expires_at: Option<String>,
    ip: &std::net::IpAddr,
    audit_note: &str,
) -> Result<(i64, String, String, String), AppError> {
    let _ = revoke_tokens_named(database, user_id, name.clone()).await?;
    let (email, role) = user_identity_by_id(database, user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user not found".into()))?;

    let name_for_token = name.clone();
    let role_for_token = role.clone();
    let expires_for_token = expires_at;
    let db = database.clone();
    let result = tokio::task::spawn_blocking(move || {
        db::create_scoped_user_token(
            &db,
            user_id,
            &name_for_token,
            Some(&role_for_token),
            expires_for_token.as_deref(),
        )
    })
    .await
    .map_err(AppError::from)?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint") {
            AppError::Conflict(
                "token name already exists — revoke the previous desktop token and sign in again".into(),
            )
        } else {
            AppError::Internal("failed to create token".into())
        }
    })?;
    let (token_id, plaintext) = result;

    let db = database.clone();
    let email_clone = email.clone();
    let name_clone = name.clone();
    let ip_str = ip.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        db::log_token_event(
            &db,
            Some(token_id),
            Some(&name_clone),
            &email_clone,
            "created",
            Some(&ip_str),
            Some(audit_note),
        )
    })
    .await;
    Ok((token_id, plaintext, name, role))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_8_chars_from_unambiguous_alphabet() {
        for _ in 0..100 {
            let code = generate_code();
            assert_eq!(code.len(), CODE_LEN);
            assert!(valid_code_shape(&code), "code {code} has ambiguous chars");
        }
    }

    #[test]
    fn normalize_strips_separators_and_uppercases() {
        assert_eq!(normalize_code("abcd-2345"), "ABCD2345");
        assert_eq!(normalize_code(" abcd 2345 "), "ABCD2345");
        assert_eq!(normalize_code("abcd2345"), "ABCD2345");
    }

    #[test]
    fn shape_check_rejects_short_and_ambiguous() {
        assert!(valid_code_shape("ABCD2345"));
        assert!(!valid_code_shape("ABCD234"));
        assert!(!valid_code_shape("ABCD23456"));
        assert!(!valid_code_shape("ABCDO345"), "O is ambiguous");
        assert!(!valid_code_shape("ABCDl345"), "l is ambiguous");
        assert!(!valid_code_shape("ABCD2345-"), "dash is not a code char");
    }

    #[test]
    fn token_name_labels_hostname() {
        assert_eq!(token_name("dev-box"), "Persea Desktop (dev-box)");
        assert_eq!(token_name(""), "Persea Desktop");
        assert_eq!(token_name("  "), "Persea Desktop");
    }

    #[test]
    fn sanitize_hostname_drops_unsafe_chars_and_truncates() {
        assert_eq!(sanitize_hostname("dev-box:2"), "dev-box:2");
        assert_eq!(sanitize_hostname("a<b>\"c\\d`e"), "abcde");
        assert_eq!(sanitize_hostname(&"abc".repeat(30)).len(), HOSTNAME_MAX_LEN);
    }

    #[test]
    fn hashes_are_sha256_hex() {
        let h = sha256_hex("ABCD2345");
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(sha256_hex("ABCD2345"), sha256_hex("ABCD2346"));
    }

    #[test]
    fn limiter_allows_max_hits_per_window() {
        let limiter = WindowLimiter::new(Duration::from_secs(60), 3);
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(limiter.allow("k"));
        assert!(!limiter.allow("k"));
        assert!(limiter.allow("other"));
    }

    #[tokio::test]
    async fn login_scoped_token_is_scoped_with_12h_ttl() {
        use crate::db::{self, Db};
        let db: Db = db::init_db(std::path::Path::new(":memory:")).unwrap();
        let user = db::upsert_user(&db, "desktop@example.com", "Desktop", None, "poweruser", &[])
            .unwrap();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let (token_id, plaintext, name, max_role, expires_db, expires_rfc) =
            mint_login_scoped_token(&db, user.id, &ip).await.unwrap();

        assert_eq!(name, LOGIN_TOKEN_NAME);
        assert_eq!(max_role, "poweruser");

        // Stored as a scoped user token with a server-side expiry ~12h out.
        let tokens = db::list_user_tokens(&db, user.id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, token_id);
        assert_eq!(tokens[0].token_type, "scoped");
        let exp = tokens[0]
            .expires_at
            .clone()
            .expect("login scoped token must carry an expiry");
        assert_eq!(exp, expires_db);
        let exp_ndt = chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%d %H:%M:%S").unwrap();
        let hours_ahead = (exp_ndt - chrono::Utc::now().naive_utc()).num_minutes() as f64 / 60.0;
        assert!(
            (11.0..13.0).contains(&hours_ahead),
            "TTL should be about 12 hours, got {hours_ahead:.1}h"
        );
        assert!(expires_rfc.starts_with("20"), "rfc3339 expiry: {expires_rfc}");

        // The token validates through the normal user-token path (same
        // surface the pairing token covers), role-capped at the user role.
        let (u, meta) = db::validate_user_token(&db, &plaintext).unwrap();
        assert_eq!(u.id, user.id);
        assert_eq!(meta.token_type, "scoped");
        assert_eq!(meta.max_role.as_deref(), Some("poweruser"));
    }

    #[tokio::test]
    async fn login_scoped_token_refreshes_and_is_revocable() {
        use crate::db::{self, Db};
        let db: Db = db::init_db(std::path::Path::new(":memory:")).unwrap();
        let user = db::upsert_user(&db, "desktop@example.com", "Desktop", None, "operator", &[])
            .unwrap();
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let (token_id, _t1, _n, _r, _e1, _e2) =
            mint_login_scoped_token(&db, user.id, &ip).await.unwrap();
        let (token_id2, _t2, _n2, _r2, _e3, _e4) =
            mint_login_scoped_token(&db, user.id, &ip).await.unwrap();
        assert_ne!(token_id, token_id2);

        // Refresh semantics: a new login revokes the previous login token.
        let tokens = db::list_user_tokens(&db, user.id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, token_id2);
        assert!(db::revoke_user_token(&db, user.id, token_id2).unwrap());
        assert!(db::list_user_tokens(&db, user.id).unwrap().is_empty());
    }
}
