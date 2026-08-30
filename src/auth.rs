//! Authentication middleware — supports API key, OIDC session cookie, and
//! single-use WebSocket tickets.

use crate::db::{self, AuthError, Db};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Extension,
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Instant;
use tokio::sync::Mutex;

// ── Cached system_settings flags (persea#276, coherence persea#289) ──
//
// Two boolean flags are read on every API-key-authenticated request but
// change rarely (admin toggles). Holding them in a process-wide cache
// eliminates two `spawn_blocking` DB reads per request on the hottest
// path. Coherence depends on the deployment mode:
//
// - Single instance (no shared SQLx pool): the only writer is this
//   process — the PUT /api/system/settings handler updates the cache
//   directly after its commit — so the cache is always fresh and cached
//   reads touch no database at all (the persea#276 win, unchanged).
// - HA / shared DB backend: every instance caches its own view, so a
//   toggle committed on instance A stayed invisible to instance B until
//   B restarted or issued its own PUT (the v1.1.1 regression). Each
//   cache entry therefore also stores the `settings_epoch` value it was
//   loaded at, and every read validates it against the shared DB with
//   one primary-key point read (`SELECT value ... WHERE key =
//   'settings_epoch'`). The PUT handler bumps that row in the same
//   commit as the flag writes, so a changed epoch guarantees the new
//   flags are already committed and instance B sees A's toggle within
//   one request. The per-request cost is bounded at that single indexed
//   point read; the full flag reload happens only when a change is
//   actually detected.
//
// Invalidation: the PUT handler calls `update_settings_cache(key, value)`
// for each written flag and `set_settings_cache_epoch(new_epoch)` for the
// epoch its commit produced, so the local instance takes effect instantly
// and does not churn a reload for its own change.

/// Cached boolean flags from `system_settings`.
#[derive(Clone, Copy, Debug)]
pub struct SettingsFlags {
    /// Whether API-key authentication is permitted.
    pub api_keys_enabled: bool,
    /// Whether compliance mode (persea#228) is active.
    pub compliance_mode_enabled: bool,
}

/// A cache entry: the flags plus the `settings_epoch` they were loaded
/// at (persea#289). Single-instance mode ignores the epoch; HA mode
/// compares it against the shared DB on every read.
#[derive(Clone, Copy, Debug)]
struct CachedSettings {
    epoch: i64,
    flags: SettingsFlags,
}

/// Process-wide cache. Initialized once at startup via
/// [`init_settings_cache`]; invalidated per-key by the admin PUT handler
/// via [`update_settings_cache`], with the post-commit epoch recorded by
/// [`set_settings_cache_epoch`].
static SETTINGS_CACHE: OnceLock<RwLock<CachedSettings>> = OnceLock::new();

/// Load both flags from the database in a single blocking call. Returns
/// the defaults when the table is missing or unreadable (matches the
/// legacy per-read fallbacks).
fn load_settings_flags_from_db(db: &Db) -> SettingsFlags {
    SettingsFlags {
        api_keys_enabled: crate::settings_merge::read_toggle(db, "enable_api_keys", true),
        compliance_mode_enabled: crate::settings_merge::read_toggle(db, "compliance_mode", false),
    }
}

/// Whether this process shares `system_settings` with peers (HA mode:
/// a shared SQLx pool is installed — same detection as
/// `SessionManager::ha_enabled`). Single-instance deployments skip the
/// epoch check entirely: their cache is the only view and the PUT
/// handler keeps it fresh, so reads stay pure-memory.
fn settings_epoch_check_enabled() -> bool {
    crate::db::active_pool().is_some()
}

/// Seed the cache at startup. Must be called once, after the DB pool is
/// ready and before the router serves requests. Records the current
/// `settings_epoch` so HA mode starts coherent with the shared backend.
pub fn init_settings_cache(db: &Db) {
    let flags = load_settings_flags_from_db(db);
    let epoch = crate::db::settings_epoch(db).unwrap_or(0);
    let _ = SETTINGS_CACHE.set(RwLock::new(CachedSettings { epoch, flags }));
}

/// Refresh the cached value for one flag key. Called by the admin
/// settings PUT handler after a successful DB commit. No-op when the
/// cache has not been initialized (defensive; should not happen in
/// production). HA callers follow with [`set_settings_cache_epoch`] so
/// the entry's epoch matches the commit that produced these values.
pub fn update_settings_cache(key: &str, value: &str) {
    let Some(rw) = SETTINGS_CACHE.get() else {
        return;
    };
    if let Ok(mut cache) = rw.write() {
        match key {
            "enable_api_keys" => cache.flags.api_keys_enabled = value == "true",
            "compliance_mode" => cache.flags.compliance_mode_enabled = value == "true",
            _ => {}
        }
    }
}

/// Record the `settings_epoch` the cache now reflects (persea#289).
/// Called by the admin PUT handler after its commit bumped the DB epoch,
/// so the local instance's next read passes the freshness check without
/// a redundant reload. No-op when the cache has not been initialized.
pub fn set_settings_cache_epoch(epoch: i64) {
    let Some(rw) = SETTINGS_CACHE.get() else {
        return;
    };
    if let Ok(mut cache) = rw.write() {
        cache.epoch = epoch;
    }
}

/// Uncached fallback: both flags from one blocking DB read. Defaults on
/// any failure — api keys enabled, compliance off — exactly the legacy
/// per-read fallbacks.
async fn direct_settings_flags(db: &Db) -> SettingsFlags {
    let db = db.clone();
    tokio::task::spawn_blocking(move || load_settings_flags_from_db(&db))
        .await
        .unwrap_or(SettingsFlags {
            api_keys_enabled: true,
            compliance_mode_enabled: false,
        })
}

/// Point-read the DB epoch off the hot path. `None` on any error: a
/// failing freshness check must never fail auth, and serving the cache
/// beats churning reloads while the backend is unhealthy. The failure is
/// logged so a stuck epoch check (peers stop seeing each other's
/// toggles) stays diagnosable.
async fn current_settings_epoch(db: &Db) -> Option<i64> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || match crate::db::settings_epoch(&db) {
        Ok(epoch) => Some(epoch),
        Err(e) => {
            tracing::warn!(error = %e, "settings epoch read failed; serving cached auth flags");
            None
        }
    })
    .await
    .unwrap_or_default()
}

/// Read one cached flag with epoch validation (persea#289). Single
/// instance: pure cache, zero DB reads. HA: one primary-key point read
/// per request; on a mismatch the flags and epoch reload once.
async fn cached_flag(db: &Db, pick: fn(&SettingsFlags) -> bool) -> bool {
    let Some(rw) = SETTINGS_CACHE.get() else {
        return pick(&direct_settings_flags(db).await);
    };
    let cached_epoch = {
        let Ok(cache) = rw.read() else {
            // Poisoned lock: fall back to the uncached read.
            return pick(&direct_settings_flags(db).await);
        };
        if !settings_epoch_check_enabled() {
            // Single-instance: only this process writes, and the PUT
            // handler updates this cache directly — always fresh, no DB.
            return pick(&cache.flags);
        }
        cache.epoch
    }; // read guard dropped before any await or DB access

    // HA mode: bounded freshness check — one indexed point read.
    let Some(db_epoch) = current_settings_epoch(db).await else {
        // Backend unreadable: serve the cache rather than fail auth or
        // hammer a sick database with reloads.
        if let Ok(cache) = rw.read() {
            return pick(&cache.flags);
        }
        return pick(&direct_settings_flags(db).await);
    };
    if db_epoch == cached_epoch {
        if let Ok(cache) = rw.read() {
            if cache.epoch == db_epoch {
                return pick(&cache.flags);
            }
        }
        // The entry changed between the two reads (concurrent reload);
        // fall through and reload — the CAS below keeps it cheap.
    }

    // Epoch mismatch (a peer committed a toggle) or a lost race: reload
    // flags + epoch once, outside the lock.
    let fresh_db = db.clone();
    let fresh = match tokio::task::spawn_blocking(move || CachedSettings {
        epoch: crate::db::settings_epoch(&fresh_db).unwrap_or(0),
        flags: load_settings_flags_from_db(&fresh_db),
    })
    .await
    {
        Ok(fresh) => fresh,
        Err(_) => return pick(&direct_settings_flags(db).await),
    };
    let Ok(mut cache) = rw.write() else {
        return pick(&fresh.flags);
    };
    // Monotonic install: never move the entry backwards. An equal epoch
    // means another request already installed this state.
    if fresh.epoch > cache.epoch {
        *cache = fresh;
    }
    pick(&cache.flags)
}

/// Read the cached `enable_api_keys` flag. Falls back to a direct DB
/// read when the cache has not been initialized.
pub async fn cached_api_keys_enabled(db: &Db) -> bool {
    cached_flag(db, |f| f.api_keys_enabled).await
}

/// Read the cached `compliance_mode` flag. Falls back to a direct DB
/// read when the cache has not been initialized.
pub async fn cached_compliance_mode_enabled(db: &Db) -> bool {
    cached_flag(db, |f| f.compliance_mode_enabled).await
}

/// Single-use WebSocket ticket. Created via POST /api/ws-ticket, consumed on
/// WebSocket connect. Prevents API keys from appearing in WebSocket URLs.
struct WsTicket {
    identity: AuthIdentity,
    created: Instant,
}

/// Thread-safe store of pending WebSocket tickets.
///
/// When a shared backend pool is active, every ticket is also persisted
/// (SHA-256 hash only) to the `ws_tickets` table so any instance can
/// validate a ticket issued by another. The in-memory map remains the fast
/// path; a miss falls through to the DB. Without a pool the store is purely
/// in-memory — the legacy single-instance behavior, unchanged.
#[derive(Clone)]
pub struct WsTicketStore {
    inner: Arc<Mutex<HashMap<String, WsTicket>>>,
    db: Option<Db>,
}

const WS_TICKET_TTL_SECS: u64 = 30;

/// Whether a validated admin API key may authenticate. False in compliance
/// mode: the admin-key surface is the direct API access the mode closes
/// (persea#228).
fn admin_api_key_allowed(compliance_mode: bool) -> bool {
    !compliance_mode
}

/// Whether a validated user token may authenticate. Scoped tokens (minted
/// by the interactive desktop login/pairing flow) always pass; regular
/// self-service tokens are part of the direct API surface compliance mode
/// closes (persea#228).
fn user_token_allowed(compliance_mode: bool, token_type: &str) -> bool {
    !compliance_mode || token_type == "scoped"
}

/// Marker extension: the request's identity was derived from a consumed
/// WebSocket ticket (not a cookie/API key). Lets the WS handler trust the
/// ticket as the anti-CSWSh credential and skip the Origin/Host match for
/// cross-instance redirects — tickets are minted only by
/// authenticated callers, are single-use, and expire in 30s.
#[derive(Clone)]
pub struct TicketAuthenticated;

/// Whether ticket persistence is active right now (shared pool present).
fn ws_ticket_persist_enabled() -> bool {
    crate::db::active_pool().is_some()
}

fn ticket_hash(ticket: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(ticket.as_bytes()))
}

impl WsTicketStore {
    /// Create a purely in-memory ticket store (legacy single-instance mode).
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            db: None,
        }
    }

    /// Create a store that persists tickets to the shared backend when a
    /// pool is present (see `ws_ticket_persist_enabled`).
    pub fn new_with_db(db: Option<Db>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            db,
        }
    }

    /// Create a ticket for the given identity. Returns the ticket string.
    pub async fn create(&self, identity: AuthIdentity) -> String {
        let ticket = format!("wst_{}", uuid::Uuid::new_v4().as_simple());
        let issued_by = identity.display_name().to_string();
        let identity_json = serde_json::to_string(&identity).ok();
        {
            let mut store = self.inner.lock().await;

            // Prune expired tickets while we have the lock
            let cutoff = Instant::now() - std::time::Duration::from_secs(WS_TICKET_TTL_SECS);
            store.retain(|_, t| t.created > cutoff);

            store.insert(
                ticket.clone(),
                WsTicket {
                    identity,
                    created: Instant::now(),
                },
            );
        }

        // Persist for cross-instance validation (best effort — a failed
        // write degrades to the local-only store, never blocks the ticket).
        if ws_ticket_persist_enabled() {
            if let (Some(ref db), Some(identity_json)) = (self.db.clone(), identity_json) {
                let db = db.clone();
                let hash = ticket_hash(&ticket);
                let expires_at = crate::db::registry_ts(
                    chrono::Utc::now() + chrono::Duration::seconds(WS_TICKET_TTL_SECS as i64),
                );
                let _ = tokio::task::spawn_blocking(move || {
                    crate::db::ws_ticket_insert(
                        &db,
                        &hash,
                        &identity_json,
                        None,
                        &issued_by,
                        &expires_at,
                    )
                })
                .await;
            }
        }
        ticket
    }

    /// Consume a ticket, returning the identity if valid and not expired.
    /// Single-use: the ticket is removed on consumption — from the local
    /// map (fast path) and, for HA, from the shared backend so a ticket
    /// consumed on one instance cannot be replayed on another.
    pub async fn consume(&self, ticket: &str) -> Option<AuthIdentity> {
        let identity = {
            let mut store = self.inner.lock().await;
            match store.remove(ticket) {
                Some(entry) if entry.created.elapsed().as_secs() <= WS_TICKET_TTL_SECS => {
                    Some(entry.identity)
                }
                // Missing (issued by another instance) or expired: fall
                // through to the shared backend below.
                _ => None,
            }
        };
        if identity.is_some() {
            // Also delete the persisted copy (if any) so the ticket is
            // single-use across the fleet.
            if ws_ticket_persist_enabled() {
                if let Some(ref db) = self.db {
                    let db = db.clone();
                    let hash = ticket_hash(ticket);
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::db::ws_ticket_delete(&db, &hash)
                    })
                    .await;
                }
            }
            return identity;
        }

        // Local miss: fall through to the shared backend — this is how a
        // ticket issued by another instance validates here.
        if ws_ticket_persist_enabled() {
            if let Some(ref db) = self.db {
                let db = db.clone();
                let hash = ticket_hash(ticket);
                let row = tokio::task::spawn_blocking({
                    let db = db.clone();
                    let hash = hash.clone();
                    move || crate::db::ws_ticket_get(&db, &hash)
                })
                .await
                .ok()
                .and_then(|r| r.ok());
                if let Some(Some((identity_json, expires_at))) = row {
                    // Single-use: consume the persisted row.
                    let db2 = db.clone();
                    let hash2 = hash.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::db::ws_ticket_delete(&db2, &hash2)
                    })
                    .await;
                    let expires =
                        chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%d %H:%M:%S")
                            .map(|ndt| ndt.and_utc())
                            .unwrap_or(chrono::Utc::now() - chrono::Duration::seconds(1));
                    if expires > chrono::Utc::now() {
                        return serde_json::from_str(&identity_json).ok();
                    }
                }
            }
        }
        None
    }

    /// Re-issue a ticket for a forwarded cross-instance connection:
    /// the raw ticket was already consumed by this instance's auth
    /// middleware, so before redirecting the browser to the owning instance
    /// a fresh persisted ticket is minted for the same identity. Returns
    /// the new ticket string.
    pub async fn forward(&self, identity: AuthIdentity) -> String {
        self.create(identity).await
    }
}

impl Default for WsTicketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared extension carrying the trusted proxy CIDRs from config.
#[derive(Clone)]
pub struct TrustedProxies(pub Vec<String>);

/// Identity of the authenticated caller.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum AuthIdentity {
    /// API key admin — always full admin access.
    ApiKey(String),
    /// OIDC user with email, display name, role, and group memberships.
    User {
        /// Email address, used as the canonical identifier.
        email: String,
        /// Display name; falls back to the email when empty.
        name: String,
        /// Effective role name (admin, poweruser, operator, viewer).
        role: String,
        /// OIDC group memberships.
        groups: Vec<String>,
    },
}

impl AuthIdentity {
    /// Human-readable name: display name when set, email otherwise,
    /// or the API key name.
    pub fn display_name(&self) -> &str {
        match self {
            AuthIdentity::ApiKey(name) => name,
            AuthIdentity::User { email, name, .. } => {
                if name.is_empty() {
                    email
                } else {
                    name
                }
            }
        }
    }

    /// Effective role name; API key identities always resolve to admin.
    pub fn role(&self) -> &str {
        match self {
            AuthIdentity::ApiKey(_) => "admin",
            AuthIdentity::User { role, .. } => role,
        }
    }

    /// Return OIDC group memberships. Empty for API key identities.
    pub fn groups(&self) -> &[String] {
        match self {
            AuthIdentity::ApiKey(_) => &[],
            AuthIdentity::User { groups, .. } => groups,
        }
    }

    /// Check if identity has at least the given role level.
    /// admin > poweruser > operator > viewer
    pub fn has_role(&self, min_role: &str) -> bool {
        role_level(self.role()) >= role_level(min_role)
    }
}

// Re-export role utilities from the shared module.
pub use crate::role::{is_valid_role, role_level};

/// Guard helper: extract an authenticated identity from the optional
/// extension that auth middleware inserts, and require it to hold at
/// least `role`. Returns the inner `&AuthIdentity` so callers can keep
/// using `display_name()` / `has_role()` / `groups()` on the same
/// binding without an extra deref.
///
/// This is the single source of truth for the admin/poweruser cascade
/// that used to be pasted across every restricted handler. Migrating
/// a handler means replacing the `let id = identity.as_ref()...
/// .ok_or(...)?` + `if !id.has_role(...)` pair with one call.
///
/// Error contract:
/// - Missing identity → `AppError::Forbidden("authentication required")`
/// - Identity present but role too low → `AppError::Forbidden("<role> role required")`
/// - HTTP status is 403 in both cases (matches `AppError::Forbidden`'s
///   existing mapping in `src/error.rs`); existing tests assert the
///   exact strings, so do not reword them here without updating them.
pub fn require_role<'a>(
    identity: &'a Option<Extension<AuthIdentity>>,
    role: &str,
) -> Result<&'a AuthIdentity, crate::error::AppError> {
    match identity {
        Some(Extension(id)) if id.has_role(role) => Ok(id),
        Some(_) => Err(crate::error::AppError::Forbidden(format!(
            "{role} role required"
        ))),
        None => Err(crate::error::AppError::Forbidden(
            "authentication required".into(),
        )),
    }
}

/// Compute the effective role for a user API token.
/// Returns the lower of the user's current role and the token's max_role cap.
pub fn compute_effective_role(user_role: &str, max_role: &Option<String>) -> String {
    match max_role {
        Some(max) if role_level(max) < role_level(user_role) => max.clone(),
        _ => user_role.to_string(),
    }
}

/// Extract the real client IP, honouring X-Forwarded-For when the socket
/// address belongs to a trusted proxy CIDR.
pub fn client_ip(headers: &HeaderMap, socket_addr: IpAddr, trusted_proxies: &[String]) -> IpAddr {
    if !trusted_proxies.is_empty() {
        let networks: Vec<IpNetwork> = trusted_proxies
            .iter()
            .filter_map(|s| s.parse::<IpNetwork>().ok())
            .collect();

        if networks.iter().any(|net| net.contains(socket_addr)) {
            if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
                // First IP in X-Forwarded-For is the original client
                if let Some(first) = xff.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }
    }
    socket_addr
}

/// Extract a cookie value from a HeaderMap.
///
/// Combines ALL `cookie` headers (HTTP/1.1 permits multiple Cookie headers;
/// some clients and proxies split cookies across them) before parsing, so a
/// cookie split across headers is still found.
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let combined: String = headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.is_empty() {
        return None;
    }
    combined.split(';').find_map(|c| {
        let c = c.trim();
        if let Some(val) = c.strip_prefix(name) {
            val.strip_prefix('=').map(|v| v.to_string())
        } else {
            None
        }
    })
}

/// Axum middleware that validates either API key or session cookie.
/// On success, inserts `AuthIdentity` into request extensions.
pub async fn require_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let db = request.extensions().get::<Db>().cloned();
    let db = match db {
        Some(db) => db,
        None => {
            return next.run(request).await;
        }
    };

    let trusted = request.extensions().get::<TrustedProxies>().cloned();
    let proxies = trusted.map(|t| t.0).unwrap_or_default();
    let ip = client_ip(request.headers(), addr.ip(), &proxies);
    let path = request.uri().path().to_string();

    // Path 1: API key from Authorization: Bearer <key> or X-API-Key: <key>
    let api_key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        })
        .map(|k| k.to_string());

    if let Some(key) = api_key {
        // The admin can lock down API-key auth entirely. Reject
        // outright when disabled — a request presenting only an API key has
        // no other way to authenticate (admin keys and user tokens alike).
        if !cached_api_keys_enabled(&db).await {
            tracing::warn!(client_ip = %ip, "API key authentication rejected: enable_api_keys is disabled by an administrator");
            return crate::error::AppError::error_response(
                StatusCode::FORBIDDEN,
                "API key authentication is disabled by an administrator",
            );
        }

        // Compliance mode (persea#228): a per-instance setting that closes
        // the direct API surface. Admin API keys and self-service user
        // tokens stop authenticating; interactive sessions and scoped
        // tokens (minted by the desktop login/pairing flow) keep working.
        let compliance = cached_compliance_mode_enabled(&db).await;

        let validate_ip = Some(ip);
        let db_clone = db.clone();
        let key_clone = key.clone();
        let result = tokio::task::spawn_blocking(move || {
            db::validate_api_key(&db_clone, &key_clone, validate_ip)
        })
        .await
        .unwrap_or(Err(AuthError::InvalidKey));

        match result {
            Ok(admin) => {
                if !admin_api_key_allowed(compliance) {
                    tracing::warn!(
                        client_ip = %ip,
                        "API key rejected: compliance mode disables direct API access"
                    );
                    return crate::error::AppError::error_response(
                        StatusCode::FORBIDDEN,
                        "API key authentication is disabled in compliance mode",
                    );
                }
                tracing::debug!(admin = %admin.name, "API key authenticated");
                let mut request = request;
                request
                    .extensions_mut()
                    .insert(AuthIdentity::ApiKey(admin.name));
                return next.run(request).await;
            }
            Err(AuthError::InvalidKey) => {
                // Not found in admins table — try user API tokens
                let db_clone = db.clone();
                let token_result =
                    tokio::task::spawn_blocking(move || db::validate_user_token(&db_clone, &key))
                        .await
                        .unwrap_or(Err(AuthError::InvalidKey));

                match token_result {
                    Ok((user, token_meta)) => {
                        if !user_token_allowed(compliance, &token_meta.token_type) {
                            tracing::warn!(
                                client_ip = %ip,
                                token = %token_meta.name,
                                "User token rejected: compliance mode disables direct API tokens"
                            );
                            return crate::error::AppError::error_response(
                                StatusCode::FORBIDDEN,
                                "user token authentication is disabled in compliance mode; sign in interactively or use a scoped desktop token",
                            );
                        }
                        let effective_role =
                            compute_effective_role(&user.role, &token_meta.max_role);
                        tracing::debug!(email = %user.email, role = %effective_role, token = %token_meta.name, "User token authenticated");
                        let groups = user.groups_vec();
                        let mut request = request;
                        request.extensions_mut().insert(AuthIdentity::User {
                            email: user.email,
                            name: user.name,
                            role: effective_role,
                            groups,
                        });
                        return next.run(request).await;
                    }
                    Err(_) => {
                        tracing::warn!(client_ip = %ip, "Authentication failed: invalid API key/token");
                        return crate::error::AppError::error_response(
                            StatusCode::UNAUTHORIZED,
                            "invalid API key or token",
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(client_ip = %ip, reason = %e, "Authentication failed");
                return crate::error::AppError::error_response(
                    StatusCode::FORBIDDEN,
                    e.to_string(),
                );
            }
        }
    }

    // Path 2: Session cookie
    let session_token = extract_cookie(request.headers(), "persea_session");
    if let Some(token) = session_token {
        let db_clone = db.clone();
        let result =
            tokio::task::spawn_blocking(move || db::validate_auth_session(&db_clone, &token))
                .await
                .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(user) => {
                tracing::debug!(email = %user.email, role = %user.role, "Session cookie authenticated");
                let groups = user.groups_vec();
                let mut request = request;
                request.extensions_mut().insert(AuthIdentity::User {
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    groups,
                });
                next.run(request).await
            }
            Err(_) => {
                tracing::warn!(client_ip = %ip, "Authentication failed: invalid session cookie");
                crate::error::AppError::error_response(
                    StatusCode::UNAUTHORIZED,
                    "invalid or expired session",
                )
            }
        };
    }

    // Neither API key nor cookie
    tracing::warn!(client_ip = %ip, path = %path, "Authentication failed: no credentials");

    // A browser navigating to a protected page with no session should land
    // on the login screen, not a standalone "Unauthorized" error page —
    // API/AJAX callers (which send a non-HTML Accept header, or hit /api/*)
    // still get the JSON 401 so their own error handling can react to it.
    let wants_html = !path.starts_with("/api/")
        && request
            .headers()
            .get(axum::http::header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("text/html"))
            .unwrap_or(false);
    if wants_html {
        return Redirect::to("/?error=login_required").into_response();
    }

    crate::error::AppError::error_response(
        StatusCode::UNAUTHORIZED,
        "authentication required — use API key or sign in via SSO",
    )
}

/// Optional auth middleware — identical to `require_auth` but passes through
/// silently when no credentials are present (no 401). Inserts `AuthIdentity`
/// into extensions on success.
/// Also checks for `key` query parameter as a fallback for API-key auth
/// (used by WebSocket connections from API-key users).
pub async fn optional_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let db = request.extensions().get::<Db>().cloned();
    let db = match db {
        Some(db) => db,
        None => {
            return next.run(request).await;
        }
    };

    let trusted = request.extensions().get::<TrustedProxies>().cloned();
    let proxies = trusted.map(|t| t.0).unwrap_or_default();
    let ip = client_ip(request.headers(), addr.ip(), &proxies);

    // Path 1: API key from Authorization: Bearer <key> or X-API-Key: <key>.
    // Mirrors require_auth's Path 1 (admin key, then user token), except a
    // bad/missing key here just falls through unauthenticated instead of
    // hard-failing — this middleware is "optional", not "required".
    let api_key = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            request
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
        })
        .map(|k| k.to_string());

    if let Some(key) = api_key {
        // When the admin locked down API-key auth, an API key is
        // ignored here — optional auth passes through silently so a cookie
        // or ticket on the same request can still authenticate it.
        if !cached_api_keys_enabled(&db).await {
            tracing::debug!(client_ip = %ip, "Optional auth: API key ignored — enable_api_keys is disabled by an administrator");
        } else {
            // Compliance mode (persea#228): a valid admin key or
            // self-service user token is ignored here too, mirroring the
            // enable_api_keys lockdown — the request keeps whatever cookie
            // or ticket it also carries.
            let compliance = cached_compliance_mode_enabled(&db).await;
            let db_clone = db.clone();
            let key_clone = key.clone();
            let result = tokio::task::spawn_blocking(move || {
                db::validate_api_key(&db_clone, &key_clone, Some(ip))
            })
            .await
            .unwrap_or(Err(AuthError::InvalidKey));

            match result {
                Ok(admin) => {
                    if !admin_api_key_allowed(compliance) {
                        tracing::debug!(
                            client_ip = %ip,
                            "Optional auth: admin API key ignored — compliance mode disables direct API access"
                        );
                    } else {
                        tracing::debug!(
                            admin = %admin.name,
                            "Optional auth: API key authenticated"
                        );
                        let mut request = request;
                        request
                            .extensions_mut()
                            .insert(AuthIdentity::ApiKey(admin.name));
                        return next.run(request).await;
                    }
                }
                Err(_) => {
                    // Not an admin key — try user API tokens before giving up.
                    let db_clone = db.clone();
                    let token_result = tokio::task::spawn_blocking(move || {
                        db::validate_user_token(&db_clone, &key)
                    })
                    .await
                    .unwrap_or(Err(AuthError::InvalidKey));

                    if let Ok((user, token_meta)) = token_result {
                        if !user_token_allowed(compliance, &token_meta.token_type) {
                            tracing::debug!(
                                client_ip = %ip,
                                token = %token_meta.name,
                                "Optional auth: user token ignored — compliance mode disables direct API tokens"
                            );
                        } else {
                            let effective_role =
                                compute_effective_role(&user.role, &token_meta.max_role);
                            tracing::debug!(
                                email = %user.email,
                                role = %effective_role,
                                token = %token_meta.name,
                                "Optional auth: user token authenticated"
                            );
                            let groups = user.groups_vec();
                            let mut request = request;
                            request.extensions_mut().insert(AuthIdentity::User {
                                email: user.email,
                                name: user.name,
                                role: effective_role,
                                groups,
                            });
                            return next.run(request).await;
                        }
                    } else {
                        tracing::warn!(
                            client_ip = %ip,
                            "Optional auth: invalid API key/token, continuing unauthenticated"
                        );
                    }
                    // Fall through to the other auth paths below rather than
                    // returning — a bad key shouldn't block a cookie/ticket
                    // that might still be present.
                }
            }
        }
    }

    // Path 1b: Single-use WebSocket ticket from ?ticket= query parameter.
    // Tickets are created via POST /api/ws-ticket and consumed here.
    // This prevents API keys from appearing in WebSocket URLs.
    if let Some(ticket_store) = request.extensions().get::<WsTicketStore>().cloned() {
        let ticket_val = request.uri().query().and_then(|q| {
            q.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "ticket" {
                    Some(v.split('?').next().unwrap_or(v).to_string())
                } else {
                    None
                }
            })
        });
        if let Some(ticket) = ticket_val {
            if let Some(identity) = ticket_store.consume(&ticket).await {
                tracing::debug!("Optional auth: WebSocket ticket consumed");
                let mut request = request;
                request.extensions_mut().insert(identity);
                // The ticket is the anti-CSWSh credential for this
                // request — the WS handler may skip the Origin/Host match
                // (needed for cross-instance join redirects).
                request.extensions_mut().insert(TicketAuthenticated);
                return next.run(request).await;
            }
            // Invalid/expired ticket — fall through to other auth methods
        }
    }

    // Path 2: Session cookie
    let session_token = extract_cookie(request.headers(), "persea_session");
    if let Some(token) = session_token {
        let db_clone = db.clone();
        let result =
            tokio::task::spawn_blocking(move || db::validate_auth_session(&db_clone, &token))
                .await
                .unwrap_or(Err(AuthError::InvalidSession));

        return match result {
            Ok(user) => {
                tracing::debug!(email = %user.email, role = %user.role, "Optional auth: session cookie authenticated");
                let groups = user.groups_vec();
                let mut request = request;
                request.extensions_mut().insert(AuthIdentity::User {
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    groups,
                });
                next.run(request).await
            }
            Err(_) => {
                tracing::warn!(client_ip = %ip, "Authentication failed: invalid session cookie (optional auth)");
                next.run(request).await
            }
        };
    }

    // No credentials — pass through without identity
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_level_hierarchy() {
        assert_eq!(role_level("admin"), 4);
        assert_eq!(role_level("poweruser"), 3);
        assert_eq!(role_level("operator"), 2);
        assert_eq!(role_level("viewer"), 1);
        assert_eq!(role_level("unknown"), 0);
        assert_eq!(role_level(""), 0);
    }

    #[test]
    fn test_role_level_ordering() {
        assert!(role_level("admin") > role_level("poweruser"));
        assert!(role_level("poweruser") > role_level("operator"));
        assert!(role_level("operator") > role_level("viewer"));
        assert!(role_level("viewer") > role_level("garbage"));
    }

    #[test]
    fn test_compute_effective_role_no_cap() {
        assert_eq!(compute_effective_role("admin", &None), "admin");
        assert_eq!(compute_effective_role("viewer", &None), "viewer");
    }

    #[test]
    fn test_compute_effective_role_capped() {
        let cap = Some("operator".into());
        assert_eq!(compute_effective_role("admin", &cap), "operator");
        assert_eq!(compute_effective_role("poweruser", &cap), "operator");
    }

    #[test]
    fn test_compute_effective_role_cap_higher_than_user() {
        let cap = Some("admin".into());
        assert_eq!(compute_effective_role("viewer", &cap), "viewer");
        assert_eq!(compute_effective_role("operator", &cap), "operator");
    }

    #[test]
    fn test_compute_effective_role_same_level() {
        let cap = Some("operator".into());
        assert_eq!(compute_effective_role("operator", &cap), "operator");
    }

    #[test]
    fn test_client_ip_no_proxies() {
        let headers = HeaderMap::new();
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &[]);
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_client_ip_xff_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50, 10.0.0.1".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "203.0.113.50");
    }

    #[test]
    fn test_client_ip_xff_untrusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "203.0.113.50".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        // Socket is NOT in trusted range
        let ip = client_ip(&headers, "192.168.1.1".parse().unwrap(), &proxies);
        assert_eq!(ip.to_string(), "192.168.1.1");
    }

    #[test]
    fn test_client_ip_xff_invalid_ip() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "not-an-ip".parse().unwrap());
        let proxies = vec!["10.0.0.0/8".into()];
        let ip = client_ip(&headers, "10.0.0.1".parse().unwrap(), &proxies);
        // Falls back to socket addr when XFF can't be parsed
        assert_eq!(ip.to_string(), "10.0.0.1");
    }

    #[test]
    fn test_has_role() {
        let admin = AuthIdentity::ApiKey("admin".into());
        assert!(admin.has_role("viewer"));
        assert!(admin.has_role("admin"));

        let viewer = AuthIdentity::User {
            email: "test@test.com".into(),
            name: "Test User".into(),
            role: "viewer".into(),
            groups: vec![],
        };
        assert!(viewer.has_role("viewer"));
        assert!(!viewer.has_role("operator"));
        assert!(!viewer.has_role("admin"));
    }

    #[tokio::test]
    async fn api_key_gate_defaults_enabled_and_reads_db() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        // Unset toggle → enabled (existing deployments unaffected).
        assert!(direct_settings_flags(&db).await.api_keys_enabled);

        // Stored "false" → API keys rejected. The first read created the
        // system_settings table via load_db_settings.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES ('enable_api_keys', 'false')",
                [],
            )
            .unwrap();
        }
        assert!(!direct_settings_flags(&db).await.api_keys_enabled);

        // Flipped back to "true" → accepted again.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE system_settings SET value = 'true' WHERE key = 'enable_api_keys'",
                [],
            )
            .unwrap();
        }
        assert!(direct_settings_flags(&db).await.api_keys_enabled);
    }

    #[tokio::test]
    async fn compliance_mode_defaults_off_and_reads_db() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        // Unset toggle → off (existing deployments unaffected). The first
        // read created the system_settings table via load_db_settings.
        assert!(!direct_settings_flags(&db).await.compliance_mode_enabled);

        // Stored "true" → compliance mode on.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES ('compliance_mode', 'true')",
                [],
            )
            .unwrap();
        }
        assert!(direct_settings_flags(&db).await.compliance_mode_enabled);

        // Flipped back to "false" → off again.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE system_settings SET value = 'false' WHERE key = 'compliance_mode'",
                [],
            )
            .unwrap();
        }
        assert!(!direct_settings_flags(&db).await.compliance_mode_enabled);
    }

    #[test]
    fn compliance_gate_rejects_admin_api_keys() {
        // Off: admin API keys authenticate exactly as today.
        assert!(admin_api_key_allowed(false));
        // On: the admin-key surface is the direct API access the mode closes.
        assert!(!admin_api_key_allowed(true));
    }

    #[test]
    fn compliance_gate_keeps_scoped_tokens_and_sessions() {
        // Off: every token authenticates.
        assert!(user_token_allowed(false, "user"));
        assert!(user_token_allowed(false, "scoped"));
        // On: scoped tokens (minted by the interactive desktop login or
        // device pairing) pass; self-service tokens are part of the closed
        // direct API surface.
        assert!(user_token_allowed(true, "scoped"));
        assert!(!user_token_allowed(true, "user"));
        // Unknown token types fail closed rather than slipping through.
        assert!(!user_token_allowed(true, ""));
        assert!(!user_token_allowed(true, "admin"));
    }
}
