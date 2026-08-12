//! Authentication middleware — supports API key, OIDC session cookie, and
//! single-use WebSocket tickets.

use crate::db::{self, AuthError, Db};
use axum::{
    extract::{ConnectInfo, Request},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Single-use WebSocket ticket. Created via POST /api/ws-ticket, consumed on
/// WebSocket connect. Prevents API keys from appearing in WebSocket URLs.
struct WsTicket {
    identity: AuthIdentity,
    created: Instant,
}

/// Thread-safe store of pending WebSocket tickets.
///
/// Enterprise HA (R110): when a shared backend pool is active AND the FEAT_HA
/// license grants it, every ticket is also persisted (SHA-256 hash only) to
/// the `ws_tickets` table so any instance can validate a ticket issued by
/// another. The in-memory map remains the fast path; a miss falls through to
/// the DB. Without the license/pool the store is purely in-memory — the
/// legacy single-instance behavior, unchanged.
#[derive(Clone)]
pub struct WsTicketStore {
    inner: Arc<Mutex<HashMap<String, WsTicket>>>,
    db: Option<Db>,
}

const WS_TICKET_TTL_SECS: u64 = 30;

/// R105: whether API-key authentication is permitted. Reads the
/// `enable_api_keys` lockdown toggle from the DB; unset or unreadable →
/// enabled, so existing deployments behave exactly as before.
async fn api_keys_enabled(db: &Db) -> bool {
    let db = db.clone();
    tokio::task::spawn_blocking(move || {
        crate::settings_merge::read_toggle(&db, "enable_api_keys", true)
    })
    .await
    .unwrap_or(true)
}

/// Marker extension: the request's identity was derived from a consumed
/// WebSocket ticket (not a cookie/API key). Lets the WS handler trust the
/// ticket as the anti-CSWSh credential and skip the Origin/Host match for
/// cross-instance redirects (R110) — tickets are minted only by
/// authenticated callers, are single-use, and expire in 30s.
#[derive(Clone)]
pub struct TicketAuthenticated;

/// Whether ticket persistence is active right now (license + shared pool).
fn ws_ticket_persist_enabled() -> bool {
    crate::db::active_pool().is_some()
        && crate::license::global().is_some_and(|lm| lm.has_feature(crate::license::FEAT_HA))
}

fn ticket_hash(ticket: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(ticket.as_bytes()))
}

impl WsTicketStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            db: None,
        }
    }

    /// Create a store that persists tickets to the shared backend when the
    /// HA license is active (see `ws_ticket_persist_enabled`).
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
            let entry = store.remove(ticket)?;
            if entry.created.elapsed().as_secs() <= WS_TICKET_TTL_SECS {
                Some(entry.identity)
            } else {
                None
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
                    let expires = chrono::NaiveDateTime::parse_from_str(
                        &expires_at,
                        "%Y-%m-%d %H:%M:%S",
                    )
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

    /// Re-issue a ticket for a forwarded cross-instance connection (R110):
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
        email: String,
        name: String,
        role: String,
        groups: Vec<String>,
    },
}

impl AuthIdentity {
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
pub(crate) fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
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
        // R105: the admin can lock down API-key auth entirely. Reject
        // outright when disabled — a request presenting only an API key has
        // no other way to authenticate (admin keys and user tokens alike).
        if !api_keys_enabled(&db).await {
            tracing::warn!(client_ip = %ip, "API key authentication rejected: enable_api_keys is disabled by an administrator");
            return crate::error::AppError::error_response(
                StatusCode::FORBIDDEN,
                "API key authentication is disabled by an administrator",
            );
        }

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
        // R105: when the admin locked down API-key auth, an API key is
        // ignored here — optional auth passes through silently so a cookie
        // or ticket on the same request can still authenticate it.
        if !api_keys_enabled(&db).await {
            tracing::debug!(client_ip = %ip, "Optional auth: API key ignored — enable_api_keys is disabled by an administrator");
        } else {
            let db_clone = db.clone();
            let key_clone = key.clone();
            let result = tokio::task::spawn_blocking(move || {
                db::validate_api_key(&db_clone, &key_clone, Some(ip))
            })
            .await
            .unwrap_or(Err(AuthError::InvalidKey));

            match result {
                Ok(admin) => {
                    tracing::debug!(admin = %admin.name, "Optional auth: API key authenticated");
                    let mut request = request;
                    request
                        .extensions_mut()
                        .insert(AuthIdentity::ApiKey(admin.name));
                    return next.run(request).await;
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
                        let effective_role =
                            compute_effective_role(&user.role, &token_meta.max_role);
                        tracing::debug!(email = %user.email, role = %effective_role, token = %token_meta.name, "Optional auth: user token authenticated");
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
                    tracing::warn!(client_ip = %ip, "Optional auth: invalid API key/token, continuing unauthenticated");
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
                // R110: the ticket is the anti-CSWSh credential for this
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
        assert!(api_keys_enabled(&db).await);

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
        assert!(!api_keys_enabled(&db).await);

        // Flipped back to "true" → accepted again.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE system_settings SET value = 'true' WHERE key = 'enable_api_keys'",
                [],
            )
            .unwrap();
        }
        assert!(api_keys_enabled(&db).await);
    }
}
