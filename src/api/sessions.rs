//! Session lifecycle endpoints.
//!
//! Create, list, inspect, and terminate sessions, upload and fetch
//! thumbnails, mint shadow tokens, and list VDI containers and login
//! scripts. Ownership rules apply: non-admins only see and control their
//! own sessions.
use super::AppState;
use crate::audit;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::rbac;
use crate::session::{CreateSessionRequest, SessionStatus};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, OnceLock};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

/// Query parameters for `GET /api/sessions`.
#[derive(Deserialize, Default)]
pub struct ListSessionsQuery {
    /// Include every user's sessions; only honored for admins.
    #[serde(default)]
    pub all: bool,
    /// Optional limit on the number of sessions returned (most recent first).
    pub limit: Option<usize>,
}

/// Query parameters for `GET /api/sessions/{id}/banner`.
#[derive(Deserialize)]
pub struct BannerQuery {
    /// Share token proving access to the session.
    pub token: String,
}

/// `POST /api/sessions`: start an ad-hoc session from the request
/// body. Requires poweruser or higher (or a custom role with the
/// `create_session` system permission). Returns the new session info,
/// or `AppError::Forbidden` when the role gate fails and
/// `AppError::Session` when guacd rejects the connection.
pub async fn create_session(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<CreateSessionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let identity = identity.map(|Extension(id)| id);
    let admin_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_else(|| "unknown".into());

    // Fail closed: every authenticated caller (cookie session, user token,
    // admin key) must clear the role gate. `require_auth` blocks anonymous
    // requests at the router, but the gate must not silently pass when the
    // identity is absent (T09 audit).
    let Some(ref id) = identity else {
        return Err(AppError::Forbidden(
            "authentication required to create a session".into(),
        ));
    };
    // Sessions are keyed on the stable identity (email / API-key name),
    // not the display name: display names are non-unique and
    // user-controllable, so ownership and the per-user session quota
    // must not depend on them.
    let creator_identity = identity_key(id).to_string();
    if !id.has_role("poweruser") {
        // Custom role holders with the global `create_session` system
        // permission may start ad-hoc sessions from any role floor.
        let allowed = manager
            .db()
            .map(|db| {
                rbac::identity_has_system_permission(db, id, rbac::SystemPermission::CreateSession)
            })
            .unwrap_or(false);
        if !allowed {
            return Err(AppError::Forbidden(
                "insufficient permissions — poweruser role required for ad-hoc sessions".into(),
            ));
        }
    }

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);

    // V09: connection reason policy. `[session] reason_required = true`
    // rejects creation without a reason (400 with a clear message); the
    // reason itself is length-capped to keep the history column tidy.
    let reason = req
        .reason
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty());
    if manager.config().session_reason_required() && reason.is_none() {
        return Err(AppError::Validation(
            "a connection reason is required — pick one from the list or type a description".into(),
        ));
    }
    if reason.is_some_and(|r| r.chars().count() > 500) {
        return Err(AppError::Validation(
            "connection reason must be 500 characters or fewer".into(),
        ));
    }

    let target = match req.session_type {
        crate::session::SessionType::Ssh => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(22)
            )
        }
        crate::session::SessionType::Rdp => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(3389)
            )
        }
        crate::session::SessionType::Vnc => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(5900)
            )
        }
        crate::session::SessionType::Spice => {
            format!(
                "{}:{}",
                req.hostname.as_deref().unwrap_or("?"),
                req.port.unwrap_or(5900)
            )
        }
        crate::session::SessionType::Proxmox => {
            format!(
                "{}/{}",
                req.proxmox
                    .as_ref()
                    .and_then(|p| p.proxmox_node.as_deref())
                    .unwrap_or("?"),
                req.proxmox
                    .as_ref()
                    .and_then(|p| p.proxmox_vmid)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        }
        crate::session::SessionType::Web => req
            .web
            .as_ref()
            .and_then(|w| w.url.as_deref())
            .unwrap_or("?")
            .to_string(),
        crate::session::SessionType::Vdi => req
            .vdi
            .as_ref()
            .and_then(|v| v.container_image.as_deref())
            .unwrap_or("?")
            .to_string(),
    };

    tracing::info!(
        admin = %admin_name,
        client_ip = %client_ip,
        session_type = ?req.session_type,
        target = %target,
        "Session creation requested"
    );

    match manager
        .create_session(req, creator_identity.clone(), Some(client_ip.to_string()))
        .await
    {
        Ok(info) => {
            tracing::info!(
                admin = %admin_name,
                client_ip = %client_ip,
                session_id = %info.session_id,
                session_type = ?info.session_type,
                target = %target,
                "Session created successfully"
            );
            // Audit: session start
            if let Some(db_audit) = manager.db().cloned() {
                let sid = info.session_id.to_string();
                let ip = client_ip.to_string();
                let user_id = admin_name.clone();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("session.start", "success")
                            .user_id(&user_id)
                            .source_ip(&ip)
                            .session_id(&sid)
                            .build(),
                    );
                })
                .await
                {
                    tracing::error!(error = %e, "audit task failed");
                }
            }
            Ok(Json(json!(info)))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(
                admin = %admin_name,
                client_ip = %client_ip,
                target = %target,
                error = %msg,
                "Session creation failed"
            );
            Err(AppError::Session(msg))
        }
    }
}

/// Stable identity key used for session ownership and quota checks: the
/// email for user identities, the key name for API keys. Display names
/// are non-unique and user-controllable, so they must never key
/// ownership.
fn identity_key(id: &AuthIdentity) -> &str {
    match id {
        AuthIdentity::ApiKey(name) => name,
        AuthIdentity::User { email, .. } => email,
    }
}

/// Whether `creator` (a session's stored `created_by`) belongs to this
/// identity. The stable identity (email / API-key name) is matched
/// first; the display-name leg covers sessions whose stored creator is
/// a legacy display name (created before identity keying or via paths
/// outside this fix).
fn session_owned_by(id: &AuthIdentity, creator: &str) -> bool {
    creator == identity_key(id) || creator == id.display_name()
}

/// FNV-1a hash, the same scheme the VDI driver uses for its stable
/// per-username container-name suffixes.
fn fnv1a(value: &str) -> u64 {
    value.bytes().fold(0xcbf29ce484222325_u64, |hash, b| {
        hash.wrapping_mul(0x100000001b3) ^ u64::from(b)
    })
}

/// Container username for the current identity: the same derivation the
/// session-creation path uses (no per-entry override): the identity's
/// local part before any `@`, lowercased, non-alphanumerics mapped to
/// `_`.
fn vdi_container_username(identity: &AuthIdentity) -> String {
    identity_key(identity)
        .split('@')
        .next()
        .unwrap_or_default()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Deterministic container-name prefix for a VDI container username:
/// `persea-vdi-{user}-{hash}`, mirroring the driver's naming (dash
/// sanitization plus the FNV-1a hash of the raw username). Ownership of
/// a container name is decided by this prefix, never by display name.
fn vdi_container_prefix(container_username: &str) -> String {
    let dashed: String = container_username
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    format!(
        "persea-vdi-{}-{:08x}",
        dashed,
        fnv1a(container_username) as u32
    )
}

/// Whether a container name is owned by the caller: exact prefix match,
/// or an entry-suffixed name under it.
fn vdi_container_owned_by(name: &str, prefix: &str) -> bool {
    name == prefix || name.starts_with(&format!("{}-", prefix))
}

fn redact_share_url(
    mut info: crate::session::SessionInfo,
    identity: &Option<Extension<AuthIdentity>>,
) -> crate::session::SessionInfo {
    let is_owner_or_admin = match identity {
        Some(Extension(id)) => id.has_role("admin") || session_owned_by(id, &info.created_by),
        None => false,
    };
    if !is_owner_or_admin {
        info.share_url = None;
    }
    info
}

/// `GET /api/sessions`: list sessions, newest first. Non-admins only
/// see sessions they created, and share URLs are redacted for anyone
/// who is neither the owner nor an admin.
pub async fn list_sessions(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    axum::extract::Query(q): axum::extract::Query<ListSessionsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let identity_ref = identity.as_ref().map(|Extension(id)| id);
    let show_all = q.all && is_admin;

    let mut sessions: Vec<_> = manager
        .list_sessions()
        .await
        .into_iter()
        .filter(|s| show_all || identity_ref.is_some_and(|id| session_owned_by(id, &s.created_by)))
        .map(|s| redact_share_url(s, &identity))
        .collect();
    // Sort by creation time descending (most recent first)
    sessions.sort_by_key(|s| std::cmp::Reverse(s.created_at));
    if let Some(limit) = q.limit {
        sessions.truncate(limit);
    }
    Ok(Json(json!(sessions)))
}

/// Query parameters for `GET /api/sessions/recent`.
#[derive(Deserialize, Default)]
pub struct RecentSessionsQuery {
    /// Maximum number of rows returned (clamped to 1..=50). Default 10.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `GET /api/sessions/recent`: the current user's most recent sessions
/// from the session-history table (V10). Rows are ordered by start time
/// descending; every row carries the stored status (`active`,
/// `disconnected`, `completed`, `logged_out`, ...), the connection reason
/// (V09) when one was given, and a `client_url` for live rows.
///
/// Scoped strictly to the caller's own history: `query_session_history`
/// matches `created_by` with LIKE, so the wider page is pulled and then
/// exact-filtered here — a like-named user's rows can neither displace
/// nor leak into this list. Two LIKE passes cover both the stable
/// identity and the legacy display-name key.
pub async fn recent_connections(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(q): Query<RecentSessionsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(Extension(id)) = identity else {
        return Err(AppError::Forbidden(
            "authentication required to list recent sessions".into(),
        ));
    };
    let limit = q.limit.unwrap_or(10).clamp(1, 50) as usize;
    let user = id.display_name().to_string();
    let key = identity_key(&id).to_string();

    // Two LIKE passes: the display name (legacy rows) and the stable
    // identity (rows created under identity keying). Rows matching both
    // patterns are deduped by session_id below.
    let mut all_rows: Vec<serde_json::Value> = Vec::new();
    for who in [user.clone(), key.clone()] {
        let db_clone = database.clone();
        let who_clone = who.clone();
        let (rows, _) = tokio::task::spawn_blocking(move || {
            db::query_session_history(&db_clone, Some(&who_clone), None, None, None, None, 200, 0)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(format!("failed to query session history: {e}")))?;
        all_rows.extend(rows);
    }
    let mut seen = std::collections::HashSet::new();
    all_rows.retain(|r| seen.insert(r["session_id"].as_str().unwrap_or("").to_string()));
    // Newest first; the seeded/inserted timestamps are zero-padded
    // RFC3339-ish strings, so lexicographic order matches chronological.
    all_rows.sort_by(|a, b| {
        b["started_at"]
            .as_str()
            .unwrap_or("")
            .cmp(a["started_at"].as_str().unwrap_or(""))
    });

    let recent: Vec<serde_json::Value> = all_rows
        .into_iter()
        .filter(|r| {
            let created_by = r["created_by"].as_str();
            created_by == Some(user.as_str()) || created_by == Some(key.as_str())
        })
        .take(limit)
        .map(|mut r| {
            let sid = r["session_id"].as_str().unwrap_or("").to_string();
            r["client_url"] = serde_json::json!(format!("/client/{}", sid));
            r
        })
        .collect();

    Ok(Json(json!({ "recent": recent })))
}

/// `GET /api/sessions/{id}`: one session with its share URL redacted
/// for non-owners. Returns `AppError::Session` (404) when the session
/// does not exist or belongs to someone else.
pub async fn get_session(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    match manager.get_session(id).await {
        Some(info) => {
            let is_admin = identity
                .as_ref()
                .map(|Extension(id)| id.has_role("admin"))
                .unwrap_or(false);
            let is_owner = identity
                .as_ref()
                .map(|Extension(id)| session_owned_by(id, &info.created_by))
                .unwrap_or(false);
            if !is_admin && !is_owner {
                return Err(AppError::Session("session not found".into()));
            }
            let info = redact_share_url(info, &identity);
            let mut value = json!(info);
            // The idle reaper ends sessions idle past this global timeout
            // (0 = disabled). client.html reads it to warn the user ~60s
            // before the reaper would fire. Config value, not per-session.
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "session_idle_timeout_secs".to_string(),
                    json!(manager.config().session_idle_timeout_secs),
                );
            }
            Ok(Json(value))
        }
        None => Err(AppError::Session("session not found".into())),
    }
}

/// `DELETE /api/sessions/{id}`: terminate a session. Requires
/// operator or higher; non-admins may only delete their own sessions.
/// Sessions hosted by another instance are rejected with an explicit
/// message. Returns 204 on success, `AppError::Session` when the
/// session is not found.
pub async fn delete_session(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);

    let id_inner = identity
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Auth("authentication required".into()))?;

    if !id_inner.has_role("operator") {
        return Err(AppError::Forbidden(
            "insufficient permissions — operator role required".into(),
        ));
    }

    if !id_inner.has_role("admin") {
        if let Some(creator) = manager.get_session_creator(id).await {
            if !session_owned_by(&id_inner, &creator) {
                return Err(AppError::Forbidden(
                    "you can only delete your own sessions".into(),
                ));
            }
        }
    }

    // A session hosted by another instance cannot be terminated from
    // here — its guacd stream and reaper live on the owning instance. Fail
    // with an explicit message instead of a misleading 404.
    if let Some(info) = manager.get_session(id).await {
        if info.remote {
            return Err(AppError::Session(format!(
                "session is owned by instance {} — terminate it from that instance",
                info.owner_instance.as_deref().unwrap_or("unknown")
            )));
        }
    }

    // V10 logout semantics: a user-initiated end is a LOGOUT, distinct
    // from a normal end. Mark the session `logged_out` (a terminal status
    // that can no longer be joined or resumed), clear its reconnect data
    // (guacd stream + cancel token), and record the distinct history
    // event BEFORE the manager tears the session down. The WebSocket
    // teardown's own history write is guarded by `ended_at IS NULL`, so
    // once the logout row is closed the teardown cannot overwrite it with
    // "disconnected"/"completed".
    let mut logout_meta: Option<(chrono::DateTime<chrono::Utc>, bool)> = None;
    {
        let sessions = manager.sessions.write().await;
        if let Some(session_arc) = sessions.get(&id) {
            let mut session = session_arc.lock().await;
            if session.status != SessionStatus::LoggedOut {
                let old_status = session.status.clone();
                if old_status == SessionStatus::Active {
                    crate::metrics::session_active_dec();
                }
                session.status = SessionStatus::LoggedOut;
                session.guacd_stream = None;
                // Terminal transition: publishes `session_ended` with the
                // `logged_out` status and records ended_at.
                manager.publish_transition(&old_status, &session);
                logout_meta = Some((session.created_at, session.recording_enabled));
            }
        }
    }
    if let Some((created_at, recording)) = logout_meta {
        let duration = (chrono::Utc::now() - created_at).num_seconds().max(0) as u64;
        // Write BEFORE delete_session cancels the session: the cancel
        // fires the WebSocket teardown, whose own history write is
        // guarded by `ended_at IS NULL` — once the logout row is closed,
        // the teardown cannot overwrite it with "disconnected"/"completed".
        manager.end_session_history(id, "logged_out", duration, recording);
    }

    if manager.delete_session(id).await {
        tracing::info!(
            session_id = %id,
            identity = %id_inner.display_name(),
            client_ip = %ip,
            "Session deleted"
        );
        // Audit: session end
        if let Some(db_audit) = manager.db().cloned() {
            let sid = id.to_string();
            let user_id = identity_key(&id_inner).to_string();
            let ip_audit = ip.to_string();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let _ = audit::log_event(
                    &db_audit,
                    &mut audit::EventBuilder::new("session.end", "success")
                        .user_id(&user_id)
                        .source_ip(&ip_audit)
                        .session_id(&sid)
                        .build(),
                );
            })
            .await
            {
                tracing::error!(error = %e, "audit task failed");
            }
        }
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Session("session not found".into()))
    }
}

pub(crate) fn is_jpeg_magic(body: &[u8]) -> bool {
    body.len() >= 3 && body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF
}

/// Maximum thumbnail body size in bytes (100 KiB).
const MAX_THUMBNAIL_BODY_LEN: usize = 100_000;

/// `PUT /api/sessions/{id}/thumbnail`: store the session thumbnail
/// image. The owner or an admin may upload; the body must be a JPEG of
/// at most 100 KiB. Returns 204, or 404/400/413/500 for the matching
/// failure mode.
pub async fn put_session_thumbnail(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let Some(info) = manager.get_session(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let is_owner = identity
        .as_ref()
        .map(|Extension(id)| session_owned_by(id, &info.created_by))
        .unwrap_or(false);
    if !is_admin && !is_owner {
        return StatusCode::NOT_FOUND.into_response();
    }
    if body.len() > MAX_THUMBNAIL_BODY_LEN {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    }
    if !is_jpeg_magic(&body) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let dir = manager.thumbnails_dir();
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!("Failed to create thumbnails dir: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let path = manager.thumbnail_path(id);
    match tokio::fs::write(&path, &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::warn!(session_id = %id, "Failed to write thumbnail: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// `GET /api/sessions/{id}/thumbnail`: serve the stored thumbnail
/// JPEG. The owner or an admin may fetch; 404 when the session or the
/// image is missing.
pub async fn get_session_thumbnail(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    let Some(info) = manager.get_session(id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let is_owner = identity
        .as_ref()
        .map(|Extension(id)| session_owned_by(id, &info.created_by))
        .unwrap_or(false);
    if !is_admin && !is_owner {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = manager.thumbnail_path(id);
    match tokio::fs::read(&path).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "image/jpeg"),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `POST /api/sessions/{id}/shadow`: mint a shadow (view-only) token
/// for live session monitoring. Admin only. Returns the client URL,
/// expiry, and TTL. `AppError::Forbidden` for non-admins,
/// `AppError::Session` when the session is not found.
pub async fn shadow_session(
    State(manager): State<AppState>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id_inner = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.clone(),
        _ => {
            return Err(AppError::Forbidden("admin role required".into()));
        }
    };

    let info = manager
        .get_session(id)
        .await
        .ok_or_else(|| AppError::Session("session not found".into()))?;

    let admin_email = identity_key(&id_inner).to_string();
    // For a session hosted by another instance, the shadow token is
    // persisted on the shared registry row (the in-memory session — and its
    // token list — lives on the owning instance). Either instance can then
    // validate it; the browser is redirected to the owner for the stream.
    let (raw, expires_at) = if info.remote {
        manager
            .mint_remote_shadow_token(id, &admin_email)
            .await
            .ok_or_else(|| AppError::Session("session not found".into()))?
    } else {
        manager
            .mint_shadow_token(id, &admin_email)
            .await
            .ok_or_else(|| AppError::Session("session not found".into()))?
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies).to_string();
    let details = format!(
        "session_id={}, owner={}, expires_at={}",
        id,
        info.created_by,
        expires_at.to_rfc3339()
    );
    let db_clone = database.clone();
    let admin_for_audit = admin_email.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || {
        if let Err(e) = db::log_token_event(
            &db_clone,
            None,
            None,
            &admin_for_audit,
            "shadow_session",
            Some(&ip),
            Some(&details),
        ) {
            tracing::warn!(error = %e, "failed to write shadow audit log");
        }
    })
    .await
    {
        tracing::error!(error = %e, "audit task failed");
    }

    tracing::info!(
        admin = %admin_email,
        session_id = %id,
        owner = %info.created_by,
        "Admin minted shadow token"
    );

    let url = format!("/client/{}?token={}", id, raw);
    Ok(Json(json!({
        "url": url,
        "expires_at": expires_at.to_rfc3339(),
        "ttl_seconds": 600,
    })))
}

/// `GET /api/vdi/containers`: list VDI containers owned by the
/// current user, with thumbnails and active-session flags. Requires
/// operator or higher. Returns an empty list when the VDI driver is
/// not configured.
pub async fn list_vdi_containers(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => {
            return Err(AppError::Forbidden("operator role required".into()));
        }
    };

    let Some(vdi) = manager.vdi_driver() else {
        return Ok(Json(json!([])));
    };

    let mut containers = vdi
        .list_managed_containers_detail()
        .await
        .unwrap_or_default();

    // Containers are scoped per identity: the container username is
    // derived from the stable identity, so a display-name collision
    // cannot surface another user's desktops.
    let current_user = vdi_container_username(id);
    containers.retain(|c| c.username == current_user);

    for c in &mut containers {
        let vdi_thumb = manager.vdi_thumbnail_path(&c.container_name);
        if vdi_thumb.exists() {
            c.thumbnail_url = Some(format!(
                "/api/vdi/containers/{}/thumbnail",
                c.container_name
            ));
        }
        c.has_active_session = manager.has_active_vdi_session(&c.container_id).await;
    }

    Ok(Json(json!(containers)))
}

/// `GET /api/vdi/containers/{name}/thumbnail`: serve a container's
/// thumbnail JPEG. Only the owning user or an admin may fetch it; 404
/// for everyone else and when the image is missing. The container name
/// must be alphanumeric (plus '-' and '_'), otherwise 400.
pub async fn get_vdi_container_thumbnail(
    State(manager): State<AppState>,
    Path(name): Path<String>,
    identity: Option<Extension<AuthIdentity>>,
) -> impl IntoResponse {
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Some(Extension(id)) = identity else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Ownership is decided by the same sanitize+hash scheme the driver
    // uses for container names: the identity's container username plus
    // the FNV-1a hash of it. The old sanitized-display-name prefix let
    // `alice` claim `persea-vdi-alice-smith-…`; the hash disambiguates.
    let container_username = vdi_container_username(&id);
    let owns = !container_username.is_empty()
        && vdi_container_owned_by(&name, &vdi_container_prefix(&container_username));
    if !id.has_role("admin") && !owns {
        return StatusCode::NOT_FOUND.into_response();
    }

    let path = manager.vdi_thumbnail_path(&name);
    match tokio::fs::read(&path).await {
        Ok(data) => (
            StatusCode::OK,
            [
                (axum::http::header::CONTENT_TYPE, "image/jpeg"),
                (axum::http::header::CACHE_CONTROL, "no-cache"),
            ],
            data,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// `GET /api/sessions/login-scripts`: list available login scripts
/// (`.js`, `.sh`, `.py` files in the configured scripts directory) for
/// browser-session automation. Requires operator or higher.
pub async fn list_login_scripts(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id_inner = match identity {
        Some(Extension(ref id_inner)) => id_inner,
        None => {
            return Err(AppError::Auth("authentication required".into()));
        }
    };

    if !id_inner.has_role("operator") {
        return Err(AppError::Forbidden(
            "insufficient permissions — operator role required".into(),
        ));
    }

    let scripts_dir = std::path::Path::new(&manager.config().login_scripts_dir);
    let mut scripts: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(scripts_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if !name.starts_with('.')
                        && (name.ends_with(".js") || name.ends_with(".sh") || name.ends_with(".py"))
                        && !name.starts_with("package")
                    {
                        scripts.push(name.to_string());
                    }
                }
            }
        }
    }
    scripts.sort();
    Ok(Json(json!({ "scripts": scripts })))
}

/// `GET /api/sessions/{id}/banner`: fetch a session's banner text.
/// The caller must present the session's share token in the query
/// string; an invalid token returns `AppError::Forbidden`.
pub async fn get_session_banner(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    Query(query): axum::extract::Query<BannerQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !manager
        .validate_share_token(id, &query.token)
        .await
        .is_valid()
    {
        return Err(AppError::Forbidden("invalid share token".into()));
    }

    match manager.get_session(id).await {
        // `auto_size` rides along so share viewers honor the flag too: the
        // client skips its `size` instructions when false, so a joined
        // session is never resized against the owner's setting.
        Some(info) => Ok(Json(json!({
            "banner": info.banner,
            "auto_size": info.auto_size,
        }))),
        None => Err(AppError::Session("session not found".into())),
    }
}

// ── RDP drive file browser ──

/// Resolve a session's per-session RDP drive directory, mirroring
/// `drive::create_session_dir` exactly (`<drive_path>/<session_id>`).
/// Returns None for non-RDP sessions, sessions without drive enabled,
/// and sessions whose drive dir has gone away.
fn session_drive_dir(
    manager: &AppState,
    info: &crate::session::SessionInfo,
) -> Option<std::path::PathBuf> {
    if info.session_type != crate::session::SessionType::Rdp || !info.drive_enabled {
        return None;
    }
    let cfg = crate::drive::drive_config_or_default(&manager.config().drive);
    let dir = cfg.drive_path.join(info.session_id.to_string());
    std::fs::canonicalize(&dir).ok()
}

/// Ownership gate plus drive dir resolution for the drive file
/// endpoints: 404 when the session is unknown, 403 when the caller is
/// neither the owner nor an admin, 404 when the session has no drive.
async fn resolve_drive_session(
    manager: &AppState,
    id: Uuid,
    identity: Option<&Extension<AuthIdentity>>,
) -> Result<std::path::PathBuf, AppError> {
    // Fail closed BEFORE any session-existence check: an unauthenticated
    // caller gets 403 whether or not the session exists (no existence
    // oracle), and a non-owner gets 403 for a known session.
    if identity.is_none() {
        return Err(AppError::Forbidden(
            "you can only access the file transfer of your own sessions".into(),
        ));
    }
    let Some(info) = manager.get_session(id).await else {
        return Err(AppError::Session("session not found".into()));
    };
    let allowed = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin") || session_owned_by(id, &info.created_by))
        .unwrap_or(false);
    if !allowed {
        return Err(AppError::Forbidden(
            "you can only access the file transfer of your own sessions".into(),
        ));
    }
    session_drive_dir(manager, &info)
        .ok_or_else(|| AppError::NotFound("this session has no file-transfer drive".into()))
}

/// Basename-only validation for drive file names: no slashes, no
/// backslashes, no NUL, and no `.`/`..` (rejects traversal).
fn valid_drive_basename(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

/// `GET /api/sessions/{id}/drive-files`: list the session's RDP drive
/// directory (name, size, modified as RFC 3339). Owner or admin only;
/// requires an RDP session with drive enabled.
pub async fn drive_list_files(
    State(manager): State<AppState>,
    Path(id): Path<Uuid>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let dir = resolve_drive_session(&manager, id, identity.as_ref()).await?;
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(session_id = %id, error = %e, "Failed to read drive directory");
            return Ok(Json(json!([])));
        }
    };
    let mut files: Vec<serde_json::Value> = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let modified = meta
            .modified()
            .map(|m| chrono::DateTime::<chrono::Utc>::from(m).to_rfc3339())
            .unwrap_or_default();
        files.push(json!({
            "name": entry.file_name().to_string_lossy(),
            "size": meta.len(),
            "modified": modified,
        }));
    }
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!(files)))
}

/// Percent-encode a file name for `filename*` (RFC 5987), keeping only
/// RFC 3986 unreserved characters verbatim.
fn rfc5987_encode(name: &str) -> String {
    let mut out = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// ASCII fallback for `filename=` (RFC 6266): non-graphic bytes and
/// quote/backslash become underscores.
fn ascii_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() && c != '"' && c != '\\' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

/// `GET /api/sessions/{id}/drive-files/{name}`: stream a file from the
/// session's RDP drive as an attachment. Owner or admin only; the name
/// must be a plain basename (no traversal). Symlinks that resolve
/// outside the drive dir are refused.
pub async fn drive_download_file(
    State(manager): State<AppState>,
    Path((id, name)): Path<(Uuid, String)>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<axum::response::Response, AppError> {
    let dir = resolve_drive_session(&manager, id, identity.as_ref()).await?;
    if !valid_drive_basename(&name) {
        return Err(AppError::Validation("invalid file name".into()));
    }
    let canonical = std::fs::canonicalize(dir.join(&name))
        .map_err(|_| AppError::NotFound("file not found".into()))?;
    if !canonical.starts_with(&dir) || !canonical.is_file() {
        return Err(AppError::NotFound("file not found".into()));
    }
    let file = tokio::fs::File::open(&canonical)
        .await
        .map_err(|_| AppError::NotFound("file not found".into()))?;
    let stream = tokio_util::io::ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);
    Ok(axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "application/octet-stream")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            format!(
                "attachment; filename=\"{}\"; filename*=UTF-8''{}",
                ascii_filename(&name),
                rfc5987_encode(&name)
            ),
        )
        .body(body)
        .unwrap()
        .into_response())
}

/// `DELETE /api/sessions/{id}/drive-files/{name}`: remove a file from
/// the session's RDP drive. Owner or admin only; 204 on success, 404
/// for missing files, 400 for invalid names.
pub async fn drive_delete_file(
    State(manager): State<AppState>,
    Path((id, name)): Path<(Uuid, String)>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<StatusCode, AppError> {
    let dir = resolve_drive_session(&manager, id, identity.as_ref()).await?;
    if !valid_drive_basename(&name) {
        return Err(AppError::Validation("invalid file name".into()));
    }
    let canonical = std::fs::canonicalize(dir.join(&name))
        .map_err(|_| AppError::NotFound("file not found".into()))?;
    if !canonical.starts_with(&dir) {
        return Err(AppError::NotFound("file not found".into()));
    }
    if canonical.is_dir() {
        return Err(AppError::Validation("cannot delete a directory".into()));
    }
    tokio::fs::remove_file(&canonical)
        .await
        .map_err(|_| AppError::NotFound("file not found".into()))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Maximum size of a single drive upload: 4 GiB. The drive is a
/// filesystem with no product-level file-size policy, so this is a hard
/// safety cap enforced while streaming. The route must also carry a
/// matching `DefaultBodyLimit` so oversized bodies are cut off at the
/// transport layer before the handler sees them.
const MAX_DRIVE_UPLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Idle timeout for a drive upload body: if no chunk arrives within
/// this window the upload is aborted and the partial file removed,
/// releasing the permit and file handle. A stalled client can no longer
/// pin an upload slot (or an open fd) indefinitely.
const DRIVE_UPLOAD_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Maximum concurrent uploads per session. guacd serializes its own file
/// transfers, so more parallel streams cannot help; excess uploads wait
/// for a free slot (serialized) instead of failing.
const MAX_CONCURRENT_DRIVE_UPLOADS: usize = 5;

/// Per-session upload semaphores. Entries are created on first use and
/// never pruned: a few dozen bytes per distinct session id, negligible
/// next to the sessions themselves.
static DRIVE_UPLOAD_SEMAPHORES: OnceLock<StdMutex<HashMap<Uuid, Arc<tokio::sync::Semaphore>>>> =
    OnceLock::new();

fn drive_upload_semaphore(session_id: Uuid) -> Arc<tokio::sync::Semaphore> {
    let map = DRIVE_UPLOAD_SEMAPHORES.get_or_init(|| StdMutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    guard
        .entry(session_id)
        .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DRIVE_UPLOADS)))
        .clone()
}

/// Re-verify that the opened fd still refers to the file at `path`
/// (same device and inode). Callers that resolved `path` beforehand
/// use this to detect a file swapped in between resolution and open:
/// the write would otherwise target a file the confinement check never
/// saw. `#[cfg(unix)]`: inode comparison is only meaningful there.
#[cfg(unix)]
async fn verify_drive_file_fd(
    file: &tokio::fs::File,
    path: &std::path::Path,
) -> Result<(), AppError> {
    use std::os::unix::fs::MetadataExt;
    let opened = file.metadata().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to stat opened drive upload");
        AppError::Drive("failed to stat drive file for upload".into())
    })?;
    let at_path = std::fs::metadata(path).map_err(|e| {
        tracing::warn!(error = %e, "failed to stat drive upload target");
        AppError::NotFound("file not found".into())
    })?;
    if opened.dev() != at_path.dev() || opened.ino() != at_path.ino() {
        return Err(AppError::NotFound("file not found".into()));
    }
    Ok(())
}

/// Stream a request body into an open drive file, enforcing the size
/// cap and the per-chunk idle timeout. Returns the number of bytes
/// written; the file is flushed before returning so size and mtime
/// reads see the final state. On any error (cap, idle, read, write)
/// the caller removes the partial file.
async fn stream_body_into_drive_file(
    body: axum::body::Body,
    file: &mut tokio::fs::File,
    max_bytes: u64,
    idle_timeout: std::time::Duration,
) -> Result<u64, AppError> {
    let mut stream = body.into_data_stream();
    let mut written: u64 = 0;
    loop {
        // Fresh deadline per chunk: a slow-but-alive client never hits
        // it, a stalled one frees the permit within one window.
        let chunk = match tokio::time::timeout(idle_timeout, stream.next()).await {
            Err(_) => {
                tracing::warn!("drive upload body idle timeout");
                return Err(AppError::Drive("upload idle timeout".into()));
            }
            Ok(Some(chunk)) => chunk.map_err(|e| {
                tracing::warn!(error = %e, "failed to read drive upload body");
                AppError::Internal("failed to read upload body".into())
            })?,
            Ok(None) => break,
        };
        written = written.saturating_add(chunk.len() as u64);
        if written > max_bytes {
            return Err(AppError::Validation(
                "file exceeds the 4 GiB upload cap".into(),
            ));
        }
        file.write_all(&chunk).await.map_err(|e| {
            tracing::warn!(error = %e, "failed to write drive upload");
            AppError::Drive("failed to write upload to drive".into())
        })?;
    }
    file.flush().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to flush drive upload");
        AppError::Drive("failed to flush upload to drive".into())
    })?;
    Ok(written)
}

/// `PUT /api/sessions/{id}/drive-files/{name}`: stream the raw request
/// body into a file in the session's RDP drive, creating or replacing it.
///
/// Exactly one file per request: the body is the file content, streamed
/// straight to disk (no multipart, no buffering). Returns 201 with the
/// drive listing entry `{name, size, modified}`. A failed request
/// removes the partial file, so errors, cap violations, and idle
/// timeouts never leave truncated content on the drive.
///
/// Gate and safety rules match the sibling drive endpoints: owner or
/// admin only (403 otherwise, 404 for unknown sessions and sessions
/// without a drive), the name must be a plain basename (400 for `..`,
/// slashes, or `.`), and symlinks resolving outside the drive directory
/// are refused. Existing files open without following symlinks and the
/// opened fd is re-verified against the canonical path. Uploads over
/// 4 GiB are rejected (the route must carry a matching
/// `DefaultBodyLimit`), and uploads that receive no data for 120
/// seconds are aborted, releasing the upload permit and file handle.
/// At most 5 uploads run concurrently per session; excess requests wait
/// for a free slot (serialized) rather than failing.
///
/// CSRF: like every other state-changing endpoint, this route sits
/// behind the global double-submit cookie check and gets no exemption.
/// A Bearer-only client must bootstrap the `csrf_token` cookie once:
/// perform any anonymous GET (e.g. `/api/auth/status`), capture
/// `Set-Cookie: csrf_token=...`, then send both `Cookie: csrf_token=...`
/// and `X-CSRF-Token: ...` on this PUT.
pub async fn drive_upload_file(
    State(manager): State<AppState>,
    Path((id, name)): Path<(Uuid, String)>,
    identity: Option<Extension<AuthIdentity>>,
    body: axum::body::Body,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let dir = resolve_drive_session(&manager, id, identity.as_ref()).await?;
    if !valid_drive_basename(&name) {
        return Err(AppError::Validation("invalid file name".into()));
    }
    let target = dir.join(&name);
    let existing = std::fs::symlink_metadata(&target).is_ok();
    let write_path = if existing {
        // Existing entry: resolve symlinks and confine the write to the
        // drive dir, exactly like download/delete.
        let canonical = std::fs::canonicalize(&target)
            .map_err(|_| AppError::NotFound("file not found".into()))?;
        if !canonical.starts_with(&dir) || !canonical.is_file() {
            return Err(AppError::NotFound("file not found".into()));
        }
        canonical
    } else {
        target
    };
    let _permit = drive_upload_semaphore(id)
        .acquire_owned()
        .await
        .map_err(|_| AppError::Internal("upload semaphore closed".into()))?;
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true);
    #[cfg(unix)]
    {
        // Refuse to follow a symlink planted after the canonicalize
        // above: O_NOFOLLOW fails the open instead of redirecting the
        // truncating write outside the drive directory.
        options.custom_flags(libc::O_NOFOLLOW);
    }
    if existing {
        options.create(true).truncate(true);
    } else {
        // O_EXCL refuses to follow a symlink planted between the
        // existence check and the open.
        options.create_new(true);
    }
    let mut file = options.open(&write_path).await.map_err(|e| {
        tracing::warn!(error = %e, "failed to open drive upload target");
        AppError::Drive("failed to open drive file for upload".into())
    })?;
    #[cfg(unix)]
    if existing {
        verify_drive_file_fd(&file, &write_path).await?;
    }
    let written = match stream_body_into_drive_file(
        body,
        &mut file,
        MAX_DRIVE_UPLOAD_BYTES,
        DRIVE_UPLOAD_IDLE_TIMEOUT,
    )
    .await
    {
        Ok(written) => written,
        Err(err) => {
            // Best-effort cleanup: failed uploads must not leave a
            // truncated or half-written file on the drive.
            if let Err(e) = tokio::fs::remove_file(&write_path).await {
                tracing::warn!(error = %e, "failed to remove partial drive upload");
            }
            return Err(err);
        }
    };
    let meta = file.metadata().await.map_err(|e| {
        tracing::warn!(error = %e, "failed to stat drive upload");
        AppError::Drive("failed to stat uploaded file".into())
    })?;
    let modified = meta
        .modified()
        .map(|m| chrono::DateTime::<chrono::Utc>::from(m).to_rfc3339())
        .unwrap_or_default();
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "name": name,
            "size": written,
            "modified": modified,
        })),
    ))
}

#[cfg(test)]
mod drive_tests {
    use super::*;
    use crate::session::{Session, SessionManager, SessionStatus, SessionType};
    use std::sync::Arc;
    use tokio::sync::Mutex as AsyncMutex;

    fn test_identity(name: &str, role: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: format!("{}@example.com", name),
            name: name.to_string(),
            role: role.to_string(),
            groups: Vec::new(),
        }
    }

    /// Manager whose `[drive]` config points at a fresh temp dir, plus a
    /// seeded RDP session with drive enabled. Returns (manager, session id,
    /// drive dir).
    async fn seeded_rdp_session() -> (Arc<SessionManager>, Uuid, std::path::PathBuf) {
        let tmp = std::env::temp_dir().join(format!("persea-drive-api-test-{}", Uuid::new_v4()));
        let mut config = crate::config::Config::default();
        config.recording_path = Some(tmp.join("recordings"));
        config.drive = Some(crate::config::DriveConfig {
            enabled: true,
            drive_path: tmp.join("drives"),
            ..Default::default()
        });
        let manager: AppState = Arc::new(SessionManager::new(config, None));
        let id = Uuid::new_v4();
        let drive_cfg = crate::drive::drive_config_or_default(&manager.config().drive);
        let drive_dir = crate::drive::create_session_dir(&drive_cfg, id).unwrap();
        seed_session(
            &manager,
            id,
            SessionType::Rdp,
            true,
            Some(drive_dir.clone()),
            "alice",
        )
        .await;
        (manager, id, drive_dir)
    }

    #[allow(clippy::too_many_arguments)]
    async fn seed_session(
        manager: &SessionManager,
        id: Uuid,
        session_type: SessionType,
        drive_enabled: bool,
        drive_path: Option<std::path::PathBuf>,
        created_by: &str,
    ) {
        let session = Session {
            id,
            session_type,
            status: SessionStatus::Active,
            created_at: chrono::Utc::now(),
            hostname: "test-host".into(),
            username: "alice".into(),
            url: None,
            banner: None,
            guacd_stream: None,
            connection_id: "conn-test".into(),
            share_token: "owner-secret".into(),
            width: 1024,
            height: 768,
            active_connections: 0,
            created_by: created_by.to_string(),
            cancel: tokio_util::sync::CancellationToken::new(),
            browser_session: None,
            deferred_params: None,
            drive_path,
            drive_enabled,
            tunnels: Vec::new(),
            container_id: None,
            container_name: None,
            recording_enabled: false,
            address_book_entry: None,
            address_book_folder: None,
            entry_display_name: None,
            max_recordings: None,
            login_script_handle: None,
            shadow_tokens: Vec::new(),
            share_allowed: false,
            fullscreen_on_connect: false,
            autohide_side_tabs: false,
            auto_size: true,
            last_activity: std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp()),
            source_ip: None,
            user_id: Some(created_by.to_string()),
        };
        manager
            .sessions
            .write()
            .await
            .insert(id, Arc::new(AsyncMutex::new(session)));
    }

    fn write_test_file(dir: &std::path::Path, name: &str, content: &[u8]) {
        std::fs::write(dir.join(name), content).unwrap();
    }

    #[tokio::test]
    async fn drive_list_as_owner_returns_files() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "notes.txt", b"hello drive");
        let res = drive_list_files(
            State(manager),
            Path(id),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap();
        let files = res.0.as_array().unwrap();
        assert_eq!(files.len(), 1, "unexpected listing: {}", res.0);
        assert_eq!(files[0]["name"].as_str().unwrap(), "notes.txt");
        assert_eq!(files[0]["size"].as_u64().unwrap(), 11);
        assert!(files[0]["modified"].as_str().unwrap().contains('T'));
    }

    #[tokio::test]
    async fn drive_list_as_admin_allowed() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "notes.txt", b"x");
        let res = drive_list_files(
            State(manager),
            Path(id),
            Some(Extension(test_identity("root", "admin"))),
        )
        .await
        .unwrap();
        assert_eq!(res.0.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn drive_list_as_non_owner_is_403() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        let err = drive_list_files(
            State(manager),
            Path(id),
            Some(Extension(test_identity("mallory", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_list_nonexistent_session_is_404() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let err = drive_list_files(
            State(manager),
            Path(Uuid::new_v4()),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Session(ref m) if m.contains("not found")),
            "got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn drive_list_ssh_sftp_session_has_no_drive() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let ssh_id = Uuid::new_v4();
        seed_session(&manager, ssh_id, SessionType::Ssh, true, None, "alice").await;
        let err = drive_list_files(
            State(manager),
            Path(ssh_id),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_download_as_owner_streams_file() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "report.pdf", b"PDFDATA");
        let res = drive_download_file(
            State(manager),
            Path((id, "report.pdf".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cd = res
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(cd.starts_with("attachment;"), "got: {}", cd);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"PDFDATA");
    }

    #[tokio::test]
    async fn drive_download_utf8_filename_header() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "na\u{00ef}ve.txt", b"x");
        let res = drive_download_file(
            State(manager),
            Path((id, "na\u{00ef}ve.txt".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let cd = res
            .headers()
            .get(axum::http::header::CONTENT_DISPOSITION)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(
            cd.contains("filename*=UTF-8''na%C3%AFve.txt"),
            "got: {}",
            cd
        );
    }

    #[tokio::test]
    async fn drive_download_as_non_owner_is_403() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "report.pdf", b"PDFDATA");
        let err = drive_download_file(
            State(manager),
            Path((id, "report.pdf".into())),
            Some(Extension(test_identity("mallory", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_download_nonexistent_session_is_404() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let err = drive_download_file(
            State(manager),
            Path((Uuid::new_v4(), "report.pdf".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Session(ref m) if m.contains("not found")),
            "got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn drive_download_missing_file_is_404() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        let err = drive_download_file(
            State(manager),
            Path((id, "ghost.txt".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_download_traversal_names_rejected() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "real.txt", b"x");
        for name in ["../secrets", "a/b", "a\\b", "..", ".", ""] {
            let err = drive_download_file(
                State(manager.clone()),
                Path((id, name.to_string())),
                Some(Extension(test_identity("alice", "viewer"))),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "name {:?} should 400, got {:?}",
                name,
                err
            );
        }
    }

    #[tokio::test]
    async fn drive_delete_as_owner_removes_file() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "junk.bin", b"delete me");
        let identity = test_identity("alice", "viewer");
        assert_eq!(
            drive_delete_file(
                State(manager.clone()),
                Path((id, "junk.bin".into())),
                Some(Extension(identity.clone())),
            )
            .await
            .unwrap(),
            StatusCode::NO_CONTENT
        );
        assert!(!dir.join("junk.bin").exists());
        let err = drive_delete_file(
            State(manager),
            Path((id, "junk.bin".into())),
            Some(Extension(identity)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_delete_as_non_owner_is_403() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "junk.bin", b"delete me");
        let err = drive_delete_file(
            State(manager),
            Path((id, "junk.bin".into())),
            Some(Extension(test_identity("mallory", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_delete_traversal_names_rejected() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        for name in ["../secrets", "a/b", "..", ""] {
            let err = drive_delete_file(
                State(manager.clone()),
                Path((id, name.to_string())),
                Some(Extension(test_identity("alice", "viewer"))),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "name {:?} should 400, got {:?}",
                name,
                err
            );
        }
    }

    #[tokio::test]
    async fn drive_delete_nonexistent_session_is_404() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let err = drive_delete_file(
            State(manager),
            Path((Uuid::new_v4(), "junk.bin".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Session(ref m) if m.contains("not found")),
            "got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn drive_endpoints_need_authentication() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        let err = drive_list_files(State(manager.clone()), Path(id), None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
        let err = drive_download_file(State(manager.clone()), Path((id, "x.txt".into())), None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
        let err = drive_delete_file(State(manager), Path((id, "x.txt".into())), None)
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
    }

    async fn upload(
        manager: &Arc<SessionManager>,
        id: Uuid,
        name: &str,
        identity: Option<AuthIdentity>,
        payload: Vec<u8>,
    ) -> Result<(StatusCode, serde_json::Value), AppError> {
        drive_upload_file(
            State(manager.clone()),
            Path((id, name.to_string())),
            identity.map(Extension),
            axum::body::Body::from(payload),
        )
        .await
        .map(|(code, json)| (code, json.0))
    }

    #[tokio::test]
    async fn drive_upload_creates_file_and_returns_entry() {
        let (manager, id, dir) = seeded_rdp_session().await;
        let payload = b"streamed upload body".to_vec();
        let (status, json) = upload(
            &manager,
            id,
            "upload.bin",
            Some(test_identity("alice", "viewer")),
            payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json["name"], "upload.bin");
        assert_eq!(json["size"], payload.len() as u64);
        assert!(json["modified"].as_str().unwrap().contains('T'));
        assert_eq!(std::fs::read(dir.join("upload.bin")).unwrap(), payload);
        // Round-trip through the download endpoint.
        let res = drive_download_file(
            State(manager),
            Path((id, "upload.bin".into())),
            Some(Extension(test_identity("alice", "viewer"))),
        )
        .await
        .unwrap();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], payload);
    }

    #[tokio::test]
    async fn drive_upload_overwrites_existing_file() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "notes.txt", b"old content");
        let payload = b"new".to_vec();
        let (status, json) = upload(
            &manager,
            id,
            "notes.txt",
            Some(test_identity("alice", "viewer")),
            payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json["size"], 3);
        assert_eq!(std::fs::read(dir.join("notes.txt")).unwrap(), payload);
    }

    #[tokio::test]
    async fn drive_upload_as_admin_allowed() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        let (status, json) = upload(
            &manager,
            id,
            "admin.bin",
            Some(test_identity("root", "admin")),
            b"by admin".to_vec(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json["size"], 8);
    }

    #[tokio::test]
    async fn drive_upload_as_non_owner_is_403() {
        let (manager, id, dir) = seeded_rdp_session().await;
        let err = upload(
            &manager,
            id,
            "evil.bin",
            Some(test_identity("mallory", "viewer")),
            b"x".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
        assert!(!dir.join("evil.bin").exists());
    }

    #[tokio::test]
    async fn drive_upload_without_identity_is_403() {
        let (manager, id, dir) = seeded_rdp_session().await;
        let err = upload(&manager, id, "anon.bin", None, b"x".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
        assert!(!dir.join("anon.bin").exists());
    }

    #[tokio::test]
    async fn drive_upload_nonexistent_session_is_404() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let err = upload(
            &manager,
            Uuid::new_v4(),
            "x.bin",
            Some(test_identity("alice", "viewer")),
            b"x".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Session(ref m) if m.contains("not found")),
            "got {:?}",
            err
        );
    }

    #[tokio::test]
    async fn drive_upload_traversal_names_rejected() {
        let (manager, id, dir) = seeded_rdp_session().await;
        for name in ["../secrets", "a/b", "a\\b", "..", ".", ""] {
            let err = upload(
                &manager,
                id,
                name,
                Some(test_identity("alice", "viewer")),
                b"x".to_vec(),
            )
            .await
            .unwrap_err();
            assert!(
                matches!(err, AppError::Validation(_)),
                "name {:?} should 400, got {:?}",
                name,
                err
            );
        }
        assert!(!dir.parent().unwrap().join("secrets").exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn drive_upload_symlink_escape_refused() {
        let (manager, id, dir) = seeded_rdp_session().await;
        let outside = dir
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("outside-target.txt");
        std::fs::write(&outside, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("escape.txt")).unwrap();
        let err = upload(
            &manager,
            id,
            "escape.txt",
            Some(test_identity("alice", "viewer")),
            b"x".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
        assert_eq!(std::fs::read(&outside).unwrap(), b"do not touch");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn drive_upload_symlink_inside_drive_dir_allowed() {
        let (manager, id, dir) = seeded_rdp_session().await;
        write_test_file(&dir, "real.txt", b"orig");
        std::os::unix::fs::symlink("real.txt", dir.join("alias.txt")).unwrap();
        let payload = b"via-alias".to_vec();
        upload(
            &manager,
            id,
            "alias.txt",
            Some(test_identity("alice", "viewer")),
            payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(dir.join("real.txt")).unwrap(), payload);
        assert!(
            std::fs::symlink_metadata(dir.join("alias.txt"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "alias must remain a symlink"
        );
    }

    #[tokio::test]
    async fn drive_upload_to_directory_rejected() {
        let (manager, id, dir) = seeded_rdp_session().await;
        std::fs::create_dir(dir.join("subdir")).unwrap();
        let err = upload(
            &manager,
            id,
            "subdir",
            Some(test_identity("alice", "viewer")),
            b"x".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
    }

    #[tokio::test]
    async fn drive_upload_ssh_session_has_no_drive() {
        let (manager, _id, _dir) = seeded_rdp_session().await;
        let ssh_id = Uuid::new_v4();
        seed_session(&manager, ssh_id, SessionType::Ssh, true, None, "alice").await;
        let err = upload(
            &manager,
            ssh_id,
            "x.bin",
            Some(test_identity("alice", "viewer")),
            b"x".to_vec(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::NotFound(_)), "got {:?}", err);
    }

    /// Manager whose drive config carries LUKS fields, as if the volume
    /// were already mounted at `drive_path` (the mount itself is a
    /// startup-time root step, `drive::mount_luks`). Pins that upload
    /// resolution is identical on LUKS-configured drives.
    async fn seeded_rdp_session_with_luks_config() -> (Arc<SessionManager>, Uuid, std::path::PathBuf)
    {
        let tmp = std::env::temp_dir().join(format!("persea-drive-api-test-{}", Uuid::new_v4()));
        let mut config = crate::config::Config::default();
        config.recording_path = Some(tmp.join("recordings"));
        config.drive = Some(crate::config::DriveConfig {
            enabled: true,
            drive_path: tmp.join("drives"),
            luks_device: Some(tmp.join("container.img")),
            luks_name: "persea-test".into(),
            luks_key_path: Some("secret/test".into()),
            ..Default::default()
        });
        let manager: AppState = Arc::new(SessionManager::new(config, None));
        let id = Uuid::new_v4();
        let drive_cfg = crate::drive::drive_config_or_default(&manager.config().drive);
        let drive_dir = crate::drive::create_session_dir(&drive_cfg, id).unwrap();
        seed_session(
            &manager,
            id,
            SessionType::Rdp,
            true,
            Some(drive_dir.clone()),
            "alice",
        )
        .await;
        (manager, id, drive_dir)
    }

    #[tokio::test]
    async fn drive_upload_luks_configured_drive_round_trip() {
        let (manager, id, dir) = seeded_rdp_session_with_luks_config().await;
        let payload = b"luks-encrypted payload".to_vec();
        let (status, json) = upload(
            &manager,
            id,
            "luks.bin",
            Some(test_identity("alice", "viewer")),
            payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(json["size"], payload.len() as u64);
        assert_eq!(std::fs::read(dir.join("luks.bin")).unwrap(), payload);
    }

    #[tokio::test]
    async fn drive_upload_concurrent_uploads_capped_per_session() {
        let (manager, id, _dir) = seeded_rdp_session().await;
        let sem = drive_upload_semaphore(id);
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_DRIVE_UPLOADS {
            held.push(sem.clone().acquire_owned().await.unwrap());
        }
        let identity = test_identity("alice", "viewer");
        let handle = tokio::spawn(async move {
            drive_upload_file(
                State(manager),
                Path((id, "queued.bin".into())),
                Some(Extension(identity)),
                axum::body::Body::from(b"queued".to_vec()),
            )
            .await
        });
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert!(!handle.is_finished(), "upload must wait for a free permit");
        drop(held.pop());
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("upload must complete once a permit frees up")
            .expect("upload task must not panic")
            .unwrap();
        assert_eq!(result.0, StatusCode::CREATED);
    }

    #[tokio::test]
    async fn stream_body_idle_timeout_aborts_upload() {
        let dir = std::env::temp_dir().join(format!("persea-drive-idle-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut file = tokio::fs::File::create(dir.join("idle.bin")).await.unwrap();
        // One chunk, then silence: the deadline must fire on the next
        // read even though the stream never ends.
        let stalled = futures_util::stream::iter(vec![Ok::<axum::body::Bytes, axum::Error>(
            axum::body::Bytes::from_static(b"first"),
        )])
        .chain(futures_util::stream::pending());
        let err = stream_body_into_drive_file(
            axum::body::Body::from_stream(stalled),
            &mut file,
            MAX_DRIVE_UPLOAD_BYTES,
            std::time::Duration::from_millis(100),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, AppError::Drive(ref m) if m.contains("idle")),
            "got {:?}",
            err
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn stream_body_cap_rejects_oversized_upload() {
        let dir = std::env::temp_dir().join(format!("persea-drive-cap-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut file = tokio::fs::File::create(dir.join("cap.bin")).await.unwrap();
        let err = stream_body_into_drive_file(
            axum::body::Body::from(b"0123456789".to_vec()),
            &mut file,
            3,
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "got {:?}", err);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn drive_upload_stream_error_removes_partial_file_and_releases_permit() {
        let (manager, id, dir) = seeded_rdp_session().await;
        let failing = futures_util::stream::iter(vec![
            Ok::<axum::body::Bytes, axum::Error>(axum::body::Bytes::from_static(b"partial data")),
            Err::<axum::body::Bytes, axum::Error>(axum::Error::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                "boom",
            ))),
        ]);
        let err = drive_upload_file(
            State(manager.clone()),
            Path((id, "failing.bin".into())),
            Some(Extension(test_identity("alice", "viewer"))),
            axum::body::Body::from_stream(failing),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Internal(_)), "got {:?}", err);
        assert!(
            !dir.join("failing.bin").exists(),
            "partial file must be removed after a failed upload"
        );
        // The failed upload must release its permit: a full set of
        // fresh acquisitions completes without blocking.
        let sem = drive_upload_semaphore(id);
        for _ in 0..MAX_CONCURRENT_DRIVE_UPLOADS {
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                sem.clone().acquire_owned(),
            )
            .await
            .expect("a permit must be free after the failed upload")
            .unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn verify_drive_file_fd_rejects_swapped_path() {
        let dir = std::env::temp_dir().join(format!("persea-drive-verify-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        let file = tokio::fs::File::open(&a).await.unwrap();
        // The fd refers to a.txt; the path being verified is b.txt: the
        // device/inode comparison must fail.
        verify_drive_file_fd(&file, &b).await.unwrap_err();
        // A matching fd and path verify clean.
        verify_drive_file_fd(&file, &a).await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn terminating_session_leaves_user_tokens_untouched() {
        let db: Db = db::init_db(std::path::Path::new(":memory:")).unwrap();
        let user =
            db::upsert_user(&db, "alice@example.com", "Alice", None, "operator", &[]).unwrap();
        let (token_id, plaintext) =
            db::create_user_token(&db, user.id, "ci-token", None, None).unwrap();

        let tmp =
            std::env::temp_dir().join(format!("persea-session-token-api-test-{}", Uuid::new_v4()));
        let mut config = crate::config::Config::default();
        config.recording_path = Some(tmp.join("recordings"));
        let manager: AppState = Arc::new(SessionManager::new_with_db(config, None, db.clone()));
        let id = Uuid::new_v4();
        seed_session(
            &manager,
            id,
            SessionType::Rdp,
            false,
            None,
            "alice@example.com",
        )
        .await;

        // End the session through the same manager path the API's
        // DELETE /api/sessions/{id} uses.
        assert!(manager.delete_session(id).await);
        assert!(manager.get_session(id).await.is_none());

        // Independence invariant: ending the session cascades nowhere.
        // The token is still listed and still authenticates.
        let tokens = db::list_user_tokens(&db, user.id).unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].id, token_id);
        let (u, _meta) = db::validate_user_token(&db, &plaintext).unwrap();
        assert_eq!(u.id, user.id);
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    fn user(email: &str, name: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: email.to_string(),
            name: name.to_string(),
            role: "operator".into(),
            groups: Vec::new(),
        }
    }

    #[test]
    fn identity_key_prefers_email_over_display_name() {
        assert_eq!(
            identity_key(&user("alice@example.com", "Alice")),
            "alice@example.com"
        );
        assert_eq!(
            identity_key(&AuthIdentity::ApiKey("deploy".into())),
            "deploy"
        );
    }

    #[test]
    fn session_owned_by_matches_stable_identity_first() {
        // Email-keyed session: only the owner's email matches; a user
        // with the same display name is not the owner.
        let owner = user("alice@example.com", "Alice Smith");
        assert!(session_owned_by(&owner, "alice@example.com"));
        let collider = user("mallory@example.com", "Alice Smith");
        assert!(!session_owned_by(&collider, "alice@example.com"));
        // Legacy display-name-keyed session: the display-name leg keeps
        // the creator authorized.
        assert!(session_owned_by(&owner, "Alice Smith"));
    }

    #[test]
    fn vdi_container_username_derives_from_identity() {
        assert_eq!(
            vdi_container_username(&user("alice@example.com", "Alice")),
            "alice"
        );
        assert_eq!(
            vdi_container_username(&user("a.b+tag@corp.com", "A B")),
            "a_b_tag"
        );
        assert_eq!(
            vdi_container_username(&AuthIdentity::ApiKey("deploy".into())),
            "deploy"
        );
    }

    #[test]
    fn vdi_container_prefix_matches_driver_scheme() {
        // The prefix is `persea-vdi-{dash-sanitized}-{fnv1a:08x}`: the
        // same shape the driver produces (entry-suffixed names extend it).
        let prefix = vdi_container_prefix("alice");
        assert_eq!(
            prefix,
            format!("persea-vdi-alice-{:08x}", fnv1a("alice") as u32)
        );
        assert!(prefix.starts_with("persea-vdi-alice-"));
        assert_eq!(prefix.len(), "persea-vdi-alice-".len() + 8);
    }

    #[test]
    fn vdi_container_owned_exact_and_entry_suffixed() {
        let prefix = vdi_container_prefix("alice");
        assert!(vdi_container_owned_by(&prefix, &prefix));
        assert!(vdi_container_owned_by(
            &format!("{}-web-server", prefix),
            &prefix
        ));
        // A different user's container (different hash) is not owned.
        let mallory = vdi_container_prefix("mallory");
        assert!(!vdi_container_owned_by(&mallory, &prefix));
    }

    #[test]
    fn vdi_container_ownership_hash_disambiguates_name_prefixes() {
        // `alice` must not own `alice-smith`'s containers: the dashed
        // prefix matches but the hash differs.
        let alice = vdi_container_prefix("alice");
        let alice_smith = vdi_container_prefix("alice_smith");
        assert_ne!(alice, alice_smith);
        assert!(alice_smith.starts_with(&format!("persea-vdi-alice-")));
        assert!(!vdi_container_owned_by(&alice_smith, &alice));
    }

    #[test]
    fn vdi_container_ownership_distinguishes_sanitize_collisions() {
        // Usernames that dash-sanitize to the same form still hash
        // differently, so neither claims the other's containers.
        let a = vdi_container_prefix("a_b");
        let b = vdi_container_prefix("a-b");
        assert_ne!(a, b);
        assert!(!vdi_container_owned_by(&a, &b));
    }
}
