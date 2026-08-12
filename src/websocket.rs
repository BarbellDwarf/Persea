//! WebSocket proxy: bridges browser ↔ guacd TCP socket.

use crate::api::AppState;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::guacd::GuacdStream;
use crate::protocol::{last_instruction_boundary, Instruction};
use crate::session::{SessionManager, ShareTokenValidation};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
    Extension,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Which side terminated the proxy connection.
enum ProxyResult {
    /// guacd closed the connection (with optional error).
    GuacdEnded(Option<String>),
    /// Browser/WebSocket closed the connection (with optional error).
    BrowserEnded(Option<String>),
    /// Session was cancelled externally.
    Cancelled,
}

/// Direction of a transfer instruction, used by the audit sniffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferDirection {
    BrowserToGuacd,
    GuacdToBrowser,
}

/// Whether a tracked transfer is an upload (browser → remote) or a
/// download (remote → browser).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferKind {
    Upload,
    Download,
}

/// A file transfer in progress, tracked by its Guacamole stream index.
#[derive(Debug, Clone)]
struct PendingTransfer {
    kind: TransferKind,
    filename: String,
    mimetype: String,
    size: u64,
}

/// A transfer that completed or failed, ready to be written to the audit
/// hash chain.
#[derive(Debug, PartialEq)]
struct TransferAuditEvent {
    kind: TransferKind,
    filename: String,
    mimetype: String,
    size: u64,
    error: bool,
}

/// Byte length of a base64-encoded blob argument (exact for standard padded
/// base64, which is what guacd and the JS client emit).
fn base64_blob_len(data: &str) -> u64 {
    let data = data.trim_end();
    let mut len = data.len() as u64;
    if data.ends_with("==") {
        len -= 2;
    } else if len > 0 && data.ends_with('=') {
        len -= 1;
    }
    len * 3 / 4
}

/// Sniff one parsed instruction for file-transfer activity, updating the
/// shared pending-transfer map and returning audit events to emit.
///
/// Mirrors the clipboard sniff: pure, unit-testable, and does not alter the
/// forwarded stream in any way.
///
/// Browser → guacd: `file,<idx>,<mimetype>,<name>` opens an upload;
/// `blob,<idx>,<b64>` carries its data; `end,<idx>` completes it. A failed
/// upload is surfaced by guacd's `ack,<idx>,<msg>,<code>` (code != 0).
///
/// guacd → browser: `body,<obj>,<stream>,<mimetype>,<name>` delivers a
/// requested stream — directory listings (stream-index mimetype) are not
/// transfers, everything else is a download of `name`. `file,<idx>,<mimetype>,<name>`
/// (RDP drive pushes, SSH terminal-triggered downloads) is a download too.
/// Blobs accumulate the size; `end,<idx>` finalizes. A failed download is
/// surfaced by the browser's `ack,<idx>,<msg>,<code>` (code != 0).
fn sniff_transfer_instruction(
    instr: &Instruction,
    direction: TransferDirection,
    pending: &mut HashMap<i64, PendingTransfer>,
) -> Vec<TransferAuditEvent> {
    let mut events = Vec::new();
    let kind_matches = |p: &PendingTransfer| {
        (p.kind == TransferKind::Upload) == (direction == TransferDirection::BrowserToGuacd)
    };
    match instr.opcode.as_str() {
        "file" => {
            // Uploads (browser → guacd) and pushed downloads (guacd →
            // browser) both carry <idx>,<mimetype>,<filename>.
            if instr.args.len() >= 3 {
                if let Ok(idx) = instr.args[0].parse::<i64>() {
                    if idx >= 0 {
                        pending.insert(
                            idx,
                            PendingTransfer {
                                kind: match direction {
                                    TransferDirection::BrowserToGuacd => TransferKind::Upload,
                                    TransferDirection::GuacdToBrowser => TransferKind::Download,
                                },
                                filename: instr.args[2].clone(),
                                mimetype: instr.args[1].clone(),
                                size: 0,
                            },
                        );
                    }
                }
            }
        }
        "body" => {
            // guacd responds to get requests with body instructions. The
            // stream-index mimetype denotes a directory listing, not a
            // transfer; anything else is a file download (name = path).
            if direction == TransferDirection::GuacdToBrowser && instr.args.len() >= 4 {
                if instr.args[2] != "application/vnd.glyptodon.guacamole.stream-index+json" {
                    if let Ok(idx) = instr.args[1].parse::<i64>() {
                        if idx >= 0 {
                            let path = instr.args[3].clone();
                            let filename = path.rsplit('/').next().unwrap_or(&path).to_string();
                            pending.insert(
                                idx,
                                PendingTransfer {
                                    kind: TransferKind::Download,
                                    filename,
                                    mimetype: instr.args[2].clone(),
                                    size: 0,
                                },
                            );
                        }
                    }
                }
            }
        }
        "blob" => {
            if let Some(idx) = instr.args.first().and_then(|a| a.parse::<i64>().ok()) {
                if let Some(p) = pending.get_mut(&idx) {
                    if kind_matches(p) {
                        if let Some(data) = instr.args.get(1) {
                            p.size += base64_blob_len(data);
                        }
                    }
                }
            }
        }
        "end" => {
            if let Some(idx) = instr.args.first().and_then(|a| a.parse::<i64>().ok()) {
                if let Some(p) = pending.get(&idx) {
                    if kind_matches(p) {
                        if let Some(p) = pending.remove(&idx) {
                            events.push(TransferAuditEvent {
                                kind: p.kind,
                                filename: p.filename,
                                mimetype: p.mimetype,
                                size: p.size,
                                error: false,
                            });
                        }
                    }
                }
            }
        }
        "ack" => {
            // Acks for uploads come from guacd (guacd → browser); acks for
            // downloads come from the browser (browser → guacd). A non-zero
            // code fails the transfer.
            if let Some(idx) = instr.args.first().and_then(|a| a.parse::<i64>().ok()) {
                if let Some(p) = pending.get(&idx) {
                    if (p.kind == TransferKind::Upload)
                        == (direction == TransferDirection::GuacdToBrowser)
                    {
                        if instr.args.get(2).map(|s| s.as_str()).unwrap_or("0") != "0" {
                            if let Some(p) = pending.remove(&idx) {
                                events.push(TransferAuditEvent {
                                    kind: p.kind,
                                    filename: p.filename,
                                    mimetype: p.mimetype,
                                    size: p.size,
                                    error: true,
                                });
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    events
}

/// Write a transfer audit event into the hash-chain audit log. Runs the DB
/// write on a blocking thread (rusqlite is synchronous). Silent on failure —
/// audit logging must never take down the proxy.
fn emit_transfer_audit(
    database: Option<&Db>,
    session_id: Uuid,
    user: Option<&str>,
    event: TransferAuditEvent,
) {
    let Some(db) = database else {
        return;
    };
    let db = db.clone();
    let sid = session_id.to_string();
    let user = user.unwrap_or("unknown").to_string();
    let event_type = match event.kind {
        TransferKind::Upload => "session.file.upload",
        TransferKind::Download => "session.file.download",
    };
    let outcome = if event.error { "error" } else { "success" };
    let details = json!({
        "filename": event.filename,
        "mimetype": event.mimetype,
        "size": event.size,
    });
    tokio::task::spawn_blocking(move || {
        let _ = crate::audit::log_event(
            &db,
            &mut crate::audit::EventBuilder::new(event_type, outcome)
                .user_id(&user)
                .session_id(&sid)
                .details(details)
                .build(),
        );
    });
}

/// Outcome of the proxy session, including whether guacd sent a disconnect instruction.
struct ProxyOutcome {
    result: ProxyResult,
    /// True if guacd sent `10.disconnect;` through the stream — indicates the
    /// remote server ended the session (user logout, crash), as opposed to the
    /// browser/network dropping the WebSocket.
    server_disconnected: bool,
    /// The message from guacd's `error` instruction, if one was seen (e.g.
    /// "Server refused connection (wrong security type?)"). Forwarded to the
    /// browser verbatim; captured here for logging and the disconnect reason.
    guacd_error: Option<String>,
}

#[derive(Deserialize)]
pub struct WsQuery {
    pub token: Option<String>,
}

/// Parts of the WS upgrade request the handler needs beyond the typed
/// extracts: the raw query string (for preserving ?token= etc. on the
/// cross-instance redirect) and whether the identity came from a
/// consumed ticket (which lets the origin check be skipped — the ticket is
/// the anti-CSWSh credential). Implemented as a parts extractor so it can
/// coexist with `WebSocketUpgrade` (both cannot consume the body).
#[derive(Clone)]
pub struct WsRequestParts {
    pub query_string: Option<String>,
    pub ticket_authenticated: bool,
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for WsRequestParts {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            query_string: parts.uri.query().map(|q| q.to_string()),
            ticket_authenticated: parts
                .extensions
                .get::<crate::auth::TicketAuthenticated>()
                .is_some(),
        })
    }
}

/// GET /ws/:session_id — Upgrade to WebSocket and proxy to guacd.
#[allow(clippy::too_many_arguments)]
pub async fn ws_handler(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(session_id): Path<Uuid>,
    Query(query): Query<WsQuery>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    database: Option<Extension<Db>>,
    ticket_store: Extension<crate::auth::WsTicketStore>,
    ws_parts: WsRequestParts,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    let identity = identity.map(|Extension(id)| id);

    // When the identity came from a consumed WebSocket ticket, the
    // ticket itself is the anti-CSWSh credential (minted only by
    // authenticated callers, single-use, 30s TTL) — the Origin/Host match is
    // skipped so cross-instance join/shadow redirects (which necessarily
    // carry another instance's Origin) can land here. Without a ticket the
    // strict Origin check below still applies.
    let ticket_authenticated = ws_parts.ticket_authenticated;

    // Validate Origin header to prevent cross-site WebSocket hijacking (CSWSH).
    // Compare Origin's hostname against the request's Host header hostname.
    // Only the hostname is compared (ports stripped) to avoid false rejections
    // behind reverse proxies that may add/remove default ports.
    // Reject WebSocket upgrades when Origin is missing to prevent CSWSH.
    if !ticket_authenticated {
        match headers.get("origin").and_then(|v| v.to_str().ok()) {
            Some(origin) => {
                let host = headers
                    .get("host")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if !origin_host_matches(origin, host) {
                    tracing::warn!(
                        session_id = %session_id,
                        client_ip = %ip,
                        origin = %origin,
                        host = %host,
                        "WebSocket upgrade rejected: Origin does not match Host (possible CSWSH)"
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        axum::Json(json!({"error": "cross-origin WebSocket request rejected"})),
                    )
                        .into_response();
                }
            }
            None => {
                tracing::warn!(
                    session_id = %session_id,
                    client_ip = %ip,
                    "WebSocket upgrade rejected: missing Origin header (possible CSWSH)"
                );
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({"error": "WebSocket upgrade requires Origin header"})),
                )
                    .into_response();
            }
        }
    }

    // Reject new WebSocket connections during shutdown
    if manager.is_shutting_down() {
        tracing::debug!(session_id = %session_id, "Rejecting WebSocket during shutdown");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(json!({"error": "server is shutting down"})),
        )
            .into_response();
    }

    // Cross-instance join/shadow/owner-reconnect: the guacd stream
    // lives on the owning instance, so a WebSocket that lands here for a
    // remote session is redirected to the owner's WS endpoint. The ticket is
    // DB-backed, so the owner instance validates it; a fresh ticket is
    // minted with the (already authenticated) identity so the forwarded
    // connection carries credentials the owner trusts. The share token
    // (?token=) is preserved verbatim — the owner validates it in-memory.
    if let Some(info) = manager.get_session(session_id).await {
        if info.remote {
            let Some(owner_base) = info.owner_base_url.as_deref() else {
                tracing::warn!(
                    session_id = %session_id,
                    client_ip = %ip,
                    owner = %info.owner_instance.as_deref().unwrap_or("?"),
                    "Remote session join rejected: owning instance advertises no ha_base_url"
                );
                return (
                    StatusCode::BAD_GATEWAY,
                    axum::Json(json!({
                        "error": "session is hosted by another instance that advertises no ha_base_url — configure ha_base_url on the owning instance"
                    })),
                )
                    .into_response();
            };
            let Some(id) = identity else {
                tracing::warn!(
                    session_id = %session_id,
                    client_ip = %ip,
                    "Remote session join rejected: no authenticated identity to forward"
                );
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(json!({
                        "error": "authentication required to join a session on another instance"
                    })),
                )
                    .into_response();
            };

            // Preserve every query param except `ticket` (the old ticket was
            // already consumed by the auth middleware; the fresh one below
            // replaces it).
            let mut kept: Vec<String> = Vec::new();
            if let Some(qs) = ws_parts.query_string.as_deref() {
                for pair in qs.split('&') {
                    if pair.is_empty() {
                        continue;
                    }
                    let key = pair.split('=').next().unwrap_or("");
                    if key == "ticket" {
                        continue;
                    }
                    kept.push(pair.to_string());
                }
            }
            let fresh_ticket = ticket_store.forward(id).await;
            let mut location = format!(
                "{}/ws/{}?ticket={}",
                owner_base.trim_end_matches('/'),
                session_id,
                fresh_ticket
            );
            if !kept.is_empty() {
                location.push('&');
                location.push_str(&kept.join("&"));
            }
            tracing::info!(
                session_id = %session_id,
                client_ip = %ip,
                owner = %info.owner_instance.as_deref().unwrap_or("?"),
                location = %location,
                "Redirecting cross-instance WebSocket to the owning instance"
            );
            return axum::response::Response::builder()
                .status(StatusCode::TEMPORARY_REDIRECT)
                .header(axum::http::header::LOCATION, location)
                .body(axum::body::Body::empty())
                .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    }

    // Check if this is an owner connection (session is Pending or Disconnected)
    let is_owner = manager.is_session_pending(session_id).await
        || manager.is_session_disconnected(session_id).await;

    if is_owner {
        // Owner path: require authenticated identity with operator+ role
        match &identity {
            Some(id) if id.has_role("operator") => {
                // Authorized — proceed
            }
            _ => {
                tracing::warn!(session_id = %session_id, client_ip = %ip, "Unauthorized owner connection attempt");
                return (
                    StatusCode::FORBIDDEN,
                    axum::Json(
                        json!({"error": "authentication required to connect as session owner"}),
                    ),
                )
                    .into_response();
            }
        }
    }

    let identity_name = identity.as_ref().map(|id| id.display_name().to_string());
    let database = database.map(|Extension(db)| db);

    ws.protocols(["guacamole"])
        .on_upgrade(move |socket| {
            handle_ws(
                manager,
                session_id,
                query.token,
                socket,
                ip,
                identity_name,
                database,
            )
        })
        .into_response()
}

async fn handle_ws(
    manager: Arc<SessionManager>,
    session_id: Uuid,
    token: Option<String>,
    ws: WebSocket,
    client_addr: IpAddr,
    identity_name: Option<String>,
    database: Option<Db>,
) {
    // Try to take the guacd stream (owner/first connection)
    let (guacd_stream, cancel) = if let Some((stream, cancel)) =
        manager.take_guacd_stream(session_id).await
    {
        let identity_str = identity_name.as_deref().unwrap_or("unknown");
        tracing::info!(session_id = %session_id, client_ip = %client_addr, identity = %identity_str, "Session owner connected");
        (stream, cancel)
    } else if let Some((stream, cancel)) = manager.reconnect_session(session_id).await {
        let identity_str = identity_name.as_deref().unwrap_or("unknown");
        tracing::info!(session_id = %session_id, client_ip = %client_addr, identity = %identity_str, "Session owner reconnected");
        (stream, cancel)
    } else {
        // Not pending — try to join an active session
        // Joining requires a valid share token
        let token = match token {
            Some(t) => t,
            None => {
                tracing::warn!(session_id = %session_id, client_ip = %client_addr, "Join attempt without share token");
                return;
            }
        };

        let validation = manager.validate_share_token(session_id, &token).await;
        match &validation {
            ShareTokenValidation::Invalid => {
                tracing::warn!(session_id = %session_id, client_ip = %client_addr, "Share token rejected");
                return;
            }
            ShareTokenValidation::Owner => {}
            ShareTokenValidation::Shadow { issued_by } => {
                // Audit every shadow-token use (not just the mint). A leaked
                // token remains reusable within its TTL, but each reuse is
                // now visible in token_audit_log with the connecting IP.
                if let Some(db) = database.as_ref() {
                    let db_clone = db.clone();
                    let ip_str = client_addr.to_string();
                    let issued_by = issued_by.clone();
                    let details = format!("session_id={}, issued_by={}", session_id, issued_by);
                    let _ = tokio::task::spawn_blocking(move || {
                        if let Err(e) = db::log_token_event(
                            &db_clone,
                            None,
                            None,
                            &issued_by,
                            "shadow_used",
                            Some(&ip_str),
                            Some(&details),
                        ) {
                            tracing::warn!(error = %e, "failed to write shadow_used audit log");
                        }
                    })
                    .await;
                }
                tracing::info!(
                    session_id = %session_id,
                    client_ip = %client_addr,
                    issued_by = %issued_by,
                    "Shadow token consumed"
                );
            }
        }

        // Per-session concurrent viewer limit.
        // The owner connection is not counted (active_connections starts at 0
        // for a Pending session).  max_viewers == 0 means unlimited.
        {
            let max_viewers = manager.config().max_viewers;
            if max_viewers > 0 {
                let session = manager.get_session(session_id).await;
                if let Some(info) = session {
                    if info.active_connections >= max_viewers {
                        tracing::warn!(
                            session_id = %session_id,
                            client_ip = %client_addr,
                            active = info.active_connections,
                            max = max_viewers,
                            "Rejecting viewer: per-session concurrent viewer limit reached"
                        );
                        return;
                    }
                }
            }
        }

        match manager.join_session(session_id).await {
            Ok((stream, cancel)) => {
                tracing::info!(session_id = %session_id, client_ip = %client_addr, "Viewer connected via share token");
                (stream, cancel)
            }
            Err(e) => {
                tracing::warn!(session_id = %session_id, client_ip = %client_addr, error = %e, "Failed to join session");
                return;
            }
        }
    };

    tracing::info!(session_id = %session_id, client_ip = %client_addr, "Starting proxy");

    // Set up recording file (only for owner connections, and only if recording is enabled)
    let is_recording_enabled = manager.is_recording_enabled(session_id).await;
    let recording_path = manager
        .recording_path()
        .join(format!("{}.guac", session_id));
    let recording_file = if is_recording_enabled && !recording_path.exists() {
        match tokio::fs::File::create(&recording_path).await {
            Ok(f) => {
                // Set restrictive permissions on recording file
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = tokio::fs::set_permissions(
                        &recording_path,
                        std::fs::Permissions::from_mode(0o640),
                    )
                    .await;
                }

                // Write sidecar .meta file with session context
                {
                    let session_info = manager.get_session(session_id).await;
                    let ab_entry = session_info
                        .as_ref()
                        .and_then(|s| s.address_book_entry.clone());
                    let meta = crate::recording::RecordingMeta {
                        address_book_entry: ab_entry,
                        created_at: chrono::Utc::now().to_rfc3339(),
                        user: session_info.as_ref().map(|s| s.created_by.clone()),
                        folder: session_info
                            .as_ref()
                            .and_then(|s| s.address_book_folder.clone()),
                        entry_display_name: session_info
                            .as_ref()
                            .and_then(|s| s.entry_display_name.clone()),
                        session_type: session_info
                            .as_ref()
                            .map(|s| format!("{:?}", s.session_type).to_lowercase()),
                    };
                    if let Err(e) = crate::recording::write_meta(&recording_path, &meta) {
                        tracing::warn!(session_id = %session_id, error = %e, "Failed to write recording .meta");
                    }
                }

                Some(f)
            }
            Err(e) => {
                tracing::error!(session_id = %session_id, error = %e, "Failed to create recording file");
                None
            }
        }
    } else {
        None // Viewer connections don't record, or recording is disabled
    };

    // Run the bidirectional proxy
    let start = Instant::now();
    let session_user = manager
        .get_session(session_id)
        .await
        .map(|info| info.created_by);
    let proxy_outcome = proxy_ws_guacd(
        session_id,
        ws,
        guacd_stream,
        recording_file,
        cancel,
        manager.clone(),
        database,
        session_user,
    )
    .await;
    let elapsed = start.elapsed();
    let server_disconnected = proxy_outcome.server_disconnected;
    let proxy_result = proxy_outcome.result;
    let guacd_error = proxy_outcome.guacd_error;

    manager.disconnect_viewer(session_id).await;

    // Log termination direction and timing
    let mark_error = match &proxy_result {
        ProxyResult::GuacdEnded(err) => {
            if elapsed.as_secs() < 5 {
                tracing::warn!(
                    session_id = %session_id, client_ip = %client_addr,
                    elapsed_ms = elapsed.as_millis() as u64,
                    error = ?err,
                    guacd_error = ?guacd_error,
                    "guacd closed connection quickly (possible connection failure)"
                );
                true // mark as error
            } else {
                tracing::info!(
                    session_id = %session_id, client_ip = %client_addr,
                    elapsed_secs = elapsed.as_secs(),
                    "Proxy ended: guacd closed connection"
                );
                false
            }
        }
        ProxyResult::BrowserEnded(err) => {
            tracing::info!(
                session_id = %session_id, client_ip = %client_addr,
                elapsed_secs = elapsed.as_secs(),
                error = ?err,
                "Proxy ended: browser disconnected"
            );
            false
        }
        ProxyResult::Cancelled => {
            tracing::info!(
                session_id = %session_id, client_ip = %client_addr,
                elapsed_secs = elapsed.as_secs(),
                "Proxy ended: session cancelled"
            );
            false
        }
    };

    let status_str;
    if mark_error {
        manager.error_session(session_id).await;
        status_str = "error";
    } else if server_disconnected {
        // Server-side end (user logout / crash) — terminal, cannot reconnect
        manager.complete_session(session_id).await;
        status_str = "completed";
    } else {
        // Browser disconnected or network drop — session stays in manager
        // for reconnection. Only set Disconnected if no more active connections.
        let info = manager.get_session(session_id).await;
        if let Some(info) = info {
            if info.active_connections == 0 {
                manager.disconnect_session(session_id).await;
                status_str = "disconnected";
            } else {
                status_str = "active";
            }
        } else {
            status_str = "completed";
        }
    }

    // VDI container lifecycle on session end
    if let Some((crate::session::SessionType::Vdi, Some(ref _cid), container_name)) =
        manager.get_vdi_info(session_id).await
    {
        if server_disconnected {
            // User logged out / session crashed → stop container immediately
            manager.stop_vdi_container(session_id).await;
            // Clean up session thumbnail
            let _ = tokio::fs::remove_file(manager.thumbnail_path(session_id)).await;
        } else {
            // Browser disconnect / network drop → container persists.
            // Copy session thumbnail to container-keyed file for the active desktops UI.
            let session_thumb = manager.thumbnail_path(session_id);
            if let Some(container_name) = container_name {
                let vdi_thumb = manager.vdi_thumbnail_path(&container_name);
                if session_thumb.exists() {
                    let _ = tokio::fs::copy(&session_thumb, &vdi_thumb).await;
                }
            }
        }
    }

    // Encrypt recording at rest (file is closed after proxy_ws_guacd returns).
    // Enterprise-gated — checked via the process-global handle since
    // this isn't an axum handler and can't take an `Extension<T>`.
    if is_recording_enabled && recording_path.exists() {
        let rec_config = manager.recording_config();
        let enc_key = manager.config().storage_encryption_key();
        if crate::recording::should_encrypt_at_rest(&rec_config, enc_key.as_deref()) {
            let licensed = crate::license::global()
                .map(|lm| lm.has_feature(crate::license::FEAT_ENCRYPTED_RECORDING))
                .unwrap_or(false);
            if !licensed {
                tracing::warn!(
                    session_id = %session_id,
                    "Recording encryption at rest is configured but requires an enterprise license — this recording was saved unencrypted"
                );
            } else if let Some(ref key_hex) = enc_key {
                if let Err(e) = crate::recording::encrypt_recording_file(&recording_path, key_hex) {
                    tracing::error!(
                        session_id = %session_id, error = %e,
                        "Failed to encrypt recording at rest"
                    );
                }
            }
        }
    }

    // Record session end in history
    manager.end_session_history(
        session_id,
        status_str,
        elapsed.as_secs(),
        is_recording_enabled,
    );

    // Per-entry recording rotation (after session ends, recording file is complete)
    if is_recording_enabled {
        if let Some((Some(entry_key), Some(max_recs))) =
            manager.get_recording_meta(session_id).await
        {
            if max_recs > 0 {
                let rec_dir = manager.recording_path().to_path_buf();
                tokio::task::spawn_blocking(move || {
                    crate::recording::rotate_per_entry(&rec_dir, &entry_key, max_recs);
                });
            }
        }
    }

    tracing::info!(session_id = %session_id, client_ip = %client_addr, "Session disconnected");
}

/// Bidirectional proxy between WebSocket and guacd stream (TCP or TLS).
async fn proxy_ws_guacd(
    session_id: Uuid,
    ws: WebSocket,
    guacd: GuacdStream,
    recording_file: Option<tokio::fs::File>,
    cancel: CancellationToken,
    manager: Arc<crate::session::SessionManager>,
    database: Option<Db>,
    session_user: Option<String>,
) -> ProxyOutcome {
    let (guacd_read, guacd_write) = tokio::io::split(guacd);
    let (ws_write, ws_read) = ws.split();

    let recording = recording_file.map(|f| Arc::new(tokio::sync::Mutex::new(f)));

    // Shared flag: set by guacd_to_ws when it sees `10.disconnect;` in the stream
    let server_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Captured message from guacd's `error` instruction, if any.
    let guacd_error = Arc::new(tokio::sync::Mutex::new(None::<String>));

    // The WebSocket sink is shared so both halves can write to it. The browser →
    // guacd side needs to echo `0.,4.ping,...` instructions back to the client
    // (Apache webapp parity), without ever forwarding them to guacd.
    let ws_sink = Arc::new(tokio::sync::Mutex::new(ws_write));

    // In-flight file transfers shared by both directions so uploads (tracked
    // browser → guacd) can be failed by guacd's error acks (guacd → browser)
    // and vice versa. Stream indices are connection-global, so the key space
    // never collides.
    let pending_transfers = Arc::new(tokio::sync::Mutex::new(
        HashMap::<i64, PendingTransfer>::new(),
    ));

    // guacd → browser (also tee to recording)
    let recording_clone = recording.clone();
    let sd_flag = server_disconnected.clone();
    let ws_sink_g = ws_sink.clone();
    let err_flag = guacd_error.clone();
    let pending_g = pending_transfers.clone();
    let db_g = database.clone();
    let user_g = session_user.clone();
    let guacd_to_browser = tokio::spawn(async move {
        guacd_to_ws(
            session_id,
            guacd_read,
            ws_sink_g,
            recording_clone,
            sd_flag,
            err_flag,
            pending_g,
            db_g,
            user_g,
        )
        .await
    });

    // browser → guacd
    let ws_sink_b = ws_sink.clone();
    let pending_b = pending_transfers.clone();
    let db_b = database.clone();
    let user_b = session_user.clone();
    let browser_to_guacd = tokio::spawn(async move {
        ws_to_guacd(
            ws_read,
            guacd_write,
            ws_sink_b,
            session_id,
            manager,
            pending_b,
            db_b,
            user_b,
        )
        .await
    });

    // Wait for either direction to finish, or cancellation
    let result = tokio::select! {
        result = guacd_to_browser => {
            let err = match result {
                Ok(Err(e)) => Some(e.to_string()),
                Err(e) => Some(e.to_string()),
                _ => None,
            };
            ProxyResult::GuacdEnded(err)
        }
        result = browser_to_guacd => {
            let err = match result {
                Ok(Err(e)) => Some(e.to_string()),
                Err(e) => Some(e.to_string()),
                _ => None,
            };
            ProxyResult::BrowserEnded(err)
        }
        _ = cancel.cancelled() => {
            ProxyResult::Cancelled
        }
    };

    let guacd_err = guacd_error.lock().await.take();

    ProxyOutcome {
        result,
        server_disconnected: server_disconnected.load(std::sync::atomic::Ordering::Relaxed),
        guacd_error: guacd_err,
    }
}

type WsSink = Arc<tokio::sync::Mutex<futures_util::stream::SplitSink<WebSocket, Message>>>;

/// Maximum bytes the guacd-side carry buffer is allowed to grow to before
/// force-flushing without a clean instruction boundary. In practice guacd
/// instructions are tiny; this exists to bound memory if upstream sends
/// something pathological. 16 MiB is well above any real instruction.
const MAX_GUACD_CARRY: usize = 16 * 1024 * 1024;

/// Forward data from guacd to WebSocket, recording along the way.
///
/// The browser's Tunnel.js parser concatenates every Message::Text into a
/// single rolling buffer with no message-boundary semantics. If we send a
/// chunk that ends mid-instruction and `ws_to_guacd` then echoes a tunnel
/// ping over the shared sink, the ping bytes splice into the middle of the
/// in-flight instruction and the parser blows up with "Element terminator
/// of instruction was not ';' nor ','". To prevent that, every Message::Text
/// we emit ends at a true Guacamole instruction boundary; partial tail data
/// is held in `carry` until the next read completes it.
async fn guacd_to_ws(
    session_id: Uuid,
    mut guacd: tokio::io::ReadHalf<GuacdStream>,
    ws: WsSink,
    recording: Option<Arc<tokio::sync::Mutex<tokio::fs::File>>>,
    server_disconnected: Arc<std::sync::atomic::AtomicBool>,
    last_error: Arc<tokio::sync::Mutex<Option<String>>>,
    pending_transfers: Arc<tokio::sync::Mutex<HashMap<i64, PendingTransfer>>>,
    database: Option<Db>,
    session_user: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = vec![0u8; 65536];
    let mut carry = bytes::BytesMut::new();

    loop {
        let n = guacd.read(&mut buf).await?;
        if n == 0 {
            break;
        }

        let data = &buf[..n];

        // Recording captures the raw guacd stream regardless of buffering.
        if let Some(ref recording) = recording {
            let mut file = recording.lock().await;
            let _ = file.write_all(data).await;
        }

        carry.extend_from_slice(data);

        // Flush up to the last complete instruction boundary in the carry.
        // Anything past that is held over for the next read.
        let carry_data: bytes::BytesMut = match last_instruction_boundary(&carry) {
            Some(end) => carry.split_to(end),
            None if carry.len() > MAX_GUACD_CARRY => {
                tracing::warn!(
                    len = carry.len(),
                    cap = MAX_GUACD_CARRY,
                    "guacd carry exceeded cap; force-flushing without instruction boundary"
                );
                std::mem::take(&mut carry)
            }
            None => continue,
        };

        // The boundary scanner only advances over valid UTF-8, so this
        // String::from_utf8 should never fail in practice; defensive in
        // case a force-flush above happened mid-multibyte char.
        let text = String::from_utf8(carry_data.to_vec()).map_err(
            |e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("invalid UTF-8 from guacd: {}", e).into()
            },
        )?;

        // Capture guacd's `error` instructions (e.g. RDP negotiation failures
        // like "Server refused connection (wrong security type?)"). The
        // instruction is forwarded to the browser verbatim, but logging it
        // here gives the operator the reason in persea's own logs, and the
        // message is used as the disconnect reason when the proxy ends.
        let mut parser = crate::protocol::InstructionParser::new();
        for parsed in parser.receive(&text) {
            if let Ok(instr) = parsed {
                if instr.opcode == "error" {
                    // guacd encodes the error instruction as
                    // `error,<message>,<code>` (guac_protocol_send_error).
                    let message = instr
                        .args
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "unknown error".to_string());
                    let code = instr.args.get(1).cloned().unwrap_or_default();
                    tracing::warn!(
                        session_id = %session_id,
                        code = %code,
                        "guacd reported upstream error: {}", message
                    );
                    *last_error.lock().await = Some(message);
                } else if instr.opcode == "filesystem" {
                    // guacd exposed an SFTP session (SSH) or drive (RDP).
                    // Availability alone is not a transfer, so this is logged
                    // but not audited.
                    tracing::info!(
                        session_id = %session_id,
                        name = instr.args.get(1).map(String::as_str).unwrap_or("?"),
                        "guacd exposed a filesystem (SFTP or drive)"
                    );
                } else if matches!(
                    instr.opcode.as_str(),
                    "file" | "blob" | "ack" | "end" | "body"
                ) {
                    // Audit file-transfer activity (downloads delivered by
                    // guacd, uploads failed by guacd's error acks).
                    let mut pending = pending_transfers.lock().await;
                    for event in sniff_transfer_instruction(
                        &instr,
                        TransferDirection::GuacdToBrowser,
                        &mut pending,
                    ) {
                        emit_transfer_audit(
                            database.as_ref(),
                            session_id,
                            session_user.as_deref(),
                            event,
                        );
                    }
                }
            }
        }

        // Detect guacd-initiated disconnect (server-side logout/crash).
        // guacd sends "10.disconnect;" as the final instruction when the
        // remote server ends the session. Buffering at instruction boundary
        // means the disconnect appears intact in the flushed text, either
        // at the start or after a previous ";".
        if text.starts_with("10.disconnect;") || text.contains(";10.disconnect;") {
            server_disconnected.store(true, std::sync::atomic::Ordering::Relaxed);
        }

        let mut sink = ws.lock().await;
        sink.send(Message::Text(text.into())).await?;
    }

    Ok(())
}

/// Forward data from WebSocket to guacd, intercepting empty-opcode tunnel
/// pings. The Guacamole client sends `0.,4.ping,<ts>;` every 500ms over the
/// "internal data" opcode (the empty string) to keep the tunnel from going
/// UNSTABLE. Apache's webapp echoes these back without ever forwarding them
/// to guacd; guacd silently drops unknown opcodes (libguac/user-handlers.c
/// `__guac_user_call_opcode_handler`), so without echoing here the client
/// would mark the tunnel UNSTABLE after 1.5s of guacd quiet time and close
/// it after 15s. We mirror Apache's filter behaviour.
async fn ws_to_guacd(
    mut ws_read: futures_util::stream::SplitStream<WebSocket>,
    mut guacd: tokio::io::WriteHalf<GuacdStream>,
    ws_sink: WsSink,
    session_id: Uuid,
    manager: Arc<crate::session::SessionManager>,
    pending_transfers: Arc<tokio::sync::Mutex<HashMap<i64, PendingTransfer>>>,
    database: Option<Db>,
    session_user: Option<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    /// Maximum allowed WebSocket message size (64 MiB).
    const MAX_WS_MSG_SIZE: usize = 64 * 1024 * 1024;

    while let Some(msg) = ws_read.next().await {
        let msg = msg?;
        match msg {
            Message::Text(text) => {
                if text.len() > MAX_WS_MSG_SIZE {
                    tracing::warn!(
                        len = text.len(),
                        limit = MAX_WS_MSG_SIZE,
                        "WebSocket message exceeds size limit, closing connection"
                    );
                    break;
                }
                // Empty-opcode instructions always start with "0.," — fast
                // path skips the parse for normal traffic.
                if text.starts_with("0.,") {
                    if let Ok(instr) = Instruction::parse(text.trim_end_matches(';')) {
                        if instr.opcode.is_empty() {
                            // Echo ping requests; drop everything else on the
                            // internal channel.
                            if instr.args.first().map(|s| s.as_str()) == Some("ping") {
                                let echo = Instruction::new("", instr.args).encode();
                                let mut sink = ws_sink.lock().await;
                                sink.send(Message::Text(echo.into())).await?;
                            }
                            continue;
                        }
                    }
                }

                // Log clipboard instructions from browser → guacd
                if text.contains(".clipboard,") {
                    tracing::info!("browser sent clipboard instruction to guacd");
                }

                // Audit file-transfer activity (uploads browser → guacd, and
                // downloads failed by the browser's error acks). Only parsed
                // when the message might carry a transfer instruction.
                if text.contains("file,")
                    || text.contains("blob,")
                    || text.contains("ack,")
                    || text.contains("end,")
                {
                    let mut parser = crate::protocol::InstructionParser::new();
                    for parsed in parser.receive(&text) {
                        if let Ok(instr) = parsed {
                            if matches!(instr.opcode.as_str(), "file" | "blob" | "ack" | "end") {
                                let mut pending = pending_transfers.lock().await;
                                for event in sniff_transfer_instruction(
                                    &instr,
                                    TransferDirection::BrowserToGuacd,
                                    &mut pending,
                                ) {
                                    emit_transfer_audit(
                                        database.as_ref(),
                                        session_id,
                                        session_user.as_deref(),
                                        event,
                                    );
                                }
                            }
                        }
                    }
                }

                // Real client activity (ping echoes `continue`d above), so
                // idle sessions are not reaped while the user is typing.
                // Server keepalive pings never reach this point.
                manager.update_activity(&session_id).await;
                guacd.write_all(text.as_bytes()).await?;
            }
            Message::Binary(data) => {
                if data.len() > MAX_WS_MSG_SIZE {
                    tracing::warn!(
                        len = data.len(),
                        limit = MAX_WS_MSG_SIZE,
                        "WebSocket binary message exceeds size limit, closing connection"
                    );
                    break;
                }
                continue;
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    Ok(())
}

/// Return true if the browser-supplied Origin and the request Host header
/// refer to the same hostname (ports stripped). Extracted for test.
///
/// If Origin is missing or empty, the request is **rejected** — WebSocket
/// upgrades without an Origin header are suspicious and likely from a
/// non-browser client or a CSWSH attack vector. The caller must still
/// ensure auth is enforced separately.
pub(crate) fn origin_host_matches(origin: &str, host: &str) -> bool {
    let origin_host = origin
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
        .split(':')
        .next()
        .unwrap_or("");
    let host_name = host.split(':').next().unwrap_or("");
    if host_name.is_empty() || origin_host.is_empty() {
        return false;
    }
    origin_host.eq_ignore_ascii_case(host_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_match_same_hostname_no_ports() {
        assert!(origin_host_matches(
            "https://console.example.com",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_match_ports_stripped() {
        assert!(origin_host_matches(
            "https://console.example.com:8443",
            "console.example.com:80"
        ));
        assert!(origin_host_matches("http://host.local:8080", "host.local"));
    }

    #[test]
    fn origin_match_trailing_slash_tolerated() {
        assert!(origin_host_matches(
            "https://console.example.com/",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_match_case_insensitive_hostname() {
        // DNS is case-insensitive; browsers can vary casing.
        assert!(origin_host_matches(
            "https://Console.Example.COM",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_mismatch_different_subdomain_rejected() {
        assert!(!origin_host_matches(
            "https://evil.example.com",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_mismatch_unrelated_host_rejected() {
        assert!(!origin_host_matches(
            "https://evil.attacker.io",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_empty_rejected() {
        // Missing Origin header is suspicious — reject to prevent CSWSH.
        assert!(!origin_host_matches("", "console.example.com"));
        assert!(!origin_host_matches("https://console.example.com", ""));
    }

    #[test]
    fn origin_mismatch_path_in_origin_ignored_by_host() {
        // An Origin with a path should never happen (spec forbids it) but
        // if it slips through, the split should not cause a match by
        // accident.
        assert!(!origin_host_matches(
            "https://evil.example.com/path",
            "console.example.com"
        ));
    }

    #[test]
    fn origin_mismatch_prefix_attack_rejected() {
        // `console.example.com.attacker.io` must NOT match
        // `console.example.com`. Split-on-`:` + exact compare handles this.
        assert!(!origin_host_matches(
            "https://console.example.com.attacker.io",
            "console.example.com"
        ));
    }

    #[test]
    fn base64_blob_len_counts_decoded_bytes() {
        assert_eq!(base64_blob_len("AAAAAA=="), 4); // 4 zero bytes
        assert_eq!(base64_blob_len(""), 0);
        assert_eq!(base64_blob_len("SGVsbG8="), 5); // "Hello"
    }

    #[test]
    fn sniff_upload_instructions_produce_event_with_size() {
        let mut pending = HashMap::new();
        let file = Instruction::new(
            "file",
            vec![
                "7".into(),
                "application/octet-stream".into(),
                "report.txt".into(),
            ],
        );
        assert!(
            sniff_transfer_instruction(&file, TransferDirection::BrowserToGuacd, &mut pending)
                .is_empty()
        );
        assert_eq!(pending.len(), 1);

        // "AAAAAA==" is 4 zero bytes
        let blob = Instruction::new("blob", vec!["7".into(), "AAAAAA==".into()]);
        assert!(
            sniff_transfer_instruction(&blob, TransferDirection::BrowserToGuacd, &mut pending)
                .is_empty()
        );

        let end = Instruction::new("end", vec!["7".into()]);
        let events =
            sniff_transfer_instruction(&end, TransferDirection::BrowserToGuacd, &mut pending);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferKind::Upload);
        assert_eq!(events[0].filename, "report.txt");
        assert_eq!(events[0].mimetype, "application/octet-stream");
        assert_eq!(events[0].size, 4);
        assert!(!events[0].error);
        assert!(pending.is_empty());
    }

    #[test]
    fn sniff_download_body_instructions_produce_event() {
        let mut pending = HashMap::new();
        let body = Instruction::new(
            "body",
            vec![
                "0".into(),
                "9".into(),
                "application/octet-stream".into(),
                "/home/user/file.zip".into(),
            ],
        );
        assert!(
            sniff_transfer_instruction(&body, TransferDirection::GuacdToBrowser, &mut pending)
                .is_empty()
        );
        assert!(pending.contains_key(&9));

        // Directory listings (stream-index mimetype) are not transfers.
        let dir = Instruction::new(
            "body",
            vec![
                "0".into(),
                "10".into(),
                "application/vnd.glyptodon.guacamole.stream-index+json".into(),
                "/home/user".into(),
            ],
        );
        assert!(
            sniff_transfer_instruction(&dir, TransferDirection::GuacdToBrowser, &mut pending)
                .is_empty()
        );
        assert!(!pending.contains_key(&10));

        let blob = Instruction::new("blob", vec!["9".into(), "AAAAAA==".into()]);
        sniff_transfer_instruction(&blob, TransferDirection::GuacdToBrowser, &mut pending);
        let end = Instruction::new("end", vec!["9".into()]);
        let events =
            sniff_transfer_instruction(&end, TransferDirection::GuacdToBrowser, &mut pending);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferKind::Download);
        assert_eq!(events[0].filename, "file.zip");
        assert_eq!(events[0].size, 4);
        assert!(!events[0].error);
    }

    #[test]
    fn sniff_guacd_file_push_instruction_produces_download_event() {
        // RDP drive pushes / SSH terminal-triggered downloads arrive as
        // `file,<idx>,<mimetype>,<filename>` from guacd.
        let mut pending = HashMap::new();
        let file = Instruction::new(
            "file",
            vec![
                "12".into(),
                "application/octet-stream".into(),
                "screenshot.png".into(),
            ],
        );
        assert!(
            sniff_transfer_instruction(&file, TransferDirection::GuacdToBrowser, &mut pending)
                .is_empty()
        );
        let end = Instruction::new("end", vec!["12".into()]);
        let events =
            sniff_transfer_instruction(&end, TransferDirection::GuacdToBrowser, &mut pending);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferKind::Download);
        assert_eq!(events[0].filename, "screenshot.png");
        assert!(!events[0].error);
    }

    #[test]
    fn sniff_upload_failed_by_guacd_ack() {
        let mut pending = HashMap::new();
        let file = Instruction::new(
            "file",
            vec![
                "7".into(),
                "application/octet-stream".into(),
                "x.bin".into(),
            ],
        );
        sniff_transfer_instruction(&file, TransferDirection::BrowserToGuacd, &mut pending);

        // guacd rejects the upload stream with an error ack.
        let ack = Instruction::new(
            "ack",
            vec!["7".into(), "SFTP: Open failed".into(), "516".into()],
        );
        let events =
            sniff_transfer_instruction(&ack, TransferDirection::GuacdToBrowser, &mut pending);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferKind::Upload);
        assert!(events[0].error);
        assert_eq!(events[0].filename, "x.bin");
        assert!(pending.is_empty());

        // Success acks produce no event and keep the transfer tracked.
        let file2 = Instruction::new(
            "file",
            vec![
                "8".into(),
                "application/octet-stream".into(),
                "y.bin".into(),
            ],
        );
        sniff_transfer_instruction(&file2, TransferDirection::BrowserToGuacd, &mut pending);
        let ok_ack = Instruction::new("ack", vec!["8".into(), "SFTP: OK".into(), "0".into()]);
        assert!(sniff_transfer_instruction(
            &ok_ack,
            TransferDirection::GuacdToBrowser,
            &mut pending
        )
        .is_empty());
        assert!(pending.contains_key(&8));
    }

    #[test]
    fn sniff_download_failed_by_browser_ack() {
        let mut pending = HashMap::new();
        let body = Instruction::new(
            "body",
            vec![
                "0".into(),
                "9".into(),
                "application/octet-stream".into(),
                "/data/secret.db".into(),
            ],
        );
        sniff_transfer_instruction(&body, TransferDirection::GuacdToBrowser, &mut pending);
        // The browser aborts the download.
        let ack = Instruction::new(
            "ack",
            vec!["9".into(), "Client aborted".into(), "776".into()],
        );
        let events =
            sniff_transfer_instruction(&ack, TransferDirection::BrowserToGuacd, &mut pending);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, TransferKind::Download);
        assert!(events[0].error);
        assert_eq!(events[0].filename, "secret.db");
        assert!(pending.is_empty());
    }

    #[test]
    fn sniff_ignores_unrelated_and_wrong_direction_instructions() {
        let mut pending = HashMap::new();
        // `end` for an unknown stream.
        let end = Instruction::new("end", vec!["77".into()]);
        assert!(
            sniff_transfer_instruction(&end, TransferDirection::GuacdToBrowser, &mut pending)
                .is_empty()
        );
        // Unrelated opcodes.
        let key = Instruction::new("key", vec!["1".into(), "113".into()]);
        assert!(
            sniff_transfer_instruction(&key, TransferDirection::BrowserToGuacd, &mut pending)
                .is_empty()
        );
        assert!(pending.is_empty());
    }
}
