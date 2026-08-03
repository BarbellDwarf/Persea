use super::AppState;
use crate::audit;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::session::CreateSessionRequest;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Deserialize, Default)]
pub struct ListSessionsQuery {
    #[serde(default)]
    pub all: bool,
}

#[derive(Deserialize)]
pub struct BannerQuery {
    pub token: String,
}

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

    if let Some(ref id) = identity {
        if !id.has_role("poweruser") {
            return Err(AppError::Forbidden(
                "insufficient permissions — poweruser role required for ad-hoc sessions".into(),
            ));
        }
    }

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);

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
                req.proxmox_node.as_deref().unwrap_or("?"),
                req.proxmox_vmid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        }
        crate::session::SessionType::Web => req.url.as_deref().unwrap_or("?").to_string(),
        crate::session::SessionType::Vdi => {
            req.container_image.as_deref().unwrap_or("?").to_string()
        }
    };

    tracing::info!(
        admin = %admin_name,
        client_ip = %client_ip,
        session_type = ?req.session_type,
        target = %target,
        "Session creation requested"
    );

    match manager.create_session(req, admin_name.clone()).await {
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

fn redact_share_url(
    mut info: crate::session::SessionInfo,
    identity: &Option<Extension<AuthIdentity>>,
) -> crate::session::SessionInfo {
    let is_owner_or_admin = match identity {
        Some(Extension(id)) => id.has_role("admin") || id.display_name() == info.created_by,
        None => false,
    };
    if !is_owner_or_admin {
        info.share_url = None;
    }
    info
}

pub async fn list_sessions(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    axum::extract::Query(q): axum::extract::Query<ListSessionsQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let is_admin = identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false);
    let owner = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string());
    let show_all = q.all && is_admin;

    let sessions: Vec<_> = manager
        .list_sessions()
        .await
        .into_iter()
        .filter(|s| show_all || owner.as_deref().map(|o| s.created_by == o).unwrap_or(false))
        .map(|s| redact_share_url(s, &identity))
        .collect();
    Ok(Json(json!(sessions)))
}

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
                .map(|Extension(id)| info.created_by == id.display_name())
                .unwrap_or(false);
            if !is_admin && !is_owner {
                return Err(AppError::Session("session not found".into()));
            }
            let info = redact_share_url(info, &identity);
            Ok(Json(json!(info)))
        }
        None => Err(AppError::Session("session not found".into())),
    }
}

pub async fn delete_session(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);

    let id_inner = match identity {
        Some(Extension(ref id_inner)) => id_inner,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "authentication required"})),
            )
                .into_response();
        }
    };

    if !id_inner.has_role("operator") {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "insufficient permissions — operator role required"})),
        )
            .into_response();
    }

    if !id_inner.has_role("admin") {
        if let Some(creator) = manager.get_session_creator(id).await {
            if creator != id_inner.display_name() {
                return (
                    StatusCode::FORBIDDEN,
                    Json(json!({"error": "you can only delete your own sessions"})),
                )
                    .into_response();
            }
        }
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
            let user_id = id_inner.display_name().to_string();
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
        StatusCode::NO_CONTENT.into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "session not found" })),
        )
            .into_response()
    }
}

pub(crate) fn is_jpeg_magic(body: &[u8]) -> bool {
    body.len() >= 3 && body[0] == 0xFF && body[1] == 0xD8 && body[2] == 0xFF
}

/// Maximum thumbnail body size in bytes (100 KiB).
const MAX_THUMBNAIL_BODY_LEN: usize = 100_000;

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
        .map(|Extension(id)| info.created_by == id.display_name())
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
        .map(|Extension(id)| info.created_by == id.display_name())
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

    let admin_email = id_inner.display_name().to_string();
    let (raw, expires_at) = manager
        .mint_shadow_token(id, &admin_email)
        .await
        .ok_or_else(|| AppError::Session("session not found".into()))?;

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

    let current_user = id
        .display_name()
        .split('@')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();

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
    let current_user = id
        .display_name()
        .split('@')
        .next()
        .unwrap_or("")
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    let owns = !current_user.is_empty()
        && (name == format!("rustguac-vdi-{}", current_user)
            || name.starts_with(&format!("rustguac-vdi-{}-", current_user)));
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
        Some(info) => Ok(Json(json!({ "banner": info.banner }))),
        None => Err(AppError::Session("session not found".into())),
    }
}
