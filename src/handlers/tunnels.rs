use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::AppState;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;

/// Request body for creating a jump host (POST /api/admin/jump-hosts).
#[derive(Deserialize)]
pub struct CreateJumpHost {
    /// Display name shown in the tunnel management UI.
    pub name: String,
    /// Hostname or IP address of the jump server.
    pub hostname: String,
    /// SSH port of the jump server; a value of 0 defaults to 22.
    pub port: u16,
    /// SSH login user on the jump server.
    pub username: String,
    /// Authentication method, "password" or "key"; the key variant
    /// requires `key_path`.
    pub auth_method: String,
    /// Path to a private key on this server, used when `auth_method` is
    /// "key".
    pub key_path: Option<String>,
}

/// Request body for updating a jump host (PUT /api/admin/jump-hosts/{id}).
///
/// The update replaces every field; values come from the same form that
/// creates a jump host.
#[derive(Deserialize)]
pub struct UpdateJumpHost {
    /// Display name shown in the tunnel management UI.
    pub name: String,
    /// Hostname or IP address of the jump server.
    pub hostname: String,
    /// SSH port of the jump server; a value of 0 defaults to 22.
    pub port: u16,
    /// SSH login user on the jump server.
    pub username: String,
    /// Authentication method, "password" or "key"; the key variant
    /// requires `key_path`.
    pub auth_method: String,
    /// Path to a private key on this server, used when `auth_method` is
    /// "key".
    pub key_path: Option<String>,
}

/// Result of a jump-host connectivity probe.
#[derive(Serialize)]
pub struct TestResult {
    /// Whether the TCP connection and SSH host-key exchange succeeded.
    pub ok: bool,
    /// Human-readable success detail, e.g. the host key fingerprint.
    pub message: Option<String>,
    /// Failure description when `ok` is false.
    pub error: Option<String>,
}

fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(()),
        _ => Err(AppError::Forbidden("admin role required".into())),
    }
}

/// Request-time gate: the jump-host/tunnel management API returns 404 when
/// the admin has turned `enable_ssh_tunnels` off (the routes stay mounted;
/// the check runs per request so a settings change applies without restart).
fn require_tunnels_enabled(db: &Db) -> Result<(), AppError> {
    if crate::settings_merge::read_toggle(db, "enable_ssh_tunnels", true) {
        Ok(())
    } else {
        Err(AppError::NotFound("SSH tunnels are disabled".into()))
    }
}

/// GET /api/admin/jump-hosts — list configured jump hosts.
///
/// Requires the admin role; returns 404 when the `enable_ssh_tunnels`
/// admin toggle is off and 403 for non-admins.
pub async fn list_jump_hosts(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<Vec<crate::db::JumpHostRecord>>, AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    let hosts = crate::db::list_jump_hosts(&db).map_err(|e| {
        tracing::error!(error = %e, "failed to list jump hosts");
        AppError::Internal("failed to list jump hosts".into())
    })?;
    Ok(Json(hosts))
}

/// POST /api/admin/jump-hosts — create a jump host.
///
/// Requires the admin role and a non-empty name, hostname, and username.
/// Returns 201 with the new record's id on success, 400 for missing
/// fields, 404 when tunnels are disabled, 403 for non-admins.
pub async fn create_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Json(input): Json<CreateJumpHost>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    if input.name.is_empty() || input.hostname.is_empty() || input.username.is_empty() {
        return Err(AppError::Validation(
            "name, hostname, and username are required".into(),
        ));
    }
    let port = if input.port == 0 { 22 } else { input.port };
    let id = crate::db::create_jump_host(
        &db,
        &input.name,
        &input.hostname,
        port,
        &input.username,
        &input.auth_method,
        input.key_path.as_deref(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to create jump host");
        AppError::Internal("failed to create jump host".into())
    })?;
    Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id }))))
}

/// PUT /api/admin/jump-hosts/{id} — replace a jump host's settings.
///
/// Requires the admin role. Returns 200 when the record was updated and
/// `Internal` when no record with that id exists.
pub async fn update_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
    Json(input): Json<UpdateJumpHost>,
) -> Result<StatusCode, AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    let updated = crate::db::update_jump_host(
        &db,
        &id,
        &input.name,
        &input.hostname,
        input.port,
        &input.username,
        &input.auth_method,
        input.key_path.as_deref(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "failed to update jump host");
        AppError::Internal("failed to update jump host".into())
    })?;
    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(AppError::Internal("jump host not found".into()))
    }
}

/// DELETE /api/admin/jump-hosts/{id} — remove a jump host.
///
/// Requires the admin role. Returns 204 when the record was deleted and
/// `Internal` when no record with that id exists.
pub async fn delete_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    let deleted = crate::db::delete_jump_host(&db, &id).map_err(|e| {
        tracing::error!(error = %e, "failed to delete jump host");
        AppError::Internal("failed to delete jump host".into())
    })?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Internal("jump host not found".into()))
    }
}

/// POST /api/admin/jump-hosts/{id}/test — probe a jump host.
///
/// Opens a TCP connection and exchanges SSH host keys, then returns the
/// fingerprint on success or the failure reason on error. Requires the
/// admin role.
pub async fn test_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    let host = crate::db::get_jump_host(&db, &id)
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get jump host");
            AppError::Internal("failed to get jump host".into())
        })?
        .ok_or_else(|| AppError::Internal("jump host not found".into()))?;

    let result = crate::tunnel::probe_host_key(&host.hostname, host.port).await;
    match result {
        Ok(fingerprint) => Ok(Json(TestResult {
            ok: true,
            message: Some(format!("Connected — host key: {}", fingerprint)),
            error: None,
        })),
        Err(e) => Ok(Json(TestResult {
            ok: false,
            message: None,
            error: Some(format!("{}", e)),
        })),
    }
}

/// GET /api/admin/tunnels/active — list currently open tunnels.
///
/// Requires the admin role. Returns an empty list for now; the endpoint
/// is reserved for live tunnel tracking.
pub async fn list_active_tunnels(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    require_tunnels_enabled(&db)?;
    require_admin(&identity)?;
    Ok(Json(vec![]))
}
