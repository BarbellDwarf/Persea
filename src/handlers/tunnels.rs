use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::AppState;
use crate::auth::AuthIdentity;
use crate::db::Db;

#[derive(Deserialize)]
pub struct CreateJumpHost {
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_path: Option<String>,
}

#[derive(Deserialize)]
pub struct UpdateJumpHost {
    pub name: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub auth_method: String,
    pub key_path: Option<String>,
}

#[derive(Serialize)]
pub struct TestResult {
    pub ok: bool,
    pub message: Option<String>,
    pub error: Option<String>,
}

/// Require admin role. Returns 403 if not admin.
fn require_admin(identity: &Option<axum::Extension<AuthIdentity>>) -> Result<(), StatusCode> {
    match identity {
        Some(axum::Extension(id)) if id.has_role("admin") => Ok(()),
        _ => Err(StatusCode::FORBIDDEN),
    }
}

/// GET /api/admin/jump-hosts
pub async fn list_jump_hosts(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    Extension(identity): Extension<AuthIdentity>,
) -> Result<Json<Vec<crate::db::JumpHostRecord>>, StatusCode> {
    let _ = identity;
    let hosts = crate::db::list_jump_hosts(&db).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(hosts))
}

/// POST /api/admin/jump-hosts
pub async fn create_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    Extension(identity): Extension<AuthIdentity>,
    Json(input): Json<CreateJumpHost>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    let _ = identity;
    if input.name.is_empty() || input.hostname.is_empty() || input.username.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
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
        tracing::warn!("Failed to create jump host: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id })),
    ))
}

/// PUT /api/admin/jump-hosts/{id}
pub async fn update_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    Extension(identity): Extension<AuthIdentity>,
    Path(id): Path<String>,
    Json(input): Json<UpdateJumpHost>,
) -> Result<StatusCode, StatusCode> {
    let _ = identity;
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
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// DELETE /api/admin/jump-hosts/{id}
pub async fn delete_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    Extension(identity): Extension<AuthIdentity>,
    Path(id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let _ = identity;
    let deleted =
        crate::db::delete_jump_host(&db, &id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

/// POST /api/admin/jump-hosts/{id}/test
pub async fn test_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    Extension(identity): Extension<AuthIdentity>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, StatusCode> {
    let _ = identity;
    let host = crate::db::get_jump_host(&db, &id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;

    // Attempt an SSH connection test
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

/// GET /api/admin/tunnels/active
pub async fn list_active_tunnels(
    State(_state): State<AppState>,
    Extension(identity): Extension<AuthIdentity>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let _ = identity;
    // Placeholder — active tunnel tracking is not yet wired to SessionManager
    Ok(Json(vec![]))
}
