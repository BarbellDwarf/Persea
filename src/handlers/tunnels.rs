use axum::extract::{Extension, Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::AppState;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;

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

fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(()),
        _ => Err(AppError::Forbidden("admin role required".into())),
    }
}

pub async fn list_jump_hosts(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<Vec<crate::db::JumpHostRecord>>, AppError> {
    require_admin(&identity)?;
    let hosts = crate::db::list_jump_hosts(&db).map_err(|e| {
        tracing::error!(error = %e, "failed to list jump hosts");
        AppError::Internal("failed to list jump hosts".into())
    })?;
    Ok(Json(hosts))
}

pub async fn create_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Json(input): Json<CreateJumpHost>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
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
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "id": id })),
    ))
}

pub async fn update_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
    Json(input): Json<UpdateJumpHost>,
) -> Result<StatusCode, AppError> {
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

pub async fn delete_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<StatusCode, AppError> {
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

pub async fn test_jump_host(
    State(_state): State<AppState>,
    Extension(db): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
    Path(id): Path<String>,
) -> Result<Json<TestResult>, AppError> {
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

pub async fn list_active_tunnels(
    State(_state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    require_admin(&identity)?;
    Ok(Json(vec![]))
}
