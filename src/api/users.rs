use super::{VaultConfigured, VaultState};
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateGroupMappingRequest {
    pub group: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct UpdateGroupMappingRequest {
    pub group: String,
    pub role: String,
}

pub async fn list_users(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return Err(AppError::Forbidden("admin role required".into()));
        }
    }

    let db_clone = database.clone();
    let users = tokio::task::spawn_blocking(move || db::list_users(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(users)))
}

pub async fn set_user_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return Err(AppError::Forbidden("admin role required".into()));
        }
    }

    if !crate::auth::is_valid_role(&req.role) {
        return Err(AppError::Internal(
            "role must be admin, poweruser, operator, or viewer".into(),
        ));
    }

    let db_clone = database.clone();
    let role = req.role.clone();
    let found = tokio::task::spawn_blocking(move || db::set_user_role(&db_clone, &email, &role))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("user not found".into()))
    }
}

pub async fn delete_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> impl IntoResponse {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response();
        }
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::delete_user(&db_clone, &email)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to delete user"})),
        )
            .into_response(),
    }
}

pub async fn delete_user_sessions(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Session("user not found".into()))?;

    let db_clone = database.clone();
    let user_id = user.id;
    let count =
        tokio::task::spawn_blocking(move || db::delete_user_sessions(&db_clone, user_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    tracing::info!(email = %email, sessions_revoked = count, "Admin force-logout user");
    Ok(Json(json!({"ok": true, "sessions_revoked": count})))
}

pub async fn me(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(vault_configured): Extension<VaultConfigured>,
) -> Result<Json<serde_json::Value>, AppError> {
    match identity {
        Some(Extension(id)) => {
            let vault_available = vault.any_connected().await;
            Ok(Json(json!({
                "name": id.display_name(),
                "role": id.role(),
                "groups": id.groups(),
                "vault_enabled": vault_available,
                "vault_configured": vault_configured.0,
            })))
        }
        None => Err(AppError::Auth("not authenticated".into())),
    }
}

pub async fn disable_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let found = tokio::task::spawn_blocking(move || db::disable_user(&db_clone, &email))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("user not found".into()))
    }
}

pub async fn enable_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let found = tokio::task::spawn_blocking(move || db::enable_user(&db_clone, &email))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("user not found".into()))
    }
}

pub async fn list_group_mappings(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let mappings = tokio::task::spawn_blocking(move || db::list_group_mappings(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(mappings)))
}

pub async fn list_known_groups(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let groups = tokio::task::spawn_blocking(move || db::list_known_groups(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!({ "groups": groups })))
}

pub async fn create_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateGroupMappingRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if !crate::auth::is_valid_role(&req.role) {
        return Err(AppError::Internal(
            "role must be admin, poweruser, operator, or viewer".into(),
        ));
    }

    let db_clone = database.clone();
    let mapping = tokio::task::spawn_blocking(move || {
        db::create_group_mapping(&db_clone, &req.group, &req.role)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE") {
            AppError::Conflict("mapping for this group already exists".into())
        } else {
            AppError::Internal(msg)
        }
    })?;
    Ok(Json(json!(mapping)))
}

pub async fn update_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupMappingRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if !crate::auth::is_valid_role(&req.role) {
        return Err(AppError::Internal(
            "role must be admin, poweruser, operator, or viewer".into(),
        ));
    }

    let db_clone = database.clone();
    let found = tokio::task::spawn_blocking(move || {
        db::update_group_mapping(&db_clone, id, &req.group, &req.role)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE") {
            AppError::Conflict("mapping for this group already exists".into())
        } else {
            AppError::Internal(msg)
        }
    })?;
    if found {
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("mapping not found".into()))
    }
}

pub async fn delete_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "admin role required"})),
        )
            .into_response();
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::delete_group_mapping(&db_clone, id)).await {
        Ok(Ok(true)) => StatusCode::NO_CONTENT.into_response(),
        Ok(Ok(false)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "mapping not found"})),
        )
            .into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": "failed to delete mapping"})),
        )
            .into_response(),
    }
}
