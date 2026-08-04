//! RBAC management API endpoints.

use crate::audit;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;
use crate::rbac;
use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;

// ── Request types ──

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_id: i64,
}

#[derive(Deserialize)]
pub struct GrantPermissionRequest {
    pub entity_id: String,
    pub permission: String,
}

// ── Handlers ──

/// GET /api/admin/rbac/groups
pub async fn list_rbac_groups(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let groups = tokio::task::spawn_blocking(move || rbac::list_groups(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(groups)))
}

/// POST /api/admin/rbac/groups
pub async fn create_rbac_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let name = req.name.clone();
    let parent = req.parent_id.clone();
    let desc = req.description.clone();
    let group_id = tokio::task::spawn_blocking(move || {
        rbac::create_group(&db_clone, &name, parent.as_deref(), desc.as_deref())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let gname = req.name.clone();
        let gid = group_id.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "create_rbac_group",
                        "group_id": gid,
                        "name": gname,
                    }))
                    .build(),
            );
        })
        .await;
    }

    Ok(Json(json!({"id": group_id})))
}

/// DELETE /api/admin/rbac/groups/{id}
pub async fn delete_rbac_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(group_id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let gid = group_id.clone();
    let deleted = tokio::task::spawn_blocking(move || rbac::delete_group(&db_clone, &gid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "delete_rbac_group",
                        "group_id": group_id,
                    }))
                    .build(),
            );
        })
        .await;
    }

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Session("group not found".into()))
    }
}

/// POST /api/admin/rbac/groups/{id}/members
pub async fn add_group_member(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(group_id): Path<String>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let gid = group_id.clone();
    tokio::task::spawn_blocking(move || rbac::add_user_to_group(&db_clone, req.user_id, &gid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "add_group_member",
                        "group_id": group_id,
                        "member_user_id": req.user_id,
                    }))
                    .build(),
            );
        })
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/admin/rbac/groups/{id}/members/{user_id}
pub async fn remove_group_member(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((group_id, user_id)): Path<(String, i64)>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let gid = group_id.clone();
    tokio::task::spawn_blocking(move || rbac::remove_user_from_group(&db_clone, user_id, &gid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "remove_group_member",
                        "group_id": group_id,
                        "member_user_id": user_id,
                    }))
                    .build(),
            );
        })
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// GET /api/admin/rbac/connections/{id}/permissions
pub async fn list_connection_permissions(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(connection_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let cid = connection_id.clone();
    let perms =
        tokio::task::spawn_blocking(move || rbac::list_connection_permissions(&db_clone, &cid))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(perms)))
}

/// POST /api/admin/rbac/connections/{id}/permissions
pub async fn grant_connection_permission(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(connection_id): Path<String>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let permission = rbac::ObjectPermission::parse(&req.permission)
        .ok_or_else(|| AppError::Internal(format!("invalid permission: {}", req.permission)))?;

    let db_clone = database.clone();
    let cid = connection_id.clone();
    let eid = req.entity_id.clone();
    tokio::task::spawn_blocking(move || {
        rbac::grant_connection_permission(&db_clone, &eid, &cid, permission)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "grant_connection_permission",
                        "connection_id": connection_id,
                        "entity_id": req.entity_id,
                        "permission": req.permission,
                    }))
                    .build(),
            );
        })
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

/// DELETE /api/admin/rbac/connections/{id}/permissions
pub async fn revoke_connection_permission(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(connection_id): Path<String>,
    Json(req): Json<GrantPermissionRequest>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let permission = rbac::ObjectPermission::parse(&req.permission)
        .ok_or_else(|| AppError::Internal(format!("invalid permission: {}", req.permission)))?;

    let db_clone = database.clone();
    let cid = connection_id.clone();
    let eid = req.entity_id.clone();
    let revoked = tokio::task::spawn_blocking(move || {
        rbac::revoke_connection_permission(&db_clone, &eid, &cid, permission)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let db_audit = database.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(json!({
                        "action": "revoke_connection_permission",
                        "connection_id": connection_id,
                        "entity_id": req.entity_id,
                        "permission": req.permission,
                        "revoked": revoked,
                    }))
                    .build(),
            );
        })
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Helpers ──

fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(()),
        _ => Err(AppError::Forbidden("admin role required".into())),
    }
}
