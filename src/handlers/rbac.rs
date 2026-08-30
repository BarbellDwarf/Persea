//! RBAC management API endpoints.

use crate::audit;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;
use crate::rbac;
use axum::{extract::Path, http::StatusCode, response::IntoResponse, Extension, Json};
use serde::Deserialize;
use serde_json::json;

// ── Request types ──

/// Request body for creating an RBAC group
/// (POST /api/admin/rbac/groups).
#[derive(Deserialize)]
pub struct CreateGroupRequest {
    /// Group name; must be unique among groups.
    pub name: String,
    /// Id of the parent group when this group nests under another.
    #[serde(default)]
    pub parent_id: Option<String>,
    /// Free-form description shown in the admin UI.
    #[serde(default)]
    pub description: Option<String>,
}

/// Request body for adding a user to a group
/// (POST /api/admin/rbac/groups/{id}/members).
#[derive(Deserialize)]
pub struct AddMemberRequest {
    /// Database id of the user to add.
    pub user_id: i64,
}

/// Request body for granting or revoking a connection permission
/// (POST/DELETE /api/admin/rbac/connections/{id}/permissions).
#[derive(Deserialize)]
pub struct GrantPermissionRequest {
    /// Entity the permission applies to, "u:{user_id}" or "g:{group_id}";
    /// a bare id is treated as a user.
    pub entity_id: String,
    /// Permission name from the object-permission vocabulary
    /// (read, connect, update, delete, administer).
    pub permission: String,
}

/// Request body for creating a custom role (POST /api/admin/roles).
#[derive(Deserialize)]
pub struct CreateCustomRoleRequest {
    /// Role name; must be unique among custom roles.
    pub name: String,
    /// Free-form description shown in the admin UI.
    #[serde(default)]
    pub description: Option<String>,
    /// Permission strings from the fixed vocabulary (object perms
    /// read/connect/update/delete/administer + system perms
    /// create_session/create_connection/create_connection_group/audit).
    #[serde(default)]
    pub permissions: Vec<String>,
}

/// Request body for updating a custom role (PUT /api/admin/roles/{id}).
///
/// Omitted fields keep their current values.
#[derive(Deserialize)]
pub struct UpdateCustomRoleRequest {
    /// Replacement role name; None keeps the current name.
    #[serde(default)]
    pub name: Option<String>,
    /// Replacement description; None keeps the current description.
    #[serde(default)]
    pub description: Option<String>,
    /// Replacement permission list; None keeps the current list.
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "create_rbac_group",
                "group_id": &group_id,
                "name": &req.name,
            }),
            None,
            None,
        )
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "delete_rbac_group",
                "group_id": &group_id,
            }),
            None,
            None,
        )
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "add_group_member",
                "group_id": &group_id,
                "member_user_id": req.user_id,
            }),
            None,
            None,
        )
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "remove_group_member",
                "group_id": &group_id,
                "member_user_id": user_id,
            }),
            None,
            None,
        )
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "grant_connection_permission",
                "connection_id": &connection_id,
                "entity_id": &req.entity_id,
                "permission": &req.permission,
            }),
            None,
            None,
        )
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "revoke_connection_permission",
                "connection_id": &connection_id,
                "entity_id": &req.entity_id,
                "permission": &req.permission,
                "revoked": revoked,
            }),
            None,
            None,
        )
        .await;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Custom roles (T05) ──

/// The custom-role permission vocabulary: object permissions (global scope)
/// plus the system permissions. `create_user_group` and the system
/// `administer` are deliberately excluded — admins get those through the
/// admin role, and per-object grants cover the object `administer`.
fn is_custom_role_permission(s: &str) -> bool {
    rbac::ObjectPermission::parse(s).is_some()
        || (rbac::SystemPermission::parse(s).is_some() && s != "create_user_group")
}

/// Map a UNIQUE violation onto a 409 (name conflicts); anything else stays
/// an internal error.
fn map_role_conflict(e: rusqlite::Error) -> AppError {
    let msg = e.to_string();
    if msg.contains("UNIQUE") {
        AppError::Conflict("a custom role with this name already exists".into())
    } else {
        AppError::Internal(msg)
    }
}

fn validate_custom_role_permissions(permissions: &[String]) -> Result<(), AppError> {
    for p in permissions {
        if !is_custom_role_permission(p) {
            return Err(AppError::Validation(format!(
                "unknown permission '{p}' — expected one of: read, connect, update, delete, administer, create_session, create_connection, create_connection_group, audit"
            )));
        }
    }
    Ok(())
}

/// GET /api/admin/roles
pub async fn list_custom_roles(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let roles = tokio::task::spawn_blocking(move || rbac::list_custom_roles(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(roles)))
}

/// POST /api/admin/roles
pub async fn create_custom_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateCustomRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    validate_custom_role_permissions(&req.permissions)?;

    let db_clone = database.clone();
    let name = req.name.clone();
    let desc = req.description.clone();
    let perms = req.permissions.clone();
    let role_id = tokio::task::spawn_blocking(move || {
        rbac::create_custom_role(&db_clone, &name, desc.as_deref(), &perms)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(map_role_conflict)?;

    // Audit
    {
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "create_custom_role",
                "role_id": &role_id,
                "name": &req.name,
                "permissions": &req.permissions,
            }),
            None,
            None,
        )
        .await;
    }

    Ok(Json(json!({"id": role_id})))
}

/// GET /api/admin/roles/{id}
pub async fn get_custom_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(role_id): Path<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let rid = role_id.clone();
    let role = tokio::task::spawn_blocking(move || rbac::get_custom_role(&db_clone, &rid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    match role {
        Some(role) => Ok(Json(json!(role))),
        None => Err(AppError::NotFound("custom role not found".into())),
    }
}

/// PUT /api/admin/roles/{id}
pub async fn update_custom_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(role_id): Path<String>,
    Json(req): Json<UpdateCustomRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let rid = role_id.clone();
    // Read the existing role so omitted fields keep their current values.
    let existing = tokio::task::spawn_blocking(move || rbac::get_custom_role(&db_clone, &rid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    let existing = existing.ok_or(AppError::NotFound("custom role not found".into()))?;

    let name = req.name.clone().unwrap_or(existing.name.clone());
    let description = req
        .description
        .clone()
        .or_else(|| existing.description.clone());
    let permissions = req
        .permissions
        .clone()
        .unwrap_or(existing.permissions.clone());
    validate_custom_role_permissions(&permissions)?;

    let db_clone = database.clone();
    let rid = role_id.clone();
    let rname = name.clone();
    let rdesc = description.clone();
    let rperms = permissions.clone();
    let updated = tokio::task::spawn_blocking(move || {
        rbac::update_custom_role(&db_clone, &rid, &rname, rdesc.as_deref(), &rperms)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(map_role_conflict)?;
    if !updated {
        return Err(AppError::NotFound("custom role not found".into()));
    }

    // Audit
    {
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "update_custom_role",
                "role_id": &role_id,
                "name": &name,
                "permissions": &permissions,
            }),
            None,
            None,
        )
        .await;
    }

    Ok(Json(
        json!({"ok": true, "id": role_id, "name": name, "permissions": permissions}),
    ))
}

/// DELETE /api/admin/roles/{id}
///
/// The role's permission rows are cascaded away and every user referencing
/// it has `custom_role_id` set to NULL (both explicit and via the FK).
pub async fn delete_custom_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(role_id): Path<String>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let rid = role_id.clone();
    let deleted = tokio::task::spawn_blocking(move || rbac::delete_custom_role(&db_clone, &rid))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit
    {
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            Some(&admin_name),
            "admin.config.change",
            "success",
            json!({
                "action": "delete_custom_role",
                "role_id": &role_id,
            }),
            None,
            None,
        )
        .await;
    }

    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound("custom role not found".into()))
    }
}

// ── Admin page ──

/// GET /admin/roles.html — admin custom roles page (admin-only; the
/// template itself is the T06 admin/roles.html page).
pub async fn admin_roles_page(
    Extension(site_title): Extension<crate::api::SiteTitle>,
    Extension(theme): Extension<crate::api::ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<crate::CspNonce>,
) -> Result<axum::response::Response, AppError> {
    require_admin(&identity)?;
    let tmpl = crate::templates::AdminRolesTemplate {
        site_title: site_title.0.clone(),
        logo_url: theme.logo_url.clone().unwrap_or_default(),
        is_admin: true,
        active_page: "roles".to_string(),
        csp_nonce: nonce.0.clone(),
    };
    Ok(tmpl.into_response())
}

// ── Helpers ──

fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    match identity {
        Some(Extension(id)) if id.has_role("admin") => Ok(()),
        _ => Err(AppError::Forbidden("admin role required".into())),
    }
}
