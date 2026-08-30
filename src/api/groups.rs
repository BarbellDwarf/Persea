//! Admin API for local group management.
//!
//! Routes (registered by the orchestrator in `src/main.rs`; all admin-only):
//!
//! * `GET    /api/admin/groups`               — list local groups
//! * `POST   /api/admin/groups`               — create `{name, description?}`
//! * `GET    /api/admin/groups/{id}`          — group + its mappings + known groups
//! * `PUT    /api/admin/groups/{id}`          — update `{name?, description?}`
//! * `DELETE /api/admin/groups/{id}`          — delete group + its mappings
//! * `POST   /api/admin/groups/{id}/mappings` — `{provider_group}`
//! * `DELETE /api/admin/groups/{id}/mappings/{mapping_id}`
//!
//! Data model: `local_groups` (id, name UNIQUE, description) plus
//! `group_mappings` (provider-group name → local group id; one provider group
//! maps to at most one local group). Folder `allowed_groups` reference local
//! groups by *name* as free-form strings (vault `FolderConfig` and
//! `address_book_entries.allowed_groups`) — deleting a group removes its
//! `group_mappings` rows but leaves folder `allowed_groups` untouched, so
//! anyone whose claims carry that name keeps access.

use crate::audit;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};

/// Body for `POST /api/admin/groups`.
#[derive(Deserialize)]
pub struct CreateGroupRequest {
    /// Unique group name.
    pub name: String,
    /// Optional free-text description.
    #[serde(default)]
    pub description: String,
}

/// Body for `PUT /api/admin/groups/{id}`.
#[derive(Deserialize)]
pub struct UpdateGroupRequest {
    /// New name when renaming.
    pub name: Option<String>,
    /// New description when changing it.
    pub description: Option<String>,
}

/// Body for `POST /api/admin/groups/{id}/mappings`.
#[derive(Deserialize)]
pub struct CreateMappingRequest {
    /// Auth-provider group name to map to the local group.
    pub provider_group: String,
}

/// Admin-only gate shared by every handler in this module (users.rs pattern).
fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    if identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        Ok(())
    } else {
        Err(AppError::Forbidden("admin role required".into()))
    }
}

/// Fire-and-forget audit event for a config change, mirroring users.rs.
pub(crate) async fn audit_config_change(
    database: &Db,
    identity: &Option<Extension<AuthIdentity>>,
    details: Value,
) {
    let admin_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_default();
    audit::fire(
        database,
        Some(&admin_name),
        "admin.config.change",
        "success",
        details,
        None,
        None,
    )
    .await;
}

/// Map a rusqlite error: UNIQUE violations become 409, everything else 500.
fn map_group_conflict(e: &rusqlite::Error) -> AppError {
    use rusqlite::ErrorCode;
    if matches!(
        e,
        rusqlite::Error::SqliteFailure(ref f, _)
            if f.code == ErrorCode::ConstraintViolation
    ) {
        AppError::Conflict("a group with this name already exists".into())
    } else {
        AppError::Internal(e.to_string())
    }
}

/// GET /api/admin/groups — list local groups with usage counts.
pub async fn list_groups(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let groups = tokio::task::spawn_blocking(move || db::list_local_groups(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!({ "groups": groups })))
}

/// POST /api/admin/groups — create a local group. 201 on success.
pub async fn create_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    require_admin(&identity)?;

    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Validation("group name must not be empty".into()));
    }
    if name.contains(',') {
        return Err(AppError::Validation(
            "group name must not contain commas".into(),
        ));
    }

    let db_clone = database.clone();
    let name_for_db = name.clone();
    let description = req.description.clone();
    let group = tokio::task::spawn_blocking(move || {
        db::create_local_group(&db_clone, &name_for_db, &description)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| map_group_conflict(&e))?;

    audit_config_change(
        &database,
        &identity,
        json!({"action": "create_group", "name": name}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!(group))))
}

/// GET /api/admin/groups/{id} — group, its mappings, and the known-groups
/// list (from `/api/auth/known-groups`) merged with mapping status.
pub async fn get_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let group = tokio::task::spawn_blocking(move || db::get_local_group(&db_clone, id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Session("group not found".into()))?;

    let db_clone = database.clone();
    let (mappings, known, all_mappings, all_groups) = tokio::task::spawn_blocking(move || {
        let mappings = db::list_provider_group_mappings(&db_clone, Some(id))?;
        let known = db::list_known_groups(&db_clone)?;
        let all_mappings = db::list_provider_group_mappings(&db_clone, None)?;
        let all_groups = db::list_local_groups(&db_clone)?;
        Ok::<_, rusqlite::Error>((mappings, known, all_mappings, all_groups))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let name_by_id: std::collections::HashMap<i64, String> =
        all_groups.iter().map(|g| (g.id, g.name.clone())).collect();
    let known_groups: Vec<Value> = known
        .iter()
        .map(|name| {
            let mapped = all_mappings.iter().find(|m| &m.provider_group == name);
            json!({
                "name": name,
                "mapped": mapped.is_some(),
                "group_id": mapped.map(|m| m.group_id),
                "group_name": mapped.and_then(|m| name_by_id.get(&m.group_id)).cloned(),
            })
        })
        .collect();

    Ok(Json(json!({
        "group": group,
        "mappings": mappings,
        "known_groups": known_groups,
    })))
}

/// PUT /api/admin/groups/{id} — rename / re-describe a local group.
pub async fn update_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateGroupRequest>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let name = req.name.as_ref().map(|n| n.trim().to_string());
    if let Some(ref n) = name {
        if n.is_empty() {
            return Err(AppError::Validation("group name must not be empty".into()));
        }
        if n.contains(',') {
            return Err(AppError::Validation(
                "group name must not contain commas".into(),
            ));
        }
    }

    // If renaming, check that the old name isn't referenced in any folder/entry ACLs.
    if let Some(ref new_name) = name {
        let db_clone = database.clone();
        let current = tokio::task::spawn_blocking(move || db::get_local_group(&db_clone, id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(current) = current {
            if current.name != *new_name {
                let db_clone = database.clone();
                let old_name = current.name.clone();
                let refs = tokio::task::spawn_blocking(move || {
                    db::count_group_name_references(&db_clone, &old_name)
                })
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
                .map_err(|e| AppError::Internal(e.to_string()))?;
                if refs > 0 {
                    return Err(AppError::Conflict(format!(
                        "Group is referenced by {} folder/entry ACL(s); remove references before renaming",
                        refs,
                    )));
                }
            }
        }
    }

    let db_clone = database.clone();
    let name_for_db = name.clone();
    let description = req.description.clone();
    let group = tokio::task::spawn_blocking(move || {
        db::update_local_group(
            &db_clone,
            id,
            name_for_db.as_deref(),
            description.as_deref(),
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| map_group_conflict(&e))?
    .ok_or_else(|| AppError::Session("group not found".into()))?;

    audit_config_change(
        &database,
        &identity,
        json!({"action": "update_group", "id": id, "name": group.name}),
    )
    .await;
    Ok(Json(json!(group)))
}

/// DELETE /api/admin/groups/{id} — delete the group and its provider-group
/// mappings. Folder `allowed_groups` referencing the group's name are left
/// untouched (names are free-form strings). The response reports how many
/// mappings were removed.
pub async fn delete_group(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let mappings_removed =
        tokio::task::spawn_blocking(move || db::delete_local_group(&db_clone, id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(e.to_string()))?
            .ok_or_else(|| AppError::Session("group not found".into()))?;

    audit_config_change(
        &database,
        &identity,
        json!({"action": "delete_group", "id": id, "mappings_removed": mappings_removed}),
    )
    .await;
    Ok(Json(
        json!({ "ok": true, "mappings_removed": mappings_removed }),
    ))
}

/// POST /api/admin/groups/{id}/mappings — map an auth-provider group to this
/// local group. Any existing mapping for the same provider group is replaced
/// (one provider group maps to one local group). 201 on success.
pub async fn add_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(req): Json<CreateMappingRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    require_admin(&identity)?;

    let provider_group = req.provider_group.trim().to_string();
    if provider_group.is_empty() {
        return Err(AppError::Validation(
            "provider_group must not be empty".into(),
        ));
    }

    let db_clone = database.clone();
    let pg_for_db = provider_group.clone();
    let mapping = tokio::task::spawn_blocking(move || -> Result<_, AppError> {
        if db::get_local_group(&db_clone, id)?.is_none() {
            return Err(AppError::Session("group not found".into()));
        }
        db::create_provider_group_mapping(&db_clone, id, &pg_for_db).map_err(|e| {
            if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                AppError::Session("group not found".into())
            } else {
                AppError::Internal(e.to_string())
            }
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    audit_config_change(
        &database,
        &identity,
        json!({
            "action": "add_group_mapping",
            "group_id": id,
            "provider_group": provider_group,
        }),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!(mapping))))
}

/// DELETE /api/admin/groups/{id}/mappings/{mapping_id} — remove a mapping.
/// 204 on success; 404 if the mapping doesn't exist on this group.
pub async fn remove_group_mapping(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((id, mapping_id)): Path<(i64, i64)>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let deleted = tokio::task::spawn_blocking(move || -> Result<bool, AppError> {
        let mappings = db::list_provider_group_mappings(&db_clone, Some(id))?;
        if !mappings.iter().any(|m| m.id == mapping_id) {
            return Ok(false);
        }
        db::delete_provider_group_mapping(&db_clone, mapping_id)
            .map_err(|e| AppError::Internal(e.to_string()))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;
    if !deleted {
        return Err(AppError::Session("mapping not found".into()));
    }

    audit_config_change(
        &database,
        &identity,
        json!({"action": "remove_group_mapping", "group_id": id, "mapping_id": mapping_id}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
