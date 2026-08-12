use super::{VaultConfigured, VaultState};
use crate::audit;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct SetRoleRequest {
    pub role: String,
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: String,
    pub password: String,
    pub role: Option<String>,
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
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let users = tokio::task::spawn_blocking(move || db::list_users(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(users)))
}

pub async fn create_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    policy: Option<Extension<crate::password::PasswordPolicy>>,
    Json(body): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    // Password policy: minimum length enforced at creation, and the
    // new hash goes into the per-user reuse history. Handlers fall back to
    // the documented defaults when the extension is absent (test routers).
    let policy = policy.map(|Extension(p)| p).unwrap_or_default();
    policy
        .check_length(&body.password)
        .map_err(AppError::Validation)?;

    let role = body.role.unwrap_or_else(|| "viewer".to_string());
    let db_clone = database.clone();
    let email = body.email.clone();
    let name = body.name.clone();
    let password = body.password.clone();
    let role_clone = role.clone();

    tokio::task::spawn_blocking(move || {
        let password_hash = crate::password::hash_password(&password)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        db::create_user_with_password(
            &db_clone,
            &email,
            &name,
            &password_hash,
            &role_clone,
            "local",
        )
        .map_err(|e| AppError::Internal(e.to_string()))?;
        // Record the initial hash in the reuse history. The user row was
        // just inserted, so the lookup cannot fail in practice.
        if let Ok(user) = db::get_user_by_email(&db_clone, &email) {
            let _ = crate::password::record_password_history(
                &db_clone,
                user.id,
                &password_hash,
                policy.history,
            );
        }
        Ok::<_, AppError>(())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let role_for_response = role.clone();

    let admin_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_default();
    let email_audit = body.email.clone();
    let role_audit = role.clone();
    let db_audit = database.clone();
    tokio::task::spawn_blocking(move || {
        let _ = audit::log_event(
            &db_audit,
            &mut audit::EventBuilder::new("admin.user.create", "success")
                .user_id(&admin_name)
                .details(serde_json::json!({"email": email_audit, "role": role_audit}))
                .build(),
        );
    })
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(json!({"email": body.email, "role": role_for_response})),
    ))
}

pub async fn set_user_role(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if !crate::auth::is_valid_role(&req.role) {
        return Err(AppError::Internal(
            "role must be admin, poweruser, operator, or viewer".into(),
        ));
    }

    let db_clone = database.clone();
    let role = req.role.clone();
    // Fetch old role for audit before updating
    let old_role = {
        let db_for_read = database.clone();
        let email_clone = email.clone();
        tokio::task::spawn_blocking(move || {
            db::get_user_by_email(&db_for_read, &email_clone)
                .ok()
                .map(|u| u.role)
        })
        .await
        .unwrap_or(None)
    };
    let email_for_update = email.clone();
    let role_for_update = role.clone();
    let found = tokio::task::spawn_blocking(move || {
        db::set_user_role(&db_clone, &email_for_update, &role_for_update)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        // Audit: role change
        {
            let db_audit = database.clone();
            let email_audit = email.clone();
            let new_role = role.clone();
            let admin_name = identity
                .as_ref()
                .map(|id| id.display_name().to_string())
                .unwrap_or_default();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let _ = audit::log_event(
                    &db_audit,
                    &mut audit::EventBuilder::new("admin.role.change", "success")
                        .user_id(&admin_name)
                        .details(serde_json::json!({
                            "target_email": email_audit,
                            "old_role": old_role,
                            "new_role": new_role,
                        }))
                        .build(),
                );
            })
            .await
            {
                tracing::error!(error = %e, "audit task failed");
            }
        }
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("user not found".into()))
    }
}

pub async fn delete_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(email): Path<String>,
) -> Result<StatusCode, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let email_for_delete = email.clone();
    match tokio::task::spawn_blocking(move || db::delete_user(&db_clone, &email_for_delete)).await {
        Ok(Ok(true)) => {
            // Audit: user delete
            {
                let db_audit = database.clone();
                let email_audit = email.clone();
                let admin_name = identity
                    .as_ref()
                    .map(|id| id.display_name().to_string())
                    .unwrap_or_default();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("admin.user.delete", "success")
                            .user_id(&admin_name)
                            .details(serde_json::json!({"target_email": email_audit}))
                            .build(),
                    );
                })
                .await
                {
                    tracing::error!(error = %e, "audit task failed");
                }
            }
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(Ok(false)) => Err(AppError::Session("user not found".into())),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to delete user");
            Err(AppError::Internal("failed to delete user".into()))
        }
        Err(e) => {
            tracing::error!(error = %e, "Task panicked while deleting user");
            Err(AppError::Internal("Task panicked".into()))
        }
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
    let count = tokio::task::spawn_blocking(move || db::delete_user_sessions(&db_clone, user_id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    tracing::info!(email = %email, sessions_revoked = count, "Admin force-logout user");
    Ok(Json(json!({"ok": true, "sessions_revoked": count})))
}

pub async fn me(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Extension(vault_configured): Extension<VaultConfigured>,
) -> Result<Json<serde_json::Value>, AppError> {
    match identity {
        Some(Extension(id)) => {
            let vault_available = vault.any_connected().await;
            let email = match &id {
                AuthIdentity::ApiKey(name) => name.clone(),
                AuthIdentity::User { email, .. } => email.clone(),
            };
            let db_clone = database.clone();
            let email_clone = email.clone();
            let user_result = tokio::task::spawn_blocking(move || {
                db::get_user_by_email(&db_clone, &email_clone).ok()
            })
            .await
            .unwrap_or(None);
            let auth_source_clone = database.clone();
            let email_clone2 = email.clone();
            let auth_source = tokio::task::spawn_blocking(move || {
                db::get_user_auth_source(&auth_source_clone, &email_clone2)
            })
            .await
            .unwrap_or(Ok("unknown".to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
            let name = user_result
                .as_ref()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| id.display_name().to_string());
            let created_at = user_result.as_ref().map(|u| u.created_at.clone());
            Ok(Json(json!({
                "name": name,
                "email": email,
                "role": id.role(),
                "groups": id.groups(),
                "auth_source": auth_source,
                "vault_enabled": vault_available,
                "vault_configured": vault_configured.0,
                "created_at": created_at,
            })))
        }
        None => Err(AppError::Auth("not authenticated".into())),
    }
}

#[derive(Deserialize)]
pub struct UpdateMeRequest {
    pub name: String,
}

pub async fn update_me(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(body): Json<UpdateMeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => return Err(AppError::Auth("OIDC authentication required".into())),
    };

    let db_clone = database.clone();
    let email_clone = email.clone();
    let name = body.name.clone();
    let updated =
        tokio::task::spawn_blocking(move || db::update_user_name(&db_clone, &email_clone, &name))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    if !updated {
        return Err(AppError::Session("user not found".into()));
    }

    let db_clone2 = database.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone2, &email))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Session("user not found".into()))?;

    Ok(Json(json!({
        "name": user.name,
        "email": user.email,
        "created_at": user.created_at,
    })))
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
    let email_for_disable = email.clone();
    let found =
        tokio::task::spawn_blocking(move || db::disable_user(&db_clone, &email_for_disable))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        // Audit: user disable
        {
            let db_audit = database.clone();
            let email_audit = email.clone();
            let admin_name = identity
                .as_ref()
                .map(|id| id.display_name().to_string())
                .unwrap_or_default();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let _ = audit::log_event(
                    &db_audit,
                    &mut audit::EventBuilder::new("admin.user.disable", "success")
                        .user_id(&admin_name)
                        .details(serde_json::json!({"target_email": email_audit}))
                        .build(),
                );
            })
            .await
            {
                tracing::error!(error = %e, "audit task failed");
            }
        }
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
    let email_for_enable = email.clone();
    let found = tokio::task::spawn_blocking(move || db::enable_user(&db_clone, &email_for_enable))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        // Audit: user enable
        {
            let db_audit = database.clone();
            let email_audit = email.clone();
            let admin_name = identity
                .as_ref()
                .map(|id| id.display_name().to_string())
                .unwrap_or_default();
            if let Err(e) = tokio::task::spawn_blocking(move || {
                let _ = audit::log_event(
                    &db_audit,
                    &mut audit::EventBuilder::new("admin.user.enable", "success")
                        .user_id(&admin_name)
                        .details(serde_json::json!({"target_email": email_audit}))
                        .build(),
                );
            })
            .await
            {
                tracing::error!(error = %e, "audit task failed");
            }
        }
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
    let group_for_mapping = req.group.clone();
    let role_for_mapping = req.role.clone();
    let mapping = tokio::task::spawn_blocking(move || {
        db::create_group_mapping(&db_clone, &group_for_mapping, &role_for_mapping)
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
    // Audit: config change
    {
        let db_audit = database.clone();
        let group = req.group.clone();
        let role = req.role.clone();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .details(serde_json::json!({
                        "action": "create_group_mapping",
                        "group": group,
                        "role": role,
                    }))
                    .build(),
            );
        })
        .await
        {
            tracing::error!(error = %e, "audit task failed");
        }
    }
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
) -> Result<StatusCode, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    match tokio::task::spawn_blocking(move || db::delete_group_mapping(&db_clone, id)).await {
        Ok(Ok(true)) => {
            // Audit: config change
            {
                let db_audit = database.clone();
                let admin_name = identity
                    .as_ref()
                    .map(|id| id.display_name().to_string())
                    .unwrap_or_default();
                if let Err(e) = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("admin.config.change", "success")
                            .user_id(&admin_name)
                            .details(serde_json::json!({
                                "action": "delete_group_mapping",
                                "mapping_id": id,
                            }))
                            .build(),
                    );
                })
                .await
                {
                    tracing::error!(error = %e, "audit task failed");
                }
            }
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(Ok(false)) => Err(AppError::Session("mapping not found".into())),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "Failed to delete group mapping");
            Err(AppError::Internal("failed to delete mapping".into()))
        }
        Err(e) => {
            tracing::error!(error = %e, "Task panicked while deleting group mapping");
            Err(AppError::Internal("Task panicked".into()))
        }
    }
}
