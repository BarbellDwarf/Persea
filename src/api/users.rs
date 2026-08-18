//! User administration and profile endpoints.
//!
//! List, create, and delete users, change roles, enable and disable
//! accounts, manage provider-group mappings, and serve the current user's
//! own profile. All handlers except the `/me` ones require admin.
use super::{VaultConfigured, VaultState};
use crate::audit;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use crate::rbac;
use axum::{extract::Path, http::StatusCode, Extension, Json};
use serde::Deserialize;
use serde_json::json;

/// Body for `POST /api/admin/users/{email}/role`.
#[derive(Deserialize)]
pub struct SetRoleRequest {
    /// A premade role name (admin/poweruser/operator/viewer), a custom
    /// role NAME, or NULL/empty to clear the custom role.
    pub role: Option<String>,
}

/// Body for `POST /api/admin/users`.
#[derive(Deserialize)]
pub struct CreateUserRequest {
    /// Login email, unique per user.
    pub email: String,
    /// Display name.
    pub name: String,
    /// Initial password, checked against the configured password policy.
    pub password: String,
    /// Premade role to assign (admin/poweruser/operator/viewer).
    pub role: Option<String>,
    /// Optional custom role NAME to assign (validated to exist).
    #[serde(default)]
    pub custom_role: Option<String>,
}

/// Body for `PUT /api/users/{email}`. Every field is optional; at least
/// one must be present. Name edits apply to any user; email and password
/// changes are restricted to database users (LDAP/OIDC identities are
/// provider-owned).
#[derive(Deserialize)]
pub struct UpdateUserRequest {
    /// New display name.
    #[serde(default)]
    pub name: Option<String>,
    /// New login email (database users only).
    #[serde(default)]
    pub email: Option<String>,
    /// New password (database users only, policy enforced).
    #[serde(default)]
    pub password: Option<String>,
}

/// Body for `POST /api/admin/group-mappings`.
#[derive(Deserialize)]
pub struct CreateGroupMappingRequest {
    /// Auth-provider group name.
    pub group: String,
    /// Role granted to members of the group.
    pub role: String,
}

/// Body for `PUT /api/admin/group-mappings/{id}`.
#[derive(Deserialize)]
pub struct UpdateGroupMappingRequest {
    /// New group name for the mapping.
    pub group: String,
    /// New role for the mapping.
    pub role: String,
}

/// `GET /api/admin/users`: list all users with roles, custom roles,
/// and login metadata. Admin only; `AppError::Forbidden` for lower
/// roles.
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
    // Resolve custom role ids to {id, name} in one pass.
    let roles = rbac::list_custom_roles(&database).unwrap_or_default();
    let roles_by_id: std::collections::HashMap<&str, &rbac::CustomRole> =
        roles.iter().map(|r| (r.id.as_str(), r)).collect();
    let out: Vec<serde_json::Value> = users
        .iter()
        .map(|u| {
            let custom_role = u
                .custom_role_id
                .as_deref()
                .and_then(|id| roles_by_id.get(id))
                .map(|r| json!({"id": r.id, "name": r.name}));
            json!({
                "id": u.id,
                "email": u.email,
                "name": u.name,
                "oidc_subject": u.oidc_subject,
                "role": u.role,
                "disabled": u.disabled,
                "created_at": u.created_at,
                "last_login_at": u.last_login_at,
                "oidc_groups": u.oidc_groups,
                "auth_source": u.auth_source,
                "custom_role": custom_role.unwrap_or(serde_json::Value::Null),
            })
        })
        .collect();
    Ok(Json(json!(out)))
}

/// `POST /api/admin/users`: create a local user, enforcing the
/// password policy (minimum length, reuse history). Admin only. Returns
/// 201 plus the created user, `AppError::Conflict` for duplicate emails,
/// `AppError::Validation` for policy violations.
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
    let email_for_assign = email.clone();
    let name = body.name.clone();
    let password = body.password.clone();
    let role_clone = role.clone();

    // Validate the custom role BEFORE creating the user so an unknown name
    // rejects the request without leaving a half-created account behind.
    let custom_role_name = body.custom_role.clone().filter(|n| !n.trim().is_empty());
    let custom_role_id = match custom_role_name {
        Some(ref name) => {
            let db_for_lookup = database.clone();
            let name_for_lookup = name.clone();
            let role_rec = tokio::task::spawn_blocking(move || {
                rbac::get_custom_role_by_name(&db_for_lookup, &name_for_lookup)
            })
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
            match role_rec {
                Some(role_rec) => Some(role_rec.id),
                None => {
                    return Err(AppError::Validation(format!(
                        "unknown custom role '{name}'"
                    )));
                }
            }
        }
        None => None,
    };

    tokio::task::spawn_blocking(move || {
        let password_hash = crate::password::hash_password(&password)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        db::create_user_with_password(
            &db_clone,
            &email,
            &name,
            &password_hash,
            &role_clone,
            "database",
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

    if let Some(ref role_id) = custom_role_id {
        let db_for_assign = database.clone();
        let role_id_for_assign = role_id.clone();
        tokio::task::spawn_blocking(move || {
            rbac::set_user_custom_role(&db_for_assign, &email_for_assign, Some(&role_id_for_assign))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    }

    let role_for_response = role.clone();

    let admin_name = identity
        .as_ref()
        .map(|id| id.display_name().to_string())
        .unwrap_or_default();
    let email_audit = body.email.clone();
    let role_audit = role.clone();
    let custom_role_audit = custom_role_name.clone();
    let db_audit = database.clone();
    tokio::task::spawn_blocking(move || {
        let _ = audit::log_event(
            &db_audit,
            &mut audit::EventBuilder::new("admin.user.create", "success")
                .user_id(&admin_name)
                .details(serde_json::json!({
                    "email": email_audit,
                    "role": role_audit,
                    "custom_role": custom_role_audit
                }))
                .build(),
        );
    })
    .await
    .ok();

    Ok((
        StatusCode::CREATED,
        Json(json!({
            "email": body.email,
            "role": role_for_response,
            "custom_role": custom_role_name
        })),
    ))
}

/// `PUT /api/users/{email}`: edit a user's name, email, and/or password.
/// Admin only. Name edits apply to any user; email and password changes
/// are restricted to database users (LDAP/OIDC identities are
/// provider-owned). Returns 404 for unknown users, 400 for invalid
/// input, and 409 when the new email is already in use.
pub async fn update_user(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    policy: Option<Extension<crate::password::PasswordPolicy>>,
    Path(email): Path<String>,
    Json(body): Json<UpdateUserRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if body.name.is_none() && body.email.is_none() && body.password.is_none() {
        return Err(AppError::Validation("nothing to update".into()));
    }

    // Handlers fall back to the documented defaults when the extension is
    // absent (test routers).
    let policy = policy.map(|Extension(p)| p).unwrap_or_default();

    // Resolve the target user up front: 404 for unknown accounts, and the
    // auth source gates the email/password fields.
    let db_for_read = database.clone();
    let email_for_read = email.clone();
    let user = tokio::task::spawn_blocking(move || {
        db::get_user_by_email(&db_for_read, &email_for_read)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|_| AppError::NotFound("user not found".into()))?;
    let is_database = user.auth_source == "database";

    let new_name = match &body.name {
        Some(name) => {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(AppError::Validation("name must not be empty".into()));
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    let new_email = match &body.email {
        Some(new_email) => {
            if !is_database {
                return Err(AppError::Validation(
                    "email is managed by the identity provider for this user".into(),
                ));
            }
            let trimmed = new_email.trim();
            if trimmed.is_empty()
                || !trimmed.contains('@')
                || trimmed.chars().any(char::is_whitespace)
            {
                return Err(AppError::Validation("invalid email address".into()));
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    // Password length is checked up front (cheap); the reuse check and the
    // Argon2id hash run in the blocking pool.
    if let Some(password) = &body.password {
        if !is_database {
            return Err(AppError::Validation(
                "password is managed by the identity provider for this user".into(),
            ));
        }
        policy.check_length(password).map_err(AppError::Validation)?;
    }

    let history = policy.history;
    let db_clone = database.clone();
    let email_clone = email.clone();
    let name_for_update = new_name.clone();
    let email_for_update = new_email.clone();
    let password_for_update = body.password.clone();
    let user_id = user.id;

    let updated = tokio::task::spawn_blocking(move || {
        // Reuse check + hashing run in the blocking pool (Argon2id is
        // expensive); the DB write happens in the same call so the new
        // password and its history entry land together.
        let password_hash = match &password_for_update {
            Some(pw) => {
                if crate::password::password_is_recent(&db_clone, user_id, pw, history)
                    .map_err(|e| AppError::Internal(e.to_string()))?
                {
                    return Err(AppError::Validation(format!(
                        "password must differ from the user's last {} passwords",
                        history
                    )));
                }
                Some(
                    crate::password::hash_password(pw)
                        .map_err(|e| AppError::Internal(e.to_string()))?,
                )
            }
            None => None,
        };
        let updated = db::update_user(
            &db_clone,
            &email_clone,
            name_for_update.as_deref(),
            email_for_update.as_deref(),
            password_hash.as_deref(),
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                AppError::Conflict("a user with this email already exists".into())
            } else {
                AppError::Internal(msg)
            }
        })?;
        if let (Some(hash), Some(user)) = (&password_hash, &updated) {
            let _ = crate::password::record_password_history(&db_clone, user.id, hash, history);
        }
        Ok::<_, AppError>(updated)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let user = updated.ok_or(AppError::NotFound("user not found".into()))?;

    // Audit: user edit (no secrets — just which fields changed).
    {
        let db_audit = database.clone();
        let email_audit = email.clone();
        let new_email_audit = new_email.clone();
        let name_changed = new_name.is_some();
        let email_changed = new_email.is_some();
        let password_changed = body.password.is_some();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("admin.user.edit", "success")
                    .user_id(&admin_name)
                    .details(serde_json::json!({
                        "target_email": email_audit,
                        "new_email": new_email_audit,
                        "name_changed": name_changed,
                        "email_changed": email_changed,
                        "password_changed": password_changed,
                    }))
                    .build(),
            );
        })
        .await
        {
            tracing::error!(error = %e, "audit task failed");
        }
    }

    Ok(Json(json!({
        "ok": true,
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "auth_source": user.auth_source,
    })))
}

/// `POST /api/admin/users/{email}/role`: assign a premade role
/// (clearing any custom role), clear a custom role, or assign a custom
/// role by name. Admin only. Returns `AppError::Session` when the user
/// is missing.
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

    let role = req.role.unwrap_or_default();

    // Fetch old role + custom role for audit before updating.
    let (old_role, old_custom_role_id) = {
        let db_for_read = database.clone();
        let email_clone = email.clone();
        tokio::task::spawn_blocking(move || {
            db::get_user_by_email(&db_for_read, &email_clone)
                .ok()
                .map(|u| (u.role, u.custom_role_id))
        })
        .await
        .ok()
        .flatten()
        .unwrap_or_else(|| (String::new(), None))
    };

    // Premade role: set the base role AND clear any custom role (they are
    // mutually exclusive in the UI; the assignment is still additive).
    let custom_role_name: Option<String> = if crate::auth::is_valid_role(&role) {
        let db_for_update = database.clone();
        let email_for_update = email.clone();
        let role_for_update = role.clone();
        let found = tokio::task::spawn_blocking(move || {
            db::set_user_role(&db_for_update, &email_for_update, &role_for_update)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        if !found {
            return Err(AppError::Session("user not found".into()));
        }
        let db_for_clear = database.clone();
        let email_for_clear = email.clone();
        tokio::task::spawn_blocking(move || {
            rbac::set_user_custom_role(&db_for_clear, &email_for_clear, None)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        None
    } else if role.is_empty() {
        // NULL/empty: clear the custom role, keep the base role.
        let db_for_clear = database.clone();
        let email_for_clear = email.clone();
        let found = tokio::task::spawn_blocking(move || {
            rbac::set_user_custom_role(&db_for_clear, &email_for_clear, None)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        if !found {
            return Err(AppError::Session("user not found".into()));
        }
        None
    } else {
        // Custom role name: validate it exists, assign by id, keep the
        // base role untouched (custom roles are additive).
        let db_for_lookup = database.clone();
        let name_for_lookup = role.clone();
        let role_rec = tokio::task::spawn_blocking(move || {
            rbac::get_custom_role_by_name(&db_for_lookup, &name_for_lookup)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        match role_rec {
            Some(role_rec) => {
                let db_for_assign = database.clone();
                let email_for_assign = email.clone();
                let role_id_for_assign = role_rec.id.clone();
                let found = tokio::task::spawn_blocking(move || {
                    rbac::set_user_custom_role(
                        &db_for_assign,
                        &email_for_assign,
                        Some(&role_id_for_assign),
                    )
                })
                .await
                .map_err(|e| AppError::Internal(e.to_string()))??;
                if !found {
                    return Err(AppError::Session("user not found".into()));
                }
                Some(role_rec.name)
            }
            None => {
                return Err(AppError::Internal(
                    "role must be admin, poweruser, operator, viewer, or a custom role name".into(),
                ));
            }
        }
    };

    // Audit: role change
    {
        let db_audit = database.clone();
        let email_audit = email.clone();
        let new_role = role.clone();
        let new_custom_role = custom_role_name.clone();
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
                        "old_custom_role_id": old_custom_role_id,
                        "new_custom_role": new_custom_role,
                    }))
                    .build(),
            );
        })
        .await
        {
            tracing::error!(error = %e, "audit task failed");
        }
    }

    // Response carries the post-change state so the UI can refresh badges.
    let db_for_read = database.clone();
    let email_for_read = email.clone();
    let user =
        tokio::task::spawn_blocking(move || db::get_user_by_email(&db_for_read, &email_for_read))
            .await
            .ok()
            .and_then(|r| r.ok());
    let custom_role_info = match user.as_ref().and_then(|u| u.custom_role_id.as_deref()) {
        Some(role_id) => rbac::get_custom_role(&database, role_id)
            .ok()
            .flatten()
            .map(|r| json!({"id": r.id, "name": r.name})),
        None => None,
    };
    Ok(Json(json!({
        "ok": true,
        "role": user.map(|u| u.role).unwrap_or(role),
        "custom_role": custom_role_info.unwrap_or(serde_json::Value::Null),
    })))
}

/// `DELETE /api/admin/users/{email}`: delete a user. Admin only.
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

/// `DELETE /api/admin/users/{email}/sessions`: revoke all of a
/// user's sessions and tokens. Admin only. Returns the number of
/// sessions revoked.
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

/// `GET /api/me`: the current user's profile, including role,
/// groups, auth source, Vault availability, and custom role. Returns
/// `AppError::Auth` when not authenticated.
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
                let user = db::get_user_by_email(&db_clone, &email_clone).ok();
                // Resolve the assigned custom role in the same blocking
                // call so the DB mutex is not touched from the async side.
                let custom_role = user
                    .as_ref()
                    .and_then(|u| u.custom_role_id.as_deref())
                    .and_then(|id| rbac::get_custom_role(&db_clone, id).ok().flatten());
                (user, custom_role)
            })
            .await
            .unwrap_or((None, None));
            let auth_source_clone = database.clone();
            let email_clone2 = email.clone();
            let auth_source = tokio::task::spawn_blocking(move || {
                db::get_user_auth_source(&auth_source_clone, &email_clone2)
            })
            .await
            .unwrap_or(Ok("unknown".to_string()))
            .unwrap_or_else(|_| "unknown".to_string());
            let name = user_result
                .0
                .as_ref()
                .map(|u| u.name.clone())
                .unwrap_or_else(|| id.display_name().to_string());
            let created_at = user_result.0.as_ref().map(|u| u.created_at.clone());
            Ok(Json(json!({
                "name": name,
                "email": email,
                "role": id.role(),
                "groups": id.groups(),
                "auth_source": auth_source,
                "vault_enabled": vault_available,
                "vault_configured": vault_configured.0,
                "created_at": created_at,
                "custom_role": user_result
                    .1
                    .as_ref()
                    .map(|r| json!({"id": r.id, "name": r.name}))
                    .unwrap_or(serde_json::Value::Null),
            })))
        }
        None => Err(AppError::Auth("not authenticated".into())),
    }
}

/// Body for `PUT /api/me`.
#[derive(Deserialize)]
pub struct UpdateMeRequest {
    /// New display name.
    pub name: String,
}

/// `PUT /api/me`: change the current user's display name. Returns
/// `AppError::Auth` for non-user identities and `AppError::Session`
/// when the account is missing.
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

/// `POST /api/admin/users/{email}/disable`: block the user from
/// logging in. Admin only; `AppError::Session` when the user is
/// missing.
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

/// `POST /api/admin/users/{email}/enable`: lift a previous
/// disable. Admin only; `AppError::Session` when the user is missing.
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

/// `GET /api/admin/group-mappings`: list all provider-group to role
/// mappings. Admin only.
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

/// `GET /api/admin/known-groups`: list group names seen in
/// authentication claims. Admin only.
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

/// `POST /api/admin/group-mappings`: map an auth-provider group to
/// a role. Admin only. Returns `AppError::Conflict` when the group is
/// already mapped.
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

/// `PUT /api/admin/group-mappings/{id}`: change a mapping's group
/// name or role. Admin only; `AppError::Session` when the mapping is
/// missing.
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

/// `DELETE /api/admin/group-mappings/{id}`: remove a mapping. Admin
/// only. Returns 204 on success, `AppError::Session` when the mapping
/// is missing.
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
