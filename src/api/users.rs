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
    audit::fire(
        &database,
        &admin_name,
        "admin.user.create",
        "success",
        serde_json::json!({
            "email": &body.email,
            "role": &role,
            "custom_role": &custom_role_name,
        }),
        None,
        None,
    )
    .await;

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
    let user =
        tokio::task::spawn_blocking(move || db::get_user_by_email(&db_for_read, &email_for_read))
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
        policy
            .check_length(password)
            .map_err(AppError::Validation)?;
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
        // A password reset by an admin must revoke the user's existing
        // sessions (and API tokens) so a compromised account cannot keep
        // using old credentials.
        if password_hash.is_some() {
            let _ = db::delete_user_sessions(&db_clone, user_id);
            let _ = db::revoke_all_user_tokens(&db_clone, user_id);
        }
        Ok::<_, AppError>(updated)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let user = updated.ok_or(AppError::NotFound("user not found".into()))?;

    // Audit: user edit (no secrets — just which fields changed).
    {
        let name_changed = new_name.is_some();
        let email_changed = new_email.is_some();
        let password_changed = body.password.is_some();
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            &admin_name,
            "admin.user.edit",
            "success",
            serde_json::json!({
                "target_email": &email,
                "new_email": &new_email,
                "name_changed": name_changed,
                "email_changed": email_changed,
                "password_changed": password_changed,
            }),
            None,
            None,
        )
        .await;
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            &admin_name,
            "admin.role.change",
            "success",
            serde_json::json!({
                "target_email": &email,
                "old_role": old_role,
                "new_role": &role,
                "old_custom_role_id": old_custom_role_id,
                "new_custom_role": &custom_role_name,
            }),
            None,
            None,
        )
        .await;
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
                let admin_name = identity
                    .as_ref()
                    .map(|id| id.display_name().to_string())
                    .unwrap_or_default();
                audit::fire(
                    &database,
                    &admin_name,
                    "admin.user.delete",
                    "success",
                    serde_json::json!({"target_email": &email}),
                    None,
                    None,
                )
                .await;
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

    // Revoke all derived tokens (scoped desktop tokens, etc.) so they
    // cannot outlive the sessions they were created from.
    let db_clone = database.clone();
    let tokens_revoked =
        tokio::task::spawn_blocking(move || db::revoke_all_user_tokens(&db_clone, user_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;

    tracing::info!(
        email = %email,
        sessions_revoked = count,
        tokens_revoked = tokens_revoked,
        "Admin force-logout user"
    );

    // Audit: force-logout including token revocation.
    {
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            &admin_name,
            "admin.user.force_logout",
            "success",
            serde_json::json!({
                "target_email": &email,
                "sessions_revoked": count,
                "tokens_revoked": tokens_revoked,
            }),
            None,
            None,
        )
        .await;
    }

    Ok(Json(
        json!({"ok": true, "sessions_revoked": count, "tokens_revoked": tokens_revoked}),
    ))
}

/// `GET /api/me`: the current user's profile, including role,
/// groups, auth source, Vault availability, TOTP status, and custom
/// role. Returns `AppError::Auth` when not authenticated.
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
                let totp_enabled = user
                    .as_ref()
                    .map(|u| db::user_totp_enabled(&db_clone, u.id).unwrap_or(false))
                    .unwrap_or(false);
                (user, custom_role, totp_enabled)
            })
            .await
            .unwrap_or((None, None, false));
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
                "totp_enabled": user_result.2,
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
    /// New display name (canonical field).
    #[serde(default)]
    pub name: Option<String>,
    /// Alias for `name`; the profile page historically sent this field.
    /// When both are present, `name` wins.
    #[serde(default)]
    pub display_name: Option<String>,
    /// New login email (database users only, requires `current_password`).
    #[serde(default)]
    pub email: Option<String>,
    /// The user's current password, required when changing the email.
    #[serde(default)]
    pub current_password: Option<String>,
}

/// `PUT /api/me`: change the current user's display name and/or email.
///
/// Name and email edits are restricted to database accounts: LDAP/OIDC
/// identities are provider-owned and their fields are overwritten on every
/// login. An email change re-verifies the current password. Returns
/// `AppError::Auth` for non-user identities, `AppError::Session` when the
/// account is missing, `AppError::Validation` for policy violations, and
/// `AppError::Conflict` when the new email is already in use.
pub async fn update_me(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(body): Json<UpdateMeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => return Err(AppError::Auth("user session required".into())),
    };

    // Resolve the account and its auth source up front: LDAP/OIDC fields
    // are provider-owned and must not be editable through self-service.
    let db_for_read = database.clone();
    let email_for_read = email.clone();
    let user =
        tokio::task::spawn_blocking(move || db::get_user_by_email(&db_for_read, &email_for_read))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|_| AppError::Session("user not found".into()))?;
    let is_database = user.auth_source == "database";

    // `name` is the canonical field; `display_name` is the alias the
    // profile page historically sent.
    let new_name = body
        .name
        .or(body.display_name)
        .map(|n| n.trim().to_string());
    if let Some(n) = &new_name {
        if n.is_empty() {
            return Err(AppError::Validation("name must not be empty".into()));
        }
        if !is_database {
            return Err(AppError::Validation(
                "name is managed by the identity provider for this user".into(),
            ));
        }
    }

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
            if body.current_password.as_deref().unwrap_or("").is_empty() {
                return Err(AppError::Validation(
                    "current password is required to change your email".into(),
                ));
            }
            Some(trimmed.to_string())
        }
        None => None,
    };

    if new_name.is_none() && new_email.is_none() {
        return Err(AppError::Validation("nothing to update".into()));
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let name_for_update = new_name.clone();
    let email_for_update = new_email.clone();
    let current_password = body.current_password.clone();
    let updated = tokio::task::spawn_blocking(move || {
        // An email change re-verifies the current password against the
        // stored hash before touching the account.
        if email_for_update.is_some() {
            let (_, _, _, _, _, stored_hash) = db::get_user_login_info(&db_clone, &email_clone)
                .map_err(|_| AppError::Session("user not found".into()))?
                .ok_or(AppError::Session("user not found".into()))?;
            let valid = match stored_hash {
                Some(h) if !h.is_empty() => {
                    crate::password::verify_password(current_password.as_deref().unwrap_or(""), &h)
                        .map_err(|e| AppError::Internal(e.to_string()))?
                }
                _ => false,
            };
            if !valid {
                return Err(AppError::Validation("current password is incorrect".into()));
            }
        }
        db::update_user(
            &db_clone,
            &email_clone,
            name_for_update.as_deref(),
            email_for_update.as_deref(),
            None,
        )
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("UNIQUE") {
                AppError::Conflict("a user with this email already exists".into())
            } else {
                AppError::Internal(msg)
            }
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    let user = updated.ok_or(AppError::Session("user not found".into()))?;

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
            let admin_name = identity
                .as_ref()
                .map(|id| id.display_name().to_string())
                .unwrap_or_default();
            audit::fire(
                &database,
                &admin_name,
                "admin.user.disable",
                "success",
                serde_json::json!({"target_email": &email}),
                None,
                None,
            )
            .await;
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
            let admin_name = identity
                .as_ref()
                .map(|id| id.display_name().to_string())
                .unwrap_or_default();
            audit::fire(
                &database,
                &admin_name,
                "admin.user.enable",
                "success",
                serde_json::json!({"target_email": &email}),
                None,
                None,
            )
            .await;
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
        let admin_name = identity
            .as_ref()
            .map(|id| id.display_name().to_string())
            .unwrap_or_default();
        audit::fire(
            &database,
            &admin_name,
            "admin.config.change",
            "success",
            serde_json::json!({
                "action": "create_group_mapping",
                "group": &req.group,
                "role": &req.role,
            }),
            None,
            None,
        )
        .await;
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
                let admin_name = identity
                    .as_ref()
                    .map(|id| id.display_name().to_string())
                    .unwrap_or_default();
                audit::fire(
                    &database,
                    &admin_name,
                    "admin.config.change",
                    "success",
                    serde_json::json!({
                        "action": "delete_group_mapping",
                        "mapping_id": id,
                    }),
                    None,
                    None,
                )
                .await;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn test_db() -> Db {
        crate::db::init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn test_vault_state() -> VaultState {
        let cell: crate::api::VaultCell = Arc::new(tokio::sync::RwLock::new(None));
        Arc::new(crate::api::VaultBackends {
            default: cell.clone(),
            shared: cell.clone(),
            local: cell,
        })
    }

    fn identity(email: &str) -> Option<Extension<AuthIdentity>> {
        Some(Extension(AuthIdentity::User {
            email: email.to_string(),
            name: "Test User".to_string(),
            role: "viewer".to_string(),
            groups: vec![],
        }))
    }

    fn create_db_user(db: &Db, email: &str, name: &str, auth_source: &str) {
        let hash = crate::password::hash_password("s3cret-p@ss").unwrap();
        crate::db::create_user_with_password(db, email, name, &hash, "viewer", auth_source)
            .unwrap();
    }

    fn me_request(name: Option<&str>, display_name: Option<&str>) -> UpdateMeRequest {
        UpdateMeRequest {
            name: name.map(str::to_string),
            display_name: display_name.map(str::to_string),
            email: None,
            current_password: None,
        }
    }

    #[tokio::test]
    async fn update_me_accepts_name() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let resp = update_me(
            identity("u@example.com"),
            Extension(db.clone()),
            Json(me_request(Some("New Name"), None)),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["name"], "New Name");
        assert_eq!(
            crate::db::get_user_by_email(&db, "u@example.com")
                .unwrap()
                .name,
            "New Name"
        );
    }

    #[tokio::test]
    async fn update_me_accepts_display_name_alias() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let resp = update_me(
            identity("u@example.com"),
            Extension(db.clone()),
            Json(me_request(None, Some("Alias Name"))),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["name"], "Alias Name");
        assert_eq!(
            crate::db::get_user_by_email(&db, "u@example.com")
                .unwrap()
                .name,
            "Alias Name"
        );
    }

    #[tokio::test]
    async fn update_me_name_wins_over_display_name_alias() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let resp = update_me(
            identity("u@example.com"),
            Extension(db.clone()),
            Json(me_request(Some("Canonical"), Some("Alias"))),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["name"], "Canonical");
    }

    #[tokio::test]
    async fn update_me_rejects_name_change_for_oidc_user() {
        let db = test_db();
        create_db_user(&db, "oidc@example.com", "Provider Name", "oidc");
        let err = update_me(
            identity("oidc@example.com"),
            Extension(db),
            Json(me_request(Some("Hacked"), None)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn update_me_rejects_email_change_for_oidc_user() {
        let db = test_db();
        create_db_user(&db, "oidc@example.com", "Provider Name", "oidc");
        let err = update_me(
            identity("oidc@example.com"),
            Extension(db),
            Json(UpdateMeRequest {
                name: None,
                display_name: None,
                email: Some("new@example.com".to_string()),
                current_password: Some("s3cret-p@ss".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn update_me_email_change_requires_current_password() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let err = update_me(
            identity("u@example.com"),
            Extension(db),
            Json(UpdateMeRequest {
                name: None,
                display_name: None,
                email: Some("new@example.com".to_string()),
                current_password: None,
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn update_me_email_change_rejects_wrong_current_password() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let err = update_me(
            identity("u@example.com"),
            Extension(db),
            Json(UpdateMeRequest {
                name: None,
                display_name: None,
                email: Some("new@example.com".to_string()),
                current_password: Some("wrong-password".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn update_me_email_change_succeeds_with_current_password() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let resp = update_me(
            identity("u@example.com"),
            Extension(db.clone()),
            Json(UpdateMeRequest {
                name: None,
                display_name: None,
                email: Some("new@example.com".to_string()),
                current_password: Some("s3cret-p@ss".to_string()),
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["email"], "new@example.com");
        assert!(crate::db::get_user_by_email(&db, "new@example.com").is_ok());
    }

    #[tokio::test]
    async fn update_me_email_uniqueness_conflict() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "First", "database");
        create_db_user(&db, "other@example.com", "Second", "database");
        let err = update_me(
            identity("u@example.com"),
            Extension(db),
            Json(UpdateMeRequest {
                name: None,
                display_name: None,
                email: Some("other@example.com".to_string()),
                current_password: Some("s3cret-p@ss".to_string()),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Conflict(_)));
    }

    #[tokio::test]
    async fn update_me_rejects_empty_payload() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let err = update_me(
            identity("u@example.com"),
            Extension(db),
            Json(me_request(None, None)),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn me_returns_totp_enabled() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let user = crate::db::get_user_by_email(&db, "u@example.com").unwrap();
        crate::db::store_totp_secret(&db, user.id, "JBSWY3DPEHPK3PXP", "SHA1", 6, 30).unwrap();
        crate::db::set_totp_enabled(&db, user.id, true).unwrap();
        let resp = me(
            identity("u@example.com"),
            Extension(db),
            Extension(test_vault_state()),
            Extension(VaultConfigured(false)),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["totp_enabled"], true);
        assert_eq!(resp.0["auth_source"], "database");
    }

    #[tokio::test]
    async fn me_returns_totp_disabled_when_not_enrolled() {
        let db = test_db();
        create_db_user(&db, "u@example.com", "Old Name", "database");
        let resp = me(
            identity("u@example.com"),
            Extension(db),
            Extension(test_vault_state()),
            Extension(VaultConfigured(false)),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["totp_enabled"], false);
    }
}
