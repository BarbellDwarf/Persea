//! API token management and user credential variables.
//!
//! Personal token CRUD, admin token management, token and address-book
//! audit logs, and the per-user credential variables used as template
//! variables in connections.
use super::{CredentialDefaultScope, StorageBackend, StorageKey, VaultState};
use crate::auth::{client_ip, role_level, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use axum::{
    extract::{ConnectInfo, Path, Query},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

/// Body for `POST /api/tokens` (personal token creation).
#[derive(Deserialize)]
pub struct CreateTokenRequest {
    /// Token name, 1-100 characters, unique per user.
    pub name: String,
    /// Ceiling role for the token; cannot exceed the caller's role.
    pub max_role: Option<String>,
    /// Optional RFC 3339 expiry; tokens never expire when absent.
    pub expires_at: Option<String>,
}

/// Body for `POST /api/admin/users/{email}/tokens`.
#[derive(Deserialize)]
pub struct AdminCreateTokenRequest {
    /// The user the token is minted for.
    pub email: String,
    /// Token name, 1-100 characters, unique per user.
    pub name: String,
    /// Ceiling role for the token; cannot exceed the target user's role.
    pub max_role: Option<String>,
    /// Optional RFC 3339 expiry; tokens never expire when absent.
    pub expires_at: Option<String>,
}

/// Query parameters for the token and address-book audit endpoints.
#[derive(Deserialize)]
pub struct AuditLogQuery {
    /// Maximum number of events to return.
    pub limit: Option<u32>,
    /// Restrict to events for this user.
    pub email: Option<String>,
}

/// `POST /api/tokens`: create a personal API token and return its
/// plaintext once. Requires poweruser or higher. Returns
/// `AppError::Forbidden` for lower roles and `AppError::Conflict` when
/// the token name is already taken.
pub async fn create_my_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) => id.clone(),
        None => return Err(AppError::Auth("authentication required".into())),
    };

    if !id.has_role("poweruser") {
        return Err(AppError::Forbidden(
            "poweruser role or higher required to create tokens".into(),
        ));
    }

    let email = match &id {
        AuthIdentity::User { email, .. } => email.clone(),
        AuthIdentity::ApiKey(_) => {
            return Err(AppError::Internal(
                "API key admins cannot create user tokens — use the admin endpoint".into(),
            ))
        }
    };

    if let Some(ref max_role) = req.max_role {
        if !crate::auth::is_valid_role(max_role) {
            return Err(AppError::Internal(
                "max_role must be admin, poweruser, operator, or viewer".into(),
            ));
        }
        if role_level(max_role) > role_level(id.role()) {
            return Err(AppError::Forbidden(
                "max_role cannot exceed your current role".into(),
            ));
        }
    }

    if req.name.is_empty() || req.name.len() > 100 {
        return Err(AppError::Internal(
            "token name must be 1-100 characters".into(),
        ));
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Internal("failed to look up user".into()))?;

    let db_clone = database.clone();
    let name = req.name.clone();
    let max_role = req.max_role.clone();
    let expires_at = req.expires_at.clone();
    let result = tokio::task::spawn_blocking(move || {
        db::create_user_token(
            &db_clone,
            user.id,
            &name,
            max_role.as_deref(),
            expires_at.as_deref(),
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint") {
            AppError::Conflict(format!("token name '{}' already exists", req.name))
        } else {
            AppError::Internal("failed to create token".into())
        }
    })?;

    let (token_id, plaintext) = result;
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    let details = serde_json::to_string(&json!({
        "max_role": req.max_role,
        "expires_at": req.expires_at,
    }))
    .ok();
    let db_clone = database.clone();
    let email_clone = email.clone();
    let name_clone = req.name.clone();
    let _ = tokio::task::spawn_blocking(move || {
        db::log_token_event(
            &db_clone,
            Some(token_id),
            Some(&name_clone),
            &email_clone,
            "created",
            Some(&ip.to_string()),
            details.as_deref(),
        )
    })
    .await;

    Ok(Json(json!({
        "id": token_id,
        "name": req.name,
        "token": plaintext,
        "max_role": req.max_role,
        "expires_at": req.expires_at,
    })))
}

/// `GET /api/tokens`: list the caller's tokens. Only cookie-session
/// users may call it; API-key identities get `AppError::Auth`.
pub async fn list_my_tokens(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => return Err(AppError::Auth("OIDC authentication required".into())),
    };

    let db_clone = database.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Internal("failed to look up user".into()))?;

    let db_clone = database.clone();
    let tokens = tokio::task::spawn_blocking(move || db::list_user_tokens(&db_clone, user.id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(tokens)))
}

/// `DELETE /api/tokens/{id}`: revoke one of the caller's tokens.
/// Requires poweruser or higher. Returns `AppError::Auth` for
/// non-user identities and `AppError::NotFound` when the token does
/// not exist or belongs to someone else.
pub async fn revoke_my_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Path(token_id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (email, role) = match identity {
        Some(Extension(AuthIdentity::User {
            ref email,
            ref role,
            ..
        })) => (email.clone(), role.clone()),
        _ => return Err(AppError::Auth("OIDC authentication required".into())),
    };

    if role_level(&role) < role_level("poweruser") {
        return Err(AppError::Forbidden(
            "poweruser role or higher required to manage tokens".into(),
        ));
    }

    let db_clone = database.clone();
    let email_clone = email.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Internal("failed to look up user".into()))?;

    let db_clone = database.clone();
    let user_id = user.id;
    let found =
        tokio::task::spawn_blocking(move || db::revoke_user_token(&db_clone, user_id, token_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;

    if found {
        let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
        let ip = client_ip(&headers, addr.ip(), &proxies);
        let db_clone = database.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db::log_token_event(
                &db_clone,
                Some(token_id),
                None,
                &email,
                "revoked",
                Some(&ip.to_string()),
                Some("self-service revocation"),
            )
        })
        .await;
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("token not found or not yours".into()))
    }
}

fn mask_credential(name: &str, value: &str, scope: &str) -> serde_json::Value {
    let display = if value.is_empty() {
        String::new()
    } else if name.ends_with("_password") || name.ends_with("_key") {
        "••••••••".to_string()
    } else {
        value.to_string()
    };
    json!({ "set": !value.is_empty(), "display": display, "scope": scope })
}

pub(crate) fn partition_credential_writes(
    mut existing_local: std::collections::HashMap<String, String>,
    mut existing_shared: std::collections::HashMap<String, String>,
    incoming: &std::collections::HashMap<String, String>,
    scopes: &std::collections::HashMap<String, String>,
    default_scope: &str,
    split: bool,
) -> (
    std::collections::HashMap<String, String>,
    std::collections::HashMap<String, String>,
) {
    for (name, val) in incoming {
        let value = if !val.is_empty() {
            val.clone()
        } else {
            existing_local
                .get(name)
                .or_else(|| existing_shared.get(name))
                .cloned()
                .unwrap_or_default()
        };
        if value.is_empty() {
            existing_local.remove(name);
            existing_shared.remove(name);
            continue;
        }
        let to_shared = split
            && scopes
                .get(name)
                .map(String::as_str)
                .unwrap_or(default_scope)
                == "shared";
        if to_shared {
            existing_shared.insert(name.clone(), value);
            existing_local.remove(name);
        } else {
            existing_local.insert(name.clone(), value);
            existing_shared.remove(name);
        }
    }
    (existing_local, existing_shared)
}

/// `GET /api/tokens/credentials`: the caller's credential variables,
/// masked per store scope. Requires an authenticated user session.
pub async fn get_my_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(default_scope): Extension<CredentialDefaultScope>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => return Err(AppError::Auth("OIDC authentication required".into())),
    };

    let split = vault.creds_split();
    let local = vault.get_user_credentials_scoped(&email, false).await?;
    let shared = if split {
        vault
            .get_user_credentials_scoped(&email, true)
            .await
            .unwrap_or_default()
    } else {
        std::collections::HashMap::new()
    };

    let mut masked = serde_json::Map::new();
    for (k, v) in &shared {
        masked.insert(k.clone(), mask_credential(k, v, "shared"));
    }
    for (k, v) in &local {
        masked.insert(k.clone(), mask_credential(k, v, "local"));
    }

    Ok(Json(json!({
        "credentials": masked,
        "creds_split": split,
        "default_scope": default_scope.0,
    })))
}

/// `PUT /api/tokens/credentials`: write the caller's credential
/// variables, routing each key to the shared or local store by the
/// optional `scopes` map (default scope from config). Requires
/// operator or higher. Returns `AppError::Forbidden` below that and
/// `AppError::Internal` for invalid variable names.
pub async fn put_my_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Extension(default_scope): Extension<CredentialDefaultScope>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User {
            ref email,
            ref role,
            ..
        })) if role_level(role) >= role_level("operator") => email.clone(),
        Some(Extension(AuthIdentity::User { .. })) => {
            return Err(AppError::Forbidden("operator role required".into()))
        }
        _ => return Err(AppError::Auth("OIDC authentication required".into())),
    };

    let creds_obj = match body.get("credentials").and_then(|v| v.as_object()) {
        Some(obj) => obj,
        None => {
            return Err(AppError::Internal(
                "missing or invalid 'credentials' object".into(),
            ))
        }
    };

    let mut incoming = std::collections::HashMap::new();
    for (k, v) in creds_obj {
        if !k
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
        {
            return Err(AppError::Internal(format!(
                "invalid variable name '{}': use lowercase alphanumeric, underscores and hyphens",
                k
            )));
        }
        incoming.insert(k.clone(), v.as_str().unwrap_or("").to_string());
    }

    let mut scopes = std::collections::HashMap::new();
    if let Some(obj) = body.get("scopes").and_then(|v| v.as_object()) {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                if s == "shared" || s == "local" {
                    scopes.insert(k.clone(), s.to_string());
                }
            }
        }
    }

    let split = vault.creds_split();

    let existing_local = vault.get_user_credentials_scoped(&email, false).await?;
    let existing_shared = if split {
        vault.get_user_credentials_scoped(&email, true).await?
    } else {
        std::collections::HashMap::new()
    };

    let (new_local, new_shared) = partition_credential_writes(
        existing_local,
        existing_shared,
        &incoming,
        &scopes,
        &default_scope.0,
        split,
    );

    vault
        .put_user_credentials_scoped(&email, false, &new_local)
        .await?;
    if split {
        vault
            .put_user_credentials_scoped(&email, true, &new_shared)
            .await?;
    }

    let count = new_local.len() + new_shared.len();
    tracing::info!(user = %email, count, "User credentials updated");
    Ok(Json(json!({"ok": true, "count": count})))
}

/// GET /api/me/preset-credentials
///
/// Per-user fallback credentials used by address book entries that carry no
/// credentials of their own. Values are never returned — only presence flags
/// (and the username, which is not secret).
pub async fn get_my_preset_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        Some(Extension(AuthIdentity::ApiKey { .. })) => {
            return Err(AppError::Auth(
                "preset credentials require a user session".into(),
            ))
        }
        _ => return Err(AppError::Auth("authentication required".into())),
    };
    let user = db::get_user_by_email(&database, &email)
        .map_err(|_| AppError::NotFound("user not found".into()))?;
    let (username, password_enc) =
        db::get_user_preset_credentials(&database, user.id)?.unwrap_or_default();
    Ok(Json(json!({
        "username": username,
        "has_username": !username.is_empty(),
        "has_password": !password_enc.is_empty(),
    })))
}

/// PUT /api/me/preset-credentials
///
/// Body: {"username": "...", "password": "..."}. An empty password keeps the
/// stored one; both empty clears the preset entirely.
pub async fn put_my_preset_credentials(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    storage_key: Option<Extension<StorageKey>>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let email = match identity {
        Some(Extension(AuthIdentity::User { ref email, .. })) => email.clone(),
        _ => return Err(AppError::Auth("authentication required".into())),
    };
    let user = db::get_user_by_email(&database, &email)
        .map_err(|_| AppError::NotFound("user not found".into()))?;

    let username = body
        .get("username")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let password = body
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    if username.is_empty() && password.is_empty() {
        db::clear_user_preset_credentials(&database, user.id)?;
        return Ok(Json(json!({"cleared": true})));
    }

    let mut password_enc = String::new();
    if password.is_empty() {
        // Keep the stored password when the field is left blank.
        if let Some((_, enc)) = db::get_user_preset_credentials(&database, user.id)? {
            password_enc = enc;
        }
    } else {
        let key_hex = crate::api::address_book::resolve_encryption_key(
            storage_key.as_ref().map(|Extension(k)| k),
        );
        if key_hex.is_empty() {
            return Err(AppError::Validation(
                "no [storage].encryption_key / PERSEA_STORAGE_KEY configured — cannot store credentials"
                    .into(),
            ));
        }
        let key = crate::crypto::EncryptionKey::from_hex(&key_hex)
            .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;
        password_enc = crate::crypto::encrypt_value(&key, &password)
            .map_err(|e| AppError::Internal(format!("encryption failed: {e}")))?;
    }

    db::upsert_user_preset_credentials(&database, user.id, &username, &password_enc)?;
    Ok(Json(json!({
        "saved": true,
        "has_username": !username.is_empty(),
        "has_password": !password_enc.is_empty(),
    })))
}

/// `GET /api/tokens/credential-variables`: scan every address book
/// entry the caller can access and report the template variables
/// available, grouped by domain, with per-entry counts. Requires
/// operator or higher.
pub async fn list_credential_variables(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    storage_key: Option<Extension<StorageKey>>,
    backend: Option<Extension<StorageBackend>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    // DB-first storage: folders/entries metadata lives in the
    // DB; credentials live in the DB unless [storage].backend = "vault".
    let vault_creds =
        super::address_book::vault_credentials_enabled(backend.as_ref().map(|b| &b.0), &vault)
            .await;
    let enc_key = super::address_book::resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
    let enc_key_parsed = if enc_key.is_empty() {
        None
    } else {
        match crate::crypto::EncryptionKey::from_hex(&enc_key) {
            Ok(k) => Some(k),
            Err(e) => {
                return Err(AppError::Internal(format!("invalid encryption key: {e}")));
            }
        }
    };

    let folders = db::list_ab_folders(&database, None).unwrap_or_default();
    let mut all_vars: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    // Seed the walk with top-level folders only; children are pushed as the
    // slash-hierarchy is traversed (seeding all folders would double-visit
    // every nested folder).
    let mut stack: Vec<(String, String)> = folders
        .iter()
        .filter(|f| !f.name.contains('/'))
        .map(|f| (f.scope.clone(), f.name.clone()))
        .collect();

    while let Some((scope, path)) = stack.pop() {
        // Skip folders the user cannot access (same rule as the address book:
        // empty description = unrestricted, otherwise entries' allowed_groups).
        if !super::address_book::folder_allowed_for_user(&database, &scope, &path, id.groups()) {
            continue;
        }

        if let Ok(folder) = db::get_ab_folder(&database, &scope, &path) {
            for entry in db::list_ab_entries(&database, folder.id).unwrap_or_default() {
                let mut fields: Vec<Option<String>> = vec![if entry.username.is_empty() {
                    None
                } else {
                    Some(entry.username.clone())
                }];
                if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&entry.protocol_config) {
                    if let Some(d) = cfg.get("domain").and_then(|v| v.as_str()) {
                        if !d.is_empty() {
                            fields.push(Some(d.to_string()));
                        }
                    }
                }
                if vault_creds {
                    if let Ok(ve) = vault.get_entry(&scope, &path, &entry.name).await {
                        fields.push(ve.password);
                        fields.push(ve.private_key);
                        fields.push(ve.container_password);
                    }
                } else if !enc_key.is_empty() {
                    for cred in db::list_ab_credentials(&database, entry.id).unwrap_or_default() {
                        let decrypted = crate::crypto::decrypt_value(
                            enc_key_parsed.as_ref().unwrap(),
                            &cred.credential_data,
                        )
                        .unwrap_or(cred.credential_data.clone());
                        match cred.credential_type.as_str() {
                            "password" => fields.push(Some(decrypted)),
                            "private_key" => fields.push(Some(decrypted)),
                            "container_password" => fields.push(Some(decrypted)),
                            _ => {}
                        }
                    }
                }
                for var in fields
                    .iter()
                    .filter_map(|f| f.as_deref())
                    .filter_map(crate::vault::variable_name)
                {
                    *all_vars.entry(var.to_string()).or_insert(0) += 1;
                }
            }
        }

        // BFS: folders are flat rows whose names carry slash hierarchy —
        // push only IMMEDIATE children (a grandchild is pushed when its
        // parent is processed, so it can never be visited twice).
        for sub in folders.iter().filter(|f| {
            f.scope == scope
                && f.name
                    .strip_prefix(&format!("{}/", path))
                    .map(|rest| !rest.contains('/'))
                    .unwrap_or(false)
        }) {
            stack.push((scope.clone(), sub.name.clone()));
        }
    }

    let mut domains: std::collections::HashMap<String, Vec<serde_json::Value>> =
        std::collections::HashMap::new();
    for (var, count) in &all_vars {
        let domain = var
            .rsplit_once('_')
            .map(|(prefix, _suffix)| prefix.to_string())
            .unwrap_or_else(|| var.clone());
        domains
            .entry(domain)
            .or_default()
            .push(json!({"name": var, "entry_count": count}));
    }

    Ok(Json(json!({ "variables": all_vars, "domains": domains })))
}

/// `POST /api/admin/users/{email}/tokens`: mint a token for another
/// user and return its plaintext once. Admin only. Returns
/// `AppError::Session` when the user does not exist and
/// `AppError::Conflict` when the token name is taken.
pub async fn admin_create_user_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Json(req): Json<AdminCreateTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_name = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if req.name.is_empty() || req.name.len() > 100 {
        return Err(AppError::Internal(
            "token name must be 1-100 characters".into(),
        ));
    }

    if let Some(ref max_role) = req.max_role {
        if !crate::auth::is_valid_role(max_role) {
            return Err(AppError::Internal(
                "max_role must be admin, poweruser, operator, or viewer".into(),
            ));
        }
    }

    let db_clone = database.clone();
    let target_email = req.email.clone();
    let user = tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &target_email))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|_| AppError::Session("user not found".into()))?;

    if let Some(ref max_role) = req.max_role {
        if role_level(max_role) > role_level(&user.role) {
            return Err(AppError::Internal(format!(
                "max_role '{}' exceeds user's role '{}'",
                max_role, user.role
            )));
        }
    }

    let db_clone = database.clone();
    let name = req.name.clone();
    let max_role = req.max_role.clone();
    let expires_at = req.expires_at.clone();
    let user_id = user.id;
    let result = tokio::task::spawn_blocking(move || {
        db::create_user_token(
            &db_clone,
            user_id,
            &name,
            max_role.as_deref(),
            expires_at.as_deref(),
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint") {
            AppError::Conflict(format!(
                "token name '{}' already exists for this user",
                req.name
            ))
        } else {
            AppError::Internal("failed to create token".into())
        }
    })?;

    let (token_id, plaintext) = result;
    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let ip = client_ip(&headers, addr.ip(), &proxies);
    let details = serde_json::to_string(&json!({
        "created_by": admin_name,
        "for_user": req.email,
        "max_role": req.max_role,
        "expires_at": req.expires_at,
    }))
    .ok();
    let db_clone = database.clone();
    let email_clone = req.email.clone();
    let name_clone = req.name.clone();
    let _ = tokio::task::spawn_blocking(move || {
        db::log_token_event(
            &db_clone,
            Some(token_id),
            Some(&name_clone),
            &email_clone,
            "created",
            Some(&ip.to_string()),
            details.as_deref(),
        )
    })
    .await;

    Ok(Json(json!({
        "id": token_id,
        "name": req.name,
        "email": req.email,
        "token": plaintext,
        "max_role": req.max_role,
        "expires_at": req.expires_at,
    })))
}

/// `GET /api/admin/users/{email}/tokens`: list another user's
/// tokens. Admin only.
pub async fn admin_list_user_tokens(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let db_clone = database.clone();
    let tokens = tokio::task::spawn_blocking(move || db::list_all_user_tokens(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;

    let entries: Vec<_> = tokens
        .into_iter()
        .map(|(t, email)| {
            json!({
                "id": t.id,
                "user_id": t.user_id,
                "email": email,
                "name": t.name,
                "max_role": t.max_role,
                "expires_at": t.expires_at,
                "disabled": t.disabled,
                "created_at": t.created_at,
                "last_used_at": t.last_used_at,
            })
        })
        .collect();
    Ok(Json(json!(entries)))
}

/// `DELETE /api/admin/users/{email}/tokens/{id}`: revoke another
/// user's token. Admin only.
pub async fn admin_revoke_user_token(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    trusted: Option<Extension<TrustedProxies>>,
    Path(token_id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_name = match identity {
        Some(Extension(ref id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let db_clone = database.clone();
    let found =
        tokio::task::spawn_blocking(move || db::admin_revoke_user_token(&db_clone, token_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;

    if found {
        let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
        let ip = client_ip(&headers, addr.ip(), &proxies);
        let db_clone = database.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db::log_token_event(
                &db_clone,
                Some(token_id),
                None,
                &admin_name,
                "admin_revoked",
                Some(&ip.to_string()),
                None,
            )
        })
        .await;
        Ok(Json(json!({"ok": true})))
    } else {
        Err(AppError::Session("token not found".into()))
    }
}

/// `GET /api/admin/tokens/audit`: token lifecycle events (created,
/// revoked) with optional user filter. Admin only.
pub async fn admin_token_audit(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let limit = query.limit.unwrap_or(200).min(1000);
    let email = query.email.clone();
    let db_clone = database.clone();
    let entries = tokio::task::spawn_blocking(move || {
        db::list_token_audit_log(&db_clone, limit, email.as_deref())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(entries)))
}

/// `GET /api/admin/addressbook/audit`: address book change events
/// with optional user filter. Admin only.
pub async fn admin_addressbook_audit(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let limit = query.limit.unwrap_or(200).min(1000);
    let email = query.email.clone();
    let db_clone = database.clone();
    let entries = tokio::task::spawn_blocking(move || {
        db::list_addressbook_audit_log(&db_clone, limit, email.as_deref())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(json!(entries)))
}
