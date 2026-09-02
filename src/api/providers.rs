//! Admin API for DB-configured auth providers.
//!
//! Routes (registered by the orchestrator in `src/main.rs`; all admin-only):
//!
//! * `GET    /api/auth/providers`        — list `{id, name, type, enabled, position}`
//! * `POST   /api/auth/providers`        — create `{name, type, config: {...}}`
//! * `GET    /api/auth/providers/{id}`   — full row incl. config
//! * `POST   /api/auth/providers/{id}/enable`
//! * `POST   /api/auth/providers/{id}/disable`
//! * `POST   /api/auth/providers/{id}/move` — `{direction: "up"|"down"}`
//! * `GET    /api/auth/providers/{id}/config`
//! * `POST   /api/auth/providers/{id}/test`
//! * `DELETE /api/auth/providers/{id}`
//!
//! Provider config JSON may contain secrets (`client_secret`,
//! `bind_password`, RADIUS secret); the endpoints that return it
//! (`GET /{id}`, `GET /{id}/config`) are admin-only and return it as stored.

use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;
use crate::oidc::friendly_discovery_error;
use crate::providers_db::{self, DbProvider, MoveDirection};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

/// Body for `POST /api/auth/providers`.
#[derive(Deserialize)]
pub struct CreateProviderRequest {
    /// Display name, used in SSO button URLs and cookies, so it is
    /// restricted to letters, digits, spaces, '-', '_' and '.'.
    pub name: String,
    /// Provider kind, one of [`crate::providers_db::PROVIDER_TYPES`].
    #[serde(rename = "type")]
    pub provider_type: String,
    /// Provider-specific config JSON. May contain secrets
    /// (`client_secret`, `bind_password`, RADIUS secret), which the
    /// read-back endpoints mask.
    #[serde(default)]
    pub config: Value,
}

/// Body for `POST /api/auth/providers/{id}/move`.
#[derive(Deserialize)]
pub struct MoveProviderRequest {
    /// `"up"` or `"down"`.
    pub direction: String,
}

/// All provider endpoints are admin-only. Mirrors the strict check used by
/// the user-management handlers in `users.rs`.
fn require_admin(identity: &Option<Extension<AuthIdentity>>) -> Result<(), AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    Ok(())
}

/// Secret-bearing config keys, masked in API responses. The chain merge and
/// the PUT endpoint operate on the unmasked DB row; only API output masks.
const SECRET_KEYS: &[&str] = &[
    "client_secret",
    "bind_password",
    "shared_secret",
    "secret",
    // SAML SP signing key (PEM) — equivalent to a private key.
    "private_key",
];

fn mask_config(config: &Value) -> Value {
    let mut out = config.clone();
    if let Some(obj) = out.as_object_mut() {
        for key in SECRET_KEYS {
            if let Some(v) = obj.get_mut(*key) {
                if v.as_str().map(|s| !s.is_empty()).unwrap_or(false) {
                    *v = json!("\u{2022}\u{2022}\u{2022}configured\u{2022}\u{2022}\u{2022}");
                }
            }
        }
    }
    out
}

fn mask_provider(mut provider: providers_db::DbProvider) -> providers_db::DbProvider {
    provider.config = mask_config(&provider.config);
    provider
}

/// GET /api/auth/providers — `{"providers": [{"id", "name", "type", "enabled", "position"}]}`
pub async fn list_providers(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let providers = tokio::task::spawn_blocking(move || providers_db::load_providers(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    let list: Vec<Value> = providers
        .iter()
        .map(|p| {
            json!({
                "id": p.id,
                "name": p.name,
                "type": p.provider_type,
                "enabled": p.enabled,
                "position": p.position,
            })
        })
        .collect();
    Ok(Json(json!({ "providers": list })))
}

/// POST /api/auth/providers — validate config by type, append to the chain.
pub async fn create_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(body): Json<CreateProviderRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    require_admin(&identity)?;

    let name = body.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::Validation("name is required".into()));
    }
    // Provider names appear in URLs (SSO buttons) and cookies — keep them
    // to a safe charset so no encoding/escaping can be bypassed.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err(AppError::Validation(
            "name may only contain letters, digits, spaces, '-', '_' and '.'".into(),
        ));
    }
    if !providers_db::PROVIDER_TYPES.contains(&body.provider_type.as_str()) {
        return Err(AppError::Validation(format!(
            "unknown provider type: {}",
            body.provider_type
        )));
    }
    providers_db::validate_config(&body.provider_type, &body.config)
        .map_err(AppError::Validation)?;

    let db_clone = database.clone();
    let name_for_insert = name.clone();
    let type_for_insert = body.provider_type.clone();
    let config_for_insert = body.config.clone();
    let provider = tokio::task::spawn_blocking(move || {
        providers_db::insert_provider(
            &db_clone,
            &name_for_insert,
            &type_for_insert,
            &config_for_insert,
        )
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| {
        use rusqlite::ErrorCode;
        if matches!(
            e,
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == ErrorCode::ConstraintViolation
        ) {
            AppError::Conflict("a provider with this name already exists".into())
        } else {
            AppError::Internal(e.to_string())
        }
    })?;

    super::groups::audit_config_change(
        &database,
        &identity,
        json!({"action": "create_provider", "id": provider.id, "name": provider.name}),
    )
    .await;
    Ok((StatusCode::CREATED, Json(json!(mask_provider(provider)))))
}

/// PUT /api/auth/providers/{id} — replace the provider's config JSON
/// (admin only). The body is the config object itself, validated against the
/// provider's type like create. Secrets are written unmasked to the DB; API
/// responses mask them.
pub async fn update_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let body_clone = body.clone();
    let changed = tokio::task::spawn_blocking(move || -> Result<bool, AppError> {
        let existing = providers_db::get_provider(&db_clone, id)?
            .ok_or_else(|| AppError::Session("provider not found".into()))?;
        // Secret fields sent empty (or as the masked sentinel from a GET
        // round-trip) keep their stored value — the config modal shows them
        // blank with "leave blank to keep". Secrets must be strings; any
        // other type is rejected so masking can never be bypassed. When a
        // secret is blank but nothing is stored, the key is dropped so
        // validation fails for providers that require it — the correct error
        // rather than storing the literal sentinel.
        let mut merged = body_clone;
        if let Some(obj) = merged.as_object_mut() {
            for key in SECRET_KEYS {
                let masked = "\u{2022}\u{2022}\u{2022}configured\u{2022}\u{2022}\u{2022}";
                match obj.get(*key) {
                    Some(Value::String(inner)) if inner.is_empty() || inner == masked => {
                        if let Some(old_val) = existing
                            .config
                            .as_object()
                            .and_then(|o| o.get(*key))
                            .cloned()
                        {
                            obj.insert((*key).to_string(), old_val);
                        } else {
                            obj.remove(*key);
                        }
                    }
                    Some(Value::String(_)) => {}
                    Some(_) => {
                        return Err(AppError::Validation(format!(
                            "provider config key '{key}' must be a string"
                        )));
                    }
                    None => {}
                }
            }
        }
        providers_db::validate_config(&existing.provider_type, &merged)
            .map_err(AppError::Validation)?;
        providers_db::update_config(&db_clone, id, &merged)
            .map_err(|e| AppError::Internal(e.to_string()))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;
    if !changed {
        return Err(AppError::Session("provider not found".into()));
    }

    super::groups::audit_config_change(
        &database,
        &identity,
        json!({"action": "update_provider", "id": id}),
    )
    .await;
    let provider = fetch_provider(&database, id).await?;
    Ok(Json(json!(mask_provider(provider))))
}

/// GET /api/auth/providers/{id} — full row incl. config (admin only).
pub async fn get_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let provider = fetch_provider(&db_clone, id).await?;
    Ok(Json(json!(mask_provider(provider))))
}

/// POST /api/auth/providers/{id}/enable
pub async fn enable_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;
    flip_enabled(&database, id, true, &identity).await
}

/// POST /api/auth/providers/{id}/disable
pub async fn disable_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;
    flip_enabled(&database, id, false, &identity).await
}

/// POST /api/auth/providers/{id}/move — `{direction: "up"|"down"}`
pub async fn move_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
    Json(req): Json<MoveProviderRequest>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let direction = match req.direction.as_str() {
        "up" => MoveDirection::Up,
        "down" => MoveDirection::Down,
        other => {
            return Err(AppError::Validation(format!(
                "direction must be 'up' or 'down', got '{other}'"
            )));
        }
    };

    let db_clone = database.clone();
    let provider =
        tokio::task::spawn_blocking(move || providers_db::move_provider(&db_clone, id, direction))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??
            .ok_or_else(|| AppError::Session("provider not found".into()))?;

    super::groups::audit_config_change(
        &database,
        &identity,
        json!({"action": "move_provider", "id": id}),
    )
    .await;
    Ok(Json(
        json!({ "ok": true, "provider": mask_provider(provider) }),
    ))
}

/// GET /api/auth/providers/{id}/config — the raw config JSON object.
pub async fn get_provider_config(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let provider = fetch_provider(&db_clone, id).await?;
    Ok(Json(mask_config(&provider.config)))
}

/// POST /api/auth/providers/{id}/test — connection test for the provider.
///
/// Always answers `200` with `{"ok": bool, "detail": string}` so the UI can
/// show the outcome; `ok: false` with a human-readable `detail` on failure.
pub async fn test_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let provider = tokio::task::spawn_blocking(move || providers_db::get_provider(&db_clone, id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??
        .ok_or_else(|| AppError::Session("provider not found".into()))?;

    let (ok, detail) = match provider.provider_type.as_str() {
        "oidc" => test_oidc_discovery(&provider).await,
        "ldap" => {
            // LDAP binds can block for seconds on unreachable hosts — run the
            // sync bind off the executor thread.
            let p = provider.clone();
            tokio::task::spawn_blocking(move || test_ldap_bind(&p))
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
        }
        other => (
            false,
            format!("test not supported for provider type '{other}'"),
        ),
    };
    Ok(Json(json!({ "ok": ok, "detail": detail })))
}

/// DELETE /api/auth/providers/{id}
pub async fn delete_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    require_admin(&identity)?;

    let db_clone = database.clone();
    let found = tokio::task::spawn_blocking(move || providers_db::delete_provider(&db_clone, id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        super::groups::audit_config_change(
            &database,
            &identity,
            json!({"action": "delete_provider", "id": id}),
        )
        .await;
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::Session("provider not found".into()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fetch_provider(db: &Db, id: i64) -> Result<DbProvider, AppError> {
    let db_clone = db.clone();
    tokio::task::spawn_blocking(move || providers_db::get_provider(&db_clone, id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?
        .ok_or_else(|| AppError::Session("provider not found".into()))
}

async fn flip_enabled(
    db: &Db,
    id: i64,
    enabled: bool,
    identity: &Option<Extension<AuthIdentity>>,
) -> Result<Json<Value>, AppError> {
    let db_clone = db.clone();
    let found =
        tokio::task::spawn_blocking(move || providers_db::set_enabled(&db_clone, id, enabled))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
        super::groups::audit_config_change(
            db,
            identity,
            json!({"action": if enabled { "enable_provider" } else { "disable_provider" }, "id": id}),
        )
        .await;
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(AppError::Session("provider not found".into()))
    }
}

/// OIDC test: discover provider metadata from `issuer_url` (same discovery
/// path the runtime client uses in `src/oidc.rs`).
async fn test_oidc_discovery(provider: &DbProvider) -> (bool, String) {
    use openidconnect::core::CoreProviderMetadata;
    use openidconnect::IssuerUrl;

    let issuer_url = match provider.config.get("issuer_url").and_then(|v| v.as_str()) {
        Some(u) if !u.trim().is_empty() => u.to_string(),
        _ => return (false, "issuer_url is not configured".into()),
    };

    let http_client = match openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => return (false, format!("failed to build HTTP client: {e}")),
    };

    let issuer = match IssuerUrl::new(issuer_url.clone()) {
        Ok(u) => u,
        Err(e) => return (false, format!("invalid issuer_url: {e}")),
    };

    // Reshape failures the same way the interactive login path does
    // (issuer slash mistakes, empty JWKS): the operator gets the fix
    // instead of a Debug dump.
    match CoreProviderMetadata::discover_async(issuer, &http_client).await {
        Ok(_) => (true, "discovery ok".into()),
        Err(e) => (false, friendly_discovery_error(&format!("{e:?}"))),
    }
}

/// LDAP test: connect to `url` and bind with the configured `bind_dn`.
/// Runs synchronously (ldap3 sync feature), hence inside `spawn_blocking`
/// at the call site.
fn test_ldap_bind(provider: &DbProvider) -> (bool, String) {
    use ldap3::{LdapConn, LdapConnSettings};

    let get_str = |key: &str| {
        provider
            .config
            .get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let url = get_str("url");
    let bind_dn = get_str("bind_dn");
    let bind_password = get_str("bind_password");
    if url.is_empty() || bind_dn.is_empty() {
        return (
            false,
            "url and bind_dn are required for the LDAP test".into(),
        );
    }

    let settings = LdapConnSettings::new().set_conn_timeout(Duration::from_secs(10));
    let mut conn = match LdapConn::with_settings(settings, &url) {
        Ok(c) => c,
        Err(e) => return (false, format!("LDAP connect failed: {e}")),
    };

    match conn.simple_bind(&bind_dn, &bind_password) {
        Ok(res) if res.rc == 0 => {
            let _ = conn.unbind();
            (true, "bind ok".into())
        }
        Ok(res) => {
            let _ = conn.unbind();
            (
                false,
                format!("LDAP bind failed: rc={} {}", res.rc, res.text),
            )
        }
        Err(e) => (false, format!("LDAP bind failed: {e}")),
    }
}
