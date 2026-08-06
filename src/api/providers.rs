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
use crate::providers_db::{self, DbProvider, MoveDirection};
use axum::extract::Path;
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Deserialize)]
pub struct CreateProviderRequest {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(default)]
    pub config: Value,
}

#[derive(Deserialize)]
pub struct MoveProviderRequest {
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
    .map_err(|e| AppError::Internal(e.to_string()))??;

    Ok((StatusCode::CREATED, Json(json!(provider))))
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
    Ok(Json(json!(provider)))
}

/// POST /api/auth/providers/{id}/enable
pub async fn enable_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;
    flip_enabled(&database, id, true).await
}

/// POST /api/auth/providers/{id}/disable
pub async fn disable_provider(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    require_admin(&identity)?;
    flip_enabled(&database, id, false).await
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

    Ok(Json(json!({ "ok": true, "provider": provider })))
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
    Ok(Json(provider.config))
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
        "ldap" => test_ldap_bind(&provider),
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

async fn flip_enabled(db: &Db, id: i64, enabled: bool) -> Result<Json<Value>, AppError> {
    let db_clone = db.clone();
    let found =
        tokio::task::spawn_blocking(move || providers_db::set_enabled(&db_clone, id, enabled))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
    if found {
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

    match CoreProviderMetadata::discover_async(issuer, &http_client).await {
        Ok(_) => (true, "discovery ok".into()),
        Err(e) => (false, format!("OIDC discovery failed: {e:?}")),
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
