use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;

use crate::api::{SiteTitle, ThemeData};
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;
use crate::templates;
use crate::CspNonce;

/// POST /api/me/password — change the signed-in user's password.
///
/// Enforces the password policy: minimum length, and the new
/// password must not match any of the user's last `password.history`
/// hashes. The new hash is recorded into the reuse history.
#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

pub async fn change_password(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    policy: Option<Extension<crate::password::PasswordPolicy>>,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    let email = match id {
        AuthIdentity::User { email, .. } => email.clone(),
        _ => {
            return Err(AppError::Forbidden(
                "API-key sessions cannot change the account password".into(),
            ))
        }
    };

    let policy = policy.map(|Extension(p)| p).unwrap_or_default();
    policy
        .check_length(&body.new_password)
        .map_err(AppError::Validation)?;

    let db_clone = database.clone();
    let email_clone = email.clone();
    let current = body.current_password.clone();
    let new_password = body.new_password.clone();
    let history = policy.history;

    tokio::task::spawn_blocking(move || {
        // Verify the current password against the stored hash.
        let (user_id, _, _, _, _disabled, stored_hash) =
            crate::db::get_user_login_info(&db_clone, &email_clone)
                .map_err(|_| AppError::Session("user not found".into()))?
                .ok_or(AppError::Session("user not found".into()))?;
        let valid = match stored_hash {
            Some(h) if !h.is_empty() => crate::password::verify_password(&current, &h)
                .map_err(|e| AppError::Internal(e.to_string()))?,
            _ => false,
        };
        if !valid {
            return Err(AppError::Validation("current password is incorrect".into()));
        }

        // Reuse check: reject passwords used recently (last `history` hashes).
        if crate::password::password_is_recent(&db_clone, user_id, &new_password, history)
            .map_err(|e| AppError::Internal(e.to_string()))?
        {
            return Err(AppError::Validation(format!(
                "password must differ from your last {} passwords",
                history
            )));
        }

        let password_hash = crate::password::hash_password(&new_password)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        crate::password::update_user_password_hash(&db_clone, user_id, &password_hash)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        crate::password::record_password_history(&db_clone, user_id, &password_hash, history)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok::<_, AppError>(())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Audit the change (no secrets — just the subject).
    let db_audit = database.clone();
    let email_audit = email.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = crate::audit::log_event(
            &db_audit,
            &mut crate::audit::EventBuilder::new("user.password.change", "success")
                .user_id(&email_audit)
                .build(),
        );
    })
    .await;

    Ok(Json(serde_json::json!({"ok": true})))
}

/// Determine if the current user has admin role.
fn is_admin(identity: &Option<Extension<AuthIdentity>>) -> bool {
    identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
}

/// Branding logo URL resolved from the startup ThemeData (config + DB
/// settings overlay); empty string renders the sidebar placeholder.
fn logo_url(theme: &ThemeData) -> String {
    theme.logo_url.clone().unwrap_or_default()
}

/// GET /account/profile.html
pub async fn profile_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::ProfileTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "profile".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /account/tokens.html
pub async fn tokens_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::AccountTokensTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "tokens".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /account/totp.html
pub async fn totp_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::AccountTotpTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "totp".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// GET /docs
pub async fn docs_page(
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    templates::DocsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "docs".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}
