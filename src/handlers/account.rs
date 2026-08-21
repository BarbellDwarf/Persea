use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::Deserialize;

use crate::api::{AppState, SiteTitle, ThemeData};
use crate::auth::{extract_cookie, AuthIdentity};
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
    /// The user's current password, verified against the stored hash
    /// before any change is made.
    pub current_password: String,
    /// The replacement password, checked against the policy minimum
    /// length and the reuse history before hashing.
    pub new_password: String,
}

/// Change the signed-in user's password (POST /api/me/password).
///
/// Verifies the current password, applies the policy minimum length and
/// reuse-history checks, then stores the new Argon2id hash. Returns
/// `Validation` when the current password is wrong or the policy rejects
/// the new one, `Forbidden` when no user session is present, and
/// `Internal` when hashing or the database fails.
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

    // LDAP/OIDC accounts have no local password: reject before the
    // current-password check so the message is accurate.
    let db_for_source = database.clone();
    let email_for_source = email.clone();
    let auth_source = tokio::task::spawn_blocking(move || {
        crate::db::get_user_auth_source(&db_for_source, &email_for_source)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|_| AppError::Session("user not found".into()))?;
    if auth_source != "database" {
        return Err(AppError::Validation(
            "password is managed by the identity provider for this user".into(),
        ));
    }

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

// ── TOTP self-service ──────────────────────────────────────────────────────

/// Resolve the user behind a TOTP self-service request.
///
/// Accepts a full session identity, or the pending-MFA cookie set by the
/// enrollment gate. The enrollment path grants no session powers: the
/// cookie only reaches the enrollment page and these endpoints, and the
/// session is minted only after the factor is verified on the MFA page.
async fn resolve_totp_identity(
    identity: Option<Extension<AuthIdentity>>,
    database: &Db,
    headers: &HeaderMap,
) -> Result<(i64, String), AppError> {
    if let Some(Extension(AuthIdentity::User { email, .. })) = identity {
        let db_clone = database.clone();
        let email_clone = email.clone();
        let user = tokio::task::spawn_blocking(move || {
            crate::db::get_user_by_email(&db_clone, &email_clone)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok((user.id, email));
    }
    if let Some(token) = extract_cookie(headers, "persea_mfa_pending") {
        let db_clone = database.clone();
        let pending =
            tokio::task::spawn_blocking(move || crate::db::get_pending_mfa(&db_clone, &token))
                .await
                .map_err(|e| AppError::Internal(e.to_string()))?
                .map_err(|e| AppError::Internal(e.to_string()))?;
        if let Some(p) = pending {
            return Ok((p.user_id, p.user_email));
        }
    }
    Err(AppError::Forbidden("authentication required".into()))
}

/// Body of the TOTP verify/disable endpoints.
#[derive(Deserialize)]
pub struct TotpCodeRequest {
    /// Six-digit TOTP code.
    pub code: String,
}

/// GET /api/me/totp — TOTP enrollment status for the signed-in user.
pub async fn totp_status(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, _) = resolve_totp_identity(identity, &database, &headers).await?;
    let db_clone = database.clone();
    let enabled =
        tokio::task::spawn_blocking(move || crate::db::user_totp_enabled(&db_clone, user_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .unwrap_or(false);
    Ok(Json(serde_json::json!({"enabled": enabled})))
}

/// POST /api/me/totp/enroll — generate a TOTP enrollment (secret + QR).
///
/// The secret is stored disabled; it is enabled only after the code is
/// verified via /api/me/totp/verify, so a half-finished enrollment never
/// counts as a factor.
pub async fn totp_enroll(
    State(state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, email) = resolve_totp_identity(identity, &database, &headers).await?;
    let issuer = state
        .config()
        .auth
        .as_ref()
        .and_then(|a| a.totp.as_ref())
        .map(|t| t.issuer.clone())
        .unwrap_or_else(|| "persea".to_string());
    let enrollment = crate::totp::generate_enrollment(&email, &issuer)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let db_clone = database.clone();
    let secret_b32 = enrollment.secret_b32.clone();
    tokio::task::spawn_blocking(move || {
        crate::db::store_totp_secret(&db_clone, user_id, &secret_b32, "SHA1", 6, 30)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;
    // Stored disabled: only a verified code enables the factor.
    let db_clone = database.clone();
    tokio::task::spawn_blocking(move || crate::db::set_totp_enabled(&db_clone, user_id, false))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "secret_b32": enrollment.secret_b32,
        "qr_png": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &enrollment.qr_png),
        "issuer": issuer,
        "email": email,
    })))
}

/// POST /api/me/totp/verify — verify a code against the pending
/// enrollment secret and enable the factor.
pub async fn totp_verify(
    State(state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    headers: HeaderMap,
    Json(body): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, _) = resolve_totp_identity(identity, &database, &headers).await?;
    let skew = state
        .config()
        .auth
        .as_ref()
        .and_then(|a| a.totp.as_ref())
        .map(|t| t.skew)
        .unwrap_or(1);
    let db_clone = database.clone();
    let secret =
        tokio::task::spawn_blocking(move || crate::db::get_totp_secret(&db_clone, user_id))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(e.to_string()))?;
    // Verify against the stored secret regardless of its enabled state:
    // the enrollment flow verifies a code BEFORE enabling the factor.
    let valid = match secret {
        Some(s) => crate::totp::verify_code(
            &s.secret_b32,
            &body.code,
            crate::totp::algorithm_from_str(&s.algorithm),
            s.digits,
            s.period,
            skew,
        ),
        None => false,
    };
    if !valid {
        return Ok(Json(
            serde_json::json!({"ok": false, "error": "Invalid code. Try again."}),
        ));
    }
    let db_clone = database.clone();
    tokio::task::spawn_blocking(move || crate::db::set_totp_enabled(&db_clone, user_id, true))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// DELETE /api/me/totp — disable TOTP after verifying a current code.
///
/// Full session required: the pending-MFA enrollment path cannot disable
/// an existing factor.
pub async fn totp_disable(
    State(state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    _headers: HeaderMap,
    Json(body): Json<TotpCodeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Extension(AuthIdentity::User { email, .. }) =
        identity.ok_or_else(|| AppError::Forbidden("authentication required".into()))?
    else {
        return Err(AppError::Forbidden(
            "API-key sessions cannot manage TOTP".into(),
        ));
    };
    let db_clone = database.clone();
    let email_clone = email.clone();
    let user =
        tokio::task::spawn_blocking(move || crate::db::get_user_by_email(&db_clone, &email_clone))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .map_err(|e| AppError::Internal(e.to_string()))?;
    let skew = state
        .config()
        .auth
        .as_ref()
        .and_then(|a| a.totp.as_ref())
        .map(|t| t.skew)
        .unwrap_or(1);
    let db_clone = database.clone();
    let user_id = user.id;
    let code = body.code.clone();
    let valid = tokio::task::spawn_blocking(move || {
        crate::totp::verify_user_code(&db_clone, user_id, &code, skew)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;
    if !valid {
        return Ok(Json(
            serde_json::json!({"ok": false, "error": "Invalid code"}),
        ));
    }
    let db_clone = database.clone();
    tokio::task::spawn_blocking(move || crate::db::delete_totp_secret(&db_clone, user_id))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .map_err(|e| AppError::Internal(e.to_string()))?;
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
        initial_tab: "profile".to_string(),
    }
    .into_response()
}

/// GET /account/tokens.html (and the legacy /tokens.html alias)
///
/// The API-key management UI now lives in the combined profile page's
/// "API Keys" tab; this deep link renders that page with the tab active.
/// The route stays feature-gated on `enable_api_keys` in main.rs.
pub async fn tokens_page(
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
        initial_tab: "tokens".to_string(),
    }
    .into_response()
}

/// GET /account/totp.html
///
/// The TOTP management UI now lives in the combined profile page's
/// "Security" tab; this deep link renders that page with the tab active.
pub async fn totp_page(
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
        initial_tab: "security".to_string(),
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
    let docs = crate::templates::DOCS
        .iter()
        .map(|(slug, title, html, headings)| templates::DocSection {
            slug: (*slug).to_string(),
            title: (*title).to_string(),
            html: (*html).to_string(),
            headings: headings
                .iter()
                .map(|(h_slug, h_text)| templates::DocHeading {
                    slug: (*h_slug).to_string(),
                    text: (*h_text).to_string(),
                })
                .collect(),
        })
        .collect();
    templates::DocsTemplate {
        site_title: site_title.0.clone(),
        logo_url: logo_url(&theme),
        is_admin: is_admin(&identity),
        active_page: "docs".to_string(),
        csp_nonce: nonce.0,
        docs,
    }
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    fn test_db() -> Db {
        crate::db::init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn create_user(db: &Db, email: &str, role: &str) -> crate::db::User {
        let hash = crate::password::hash_password("s3cret-p@ss").unwrap();
        crate::db::create_user_with_password(db, email, email, &hash, role, "database").unwrap();
        crate::db::get_user_by_email(db, email).unwrap()
    }

    #[tokio::test]
    async fn totp_identity_resolves_from_pending_mfa_cookie() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        let token =
            crate::db::create_pending_mfa(&db, user.id, "u@example.com", "U", "viewer", None, 300)
                .unwrap();
        let headers = HeaderMap::from_iter([(
            header::COOKIE,
            format!("persea_mfa_pending={token}").parse().unwrap(),
        )]);
        let (uid, email) = resolve_totp_identity(None, &db, &headers).await.unwrap();
        assert_eq!(uid, user.id);
        assert_eq!(email, "u@example.com");
    }

    #[tokio::test]
    async fn totp_identity_resolves_from_session_identity() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        let id = AuthIdentity::User {
            email: "u@example.com".into(),
            name: "U".into(),
            role: "viewer".into(),
            groups: vec![],
        };
        let (uid, email) = resolve_totp_identity(Some(Extension(id)), &db, &HeaderMap::new())
            .await
            .unwrap();
        assert_eq!(uid, user.id);
        assert_eq!(email, "u@example.com");
    }

    #[tokio::test]
    async fn totp_identity_rejects_without_credentials() {
        let db = test_db();
        assert!(resolve_totp_identity(None, &db, &HeaderMap::new())
            .await
            .is_err());
    }

    #[tokio::test]
    async fn totp_identity_rejects_expired_pending_cookie() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        let token =
            crate::db::create_pending_mfa(&db, user.id, "u@example.com", "U", "viewer", None, 1)
                .unwrap();
        // Force expiry: backdate the record.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE auth_pending_mfa SET expires_at = datetime('now', '-1 minute')",
                [],
            )
            .unwrap();
        }
        let headers = HeaderMap::from_iter([(
            header::COOKIE,
            format!("persea_mfa_pending={token}").parse().unwrap(),
        )]);
        assert!(resolve_totp_identity(None, &db, &headers).await.is_err());
    }

    fn user_identity(email: &str) -> Option<Extension<AuthIdentity>> {
        Some(Extension(AuthIdentity::User {
            email: email.to_string(),
            name: "U".to_string(),
            role: "viewer".to_string(),
            groups: vec![],
        }))
    }

    #[tokio::test]
    async fn change_password_rejects_wrong_current_password() {
        let db = test_db();
        create_user(&db, "u@example.com", "viewer");
        let err = change_password(
            user_identity("u@example.com"),
            Extension(db),
            None,
            Json(ChangePasswordRequest {
                current_password: "wrong-password".to_string(),
                new_password: "a-brand-new-password-42".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn change_password_succeeds_with_correct_current_password() {
        let db = test_db();
        create_user(&db, "u@example.com", "viewer");
        let resp = change_password(
            user_identity("u@example.com"),
            Extension(db.clone()),
            None,
            Json(ChangePasswordRequest {
                current_password: "s3cret-p@ss".to_string(),
                new_password: "a-brand-new-password-42".to_string(),
            }),
        )
        .await
        .unwrap();
        assert_eq!(resp.0["ok"], true);
        let (_, _, _, _, _, stored_hash) = crate::db::get_user_login_info(&db, "u@example.com")
            .unwrap()
            .unwrap();
        assert!(
            crate::password::verify_password("a-brand-new-password-42", &stored_hash.unwrap())
                .unwrap()
        );
    }

    #[tokio::test]
    async fn change_password_rejects_short_new_password() {
        let db = test_db();
        create_user(&db, "u@example.com", "viewer");
        let err = change_password(
            user_identity("u@example.com"),
            Extension(db),
            None,
            Json(ChangePasswordRequest {
                current_password: "s3cret-p@ss".to_string(),
                new_password: "short".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }

    #[tokio::test]
    async fn change_password_rejects_non_database_user() {
        let db = test_db();
        let hash = crate::password::hash_password("s3cret-p@ss").unwrap();
        crate::db::create_user_with_password(&db, "oidc@example.com", "O", &hash, "viewer", "oidc")
            .unwrap();
        let err = change_password(
            user_identity("oidc@example.com"),
            Extension(db),
            None,
            Json(ChangePasswordRequest {
                current_password: "s3cret-p@ss".to_string(),
                new_password: "a-brand-new-password-42".to_string(),
            }),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AppError::Validation(_)));
    }
}
