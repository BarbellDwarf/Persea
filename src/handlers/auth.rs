use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::Extension;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::api::OidcEnabled;
use crate::audit;
use crate::auth::{client_ip, extract_cookie, TrustedProxies};
use crate::auth_chain::AuthChain;
use crate::auth_provider::AuthRequest;
use crate::db::{self, Db};
use crate::templates::LoginPageTemplate;
use crate::totp::TotpEnforcement;
use crate::CspNonce;

/// Check if TOTP enforcement requires MFA for this user.
/// Returns true if TOTP is mandatory and the user has it enrolled.
async fn check_totp_enforcement(
    db: &Db,
    user_id: i64,
    role: &str,
    enforcement: &TotpEnforcement,
) -> bool {
    match enforcement {
        TotpEnforcement::Off => false,
        TotpEnforcement::AdminsOnly => {
            if role != "admin" {
                return false;
            }
            let db_clone = db.clone();
            tokio::task::spawn_blocking(move || db::user_totp_enabled(&db_clone, user_id))
                .await
                .unwrap_or(Ok(false))
                .unwrap_or(false)
        }
        TotpEnforcement::All => {
            let db_clone = db.clone();
            tokio::task::spawn_blocking(move || db::user_totp_enabled(&db_clone, user_id))
                .await
                .unwrap_or(Ok(false))
                .unwrap_or(false)
        }
    }
}

/// Create a pending MFA record and redirect to the MFA page.
/// Returns the response with the MFA pending cookie set.
async fn redirect_to_mfa(db: &Db, user: &db::User, ttl_secs: u64) -> Response {
    let db_clone = db.clone();
    let user_id = user.id;
    let email = user.email.clone();
    let name = user.name.clone();
    let role = user.role.clone();
    let oidc_subject = user.oidc_subject.clone();

    let pending_token = match tokio::task::spawn_blocking(move || {
        db::create_pending_mfa(
            &db_clone,
            user_id,
            &email,
            &name,
            &role,
            oidc_subject.as_deref(),
            ttl_secs,
        )
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return Redirect::to("/?error=mfa_setup_failed").into_response();
        }
    };

    let mfa_cookie = format!(
        "persea_mfa_pending={}; Path=/auth/mfa; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        pending_token, ttl_secs
    );

    (
        AppendHeaders([(header::SET_COOKIE, mfa_cookie)]),
        Redirect::to("/auth/mfa"),
    )
        .into_response()
}

/// GET / — login page (or redirect to connections if already authenticated).
pub async fn login_page(
    State(state): State<crate::api::AppState>,
    _addr: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(database): Extension<Db>,
    Extension(oidc_enabled): Extension<OidcEnabled>,
    Extension(_nonce): Extension<CspNonce>,
) -> Response {
    // Redirect to setup wizard if no users exist (first run)
    if crate::handlers::setup::needs_setup(&database) {
        return Redirect::to("/setup").into_response();
    }
    // Check if already authenticated via session cookie
    let session_token = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("persea_session=").map(|v| v.to_string())
            })
        });
    if let Some(token) = session_token {
        let db_clone = database.clone();
        if tokio::task::spawn_blocking(move || db::validate_auth_session(&db_clone, &token))
            .await
            .unwrap_or(Err(crate::db::AuthError::InvalidSession))
            .is_ok()
        {
            return Redirect::to("/connections.html").into_response();
        }
    }

    let site_title = state.config().site_title.clone();
    let logo_url = state
        .config()
        .theme
        .as_ref()
        .and_then(|t| t.logo_url.clone())
        .unwrap_or_default();
    let saml_enabled = state
        .config()
        .auth
        .as_ref()
        .is_some_and(|a| a.saml.is_some());

    let tmpl = LoginPageTemplate {
        site_title,
        logo_url,
        oidc_enabled: oidc_enabled.0,
        saml_enabled,
        oidc_button_text: "Sign in with SSO".into(),
        saml_button_text: "Sign in with SSO".into(),
    };

    tmpl.into_response()
}

/// POST /auth/login — password-based auth (tries DB/LDAP/RADIUS in chain order).
pub async fn login_submit(
    State(state): State<crate::api::AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(auth_chain): Extension<Arc<AuthChain>>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<LoginFormData>,
) -> Response {
    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);

    // Build auth request
    let auth_request = AuthRequest {
        client_ip,
        username: Some(form.username.clone()),
        password: Some(form.password.clone()),
        ..AuthRequest::default()
    };

    // Try each provider in chain order (first success wins)
    let result = auth_chain.authenticate(&auth_request).await;

    match result {
        crate::auth_provider::AuthResult::Success {
            subject,
            display_name,
            role,
            ..
        } => {
            // Look up the user to get their ID
            let db_clone = database.clone();
            let email = subject.clone();
            let user =
                match tokio::task::spawn_blocking(move || db::get_user_by_email(&db_clone, &email))
                    .await
                {
                    Ok(Ok(user)) => user,
                    _ => {
                        return Redirect::to("/?error=user_lookup_failed").into_response();
                    }
                };

            if user.disabled {
                return Redirect::to("/?error=account_disabled").into_response();
            }

            // Check TOTP enforcement before creating session
            let effective_role = role.clone().unwrap_or_else(|| user.role.clone());
            let totp_enforcement = state
                .config()
                .auth
                .as_ref()
                .and_then(|a| a.totp.as_ref())
                .map(|t| t.enforcement)
                .unwrap_or(TotpEnforcement::Off);

            if check_totp_enforcement(&database, user.id, &effective_role, &totp_enforcement).await
            {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(&database, &user, ttl_secs).await;
            }

            // Create auth session
            let ttl_secs = 86400; // 24 hours — matches auth_session_ttl_secs default
            let db_clone = database.clone();
            let session_token = match tokio::task::spawn_blocking(move || {
                db::create_auth_session(&db_clone, user.id, ttl_secs)
            })
            .await
            {
                Ok(Ok(token)) => token,
                _ => {
                    return Redirect::to("/?error=session_failed").into_response();
                }
            };

            tracing::info!(
                email = %display_name,
                role = role.as_deref().unwrap_or("unknown"),
                client_ip = %client_ip,
                "Password login successful"
            );

            // Audit: successful login
            {
                let db_audit = database.clone();
                let uid = user.id.to_string();
                let ip = client_ip.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("auth.login.success", "success")
                            .user_id(&uid)
                            .source_ip(&ip)
                            .build(),
                    );
                })
                .await;
            }

            let session_cookie = format!(
                "persea_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
                session_token, ttl_secs
            );

            (
                AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                Redirect::to("/connections.html"),
            )
                .into_response()
        }
        crate::auth_provider::AuthResult::Failure(msg) => {
            tracing::warn!(
                client_ip = %client_ip,
                username = %form.username,
                "Password login failed: {}",
                msg
            );
            // Audit: failed login
            {
                let db_audit = database.clone();
                let ip = client_ip.to_string();
                let reason = msg.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("auth.login.failure", "failure")
                            .source_ip(&ip)
                            .details(serde_json::json!({"reason": reason}))
                            .build(),
                    );
                })
                .await;
            }
            Redirect::to("/?error=invalid_credentials").into_response()
        }
        crate::auth_provider::AuthResult::Redirect(url) => {
            Redirect::temporary(&url).into_response()
        }
        crate::auth_provider::AuthResult::Unavailable(msg) => {
            tracing::error!("Auth provider unavailable: {}", msg);
            Redirect::to("/?error=auth_unavailable").into_response()
        }
    }
}

/// Query parameters for the MFA page.
#[derive(serde::Deserialize)]
pub struct MfaQueryParams {
    pub error: Option<String>,
}

/// GET /auth/mfa — TOTP verification page.
pub async fn mfa_page(Query(params): Query<MfaQueryParams>) -> Response {
    let error_html = match params.error.as_deref() {
        Some("expired") => {
            r#"<p style="color:#ef4444;text-align:center;margin-bottom:1rem;font-size:0.875rem;">Session expired. Please log in again.</p>"#
        }
        Some("no_session") => {
            r#"<p style="color:#ef4444;text-align:center;margin-bottom:1rem;font-size:0.875rem;">No pending MFA session. Please log in first.</p>"#
        }
        Some("invalid_code") => {
            r#"<p style="color:#ef4444;text-align:center;margin-bottom:1rem;font-size:0.875rem;">Invalid verification code. Please try again.</p>"#
        }
        Some(_) => {
            r#"<p style="color:#ef4444;text-align:center;margin-bottom:1rem;font-size:0.875rem;">An error occurred. Please try again.</p>"#
        }
        None => {
            r#"<p style="text-align:center;color:#94a3b8;margin-bottom:1rem;font-size:0.875rem;">Enter the code from your authenticator app</p>"#
        }
    };

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Factor Authentication</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .mfa-container {{ background: #111827; border: 1px solid #1e3a5f; border-radius: 12px; padding: 2rem; width: 100%; max-width: 400px; }}
        .mfa-title {{ text-align: center; margin-bottom: 1.5rem; font-size: 1.5rem; color: #e2e8f0; }}
        .form-group {{ margin-bottom: 1rem; }}
        label {{ display: block; margin-bottom: 0.25rem; font-size: 0.875rem; color: #94a3b8; }}
        input[type="text"] {{ width: 100%; padding: 0.625rem 0.75rem; background: #1e293b; border: 1px solid #1e3a5f; border-radius: 6px; color: #e2e8f0; font-size: 1.25rem; text-align: center; letter-spacing: 0.5em; outline: none; }}
        input:focus {{ border-color: #3b82f6; }}
        .btn {{ width: 100%; padding: 0.625rem; background: #3b82f6; color: #fff; border: none; border-radius: 6px; font-size: 0.875rem; cursor: pointer; }}
        .btn:hover {{ background: #2563eb; }}
    </style>
</head>
<body>
    <div class="mfa-container">
        <h1 class="mfa-title">Multi-Factor Authentication</h1>
        {error_html}
        <form method="POST" action="/auth/mfa">
            <div class="form-group">
                <label for="code">Verification Code</label>
                <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{{6}}" autocomplete="one-time-code" required autofocus>
            </div>
            <button type="submit" class="btn">Verify</button>
        </form>
    </div>
</body>
</html>"#
    );

    Html(html).into_response()
}

/// MFA form data.
#[derive(serde::Deserialize)]
pub struct MfaFormData {
    pub code: String,
}

/// POST /auth/mfa — verify TOTP code and complete login.
pub async fn mfa_submit(
    State(_state): State<crate::api::AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<MfaFormData>,
) -> Response {
    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);

    // Read the pending MFA cookie
    let pending_token = match extract_cookie(&headers, "persea_mfa_pending") {
        Some(t) => t,
        None => {
            return Redirect::to("/auth/mfa?error=no_session").into_response();
        }
    };

    // Look up the pending MFA record
    let db_clone = database.clone();
    let pending_token_for_lookup = pending_token.clone();
    let pending = match tokio::task::spawn_blocking(move || {
        db::get_pending_mfa(&db_clone, &pending_token_for_lookup)
    })
    .await
    {
        Ok(Ok(Some(p))) => p,
        Ok(Ok(None)) => {
            return Redirect::to("/auth/mfa?error=expired").into_response();
        }
        _ => {
            return Redirect::to("/auth/mfa?error=expired").into_response();
        }
    };

    // Verify TOTP code
    let db_clone = database.clone();
    let user_id = pending.user_id;
    let code = form.code.clone();
    let skew = _state
        .config()
        .auth
        .as_ref()
        .and_then(|a| a.totp.as_ref())
        .map(|t| t.skew)
        .unwrap_or(1);

    let valid = tokio::task::spawn_blocking(move || {
        crate::totp::verify_user_code(&db_clone, user_id, &code, skew)
    })
    .await
    .unwrap_or_default();

    if !valid {
        return Redirect::to("/auth/mfa?error=invalid_code").into_response();
    }

    // Delete the pending MFA record
    let db_clone = database.clone();
    let _ = tokio::task::spawn_blocking(move || db::delete_pending_mfa(&db_clone, &pending_token))
        .await;

    // Create final auth session
    let ttl_secs = 86400; // 24 hours
    let db_clone = database.clone();
    let session_token = match tokio::task::spawn_blocking(move || {
        db::create_auth_session(&db_clone, pending.user_id, ttl_secs)
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return Redirect::to("/?error=session_failed").into_response();
        }
    };

    tracing::info!(
        email = %pending.user_email,
        role = %pending.user_role,
        client_ip = %client_ip,
        "MFA login successful"
    );

    // Audit: successful MFA login
    {
        let db_audit = database.clone();
        let uid = pending.user_id.to_string();
        let ip = client_ip.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = audit::log_event(
                &db_audit,
                &mut audit::EventBuilder::new("auth.mfa.success", "success")
                    .user_id(&uid)
                    .source_ip(&ip)
                    .build(),
            );
        })
        .await;
    }

    let session_cookie = format!(
        "persea_session={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={}",
        session_token, ttl_secs
    );
    let clear_mfa_cookie =
        "persea_mfa_pending=; Path=/auth/mfa; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
            .to_string();

    (
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, clear_mfa_cookie),
        ]),
        Redirect::to("/connections.html"),
    )
        .into_response()
}

// ── Form data ──────────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct LoginFormData {
    pub username: String,
    pub password: String,
}

// ── SAML handlers ──────────────────────────────────────────────────────────

/// POST /auth/saml/acs — SAML Assertion Consumer Service callback.
///
/// Receives the SAMLResponse from the IdP, validates it, creates an auth
/// session, and redirects to connections.
/// POST /auth/saml/acs — SAML Assertion Consumer Service callback.
///
/// Receives the SAMLResponse from the IdP, validates it, creates an auth
/// session, and redirects to connections.
pub async fn saml_acs() -> Response {
    Redirect::to("/?error=saml_not_configured").into_response()
}

#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
pub struct SamlAcsForm {
    pub SAMLResponse: String,
    #[serde(default)]
    pub RelayState: Option<String>,
}

/// GET /auth/saml/metadata — SP metadata XML.
pub async fn saml_metadata(
    Extension(sp): Extension<Arc<crate::auth_providers::saml::SamlProvider>>,
) -> Response {
    use axum::http::StatusCode;
    let xml = crate::auth_providers::saml::generate_sp_metadata(sp.config());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/xml")],
        xml,
    )
        .into_response()
}
