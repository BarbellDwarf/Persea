use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap};
use axum::response::{AppendHeaders, Html, IntoResponse, Redirect, Response};
use axum::Extension;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::api::{OidcEnabled, OidcProviderNames};
use crate::audit;
use crate::auth::{client_ip, extract_cookie, TrustedProxies};
use crate::auth_chain::AuthChain;
use crate::auth_provider::AuthRequest;
use crate::db::{self, Db};
use crate::templates::LoginPageTemplate;
use crate::totp::TotpEnforcement;
use crate::CspNonce;

/// Returns true if the account/IP is locked out. Fails closed on DB error.
async fn check_lockout(database: &Db, username: &str, ip: &str) -> bool {
    let db = database.clone();
    let user = username.to_string();
    let addr = ip.to_string();
    match tokio::task::spawn_blocking(move || db::is_locked_out(&db, &user, &addr)).await {
        Ok(Ok(locked)) => locked,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, username, ip, "lockout check failed — failing closed");
            true // treat as locked out
        }
        Err(join_err) => {
            tracing::warn!(error = %join_err, username, ip, "lockout task panicked — failing closed");
            true
        }
    }
}

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
async fn redirect_to_mfa(db: &Db, user: &db::User, ttl_secs: u64, headers: &HeaderMap) -> Response {
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
        "persea_mfa_pending={}; Path=/auth/mfa; HttpOnly;{}SameSite=Lax; Max-Age={}",
        pending_token,
        crate::csrf::cookie_secure_attr(headers),
        ttl_secs
    );

    (
        AppendHeaders([(header::SET_COOKIE, mfa_cookie)]),
        Redirect::to("/auth/mfa"),
    )
        .into_response()
}

/// GET / — login page (or redirect to connections if already authenticated).
#[derive(serde::Deserialize)]
pub struct LoginQueryParams {
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub next: Option<String>,
}

pub async fn login_page(
    State(state): State<crate::api::AppState>,
    _addr: ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Extension(database): Extension<Db>,
    Extension(oidc_enabled): Extension<OidcEnabled>,
    oidc_provider_names: Option<Extension<OidcProviderNames>>,
    Extension(nonce): Extension<CspNonce>,
    axum::extract::Query(query): axum::extract::Query<LoginQueryParams>,
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

    let providers = oidc_provider_names
        .map(|Extension(p)| p.0.clone())
        .unwrap_or_default();
    let tmpl = LoginPageTemplate {
        site_title,
        logo_url,
        oidc_enabled: oidc_enabled.0,
        saml_enabled,
        oidc_button_text: "Sign in with SSO".into(),
        saml_button_text: "Sign in with SSO".into(),
        oidc_providers: providers,
        error: query.error,
        csp_nonce: nonce.0.clone(),
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

    // Reject if too many recent failed attempts (brute-force lockout)
    if check_lockout(&database, &form.username, &client_ip.to_string()).await {
        return Redirect::to("/?error=account_locked").into_response();
    }

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
            groups,
            ..
        } => {
            // Auto-provision local groups from provider claims (SAML/LDAP/
            // RADIUS) so folder ACLs referencing them work without manual
            // mapping — same behavior as the OIDC callback.
            if !groups.is_empty() {
                let db_groups = database.clone();
                let groups_provision = groups.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    match db::ensure_local_groups(&db_groups, &groups_provision) {
                        Ok(created) if created > 0 => {
                            tracing::info!(
                                created,
                                "auto-provisioned local groups from auth claims"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to auto-provision local groups")
                        }
                    }
                })
                .await;
            }
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
                return redirect_to_mfa(&database, &user, ttl_secs, &headers).await;
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

            // Clear previous failed-login lockout for this user+IP
            {
                let db_lock = database.clone();
                let username = form.username.clone();
                let ip = client_ip.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = db::record_successful_login(&db_lock, &username, &ip) {
                        tracing::warn!(error = %e, "failed to record successful login");
                    }
                })
                .await;
            }

            // Optional login credential pass-through: store the login
            // username/password encrypted so connection entries without their
            // own credentials can reuse them ([auth] pass_login_credentials).
            // TTL-bounded and replaced on every login; OIDC logins never reach
            // this handler (no password exists to store).
            if state
                .config()
                .auth
                .as_ref()
                .map(|a| a.pass_login_credentials)
                .unwrap_or(false)
            {
                let pass = form.password.clone();
                let username = form.username.clone();
                if !pass.is_empty() {
                    let key_hex = state.config().storage_encryption_key().unwrap_or_default();
                    if !key_hex.is_empty() {
                        if let Ok(key) = crate::crypto::EncryptionKey::from_hex(&key_hex) {
                            if let Ok(enc) = crate::crypto::encrypt_value(&key, &pass) {
                                let db_cred = database.clone();
                                let uid = user.id;
                                let expires =
                                    (chrono::Utc::now() + chrono::Duration::hours(12)).to_rfc3339();
                                let _ = tokio::task::spawn_blocking(move || {
                                    let _ = db::upsert_login_credentials(
                                        &db_cred, uid, &username, &enc, &expires,
                                    );
                                })
                                .await;
                            }
                        }
                    }
                }
            }

            let session_cookie = format!(
                "persea_session={}; Path=/; HttpOnly;{}SameSite=Lax; Max-Age={}",
                session_token,
                crate::csrf::cookie_secure_attr(&headers),
                ttl_secs
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

            // Record failed attempt for brute-force lockout
            {
                let db_lock = database.clone();
                let username = form.username.clone();
                let ip = client_ip.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = db::record_failed_login_attempt(&db_lock, &username, &ip) {
                        tracing::warn!(error = %e, "failed to record failed login attempt");
                    }
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
        Some("account_locked") => {
            r#"<p style="color:#ef4444;text-align:center;margin-bottom:1rem;font-size:0.875rem;">Account temporarily locked due to too many failed attempts. Please try again later.</p>"#
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
        <form method="POST" action="/auth/mfa" id="mfa-form">
            <div class="form-group">
                <label for="code">Verification Code</label>
                <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{{6}}" autocomplete="one-time-code" required autofocus>
            </div>
            <button type="submit" class="btn" id="mfa-submit">Verify</button>
        </form>
        <script>
        // CSRF: the csrf_token cookie is readable by JS (not HttpOnly), so
        // submit via fetch with the X-CSRF-Token header.
        (function() {{
            var form = document.getElementById('mfa-form');
            form.addEventListener('submit', function(evt) {{
                evt.preventDefault();
                var btn = document.getElementById('mfa-submit');
                btn.disabled = true;
                var csrf = (function() {{
                    var parts = document.cookie.split(';');
                    for (var i = 0; i < parts.length; i++) {{
                        var part = parts[i].trim();
                        if (part.indexOf('csrf_token=') === 0) return decodeURIComponent(part.substring(11));
                    }}
                    return null;
                }})();
                fetch('/auth/mfa', {{
                    method: 'POST',
                    headers: csrf ? {{ 'X-CSRF-Token': csrf }} : {{}},
                    body: new URLSearchParams(new FormData(form)),
                    credentials: 'same-origin',
                    redirect: 'follow'
                }}).then(function(resp) {{
                    if (resp.redirected) {{ location.href = resp.url; }}
                    else if (resp.ok) {{ location.href = '/'; }}
                    else {{ location.href = '/auth/mfa?error=invalid_code'; }}
                }}).catch(function() {{
                    btn.disabled = false;
                    location.href = '/auth/mfa?error=expired';
                }});
            }});
        }})();
        </script>
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

    // Check lockout before attempting TOTP verification
    if check_lockout(&database, &pending.user_email, &client_ip.to_string()).await {
        return Redirect::to("/auth/mfa?error=account_locked").into_response();
    }

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
        // Record failed MFA attempt for lockout tracking
        {
            let db_lock = database.clone();
            let username = pending.user_email.clone();
            let ip = client_ip.to_string();
            let _ = tokio::task::spawn_blocking(move || {
                if let Err(e) = db::record_failed_login_attempt(&db_lock, &username, &ip) {
                    tracing::warn!(error = %e, "failed to record failed login attempt");
                }
            })
            .await;
        }
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

    let secure = crate::csrf::cookie_secure_attr(&headers);
    let session_cookie = format!(
        "persea_session={}; Path=/; HttpOnly;{}SameSite=Lax; Max-Age={}",
        session_token,
        if secure.is_empty() { "" } else { "Secure; " },
        ttl_secs
    );
    let clear_mfa_cookie = format!(
        "persea_mfa_pending=; Path=/auth/mfa; HttpOnly;{}SameSite=Lax; Max-Age=0",
        if secure.is_empty() { "" } else { "Secure; " }
    );

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
pub async fn saml_acs(
    State(_state): State<crate::api::AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(_sp): Extension<Arc<crate::auth_providers::saml::SamlProvider>>,
    Extension(auth_chain): Extension<Arc<AuthChain>>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(totp_enforcement): Extension<TotpEnforcement>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<SamlAcsForm>,
) -> Response {
    use crate::auth_provider::{AuthRequest, AuthResult};
    use std::collections::HashMap;

    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);

    if form.SAMLResponse.is_empty() {
        return Redirect::to("/?error=saml_missing_response").into_response();
    }

    // Build an AuthRequest with the SAMLResponse as a callback parameter.
    let mut callback_params = HashMap::new();
    callback_params.insert("SAMLResponse".to_string(), form.SAMLResponse.clone());
    let auth_request = AuthRequest {
        client_ip,
        callback_params: Some(callback_params),
        ..AuthRequest::default()
    };

    // Try each provider in chain order (first success wins).
    let result = auth_chain.authenticate(&auth_request).await;

    match result {
        AuthResult::Success {
            subject,
            display_name,
            role,
            groups,
            ..
        } => {
            // Auto-provision local groups from SAML claims.
            if !groups.is_empty() {
                let db_groups = database.clone();
                let groups_provision = groups.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    match db::ensure_local_groups(&db_groups, &groups_provision) {
                        Ok(created) if created > 0 => {
                            tracing::info!(
                                created,
                                "auto-provisioned local groups from SAML claims"
                            );
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "failed to auto-provision local groups")
                        }
                    }
                })
                .await;
            }

            // Look up the user by email/subject
            let db_clone = database.clone();
            let email = subject.clone();
            let user = match tokio::task::spawn_blocking(move || {
                db::get_user_by_email(&db_clone, &email)
            })
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
            if check_totp_enforcement(&database, user.id, &effective_role, &totp_enforcement).await
            {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(&database, &user, ttl_secs, &headers).await;
            }

            // Create auth session
            let ttl_secs = 86400; // 24 hours
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
                "SAML login successful"
            );

            // Audit: successful SAML login
            {
                let db_audit = database.clone();
                let uid = user.id.to_string();
                let ip = client_ip.to_string();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = audit::log_event(
                        &db_audit,
                        &mut audit::EventBuilder::new("auth.saml.login", "success")
                            .user_id(&uid)
                            .source_ip(&ip)
                            .build(),
                    );
                })
                .await;
            }

            // Redirect to RelayState if present, otherwise /connections.html
            let redirect_to = form
                .RelayState
                .filter(|n| n.starts_with('/') && !n.starts_with("//") && !n.contains("://"))
                .unwrap_or_else(|| "/connections.html".to_string());

            let session_cookie = format!(
                "persea_session={}; Path=/; HttpOnly;{}SameSite=Lax; Max-Age={}",
                session_token,
                crate::csrf::cookie_secure_attr(&headers),
                ttl_secs
            );

            (
                AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                Redirect::to(&redirect_to),
            )
                .into_response()
        }
        AuthResult::Failure(msg) => {
            tracing::warn!(
                client_ip = %client_ip,
                "SAML authentication failed: {}",
                msg
            );
            Redirect::to("/?error=saml_auth_failed").into_response()
        }
        AuthResult::Redirect(url) => Redirect::temporary(&url).into_response(),
        AuthResult::Unavailable(msg) => {
            tracing::error!("SAML auth provider unavailable: {}", msg);
            Redirect::to("/?error=saml_unavailable").into_response()
        }
    }
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
