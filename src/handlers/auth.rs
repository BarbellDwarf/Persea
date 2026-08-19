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
use crate::csrf::TlsEnabled;
use crate::db::{self, Db};
use crate::templates::{AccountTotpTemplate, LoginPageTemplate};
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

/// Outcome of the TOTP enforcement gate for one login.
enum TotpGate {
    /// TOTP is not required for this user; login proceeds normally.
    None,
    /// TOTP is required and enrolled; send the user through the MFA page.
    Mfa,
    /// TOTP is required but not enrolled; send the user to the enrollment
    /// page with a pending-MFA cookie. No session is minted until the
    /// factor is verified on the MFA page.
    Enroll,
}

/// Apply the TOTP enforcement policy to a user about to be logged in.
///
/// AdminsOnly: admins must pass TOTP, and must enroll before their first
/// login counts. All: every user must enroll and pass TOTP. A user who
/// should be enrolled but is not is sent to the enrollment page rather
/// than silently skipping MFA (the pre-fix behavior minted a full
/// session at the Enroll gate).
async fn check_totp_enforcement(
    db: &Db,
    user_id: i64,
    role: &str,
    enforcement: &TotpEnforcement,
) -> TotpGate {
    let db_clone = db.clone();
    let enrolled = tokio::task::spawn_blocking(move || db::user_totp_enabled(&db_clone, user_id))
        .await
        .unwrap_or(Ok(false))
        .unwrap_or(false);

    match enforcement {
        TotpEnforcement::Off => TotpGate::None,
        TotpEnforcement::AdminsOnly => {
            if role != "admin" {
                TotpGate::None
            } else if enrolled {
                TotpGate::Mfa
            } else {
                TotpGate::Enroll
            }
        }
        TotpEnforcement::All => {
            if enrolled {
                TotpGate::Mfa
            } else {
                TotpGate::Enroll
            }
        }
    }
}

/// Create a pending MFA record and redirect to the given target with the
/// pending-MFA cookie. Used by the MFA gate (target `/auth/mfa`) and the
/// enrollment gate (target `/auth/enroll`); neither mints a session.
/// `desktop` marks the record as a desktop login so the MFA completion
/// handler mints the scoped token after the TOTP gate (persea#227).
/// Returns the response with the MFA pending cookie set.
// The 9 parameters mirror the caller's full request context; bundling them
// into a struct would add ceremony to both call sites for a style lint.
#[allow(clippy::too_many_arguments)]
async fn redirect_to_mfa(
    db: &Db,
    user: &db::User,
    ttl_secs: u64,
    target: &str,
    desktop: bool,
    headers: &HeaderMap,
    tls_enabled: bool,
    trusted_proxies: Option<&TrustedProxies>,
    peer_ip: Option<std::net::IpAddr>,
) -> Response {
    let db_clone = db.clone();
    let user_id = user.id;
    let email = user.email.clone();
    let name = user.name.clone();
    let role = user.role.clone();
    let oidc_subject = user.oidc_subject.clone();

    let pending_token = match tokio::task::spawn_blocking(move || {
        if desktop {
            db::create_pending_mfa_desktop(
                &db_clone,
                user_id,
                &email,
                &name,
                &role,
                oidc_subject.as_deref(),
                ttl_secs,
            )
        } else {
            db::create_pending_mfa(
                &db_clone,
                user_id,
                &email,
                &name,
                &role,
                oidc_subject.as_deref(),
                ttl_secs,
            )
        }
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return Redirect::to("/?error=mfa_setup_failed").into_response();
        }
    };

    // The enrollment target needs a Path=/ cookie so the enrollment page
    // and the TOTP self-service API can read it; the MFA target keeps the
    // cookie scoped to the MFA page.
    let cookie_path = if target == "/auth/enroll" {
        "/"
    } else {
        "/auth/mfa"
    };
    let mfa_cookie = format!(
        "persea_mfa_pending={}; Path={}; HttpOnly;{} SameSite=Lax; Max-Age={}",
        pending_token,
        cookie_path,
        crate::csrf::cookie_secure_attr(headers, tls_enabled, trusted_proxies, peer_ip),
        ttl_secs
    );

    (
        AppendHeaders([(header::SET_COOKIE, mfa_cookie)]),
        Redirect::to(target),
    )
        .into_response()
}

/// Query parameters for the login page.
#[derive(serde::Deserialize)]
pub struct LoginQueryParams {
    /// Error code from a failed login redirect (`/?error=...`), rendered
    /// as a message on the login card.
    #[serde(default)]
    pub error: Option<String>,
    /// Reserved for post-login redirects; parsed but not consumed today.
    #[serde(default)]
    pub next: Option<String>,
}

/// GET / — login page, or a redirect to the connections page when a valid
/// session cookie is already present. First run redirects to the setup
/// wizard (no users exist yet).
#[allow(clippy::too_many_arguments)]
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
    // SAML is offered whenever it's configured — the routes are
    // registered for both config-file and DB-configured providers
    // (main.rs), so the button matches what's actually reachable.
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

#[allow(clippy::too_many_arguments)]
/// POST /auth/login — password-based auth (tries DB/LDAP/RADIUS in chain order).
pub async fn login_submit(
    State(state): State<crate::api::AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(tls_enabled): Extension<TlsEnabled>,
    Extension(auth_chain): Extension<Arc<AuthChain>>,
    Extension(nonce): Extension<CspNonce>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<LoginFormData>,
) -> Response {
    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);

    // SAML SSO start: the login page's SAML button posts here with `saml=1`
    // (no username/password yet). The chain's SAML provider builds a signed
    // AuthnRequest and answers with the IdP redirect; the lockout check is
    // skipped because there is no password to validate.
    if form.saml {
        let auth_request = AuthRequest {
            client_ip,
            // Desktop logins ride the SAML RelayState so the ACS handler
            // knows to mint the scoped token after the IdP round trip.
            relay_state: form.desktop.then(|| "desktop".to_string()),
            ..AuthRequest::default()
        };
        // Providers may do blocking I/O (the LDAP client creates its own
        // tokio runtime internally), so run the chain off the async runtime.
        // futures::executor::block_on drives the future without a tokio
        // runtime context on the thread (Handle::current().block_on would
        // set one and the sync client would panic).
        let result = tokio::task::spawn_blocking(move || {
            futures::executor::block_on(auth_chain.authenticate(&auth_request))
        })
        .await
        .unwrap_or(crate::auth_provider::AuthResult::Failure(
            "no provider could authenticate".into(),
        ));
        return match result {
            crate::auth_provider::AuthResult::Redirect(url) => {
                Redirect::temporary(&url).into_response()
            }
            crate::auth_provider::AuthResult::Failure(msg) => {
                tracing::warn!(client_ip = %client_ip, "SAML login start failed: {msg}");
                Redirect::to("/?error=saml_auth_failed").into_response()
            }
            crate::auth_provider::AuthResult::Unavailable(msg) => {
                tracing::error!("SAML auth provider unavailable: {msg}");
                Redirect::to("/?error=saml_unavailable").into_response()
            }
            crate::auth_provider::AuthResult::Success { .. } => {
                tracing::warn!(client_ip = %client_ip, "SAML login start unexpectedly succeeded without credentials");
                Redirect::to("/?error=saml_auth_failed").into_response()
            }
        };
    }

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

    // Try each provider in chain order (first success wins). Providers may
    // do blocking I/O (the LDAP client creates its own tokio runtime
    // internally), so run the chain off the async runtime: a sync client
    // started on a tokio worker thread panics with "Cannot start a runtime
    // from within a runtime" and kills the request.
    let result = match tokio::task::spawn_blocking(move || {
        futures::executor::block_on(auth_chain.authenticate(&auth_request))
    })
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "auth chain panicked during password login");
            return Redirect::to("/?error=invalid_credentials").into_response();
        }
    };

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

            let totp_gate =
                check_totp_enforcement(&database, user.id, &effective_role, &totp_enforcement)
                    .await;

            // Enrolled users go through the MFA page before any session exists.
            if matches!(totp_gate, TotpGate::Mfa) {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(
                    &database,
                    &user,
                    ttl_secs,
                    "/auth/mfa",
                    form.desktop,
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip()),
                )
                .await;
            }

            // Enforcement requires enrollment but the user has no TOTP
            // yet: no session is minted. The pending-MFA cookie reaches
            // the enrollment page only; the session is created after the
            // factor is verified on the MFA page, so never enrolling
            // means never getting in.
            if matches!(totp_gate, TotpGate::Enroll) {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(
                    &database,
                    &user,
                    ttl_secs,
                    "/auth/enroll",
                    form.desktop,
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip()),
                )
                .await;
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

            // Both enforcement gates (MFA and enrollment) returned above,
            // so no factor is required and the session is safe to mint.
            let redirect_to = "/connections.html";

            let session_cookie = format!(
                "persea_session={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age={}",
                session_token,
                crate::csrf::cookie_secure_attr(
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip())
                ),
                ttl_secs
            );

            // Desktop login: mint the scoped token (12h TTL) and answer
            // with the connected page instead of the redirect, so the
            // client that asked for the token gets it in the response.
            if form.desktop {
                return match crate::api::pairing::mint_login_scoped_token(
                    &database, user.id, &client_ip,
                )
                .await
                {
                    Ok((token_id, plaintext, _name, _max_role, _expires_db, expires_rfc)) => {
                        tracing::info!(
                            email = %display_name,
                            token_id,
                            "Desktop scoped token issued after interactive login"
                        );
                        (
                            AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                            desktop_connected_page(&nonce.0, &plaintext, &expires_rfc),
                        )
                            .into_response()
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to mint desktop scoped token");
                        Redirect::to("/?error=token_failed").into_response()
                    }
                };
            }

            (
                AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                Redirect::to(redirect_to),
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
    /// Error code from the previous verification attempt, rendered as a
    /// hint on the page (`expired`, `no_session`, `invalid_code`,
    /// `account_locked`).
    pub error: Option<String>,
}

/// GET /auth/mfa — TOTP verification page.
///
/// Rendered as a self-contained page because it sits outside the template
/// tree (no site session yet). The inline script carries the CSP nonce from
/// the security-headers middleware; without it the script never runs and
/// the native form POST carries no CSRF token.
pub async fn mfa_page(
    Query(params): Query<MfaQueryParams>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
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
            <input type="hidden" name="csrf_token" value="">
            <div class="form-group">
                <label for="code">Verification Code</label>
                <input type="text" id="code" name="code" maxlength="6" pattern="[0-9]{{6}}" autocomplete="one-time-code" required autofocus>
            </div>
            <button type="submit" class="btn" id="mfa-submit">Verify</button>
        </form>
        <script nonce="{nonce}">
        // CSRF: the csrf_token cookie is readable by JS (not HttpOnly), so
        // the hidden field is filled from it and the middleware's form-body
        // peek accepts the POST. The form submits natively — the browser
        // handles the 303 redirect and its session cookie, which
        // fetch()+redirect:'follow' does not reliably do in Chromium.
        (function() {{
            var csrf = (function() {{
                var parts = document.cookie.split(';');
                for (var i = 0; i < parts.length; i++) {{
                    var part = parts[i].trim();
                    if (part.indexOf('csrf_token=') === 0) return decodeURIComponent(part.substring(11));
                }}
                return null;
            }})();
            var hidden = document.querySelector('input[name="csrf_token"]');
            if (hidden && csrf) hidden.value = csrf;
        }})();
        </script>
    </div>
</body>
</html>"#,
        nonce = nonce.0
    );

    Html(html).into_response()
}

/// MFA form data.
#[derive(serde::Deserialize)]
pub struct MfaFormData {
    /// Six-digit TOTP code the user entered.
    pub code: String,
}

/// POST /auth/mfa — verify TOTP code and complete login.
#[allow(clippy::too_many_arguments)]
pub async fn mfa_submit(
    State(_state): State<crate::api::AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(tls_enabled): Extension<TlsEnabled>,
    Extension(nonce): Extension<CspNonce>,
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

    let secure = crate::csrf::cookie_secure_attr(
        &headers,
        tls_enabled.0,
        Some(&trusted_proxies),
        Some(addr.ip()),
    );
    let session_cookie = format!(
        "persea_session={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age={}",
        session_token,
        if secure.is_empty() { "" } else { "Secure;" },
        ttl_secs
    );
    let clear_mfa_cookie = format!(
        "persea_mfa_pending=; Path=/auth/mfa; HttpOnly;{} SameSite=Lax; Max-Age=0",
        if secure.is_empty() { "" } else { "Secure;" }
    );

    // Desktop login: mint the scoped token (12h TTL) and answer with the
    // connected page instead of the redirect, so the client that asked for
    // the token gets it in the response.
    if pending.desktop {
        return match crate::api::pairing::mint_login_scoped_token(
            &database,
            pending.user_id,
            &client_ip,
        )
        .await
        {
            Ok((token_id, plaintext, _name, _max_role, _expires_db, expires_rfc)) => {
                tracing::info!(
                    email = %pending.user_email,
                    token_id,
                    "Desktop scoped token issued after MFA login"
                );
                (
                    AppendHeaders([
                        (header::SET_COOKIE, session_cookie),
                        (header::SET_COOKIE, clear_mfa_cookie),
                    ]),
                    desktop_connected_page(&nonce.0, &plaintext, &expires_rfc),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to mint desktop scoped token");
                Redirect::to("/?error=token_failed").into_response()
            }
        };
    }

    (
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, clear_mfa_cookie),
        ]),
        Redirect::to("/connections.html"),
    )
        .into_response()
}

/// GET /auth/enroll — TOTP enrollment page for users the enforcement
/// gate requires to enroll before their first login.
///
/// Reachable only with a valid pending-MFA cookie (set by the login
/// handlers when enrollment is required). No session is minted until the
/// factor is verified on the MFA page; the pending cookie grants access
/// to this page and the TOTP self-service API only. A user who is
/// already enrolled (e.g. enrollment completed in an earlier pending
/// flow) is sent to the MFA page to finish the login.
pub async fn enroll_page(
    State(state): State<crate::api::AppState>,
    headers: HeaderMap,
    Extension(database): Extension<Db>,
    Extension(nonce): Extension<CspNonce>,
) -> Response {
    let Some(token) = extract_cookie(&headers, "persea_mfa_pending") else {
        return Redirect::to("/?error=login_required").into_response();
    };
    let db_clone = database.clone();
    let pending =
        match tokio::task::spawn_blocking(move || db::get_pending_mfa(&db_clone, &token)).await {
            Ok(Ok(Some(p))) => p,
            _ => return Redirect::to("/?error=login_required").into_response(),
        };

    let db_check = database.clone();
    let enrolled =
        tokio::task::spawn_blocking(move || db::user_totp_enabled(&db_check, pending.user_id))
            .await
            .unwrap_or(Ok(false))
            .unwrap_or(false);
    if enrolled {
        return Redirect::to("/auth/mfa").into_response();
    }

    let site_title = state.config().site_title.clone();
    let logo_url = state
        .config()
        .theme
        .as_ref()
        .and_then(|t| t.logo_url.clone())
        .unwrap_or_default();
    AccountTotpTemplate {
        site_title,
        logo_url,
        is_admin: pending.user_role == "admin",
        active_page: "totp".to_string(),
        csp_nonce: nonce.0,
    }
    .into_response()
}

/// Render the desktop-connected page: the scoped token plaintext (handed
/// out exactly once, in the login response that minted it), its expiry,
/// and a copy button. The desktop shell reads the token from its webview's
/// DOM; a plain browser user can copy it manually. No-store so the
/// plaintext never lands in a cache. The token charset is
/// `[a-zA-Z0-9_]` and the other interpolations are server-generated, so
/// no HTML escaping is required.
fn desktop_connected_page(nonce: &str, token: &str, expires_rfc: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Desktop Connected</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }}
        .card {{ background: #111827; border: 1px solid #1e3a5f; border-radius: 12px; padding: 2rem; width: 100%; max-width: 560px; }}
        .title {{ text-align: center; margin-bottom: 0.5rem; font-size: 1.5rem; color: #e2e8f0; }}
        .subtitle {{ text-align: center; color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }}
        label {{ display: block; margin-bottom: 0.25rem; font-size: 0.875rem; color: #94a3b8; }}
        input {{ width: 100%; padding: 0.625rem 0.75rem; background: #1e293b; border: 1px solid #1e3a5f; border-radius: 6px; color: #e2e8f0; font-size: 0.875rem; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; margin-bottom: 1rem; outline: none; }}
        .btn {{ width: 100%; padding: 0.625rem; background: #3b82f6; color: #fff; border: none; border-radius: 6px; font-size: 0.875rem; cursor: pointer; }}
        .btn:hover {{ background: #2563eb; }}
        .hint {{ font-size: 0.75rem; color: #64748b; text-align: center; margin-top: 1.25rem; line-height: 1.6; }}
        a {{ color: #60a5fa; }}
    </style>
</head>
<body>
    <div class="card">
        <h1 class="title">Desktop Connected</h1>
        <p class="subtitle">Use this token in the desktop app. It expires in 12 hours.</p>
        <label for="scoped-token">Scoped token</label>
        <input type="text" id="scoped-token" value="{token}" readonly onclick="this.select()">
        <p class="subtitle">Expires: {expires}</p>
        <button type="button" class="btn" id="copy-btn">Copy Token</button>
        <p class="hint">You can revoke this token any time from the API Keys tab in your <a href="/account/profile.html">account settings</a>.</p>
    </div>
    <script nonce="{nonce}">
    (function() {{
        var btn = document.getElementById('copy-btn');
        var input = document.getElementById('scoped-token');
        if (btn && input) {{
            btn.addEventListener('click', function() {{
                input.focus();
                input.select();
                try {{ document.execCommand('copy'); }} catch (e) {{}}
                btn.textContent = 'Copied';
            }});
        }}
    }})();
    </script>
</body>
</html>"#,
        token = token,
        expires = expires_rfc,
        nonce = nonce
    );

    (
        AppendHeaders([(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-store"),
        )]),
        Html(html),
    )
        .into_response()
}

// ── Form data ──────────────────────────────────────────────────────────────

/// Form body of the password login form (POST /auth/login).
#[derive(serde::Deserialize)]
pub struct LoginFormData {
    /// Account identifier, matched against the auth chain providers.
    /// Defaulted so the SAML button's form (which carries no credentials)
    /// still deserializes.
    #[serde(default)]
    pub username: String,
    /// Plaintext password handed to the configured providers for
    /// verification.
    #[serde(default)]
    pub password: String,
    /// Set by the login page's SAML button (hidden `saml=1` field): starts
    /// the SAML SSO flow instead of password auth. The form then carries no
    /// username or password. The value may arrive as `1` (the template's
    /// convention), which serde_urlencoded rejects for plain `bool`, hence
    /// the tolerant flag deserializer.
    #[serde(default, deserialize_with = "deserialize_flag")]
    pub saml: bool,
    /// Desktop login flag (persea#227): when set, the login flow mints a
    /// scoped desktop token (12h TTL) after all gates pass and answers
    /// with the connected page carrying the token plaintext. The client
    /// posts this alongside the normal credentials (and the SAML start
    /// flag when SAML is used).
    #[serde(default, deserialize_with = "deserialize_flag")]
    pub desktop: bool,
}

/// Deserialize a form flag that may arrive as `1`/`0` (the HTML checkbox
/// convention used by the login page and desktop client) or `true`/`false`.
/// serde_urlencoded deserializes `bool` via `str::parse::<bool>()`, which
/// rejects `1` and would 422 the whole form.
fn deserialize_flag<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    Ok(matches!(
        s.as_str(),
        "1" | "true" | "on" | "yes" | "True" | "TRUE"
    ))
}

// ── SAML handlers ──────────────────────────────────────────────────────────

/// POST /auth/saml/acs — SAML Assertion Consumer Service callback.
///
#[allow(clippy::too_many_arguments)]
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
    Extension(tls_enabled): Extension<TlsEnabled>,
    Extension(nonce): Extension<CspNonce>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<SamlAcsForm>,
) -> Response {
    use crate::auth_provider::{AuthRequest, AuthResult};
    use std::collections::HashMap;

    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);
    // Desktop login intent, carried through the SAML RelayState we set in
    // the AuthnRequest (see login_submit's SAML start). The IdP echoes it
    // back on the ACS POST; a forged value cannot help because the
    // assertion itself must still validate.
    let desktop_login = form.RelayState.as_deref() == Some("desktop");

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

    // Try each provider in chain order (first success wins). Providers
    // may do blocking I/O (the LDAP client creates its own tokio runtime
    // internally), so run the chain off the async runtime; a panic in the
    // chain is logged distinctly instead of masking as a rejection.
    let result = match tokio::task::spawn_blocking(move || {
        futures::executor::block_on(auth_chain.authenticate(&auth_request))
    })
    .await
    {
        Ok(result) => result,
        Err(e) => {
            tracing::error!(error = %e, "auth chain panicked during SAML ACS");
            return Redirect::to("/?error=saml_auth_failed").into_response();
        }
    };

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
            let totp_gate =
                check_totp_enforcement(&database, user.id, &effective_role, &totp_enforcement)
                    .await;

            // Enrolled users go through the MFA page before any session exists.
            if matches!(totp_gate, TotpGate::Mfa) {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(
                    &database,
                    &user,
                    ttl_secs,
                    "/auth/mfa",
                    desktop_login,
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip()),
                )
                .await;
            }

            // Enforcement requires enrollment but the user has no TOTP
            // yet: no session is minted. The pending-MFA cookie reaches
            // the enrollment page only; the session is created after the
            // factor is verified on the MFA page, so never enrolling
            // means never getting in.
            if matches!(totp_gate, TotpGate::Enroll) {
                let ttl_secs = 300; // 5 minutes for MFA pending
                return redirect_to_mfa(
                    &database,
                    &user,
                    ttl_secs,
                    "/auth/enroll",
                    desktop_login,
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip()),
                )
                .await;
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

            // Redirect to RelayState if present, otherwise /connections.html.
            // Both enforcement gates (MFA and enrollment) returned above,
            // so no factor is required and the session is safe to mint.
            let redirect_to = if desktop_login {
                None
            } else {
                form.RelayState
                    .filter(|n| crate::oidc::is_safe_redirect_path(n))
            };

            let session_cookie = format!(
                "persea_session={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age={}",
                session_token,
                crate::csrf::cookie_secure_attr(
                    &headers,
                    tls_enabled.0,
                    Some(&trusted_proxies),
                    Some(addr.ip())
                ),
                ttl_secs
            );

            // Desktop login: mint the scoped token (12h TTL) and answer
            // with the connected page instead of the redirect, so the
            // client that asked for the token gets it in the response.
            if desktop_login {
                return match crate::api::pairing::mint_login_scoped_token(
                    &database, user.id, &client_ip,
                )
                .await
                {
                    Ok((token_id, plaintext, _name, _max_role, _expires_db, expires_rfc)) => {
                        tracing::info!(
                            email = %display_name,
                            token_id,
                            "Desktop scoped token issued after SAML login"
                        );
                        (
                            AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                            desktop_connected_page(&nonce.0, &plaintext, &expires_rfc),
                        )
                            .into_response()
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "failed to mint desktop scoped token");
                        Redirect::to("/?error=token_failed").into_response()
                    }
                };
            }

            (
                AppendHeaders([(header::SET_COOKIE, session_cookie)]),
                Redirect::to(redirect_to.as_deref().unwrap_or("/connections.html")),
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

/// Form body of the SAML Assertion Consumer Service callback.
///
/// The IdP posts this to `/auth/saml/acs` after the assertion exchange.
#[derive(serde::Deserialize)]
#[allow(non_snake_case)]
pub struct SamlAcsForm {
    /// Base64-encoded SAMLResponse XML from the IdP.
    pub SAMLResponse: String,
    /// RelayState echo, used as the post-login redirect target when it is
    /// a safe relative path.
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn test_db() -> Db {
        db::init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn create_user(db: &Db, email: &str, role: &str) -> db::User {
        let hash = crate::password::hash_password("s3cret-p@ss").unwrap();
        db::create_user_with_password(db, email, email, &hash, role, "database").unwrap();
        db::get_user_by_email(db, email).unwrap()
    }

    fn test_addr() -> std::net::SocketAddr {
        "127.0.0.1:8080".parse().unwrap()
    }

    /// Auth provider stub: any request authenticates as the desktop test
    /// user, so the handler exercises the real chain plumbing (lookup,
    /// gates, session, mint) without a live LDAP server.
    struct StubDesktopProvider;

    #[async_trait]
    impl crate::auth_provider::AuthProvider for StubDesktopProvider {
        fn id(&self) -> &str {
            "stub"
        }

        fn capabilities(&self) -> crate::auth_provider::Capabilities {
            crate::auth_provider::Capabilities::AUTHENTICATE
        }

        async fn authenticate(&self, _request: &AuthRequest) -> crate::auth_provider::AuthResult {
            crate::auth_provider::AuthResult::Success {
                subject: "desktop@example.com".into(),
                display_name: "Desktop User".into(),
                groups: vec![],
                role: None,
            }
        }
    }

    /// Router for the login handlers, mirroring the auth-pages wiring in
    /// main.rs (minus CSRF and rate limiting).
    fn login_router(db: Db) -> axum::Router {
        use axum::routing::post;
        let manager: crate::api::AppState = Arc::new(crate::session::SessionManager::new(
            crate::config::Config::default(),
            None,
        ));
        let chain = Arc::new(AuthChain::new(vec![Box::new(StubDesktopProvider)]));
        axum::Router::new()
            .route("/auth/login", post(super::login_submit))
            .route("/auth/mfa", post(super::mfa_submit))
            .with_state(manager)
            .layer(Extension(db))
            .layer(Extension(TrustedProxies(vec![])))
            .layer(Extension(TlsEnabled(false)))
            .layer(Extension(chain))
            .layer(Extension(CspNonce("test-nonce".into())))
    }

    fn form_post(uri: &str, body: &str, cookie: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            builder = builder.header("cookie", c);
        }
        let mut req = builder.body(Body::from(body.to_string())).unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        req
    }

    async fn body_text(response: axum::response::Response) -> String {
        String::from_utf8_lossy(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .to_string()
    }

    /// Extract the `rgu_` token from the connected page's token input.
    fn extract_token(body: &str) -> String {
        let start = body
            .find("value=\"rgu_")
            .map(|i| i + "value=\"".len())
            .expect("connected page must render the token input");
        body[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect()
    }

    #[tokio::test]
    async fn desktop_login_issues_scoped_token_in_response() {
        let db = test_db();
        create_user(&db, "desktop@example.com", "poweruser");
        let app = login_router(db.clone());
        let response = app
            .oneshot(form_post(
                "/auth/login",
                "username=desktop%40example.com&password=s3cret-p%40ss&desktop=1",
                None,
            ))
            .await
            .unwrap();

        // The connected page answers the login POST directly (no redirect)
        // with the token plaintext and the session cookie.
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookies: Vec<String> = response
            .headers()
            .get_all(axum::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok().map(str::to_string))
            .collect();
        assert!(
            set_cookies.iter().any(|c| c.starts_with("persea_session=")),
            "session cookie must be set: {set_cookies:?}"
        );
        let body = body_text(response).await;
        assert!(
            body.contains("Desktop Connected"),
            "expected connected page"
        );
        assert!(body.contains("Expires:"), "expiry must be shown");
        let token = extract_token(&body);
        assert!(token.starts_with("rgu_"), "token plaintext: {token}");

        // The token is a scoped user token with a server-side ~12h expiry.
        let (user, meta) = db::validate_user_token(&db, &token).unwrap();
        assert_eq!(user.email, "desktop@example.com");
        assert_eq!(meta.token_type, "scoped");
        assert_eq!(meta.name, "Persea Desktop (login)");
        let exp = meta.expires_at.expect("scoped token must expire");
        let exp_ndt = chrono::NaiveDateTime::parse_from_str(&exp, "%Y-%m-%d %H:%M:%S").unwrap();
        let hours = (exp_ndt - chrono::Utc::now().naive_utc()).num_minutes() as f64 / 60.0;
        assert!(
            (11.0..13.0).contains(&hours),
            "TTL should be about 12 hours, got {hours:.1}h"
        );
    }

    #[tokio::test]
    async fn plain_login_does_not_mint_scoped_token() {
        let db = test_db();
        create_user(&db, "desktop@example.com", "poweruser");
        let app = login_router(db.clone());
        let response = app
            .oneshot(form_post(
                "/auth/login",
                "username=desktop%40example.com&password=s3cret-p%40ss",
                None,
            ))
            .await
            .unwrap();

        // Ordinary login keeps redirecting to the connections page and
        // mints no token.
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(axum::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            location.ends_with("/connections.html"),
            "redirect: {location}"
        );
        let uid = db::get_user_by_email(&db, "desktop@example.com")
            .unwrap()
            .id;
        assert!(
            db::list_user_tokens(&db, uid).unwrap().is_empty(),
            "a web login must not mint a scoped token"
        );
    }

    #[tokio::test]
    async fn desktop_mfa_login_issues_scoped_token() {
        let db = test_db();
        let user = create_user(&db, "desktop@example.com", "poweruser");
        // Full-length generated secret: hardcoded short base32 values (e.g.
        // JBSWY3DPEHPK3PXP, 80 bits) fail totp_rs's minimum secret check.
        let secret = totp_rs::Secret::generate();
        let secret_b32 = secret.to_base32();
        db::store_totp_secret(&db, user.id, &secret_b32, "SHA1", 6, 30).unwrap();
        // The login with TOTP enforcement would have redirected to the MFA
        // page with a desktop-marked pending record; simulate that record.
        let pending = db::create_pending_mfa_desktop(
            &db,
            user.id,
            "desktop@example.com",
            "Desktop User",
            "poweruser",
            None,
            300,
        )
        .unwrap();

        // Generate a valid code for the stored secret.
        let secret_bytes = secret.as_bytes().to_vec();
        let totp = totp_rs::Builder::new()
            .with_algorithm(totp_rs::Algorithm::SHA1)
            .with_digits(6)
            .with_skew(1)
            .with_step_duration(30)
            .with_secret(secret_bytes)
            .build()
            .unwrap();
        let code = totp.generate_current().to_string();

        let app = login_router(db.clone());
        let response = app
            .oneshot(form_post(
                "/auth/mfa",
                &format!("code={code}"),
                Some(&format!("persea_mfa_pending={pending}")),
            ))
            .await
            .unwrap();

        // The MFA completion answers with the connected page and the
        // scoped token, not the /connections.html redirect.
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_text(response).await;
        assert!(
            body.contains("Desktop Connected"),
            "expected connected page"
        );
        let token = extract_token(&body);
        let (u, meta) = db::validate_user_token(&db, &token).unwrap();
        assert_eq!(u.id, user.id);
        assert_eq!(meta.token_type, "scoped");
        assert!(
            meta.expires_at.is_some(),
            "MFA-issued scoped token must expire"
        );
    }

    #[tokio::test]
    async fn totp_gate_requires_enrollment_for_unenrolled_admin() {
        let db = test_db();
        let user = create_user(&db, "admin@example.com", "admin");
        let gate =
            check_totp_enforcement(&db, user.id, "admin", &TotpEnforcement::AdminsOnly).await;
        assert!(
            matches!(gate, TotpGate::Enroll),
            "an unenrolled admin under AdminsOnly must be sent to enrollment"
        );
    }

    #[tokio::test]
    async fn totp_gate_off_never_requires() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        let gate = check_totp_enforcement(&db, user.id, "viewer", &TotpEnforcement::Off).await;
        assert!(matches!(gate, TotpGate::None));
    }

    #[tokio::test]
    async fn totp_gate_enrolled_user_goes_to_mfa() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        db::store_totp_secret(&db, user.id, "JBSWY3DPEHPK3PXP", "SHA1", 6, 30).unwrap();
        let gate = check_totp_enforcement(&db, user.id, "viewer", &TotpEnforcement::All).await;
        assert!(matches!(gate, TotpGate::Mfa));
    }

    #[tokio::test]
    async fn totp_gate_non_admin_skipped_under_admins_only() {
        let db = test_db();
        let user = create_user(&db, "u@example.com", "viewer");
        let gate =
            check_totp_enforcement(&db, user.id, "viewer", &TotpEnforcement::AdminsOnly).await;
        assert!(matches!(gate, TotpGate::None));
    }
}
