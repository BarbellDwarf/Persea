//! OIDC authentication — login, callback, logout handlers.

use crate::auth::{client_ip, extract_cookie, TrustedProxies};
use crate::config::OidcConfig;
use crate::csrf::TlsEnabled;
use crate::db::{self, Db};
use crate::totp::TotpEnforcement;
use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{AppendHeaders, IntoResponse, Redirect, Response},
    Extension,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthType, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

/// The concrete CoreClient type after from_provider_metadata + set_redirect_uri.
/// from_provider_metadata sets auth/token/userinfo to EndpointSet when present in metadata.
type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Pending OIDC flow entry: PKCE verifier, nonce, and creation timestamp.
type PendingFlows =
    Arc<Mutex<std::collections::HashMap<String, (PkceCodeVerifier, Nonce, Instant)>>>;

/// Shared OIDC state initialized once at startup.
#[derive(Clone)]
pub struct OidcState {
    /// Discovered and configured OIDC client.
    pub client: OidcClient,
    /// HTTP client used for discovery and token exchange.
    pub http_client: openidconnect::reqwest::Client,
    /// The OIDC configuration this state was built from.
    pub config: OidcConfig,
    /// Auth session TTL in seconds.
    pub session_ttl_secs: u64,
    /// Pending OIDC flows: state -> (pkce_verifier, nonce, created_at)
    pub pending: PendingFlows,
    /// HMAC-SHA256 key for the state-cookie browser fingerprint (H01).
    /// Derived from the client secret, so it is a server-side secret the
    /// login-CSRF attacker (who knows the flow's state token, the victim's
    /// IP and User-Agent) cannot compute. Never logged.
    pub fingerprint_key: [u8; 32],
}

/// Derive the state-fingerprint HMAC key from the OIDC client secret.
///
/// Domain-separated SHA-256 so the key material is a fixed 32 bytes
/// regardless of the secret's length and cannot be confused with the
/// secret itself if it ever leaks from a different context. The secret is
/// validated present at init (see [`init_oidc`]), so this always has input.
fn derive_fingerprint_key(client_secret: &str) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    ctx.update(b"persea-oidc-fingerprint-v1");
    ctx.update(client_secret.as_bytes());
    let digest = ctx.finish();
    let mut key = [0u8; 32];
    key.copy_from_slice(digest.as_ref());
    key
}

/// Extract the client fingerprint inputs (IP + User-Agent) from the
/// request. The IP is the proxy-gated `client_ip()` result — never the raw
/// `X-Forwarded-For`/`X-Real-IP` headers, which any client can forge when
/// the socket peer is not a trusted proxy. Mirrors how the callback
/// compares the cookie against the current request, so both sides must use
/// this same helper.
fn client_fingerprint_inputs(
    headers: &axum::http::HeaderMap,
    client_ip: std::net::IpAddr,
) -> (String, String) {
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string();
    (client_ip.to_string(), ua)
}

/// HMAC-SHA256 fingerprint of (IP, User-Agent) keyed by the server-side
/// fingerprint key. The state cookie carries `state:fingerprint`; the
/// callback recomputes this from the current request and rejects on
/// mismatch, so a flow started in one browser cannot be completed from
/// another (login CSRF), and — because the key is a server secret — the
/// attacker cannot forge a cookie for a victim whose IP and UA they know.
fn state_fingerprint(key: &[u8; 32], ip: &str, ua: &str) -> String {
    use ring::hmac;
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let mut data = Vec::new();
    data.extend_from_slice(ip.as_bytes());
    data.extend_from_slice(ua.as_bytes());
    let tag = hmac::sign(&key, &data);
    hex::encode(tag.as_ref())
}

/// Is `s` a safe same-origin redirect target?
///
/// Accepts only relative paths that start with a single `/`. Rejects
/// protocol-relative URLs (`//host`), absolute URLs (`scheme://host`),
/// backslashes (browsers normalize `\` to `/`, so `/\evil.com` and
/// `\\evil.com` become protocol-relative), and control characters.
pub fn is_safe_redirect_path(s: &str) -> bool {
    if !s.starts_with('/') || s.starts_with("//") || s.contains("://") {
        return false;
    }
    if s.contains('\\') {
        return false;
    }
    !s.chars().any(|c| c.is_control())
}

/// One named OIDC provider (DB-configured via the admin auth page, or the
/// `[oidc]` config section) with its own client and pending-flow state.
pub struct OidcProvider {
    /// Provider name, used in the `?provider=` login parameter.
    pub name: String,
    /// Client and pending-flow state for this provider.
    pub state: OidcState,
}

/// All configured OIDC providers, for multi-provider SSO: the login page
/// renders one button per provider and the state cookie
/// carries the provider name so the callback resolves the right client.
pub struct OidcRegistry {
    /// All configured providers, in display order.
    pub providers: Vec<OidcProvider>,
}

impl OidcRegistry {
    /// Resolve a provider by name. An absent name falls back to the first
    /// configured provider; an UNKNOWN name returns `None` so a stale or
    /// typo'd `?provider=` never silently signs the user into a different
    /// IdP than the one they clicked.
    pub fn get(&self, name: Option<&str>) -> Option<&OidcProvider> {
        match name {
            Some(n) => self.providers.iter().find(|p| p.name == n),
            None => self.providers.first(),
        }
    }
}

/// Initialize OIDC client by discovering provider metadata.
pub async fn init_oidc(config: &OidcConfig, session_ttl_secs: u64) -> Result<OidcState, String> {
    let mut builder = openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none());

    if config.tls_skip_verify {
        tracing::warn!(
            "OIDC TLS certificate verification is DISABLED (tls_skip_verify = true). \
             This exposes client_secret and tokens to MITM attacks — do NOT use in production."
        );
        builder = builder.danger_accept_invalid_certs(true);
    }

    if let Some(ref ca_path) = config.ca_cert {
        let pem = std::fs::read(ca_path)
            .map_err(|e| format!("Failed to read OIDC CA cert {}: {}", ca_path, e))?;
        let cert = reqwest::tls::Certificate::from_pem(&pem)
            .map_err(|e| format!("Failed to parse OIDC CA cert {}: {}", ca_path, e))?;
        builder = builder.add_root_certificate(cert);
        tracing::info!("OIDC TLS: added custom CA certificate from {}", ca_path);
    }

    let http_client = builder
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {}", e))?;

    let issuer_url = IssuerUrl::new(config.issuer_url.clone())
        .map_err(|e| format!("Invalid issuer URL: {}", e))?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer_url, &http_client)
        .await
        .map_err(|e| friendly_discovery_error(&format!("{:?}", e)))?;

    // client_secret is validated at config-load time when [oidc] is
    // configured (Config::load), so reaching this point with None
    // means we were called with a partially-constructed config; treat
    // that as a programming error rather than a user-facing one.
    let client_secret = config
        .client_secret
        .clone()
        .ok_or_else(|| "OIDC client_secret missing at startup".to_string())?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(client_secret.clone())),
    )
    .set_auth_type(AuthType::RequestBody)
    .set_redirect_uri(
        RedirectUrl::new(config.redirect_uri.clone())
            .map_err(|e| format!("Invalid redirect URI: {}", e))?,
    );

    Ok(OidcState {
        client,
        http_client,
        config: config.clone(),
        session_ttl_secs,
        pending: Arc::new(Mutex::new(std::collections::HashMap::new())),
        fingerprint_key: derive_fingerprint_key(&client_secret),
    })
}

/// Query parameters accepted by the login endpoint.
#[derive(Deserialize)]
pub struct LoginParams {
    /// Post-login redirect target; honored only when it is a same-origin path.
    pub next: Option<String>,
    /// OIDC provider name (multi-provider SSO). Defaults to the first
    /// configured provider when absent.
    pub provider: Option<String>,
    /// Desktop login intent (persea#227): when set, the callback mints a
    /// scoped desktop token (12h TTL) after all gates pass and answers
    /// with the connected page carrying the token plaintext. The desktop
    /// shell navigates to `/auth/login?desktop=1`. Accepts `1`/`true`/`on`
    /// like the password form's desktop flag.
    #[serde(default, deserialize_with = "crate::handlers::auth::deserialize_flag")]
    pub desktop: bool,
}

/// GET /auth/login — redirect user to OIDC provider.
pub async fn login(
    State(registry): State<std::sync::Arc<OidcRegistry>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(tls_enabled): Extension<TlsEnabled>,
    Query(params): Query<LoginParams>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(provider) = registry.get(params.provider.as_deref()) else {
        tracing::error!("OIDC login requested but no OIDC provider is configured");
        return axum::response::Redirect::to("/?sso_error=1").into_response();
    };
    let oidc = &provider.state;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = oidc
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge);

    // Request any extra scopes configured (e.g. "groups")
    for scope in &oidc.config.extra_scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.clone()));
    }

    let (auth_url, csrf_token, nonce) = auth_request.url();

    // Store PKCE verifier + nonce keyed by CSRF state, and evict stale entries
    let state_key = csrf_token.secret().clone();
    let mut pending = oidc.pending.lock().await;
    let cutoff = Instant::now() - std::time::Duration::from_secs(600);
    pending.retain(|_, (_, _, created)| *created > cutoff);
    pending.insert(state_key.clone(), (pkce_verifier, nonce, Instant::now()));
    drop(pending);

    // Set state in a cookie so we can verify on callback, then redirect
    // Bind state to client fingerprint (IP + User-Agent) to prevent CSRF.
    // HMAC-SHA256 keyed by a server-side secret derived from the client
    // secret (H01): the state token alone is public (it rides in the auth
    // URL), so keying with it would let an attacker who knows the
    // victim's IP + UA forge the cookie.
    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);
    let (ip, ua) = client_fingerprint_inputs(&headers, client_ip);
    let fingerprint = state_fingerprint(&oidc.fingerprint_key, &ip, &ua);
    let cookie_value = format!("{}:{}", state_key, fingerprint);

    let sec = crate::csrf::cookie_secure_attr(
        &headers,
        tls_enabled.0,
        Some(&trusted_proxies),
        Some(addr.ip()),
    );
    let state_cookie = format!(
        "persea_oidc_state={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=600",
        cookie_value, sec
    );
    // The provider name lives in its own cookie (names may contain colons,
    // which would be ambiguous inside the state cookie).
    let provider_cookie = format!(
        "persea_oidc_provider={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=600",
        provider.name, sec
    );

    let mut cookies = vec![
        (header::SET_COOKIE, state_cookie),
        (header::SET_COOKIE, provider_cookie),
    ];

    // Store post-login redirect URL in a cookie if provided and safe
    if let Some(ref next) = params.next {
        if is_safe_redirect_path(next) {
            let next_cookie = format!(
                "persea_next={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=600",
                next, sec
            );
            cookies.push((header::SET_COOKIE, next_cookie));
        }
    }

    // Desktop login intent rides a cookie so the callback can recover it
    // after the IdP round trip (mirrors the SAML RelayState mechanism).
    // The value is a fixed marker, never user input.
    if params.desktop {
        let desktop_cookie = format!(
            "persea_desktop=1; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=600",
            sec
        );
        cookies.push((header::SET_COOKIE, desktop_cookie));
    }

    (
        AppendHeaders(cookies),
        Redirect::temporary(auth_url.as_str()),
    )
        .into_response()
}

/// Query parameters the IdP sends back on the callback.
#[derive(Deserialize)]
pub struct CallbackParams {
    /// Authorization code to exchange for tokens.
    pub code: Option<String>,
    /// CSRF state echoed back from the login step.
    pub state: Option<String>,
    /// OAuth error code when the provider rejects the login.
    pub error: Option<String>,
    /// Human-readable error description from the provider.
    pub error_description: Option<String>,
}

/// Create a pending MFA record and redirect to `target` with the
/// pending-MFA cookie, clearing the OIDC state and next cookies. Used by
/// both the MFA gate (target `/auth/mfa`, cookie scoped to it) and the
/// enrollment gate (target `/auth/enroll`, cookie scoped to `/` so the
/// enrollment page and the TOTP self-service API can read it). Neither
/// path mints a session: the session is created only after the factor is
/// verified on the MFA page. `desktop` marks the record as a desktop
/// login so the MFA completion handler mints the scoped token after the
/// TOTP gate (persea#227).
#[allow(clippy::too_many_arguments)]
async fn redirect_with_pending_mfa(
    database: &Db,
    user_id: i64,
    email: &str,
    name: &str,
    role: &str,
    subject: Option<&str>,
    ttl_secs: u64,
    target: &str,
    cookie_path: &str,
    desktop: bool,
    headers: &HeaderMap,
    tls_enabled: bool,
    trusted_proxies: Option<&TrustedProxies>,
    peer_ip: Option<std::net::IpAddr>,
) -> Response {
    let db_clone = database.clone();
    let email_for_mfa = email.to_string();
    let name_for_mfa = name.to_string();
    let role_for_mfa = role.to_string();
    let subject_for_mfa = subject.map(str::to_string);
    let pending_token = match tokio::task::spawn_blocking(move || {
        if desktop {
            db::create_pending_mfa_desktop(
                &db_clone,
                user_id,
                &email_for_mfa,
                &name_for_mfa,
                &role_for_mfa,
                subject_for_mfa.as_deref(),
                ttl_secs,
            )
        } else {
            db::create_pending_mfa(
                &db_clone,
                user_id,
                &email_for_mfa,
                &name_for_mfa,
                &role_for_mfa,
                subject_for_mfa.as_deref(),
                ttl_secs,
            )
        }
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to create MFA session"})),
            )
                .into_response();
        }
    };

    let sec = crate::csrf::cookie_secure_attr(headers, tls_enabled, trusted_proxies, peer_ip);
    let mfa_cookie = format!(
        "persea_mfa_pending={}; Path={}; HttpOnly;{} SameSite=Lax; Max-Age={}",
        pending_token, cookie_path, sec, ttl_secs
    );
    let clear_state_cookie = format!(
        "persea_oidc_state=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );
    let clear_next_cookie = format!(
        "persea_next=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );
    // The desktop intent is consumed here: the pending-MFA record carries
    // it through the TOTP gate, so the cookie must not survive to mint a
    // scoped token for a later web login.
    let clear_desktop_cookie = format!(
        "persea_desktop=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );

    (
        AppendHeaders([
            (header::SET_COOKIE, mfa_cookie),
            (header::SET_COOKIE, clear_state_cookie),
            (header::SET_COOKIE, clear_next_cookie),
            (header::SET_COOKIE, clear_desktop_cookie),
        ]),
        Redirect::temporary(target),
    )
        .into_response()
}

/// GET /auth/callback — exchange code for tokens, create session.
#[allow(clippy::too_many_arguments)]
pub async fn callback(
    State(registry): State<std::sync::Arc<OidcRegistry>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(database): Extension<Db>,
    Extension(totp_enforcement): Extension<TotpEnforcement>,
    Extension(trusted_proxies): Extension<TrustedProxies>,
    Extension(tls_enabled): Extension<TlsEnabled>,
    Extension(csp_nonce): Extension<crate::CspNonce>,
    headers: axum::http::HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    // Handle SSO error responses (e.g. user denied consent, timeout)
    if let Some(ref err) = params.error {
        let desc = params
            .error_description
            .as_deref()
            .unwrap_or("unknown error");
        tracing::warn!("OIDC callback error from provider: {} — {}", err, desc);
        return axum::response::Redirect::to("/?sso_error=1").into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            tracing::warn!("OIDC callback missing 'code' parameter");
            return axum::response::Redirect::to("/?sso_error=1").into_response();
        }
    };

    let state = match params.state {
        Some(s) => s,
        None => {
            tracing::warn!("OIDC callback missing 'state' parameter");
            return axum::response::Redirect::to("/?sso_error=1").into_response();
        }
    };

    // Resolve which provider this flow belongs to from the provider cookie
    // (set alongside the state cookie at login). Cookies from before
    // multi-provider support have no provider cookie and fall back to the
    // first configured provider.
    let provider = registry.get(extract_cookie(&headers, "persea_oidc_provider").as_deref());
    let Some(oidc) = provider.map(|p| &p.state) else {
        tracing::warn!("OIDC callback: no provider configured");
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "no OIDC provider configured"})),
        )
            .into_response();
    };

    // Verify the state cookie matches the state query parameter (binds flow to browser)
    // Cookie format is "state_key:fingerprint" — verify both
    let state_cookie = extract_cookie(&headers, "persea_oidc_state");
    // Format: `state_key:fingerprint` (provider name lives in its own
    // cookie). Old 2-part cookies parse identically. Both comparisons are
    // constant-time: state and fingerprint are bearer credentials.
    let client_ip = client_ip(&headers, addr.ip(), &trusted_proxies.0);
    let (ip, ua) = client_fingerprint_inputs(&headers, client_ip);
    let cookie_valid = match state_cookie.as_deref() {
        Some(cookie_val) => match cookie_val.split_once(':') {
            Some((cookie_state, cookie_fingerprint)) => {
                if !bool::from(cookie_state.as_bytes().ct_eq(state.as_bytes())) {
                    false
                } else {
                    // Verify fingerprint matches current request, keyed by
                    // the server-side secret (H01) — same construction as
                    // the login handler.
                    let current_fp = state_fingerprint(&oidc.fingerprint_key, &ip, &ua);
                    cookie_fingerprint
                        .as_bytes()
                        .ct_eq(current_fp.as_bytes())
                        .into()
                }
            }
            None => false,
        },
        None => false,
    };
    if !cookie_valid {
        tracing::warn!("OIDC callback state cookie mismatch or fingerprint mismatch");
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(json!({"error": "OIDC state cookie mismatch"})),
        )
            .into_response();
    }

    // Retrieve and remove the pending PKCE verifier
    let pending_entry = oidc.pending.lock().await.remove(&state);
    let (pkce_verifier, nonce, _created) = match pending_entry {
        Some(entry) => entry,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                axum::Json(json!({"error": "invalid or expired OIDC state"})),
            )
                .into_response();
        }
    };

    // Desktop login intent, carried through the IdP round trip by the
    // `persea_desktop` cookie set at /auth/login?desktop=1 (persea#227).
    // A forged cookie cannot help: the assertion itself must still
    // validate, and the cookie is cleared on every callback.
    let desktop_login = extract_cookie(&headers, "persea_desktop").as_deref() == Some("1");

    // Exchange authorization code for tokens
    let code_request = match oidc.client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req,
        Err(e) => {
            tracing::error!("OIDC token endpoint not configured: {:?}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "OIDC token endpoint not available"})),
            )
                .into_response();
        }
    };

    let token_response = match code_request
        .set_pkce_verifier(pkce_verifier)
        .request_async(&oidc.http_client)
        .await
    {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("OIDC token exchange failed: {:?}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "OIDC token exchange failed"})),
            )
                .into_response();
        }
    };

    // Extract and verify ID token
    use openidconnect::core::{CoreIdToken, CoreIdTokenClaims};
    let id_token: &CoreIdToken = match token_response.id_token() {
        Some(t) => t,
        None => {
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "no ID token in OIDC response"})),
            )
                .into_response();
        }
    };

    let claims: &CoreIdTokenClaims = match id_token.claims(&oidc.client.id_token_verifier(), &nonce)
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("OIDC ID token verification failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                axum::Json(json!({"error": "ID token verification failed"})),
            )
                .into_response();
        }
    };

    // Extract user info from claims
    let subject = claims.subject().to_string();
    let email: String = claims
        .email()
        .map(|e| e.to_string())
        .unwrap_or_else(|| subject.clone());
    let name: String = claims
        .name()
        .and_then(|n| n.get(None).map(|v| v.to_string()))
        .unwrap_or_default();

    // Extract group memberships from ID token JWT payload
    let groups = extract_groups_from_jwt(&id_token.to_string(), &oidc.config.groups_claim);
    if !groups.is_empty() {
        tracing::info!(email = %email, groups = ?groups, "OIDC groups extracted");
        let db_for_seen = database.clone();
        let groups_for_seen = groups.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = db::upsert_seen_groups(&db_for_seen, &groups_for_seen) {
                tracing::warn!(error = %e, "failed to persist seen OIDC groups");
            }
            // Auto-provision local groups from the claims so folder ACLs
            // referencing provider groups work without manual mapping.
            match db::ensure_local_groups(&db_for_seen, &groups_for_seen) {
                Ok(created) if created > 0 => {
                    tracing::info!(created, "auto-provisioned local groups from OIDC claims");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "failed to auto-provision local groups"),
            }
        })
        .await;
    }

    // Resolve role from group-to-role mappings (highest matching wins).
    // Returns Some(role) only if a mapping matched; None means keep existing role.
    let db_for_role = database.clone();
    let groups_for_role = groups.clone();
    let mapped_role = match tokio::task::spawn_blocking(move || {
        db::resolve_role_from_groups(&db_for_role, &groups_for_role)
    })
    .await
    {
        Ok(Ok(role)) => role,
        _ => None,
    };

    // Upsert user in DB (sets default_role only on first login INSERT, not on subsequent updates)
    let default_role = oidc.config.default_role.clone();
    let db_clone = database.clone();
    let email_clone = email.clone();
    let name_clone = name.clone();
    let subject_clone = subject.clone();

    let user = match tokio::task::spawn_blocking(move || {
        db::upsert_user(
            &db_clone,
            &email_clone,
            &name_clone,
            Some(&subject_clone),
            &default_role,
            &groups,
        )
    })
    .await
    {
        Ok(Ok(user)) => user,
        Ok(Err(e)) => {
            tracing::error!("Failed to upsert user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to create user"})),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!("Spawn blocking failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "internal error"})),
            )
                .into_response();
        }
    };

    // If a group mapping matched, update the user's role to the mapped value
    let effective_role = if let Some(ref role) = mapped_role {
        let db_clone = database.clone();
        let email_clone = email.clone();
        let role_clone = role.clone();
        let _ = tokio::task::spawn_blocking(move || {
            db::set_user_role(&db_clone, &email_clone, &role_clone)
        })
        .await;
        tracing::info!(email = %email, role = %role, "Role set from group mapping");
        role.clone()
    } else {
        user.role.clone()
    };

    if user.disabled {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(json!({"error": "account is disabled"})),
        )
            .into_response();
    }

    // Check TOTP enforcement before creating session (mirrors the gate in
    // handlers/auth.rs): AdminsOnly requires admins enrolled, All requires
    // every user enrolled. A user who must enroll but has no TOTP is sent
    // to the enrollment page with a pending-MFA cookie, not silently
    // logged in.
    let (totp_required, enroll_required) = {
        let db_check = database.clone();
        let uid = user.id;
        let role_for_check = effective_role.clone();
        let enforcement = totp_enforcement;
        // Check if user has TOTP enabled (synchronous DB call in spawn_blocking)
        let has_totp = tokio::task::spawn_blocking(move || db::user_totp_enabled(&db_check, uid))
            .await
            .unwrap_or(Ok(false))
            .unwrap_or(false);

        match enforcement {
            TotpEnforcement::Off => (false, false),
            TotpEnforcement::AdminsOnly => {
                if role_for_check != "admin" {
                    (false, false)
                } else {
                    (has_totp, !has_totp)
                }
            }
            TotpEnforcement::All => (has_totp, !has_totp),
        }
    };

    if totp_required {
        tracing::info!(email = %email, "OIDC login requires TOTP — redirecting to MFA");
        return redirect_with_pending_mfa(
            &database,
            user.id,
            &email,
            &name,
            &effective_role,
            Some(&subject),
            300,
            "/auth/mfa",
            "/auth/mfa",
            desktop_login,
            &headers,
            tls_enabled.0,
            Some(&trusted_proxies),
            Some(addr.ip()),
        )
        .await;
    }

    // Enforcement requires enrollment but the user has no TOTP yet: no
    // session is minted. The pending-MFA cookie reaches the enrollment
    // page and the TOTP self-service API only; the session is created
    // after the factor is verified on the MFA page, so never enrolling
    // means never getting in.
    if enroll_required {
        tracing::info!(email = %email, "OIDC login requires TOTP enrollment — redirecting to enrollment");
        return redirect_with_pending_mfa(
            &database,
            user.id,
            &email,
            &name,
            &effective_role,
            Some(&subject),
            300,
            "/auth/enroll",
            "/",
            desktop_login,
            &headers,
            tls_enabled.0,
            Some(&trusted_proxies),
            Some(addr.ip()),
        )
        .await;
    }

    // Create auth session
    let user_id = user.id;
    let ttl_secs = oidc.session_ttl_secs;
    let db_clone = database.clone();
    let session_token = match tokio::task::spawn_blocking(move || {
        db::create_auth_session(&db_clone, user_id, ttl_secs)
    })
    .await
    {
        Ok(Ok(token)) => token,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(json!({"error": "failed to create session"})),
            )
                .into_response();
        }
    };

    tracing::info!(email = %email, role = %effective_role, "OIDC login successful");

    // Audit: OIDC login
    {
        let uid = user.id.to_string();
        crate::audit::fire(
            &database,
            Some(&uid),
            "auth.oidc.login",
            "success",
            serde_json::Value::Null,
            None,
            None,
        )
        .await;
    }

    // Check for post-login redirect cookie. The enforcement gates
    // (MFA and enrollment) returned above, so reaching this point means
    // no factor is required and the session is safe to mint.
    let redirect_to = extract_cookie(&headers, "persea_next")
        .filter(|n| is_safe_redirect_path(n))
        .unwrap_or_else(|| "/addressbook.html".to_string());

    // Set session cookie and redirect; clear OIDC state, next, and
    // desktop-intent cookies
    let sec = crate::csrf::cookie_secure_attr(
        &headers,
        tls_enabled.0,
        Some(&trusted_proxies),
        Some(addr.ip()),
    );
    let session_cookie = format!(
        "persea_session={}; Path=/; HttpOnly;{} SameSite=Lax; Max-Age={}",
        session_token, sec, ttl_secs
    );
    let clear_state_cookie = format!(
        "persea_oidc_state=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );
    let clear_next_cookie = format!(
        "persea_next=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );
    let clear_desktop_cookie = format!(
        "persea_desktop=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        sec
    );

    // Desktop login: mint the scoped token (12h TTL) and answer with the
    // connected page instead of the redirect, so the client that asked for
    // the token gets it in the response (persea#227).
    if desktop_login {
        return match crate::api::pairing::mint_login_scoped_token(&database, user.id, &client_ip)
            .await
        {
            Ok((token_id, plaintext, _name, _max_role, _expires_db, expires_rfc)) => {
                tracing::info!(
                    email = %email,
                    token_id,
                    "Desktop scoped token issued after OIDC login"
                );
                (
                    AppendHeaders([
                        (header::SET_COOKIE, session_cookie),
                        (header::SET_COOKIE, clear_state_cookie),
                        (header::SET_COOKIE, clear_next_cookie),
                        (header::SET_COOKIE, clear_desktop_cookie),
                    ]),
                    crate::handlers::auth::desktop_connected_page(
                        &csp_nonce.0,
                        &plaintext,
                        &expires_rfc,
                    ),
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to mint desktop scoped token after OIDC login");
                (
                    AppendHeaders([
                        (header::SET_COOKIE, session_cookie),
                        (header::SET_COOKIE, clear_state_cookie),
                        (header::SET_COOKIE, clear_next_cookie),
                        (header::SET_COOKIE, clear_desktop_cookie),
                    ]),
                    Redirect::temporary(&redirect_to),
                )
                    .into_response()
            }
        };
    }

    (
        AppendHeaders([
            (header::SET_COOKIE, session_cookie),
            (header::SET_COOKIE, clear_state_cookie),
            (header::SET_COOKIE, clear_next_cookie),
            (header::SET_COOKIE, clear_desktop_cookie),
        ]),
        Redirect::temporary(&redirect_to),
    )
        .into_response()
}

/// GET /auth/logout — clear session cookie and redirect to login.
pub async fn logout(
    Extension(database): Extension<Db>,
    request: axum::extract::Request,
) -> Response {
    // Try to delete the session from DB
    if let Some(token) = extract_cookie(request.headers(), "persea_session") {
        let db_clone = database.clone();
        let _ =
            tokio::task::spawn_blocking(move || db::delete_auth_session(&db_clone, &token)).await;
    }

    let secure = crate::csrf::is_https_request(&request);
    let clear_cookie = format!(
        "persea_session=; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=0",
        if secure { " Secure;" } else { "" }
    );

    (
        [(header::SET_COOKIE, clear_cookie)],
        Redirect::temporary("/"),
    )
        .into_response()
}

/// Extract group memberships from a JWT string by decoding the payload.
/// Accepts the raw JWT string to avoid openidconnect's complex generics.
/// Max OIDC groups kept per login. Caps `seen_groups` bloat + `oidc_groups`
/// column size if an IdP returns an absurdly large group list (misconfig or
/// compromise). Realistic AD deployments sit well under this.
const MAX_OIDC_GROUPS: usize = 64;
/// Max characters per group name. Longer names are truncated on the byte
/// boundary preserving UTF-8 (we drop trailing partial code points).
const MAX_OIDC_GROUP_LEN: usize = 256;

fn truncate_group_name(s: &str) -> String {
    if s.len() <= MAX_OIDC_GROUP_LEN {
        return s.to_string();
    }
    let mut end = MAX_OIDC_GROUP_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn extract_groups_from_jwt(token_str: &str, groups_claim: &str) -> Vec<String> {
    use base64::Engine;
    let parts: Vec<&str> = token_str.split('.').collect();
    let payload = match parts.get(1) {
        Some(p) => p,
        None => return Vec::new(),
    };

    let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let claims: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut groups: Vec<String> = match claims.get(groups_claim) {
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(truncate_group_name))
            .collect(),
        // Some OIDC providers send a plain string instead of an array when user is in one group
        Some(serde_json::Value::String(s)) => vec![truncate_group_name(s)],
        _ => Vec::new(),
    };

    if groups.len() > MAX_OIDC_GROUPS {
        tracing::warn!(
            total = groups.len(),
            kept = MAX_OIDC_GROUPS,
            "OIDC groups claim exceeds cap — truncating"
        );
        groups.truncate(MAX_OIDC_GROUPS);
    }
    groups
}

/// Reshape the openidconnect crate's discovery error into something an
/// operator can act on without grepping Debug output.
///
/// The specific case we handle is the issuer-URI mismatch that OIDC
/// Discovery's spec demands (the `issuer` claim in the discovery document
/// must byte-for-byte match the URL the client used to fetch it). This
/// fires for any OIDC provider where the operator has a trailing slash
/// wrong or copy-pasted the authorisation URL instead of the issuer URL:
/// Keycloak, Authentik, Azure AD / Entra ID, Okta, Auth0, JumpCloud,
/// Google, and so on. The original library error gives the two URIs but
/// phrases "expected" from the validator's perspective, which is
/// exactly backwards for what the operator needs to do. We flip it
/// around and name the fix explicitly.
///
/// Every other discovery failure (network, TLS, JSON parse, wrong path)
/// falls through to the raw Debug string so we don't swallow useful
/// diagnostics.
fn friendly_discovery_error(raw: &str) -> String {
    let (got, expected) = match parse_issuer_mismatch(raw) {
        Some(pair) => pair,
        None => return format!("OIDC discovery failed: {raw}"),
    };

    // `got` is what the provider actually advertises in its discovery
    // document; `expected` is what the library was told by the config.
    // The operator always needs to change `expected` to match `got`.
    let headline;
    let fix;
    if got.trim_end_matches('/') == expected.trim_end_matches('/') {
        // Slash-only mismatch — the overwhelmingly common case.
        if expected.ends_with('/') && !got.ends_with('/') {
            headline = "issuer_url has an extra trailing slash";
            fix = "remove the trailing slash from issuer_url".to_string();
        } else {
            headline = "issuer_url is missing a trailing slash";
            fix = "add a trailing slash to issuer_url".to_string();
        }
    } else {
        // Genuinely different URLs (different host, different path, wrong
        // URL copied from the provider console). Operator needs to see
        // both sides and swap in the right one.
        headline = "issuer_url does not match the provider's advertised value";
        fix = format!("set issuer_url = \"{got}\" in your [oidc] config");
    }

    format!(
        "OIDC discovery failed: {headline}.\n  \
         config:   \"{expected}\"\n  \
         provider: \"{got}\"\n  \
         Fix: {fix}."
    )
}

/// Extract (got, expected) from the openidconnect crate's issuer-mismatch
/// validation error. The error is Debug-formatted into the enclosing code
/// path and reliably contains:
///     unexpected issuer URI `GOT` (expected `EXPECTED`)
/// Returns None for any other shape so the caller falls through to the raw
/// error text.
fn parse_issuer_mismatch(raw: &str) -> Option<(String, String)> {
    let tag = "unexpected issuer URI `";
    let start = raw.find(tag)? + tag.len();
    let after = &raw[start..];
    let got_end = after.find('`')?;
    let got = after[..got_end].to_string();

    let rest = &after[got_end + 1..];
    let expected_tag = "(expected `";
    let expected_start = rest.find(expected_tag)? + expected_tag.len();
    let expected_rest = &rest[expected_start..];
    let expected_end = expected_rest.find('`')?;
    let expected = expected_rest[..expected_end].to_string();

    Some((got, expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn make_jwt(payload: &serde_json::Value) -> String {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"none","typ":"JWT"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(payload).unwrap());
        format!("{}.{}.sig", header, payload)
    }

    #[test]
    fn groups_missing_claim_returns_empty() {
        let jwt = make_jwt(&serde_json::json!({"sub": "alice"}));
        assert!(extract_groups_from_jwt(&jwt, "groups").is_empty());
    }

    #[test]
    fn groups_malformed_jwt_returns_empty() {
        assert!(extract_groups_from_jwt("not-a-jwt", "groups").is_empty());
        assert!(extract_groups_from_jwt("onlyone", "groups").is_empty());
        assert!(extract_groups_from_jwt("a.b", "groups").is_empty());
        assert!(extract_groups_from_jwt("a.!notbase64!.c", "groups").is_empty());
    }

    #[test]
    fn groups_array_passed_through() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["admins", "ops"]}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got, vec!["admins".to_string(), "ops".to_string()]);
    }

    #[test]
    fn groups_single_string_wrapped() {
        let jwt = make_jwt(&serde_json::json!({"groups": "admins"}));
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["admins"]);
    }

    #[test]
    fn groups_non_string_values_filtered() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["ok", 42, null, {"nested": "x"}]}));
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["ok"]);
    }

    #[test]
    fn groups_array_over_cap_truncated() {
        let many: Vec<String> = (0..MAX_OIDC_GROUPS + 50).map(|i| format!("g{i}")).collect();
        let jwt = make_jwt(&serde_json::json!({"groups": many}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got.len(), MAX_OIDC_GROUPS);
        assert_eq!(got[0], "g0");
    }

    #[test]
    fn groups_long_names_truncated_on_utf8_boundary() {
        // Build a name with a multi-byte char straddling the 256-byte limit.
        // '€' is 3 bytes. Pad with ASCII up to position 254 then add two '€' —
        // naive byte-truncate at 256 would split the second '€'.
        let mut name = "a".repeat(254);
        name.push('€'); // bytes 254..257
        name.push('€'); // bytes 257..260
        let jwt = make_jwt(&serde_json::json!({"groups": [name.clone()]}));
        let got = extract_groups_from_jwt(&jwt, "groups");
        assert_eq!(got.len(), 1);
        // Truncation must end on a valid UTF-8 boundary ≤ 256 bytes.
        assert!(got[0].len() <= MAX_OIDC_GROUP_LEN);
        assert!(std::str::from_utf8(got[0].as_bytes()).is_ok());
        // And must not exceed the original.
        assert!(name.starts_with(&got[0]));
    }

    #[test]
    fn groups_short_names_pass_through_unchanged() {
        let jwt = make_jwt(&serde_json::json!({"groups": ["alpha", "beta"]}));
        assert_eq!(
            extract_groups_from_jwt(&jwt, "groups"),
            vec!["alpha", "beta"]
        );
    }

    #[test]
    fn groups_custom_claim_name_respected() {
        let jwt = make_jwt(&serde_json::json!({"roles": ["r1", "r2"], "groups": ["g1"]}));
        assert_eq!(extract_groups_from_jwt(&jwt, "roles"), vec!["r1", "r2"]);
        assert_eq!(extract_groups_from_jwt(&jwt, "groups"), vec!["g1"]);
    }

    // ── State fingerprint (H01) ────────────────────────────────────────

    #[test]
    fn fingerprint_ignores_forged_forwarded_headers() {
        // The fingerprint IP comes from the proxy-gated client_ip(), never
        // from client-supplied X-Forwarded-For / X-Real-IP.
        let headers = axum::http::HeaderMap::from_iter([
            (
                axum::http::header::USER_AGENT,
                axum::http::HeaderValue::from_static("UA"),
            ),
            (
                "x-forwarded-for".parse().unwrap(),
                axum::http::HeaderValue::from_static("203.0.113.66"),
            ),
            (
                "x-real-ip".parse().unwrap(),
                axum::http::HeaderValue::from_static("203.0.113.66"),
            ),
        ]);
        let (ip, ua) = client_fingerprint_inputs(&headers, "198.51.100.7".parse().unwrap());
        assert_eq!(
            ip, "198.51.100.7",
            "forwarded headers must not leak into the fingerprint"
        );
        assert_eq!(ua, "UA");
    }

    #[test]
    fn fingerprint_deterministic_for_same_key_and_inputs() {
        let key = derive_fingerprint_key("s3cret");
        let a = state_fingerprint(&key, "10.0.0.5", "Mozilla/5.0 test");
        let b = state_fingerprint(&key, "10.0.0.5", "Mozilla/5.0 test");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "hex HMAC-SHA256 is 64 chars");
    }

    #[test]
    fn fingerprint_changes_with_ip_or_ua() {
        let key = derive_fingerprint_key("s3cret");
        let base = state_fingerprint(&key, "10.0.0.5", "UA");
        assert_ne!(base, state_fingerprint(&key, "10.0.0.6", "UA"));
        assert_ne!(base, state_fingerprint(&key, "10.0.0.5", "UA2"));
    }

    #[test]
    fn forgery_with_guessed_key_fails() {
        // The attacker knows the flow's state token, the victim's IP and
        // User-Agent, but not the server-side fingerprint key (derived
        // from the client secret). A fingerprint computed with their
        // guessed key (e.g. the public state token, the old scheme) must
        // not match the server's.
        let server_key = derive_fingerprint_key("real-client-secret");
        let ip = "203.0.113.7";
        let ua = "Mozilla/5.0 (X11; Linux x86_64)";
        let server_fp = state_fingerprint(&server_key, ip, ua);

        let attacker_key = derive_fingerprint_key("guessed-secret");
        let attacker_fp = state_fingerprint(&attacker_key, ip, ua);
        assert_ne!(attacker_fp, server_fp, "guessed key must not forge");

        // Old scheme: keyed by the public state token itself.
        let old_scheme = {
            use ring::hmac;
            let key = hmac::Key::new(hmac::HMAC_SHA256, b"public-state-token");
            let data = format!("{ip}{ua}");
            hex::encode(hmac::sign(&key, data.as_bytes()).as_ref())
        };
        assert_ne!(old_scheme, server_fp);
    }

    #[test]
    fn fingerprint_key_differs_between_secrets() {
        assert_ne!(
            derive_fingerprint_key("secret-a"),
            derive_fingerprint_key("secret-b")
        );
        // And is stable across calls for the same secret (flows survive
        // restarts as long as the client secret is unchanged).
        assert_eq!(
            derive_fingerprint_key("secret-a"),
            derive_fingerprint_key("secret-a")
        );
    }

    #[test]
    fn fingerprint_key_is_32_bytes() {
        // Any secret length must produce a fixed 32-byte key.
        for secret in ["", "short", "x".repeat(100).as_str()] {
            assert_eq!(derive_fingerprint_key(secret).len(), 32);
        }
    }

    // ── Discovery error wrapping ────────────────────────────────────────

    #[test]
    fn parse_issuer_mismatch_extracts_both_uris() {
        let raw = "Validation(\"unexpected issuer URI `https://oauth.jumpcloud.com` (expected `https://oauth.jumpcloud.com/`)\")";
        let (got, expected) = parse_issuer_mismatch(raw).expect("should parse");
        assert_eq!(got, "https://oauth.jumpcloud.com");
        assert_eq!(expected, "https://oauth.jumpcloud.com/");
    }

    #[test]
    fn parse_issuer_mismatch_handles_opposite_slash_direction() {
        // JumpCloud's other endpoint: the mirror-image of the JumpCloud bug.
        let raw = "Validation(\"unexpected issuer URI `https://oauth.id.jumpcloud.com/` (expected `https://oauth.id.jumpcloud.com`)\")";
        let (got, expected) = parse_issuer_mismatch(raw).expect("should parse");
        assert_eq!(got, "https://oauth.id.jumpcloud.com/");
        assert_eq!(expected, "https://oauth.id.jumpcloud.com");
    }

    #[test]
    fn parse_issuer_mismatch_returns_none_for_unrelated_errors() {
        assert!(parse_issuer_mismatch("Request(reqwest::Error { ... })").is_none());
        assert!(parse_issuer_mismatch("random string").is_none());
        assert!(parse_issuer_mismatch("").is_none());
    }

    #[test]
    fn friendly_discovery_error_extra_slash_in_config() {
        // Config has trailing slash, provider advertises without.
        let raw = "Validation(\"unexpected issuer URI `https://oauth.jumpcloud.com` (expected `https://oauth.jumpcloud.com/`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url has an extra trailing slash"));
        assert!(msg.contains("config:   \"https://oauth.jumpcloud.com/\""));
        assert!(msg.contains("provider: \"https://oauth.jumpcloud.com\""));
        assert!(msg.contains("Fix: remove the trailing slash from issuer_url"));
    }

    #[test]
    fn friendly_discovery_error_missing_slash_in_config() {
        // Provider advertises with trailing slash, config doesn't have one.
        let raw = "Validation(\"unexpected issuer URI `https://auth.example.com/realms/corp/` (expected `https://auth.example.com/realms/corp`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url is missing a trailing slash"));
        assert!(msg.contains("config:   \"https://auth.example.com/realms/corp\""));
        assert!(msg.contains("provider: \"https://auth.example.com/realms/corp/\""));
        assert!(msg.contains("Fix: add a trailing slash to issuer_url"));
    }

    #[test]
    fn friendly_discovery_error_different_urls_entirely() {
        // Azure-AD-style: the v2.0 authority URL vs the actual issuer.
        // Works for any provider where the operator copy-pasted a wrong URL.
        let raw = "Validation(\"unexpected issuer URI `https://sts.windows.net/tenant-id/` (expected `https://login.microsoftonline.com/tenant-id/v2.0`)\")";
        let msg = friendly_discovery_error(raw);
        assert!(msg.contains("issuer_url does not match the provider's advertised value"));
        assert!(msg.contains("config:   \"https://login.microsoftonline.com/tenant-id/v2.0\""));
        assert!(msg.contains("provider: \"https://sts.windows.net/tenant-id/\""));
        assert!(msg.contains("Fix: set issuer_url = \"https://sts.windows.net/tenant-id/\""));
    }

    #[test]
    fn friendly_discovery_error_passes_through_other_errors() {
        let raw = "Request(NetworkError(connect_timeout))";
        let msg = friendly_discovery_error(raw);
        assert_eq!(
            msg,
            "OIDC discovery failed: Request(NetworkError(connect_timeout))"
        );
    }

    // ── Redirect target validation ─────────────────────────────────────

    #[test]
    fn safe_redirect_path_accepts_relative_paths() {
        for p in ["/", "/connections.html", "/foo/bar?x=1", "/a/b/c"] {
            assert!(is_safe_redirect_path(p), "{p}");
        }
    }

    #[test]
    fn safe_redirect_path_rejects_external_targets() {
        for p in [
            "//evil.com",
            "https://evil.com",
            "http://evil.com",
            "javascript:alert(1)",
            "evil.com",
            "",
        ] {
            assert!(!is_safe_redirect_path(p), "{p}");
        }
    }

    #[test]
    fn safe_redirect_path_rejects_backslashes() {
        // Browsers normalize `\` to `/`, so `/\evil.com` and `\\evil.com`
        // become protocol-relative URLs.
        for p in ["/\\evil.com", "\\\\evil.com", "/foo\\bar", "/foo\\/bar"] {
            assert!(!is_safe_redirect_path(p), "{p}");
        }
    }

    #[test]
    fn safe_redirect_path_rejects_control_characters() {
        for p in [
            "/foo\nbar",
            "/foo\r\nbar",
            "/foo\tbar",
            "/foo\x7fbar",
            "/foo\x00bar",
        ] {
            assert!(!is_safe_redirect_path(p), "{p}");
        }
    }

    // ── Desktop login intent (persea#227) ──────────────────────────────

    #[test]
    fn login_params_desktop_flag_is_tolerant() {
        // The desktop shell's convention is `desktop=1`; plain `bool`
        // deserialization would reject it.
        let p: LoginParams = serde_urlencoded::from_str("desktop=1").unwrap();
        assert!(p.desktop);
        let p: LoginParams = serde_urlencoded::from_str("desktop=true").unwrap();
        assert!(p.desktop);
        let p: LoginParams = serde_urlencoded::from_str("desktop=0").unwrap();
        assert!(!p.desktop);
        let p: LoginParams = serde_urlencoded::from_str("").unwrap();
        assert!(!p.desktop);
        // Other params still parse alongside the flag.
        let p: LoginParams =
            serde_urlencoded::from_str("provider=corp&desktop=1&next=%2Fconnections.html").unwrap();
        assert!(p.desktop);
        assert_eq!(p.provider.as_deref(), Some("corp"));
        assert_eq!(p.next.as_deref(), Some("/connections.html"));
    }
}
