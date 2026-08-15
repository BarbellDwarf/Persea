/// Double-submit cookie CSRF protection middleware.
///
/// On state-changing methods (POST, PUT, DELETE, PATCH), the `X-CSRF-Token`
/// request header must match the `csrf_token` cookie. GET/HEAD/OPTIONS are
/// exempt. A random token cookie is set on every response.
///
/// Fallback: if the header is missing, the middleware peeks at form bodies
/// for a `csrf_token` field. This handles cases where JavaScript cannot
/// read the cookie (browser extensions, network timing, device quirks).
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, Response, StatusCode};
use subtle::ConstantTimeEq;
use tower::{Layer, Service};

use crate::auth::TrustedProxies;

/// Name of the CSRF double-submit token cookie.
pub const CSRF_COOKIE: &str = "csrf_token";
const CSRF_TOKEN_LEN: usize = 32;

/// POST path of the SAML Assertion Consumer Service.
///
/// Exempt from the double-submit check: the IdP POSTs the SAMLResponse here
/// with no browser session and no CSRF cookie, and the signed assertion is
/// itself the authentication. The exemption is a path check in this module,
/// never route wiring, so every CSRF-guarded router (the SAML routes are
/// behind `CsrfLayer` in main.rs) picks it up automatically.
pub const SAML_ACS_PATH: &str = "/auth/saml/acs";

/// Whether Persea terminates TLS itself (set at startup from the server
/// config). The process runs exactly one listener mode, so this is a
/// reliable, non-spoofable signal for direct (no-proxy) deployments.
#[derive(Clone)]
pub struct TlsEnabled(pub bool);

/// Whether to set the `Secure` attribute on cookies. Defaults to true when TLS
/// is enabled. Set to false for self-signed certs — browsers block Secure
/// cookies over connections with invalid certificates.
///
/// Stored as a process-global once set at startup, so `cookie_secure_attr` can
/// read it without threading the value through every handler.
pub struct SecureCookies(pub bool);

static SECURE_COOKIES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

impl SecureCookies {
    /// Initialize the global secure-cookies flag (call once at startup).
    pub fn init(secure: bool) {
        let _ = SECURE_COOKIES.set(secure);
    }

    /// Read the global flag. Returns true (default) if not yet initialized.
    pub fn enabled() -> bool {
        SECURE_COOKIES.get().copied().unwrap_or(true)
    }
}

/// Is the connection HTTPS? True when Persea terminated TLS itself, or when
/// a trusted proxy reports `X-Forwarded-Proto: https`. The proxy header is
/// only honoured when the immediate peer is in `trusted_proxies` — matching
/// the gate `client_ip()` applies to `X-Forwarded-For`.
pub fn is_https(
    headers: &HeaderMap,
    tls_enabled: bool,
    trusted_proxies: Option<&TrustedProxies>,
    peer_ip: Option<IpAddr>,
) -> bool {
    if tls_enabled {
        return true;
    }
    let peer_trusted = match (trusted_proxies, peer_ip) {
        (Some(proxies), Some(ip)) => proxies.0.iter().any(|cidr| {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map(|net| net.contains(ip))
                .unwrap_or(false)
        }),
        _ => false,
    };
    if !peer_trusted {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim() == "https")
        .unwrap_or(false)
}

/// `is_https` for code that holds the full request: reads `TlsEnabled`,
/// `TrustedProxies`, and `ConnectInfo` from the request extensions.
pub fn is_https_request(req: &Request<Body>) -> bool {
    // If SecureCookies is disabled (e.g. self-signed cert), skip the Secure
    // attribute on all cookies.
    if !SecureCookies::enabled() {
        return false;
    }
    let tls_enabled = req
        .extensions()
        .get::<TlsEnabled>()
        .map(|t| t.0)
        .unwrap_or(false);
    let trusted_proxies = req.extensions().get::<TrustedProxies>();
    let peer_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    is_https(req.headers(), tls_enabled, trusted_proxies, peer_ip)
}

/// `" Secure;"` when the request arrived over HTTPS (Persea's own TLS or a
/// trusted proxy), empty otherwise. Set-Cookie builders use this so session
/// cookies are not dropped by browsers when serving plain HTTP (e.g. LAN
/// access without TLS).
///
/// The value is designed to be interpolated into `HttpOnly;{} SameSite=Lax`
/// so the result is `HttpOnly; Secure; SameSite=Lax` (HTTPS) or
/// `HttpOnly; SameSite=Lax` (HTTP) — no double semicolons, always a space
/// before SameSite so Chromium parses the attribute correctly.
pub fn cookie_secure_attr(
    headers: &HeaderMap,
    tls_enabled: bool,
    trusted_proxies: Option<&TrustedProxies>,
    peer_ip: Option<IpAddr>,
) -> &'static str {
    if SecureCookies::enabled() && is_https(headers, tls_enabled, trusted_proxies, peer_ip) {
        " Secure;"
    } else {
        ""
    }
}

fn generate_token() -> String {
    use rand::RngExt;
    let mut buf = [0u8; CSRF_TOKEN_LEN];
    rand::rng().fill(&mut buf);
    hex::encode(buf)
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    // Combine ALL cookie headers before parsing — some clients split cookies
    // across multiple Cookie headers, and `get()` would only see the first.
    let combined: String = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join("; ");
    if combined.is_empty() {
        return None;
    }
    combined.split(';').find_map(|c| {
        let c = c.trim();
        if let Some(val) = c.strip_prefix(name) {
            val.strip_prefix('=').map(|v| v.to_string())
        } else {
            None
        }
    })
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

/// Tower layer that wraps a service with the CSRF double-submit check.
#[derive(Clone)]
pub struct CsrfLayer;

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService { inner }
    }
}

/// Tower service enforcing the CSRF double-submit check on
/// state-changing requests.
#[derive(Clone)]
pub struct CsrfService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for CsrfService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let method = req.method().clone();
        // Secure cookie attribute only over HTTPS: Persea's own TLS, or a
        // trusted proxy's X-Forwarded-Proto (gated on the peer address).
        // Also gated on `SecureCookies::enabled()` — same as the session
        // cookie's `cookie_secure_attr()` — so a self-signed cert (which
        // browsers refuse to send Secure-flagged cookies over, even after
        // clicking through the warning) doesn't silently drop this cookie
        // too. This was missed when that fix landed: this is a separate,
        // parallel code path that never consulted the flag at all.
        let is_https = SecureCookies::enabled() && is_https_request(&req);

        let mut inner = self.inner.clone();
        Box::pin(async move {
            // ── CSRF double-submit check ─────────────────────────────
            // Check X-CSRF-Token header first. If header is missing,
            // peek at form bodies (application/x-www-form-urlencoded)
            // for a csrf_token field. This covers devices where JS
            // cannot read the CSRF cookie.
            let mut req = req;
            // Capture the incoming CSRF cookie before `req` is moved into
            // the inner service.  Used both for the double-submit check
            // (state-changing methods) and to re-set the cookie on the
            // response without generating a fresh token each time.
            let incoming_cookie = extract_cookie(req.headers(), CSRF_COOKIE);

            // The SAML ACS callback is exempt: the IdP posts the assertion
            // with no browser cookie, and signature validation is the
            // authentication (see `SAML_ACS_PATH`).
            if is_state_changing(&method) && req.uri().path() != SAML_ACS_PATH {
                let header_token = req
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());

                let form_token = if header_token.is_none() {
                    let ct = req
                        .headers()
                        .get(header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    if ct.contains("application/x-www-form-urlencoded") {
                        let (parts, body) = req.into_parts();
                        let (bytes_result, token) = match axum::body::to_bytes(body, usize::MAX)
                            .await
                        {
                            Ok(bytes) => {
                                let form = std::str::from_utf8(&bytes).unwrap_or("");
                                let tok = form.split('&').find_map(|pair| {
                                    let (k, v) = pair.split_once('=')?;
                                    if k == CSRF_COOKIE {
                                        Some(urlencoding::decode(v).unwrap_or_default().to_string())
                                    } else {
                                        None
                                    }
                                });
                                (Some(bytes), tok)
                            }
                            Err(_) => (None, None),
                        };
                        // Always restore the request — either with original bytes or empty
                        let body = match bytes_result {
                            Some(b) => Body::from(b),
                            None => Body::empty(),
                        };
                        req = Request::from_parts(parts, body);
                        token
                    } else {
                        None
                    }
                } else {
                    None
                };

                let effective = header_token.or(form_token);
                // Constant-time comparison: the token is a bearer credential
                // and its length is fixed (hex-encoded random bytes), so a
                // timing side channel here would leak nothing about the
                // token's value — but compare in constant time anyway, per
                // the codebase's secrets policy.
                let token_matches = match (&incoming_cookie, &effective) {
                    (Some(c), Some(h)) => c.as_bytes().ct_eq(h.as_bytes()).into(),
                    _ => false,
                };
                if !token_matches {
                    let path = req.uri().path().to_string();
                    // Never log the token values themselves: they are
                    // bearer credentials. Presence flags keep the log
                    // diagnostic (was anything sent at all?) without
                    // leaking the tokens.
                    tracing::warn!(
                        had_cookie = incoming_cookie.is_some(),
                        had_token = effective.is_some(),
                        path = %path,
                        "CSRF token mismatch"
                    );
                    // The login form is a plain (non-fetch) POST — a raw
                    // JSON body here would navigate the
                    // browser straight to it instead of showing on the
                    // login page. Redirect back with a friendly error
                    // instead, matching how every other login failure
                    // is surfaced. All other endpoints (admin UI, API)
                    // are fetch/htmx-driven and expect JSON.
                    if path == "/auth/login" {
                        return Ok(Response::builder()
                            .status(StatusCode::SEE_OTHER)
                            .header(header::LOCATION, "/?error=csrf_failed")
                            .body(Body::empty())
                            .unwrap_or_else(|_| Response::new(Body::empty())));
                    }
                    let body_text =
                        serde_json::json!({"error": "CSRF token missing or invalid"})
                            .to_string();
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(body_text))
                        .unwrap_or_else(|_| Response::new(Body::empty())));
                }
            }

            let mut resp = inner.call(req).await?;

            // Reuse the incoming cookie token if present; only generate a
            // fresh one when the request had none (first visit / expired).
            // Generating a new token on *every* response caused race
            // conditions: concurrent AJAX calls would each receive a new
            // token, and whichever Set-Cookie arrived last "won", leaving
            // earlier callers with a stale cookie value.
            {
                let token = incoming_cookie.unwrap_or_else(generate_token);
                let secure = if is_https { " Secure" } else { "" };
                let cookie = format!("{}={}; Path=/; SameSite=Lax;{}", CSRF_COOKIE, token, secure);
                resp.headers_mut()
                    .append(header::SET_COOKIE, cookie.parse().unwrap());
            }
            Ok(resp)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::service_fn;
    use tower::ServiceExt;

    async fn ok_handler(_req: Request<Body>) -> Result<Response<Body>, std::convert::Infallible> {
        Ok(Response::new(Body::from("ok")))
    }

    async fn run(req: Request<Body>) -> Response<Body> {
        CsrfService {
            inner: service_fn(ok_handler),
        }
        .oneshot(req)
        .await
        .unwrap()
    }

    fn cookie_value<'a>(resp: &'a Response<Body>, name: &str) -> Option<&'a str> {
        let set_cookie = resp.headers().get(header::SET_COOKIE)?.to_str().ok()?;
        let (n, v) = set_cookie.split(';').next()?.split_once('=')?;
        (n == name).then_some(v)
    }

    #[tokio::test]
    async fn sets_cookie_not_httponly_on_plain_get() {
        let resp = run(Request::get("/").body(Body::empty()).unwrap()).await;

        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .expect("csrf cookie must be set")
            .to_str()
            .unwrap();
        assert!(set_cookie.starts_with("csrf_token="), "got {set_cookie}");
        assert!(
            !set_cookie.to_lowercase().contains("httponly"),
            "cookie must be readable by JS (double-submit pattern): {set_cookie}"
        );
        assert!(set_cookie.contains("SameSite=Lax"), "got {set_cookie}");
        assert!(
            !set_cookie.contains("Secure"),
            "no Secure over plain HTTP: {set_cookie}"
        );
    }

    #[tokio::test]
    async fn secure_flag_set_over_https_scheme() {
        let mut req = Request::builder()
            .uri("https://persea.test/")
            .body(Body::empty())
            .unwrap();
        // Persea's own TLS termination is the HTTPS signal (the URI scheme
        // alone is client-supplied and not trusted).
        req.extensions_mut().insert(TlsEnabled(true));
        let resp = run(req).await;
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Secure"), "got {set_cookie}");
    }

    #[tokio::test]
    async fn secure_flag_not_set_without_tls_or_trusted_proxy() {
        let resp = run(Request::builder()
            .uri("https://persea.test/")
            .header("x-forwarded-proto", "https")
            .body(Body::empty())
            .unwrap())
        .await;
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            !set_cookie.contains("Secure"),
            "client-supplied X-Forwarded-Proto must not set Secure: {set_cookie}"
        );
    }

    #[tokio::test]
    async fn post_without_header_is_rejected() {
        let resp = run(Request::post("/").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_without_cookie_but_header_is_rejected() {
        let resp = run(Request::post("/")
            .header("x-csrf-token", "attacker-guess")
            .body(Body::empty())
            .unwrap())
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_matching_cookie_and_header_passes() {
        // First request to learn the token the server issued.
        let first = run(Request::get("/").body(Body::empty()).unwrap()).await;
        let token = cookie_value(&first, CSRF_COOKIE)
            .expect("csrf cookie")
            .to_string();
        assert!(!token.is_empty());

        let resp = run(Request::post("/")
            .header(header::COOKIE, format!("{CSRF_COOKIE}={token}"))
            .header("x-csrf-token", token)
            .body(Body::empty())
            .unwrap())
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "matching token must pass");
    }

    #[tokio::test]
    async fn saml_acs_post_is_exempt_from_csrf() {
        // The IdP POSTs the SAMLResponse with no browser cookie; the signed
        // assertion is the authentication. The exemption lives here, as a
        // path check, not in route wiring.
        let resp = run(Request::post(SAML_ACS_PATH)
            .body(Body::from("SAMLResponse=abc123"))
            .unwrap())
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "SAML ACS POST must bypass the CSRF check"
        );
        // The response still carries the double-submit cookie so any
        // subsequent browser navigation keeps a token.
        assert!(
            resp.headers()
                .get(header::SET_COOKIE)
                .is_some_and(|v| v.to_str().is_ok_and(|s| s.starts_with("csrf_token="))),
            "ACS response must still set the CSRF cookie"
        );
    }

    #[tokio::test]
    async fn saml_acs_is_the_only_exempt_path() {
        // Near-misses (/auth/saml, /auth/saml/acs/anything) must NOT be
        // exempt — the exemption is exact-path only.
        for path in ["/auth/saml", "/auth/saml/acs/", "/auth/saml/metadata"] {
            let resp = run(Request::post(path).body(Body::empty()).unwrap()).await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "path {path}");
        }
    }

    #[tokio::test]
    async fn mismatched_tokens_rejected() {
        let first = run(Request::get("/").body(Body::empty()).unwrap()).await;
        let token = cookie_value(&first, CSRF_COOKIE)
            .expect("csrf cookie")
            .to_string();
        let resp = run(Request::post("/")
            .header(header::COOKIE, format!("{CSRF_COOKIE}={token}"))
            .header("x-csrf-token", "deadbeefdeadbeefdeadbeefdeadbeef")
            .body(Body::empty())
            .unwrap())
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_requests_are_exempt() {
        let resp = run(Request::get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[test]
    fn cookie_format_no_double_semicolons() {
        let secure = " Secure;";
        let cookie = format!(
            "persea_session=test123; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=86400",
            secure
        );
        assert!(
            !cookie.contains(";;"),
            "double semicolons in cookie: {cookie}"
        );
        assert!(
            cookie.contains("HttpOnly; Secure; SameSite=Lax"),
            "expected clean format: {cookie}"
        );
    }

    #[test]
    fn cookie_format_http_no_secure() {
        let secure = "";
        let cookie = format!(
            "persea_session=test123; Path=/; HttpOnly;{} SameSite=Lax; Max-Age=86400",
            secure
        );
        assert!(
            !cookie.contains(";;"),
            "double semicolons in cookie: {cookie}"
        );
        assert!(
            cookie.contains("HttpOnly; SameSite=Lax"),
            "expected no-secure format: {cookie}"
        );
        assert!(
            !cookie.contains("Secure"),
            "should not have Secure on HTTP: {cookie}"
        );
    }
}
