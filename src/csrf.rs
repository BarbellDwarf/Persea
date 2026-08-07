//! Double-submit cookie CSRF protection middleware.
//!
//! On state-changing methods (POST, PUT, DELETE, PATCH), the `X-CSRF-Token`
//! request header must match the `csrf_token` cookie. GET/HEAD/OPTIONS are
//! exempt. A random token cookie is set on every response that doesn't already
//! carry one.

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, Request, Response, StatusCode};
use tower::{Layer, Service};

pub const CSRF_COOKIE: &str = "csrf_token";
const CSRF_TOKEN_LEN: usize = 32;

/// Header-only variant of the HTTPS check for handlers that extract
/// `HeaderMap` instead of the full request.
pub fn is_https_headers(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or("").trim() == "https")
        .unwrap_or(false)
}

/// `"; Secure"` when the request arrived over HTTPS (or a proxy says so),
/// empty otherwise. Set-Cookie builders use this so session cookies are not
/// dropped by browsers when serving plain HTTP (e.g. LAN access without TLS).
pub fn cookie_secure_attr(headers: &HeaderMap) -> &'static str {
    if is_https_headers(headers) {
        "; Secure"
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
    headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                if let Some(val) = c.strip_prefix(name) {
                    val.strip_prefix('=').map(|v| v.to_string())
                } else {
                    None
                }
            })
        })
}

fn is_state_changing(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::DELETE | Method::PATCH
    )
}

#[derive(Clone)]
pub struct CsrfLayer;

impl<S> Layer<S> for CsrfLayer {
    type Service = CsrfService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CsrfService { inner }
    }
}

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
        // Secure cookie attribute only over HTTPS. Hyper sets the URI scheme
        // on TLS connections; behind a reverse proxy, honour X-Forwarded-Proto.
        let is_https = req
            .uri()
            .scheme()
            .map(|s| s.as_str() == "https")
            .unwrap_or(false)
            || req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .map(|v| v.split(',').next().unwrap_or("").trim() == "https")
                .unwrap_or(false);

        // Check CSRF for state-changing methods
        if is_state_changing(&method) {
            let cookie_token = extract_cookie(req.headers(), CSRF_COOKIE);
            let header_token = req
                .headers()
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());

            match (cookie_token, header_token) {
                (Some(cookie), Some(header)) if cookie == header => {
                    // Valid — proceed
                }
                _ => {
                    return Box::pin(async {
                        let body_text =
                            serde_json::json!({"error": "CSRF token missing or invalid"})
                                .to_string();
                        let resp = Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Body::from(body_text))
                            .unwrap_or_else(|_| Response::new(Body::empty()));
                        Ok(resp)
                    });
                }
            }
        }

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut resp = inner.call(req).await?;

            // Always set csrf_token cookie so the double-submit pattern works.
            // Not HttpOnly: JS (htmx/fetch) needs to read it and echo it
            // back as X-CSRF-Token.
            {
                let token = generate_token();
                let secure = if is_https { "; Secure" } else { "" };
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
        let resp = run(Request::builder()
            .uri("https://persea.test/")
            .body(Body::empty())
            .unwrap())
        .await;
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Secure"), "got {set_cookie}");
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
    async fn get_requests_are_exempt() {
        let resp = run(Request::get("/").body(Body::empty()).unwrap()).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
