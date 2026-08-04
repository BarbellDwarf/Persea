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

fn generate_token() -> String {
    use rand::Rng;
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
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let method = req.method().clone();

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
                    let mut inner = self.inner.clone();
                    return Box::pin(async move {
                        let resp = Response::builder()
                            .status(StatusCode::FORBIDDEN)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(axum::body::to_body(
                                serde_json::json!({"error": "CSRF token missing or invalid"})
                                    .to_string(),
                            ))
                            .unwrap_or_else(|_| Response::new(Body::empty()));
                        Ok(resp)
                    });
                }
            }
        }

        let mut inner = self.inner.clone();
        Box::pin(async move {
            let mut resp = inner.call(req).await?;

            // Set csrf_token cookie on responses that don't have one yet
            if !resp.headers().contains_key(header::SET_COOKIE) {
                let token = generate_token();
                let cookie = format!(
                    "{}={}; Path=/; SameSite=Lax; HttpOnly",
                    CSRF_COOKIE, token
                );
                resp.headers_mut()
                    .insert(header::SET_COOKIE, cookie.parse().unwrap());
            }
            Ok(resp)
        })
    }
}
