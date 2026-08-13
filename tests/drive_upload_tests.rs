//! Integration tests for the RDP drive upload endpoint: CSRF enforcement
//! (no exemption from the global double-submit check), the Bearer-only
//! bootstrap contract, and gate ordering through a real router.
//!
//! Success-path behavior with seeded sessions lives in the unit tests in
//! `src/api/sessions.rs` (`SessionManager::sessions` is `pub(crate)`, so
//! an integration crate cannot seed live sessions).
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Json, Router};
use persea::api::drive_upload_file;
use persea::auth::AuthIdentity;
use persea::csrf::{CsrfLayer, CSRF_COOKIE};
use persea::session::SessionManager;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

fn owner() -> AuthIdentity {
    AuthIdentity::User {
        email: "alice@example.com".into(),
        name: "alice".into(),
        role: "viewer".into(),
        groups: vec![],
    }
}

/// Stand-in for `/api/auth/status`: an anonymous GET the Bearer-only
/// client uses to bootstrap the `csrf_token` cookie.
async fn status_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
}

fn test_router() -> Router {
    let mut config = persea::config::Config::default();
    config.recording_path =
        Some(std::env::temp_dir().join(format!("persea-drive-upload-test-{}", Uuid::new_v4())));
    let manager: Arc<SessionManager> = Arc::new(SessionManager::new(config, None));
    Router::new()
        .route("/api/auth/status", get(status_handler))
        .route(
            "/api/sessions/{id}/drive-files/{name}",
            axum::routing::put(drive_upload_file),
        )
        .layer(CsrfLayer)
        .with_state(manager)
}

fn put_upload(
    id: Uuid,
    name: &str,
    payload: &[u8],
    identity: Option<AuthIdentity>,
    cookie: Option<&str>,
    csrf_header: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method("PUT")
        .uri(format!("/api/sessions/{id}/drive-files/{name}"));
    if let Some(id) = identity {
        builder = builder.extension(Extension(id));
    }
    if let Some(c) = cookie {
        builder = builder.header(header::COOKIE, c);
    }
    if let Some(t) = csrf_header {
        builder = builder.header("x-csrf-token", t);
    }
    builder.body(Body::from(payload.to_vec())).unwrap()
}

fn cookie_value(resp: &axum::response::Response, name: &str) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|sc| {
            let sc = sc.to_str().ok()?;
            let (n, v) = sc.split(';').next()?.split_once('=')?;
            (n == name).then(|| v.to_string())
        })
}

// ── CSRF: no exemption for this endpoint ──

#[tokio::test]
async fn put_without_csrf_token_is_403() {
    let router = test_router();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_with_cookie_but_no_header_is_403() {
    let router = test_router();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            Some("csrf_token=attacker"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_with_header_but_no_cookie_is_403() {
    let router = test_router();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            None,
            Some("attacker-guess"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_with_mismatched_cookie_and_header_is_403() {
    let router = test_router();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            Some("csrf_token=cookie-a"),
            Some("header-b"),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Bearer bootstrap contract ──

#[tokio::test]
async fn bearer_bootstrap_then_put_reaches_handler() {
    let router = test_router();
    // Anonymous GET sets the csrf_token cookie (no auth needed).
    let first = router
        .clone()
        .oneshot(
            Request::get("/api/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let token = cookie_value(&first, CSRF_COOKIE).expect("GET must set the csrf_token cookie");
    assert!(!token.is_empty());
    // PUT with cookie + matching header passes the CSRF layer; the
    // unknown session then 404s inside the handler, proving the request
    // was not rejected by the middleware.
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            Some(&format!("{CSRF_COOKIE}={token}")),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "CSRF must pass and the handler must run (404 unknown session)"
    );
}

// ── Gate ordering ──

#[tokio::test]
async fn put_with_valid_csrf_but_no_identity_is_403() {
    let router = test_router();
    let first = router
        .clone()
        .oneshot(
            Request::get("/api/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let token = cookie_value(&first, CSRF_COOKIE).unwrap();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            None,
            Some(&format!("{CSRF_COOKIE}={token}")),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn put_with_valid_csrf_and_unknown_session_is_404() {
    let router = test_router();
    let first = router
        .clone()
        .oneshot(
            Request::get("/api/auth/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let token = cookie_value(&first, CSRF_COOKIE).unwrap();
    let resp = router
        .oneshot(put_upload(
            Uuid::new_v4(),
            "file.bin",
            b"payload",
            Some(owner()),
            Some(&format!("{CSRF_COOKIE}={token}")),
            Some(&token),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
