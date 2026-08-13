//! U03: auth-enforced HTML page routes.
//!
//! Mirrors the `html_routes` split in `src/main.rs`: a protected group
//! (every HTML page except login/docs/setup) behind the real `require_auth`
//! middleware, plus a public group for the login-free pages. Stub handlers
//! stand in for the page handlers (they live in the binary crate, which
//! integration tests cannot reach); the middleware stack — `require_auth`,
//! the feature gates, the public/protected group split — is the same
//! structure main.rs composes, so a regression in the split fails here.
//!
//! Public-by-design routes not covered here: `/`, `/setup`, and the login
//! pages (auth_pages/setup_routes groups in main.rs) and
//! `/client/{session_id}` (unauth_routes: share links are anonymous; the
//! client page enforces auth itself via the session fetch, which returns
//! 401 without a cookie and navigates the browser to `/`).

use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::Db;
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    persea::db::init_db(std::path::Path::new(":memory:")).unwrap()
}

async fn stub_ok() -> axum::response::Response {
    use axum::response::IntoResponse;
    StatusCode::OK.into_response()
}

/// Which `enable_*` admin setting gates a page route, carried as a request
/// extension — mirrors `FeatureGate` + `feature_gate` in main.rs.
#[derive(Clone)]
struct FeatureGate(&'static str);

/// Request-time page gate mirroring main.rs: a styled 404 when the named
/// `enable_*` toggle is disabled.
async fn feature_gate(
    Extension(db): Extension<Db>,
    Extension(gate): Extension<FeatureGate>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if persea::settings_merge::read_toggle(&db, gate.0, true) {
        return next.run(request).await;
    }
    persea::templates::render_error_page(
        StatusCode::NOT_FOUND,
        "The page you requested could not be found",
        "test-nonce",
    )
}

/// Mirrors the html_routes structure in main.rs: a protected group with the
/// gated pages merged in and `require_auth` layered on top, merged with a
/// public group carrying the docs routes.
fn html_router(db: Db) -> Router {
    let gated_tunnels = Router::new()
        .route("/admin/tunnels.html", get(stub_ok))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_ssh_tunnels")))
        .layer(Extension(db.clone()));
    let gated_recordings = Router::new()
        .route("/recordings.html", get(stub_ok))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_recordings")))
        .layer(Extension(db.clone()));
    let gated_tokens = Router::new()
        .route("/tokens.html", get(stub_ok))
        .route("/account/tokens.html", get(stub_ok))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_api_keys")))
        .layer(Extension(db.clone()));

    let protected = Router::new()
        .route("/index.html", get(stub_ok))
        .route("/connections.html", get(stub_ok))
        .route("/addressbook.html", get(stub_ok))
        .route("/sessions.html", get(stub_ok))
        .route("/reports.html", get(stub_ok))
        .route("/admin.html", get(stub_ok))
        .route("/account/profile.html", get(stub_ok))
        .route("/account/totp.html", get(stub_ok))
        .route("/admin/users.html", get(stub_ok))
        .route("/admin/auth.html", get(stub_ok))
        .route("/admin/groups.html", get(stub_ok))
        .route("/admin/audit.html", get(stub_ok))
        .route("/admin/settings.html", get(stub_ok))
        .route("/admin/reports.html", get(stub_ok))
        .route("/admin/roles.html", get(stub_ok))
        .route("/admin/branding.html", get(stub_ok))
        .merge(gated_tunnels)
        .merge(gated_recordings)
        .merge(gated_tokens)
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db.clone()));

    let public = Router::new()
        .route("/docs.html", get(stub_ok))
        .route("/docs", get(stub_ok))
        // `/`, `/setup`, and the login pages live in the auth_pages and
        // setup_routes groups in main.rs; `/client/{session_id}` lives in
        // the unauth_routes group (share tokens are anonymous by design).
        .route("/", get(stub_ok))
        .route("/setup", get(stub_ok))
        .route("/client/{session_id}", get(stub_ok));

    protected.merge(public)
}

fn html_get(path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::ACCEPT, "text/html")
        .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Every route in the protected group, exactly as registered in main.rs.
const PROTECTED_PATHS: &[&str] = &[
    "/index.html",
    "/connections.html",
    "/addressbook.html",
    "/sessions.html",
    "/reports.html",
    "/admin.html",
    "/account/profile.html",
    "/account/totp.html",
    "/admin/users.html",
    "/admin/auth.html",
    "/admin/groups.html",
    "/admin/audit.html",
    "/admin/settings.html",
    "/admin/reports.html",
    "/admin/roles.html",
    "/admin/branding.html",
    "/admin/tunnels.html",
    "/recordings.html",
    "/tokens.html",
    "/account/tokens.html",
];

#[tokio::test]
async fn protected_pages_redirect_to_login_without_a_cookie() {
    let router = html_router(test_db());
    for path in PROTECTED_PATHS {
        let resp = router.clone().oneshot(html_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "path {path}");
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok());
        assert_eq!(loc, Some("/?error=login_required"), "path {path}");
    }
}

#[tokio::test]
async fn protected_pages_return_json_401_for_non_html_clients() {
    // API/AJAX callers (no `Accept: text/html`) must get the JSON 401, not
    // the login redirect — mirrors require_auth's split.
    let router = html_router(test_db());
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/connections.html")
                .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn public_pages_serve_without_a_cookie() {
    let router = html_router(test_db());
    for path in ["/", "/docs", "/docs.html", "/setup"] {
        let resp = router.clone().oneshot(html_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "path {path}");
    }
}

#[tokio::test]
async fn client_page_stays_public_for_share_tokens() {
    // `/client/{id}` must NOT be behind require_auth: share links
    // (`?token=`) are anonymous by design. Auth enforcement for the page is
    // client-side: the session fetch returns 401 without a cookie and
    // closeOrNavigate() sends the browser to `/` (client.html boot flow).
    let router = html_router(test_db());
    let resp = router
        .oneshot(html_get("/client/00000000-0000-0000-0000-000000000000"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn gated_pages_404_when_their_toggle_is_off() {
    // The 404 gate sits INSIDE require_auth in main.rs (feature_gate layer
    // on the merged protected group), so a cookie-less browser gets the
    // login redirect first — the 404 is only served to authenticated
    // callers. That ordering is locked here; the authenticated 404
    // behavior is covered in feature_toggles_tests.rs.
    let db = test_db();
    {
        let conn = db.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS system_settings (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL DEFAULT '',
                updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES ('enable_recordings', 'false')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES ('enable_ssh_tunnels', 'false')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO system_settings (key, value) VALUES ('enable_api_keys', 'false')",
            [],
        )
        .unwrap();
    }
    let router = html_router(db);
    for path in [
        "/recordings.html",
        "/admin/tunnels.html",
        "/tokens.html",
        "/account/tokens.html",
    ] {
        let resp = router.clone().oneshot(html_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "path {path}");
    }
}

#[tokio::test]
async fn gated_pages_serve_when_toggles_are_absent_or_on() {
    let router = html_router(test_db());
    for path in [
        "/recordings.html",
        "/admin/tunnels.html",
        "/tokens.html",
        "/account/tokens.html",
    ] {
        let resp = router.clone().oneshot(html_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER, "path {path}");
    }
}
