//! Setup wizard flow regression tests (persea#94).
//!
//! The wizard used to intercept its form submit with fetch() and navigate
//! to `/` on any non-redirected response, discarding the server-side
//! validation error and bouncing back to `/setup` in a silent loop. These
//! tests pin the native-form behaviour against the real handlers: a short
//! password re-renders the page with the error visible, a valid password
//! creates the admin and redirects to the login page, and a store that
//! already has users redirects GET /setup away.
//!
//! Harness mirrors tests/api_handler_tests.rs: in-memory SQLite via
//! `db::init_db(":memory:")` and tower::ServiceExt one-shot requests. The
//! handlers run on the lib-crate copy (exposed via `persea::handlers`);
//! production uses the same source files compiled into the binary.

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use persea::api::SiteTitle;
use persea::config::Config;
use persea::db::{self, Db};
use persea::handlers::setup::{needs_setup, setup_page, setup_submit};
use persea::templates::CspNonce;
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

/// Point the wizard's config-file write at a temp file so the tests never
/// touch a real /opt/persea/config.toml.
fn point_config_writes_to_temp() {
    std::env::set_var(
        "RUSTGUAC_CONFIG",
        std::env::temp_dir().join("persea-setup-test-config.toml"),
    );
}

/// Router with the real setup handlers, the same extensions the setup
/// routes group carries in main.rs (SiteTitle, Config, Db, CspNonce).
fn test_router(db: Db, config: Config) -> Router {
    Router::new()
        .route("/setup", get(setup_page).post(setup_submit))
        .layer(Extension(SiteTitle("persea".to_string())))
        .layer(Extension(config))
        .layer(Extension(db))
        .layer(Extension(CspNonce("test-nonce".to_string())))
}

fn setup_post(password: &str) -> Request<Body> {
    let body = format!(
        "listen_addr=0.0.0.0:8089&db_path=/var/lib/persea/persea.db&\
         guacd_addr=127.0.0.1:4822&admin_email=admin%40example.com&\
         admin_name=Administrator&admin_password={password}"
    );
    Request::builder()
        .method("POST")
        .uri("/setup")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
        .body(Body::from(body))
        .unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn short_password_rerenders_wizard_with_error() {
    point_config_writes_to_temp();
    let db = test_db();
    let router = test_router(db.clone(), Config::default());

    let resp = router.oneshot(setup_post("abcdefghij")).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "validation failure re-renders, no redirect"
    );
    let text = body_text(resp).await;
    assert!(
        text.contains("at least 15 characters"),
        "policy error must be visible in the re-rendered wizard, got: {text}"
    );
    assert!(
        text.contains("Complete Setup"),
        "wizard form must re-render"
    );
    assert_eq!(db::count_users(&db).unwrap(), 0, "no user may be created");
}

#[tokio::test]
async fn valid_password_creates_admin_and_redirects_to_login() {
    point_config_writes_to_temp();
    let db = test_db();
    let router = test_router(db.clone(), Config::default());

    let resp = router
        .oneshot(setup_post("supersecretpass123"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "valid submit redirects exactly once"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("/?setup=complete"));

    assert_eq!(db::count_users(&db).unwrap(), 1);
    assert!(
        !needs_setup(&db),
        "wizard must no longer be needed after setup"
    );

    // The stored hash verifies against the submitted password: the admin
    // can log in with it.
    let hash: String = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT password_hash FROM users WHERE email = ?1",
            ["admin@example.com"],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(
        persea::password::verify_password("supersecretpass123", &hash).unwrap(),
        "stored hash must verify the submitted password"
    );
}

#[tokio::test]
async fn setup_page_redirects_away_when_users_exist() {
    let db = test_db();
    db::upsert_user(&db, "admin@example.com", "Admin", None, "admin", &[]).unwrap();
    let router = test_router(db, Config::default());

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/setup")
                .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    assert_eq!(loc, Some("/"));
}

#[tokio::test]
async fn password_field_advertises_policy_minimum() {
    let db = test_db();
    let router = test_router(db, Config::default());

    let resp = router
        .oneshot(
            Request::builder()
                .uri("/setup")
                .extension(ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let text = body_text(resp).await;
    assert!(
        text.contains(r#"minlength="15""#) && text.contains("Minimum 15 characters"),
        "password hint and minlength must reflect the default policy minimum, got: {text}"
    );
}
