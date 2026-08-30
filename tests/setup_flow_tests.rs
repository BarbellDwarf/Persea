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
use persea::handlers::setup::{needs_setup, setup_page, setup_submit, WizardConfigPath};
use persea::templates::CspNonce;
use std::net::SocketAddr;
use std::path::PathBuf;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

/// Point the wizard's config-file write at a temp file so the tests never
/// touch a real /opt/persea/config.toml. Kept for the tests that don't
/// care which path is used (validation, redirect behaviour); the
/// regression test for persea#290 builds its own path explicitly and
/// asserts on it.
fn point_config_writes_to_temp() {
    std::env::set_var(
        "RUSTGUAC_CONFIG",
        std::env::temp_dir().join("persea-setup-test-config.toml"),
    );
}

/// Router with the real setup handlers, the same extensions the setup
/// routes group carries in main.rs (SiteTitle, Config, Db, CspNonce,
/// WizardConfigPath). Path defaults to a per-process temp file; pass an
/// explicit path via `test_router_with_path` to assert the wizard wrote
/// there (persea#290).
fn test_router(db: Db, config: Config) -> Router {
    test_router_with_path(db, config, wizard_default_path())
}

fn wizard_default_path() -> PathBuf {
    std::env::temp_dir().join("persea-setup-test-config.toml")
}

fn test_router_with_path(db: Db, config: Config, wizard_path: PathBuf) -> Router {
    Router::new()
        .route("/setup", get(setup_page).post(setup_submit))
        .layer(Extension(SiteTitle("persea".to_string())))
        .layer(Extension(config))
        .layer(Extension(db))
        .layer(Extension(CspNonce("test-nonce".to_string())))
        .layer(Extension(WizardConfigPath(wizard_path)))
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

/// Unique scratch file for one regression test invocation. Parallel tests
/// in this binary each pick their own path so the wizard's `fs::write`
/// never collides between runs (persea#290).
fn wizard_scratch_config(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "persea-setup-flow-{tag}-{}-{n}.toml",
        std::process::id()
    ))
}

/// Regression for persea#290: a fresh-DB wizard run with the wizard path
/// pointed at an explicit temp file (what `--config <tmpfile>` passes to
/// the handler in production) must rewrite that temp file with the
/// listen_addr the operator picked and a fresh `[storage]` encryption key.
/// Before the fix the wizard used to ignore its incoming path and try to
/// write `/opt/persea/config.toml` regardless, so dev runs and any
/// custom-location deployment silently dropped the generated config
/// while still completing setup.
#[tokio::test]
async fn wizard_writes_to_injected_config_path_not_default() {
    let target = wizard_scratch_config("wizard-writes");
    // Make sure we start from "file absent" so the post-write assertion
    // is unambiguous.
    let _ = std::fs::remove_file(&target);
    let db = test_db();
    let router = test_router_with_path(db, Config::default(), target.clone());

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
    assert_eq!(
        loc,
        Some("/?setup=complete"),
        "successful wizard write must NOT surface the `config=skipped` flag"
    );

    // The wizard wrote to the path we injected (the --config argument in
    // production), and that file now holds the listen_addr the operator
    // submitted plus a freshly-generated `[storage]` encryption key.
    let written = std::fs::read_to_string(&target).expect("wizard must write to injected path");
    assert!(
        written.contains(r#"listen_addr = "0.0.0.0:8089""#),
        "listen_addr from the wizard form must appear in the rewritten config, got: {written}"
    );
    assert!(
        written.contains("[storage]") && written.contains("encryption_key = \""),
        "[storage] section with encryption_key must be present, got: {written}"
    );
}

/// Regression for persea#290: the resolution function is a pure function
/// of (cli config, env). Pin the precedence so a future refactor cannot
/// silently regress. Matches the #271 storage-key writer and
/// docs/configuration.md:384: --config is the canonical file.
#[test]
fn wizard_config_path_resolution_precedence() {
    use persea::config::resolve_wizard_config_path;

    // 1. --config wins over RUSTGUAC_CONFIG (the server reads --config,
    //    so the wizard must write to the same file).
    assert_eq!(
        resolve_wizard_config_path(Some("/tmp/cli.toml"), Some("/tmp/env.toml"),),
        std::path::PathBuf::from("/tmp/cli.toml")
    );
    // 2. RUSTGUAC_CONFIG used only when --config is unset.
    assert_eq!(
        resolve_wizard_config_path(None, Some("/tmp/env.toml")),
        std::path::PathBuf::from("/tmp/env.toml")
    );
    // 3. --config wins when env is also set.
    assert_eq!(
        resolve_wizard_config_path(Some("/tmp/cli.toml"), None),
        std::path::PathBuf::from("/tmp/cli.toml")
    );
    // 4. Empty env treated as unset, falls through to --config.
    assert_eq!(
        resolve_wizard_config_path(Some("/tmp/cli.toml"), Some("")),
        std::path::PathBuf::from("/tmp/cli.toml")
    );
    // 5. Both unset → platform default. CI runs on Linux so /opt/persea.
    assert_eq!(
        resolve_wizard_config_path(None, None),
        std::path::PathBuf::from("/opt/persea/config.toml")
    );
}

/// Regression for persea#290: when the resolved path's parent doesn't
/// exist, setup still completes (admin created, wizard redirects) but the
/// redirect carries `config=skipped` so operators see that the write was
/// dropped, and the warn log names the resolved path.
#[tokio::test]
async fn wizard_completes_when_config_write_fails() {
    // A path whose parent directory does not exist: fs::write returns
    // NotFound. The wizard must NOT 500 — setup is best-effort on the
    // config side.
    let target = wizard_scratch_config("wizard-fail")
        .parent()
        .unwrap()
        .join("missing-dir")
        .join("config.toml");
    let _ = std::fs::remove_file(&target);
    let db = test_db();
    let router = test_router_with_path(db.clone(), Config::default(), target.clone());

    let resp = router
        .oneshot(setup_post("supersecretpass123"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "setup must complete even when the config write fails"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok());
    assert_eq!(
        loc,
        Some("/?setup=complete&config=skipped"),
        "redirect must surface the config-write skip so operators see it"
    );
    assert_eq!(
        db::count_users(&db).unwrap(),
        1,
        "admin was still created in the active store on best-effort failure"
    );
}
