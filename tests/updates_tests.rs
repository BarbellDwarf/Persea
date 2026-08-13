//! Integration tests for the server version update alert
//! (wayfinder/v1.2.0/S16): the check task's fetch/parse/compare pipeline,
//! the `GET /api/auth/status` extension, and the admin banner gating.

use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use persea::api::{DriveConfigured, OidcEnabled, SiteTitle, ThemeData};
use persea::config::UpdatesConfig;
use persea::templates::AppLayoutTemplate;
use persea::updates::{self, UpdateInfo, UpdateState};
use serde_json::Value;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::ServiceExt;

fn test_router(update_state: Option<UpdateState>) -> Router {
    let router = Router::new()
        .route("/api/auth/status", get(persea::api::admin::auth_status))
        .layer(Extension(OidcEnabled(false)))
        .layer(Extension(SiteTitle("Persea".into())))
        .layer(Extension(DriveConfigured(false)))
        .layer(Extension(ThemeData {
            admin_preset: "dark".into(),
            admin_colors: persea::config::builtin_presets()
                .first()
                .map(|(_, c)| c.clone())
                .expect("builtin presets exist"),
            logo_url: None,
            presets: HashMap::new(),
        }));
    match update_state {
        Some(st) => router.layer(Extension(st)),
        None => router,
    }
}

/// A state with a cached check result, as the background task would store it.
fn state_with(latest: Option<&str>) -> UpdateState {
    let st = UpdateState::new();
    *st.info.write().unwrap() = UpdateInfo {
        latest_version: latest.map(|v| v.to_string()),
        checked_at: Some("2026-08-13T00:00:00Z".to_string()),
        error: None,
    };
    st
}

async fn get_status(router: &Router) -> (StatusCode, Value) {
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/auth/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

// ── Endpoint shape ────────────────────────────────────────────────────────

#[tokio::test]
async fn endpoint_without_update_state_returns_null_and_false() {
    let router = test_router(None);
    let (status, body) = get_status(&router).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["latest_version"].is_null());
    assert_eq!(body["update_available"], false);
}

#[tokio::test]
async fn endpoint_with_never_checked_state_returns_null_and_false() {
    let router = test_router(Some(UpdateState::new()));
    let (_, body) = get_status(&router).await;
    assert!(body["latest_version"].is_null());
    assert_eq!(body["update_available"], false);
}

#[tokio::test]
async fn endpoint_with_failed_check_returns_null_and_false() {
    let st = UpdateState::new();
    st.info.write().unwrap().error = Some("release check failed: connection failed".into());
    let router = test_router(Some(st));
    let (_, body) = get_status(&router).await;
    assert!(body["latest_version"].is_null());
    assert_eq!(body["update_available"], false);
}

#[tokio::test]
async fn endpoint_with_newer_stable_returns_true_and_version() {
    let router = test_router(Some(state_with(Some("99.0.0"))));
    let (_, body) = get_status(&router).await;
    assert_eq!(body["latest_version"], "99.0.0");
    assert_eq!(body["update_available"], true);
}

#[tokio::test]
async fn endpoint_with_equal_version_returns_false() {
    let router = test_router(Some(state_with(Some(env!("CARGO_PKG_VERSION")))));
    let (_, body) = get_status(&router).await;
    assert_eq!(body["latest_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(body["update_available"], false);
}

#[tokio::test]
async fn endpoint_with_only_pre_release_newer_returns_false() {
    let router = test_router(Some(state_with(Some("99.0.0-beta.1"))));
    let (_, body) = get_status(&router).await;
    assert_eq!(body["latest_version"], "99.0.0-beta.1");
    assert_eq!(body["update_available"], false);
}

#[tokio::test]
async fn endpoint_existing_fields_stay_intact() {
    let router = test_router(Some(state_with(Some("99.0.0"))));
    let (_, body) = get_status(&router).await;
    assert_eq!(body["oidc_enabled"], false);
    assert_eq!(body["site_title"], "Persea");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
    let caps = body["capabilities"].as_object().unwrap();
    assert!(caps.contains_key("drive_api"));
    assert!(caps.contains_key("desktop_bridge"));
    assert!(caps.contains_key("session_events"));
}

// ── Check pipeline against a local stub (internal-mirror check_url) ───────

/// Serve one canned HTTP response on a random loopback port, returning the
/// URL (a non-default check_url, standing in for an internal mirror).
async fn spawn_stub(status: u16, body: &'static str) -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await;
            let reason = match status {
                200 => "OK",
                404 => "Not Found",
                500 => "Internal Server Error",
                _ => "X",
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(format!("{head}{body}").as_bytes()).await;
        }
    });
    (url, handle)
}

async fn check_url(url: &str) -> Result<String, updates::UpdateCheckError> {
    updates::check_for_update(&updates::build_client().unwrap(), url).await
}

#[tokio::test]
async fn fetch_parses_mocked_github_payload() {
    let (url, stub) = spawn_stub(200, r#"{"tag_name":"v1.2.3","name":"1.2.3"}"#).await;
    let result = check_url(&url).await;
    stub.await.unwrap();
    assert_eq!(result.unwrap(), "1.2.3");
}

#[tokio::test]
async fn fetch_accepts_tag_without_v_prefix() {
    let (url, stub) = spawn_stub(200, r#"{"tag_name":"1.2.3"}"#).await;
    let result = check_url(&url).await;
    stub.await.unwrap();
    assert_eq!(result.unwrap(), "1.2.3");
}

#[tokio::test]
async fn fetch_non_success_status_is_an_error() {
    let (url, stub) = spawn_stub(404, "{}").await;
    let result = check_url(&url).await;
    stub.await.unwrap();
    match result {
        Err(updates::UpdateCheckError::HttpStatus(404)) => {}
        other => panic!("expected HttpStatus(404), got {other:?}"),
    }
}

#[tokio::test]
async fn fetch_garbage_body_is_a_parse_error() {
    let (url, stub) = spawn_stub(200, "this is not json").await;
    let result = check_url(&url).await;
    stub.await.unwrap();
    assert!(matches!(result, Err(updates::UpdateCheckError::Parse(_))));
}

#[tokio::test]
async fn fetch_refused_connection_never_leaks_the_url() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/releases/latest", listener.local_addr().unwrap());
    drop(listener); // port is now closed → connection refused
    let err = check_url(&url).await.unwrap_err();
    let msg = err.to_string();
    assert!(
        !msg.contains("http"),
        "error message must not contain the check URL: {msg}"
    );
}

// ── Air-gap ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn disabled_checker_spawns_no_task_and_caches_nothing() {
    let cfg = UpdatesConfig {
        enabled: false,
        ..UpdatesConfig::default()
    };
    let state = updates::spawn_update_checker(cfg);
    let info = state.info.read().unwrap();
    assert!(info.latest_version.is_none());
    assert!(info.checked_at.is_none());
    assert!(info.error.is_none());
}

// ── Admin banner gating ───────────────────────────────────────────────────

async fn render_app_layout(is_admin: bool) -> String {
    let tmpl = AppLayoutTemplate {
        site_title: "Persea".into(),
        logo_url: String::new(),
        is_admin,
        active_page: "connections".into(),
        csp_nonce: "test-nonce".into(),
    };
    let resp = tmpl.render_page("pages/connections.html");
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn admin_layout_renders_the_banner_markup() {
    let html = render_app_layout(true).await;
    assert!(html.contains("id=\"update-banner\""));
    assert!(html.contains("id=\"update-banner-dismiss\""));
    assert!(html.contains("persea_update_dismissed_"));
}

#[tokio::test]
async fn non_admin_layout_never_renders_the_banner() {
    let html = render_app_layout(false).await;
    assert!(!html.contains("id=\"update-banner\""));
}
