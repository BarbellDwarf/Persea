//! Integration tests for the anonymous `GET /api/auth/status` endpoint:
//! the version string and the desktop-shell capabilities probe (S05).

use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::{Extension, Router};
use persea::api::admin::{
    COMPILED_DESKTOP_BRIDGE, COMPILED_DESKTOP_PAIRING, COMPILED_DRIVE_UPLOAD,
    COMPILED_SESSION_EVENTS,
};
use persea::api::{DriveConfigured, OidcEnabled, SiteTitle, ThemeData};
use persea::config::builtin_presets;
use persea::db::{self, Db};
use serde_json::Value;
use std::collections::HashMap;
use tower::ServiceExt;

const CAPABILITY_KEYS: &[&str] = &[
    "drive_api",
    "drive_upload",
    "session_events",
    "desktop_pairing",
    "desktop_bridge",
    "kiosk_allowed",
    "desktop_transfers",
];

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn test_router(db: Option<Db>) -> Router {
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
            logo_url: Some("/uploads/logo/logo.png".into()),
            presets: HashMap::new(),
        }));
    match db {
        Some(db) => router.layer(Extension(db)),
        None => router,
    }
}

/// Store a `desktop_*` admin toggle exactly as the settings API would.
fn set_setting(db: &Db, key: &str, value: &str) {
    let conn = db.lock().unwrap();
    conn.execute(
        "CREATE TABLE IF NOT EXISTS system_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO system_settings (key, value, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        rusqlite::params![key, value],
    )
    .unwrap();
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

#[tokio::test]
async fn anonymous_request_returns_200_with_version_and_capabilities() {
    let router = test_router(Some(test_db()));
    let (status, body) = get_status(&router).await;
    assert_eq!(status, StatusCode::OK);

    let version = body["version"].as_str().unwrap();
    let parts: Vec<&str> = version.split('.').collect();
    assert_eq!(parts.len(), 3, "version {version:?} must be x.y.z");
    assert!(
        parts.iter().all(|p| p.parse::<u32>().is_ok()),
        "version {version:?} must be numeric x.y.z with no git hash"
    );

    let caps = body["capabilities"].as_object().unwrap();
    assert_eq!(caps.len(), CAPABILITY_KEYS.len());
    for key in CAPABILITY_KEYS {
        assert!(
            caps.get(*key).and_then(Value::as_bool).is_some(),
            "capabilities.{key} must be a bool"
        );
    }
    assert_eq!(caps["drive_api"], true);
}

#[tokio::test]
async fn compiled_capabilities_match_the_compile_flags() {
    let router = test_router(Some(test_db()));
    let (_, body) = get_status(&router).await;
    let caps = &body["capabilities"];
    assert_eq!(caps["drive_upload"], COMPILED_DRIVE_UPLOAD);
    assert_eq!(caps["session_events"], COMPILED_SESSION_EVENTS);
    assert_eq!(caps["desktop_bridge"], COMPILED_DESKTOP_BRIDGE);
    assert_eq!(caps["desktop_pairing"], COMPILED_DESKTOP_PAIRING);
}

#[tokio::test]
async fn existing_fields_are_unchanged() {
    let router = test_router(Some(test_db()));
    let (_, body) = get_status(&router).await;
    assert_eq!(body["oidc_enabled"], false);
    assert_eq!(body["site_title"], "Persea");
    assert_eq!(body["drive_configured"], false);
    assert_eq!(body["theme"]["admin_preset"], "dark");
    assert_eq!(body["theme"]["logo_url"], "/uploads/logo/logo.png");
    assert_eq!(body["theme"]["presets"], serde_json::json!({}));
}

#[tokio::test]
async fn admin_gated_capabilities_default_on_when_settings_absent() {
    let router = test_router(Some(test_db()));
    let (_, body) = get_status(&router).await;
    let caps = &body["capabilities"];
    assert_eq!(caps["kiosk_allowed"], true);
    assert_eq!(caps["desktop_transfers"], true);
    assert_eq!(caps["desktop_pairing"], COMPILED_DESKTOP_PAIRING);
}

#[tokio::test]
async fn admin_gated_capabilities_default_on_without_any_db() {
    let router = test_router(None);
    let (status, body) = get_status(&router).await;
    assert_eq!(status, StatusCode::OK);
    let caps = &body["capabilities"];
    assert_eq!(caps["kiosk_allowed"], true);
    assert_eq!(caps["desktop_transfers"], true);
    assert_eq!(caps["desktop_pairing"], COMPILED_DESKTOP_PAIRING);
}

#[tokio::test]
async fn stored_false_toggle_wins_over_compiled_flag() {
    let db = test_db();
    set_setting(&db, "desktop_kiosk", "false");
    set_setting(&db, "desktop_transfers", "false");
    set_setting(&db, "desktop_pairing", "false");
    let router = test_router(Some(db));
    let (_, body) = get_status(&router).await;
    let caps = &body["capabilities"];
    assert_eq!(caps["kiosk_allowed"], false);
    assert_eq!(caps["desktop_transfers"], false);
    assert_eq!(
        caps["desktop_pairing"], false,
        "the S09 toggle off must win over the compiled flag"
    );
}

#[tokio::test]
async fn stored_true_toggles_report_the_compiled_state() {
    let db = test_db();
    set_setting(&db, "desktop_kiosk", "true");
    set_setting(&db, "desktop_transfers", "true");
    set_setting(&db, "desktop_pairing", "true");
    let router = test_router(Some(db));
    let (_, body) = get_status(&router).await;
    let caps = &body["capabilities"];
    assert_eq!(caps["kiosk_allowed"], true);
    assert_eq!(caps["desktop_transfers"], true);
    assert_eq!(caps["desktop_pairing"], COMPILED_DESKTOP_PAIRING);
}

#[tokio::test]
async fn mixed_toggles_resolve_independently() {
    let db = test_db();
    set_setting(&db, "desktop_kiosk", "false");
    set_setting(&db, "desktop_transfers", "true");
    let router = test_router(Some(db));
    let (_, body) = get_status(&router).await;
    let caps = &body["capabilities"];
    assert_eq!(caps["kiosk_allowed"], false);
    assert_eq!(caps["desktop_transfers"], true);
    assert_eq!(caps["desktop_pairing"], COMPILED_DESKTOP_PAIRING);
}
