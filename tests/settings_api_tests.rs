//! Integration tests for the admin system settings API.
//!
//! The handlers live in `src/api/settings.rs`. That module is declared in
//! `src/api/mod.rs` by the route-wiring orchestrator step, so this test file
//! includes the file directly (via `#[path]`) with crate-root shims for the
//! `crate::` paths it uses — keeping these tests compilable and runnable
//! independently of that wiring.

mod auth {
    pub use persea::auth::*;
}
mod db {
    pub use persea::db::*;
}
mod db_pool {
    pub use persea::db_pool::*;
}
mod error {
    pub use persea::error::*;
}
mod api {
    pub use persea::api::{AppState, SettingsBaseline};
}

#[path = "../src/api/settings.rs"]
mod settings;

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

/// Mirrors the real route wiring: `require_auth` middleware + extensions.
fn test_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/system/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

/// No auth middleware — lets requests reach the handlers with no identity so
/// the handlers' own admin role check can be exercised (403).
fn bare_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/system/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn admin_get(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn admin_put(key: &str, path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr())
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

fn no_auth_put(path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

fn no_auth_get(path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── GET defaults ──

#[tokio::test]
async fn get_settings_returns_defaults_when_empty() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;

    assert_eq!(json["listen_addr"].as_str().unwrap(), "0.0.0.0:8089");
    assert_eq!(json["guacd_addr"].as_str().unwrap(), "127.0.0.1:4822");
    assert_eq!(json["tls_cert_path"].as_str().unwrap(), "");
    assert_eq!(json["tls_key_path"].as_str().unwrap(), "");
    assert_eq!(json["session_max_duration_secs"].as_u64(), Some(28800));
    assert_eq!(json["max_concurrent_sessions"].as_u64(), Some(500));
    assert_eq!(json["session_history_retention_days"].as_u64(), Some(90));
    assert_eq!(json["enable_vdi"].as_bool(), Some(true));
    assert_eq!(json["vault_enabled"].as_bool(), Some(false));
    assert_eq!(json["db_only_mode"].as_bool(), Some(true));
}

// ── PUT + GET round trip ──

#[tokio::test]
async fn put_persists_and_get_returns_saved_values() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());

    let body = serde_json::json!({
        "listen_addr": "0.0.0.0:9999",
        "guacd_addr": "10.0.0.5:4822",
        "tls_cert_path": "/etc/persea/tls.crt",
        "tls_key_path": "/etc/persea/tls.key",
        "session_max_duration_secs": 7200,
        "max_concurrent_sessions": 25,
        "session_history_retention_days": 30,
        "enable_vdi": false,
        "vault_enabled": true,
        "db_only_mode": false
    });
    let resp = router
        .oneshot(admin_put(&key, "/api/system/settings", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let saved = body_json(resp).await;
    assert_eq!(saved["listen_addr"].as_str().unwrap(), "0.0.0.0:9999");
    assert_eq!(saved["guacd_addr"].as_str().unwrap(), "10.0.0.5:4822");
    assert_eq!(saved["session_max_duration_secs"].as_u64(), Some(7200));
    assert_eq!(saved["max_concurrent_sessions"].as_u64(), Some(25));
    assert_eq!(saved["enable_vdi"].as_bool(), Some(false));
    assert_eq!(saved["vault_enabled"].as_bool(), Some(true));

    // The stored values must survive a fresh read.
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["listen_addr"].as_str().unwrap(), "0.0.0.0:9999");
    assert_eq!(json["guacd_addr"].as_str().unwrap(), "10.0.0.5:4822");
    assert_eq!(
        json["tls_cert_path"].as_str().unwrap(),
        "/etc/persea/tls.crt"
    );
    assert_eq!(
        json["tls_key_path"].as_str().unwrap(),
        "/etc/persea/tls.key"
    );
    assert_eq!(json["session_max_duration_secs"].as_u64(), Some(7200));
    assert_eq!(json["max_concurrent_sessions"].as_u64(), Some(25));
    assert_eq!(json["session_history_retention_days"].as_u64(), Some(30));
    assert_eq!(json["enable_vdi"].as_bool(), Some(false));
    assert_eq!(json["vault_enabled"].as_bool(), Some(true));
    assert_eq!(json["db_only_mode"].as_bool(), Some(false));
}

#[tokio::test]
async fn put_accepts_array_values_from_duplicate_form_names() {
    // The settings form's checkbox+hidden pairs historically shared a name;
    // htmx's json-enc serializes duplicate names as arrays. The last entry
    // must win so the UI can save booleans and enum settings.
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());

    let body = serde_json::json!({
        "db_only_mode": ["false", "false"],
        "enable_rdp": ["true", "true"],
    });
    let resp = router
        .oneshot(admin_put(&key, "/api/system/settings", body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let saved = body_json(resp).await;
    assert_eq!(saved["db_only_mode"].as_bool(), Some(false));
    assert_eq!(saved["enable_rdp"].as_bool(), Some(true));
}

#[tokio::test]
async fn put_partial_object_only_updates_given_keys() {
    let db = test_db();
    let key = create_admin(&db, "admin");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"listen_addr": "0.0.0.0:7777"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["listen_addr"].as_str().unwrap(), "0.0.0.0:7777");
    // Untouched keys keep their defaults.
    assert_eq!(json["session_max_duration_secs"].as_u64(), Some(28800));
    assert_eq!(json["enable_vdi"].as_bool(), Some(true));
}

// ── PUT validation ──

#[tokio::test]
async fn put_rejects_invalid_listen_addr() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"listen_addr": "not-an-address"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let json = body_json(resp).await;
    assert_eq!(json["error_code"].as_str().unwrap(), "VALIDATION_ERROR");

    // Nothing was persisted.
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["listen_addr"].as_str().unwrap(), "0.0.0.0:8089");
}

#[tokio::test]
async fn put_rejects_non_positive_duration() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"session_max_duration_secs": 0}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn put_rejects_non_boolean_flag() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"enable_vdi": "yes"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Admin enforcement ──

#[tokio::test]
async fn put_requires_admin_identity() {
    let db = test_db();
    let router = bare_router(db);
    let resp = router
        .oneshot(no_auth_put(
            "/api/system/settings",
            serde_json::json!({"listen_addr": "0.0.0.0:7777"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error_code"].as_str().unwrap(), "FORBIDDEN");
}

#[tokio::test]
async fn get_requires_admin_identity() {
    let db = test_db();
    let router = bare_router(db);
    let resp = router
        .oneshot(no_auth_get("/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
