//! Integration tests for the admin auth-provider API:
//! GET/POST `/api/auth/providers`, `/{id}`,
//! `/{id}/enable|disable|move|config|test`, DELETE.
//!
//! Schema setup mirrors `tests/api_handler_tests.rs`: in-memory SQLite via
//! `db::init_db`, then `providers_db::migrate` creates the `auth_providers`
//! table (the app applies it the same way from `init_db`).

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::{self, Db};
use persea::providers_db;
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    let db = db::init_db(std::path::Path::new(":memory:")).expect("test db");
    providers_db::migrate(&db).expect("auth_providers migration");
    db
}

fn test_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/auth/providers",
            get(persea::api::providers::list_providers)
                .post(persea::api::providers::create_provider),
        )
        .route(
            "/api/auth/providers/{id}",
            get(persea::api::providers::get_provider)
                .delete(persea::api::providers::delete_provider),
        )
        .route(
            "/api/auth/providers/{id}/enable",
            post(persea::api::providers::enable_provider),
        )
        .route(
            "/api/auth/providers/{id}/disable",
            post(persea::api::providers::disable_provider),
        )
        .route(
            "/api/auth/providers/{id}/move",
            post(persea::api::providers::move_provider),
        )
        .route(
            "/api/auth/providers/{id}/config",
            get(persea::api::providers::get_provider_config),
        )
        .route(
            "/api/auth/providers/{id}/test",
            post(persea::api::providers::test_provider),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn admin_req(method: &str, key: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr())
        .body(Body::empty())
        .unwrap()
}

fn admin_json(key: &str, path: &str, body: Value) -> Request<Body> {
    let mut req = admin_req("POST", key, path);
    *req.body_mut() = Body::from(serde_json::to_vec(&body).unwrap());
    req
}

fn no_auth_req(path: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .extension(fake_addr())
        .body(Body::empty())
        .unwrap()
}

fn viewer_session_req(method: &str, path: &str, session: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, format!("persea_session={}", session))
        .extension(fake_addr())
        .body(Body::empty())
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn oidc_config() -> Value {
    json!({
        "issuer_url": "https://auth.example.com",
        "client_id": "persea",
        "client_secret": "supersecret",
        "redirect_uri": "https://persea.example.com/auth/callback",
        "groups_claim": "groups"
    })
}

// ── Authz ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_providers_requires_auth() {
    let app = test_router(test_db());
    let response = app
        .oneshot(no_auth_req("/api/auth/providers"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_providers_requires_admin() {
    let db = test_db();
    db::upsert_user(&db, "viewer@test.com", "Viewer", None, "viewer", &[]).unwrap();
    let user = db::get_user_by_email(&db, "viewer@test.com").unwrap();
    let session = db::create_auth_session(&db, user.id, 3600).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(viewer_session_req("GET", "/api/auth/providers", &session))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── List / create ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_providers_empty() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_req("GET", &key, "/api/auth/providers"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["providers"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_create_oidc_provider_success() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "Authentik", "type": "oidc", "config": oidc_config()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = body_json(response).await;
    assert_eq!(body["name"].as_str().unwrap(), "Authentik");
    assert_eq!(body["type"].as_str().unwrap(), "oidc");
    assert_eq!(body["enabled"].as_bool().unwrap(), true);
    assert_eq!(body["position"].as_i64().unwrap(), 0);
    assert_eq!(
        body["config"]["client_secret"].as_str().unwrap(),
        "\u{2022}\u{2022}\u{2022}configured\u{2022}\u{2022}\u{2022}"
    );
}

#[tokio::test]
async fn test_create_provider_missing_issuer_url_rejected() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({
                "name": "Broken OIDC",
                "type": "oidc",
                "config": {"client_id": "x", "client_secret": "y", "redirect_uri": "https://x/cb"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = body_json(response).await;
    assert!(body["error"].as_str().unwrap().contains("issuer_url"));
}

#[tokio::test]
async fn test_create_provider_unknown_type_rejected() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "FIDO", "type": "fido", "config": {}}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_provider_empty_name_rejected() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "  ", "type": "database", "config": {}}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_create_ldap_provider_with_required_fields() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({
                "name": "AD",
                "type": "ldap",
                "config": {"url": "ldap://ldap.example.com:389", "bind_dn": "cn=admin,dc=example,dc=com", "search_base": "ou=users,dc=example,dc=com"}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
}

// ── Get / config round-trip ────────────────────────────────────────────────

#[tokio::test]
async fn test_oidc_config_round_trips_through_api() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db.clone());
    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "Keycloak", "type": "oidc", "config": oidc_config()}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let id = created["id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/auth/providers/{}", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let row = body_json(response).await;
    assert_eq!(row["name"].as_str().unwrap(), "Keycloak");
    assert_eq!(row["type"].as_str().unwrap(), "oidc");
    assert_eq!(
        row["config"]["issuer_url"].as_str().unwrap(),
        "https://auth.example.com"
    );
    assert_eq!(
        row["config"]["client_secret"].as_str().unwrap(),
        "\u{2022}\u{2022}\u{2022}configured\u{2022}\u{2022}\u{2022}"
    );
    assert_eq!(row["config"]["groups_claim"].as_str().unwrap(), "groups");

    let response = app
        .clone()
        .oneshot(admin_req(
            "GET",
            &key,
            &format!("/api/auth/providers/{}/config", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let cfg = body_json(response).await;
    // Secrets are masked in API responses.
    let mut expected = oidc_config();
    expected["client_secret"] = json!("\u{2022}\u{2022}\u{2022}configured\u{2022}\u{2022}\u{2022}");
    assert_eq!(cfg, expected);
}

#[tokio::test]
async fn test_get_provider_not_found() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_req("GET", &key, "/api/auth/providers/999"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Enable / disable ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_disable_and_enable_provider() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db.clone());
    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "Google", "type": "oidc", "config": oidc_config()}),
        ))
        .await
        .unwrap();
    let id = body_json(response).await["id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/auth/providers/{}/disable", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !providers_db::get_provider(&db, id)
            .unwrap()
            .unwrap()
            .enabled
    );

    let response = app
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/auth/providers/{}/enable", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        providers_db::get_provider(&db, id)
            .unwrap()
            .unwrap()
            .enabled
    );
}

#[tokio::test]
async fn test_enable_unknown_provider_returns_404() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_req("POST", &key, "/api/auth/providers/999/enable"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Move ───────────────────────────────────────────────────────────────────

/// Create three providers (A=oidc, B=ldap, C=database); returns their ids.
async fn seed_three(app: &Router, key: &str) -> (i64, i64, i64) {
    let mut ids = Vec::new();
    for (name, ptype, config) in [
        ("A", "oidc", oidc_config()),
        (
            "B",
            "ldap",
            json!({"url": "ldap://x", "bind_dn": "cn=x", "search_base": "ou=x"}),
        ),
        ("C", "database", json!({})),
    ] {
        let response = app
            .clone()
            .oneshot(admin_json(
                key,
                "/api/auth/providers",
                json!({"name": name, "type": ptype, "config": config}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        ids.push(body_json(response).await["id"].as_i64().unwrap());
    }
    (ids[0], ids[1], ids[2])
}

async fn list_names(app: &Router, key: &str) -> Vec<String> {
    let response = app
        .clone()
        .oneshot(admin_req("GET", key, "/api/auth/providers"))
        .await
        .unwrap();
    let body = body_json(response).await;
    body["providers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn test_move_provider_down() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let (a, _b, _c) = seed_three(&app, &key).await;

    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            &format!("/api/auth/providers/{}/move", a),
            json!({"direction": "down"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(list_names(&app, &key).await, vec!["B", "A", "C"]);
}

#[tokio::test]
async fn test_move_provider_up() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let (_a, b, _c) = seed_three(&app, &key).await;

    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            &format!("/api/auth/providers/{}/move", b),
            json!({"direction": "up"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(list_names(&app, &key).await, vec!["B", "A", "C"]);
}

#[tokio::test]
async fn test_move_provider_edges_are_noops() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let (a, _b, c) = seed_three(&app, &key).await;

    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            &format!("/api/auth/providers/{}/move", a),
            json!({"direction": "up"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(list_names(&app, &key).await, vec!["A", "B", "C"]);

    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            &format!("/api/auth/providers/{}/move", c),
            json!({"direction": "down"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(list_names(&app, &key).await, vec!["A", "B", "C"]);
}

#[tokio::test]
async fn test_move_provider_bad_direction_rejected() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let (a, _, _) = seed_three(&app, &key).await;

    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            &format!("/api/auth/providers/{}/move", a),
            json!({"direction": "sideways"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_move_provider_not_found() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_json(
            &key,
            "/api/auth/providers/999/move",
            json!({"direction": "up"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Delete ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_delete_provider() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db.clone());
    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "Temp", "type": "database", "config": {}}),
        ))
        .await
        .unwrap();
    let id = body_json(response).await["id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(admin_req(
            "DELETE",
            &key,
            &format!("/api/auth/providers/{}", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(providers_db::get_provider(&db, id).unwrap().is_none());

    let response = app
        .clone()
        .oneshot(admin_req("GET", &key, "/api/auth/providers"))
        .await
        .unwrap();
    let body = body_json(response).await;
    assert_eq!(body["providers"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_delete_provider_not_found() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_req("DELETE", &key, "/api/auth/providers/999"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── Test connection ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_provider_test_unsupported_type() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .clone()
        .oneshot(admin_json(
            &key,
            "/api/auth/providers",
            json!({"name": "Local", "type": "database", "config": {}}),
        ))
        .await
        .unwrap();
    let id = body_json(response).await["id"].as_i64().unwrap();

    let response = app
        .clone()
        .oneshot(admin_req(
            "POST",
            &key,
            &format!("/api/auth/providers/{}/test", id),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["ok"].as_bool().unwrap(), false);
    assert!(body["detail"].as_str().unwrap().contains("not supported"));
}

#[tokio::test]
async fn test_provider_test_not_found() {
    let db = test_db();
    let key = db::add_admin(&db, "admin", None, None).unwrap();
    let app = test_router(db);
    let response = app
        .oneshot(admin_req("POST", &key, "/api/auth/providers/999/test"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
