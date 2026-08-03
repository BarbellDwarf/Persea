//! API handler integration tests using axum test utilities with in-memory SQLite DB.

use super::{CredentialDefaultScope, DriveConfigured, OidcEnabled, SiteTitle, VaultConfigured, VaultState, VaultBackends, VaultCell};
use crate::db::{self, Db};
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Extension;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).expect("Failed to create test DB")
}

fn insert_test_admin(db: &Db, name: &str) -> String {
    let key = format!("test-key-{}", name);
    let key_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    };
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO admins (name, api_key_hash) VALUES (?1, ?2)",
        rusqlite::params![name, key_hash],
    )
    .unwrap();
    key
}

fn insert_test_user(db: &Db, email: &str, name: &str, role: &str) {
    let conn = db.lock().unwrap();
    let _ = conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT", []);
    let _ = conn.execute("ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'", []);
    let _ = conn.execute("ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''", []);
    conn.execute(
        "INSERT INTO users (email, name, role, disabled, created_at) VALUES (?1, ?2, ?3, 0, datetime('now'))",
        rusqlite::params![email, name, role],
    )
    .unwrap();
}

fn test_vault_state() -> VaultState {
    let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(None));
    Arc::new(VaultBackends {
        default: cell.clone(),
        shared: cell.clone(),
        local: cell,
    })
}

fn test_addr() -> SocketAddr {
    "127.0.0.1:3000".parse().unwrap()
}

fn build_test_router(db: Db) -> axum::Router {
    use axum::routing::{delete, get, post, put};

    let api_routes = axum::Router::new()
        .route("/api/users", get(super::users::list_users))
        .route("/api/users/{email}/role", put(super::users::set_user_role))
        .route("/api/users/{email}", delete(super::users::delete_user))
        .route("/api/users/{email}/disable", post(super::users::disable_user))
        .route("/api/users/{email}/enable", post(super::users::enable_user))
        .route("/api/me/tokens", get(super::tokens::list_my_tokens))
        .route("/api/me/tokens", post(super::tokens::create_my_token))
        .route("/api/me/tokens/{id}", delete(super::tokens::revoke_my_token))
        .route("/api/admin/user-tokens", get(super::tokens::admin_list_user_tokens))
        .route("/api/admin/user-tokens", post(super::tokens::admin_create_user_token))
        .route("/api/admin/user-tokens/{id}", delete(super::tokens::admin_revoke_user_token))
        .with_state(());

    let vault = test_vault_state();
    api_routes
        .layer(axum::middleware::from_fn(crate::auth::require_auth))
        .layer(Extension(db))
        .layer(Extension(vault))
        .layer(Extension(VaultConfigured(false)))
        .layer(Extension(OidcEnabled(false)))
        .layer(Extension(DriveConfigured(false)))
        .layer(Extension(CredentialDefaultScope("local".into())))
        .layer(Extension(SiteTitle("Test".into())))
}

fn make_request(method: &str, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    req
}

fn make_auth_request(method: &str, uri: &str, key: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", key))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    req
}

fn make_json_request(method: &str, uri: &str, key: &str, body: Value) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {}", key))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    req
}

#[tokio::test]
async fn test_no_auth_returns_401() {
    let db = test_db();
    let app = build_test_router(db);
    let response = app.oneshot(make_request("GET", "/api/users")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_api_key_returns_401() {
    let db = test_db();
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/users", "invalid-key-12345")).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_valid_api_key_succeeds() {
    let db = test_db();
    let _key = insert_test_admin(&db, "testadmin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/users", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_x_api_key_header_works() {
    let db = test_db();
    let _key = insert_test_admin(&db, "xapikey");
    let app = build_test_router(db);
    let mut req = Request::builder()
        .uri("/api/users")
        .header("x-api-key", &_key)
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_list_users_empty() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/users", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert!(body.is_array());
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_list_users_returns_seeded() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "alice@test.com", "Alice", "viewer");
    insert_test_user(&db, "bob@test.com", "Bob", "operator");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/users", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let users = body.as_array().unwrap();
    assert_eq!(users.len(), 2);
    let emails: Vec<&str> = users.iter().map(|u| u["email"].as_str().unwrap()).collect();
    assert!(emails.contains(&"alice@test.com"));
    assert!(emails.contains(&"bob@test.com"));
}

#[tokio::test]
async fn test_delete_user_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "delete@test.com", "Delete Me", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("DELETE", "/api/users/delete@test.com", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("DELETE", "/api/users/nobody@test.com", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_role_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "role@test.com", "Role User", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("PUT", "/api/users/role@test.com/role", &_key, json!({"role": "operator"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_set_role_invalid() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "role@test.com", "Role User", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("PUT", "/api/users/role@test.com/role", &_key, json!({"role": "superadmin"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_set_role_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("PUT", "/api/users/nobody@test.com/role", &_key, json!({"role": "viewer"}))).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_disable_user_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "disable@test.com", "Disable Me", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("POST", "/api/users/disable@test.com/disable", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_disable_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("POST", "/api/users/nobody@test.com/disable", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_enable_user_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "enable@test.com", "Enable Me", "viewer");
    {
        let conn = db.lock().unwrap();
        conn.execute("UPDATE users SET disabled = 1 WHERE email = 'enable@test.com'", []).unwrap();
    }
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("POST", "/api/users/enable@test.com/enable", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_enable_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("POST", "/api/users/nobody@test.com/enable", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_list_tokens_empty() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/admin/user-tokens", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert!(body.is_array());
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_admin_create_token_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "token@test.com", "Token User", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("POST", "/api/admin/user-tokens", &_key,
        json!({"email": "token@test.com", "name": "my-test-token", "max_role": "viewer"})
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["name"].as_str().unwrap(), "my-test-token");
    assert!(body["token"].as_str().unwrap().starts_with("rgu_"));
}

#[tokio::test]
async fn test_admin_create_token_empty_name() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "token@test.com", "Token User", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("POST", "/api/admin/user-tokens", &_key,
        json!({"email": "token@test.com", "name": ""})
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_admin_create_token_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("POST", "/api/admin/user-tokens", &_key,
        json!({"email": "nobody@test.com", "name": "tok"})
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_create_token_invalid_role() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "token@test.com", "Token User", "viewer");
    let app = build_test_router(db);
    let response = app.oneshot(make_json_request("POST", "/api/admin/user-tokens", &_key,
        json!({"email": "token@test.com", "name": "bad-role", "max_role": "superadmin"})
    )).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_admin_revoke_token_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "revoke@test.com", "Revoke User", "viewer");
    let user = db::get_user_by_email(&db, "revoke@test.com").unwrap();
    let (token_id, _) = db::create_user_token(&db, user.id, "revoke-me", None, None).unwrap();
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("DELETE", &format!("/api/admin/user-tokens/{}", token_id), &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_admin_revoke_token_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("DELETE", "/api/admin/user-tokens/99999", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_viewer_token_cannot_list_users() {
    let db = test_db();
    insert_test_user(&db, "viewer@test.com", "Viewer", "viewer");
    let user = db::get_user_by_email(&db, "viewer@test.com").unwrap();
    let (_, plaintext) = db::create_user_token(&db, user.id, "viewer-token", None, None).unwrap();
    let app = build_test_router(db);
    let response = app.oneshot(make_auth_request("GET", "/api/users", &plaintext)).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_me_returns_identity() {
    let db = test_db();
    let _key = insert_test_admin(&db, "meadmin");
    use axum::routing::get as route_get;
    let app = axum::Router::new()
        .route("/api/me", route_get(super::users::me))
        .layer(axum::middleware::from_fn(crate::auth::require_auth))
        .layer(Extension(db))
        .layer(Extension(test_vault_state()))
        .layer(Extension(VaultConfigured(false)))
        .layer(Extension(OidcEnabled(false)))
        .layer(Extension(DriveConfigured(false)))
        .layer(Extension(CredentialDefaultScope("local".into())))
        .layer(Extension(SiteTitle("Test".into())));
    let response = app.oneshot(make_auth_request("GET", "/api/me", &_key)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(body["name"].as_str().unwrap(), "meadmin");
    assert_eq!(body["role"].as_str().unwrap(), "admin");
}
