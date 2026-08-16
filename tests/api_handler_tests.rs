//! Integration tests for API handlers.
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::{self, Db};
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn test_router(db: Db) -> Router {
    Router::new()
        .route("/api/users", get(persea::api::users::list_users))
        .route(
            "/api/users/{email}/role",
            put(persea::api::users::set_user_role),
        )
        .route(
            "/api/users/{email}",
            delete(persea::api::users::delete_user),
        )
        .route(
            "/api/users/{email}/disable",
            post(persea::api::users::disable_user),
        )
        .route(
            "/api/users/{email}/enable",
            post(persea::api::users::enable_user),
        )
        .route("/api/me/tokens", get(persea::api::tokens::list_my_tokens))
        .route("/api/me/tokens", post(persea::api::tokens::create_my_token))
        .route(
            "/api/me/tokens/{id}",
            delete(persea::api::tokens::revoke_my_token),
        )
        .route(
            "/api/admin/users/{email}/tokens",
            get(persea::api::tokens::admin_list_user_tokens),
        )
        .route(
            "/api/admin/user-tokens",
            post(persea::api::tokens::admin_create_user_token),
        )
        .route(
            "/api/admin/user-tokens/{id}",
            delete(persea::api::tokens::admin_revoke_user_token),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn create_user(db: &Db, email: &str, name: &str, role: &str) {
    db::upsert_user(db, email, name, None, role, &[]).unwrap();
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

fn no_auth_get(path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn bad_key_get(path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, "Bearer bad")
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn admin_post(key: &str, path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr())
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
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

fn admin_del(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn setup_session(db: &Db, email: &str, role: &str) -> String {
    create_user(db, email, "Test", role);
    let user = db::get_user_by_email(db, email).unwrap();
    db::create_auth_session(db, user.id, 3600).unwrap()
}

fn sess_req(method: &str, path: &str, tok: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header(header::COOKIE, format!("persea_session={}", tok))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn sess_post(path: &str, tok: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::COOKIE, format!("persea_session={}", tok))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr())
        .body(axum::body::Body::from(
            serde_json::to_string(&body).unwrap(),
        ))
        .unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

// ── Auth middleware ──

#[tokio::test]
async fn no_auth_returns_401() {
    let router = test_router(test_db());
    let resp = router.oneshot(no_auth_get("/api/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_key_returns_401() {
    let router = test_router(test_db());
    let resp = router.oneshot(bad_key_get("/api/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_admin_key_returns_200() {
    let db = test_db();
    let key = create_admin(&db, "test-admin");
    let router = test_router(db);
    let resp = router.oneshot(admin_get(&key, "/api/users")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── User management ──

#[tokio::test]
async fn list_users_empty() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router.oneshot(admin_get(&key, "/api/users")).await.unwrap();
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn list_users_with_data() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "alice@test.com", "Alice", "viewer");
    create_user(&db, "bob@test.com", "Bob", "operator");
    let router = test_router(db);
    let resp = router.oneshot(admin_get(&key, "/api/users")).await.unwrap();
    let json = body_json(resp).await;
    let users = json.as_array().unwrap();
    assert_eq!(users.len(), 2);
}

#[tokio::test]
async fn set_user_role_updates() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com/role",
            serde_json::json!({"role": "operator"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        db::get_user_by_email(&db, "user@test.com").unwrap().role,
        "operator"
    );
}

#[tokio::test]
async fn set_role_invalid() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com/role",
            serde_json::json!({"role": "superadmin"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn set_role_not_found() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/nobody@test.com/role",
            serde_json::json!({"role": "operator"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_user_works() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_del(&key, "/api/users/user@test.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(db::get_user_by_email(&db, "user@test.com").is_err());
}

#[tokio::test]
async fn delete_user_not_found() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_del(&key, "/api/users/nobody@test.com"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn disable_enable_user() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");

    let r1 = test_router(db.clone())
        .oneshot(admin_post(
            &key,
            "/api/users/user@test.com/disable",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    assert!(
        db::get_user_by_email(&db, "user@test.com")
            .unwrap()
            .disabled
    );

    let r2 = test_router(db.clone())
        .oneshot(admin_post(
            &key,
            "/api/users/user@test.com/enable",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    assert!(
        !db::get_user_by_email(&db, "user@test.com")
            .unwrap()
            .disabled
    );
}

#[tokio::test]
async fn viewer_cannot_list_users() {
    let db = test_db();
    let session = setup_session(&db, "viewer@test.com", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_req("GET", "/api/users", &session))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Token management ──

#[tokio::test]
async fn list_tokens_empty() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_req("GET", "/api/me/tokens", &session))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn create_and_list_token() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": "my-token"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["name"].as_str().unwrap(), "my-token");
    assert!(json["token"].as_str().unwrap().starts_with("rgu_"));
    let token_id = json["id"].as_i64().unwrap();

    let router = test_router(db);
    let resp = router
        .oneshot(sess_req("GET", "/api/me/tokens", &session))
        .await
        .unwrap();
    let json = body_json(resp).await;
    let tokens = json.as_array().unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["id"].as_i64().unwrap(), token_id);
}

#[tokio::test]
async fn create_token_empty_name() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": ""}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn create_token_duplicate_conflict() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");
    let r1 = test_router(db.clone())
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": "dup"}),
        ))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let r2 = test_router(db)
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": "dup"}),
        ))
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn revoke_token() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");

    let r = test_router(db.clone())
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": "revoke-me"}),
        ))
        .await
        .unwrap();
    let json = body_json(r).await;
    let token_id = json["id"].as_i64().unwrap();

    let r = test_router(db.clone())
        .oneshot(sess_req(
            "DELETE",
            &format!("/api/me/tokens/{}", token_id),
            &session,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    assert!(db::list_user_tokens(&db, user.id).unwrap().is_empty());
}

#[tokio::test]
async fn revoke_nonexistent_token() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "poweruser");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_req("DELETE", "/api/me/tokens/99999", &session))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn viewer_cannot_create_token() {
    let db = test_db();
    let session = setup_session(&db, "user@test.com", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_post(
            "/api/me/tokens",
            &session,
            serde_json::json!({"name": "nope"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Admin token management ──

#[tokio::test]
async fn admin_list_tokens_empty() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/admin/users/user@test.com/tokens"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn admin_list_tokens_filters_by_path_email() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "alice@test.com", "Alice", "viewer");
    create_user(&db, "bob@test.com", "Bob", "viewer");
    let alice = db::get_user_by_email(&db, "alice@test.com").unwrap();
    let bob = db::get_user_by_email(&db, "bob@test.com").unwrap();
    db::create_user_token(&db, alice.id, "alice-token", None, None).unwrap();
    db::create_user_token(&db, bob.id, "bob-token", None, None).unwrap();

    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/admin/users/alice@test.com/tokens"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "only the path user's tokens must be listed");
    assert_eq!(arr[0]["name"], "alice-token");
    assert_eq!(arr[0]["email"], "alice@test.com");
}

#[tokio::test]
async fn admin_list_tokens_unknown_user_404() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/admin/users/ghost@test.com/tokens"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_create_token_for_user() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/admin/user-tokens",
            serde_json::json!({"email": "user@test.com", "name": "admin-token"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["email"].as_str().unwrap(), "user@test.com");
    assert!(json["token"].as_str().unwrap().starts_with("rgu_"));
}

#[tokio::test]
async fn admin_create_token_nonexistent_user() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/admin/user-tokens",
            serde_json::json!({"email": "ghost@test.com", "name": "ghost"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_revoke_token() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_user(&db, "user@test.com", "User", "viewer");

    let r = test_router(db.clone())
        .oneshot(admin_post(
            &key,
            "/api/admin/user-tokens",
            serde_json::json!({"email": "user@test.com", "name": "revoke-me"}),
        ))
        .await
        .unwrap();
    let json = body_json(r).await;
    let token_id = json["id"].as_i64().unwrap();

    let r = test_router(db.clone())
        .oneshot(admin_del(
            &key,
            &format!("/api/admin/user-tokens/{}", token_id),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);

    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    assert!(db::list_user_tokens(&db, user.id).unwrap().is_empty());
}

#[tokio::test]
async fn admin_revoke_nonexistent_token() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_del(&key, "/api/admin/user-tokens/99999"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn poweruser_cannot_admin_tokens() {
    let db = test_db();
    let session = setup_session(&db, "pu@test.com", "poweruser");
    let router = test_router(db);
    let resp = router
        .oneshot(sess_req("GET", "/api/admin/users/pu%40test.com/tokens", &session))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
