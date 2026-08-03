//! Integration tests for API handlers.
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Extension, Router};
use rustguac::auth::TrustedProxies;
use rustguac::db::{self, Db};
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db { db::init_db(std::path::Path::new(":memory:")).unwrap() }

fn test_router(db: Db) -> Router {
    Router::new()
        .route("/api/users", get(rustguac::api::users::list_users))
        .route("/api/users/{email}/role", put(rustguac::api::users::set_user_role))
        .route("/api/users/{email}", delete(rustguac::api::users::delete_user))
        .route("/api/users/{email}/disable", post(rustguac::api::users::disable_user))
        .route("/api/users/{email}/enable", post(rustguac::api::users::enable_user))
        .route("/api/me/tokens", get(rustguac::api::tokens::list_my_tokens))
        .route("/api/me/tokens", post(rustguac::api::tokens::create_my_token))
        .route("/api/me/tokens/{id}", delete(rustguac::api::tokens::revoke_my_token))
        .route("/api/admin/user-tokens", get(rustguac::api::tokens::admin_list_user_tokens))
        .route("/api/admin/user-tokens", post(rustguac::api::tokens::admin_create_user_token))
        .route("/api/admin/user-tokens/{id}", delete(rustguac::api::tokens::admin_revoke_user_token))
        .layer(middleware::from_fn(rustguac::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String { db::add_admin(db, name, None, None).unwrap() }
fn create_user(db: &Db, email: &str, name: &str, role: &str) { db::upsert_user(db, email, name, None, role, &[]).unwrap(); }

fn fake_addr() -> ConnectInfo<SocketAddr> { ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap()) }

fn admin_get(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder().uri(path).header(header::AUTHORIZATION, format!("Bearer {}", key)).extension(fake_addr()).body(axum::body::Body::empty()).unwrap()
}
fn no_auth_get(path: &str) -> Request<axum::body::Body> {
    Request::builder().uri(path).extension(fake_addr()).body(axum::body::Body::empty()).unwrap()
}
fn bad_key_get(path: &str) -> Request<axum::body::Body> {
    Request::builder().uri(path).header(header::AUTHORIZATION, "Bearer bad").extension(fake_addr()).body(axum::body::Body::empty()).unwrap()
}
fn admin_post(key: &str, path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder().method("POST").uri(path).header(header::AUTHORIZATION, format!("Bearer {}", key)).header(header::CONTENT_TYPE, "application/json").extension(fake_addr()).body(axum::body::Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}
fn admin_put(key: &str, path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder().method("PUT").uri(path).header(header::AUTHORIZATION, format!("Bearer {}", key)).header(header::CONTENT_TYPE, "application/json").extension(fake_addr()).body(axum::body::Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}
fn admin_del(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder().method("DELETE").uri(path).header(header::AUTHORIZATION, format!("Bearer {}", key)).extension(fake_addr()).body(axum::body::Body::empty()).unwrap()
}

fn setup_session(db: &Db, email: &str, role: &str) -> String {
    create_user(db, email, "Test", role);
    db::create_auth_session(db, db::get_user_by_email(db, email).unwrap().id, 3600).unwrap()
}
fn sess_req(method: &str, path: &str, tok: &str) -> Request<axum::body::Body> {
    Request::builder().method(method).uri(path).header(header::COOKIE, format!("rustguac_session={}", tok)).extension(fake_addr()).body(axum::body::Body::empty()).unwrap()
}
fn sess_post(path: &str, tok: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder().method("POST").uri(path).header(header::COOKIE, format!("rustguac_session={}", tok)).header(header::CONTENT_TYPE, "application/json").extension(fake_addr()).body(axum::body::Body::from(serde_json::to_string(&body).unwrap())).unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap()
}

// ── Auth middleware ──
#[tokio::test] async fn no_auth_returns_401() { assert_eq!(test_router(test_db()).oneshot(no_auth_get("/api/users")).await.unwrap().status(), StatusCode::UNAUTHORIZED); }
#[tokio::test] async fn bad_key_returns_401() { assert_eq!(test_router(test_db()).oneshot(bad_key_get("/api/users")).await.unwrap().status(), StatusCode::UNAUTHORIZED); }
#[tokio::test] async fn valid_admin_key_returns_200() { let db=test_db(); let k=create_admin(&db,"a"); assert_eq!(test_router(db).oneshot(admin_get(&k,"/api/users")).await.unwrap().status(), StatusCode::OK); }

// ── User management ──
#[tokio::test] async fn list_users_empty() {
    let db=test_db(); let k=create_admin(&db,"a");
    let v=body_json(test_router(db).oneshot(admin_get(&k,"/api/users")).await.unwrap()).await;
    assert!(v.as_array().unwrap().is_empty());
}
#[tokio::test] async fn list_users_with_data() {
    let db=test_db(); let k=create_admin(&db,"a");
    create_user(&db,"alice@test.com","Alice","viewer"); create_user(&db,"bob@test.com","Bob","operator");
    let v=body_json(test_router(db).oneshot(admin_get(&k,"/api/users")).await.unwrap()).await;
    assert_eq!(v.as_array().unwrap().len(), 2);
}
#[tokio::test] async fn set_user_role_updates() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    let r=test_router(db.clone()).oneshot(admin_put(&k,"/api/users/u@t/role",serde_json::json!({"role":"operator"}))).await.unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(db::get_user_by_email(&db,"u@t").unwrap().role,"operator");
}
#[tokio::test] async fn set_role_invalid() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    assert_eq!(test_router(db).oneshot(admin_put(&k,"/api/users/u@t/role",serde_json::json!({"role":"bad"}))).await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[tokio::test] async fn set_role_not_found() {
    let db=test_db(); let k=create_admin(&db,"a");
    let r=test_router(db).oneshot(admin_put(&k,"/api/users/x@t/role",serde_json::json!({"role":"v"}))).await.unwrap();
    assert!(r.status().is_client_error() || r.status().is_server_error());
}
#[tokio::test] async fn delete_user_works() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    assert_eq!(test_router(db.clone()).oneshot(admin_del(&k,"/api/users/u@t")).await.unwrap().status(), StatusCode::NO_CONTENT);
    assert!(db::get_user_by_email(&db,"u@t").is_err());
}
#[tokio::test] async fn delete_user_not_found() {
    let db=test_db(); let k=create_admin(&db,"a");
    assert_eq!(test_router(db).oneshot(admin_del(&k,"/api/users/x@t")).await.unwrap().status(), StatusCode::NOT_FOUND);
}
#[tokio::test] async fn disable_enable_user() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    test_router(db.clone()).oneshot(admin_post(&k,"/api/users/u@t/disable",serde_json::json!({}))).await.unwrap();
    assert!(db::get_user_by_email(&db,"u@t").unwrap().disabled);
    test_router(db.clone()).oneshot(admin_post(&k,"/api/users/u@t/enable",serde_json::json!({}))).await.unwrap();
    assert!(!db::get_user_by_email(&db,"u@t").unwrap().disabled);
}
#[tokio::test] async fn viewer_cannot_list_users() {
    let db=test_db(); let s=setup_session(&db,"v@t","viewer");
    assert_eq!(test_router(db).oneshot(sess_req("GET","/api/users",&s)).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// ── Token management ──
#[tokio::test] async fn list_tokens_empty() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    let v=body_json(test_router(db).oneshot(sess_req("GET","/api/me/tokens",&s)).await.unwrap()).await;
    assert!(v.as_array().unwrap().is_empty());
}
#[tokio::test] async fn create_and_list_token() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    let v=body_json(test_router(db.clone()).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":"t1"}))).await.unwrap()).await;
    assert_eq!(v["name"].as_str().unwrap(),"t1");
    assert!(v["token"].as_str().unwrap().starts_with("rgu_"));
    let tid=v["id"].as_i64().unwrap();
    let v2=body_json(test_router(db).oneshot(sess_req("GET","/api/me/tokens",&s)).await.unwrap()).await;
    assert_eq!(v2.as_array().unwrap().len(),1);
    assert_eq!(v2[0]["id"].as_i64().unwrap(),tid);
}
#[tokio::test] async fn create_token_empty_name() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    assert_eq!(test_router(db).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":""}))).await.unwrap().status(), StatusCode::INTERNAL_SERVER_ERROR);
}
#[tokio::test] async fn create_token_duplicate_conflict() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    test_router(db.clone()).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":"d"}))).await.unwrap();
    assert_eq!(test_router(db).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":"d"}))).await.unwrap().status(), StatusCode::CONFLICT);
}
#[tokio::test] async fn revoke_token() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    let v=body_json(test_router(db.clone()).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":"r"}))).await.unwrap()).await;
    let tid=v["id"].as_i64().unwrap();
    assert_eq!(test_router(db.clone()).oneshot(sess_req("DELETE",&format!("/api/me/tokens/{}",tid),&s)).await.unwrap().status(), StatusCode::OK);
    assert!(db::list_user_tokens(&db,db::get_user_by_email(&db,"u@t").unwrap().id).unwrap().is_empty());
}
#[tokio::test] async fn revoke_nonexistent_token() {
    let db=test_db(); let s=setup_session(&db,"u@t","poweruser");
    assert_eq!(test_router(db).oneshot(sess_req("DELETE","/api/me/tokens/99999",&s)).await.unwrap().status(), StatusCode::NOT_FOUND);
}
#[tokio::test] async fn viewer_cannot_create_token() {
    let db=test_db(); let s=setup_session(&db,"u@t","viewer");
    assert_eq!(test_router(db).oneshot(sess_post("/api/me/tokens",&s,serde_json::json!({"name":"x"}))).await.unwrap().status(), StatusCode::FORBIDDEN);
}

// ── Admin token management ──
#[tokio::test] async fn admin_list_tokens_empty() {
    let db=test_db(); let k=create_admin(&db,"a");
    let v=body_json(test_router(db).oneshot(admin_get(&k,"/api/admin/user-tokens")).await.unwrap()).await;
    assert!(v.as_array().unwrap().is_empty());
}
#[tokio::test] async fn admin_create_token_for_user() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    let v=body_json(test_router(db).oneshot(admin_post(&k,"/api/admin/user-tokens",serde_json::json!({"email":"u@t","name":"at"}))).await.unwrap()).await;
    assert_eq!(v["email"].as_str().unwrap(),"u@t");
    assert!(v["token"].as_str().unwrap().starts_with("rgu_"));
}
#[tokio::test] async fn admin_create_token_nonexistent_user() {
    let db=test_db(); let k=create_admin(&db,"a");
    assert_eq!(test_router(db).oneshot(admin_post(&k,"/api/admin/user-tokens",serde_json::json!({"email":"x@t","name":"t"}))).await.unwrap().status(), StatusCode::NOT_FOUND);
}
#[tokio::test] async fn admin_revoke_token() {
    let db=test_db(); let k=create_admin(&db,"a"); create_user(&db,"u@t","U","v");
    let v=body_json(test_router(db.clone()).oneshot(admin_post(&k,"/api/admin/user-tokens",serde_json::json!({"email":"u@t","name":"r"}))).await.unwrap()).await;
    let tid=v["id"].as_i64().unwrap();
    assert_eq!(test_router(db.clone()).oneshot(admin_del(&k,&format!("/api/admin/user-tokens/{}",tid))).await.unwrap().status(), StatusCode::OK);
    assert!(db::list_user_tokens(&db,db::get_user_by_email(&db,"u@t").unwrap().id).unwrap().is_empty());
}
#[tokio::test] async fn admin_revoke_nonexistent_token() {
    let db=test_db(); let k=create_admin(&db,"a");
    assert_eq!(test_router(db).oneshot(admin_del(&k,"/api/admin/user-tokens/99999")).await.unwrap().status(), StatusCode::NOT_FOUND);
}
#[tokio::test] async fn poweruser_cannot_admin_tokens() {
    let db=test_db(); let s=setup_session(&db,"p@t","poweruser");
    assert_eq!(test_router(db).oneshot(sess_req("GET","/api/admin/user-tokens",&s)).await.unwrap().status(), StatusCode::FORBIDDEN);
}
