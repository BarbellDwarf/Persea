//! Integration tests for the admin user-edit endpoint
//! (`PUT /api/users/{email}`): name/email/password updates, auth-source
//! gating, password policy enforcement, and uniqueness conflicts.
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{delete, put};
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
        .route(
            "/api/users/{email}",
            delete(persea::api::users::delete_user).put(persea::api::users::update_user),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

/// A local password user (auth_source = 'database').
fn create_database_user(db: &Db, email: &str, name: &str, role: &str) {
    let hash = persea::password::hash_password("a-very-long-password").unwrap();
    db::create_user_with_password(db, email, name, &hash, role, "database").unwrap();
}

/// An OIDC user (auth_source = 'oidc').
fn create_oidc_user(db: &Db, email: &str, name: &str, role: &str) {
    db::upsert_user(db, email, name, Some("sub-1"), role, &[]).unwrap();
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
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

#[tokio::test]
async fn update_user_name_works() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "Old Name", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"name": "New Name"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        db::get_user_by_email(&db, "user@test.com").unwrap().name,
        "New Name"
    );
}

#[tokio::test]
async fn update_user_name_works_for_oidc() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_oidc_user(&db, "oidc@test.com", "Old Name", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/oidc@test.com",
            serde_json::json!({"name": "New Name"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        db::get_user_by_email(&db, "oidc@test.com").unwrap().name,
        "New Name"
    );
}

#[tokio::test]
async fn update_user_email_works_and_preserves_session() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let uid = db::get_user_by_email(&db, "user@test.com").unwrap().id;
    let session = db::create_auth_session(&db, uid, 3600).unwrap();
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"email": "renamed@test.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let updated = db::get_user_by_email(&db, "renamed@test.com").unwrap();
    assert_eq!(updated.id, uid, "email change must keep the user id");
    // The existing session still validates and resolves to the same user.
    let validated = db::validate_auth_session(&db, &session).unwrap();
    assert_eq!(validated.id, uid);
    assert_eq!(validated.email, "renamed@test.com");
}

#[tokio::test]
async fn update_user_email_conflict() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "a@test.com", "A", "viewer");
    create_database_user(&db, "b@test.com", "B", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/a@test.com",
            serde_json::json!({"email": "b@test.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_user_email_oidc_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_oidc_user(&db, "oidc@test.com", "OIDC User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/oidc@test.com",
            serde_json::json!({"email": "moved@test.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_password_oidc_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_oidc_user(&db, "oidc@test.com", "OIDC User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/oidc@test.com",
            serde_json::json!({"password": "a-very-long-password"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_password_too_short() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"password": "short"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_password_reuse_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let hash = persea::password::hash_password("a-very-long-password").unwrap();
    db::create_user_with_password(&db, "user@test.com", "User", &hash, "viewer", "database")
        .unwrap();
    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    persea::password::record_password_history(&db, user.id, &hash, 5).unwrap();
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"password": "a-very-long-password"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_password_works() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"password": "a-brand-new-long-password"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // The new password verifies against the stored hash.
    let (_, _, _, _, _, stored_hash) = db::get_user_login_info(&db, "user@test.com")
        .unwrap()
        .unwrap();
    assert!(
        persea::password::verify_password("a-brand-new-long-password", &stored_hash.unwrap())
            .unwrap()
    );
}

#[tokio::test]
async fn update_user_not_found() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/nobody@test.com",
            serde_json::json!({"name": "X"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_user_empty_body() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_invalid_email() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"email": "not-an-email"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_user_requires_admin() {
    let db = test_db();
    create_database_user(&db, "user@test.com", "User", "viewer");
    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    let session = db::create_auth_session(&db, user.id, 3600).unwrap();
    let router = test_router(db);
    let req = Request::builder()
        .method("PUT")
        .uri("/api/users/user@test.com")
        .header(header::COOKIE, format!("persea_session={}", session))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(fake_addr())
        .body(axum::body::Body::from(
            serde_json::to_string(&serde_json::json!({"name": "X"})).unwrap(),
        ))
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_user_audit_event_written() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "User", "viewer");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/users/user@test.com",
            serde_json::json!({"name": "Renamed", "email": "moved@test.com"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let events =
        persea::audit::list_events(&db, 100, 0, &persea::audit::AuditFilters::default()).unwrap();
    assert!(
        events.iter().any(|e| e.event_type == "admin.user.edit"),
        "expected an admin.user.edit audit event"
    );
    let edit = events
        .iter()
        .find(|e| e.event_type == "admin.user.edit")
        .unwrap();
    assert_eq!(edit.details["target_email"], "user@test.com");
    assert_eq!(edit.details["new_email"], "moved@test.com");
    assert_eq!(edit.details["name_changed"], true);
    assert_eq!(edit.details["email_changed"], true);
    assert_eq!(edit.details["password_changed"], false);
}
