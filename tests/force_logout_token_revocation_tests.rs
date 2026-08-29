//! Regression test for persea#270:
//! Admin force-logout must revoke scoped tokens immediately.
//!
//! Before the fix, `DELETE /api/admin/users/{email}/sessions` only deleted
//! `auth_sessions` rows, leaving scoped desktop tokens valid until TTL.
//! This test ensures that force-logout invalidates those tokens at once.

use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::delete;
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
            "/api/admin/users/{email}/sessions",
            delete(persea::api::users::delete_user_sessions),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn create_database_user(db: &Db, email: &str, name: &str, role: &str) {
    let hash = persea::password::hash_password("a-very-long-password").unwrap();
    db::create_user_with_password(db, email, name, &hash, role, "database").unwrap();
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn admin_delete(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("DELETE")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

/// Force-logout must revoke a scoped token so `validate_user_token` rejects it.
#[tokio::test]
async fn force_logout_revokes_scoped_tokens() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "Target", "viewer");

    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    let (_token_id, token) =
        db::create_scoped_user_token(&db, user.id, "desktop", None, None).unwrap();

    // Token validates before force-logout.
    assert!(
        db::validate_user_token(&db, &token).is_ok(),
        "scoped token must validate before force-logout"
    );

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_delete(
            &key,
            "/api/admin/users/user@test.com/sessions",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ok"], true);
    assert!(
        json["tokens_revoked"].as_i64().unwrap() >= 1,
        "response must report at least one token revoked"
    );

    // Token must be gone after force-logout.
    let result = db::validate_user_token(&db, &token);
    assert!(
        result.is_err(),
        "scoped token must be rejected after force-logout"
    );
}

/// Force-logout must also revoke regular (non-scoped) user tokens.
#[tokio::test]
async fn force_logout_revokes_regular_tokens() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "Target", "viewer");

    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    let (_token_id, token) = db::create_user_token(&db, user.id, "api-key", None, None).unwrap();

    assert!(
        db::validate_user_token(&db, &token).is_ok(),
        "regular token must validate before force-logout"
    );

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_delete(
            &key,
            "/api/admin/users/user@test.com/sessions",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let result = db::validate_user_token(&db, &token);
    assert!(
        result.is_err(),
        "regular token must be rejected after force-logout"
    );
}

/// The force-logout audit event must include token-revocation details.
#[tokio::test]
async fn force_logout_audit_event_includes_token_count() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    create_database_user(&db, "user@test.com", "Target", "viewer");

    let user = db::get_user_by_email(&db, "user@test.com").unwrap();
    let _ = db::create_scoped_user_token(&db, user.id, "desktop", None, None).unwrap();

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_delete(
            &key,
            "/api/admin/users/user@test.com/sessions",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let events =
        persea::audit::list_events(&db, 100, 0, &persea::audit::AuditFilters::default()).unwrap();
    let force_logout = events
        .iter()
        .find(|e| e.event_type == "admin.user.force_logout")
        .expect("expected an admin.user.force_logout audit event");
    assert_eq!(force_logout.details["target_email"], "user@test.com");
    assert!(
        force_logout.details["tokens_revoked"].as_i64().unwrap() >= 1,
        "audit event must report tokens_revoked >= 1"
    );
}
