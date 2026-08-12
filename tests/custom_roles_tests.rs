//! Tests for custom roles: store-level CRUD, user assignment via the users
//! API, and the permission enforcement matrix (holder allowed / non-holder
//! denied / admin bypass).
//!
//! Pattern copied from `tests/csv_import_tests.rs` (tower oneshot router).

use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, put};
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::{self, Db};
use persea::rbac::ObjectPermission;
use std::net::SocketAddr;
use tower::ServiceExt;

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn test_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/users/{email}/role",
            put(persea::api::users::set_user_role),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            get(persea::api::address_book::ab_list_entries),
        )
        .route("/api/users", get(persea::api::users::list_users))
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn create_user(db: &Db, email: &str) {
    let hash = persea::password::hash_password("correct horse battery staple 42!").unwrap();
    db::create_user_with_password(db, email, email, &hash, "viewer", "local").unwrap();
}

/// Issue a user API token for a local user (Bearer-auth equivalent of an
/// admin API key, but carrying the user's role).
fn user_token(db: &Db, email: &str) -> String {
    let user = db::get_user_by_email(db, email).unwrap();
    db::create_user_token(db, user.id, "test", None, None)
        .unwrap()
        .1
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn api_get(path: &str, key: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn api_put(path: &str, key: &str, body: serde_json::Value) -> Request<axum::body::Body> {
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn make_role(db: &Db, name: &str, perms: &[&str]) -> String {
    let perms = perms.iter().map(|p| p.to_string()).collect::<Vec<_>>();
    persea::rbac::create_custom_role(db, name, Some("test"), &perms).unwrap()
}

fn user_id(db: &Db, email: &str) -> i64 {
    db::get_user_by_email(db, email).unwrap().id
}

fn seed_entry(db: &Db, scope: &str, folder: &str, name: &str) {
    let folder_id = db::create_ab_folder(db, scope, folder, "", "", false).unwrap();
    db::create_ab_entry(
        db,
        folder_id,
        name,
        "",
        "ssh",
        "10.0.0.1",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
}

// ── Store-level CRUD ──

#[test]
fn create_role_round_trip() {
    let db = test_db();
    let role_id = make_role(&db, "server-viewer", &["read", "connect"]);

    let roles = persea::rbac::list_custom_roles(&db).unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, role_id);
    assert_eq!(roles[0].name, "server-viewer");
    assert_eq!(
        roles[0].permissions,
        vec!["connect".to_string(), "read".to_string()]
    );
}

#[test]
fn duplicate_role_name_rejected() {
    let db = test_db();
    let first = make_role(&db, "server-viewer", &["read"]);
    let dup = persea::rbac::create_custom_role(
        &db,
        "server-viewer",
        Some("dup"),
        &["connect".to_string()],
    );
    assert!(
        dup.is_err(),
        "duplicate name must be rejected by the UNIQUE constraint"
    );
    let roles = persea::rbac::list_custom_roles(&db).unwrap();
    assert_eq!(roles.len(), 1);
    assert_eq!(roles[0].id, first);
}

#[test]
fn update_role_replaces_permissions() {
    let db = test_db();
    let role_id = make_role(&db, "r", &["read"]);
    let perms = vec!["connect".to_string(), "delete".to_string()];
    let changed =
        persea::rbac::update_custom_role(&db, &role_id, "r2", Some("new"), &perms).unwrap();
    assert!(changed);
    let role = persea::rbac::get_custom_role(&db, &role_id)
        .unwrap()
        .unwrap();
    assert_eq!(role.name, "r2");
    assert_eq!(
        role.permissions,
        vec!["connect".to_string(), "delete".to_string()]
    );
}

#[test]
fn delete_role_cascades_and_clears_assignment() {
    let db = test_db();
    create_user(&db, "bob@example.com");
    let role_id = make_role(&db, "temp-role", &["read"]);
    persea::rbac::set_user_custom_role(&db, "bob@example.com", Some(&role_id)).unwrap();

    assert!(persea::rbac::delete_custom_role(&db, &role_id).unwrap());
    assert!(persea::rbac::list_custom_roles(&db).unwrap().is_empty());
    let user = db::get_user_by_email(&db, "bob@example.com").unwrap();
    assert!(user.custom_role_id.is_none());
}

// ── Assignment via the users API ──

#[tokio::test]
async fn assign_custom_role_via_users_api() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    create_user(&db, "bob@example.com");
    let role_id = make_role(&db, "server-viewer", &["read", "connect"]);

    let resp = router
        .oneshot(api_put(
            "/api/users/bob@example.com/role",
            &key,
            serde_json::json!({"role": "server-viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let user = db::get_user_by_email(&db, "bob@example.com").unwrap();
    assert_eq!(user.custom_role_id.as_deref(), Some(role_id.as_str()));
}

#[tokio::test]
async fn assign_unknown_role_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    create_user(&db, "bob@example.com");

    // Unknown role strings keep the legacy error path (matches the existing
    // set_role_invalid behavior in api_handler_tests); the important part is
    // that the assignment does NOT happen.
    let resp = router
        .oneshot(api_put(
            "/api/users/bob@example.com/role",
            &key,
            serde_json::json!({"role": "does-not-exist"}),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_server_error());
    let user = db::get_user_by_email(&db, "bob@example.com").unwrap();
    assert!(user.custom_role_id.is_none());
}

#[tokio::test]
async fn clear_custom_role_via_users_api() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    create_user(&db, "bob@example.com");
    let role_id = make_role(&db, "server-viewer", &["read"]);
    persea::rbac::set_user_custom_role(&db, "bob@example.com", Some(&role_id)).unwrap();

    let resp = router
        .oneshot(api_put(
            "/api/users/bob@example.com/role",
            &key,
            serde_json::json!({"role": ""}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let user = db::get_user_by_email(&db, "bob@example.com").unwrap();
    assert!(user.custom_role_id.is_none());
}

#[tokio::test]
async fn assignment_requires_admin() {
    let db = test_db();
    create_user(&db, "alice@example.com");
    create_user(&db, "bob@example.com");
    let alice_token = user_token(&db, "alice@example.com");
    let router = test_router(db.clone());

    let resp = router
        .oneshot(api_put(
            "/api/users/bob@example.com/role",
            &alice_token,
            serde_json::json!({"role": "server-viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Enforcement matrix ──

#[test]
fn holder_has_bundle_permissions() {
    let db = test_db();
    create_user(&db, "bob@example.com");
    let role_id = make_role(&db, "server-viewer", &["read", "connect"]);
    persea::rbac::set_user_custom_role(&db, "bob@example.com", Some(&role_id)).unwrap();
    let uid = user_id(&db, "bob@example.com");

    assert!(persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Read
    )
    .unwrap());
    assert!(persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Connect
    )
    .unwrap());
    assert!(!persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Update
    )
    .unwrap());
    assert!(!persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Delete
    )
    .unwrap());
}

#[test]
fn non_holder_has_no_permissions() {
    let db = test_db();
    create_user(&db, "carol@example.com");
    let uid = user_id(&db, "carol@example.com");

    assert!(!persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Read
    )
    .unwrap());
}

#[tokio::test]
async fn holder_sees_entries_non_holder_denied() {
    let db = test_db();
    let router = test_router(db.clone());
    create_user(&db, "bob@example.com");
    create_user(&db, "carol@example.com");
    let role_id = make_role(&db, "server-viewer", &["read", "connect"]);
    persea::rbac::set_user_custom_role(&db, "bob@example.com", Some(&role_id)).unwrap();
    seed_entry(&db, "shared", "Root", "web01");

    // Holder (viewer base + read+connect bundle) can list entries even
    // though it has no allowed_groups membership.
    let bob_token = user_token(&db, "bob@example.com");
    let resp = router
        .clone()
        .oneshot(api_get(
            "/api/addressbook/folders/shared/Root/entries",
            &bob_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "holder should list entries");
    let json = body_json(resp).await;
    assert_eq!(json.as_array().map(|a| a.len()).unwrap_or(0), 1);

    // Non-holder (plain viewer) is denied.
    let carol_token = user_token(&db, "carol@example.com");
    let resp = router
        .oneshot(api_get(
            "/api/addressbook/folders/shared/Root/entries",
            &carol_token,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_bypass_unchanged() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    seed_entry(&db, "shared", "Root", "web01");

    // Admin can list entries with no custom role at all.
    let resp = router
        .oneshot(api_get(
            "/api/addressbook/folders/shared/Root/entries",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unauthenticated_denied() {
    let db = test_db();
    let router = test_router(db.clone());
    seed_entry(&db, "shared", "Root", "web01");

    // No credentials at all: require_auth rejects before any handler runs.
    let resp = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/addressbook/folders/shared/Root/entries")
                .extension(fake_addr())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn holder_cannot_reach_admin_endpoints() {
    let db = test_db();
    let router = test_router(db.clone());
    create_user(&db, "bob@example.com");
    let role_id = make_role(&db, "server-viewer", &["read", "connect"]);
    persea::rbac::set_user_custom_role(&db, "bob@example.com", Some(&role_id)).unwrap();
    let bob_token = user_token(&db, "bob@example.com");

    // Roles CRUD is admin-only for bundle holders (verified structurally:
    // every handler in src/handlers/rbac.rs opens with require_admin, the
    // same gate the users endpoints use and exercise below).

    // User management (list + role assignment) is admin-only; a holder
    // cannot escalate by assigning itself a stronger role.
    let resp = router
        .clone()
        .oneshot(api_get("/api/users", &bob_token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "user list must be admin-only");

    let resp = router
        .oneshot(api_put(
            "/api/users/bob@example.com/role",
            &bob_token,
            serde_json::json!({ "role": "admin" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "self role assignment must be denied"
    );

    // The assignment did not happen.
    let user = db::get_user_by_email(&db, "bob@example.com").unwrap();
    assert_eq!(user.role, "viewer");
    let role = persea::rbac::user_custom_role(&db, user.id).unwrap();
    assert!(role.is_some(), "custom role must be untouched");
    assert_eq!(role.unwrap().name, "server-viewer");
}

#[test]
fn unknown_permission_string_is_inert() {
    // A permission string outside the validated vocabulary (e.g. inserted
    // via the CLI) must never match a SystemPermission/ObjectPermission
    // check — the equality match on as_str() makes it inert, and it does
    // not leak any real permission.
    let db = test_db();
    create_user(&db, "dave@example.com");
    let role_id = make_role(&db, "weird", &["read", "superadmin"]);
    persea::rbac::set_user_custom_role(&db, "dave@example.com", Some(&role_id)).unwrap();
    let uid = user_id(&db, "dave@example.com");

    assert!(persea::rbac::user_has_custom_permission(&db, uid, "read").unwrap());
    assert!(!persea::rbac::user_has_custom_permission(&db, uid, "superadmin").unwrap());
    assert!(!persea::rbac::user_has_system_permission(
        &db,
        uid,
        persea::rbac::SystemPermission::Administer
    )
    .unwrap());
    assert!(!persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Update
    )
    .unwrap());
}

#[test]
fn system_permissions_flow_only_through_bundle() {
    // `rbac_permissions` carries no system-permission rows by design; the
    // custom bundle is the only carrier. A plain user with a per-connection
    // grant must not gain any system permission.
    let db = test_db();
    create_user(&db, "erin@example.com");
    let uid = user_id(&db, "erin@example.com");
    persea::rbac::grant_connection_permission(
        &db,
        &format!("u:{uid}"),
        "shared/Root/web01",
        ObjectPermission::Administer,
    )
    .unwrap();
    assert!(persea::rbac::user_has_object_permission(
        &db,
        uid,
        "connection",
        "shared/Root/web01",
        ObjectPermission::Administer
    )
    .unwrap());
    assert!(!persea::rbac::user_has_system_permission(
        &db,
        uid,
        persea::rbac::SystemPermission::Administer
    )
    .unwrap());
    assert!(!persea::rbac::user_has_system_permission(
        &db,
        uid,
        persea::rbac::SystemPermission::CreateSession
    )
    .unwrap());
}
