//! API handler integration tests using axum test utilities with in-memory SQLite DB.

use super::{
    CredentialDefaultScope, DriveConfigured, OidcEnabled, SiteTitle, StorageBackend, StorageKey,
    VaultBackends, VaultCell, VaultConfigured, VaultState,
};
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

/// Whether a local guacd is listening on the default port (127.0.0.1:4822).
/// Quick-connect tests that create real sessions need it; CI does not run
/// guacd, so those tests skip there.
fn guacd_reachable() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:4822".parse().unwrap(),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
}

/// The quick-connect tests seed an SSH entry pointing at 127.0.0.1 (default
/// SSH port 22), so they also need a local SSH server — otherwise guacd
/// accepts the connection but session creation fails with 502. Skip instead
/// of failing when the target isn't present.
fn ssh_target_reachable() -> bool {
    std::net::TcpStream::connect_timeout(
        &"127.0.0.1:22".parse().unwrap(),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
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
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'",
        [],
    );
    let _ = conn.execute(
        "ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''",
        [],
    );
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

/// Vault state whose cells all point at an in-memory `MockVault`, so
/// handlers exercise the real Vault path through a fake backend.
fn mock_vault_state(mock: Arc<crate::testing::MockVault>) -> VaultState {
    let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(Some(mock)));
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
    build_test_router_with_vault(db, test_vault_state())
}

fn build_test_router_with_vault(db: Db, vault: VaultState) -> axum::Router {
    build_test_router_with_vault_and_backend(db, vault, None)
}

/// Router with an explicit `StorageBackend` marker ("db" | "vault").
/// `None` exercises the default-db path (handlers default to "db" when the
/// extension is absent).
fn build_test_router_with_vault_and_backend(
    db: Db,
    vault: VaultState,
    backend: Option<&str>,
) -> axum::Router {
    use axum::routing::{delete, get, post, put};

    let api_routes = axum::Router::new()
        .route("/api/users", get(super::users::list_users))
        .route("/api/users/{email}/role", put(super::users::set_user_role))
        .route("/api/users/{email}", delete(super::users::delete_user))
        .route(
            "/api/users/{email}/disable",
            post(super::users::disable_user),
        )
        .route("/api/users/{email}/enable", post(super::users::enable_user))
        .route("/api/me/tokens", get(super::tokens::list_my_tokens))
        .route("/api/me/tokens", post(super::tokens::create_my_token))
        .route(
            "/api/me/tokens/{id}",
            delete(super::tokens::revoke_my_token),
        )
        .route(
            "/api/admin/user-tokens",
            get(super::tokens::admin_list_user_tokens),
        )
        .route(
            "/api/admin/user-tokens",
            post(super::tokens::admin_create_user_token),
        )
        .route(
            "/api/admin/user-tokens/{id}",
            delete(super::tokens::admin_revoke_user_token),
        )
        .route("/api/addressbook", get(super::ab_list_all))
        .route("/api/addressbook/search-index", get(super::ab_search_index))
        .route("/api/addressbook/folders", get(super::ab_list_folders))
        .route("/api/addressbook/folders", post(super::ab_create_folder))
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            put(super::ab_update_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}",
            delete(super::ab_delete_folder),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/config",
            get(super::ab_get_folder_config),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/subfolders",
            get(super::ab_list_subfolders),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            get(super::ab_list_entries),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries",
            post(super::ab_create_entry),
        )
        .route(
            "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
            delete(super::ab_delete_entry),
        )
        .route(
            "/api/vsphere/vms/{vm_id}/power",
            post(super::vsphere::power_action),
        )
        .with_state(());

    let mut api_routes = api_routes
        .layer(axum::middleware::from_fn(crate::auth::require_auth))
        .layer(Extension(db))
        .layer(Extension(vault))
        .layer(Extension(VaultConfigured(false)))
        .layer(Extension(OidcEnabled(false)))
        .layer(Extension(DriveConfigured(false)))
        .layer(Extension(CredentialDefaultScope("local".into())))
        .layer(Extension(SiteTitle("Test".into())))
        .layer(Extension(super::vsphere::VsphereState::None));
    if let Some(b) = backend {
        api_routes = api_routes.layer(Extension(StorageBackend(b.into())));
    }
    api_routes
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
    let response = app
        .oneshot(make_request("GET", "/api/users"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_invalid_api_key_returns_401() {
    let db = test_db();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/users", "invalid-key-12345"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_valid_api_key_succeeds() {
    let db = test_db();
    let _key = insert_test_admin(&db, "testadmin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/users", &_key))
        .await
        .unwrap();
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
    let response = app
        .oneshot(make_auth_request("GET", "/api/users", &_key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
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
    let response = app
        .oneshot(make_auth_request("GET", "/api/users", &_key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
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
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            "/api/users/delete@test.com",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_delete_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            "/api/users/nobody@test.com",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_set_role_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "role@test.com", "Role User", "viewer");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "PUT",
            "/api/users/role@test.com/role",
            &_key,
            json!({"role": "operator"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_set_role_invalid() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "role@test.com", "Role User", "viewer");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "PUT",
            "/api/users/role@test.com/role",
            &_key,
            json!({"role": "superadmin"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_set_role_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "PUT",
            "/api/users/nobody@test.com/role",
            &_key,
            json!({"role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_disable_user_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "disable@test.com", "Disable Me", "viewer");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "POST",
            "/api/users/disable@test.com/disable",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_disable_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "POST",
            "/api/users/nobody@test.com/disable",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_enable_user_success() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "enable@test.com", "Enable Me", "viewer");
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "UPDATE users SET disabled = 1 WHERE email = 'enable@test.com'",
            [],
        )
        .unwrap();
    }
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "POST",
            "/api/users/enable@test.com/enable",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_enable_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "POST",
            "/api/users/nobody@test.com/enable",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_list_tokens_empty() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/admin/user-tokens", &_key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
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
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/admin/user-tokens",
            &_key,
            json!({"email": "token@test.com", "name": "my-test-token", "max_role": "viewer"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
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
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/admin/user-tokens",
            &_key,
            json!({"email": "token@test.com", "name": ""}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_admin_create_token_user_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/admin/user-tokens",
            &_key,
            json!({"email": "nobody@test.com", "name": "tok"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_admin_create_token_invalid_role() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    insert_test_user(&db, "token@test.com", "Token User", "viewer");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/admin/user-tokens",
            &_key,
            json!({"email": "token@test.com", "name": "bad-role", "max_role": "superadmin"}),
        ))
        .await
        .unwrap();
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
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            &format!("/api/admin/user-tokens/{}", token_id),
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_admin_revoke_token_not_found() {
    let db = test_db();
    let _key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            "/api/admin/user-tokens/99999",
            &_key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_viewer_token_cannot_list_users() {
    let db = test_db();
    insert_test_user(&db, "viewer@test.com", "Viewer", "viewer");
    let user = db::get_user_by_email(&db, "viewer@test.com").unwrap();
    let (_, plaintext) = db::create_user_token(&db, user.id, "viewer-token", None, None).unwrap();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/users", &plaintext))
        .await
        .unwrap();
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
    let response = app
        .oneshot(make_auth_request("GET", "/api/me", &_key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["name"].as_str().unwrap(), "meadmin");
    assert_eq!(body["role"].as_str().unwrap(), "admin");
}

// ── Address book: DB-first storage (Vault optional) ──

/// Seed a MockVault with a folder config + entries, mirroring the old
/// Vault KV v2 layout (`shared/<folder>/<entry>`, `shared/<folder>/.config`).
fn mock_vault_with_it_folder() -> Arc<crate::testing::MockVault> {
    use crate::vault::AddressBookEntry;
    Arc::new(
        crate::testing::MockVault::new()
            .with_entry(
                "shared/IT/.config",
                &serde_json::to_string(&crate::vault::FolderConfig {
                    allowed_groups: vec!["team-it".into()],
                    description: "IT servers".into(),
                    inherit_from_parent: false,
                })
                .unwrap(),
            )
            .with_entry(
                "shared/IT/srv-01",
                &serde_json::to_string(&AddressBookEntry {
                    session_type: "ssh".into(),
                    hostname: Some("10.0.0.5".into()),
                    username: Some("root".into()),
                    ..Default::default()
                })
                .unwrap(),
            )
            .with_entry(
                "shared/IT/web-01",
                &serde_json::to_string(&AddressBookEntry {
                    session_type: "web".into(),
                    url: Some("https://web.internal".into()),
                    ..Default::default()
                })
                .unwrap(),
            ),
    )
}

#[tokio::test]
async fn test_ab_list_folders_db_backed() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    db::create_ab_folder(&db, "shared", "IT", "IT servers", "", false).unwrap();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/addressbook/folders", &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let folders = body.as_array().unwrap();
    assert_eq!(
        folders.len(),
        1,
        "expected exactly the seeded IT folder: {}",
        body
    );
    assert_eq!(folders[0]["name"].as_str().unwrap(), "IT");
    assert_eq!(folders[0]["scope"].as_str().unwrap(), "shared");
    assert_eq!(folders[0]["description"].as_str().unwrap(), "IT servers");
}

#[tokio::test]
async fn test_ab_list_entries_db_backed() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "srv-01",
        "",
        "ssh",
        "10.0.0.5",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "web-01",
        "",
        "web",
        "",
        None,
        "",
        r#"{"url":"https://web.internal"}"#,
        "",
    )
    .unwrap();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/addressbook/folders/shared/IT/entries",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 2);
    let names: Vec<&str> = entries
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"srv-01"));
    assert!(names.contains(&"web-01"));
    let srv = entries
        .iter()
        .find(|e| e["name"].as_str() == Some("srv-01"))
        .unwrap();
    assert_eq!(srv["session_type"].as_str().unwrap(), "ssh");
    assert_eq!(srv["hostname"].as_str().unwrap(), "10.0.0.5");
}

#[tokio::test]
async fn test_ab_list_subfolders_db_backed() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    // Nested layout via slash-path folder names: Clients/Acme is a
    // subfolder of Clients.
    db::create_ab_folder(&db, "shared", "Clients", "", "", false).unwrap();
    let acme_id =
        db::create_ab_folder(&db, "shared", "Clients/Acme", "Acme subfolder", "", false).unwrap();
    db::create_ab_entry(
        &db,
        acme_id,
        "srv-01",
        "",
        "ssh",
        "10.9.0.1",
        Some(22),
        "",
        "{}",
        "",
    )
    .unwrap();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/addressbook/folders/shared/Clients/subfolders",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let subs = body.as_array().unwrap();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0]["name"].as_str().unwrap(), "Acme");
    assert_eq!(subs[0]["path"].as_str().unwrap(), "Clients/Acme");
    assert_eq!(subs[0]["description"].as_str().unwrap(), "Acme subfolder");
}

/// Vault CONNECTED but backend default "db": metadata must come from the DB
/// and the MockVault must stay untouched.
#[tokio::test]
async fn test_ab_db_backend_ignores_connected_vault() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "DBFolder", "db desc", "", false).unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "dbentry",
        "",
        "ssh",
        "10.1.1.1",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();

    let mock = mock_vault_with_it_folder();
    let app = build_test_router_with_vault(db, mock_vault_state(mock.clone()));

    let response = app
        .clone()
        .oneshot(make_auth_request("GET", "/api/addressbook/folders", &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let folders = body.as_array().unwrap();
    assert_eq!(
        folders.len(),
        1,
        "vault folders must not appear with the default db backend: {}",
        body
    );
    assert_eq!(folders[0]["name"].as_str().unwrap(), "DBFolder");

    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/addressbook/folders/shared/DBFolder/entries",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"].as_str().unwrap(), "dbentry");
    assert_eq!(entries[0]["hostname"].as_str().unwrap(), "10.1.1.1");

    // MockVault untouched: its seeded entries survive and nothing was
    // written for the DB-only folder.
    assert_eq!(mock.list_entries("shared", "IT").unwrap().len(), 2);
    assert!(mock.list_entries("shared", "DBFolder").unwrap().is_empty());
    assert!(mock.get_entry("shared", "IT", "srv-01").is_ok());
}

#[tokio::test]
async fn test_ab_list_folders_operator_filters_by_entry_groups() {
    let db = test_db();
    // Operator in group "team-it": sees IT (entry allowed team-it) but not
    // HR (team-hr). Folder descriptions are set so entry groups apply.
    insert_test_user(&db, "op@test.com", "Op", "operator");
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "UPDATE users SET oidc_groups = 'team-it' WHERE email = 'op@test.com'",
            [],
        )
        .unwrap();
    }
    let user = db::get_user_by_email(&db, "op@test.com").unwrap();
    let session = db::create_auth_session(&db, user.id, 3600).unwrap();

    let it_id = db::create_ab_folder(&db, "shared", "IT", "restricted", "", false).unwrap();
    db::create_ab_entry(
        &db,
        it_id,
        "it-01",
        "",
        "ssh",
        "10.0.0.1",
        Some(22),
        "",
        "{}",
        "team-it",
    )
    .unwrap();
    let hr_id = db::create_ab_folder(&db, "shared", "HR", "restricted", "", false).unwrap();
    db::create_ab_entry(
        &db,
        hr_id,
        "hr-01",
        "",
        "ssh",
        "10.0.0.2",
        Some(22),
        "",
        "{}",
        "team-hr",
    )
    .unwrap();

    let app = build_test_router(db);
    let mut req = Request::builder()
        .method("GET")
        .uri("/api/addressbook/folders")
        .header("cookie", format!("persea_session={}", session))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let folders = body.as_array().unwrap();
    let names: Vec<&str> = folders
        .iter()
        .map(|f| f["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["IT"],
        "operator must only see folders its group is allowed into: {}",
        body
    );
}

#[tokio::test]
async fn test_ab_list_entries_operator_denied() {
    let db = test_db();
    // Operator in group "team-other" hitting a folder restricted to
    // "team-sec" must get 403 on the entries listing.
    insert_test_user(&db, "op@test.com", "Op", "operator");
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "UPDATE users SET oidc_groups = 'team-other' WHERE email = 'op@test.com'",
            [],
        )
        .unwrap();
    }
    let user = db::get_user_by_email(&db, "op@test.com").unwrap();
    let session = db::create_auth_session(&db, user.id, 3600).unwrap();

    let folder_id = db::create_ab_folder(&db, "shared", "Sec", "restricted", "", false).unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "sec-01",
        "",
        "ssh",
        "10.0.0.9",
        Some(22),
        "",
        "{}",
        "team-sec",
    )
    .unwrap();

    let app = build_test_router(db);
    let mut req = Request::builder()
        .method("GET")
        .uri("/api/addressbook/folders/shared/Sec/entries")
        .header("cookie", format!("persea_session={}", session))
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// ── Address book: vault-credential mode (StorageBackend "vault") ──

#[tokio::test]
async fn test_ab_create_entry_vault_mode_writes_credentials_to_vault() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    db::create_ab_folder(&db, "shared", "VMode", "", "", false).unwrap();
    let mock = Arc::new(crate::testing::MockVault::new());
    let app = build_test_router_with_vault_and_backend(
        db.clone(),
        mock_vault_state(mock.clone()),
        Some("vault"),
    );
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/addressbook/folders/shared/VMode/entries",
            &key,
            json!({"name": "vm-01", "type": "ssh", "hostname": "10.0.0.7", "port": 22, "username": "root", "password": "vmsecret"}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Metadata in the DB...
    let folder = db::get_ab_folder(&db, "shared", "VMode").unwrap();
    let entries = db::list_ab_entries(&db, folder.id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "vm-01");
    // ...no DB credential rows (they belong to the vault now)...
    assert!(db::list_ab_credentials(&db, entries[0].id)
        .unwrap()
        .is_empty());
    // ...and the vault copy carries the credentials.
    let vault_entry = mock
        .get_entry("shared", "VMode", "vm-01")
        .expect("vault copy must exist after create in vault mode");
    assert_eq!(vault_entry.password.as_deref(), Some("vmsecret"));
    assert_eq!(vault_entry.hostname.as_deref(), Some("10.0.0.7"));
}

#[tokio::test]
async fn test_ab_delete_entry_vault_mode_removes_vault_copy() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "VMode", "", "", false).unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "vm-01",
        "",
        "ssh",
        "10.0.0.7",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
    let mock = Arc::new(crate::testing::MockVault::new().with_entry(
        "shared/VMode/vm-01",
        r#"{"type":"ssh","hostname":"10.0.0.7","password":"vmsecret"}"#,
    ));
    let app = build_test_router_with_vault_and_backend(
        db.clone(),
        mock_vault_state(mock.clone()),
        Some("vault"),
    );
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            "/api/addressbook/folders/shared/VMode/entries/vm-01",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let folder = db::get_ab_folder(&db, "shared", "VMode").unwrap();
    assert!(
        db::list_ab_entries(&db, folder.id).unwrap().is_empty(),
        "DB entry row must be gone"
    );
    assert!(
        mock.get_entry("shared", "VMode", "vm-01").is_err(),
        "vault copy must be gone in vault mode"
    );
}

#[tokio::test]
async fn test_ab_delete_folder_reports_subtree_counts() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    // Tree: Clients (1 entry) + Clients/Acme subfolder (2 entries); an
    // unrelated "Other" folder must survive.
    let clients_id = db::create_ab_folder(&db, "shared", "Clients", "", "", false).unwrap();
    db::create_ab_entry(
        &db,
        clients_id,
        "cli-01",
        "",
        "ssh",
        "10.0.0.1",
        Some(22),
        "",
        "{}",
        "",
    )
    .unwrap();
    let acme_id = db::create_ab_folder(&db, "shared", "Clients/Acme", "", "", false).unwrap();
    db::create_ab_entry(
        &db,
        acme_id,
        "acme-01",
        "",
        "ssh",
        "10.0.0.2",
        Some(22),
        "",
        "{}",
        "",
    )
    .unwrap();
    db::create_ab_entry(
        &db,
        acme_id,
        "acme-02",
        "",
        "ssh",
        "10.0.0.3",
        Some(22),
        "",
        "{}",
        "",
    )
    .unwrap();
    db::create_ab_folder(&db, "shared", "Other", "", "", false).unwrap();

    let app = build_test_router(db.clone());
    let response = app
        .oneshot(make_auth_request(
            "DELETE",
            "/api/addressbook/folders/shared/Clients",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["ok"].as_bool(), Some(true));
    assert_eq!(body["subfolders_deleted"].as_u64(), Some(1));
    assert_eq!(body["entries_deleted"].as_u64(), Some(3));

    assert!(db::get_ab_folder(&db, "shared", "Clients").is_err());
    assert!(db::get_ab_folder(&db, "shared", "Clients/Acme").is_err());
    assert!(db::get_ab_folder(&db, "shared", "Other").is_ok());
}

// ── Address book: connect credential sources (via /api/connect) ──

/// Router for `quick_connect` with a real SessionManager. The observable is
/// the credential prompt: an entry whose credentials resolved skips the
/// prompt and creates a session (307 redirect to /client/<id>); one without
/// credentials renders the prompt form (200).
fn build_quick_connect_router(
    db: Db,
    vault: VaultState,
    storage_key: Option<String>,
    backend: &str,
) -> axum::Router {
    use axum::routing::get;
    let mut config = crate::config::Config::default();
    // Keep the manager's recording dir out of the repo working dir.
    config.recording_path = Some(std::path::PathBuf::from(std::env::temp_dir()));
    let manager: super::AppState = Arc::new(crate::session::SessionManager::new(config, None));
    axum::Router::new()
        .route("/api/connect", get(super::quick_connect))
        .with_state(manager)
        .layer(axum::middleware::from_fn(crate::auth::require_auth))
        .layer(Extension(db))
        .layer(Extension(vault))
        .layer(Extension(OidcEnabled(false)))
        .layer(Extension(StorageKey(storage_key)))
        .layer(Extension(StorageBackend(backend.into())))
}

fn seed_ssh_entry(db: &Db, folder: &str, entry: &str) -> i64 {
    let folder_id = db::create_ab_folder(db, "shared", folder, "", "", false).unwrap();
    db::create_ab_entry(
        db,
        folder_id,
        entry,
        "",
        "ssh",
        "127.0.0.1",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap()
}

/// Control: without any stored credentials the connect flow renders the
/// credential prompt form (200) instead of attempting a session.
#[tokio::test]
async fn test_quick_connect_prompts_when_no_credentials() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    seed_ssh_entry(&db, "QC", "nocred");
    let app = build_quick_connect_router(db, test_vault_state(), None, "db");
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/connect?scope=shared&folder=QC&entry=nocred",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        html.contains("<form"),
        "expected the credential prompt form: {}",
        &html[..html.len().min(200)]
    );
}

#[tokio::test]
async fn test_quick_connect_reads_credentials_from_db() {
    if !guacd_reachable() || !ssh_target_reachable() {
        eprintln!("skipping: no guacd on 127.0.0.1:4822 or SSH target on 127.0.0.1:22");
        return;
    }
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let entry_id = seed_ssh_entry(&db, "QC", "dbcred");

    // Encrypted password in the DB credentials table.
    let enc_key = "a".repeat(64);
    let encrypted = crate::crypto::encrypt_value(
        &crate::crypto::EncryptionKey::from_hex(&enc_key).unwrap(),
        "sup3rs3cret",
    )
    .unwrap();
    db::store_ab_credential(&db, entry_id, "password", &encrypted).unwrap();

    // Vault is CONNECTED and holds a credential-less copy of the entry —
    // with backend "db" it must not be consulted.
    let mock = Arc::new(crate::testing::MockVault::new().with_entry(
        "shared/QC/dbcred",
        r#"{"type":"ssh","hostname":"127.0.0.1"}"#,
    ));
    let app = build_quick_connect_router(db, mock_vault_state(mock), Some(enc_key), "db");
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/connect?scope=shared&folder=QC&entry=dbcred",
            &key,
        ))
        .await
        .unwrap();
    // Password came from the DB → no prompt → session created → redirect to
    // the client page, not the 200 credential prompt form.
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/client/"),
        "expected redirect to the session: {}",
        location
    );
}

#[tokio::test]
async fn test_quick_connect_reads_credentials_from_vault() {
    if !guacd_reachable() || !ssh_target_reachable() {
        eprintln!("skipping: no guacd on 127.0.0.1:4822 or SSH target on 127.0.0.1:22");
        return;
    }
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    seed_ssh_entry(&db, "QC", "vaultcred");

    // No DB credentials; the vault copy carries the password.
    let mock = Arc::new(crate::testing::MockVault::new().with_entry(
        "shared/QC/vaultcred",
        r#"{"type":"ssh","hostname":"127.0.0.1","password":"vaultpass"}"#,
    ));
    let app = build_quick_connect_router(db, mock_vault_state(mock), None, "vault");
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/connect?scope=shared&folder=QC&entry=vaultcred",
            &key,
        ))
        .await
        .unwrap();
    // Password came from the vault copy → no prompt → session created →
    // redirect to the client page, not the 200 credential prompt form.
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    let location = response
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    assert!(
        location.starts_with("/client/"),
        "expected redirect to the session: {}",
        location
    );
}

// ── Address book: DB fallback when no Vault backend is connected ──

#[tokio::test]
async fn test_ab_list_folders_db_fallback() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    db::create_ab_folder(&db, "shared", "DBFolder", "desc", "", false).unwrap();
    let app = build_test_router(db); // empty vault cells — no backend connected
    let response = app
        .oneshot(make_auth_request("GET", "/api/addressbook/folders", &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let folders = body.as_array().unwrap();
    assert_eq!(folders.len(), 1);
    assert_eq!(folders[0]["name"].as_str().unwrap(), "DBFolder");
    assert_eq!(folders[0]["scope"].as_str().unwrap(), "shared");
}

#[tokio::test]
async fn test_ab_list_folders_db_fallback_empty() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request("GET", "/api/addressbook/folders", &key))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_ab_list_entries_db_fallback() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "DBFolder", "", "", false).unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "dbentry",
        "",
        "ssh",
        "10.1.1.1",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
    let app = build_test_router(db);
    let response = app
        .oneshot(make_auth_request(
            "GET",
            "/api/addressbook/folders/shared/DBFolder/entries",
            &key,
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    let entries = body.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["name"].as_str().unwrap(), "dbentry");
    assert_eq!(entries[0]["hostname"].as_str().unwrap(), "10.1.1.1");
}

#[tokio::test]
async fn test_ab_create_entry_db_fallback() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "DBFolder", "", "", false).unwrap();
    let app = build_test_router(db.clone());
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/addressbook/folders/shared/DBFolder/entries",
            &key,
            json!({"name": "dbentry2", "type": "vnc", "hostname": "10.2.2.2", "port": 5900}),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let db_entries = db::list_ab_entries(&db, folder_id).unwrap();
    assert_eq!(db_entries.len(), 1);
    assert_eq!(db_entries[0].name, "dbentry2");
    assert_eq!(db_entries[0].protocol, "vnc");
    assert_eq!(db_entries[0].hostname, "10.2.2.2");
}

#[tokio::test]
async fn test_ab_create_entry_db_fallback_missing_folder_fails() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/addressbook/folders/shared/NoSuchFolder/entries",
            &key,
            json!({"name": "x", "type": "ssh"}),
        ))
        .await
        .unwrap();
    // Missing folder is a client error, not a server error.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ── vSphere power action authorization ──
// `power_action` requires `operator` role or above. This regression test was
// missing — the role check was correct, but nothing exercised it.

#[tokio::test]
async fn test_vsphere_power_action_viewer_denied() {
    let db = test_db();
    insert_test_user(&db, "viewer@test.com", "Viewer", "viewer");
    let user = db::get_user_by_email(&db, "viewer@test.com").unwrap();
    let session = db::create_auth_session(&db, user.id, 3600).unwrap();

    let app = build_test_router(db);
    let mut req = Request::builder()
        .method("POST")
        .uri("/api/vsphere/vms/vm-01/power")
        .header("cookie", format!("persea_session={}", session))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({"action": "on"})).unwrap(),
        ))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(test_addr()));
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_vsphere_power_action_operator_passes_role_check() {
    let db = test_db();
    let key = insert_test_admin(&db, "admin");
    let app = build_test_router(db);
    let response = app
        .oneshot(make_json_request(
            "POST",
            "/api/vsphere/vms/vm-01/power",
            &key,
            json!({"action": "on"}),
        ))
        .await
        .unwrap();
    // The test router's VsphereState is always None (unconfigured) — the
    // point here is that an authorized role clears the 403 gate and reaches
    // the "not configured" error (502, via the collapsed infra-error arm in
    // error.rs) instead of being rejected for role, proving the check above
    // is a role gate and not a blanket rejection.
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}
