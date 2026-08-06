//! Tests for CSV import parsing and the address book import handlers.
//!
//! Parser tests cover the pure CSV state machine in `persea::csv_import`;
//! handler tests exercise `persea::api::imports` through a tower oneshot
//! router (pattern copied from `tests/api_handler_tests.rs`).
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::{get, post};
use axum::{middleware, Extension, Router};
use persea::api::StorageKey;
use persea::auth::TrustedProxies;
use persea::csv_import;
use persea::db::{self, Db};
use std::net::SocketAddr;
use tower::ServiceExt;

const HEADER: &str =
    "name,protocol,hostname,port,username,password,folder,display_name,allowed_groups";

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn test_router(db: Db) -> Router {
    test_router_with_key(db, None)
}

fn test_router_with_key(db: Db, storage_key: Option<String>) -> Router {
    let mut router = Router::new()
        .route(
            "/api/addressbook/import",
            post(persea::api::imports::import_csv),
        )
        .route(
            "/api/addressbook/import-template",
            get(persea::api::imports::import_template),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db));
    if let Some(key) = storage_key {
        router = router.layer(Extension(StorageKey(Some(key))));
    }
    router
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
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

fn sess_get(path: &str, tok: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(header::COOKIE, format!("persea_session={}", tok))
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ── Parser ──

#[test]
fn parse_valid_csv() {
    let csv = format!(
        "{}\n\
         web01,ssh,10.0.0.1,22,root,secret,Production/Web,Web Server 1,group1\n\
         portal,web,,443,,,Internal,Portal,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.errors.is_empty());
    assert!(result.skipped.is_empty());
    assert_eq!(result.rows.len(), 2);

    let r0 = &result.rows[0];
    assert_eq!(r0.name, "web01");
    assert_eq!(r0.protocol, "ssh");
    assert_eq!(r0.hostname, "10.0.0.1");
    assert_eq!(r0.port, Some(22));
    assert_eq!(r0.username, "root");
    assert_eq!(r0.password, "secret");
    assert_eq!(r0.folder, "Production/Web");
    assert_eq!(r0.display_name, "Web Server 1");
    assert_eq!(r0.allowed_groups, vec!["group1"]);

    let r1 = &result.rows[1];
    assert_eq!(r1.protocol, "web");
    assert_eq!(r1.hostname, "");
    assert_eq!(r1.port, Some(443));
    assert!(r1.allowed_groups.is_empty());
}

#[test]
fn parse_with_bom() {
    let csv = format!("\u{feff}{}\nMy Server,ssh,10.0.0.1,22,root,secret,Production/Web,My Server,\"group1,group2\"", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "My Server");
    assert_eq!(result.rows[0].allowed_groups, vec!["group1", "group2"]);
}

#[test]
fn parse_quoted_allowed_groups_with_commas() {
    let csv = format!(
        "{}\nweb,ssh,10.0.0.1,22,,,Root,,\"group1,group2, group3\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].allowed_groups,
        vec!["group1", "group2", "group3"]
    );
}

#[test]
fn parse_escaped_quotes_and_embedded_newline() {
    let csv = format!(
        "{}\n\"My \"\"Server\"\"\",ssh,10.0.0.1,22,,\"sec\"\"ret\",Root,,\"g1,g2\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "My \"Server\"");
    assert_eq!(result.rows[0].password, "sec\"ret");
    assert_eq!(result.rows[0].allowed_groups, vec!["g1", "g2"]);

    let csv = format!("{}\n\"line1\nline2\",ssh,10.0.0.1,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "line1\nline2");
}

#[test]
fn parse_crlf_line_endings() {
    let csv = format!("{}\r\nweb,ssh,10.0.0.1,22,,,Root,,\r\n", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "web");
}

#[test]
fn parse_bad_protocol() {
    let csv = format!("{}\nfoo,ftp,10.0.0.1,21,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].row, 1);
    assert!(result.errors[0].message.contains("invalid protocol 'ftp'"));
}

#[test]
fn parse_missing_hostname_non_web() {
    let csv = format!("{}\nfoo,ssh,,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].row, 1);
    assert!(result.errors[0]
        .message
        .contains("hostname is required for protocol 'ssh'"));
}

#[test]
fn parse_web_without_hostname_allowed() {
    let csv = format!("{}\nportal,web,,443,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "web");
    assert_eq!(result.rows[0].hostname, "");
}

#[test]
fn parse_missing_name() {
    let csv = format!("{}\n,ssh,10.0.0.1,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors[0].message, "name is required");
}

#[test]
fn parse_invalid_port() {
    let csv = format!("{}\nx,ssh,10.0.0.1,70000,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors[0].message.contains("invalid port '70000'"));

    let csv = format!("{}\nx,ssh,10.0.0.1,abc,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors[0].message.contains("invalid port 'abc'"));
}

#[test]
fn parse_duplicate_rows_skipped() {
    let csv = format!(
        "{}\ndup,ssh,10.0.0.1,22,,,Root,,\ndup,ssh,10.0.0.2,22,,,Root,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].hostname, "10.0.0.1");
    assert_eq!(result.skipped, vec![2]);
    assert!(result.errors.is_empty());
}

#[test]
fn parse_same_name_different_folders_ok() {
    let csv = format!(
        "{}\ndup,ssh,10.0.0.1,22,,,A,,\ndup,ssh,10.0.0.1,22,,,B,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert!(result.skipped.is_empty());
}

#[test]
fn parse_duplicate_after_invalid_row_imports() {
    // First occurrence is invalid; the duplicate of it must still import.
    let csv = format!(
        "{}\nbad,ftp,10.0.0.1,21,,,Root,,\nbad,ssh,10.0.0.1,22,,,Root,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "ssh");
    assert!(result.skipped.is_empty());
}

#[test]
fn parse_empty_input() {
    let err = csv_import::parse_rows("").unwrap_err();
    assert_eq!(err.row, 0);
    assert!(err.message.contains("empty CSV"));
}

#[test]
fn parse_header_only_no_rows() {
    let result = csv_import::parse_rows(HEADER).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors.is_empty());
    assert!(result.skipped.is_empty());
}

#[test]
fn parse_invalid_header() {
    let err = csv_import::parse_rows("foo,bar\n1,2\n").unwrap_err();
    assert_eq!(err.row, 0);
    assert!(err.message.contains("invalid header"));
}

#[test]
fn parse_header_case_insensitive() {
    let csv = "Name,Protocol,Hostname,Port,Username,Password,Folder,Display_Name,Allowed_Groups\nx,ssh,1.2.3.4,22,,,Root,,";
    let result = csv_import::parse_rows(csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "x");
}

#[test]
fn parse_unterminated_quote() {
    let err = csv_import::parse_rows("\"never closed\n").unwrap_err();
    assert!(err.message.contains("unterminated quoted field"));
}

#[test]
fn parse_blank_lines_ignored() {
    let csv = format!("{}\n\nx,ssh,1.2.3.4,22,,,Root,,\n\n", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "x");
}

#[test]
fn parse_too_many_columns() {
    let csv = format!("{}\nx,ssh,1.2.3.4,22,,,Root,,,extra", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].message.contains("too many columns"));
}

#[test]
fn parse_protocol_case_and_whitespace_normalized() {
    let csv = format!("{}\nX, SSH ,1.2.3.4,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "ssh");
}

#[test]
fn parse_short_row_padded() {
    let csv = format!("{}\nx,ssh,1.2.3.4", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].hostname, "1.2.3.4");
    assert_eq!(result.rows[0].username, "");
    assert_eq!(result.rows[0].folder, "");
}

#[test]
fn parse_duplicate_groups_deduped() {
    let csv = format!("{}\nx,ssh,1.2.3.4,22,,,Root,,\"a,b,a, c\"", HEADER);
    let result = csv_import::parse_rows(&csv).unwrap();
    assert_eq!(result.rows[0].allowed_groups, vec!["a", "b", "c"]);
}

#[test]
fn render_template_matches_contract() {
    let template = csv_import::render_template();
    let lines: Vec<&str> = template.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines[0],
        "name,protocol,hostname,port,username,password,folder,display_name,allowed_groups"
    );
    assert_eq!(
        lines[1],
        "My Server,ssh,10.0.0.1,22,root,secret,Production/Web,My Server,\"group1,group2\""
    );
    // The template must round-trip through the parser.
    let result = csv_import::parse_rows(&template).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "My Server");
    assert_eq!(result.rows[0].folder, "Production/Web");
    assert_eq!(result.rows[0].allowed_groups, vec!["group1", "group2"]);
}

// ── Import handler ──

#[tokio::test]
async fn import_creates_entries_and_folders() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "scope": "shared",
                "rows": [
                    {
                        "name": "web01",
                        "protocol": "ssh",
                        "hostname": "10.0.0.1",
                        "port": 22,
                        "username": "root",
                        "password": "secret",
                        "folder": "Production/Web",
                        "display_name": "Web 1",
                        "allowed_groups": ["group1", "group2"]
                    },
                    {
                        "name": "portal",
                        "protocol": "web",
                        "hostname": "",
                        "port": 443,
                        "folder": "",
                        "display_name": "Portal"
                    }
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 2);
    assert_eq!(json["skipped"], 0);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    // Folder hierarchy created level by level.
    let prod = db::get_ab_folder(&db, "shared", "Production").unwrap();
    let web = db::get_ab_folder(&db, "shared", "Production/Web").unwrap();
    // Empty folder path resolves to the scope-root folder.
    let root = db::get_ab_folder(&db, "shared", "").unwrap();

    let e1 = db::get_ab_entry(&db, web.id, "web01").unwrap();
    assert_eq!(e1.protocol, "ssh");
    assert_eq!(e1.hostname, "10.0.0.1");
    assert_eq!(e1.port, Some(22));
    assert_eq!(e1.username, "root");
    assert_eq!(e1.display_name, "Web 1");
    assert_eq!(e1.allowed_groups, "group1,group2");

    let e2 = db::get_ab_entry(&db, root.id, "portal").unwrap();
    assert_eq!(e2.protocol, "web");
    assert_eq!(e2.hostname, "");
    assert_eq!(e2.port, Some(443));
    assert!(prod.id != 0 && web.id != 0 && root.id != 0);
}

#[tokio::test]
async fn import_scope_instance() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "scope": "instance",
                "rows": [{"name": "localbox", "protocol": "ssh", "hostname": "192.168.1.5", "port": 22}]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);

    let folder = db::get_ab_folder(&db, "instance", "").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "localbox").unwrap();
    assert_eq!(entry.hostname, "192.168.1.5");
}

#[tokio::test]
async fn import_skips_in_file_duplicates() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [
                    {"name": "dup", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "folder": "Root"},
                    {"name": "dup", "protocol": "ssh", "hostname": "10.0.0.2", "port": 22, "folder": "Root"}
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["skipped"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entries = db::list_ab_entries(&db, folder.id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].hostname, "10.0.0.1");
}

#[tokio::test]
async fn import_skips_existing_db_entries() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let folder_id = db::create_ab_folder(&db, "shared", "Existing", "").unwrap();
    db::create_ab_entry(
        &db,
        folder_id,
        "dup",
        "",
        "ssh",
        "10.0.0.1",
        Some(22),
        "",
        "{}",
        "",
    )
    .unwrap();

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "dup", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "folder": "Existing"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["skipped"], 1);
    assert_eq!(db::list_ab_entries(&db, folder_id).unwrap().len(), 1);
}

#[tokio::test]
async fn import_reports_row_errors() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [
                    {"name": "good", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22},
                    {"name": "badproto", "protocol": "ftp", "hostname": "10.0.0.2", "port": 21},
                    {"name": "nohost", "protocol": "ssh", "port": 22},
                    {"name": "", "protocol": "ssh", "hostname": "10.0.0.3", "port": 22}
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["skipped"], 0);
    let errors = json["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 3);
    assert_eq!(errors[0]["row"], 2);
    assert!(errors[0]["error"]
        .as_str()
        .unwrap()
        .contains("invalid protocol 'ftp'"));
    assert_eq!(errors[1]["row"], 3);
    assert!(errors[1]["error"]
        .as_str()
        .unwrap()
        .contains("hostname is required"));
    assert_eq!(errors[2]["row"], 4);
    assert!(errors[2]["error"]
        .as_str()
        .unwrap()
        .contains("name is required"));

    // Only the valid row was written.
    let folder = db::get_ab_folder(&db, "shared", "").unwrap();
    let entries = db::list_ab_entries(&db, folder.id).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].name, "good");
}

#[tokio::test]
async fn import_empty_rows() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({"rows": []}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["skipped"], 0);
    assert!(json["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn import_requires_admin_role() {
    let db = test_db();
    db::upsert_user(&db, "op@test.com", "Op", None, "operator", &[]).unwrap();
    db::upsert_user(&db, "view@test.com", "View", None, "viewer", &[]).unwrap();
    let op_session = {
        let user = db::get_user_by_email(&db, "op@test.com").unwrap();
        db::create_auth_session(&db, user.id, 3600).unwrap()
    };
    let view_session = {
        let user = db::get_user_by_email(&db, "view@test.com").unwrap();
        db::create_auth_session(&db, user.id, 3600).unwrap()
    };

    let body = serde_json::json!({
        "rows": [{"name": "x", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22}]
    });

    let router = test_router(db.clone());
    let resp = router
        .oneshot(sess_post(
            "/api/addressbook/import",
            &op_session,
            body.clone(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let router = test_router(db.clone());
    let resp = router
        .oneshot(sess_post("/api/addressbook/import", &view_session, body))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn import_requires_auth() {
    let router = test_router(test_db());
    let resp = router
        .oneshot(no_auth_get("/api/addressbook/import"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn import_stores_encrypted_password() {
    let key = "ab".repeat(32); // 64 hex chars = 32 bytes
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router_with_key(db.clone(), Some(key.clone()));
    let resp = router
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "hunter2"}]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);

    let folder = db::get_ab_folder(&db, "shared", "").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();
    let creds = db::list_ab_credentials(&db, entry.id).unwrap();
    assert_eq!(creds.len(), 1);
    assert_eq!(creds[0].credential_type, "password");
    assert_ne!(creds[0].credential_data, "hunter2");
    let enc_key = persea::crypto::EncryptionKey::from_hex(&key).unwrap();
    let decrypted = persea::crypto::decrypt_value(&enc_key, &creds[0].credential_data).unwrap();
    assert_eq!(decrypted, "hunter2");
}

#[tokio::test]
async fn import_without_storage_key_drops_password() {
    // Guard against a PERSEA_STORAGE_KEY leaking in from the environment.
    std::env::set_var("PERSEA_STORAGE_KEY", "");
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "hunter2"}]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let folder = db::get_ab_folder(&db, "shared", "").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();
    assert!(db::list_ab_credentials(&db, entry.id).unwrap().is_empty());
}

// ── Template handler ──

#[tokio::test]
async fn template_download_ok() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(
            Request::builder()
                .uri("/api/addressbook/import-template")
                .header(header::AUTHORIZATION, format!("Bearer {}", key))
                .extension(fake_addr())
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(content_type.starts_with("text/csv"));
    let disposition = resp
        .headers()
        .get(header::CONTENT_DISPOSITION)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(disposition.contains("attachment"));
    assert!(disposition.contains("persea-connections-template.csv"));
    assert_eq!(body_text(resp).await, csv_import::render_template());
}

#[tokio::test]
async fn template_available_to_operator() {
    let db = test_db();
    db::upsert_user(&db, "op@test.com", "Op", None, "operator", &[]).unwrap();
    let session = {
        let user = db::get_user_by_email(&db, "op@test.com").unwrap();
        db::create_auth_session(&db, user.id, 3600).unwrap()
    };
    let router = test_router(db);
    let resp = router
        .oneshot(sess_get("/api/addressbook/import-template", &session))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn template_forbidden_for_viewer() {
    let db = test_db();
    db::upsert_user(&db, "view@test.com", "View", None, "viewer", &[]).unwrap();
    let session = {
        let user = db::get_user_by_email(&db, "view@test.com").unwrap();
        db::create_auth_session(&db, user.id, 3600).unwrap()
    };
    let router = test_router(db);
    let resp = router
        .oneshot(sess_get("/api/addressbook/import-template", &session))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn template_requires_auth() {
    let router = test_router(test_db());
    let resp = router
        .oneshot(no_auth_get("/api/addressbook/import-template"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
