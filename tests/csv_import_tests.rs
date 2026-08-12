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
    "name,protocol,hostname,port,username,password,folder,allowed_groups,description";

const LEGACY_HEADER: &str =
    "name,protocol,hostname,port,username,password,folder,display_name,allowed_groups,description";

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

fn admin_csv_post(key: &str, path: &str, csv: &str) -> Request<axum::body::Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .header(header::CONTENT_TYPE, "text/csv")
        .extension(fake_addr())
        .body(axum::body::Body::from(csv.to_string()))
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

/// Insert the `custom_fields` definitions into the settings store (the same
/// shape `PUT /api/system/settings` would write: a JSON array of
/// `{"name": ..., "type": ...}` objects serialized into the value column).
fn set_custom_fields(db: &Db, fields: &[(&str, &str)]) {
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS system_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .unwrap();
    let value = serde_json::to_string(
        &fields
            .iter()
            .map(|(n, t)| serde_json::json!({"name": n, "type": t}))
            .collect::<Vec<_>>(),
    )
    .unwrap();
    conn.execute(
        "INSERT INTO system_settings (key, value, updated_at)
         VALUES ('custom_fields', ?1, CURRENT_TIMESTAMP)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        rusqlite::params![value],
    )
    .unwrap();
}

/// Insert an entry directly into the DB (bypassing the import handler), the
/// way a previous import would have left it. Returns the folder ID.
fn insert_entry(db: &Db, scope: &str, folder: &str, name: &str, display_name: &str) -> i64 {
    let folder_id = match db::get_ab_folder(db, scope, folder) {
        Ok(f) => f.id,
        Err(_) => db::create_ab_folder(db, scope, folder, "", "", false).unwrap(),
    };
    db::create_ab_entry(
        db,
        folder_id,
        name,
        display_name,
        "ssh",
        "10.0.0.1",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
    folder_id
}

// ── Parser ──

#[test]
fn parse_valid_csv() {
    let csv = format!(
        "{}\n\
         web01,ssh,10.0.0.1,22,root,secret,Production/Web,group1,Production web server\n\
         portal,web,,443,,,Internal,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
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
    assert_eq!(r0.allowed_groups, vec!["group1"]);
    assert_eq!(r0.description, "Production web server");
    assert!(r0.custom_fields.is_empty());

    let r1 = &result.rows[1];
    assert_eq!(r1.protocol, "web");
    assert_eq!(r1.hostname, "");
    assert_eq!(r1.port, Some(443));
    assert!(r1.allowed_groups.is_empty());
    assert_eq!(r1.description, "");
}

#[test]
fn parse_description_with_commas_quoted() {
    let csv = format!(
        "{}\nweb,ssh,10.0.0.1,22,,,Root,\"a,b\",\"Web server, DMZ\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].allowed_groups, vec!["a", "b"]);
    assert_eq!(result.rows[0].description, "Web server, DMZ");
}

#[test]
fn parse_with_bom() {
    let csv = format!(
        "\u{feff}{}\nMy Server,ssh,10.0.0.1,22,root,secret,Production/Web,\"group1,group2\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "My Server");
    assert_eq!(result.rows[0].allowed_groups, vec!["group1", "group2"]);
}

#[test]
fn parse_quoted_allowed_groups_with_commas() {
    let csv = format!(
        "{}\nweb,ssh,10.0.0.1,22,,,Root,\"group1,group2, group3\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(
        result.rows[0].allowed_groups,
        vec!["group1", "group2", "group3"]
    );
}

#[test]
fn parse_escaped_quotes_and_embedded_newline() {
    let csv = format!(
        "{}\n\"My \"\"Server\"\"\",ssh,10.0.0.1,22,,\"sec\"\"ret\",Root,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "My \"Server\"");
    assert_eq!(result.rows[0].password, "sec\"ret");

    let csv = format!("{}\n\"line1\nline2\",ssh,10.0.0.1,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "line1\nline2");
}

#[test]
fn parse_crlf_line_endings() {
    let csv = format!("{}\r\nweb,ssh,10.0.0.1,22,,,Root,,\r\n", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "web");
}

#[test]
fn parse_bad_protocol() {
    let csv = format!("{}\nfoo,ftp,10.0.0.1,21,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.errors[0].row, 1);
    assert!(result.errors[0].message.contains("invalid protocol 'ftp'"));
}

#[test]
fn parse_missing_hostname_non_web() {
    let csv = format!("{}\nfoo,ssh,,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
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
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "web");
    assert_eq!(result.rows[0].hostname, "");
}

#[test]
fn parse_missing_name() {
    let csv = format!("{}\n,ssh,10.0.0.1,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors[0].message, "name is required");
}

#[test]
fn parse_invalid_port() {
    let csv = format!("{}\nx,ssh,10.0.0.1,70000,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors[0].message.contains("invalid port '70000'"));

    let csv = format!("{}\nx,ssh,10.0.0.1,abc,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors[0].message.contains("invalid port 'abc'"));
}

#[test]
fn parse_duplicate_rows_skipped() {
    let csv = format!(
        "{}\ndup,ssh,10.0.0.1,22,,,Root,,\ndup,ssh,10.0.0.2,22,,,Root,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
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
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
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
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.errors.len(), 1);
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "ssh");
    assert!(result.skipped.is_empty());
}

#[test]
fn parse_empty_input() {
    let err = csv_import::parse_rows("", &[]).unwrap_err();
    assert_eq!(err.row, 0);
    assert!(err.message.contains("empty CSV"));
}

#[test]
fn parse_header_only_no_rows() {
    let result = csv_import::parse_rows(HEADER, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert!(result.errors.is_empty());
    assert!(result.skipped.is_empty());
}

#[test]
fn parse_invalid_header() {
    let err = csv_import::parse_rows("foo,bar\n1,2\n", &[]).unwrap_err();
    assert_eq!(err.row, 0);
    assert!(err.message.contains("invalid header"));
}

#[test]
fn parse_header_wrong_column_reported() {
    // The fixed columns must match one by one; the error names the culprit.
    let err = csv_import::parse_rows(
        "name,protocol,host,port,username,password,folder,allowed_groups,description\nx,ssh,1.2.3.4,22,,,Root,,",
        &[],
    )
    .unwrap_err();
    assert!(err.message.contains("invalid header"));
    assert!(err.message.contains("column 3"));
    assert!(err.message.contains("'hostname'"));

    // Truncated headers are reported as missing columns.
    let err = csv_import::parse_rows("name,protocol,hostname,port\n", &[]).unwrap_err();
    assert!(err.message.contains("column 5"));
    assert!(err.message.contains("'username'"));
}

#[test]
fn parse_legacy_header_rejected() {
    // The pre-T08 template (with display_name) must be rejected with a
    // pointer at the current template, not a generic column mismatch.
    let csv = format!("{}\nweb,ssh,10.0.0.1,22,,,Root,Web 1,,", LEGACY_HEADER);
    let err = csv_import::parse_rows(&csv, &[]).unwrap_err();
    assert_eq!(err.row, 0);
    assert!(
        err.message.contains("OLD 10-column template"),
        "{}",
        err.message
    );
    assert!(err.message.contains("display_name"), "{}", err.message);
    assert!(err.message.contains("import-template"), "{}", err.message);
}

#[test]
fn parse_header_case_insensitive() {
    let csv = "Name,Protocol,Hostname,Port,Username,Password,Folder,Allowed_Groups,Description\nx,ssh,1.2.3.4,22,,,Root,,";
    let result = csv_import::parse_rows(csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "x");
}

#[test]
fn parse_unterminated_quote() {
    let err = csv_import::parse_rows("\"never closed\n", &[]).unwrap_err();
    assert!(err.message.contains("unterminated quoted field"));
}

#[test]
fn parse_blank_lines_ignored() {
    let csv = format!("{}\n\nx,ssh,1.2.3.4,22,,,Root,,\n\n", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].name, "x");
}

#[test]
fn parse_too_many_columns() {
    let csv = format!("{}\nx,ssh,1.2.3.4,22,,,Root,,,,extra", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(result.errors[0].message.contains("too many columns"));
}

#[test]
fn parse_protocol_case_and_whitespace_normalized() {
    let csv = format!("{}\nX, SSH ,1.2.3.4,22,,,Root,,", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].protocol, "ssh");
}

#[test]
fn parse_short_row_padded() {
    let csv = format!("{}\nx,ssh,1.2.3.4", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert_eq!(result.rows[0].hostname, "1.2.3.4");
    assert_eq!(result.rows[0].username, "");
    assert_eq!(result.rows[0].folder, "");
}

#[test]
fn parse_duplicate_groups_deduped() {
    let csv = format!("{}\nx,ssh,1.2.3.4,22,,,Root,\"a,b,a, c\"", HEADER);
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows[0].allowed_groups, vec!["a", "b", "c"]);
}

#[test]
fn parse_custom_field_columns() {
    let defs = vec!["Environment".to_string(), "Owner".to_string()];
    let csv = format!(
        "{},Environment,Owner\nweb01,ssh,10.0.0.1,22,root,secret,Prod,group1,desc,Production,alice\nweb02,ssh,10.0.0.2,22,,,Prod,,,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &defs).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(
        result.rows[0].custom_fields,
        vec![
            ("Environment".to_string(), "Production".to_string()),
            ("Owner".to_string(), "alice".to_string()),
        ]
    );
    // Empty trailing cells are kept verbatim.
    assert_eq!(
        result.rows[1].custom_fields,
        vec![
            ("Environment".to_string(), String::new()),
            ("Owner".to_string(), String::new()),
        ]
    );
}

#[test]
fn parse_custom_field_column_case_sensitive() {
    let defs = vec!["Environment".to_string()];
    // Wrong case must be rejected (trimmed + case-sensitive match).
    let csv = format!(
        "{},environment\nweb01,ssh,10.0.0.1,22,,,Prod,,,production",
        HEADER
    );
    let err = csv_import::parse_rows(&csv, &defs).unwrap_err();
    assert!(err.message.contains("column 10"), "{}", err.message);
    assert!(err.message.contains("'environment'"), "{}", err.message);
    assert!(err.message.contains("Environment"), "{}", err.message);
}

#[test]
fn parse_custom_field_column_when_none_configured_rejected() {
    let csv = format!(
        "{},Environment\nweb01,ssh,10.0.0.1,22,,,Prod,,,production",
        HEADER
    );
    let err = csv_import::parse_rows(&csv, &[]).unwrap_err();
    assert!(err.message.contains("column 10"), "{}", err.message);
    assert!(
        err.message.contains("none are configured"),
        "{}",
        err.message
    );
}

#[test]
fn parse_optional_settings_any_order_case_insensitive() {
    // A shuffled, mixed-case subset of the optional settings columns.
    let csv = format!(
        "{},Disable_Paste,Security,COLOR_DEPTH,domain\n\
         win,rdp,10.0.0.50,3389,admin,secret,Windows,,gateway,false,nla,24,corp.example.com",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    let s = &result.rows[0].settings;
    assert_eq!(s.disable_paste, Some(false));
    assert_eq!(s.security.as_deref(), Some("nla"));
    assert_eq!(s.color_depth, Some(24));
    assert_eq!(s.domain.as_deref(), Some("corp.example.com"));
    assert_eq!(s.enable_gfx, None);
    assert_eq!(s.auth_pkg, None);
}

#[test]
fn parse_optional_settings_blank_cells_are_none() {
    let csv = format!(
        "{},security,enable_gfx,color_depth,domain\n\
         win,rdp,10.0.0.50,3389,,,Windows,,gateway,,,,",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    let s = &result.rows[0].settings;
    assert_eq!(s.security, None);
    assert_eq!(s.enable_gfx, None);
    assert_eq!(s.color_depth, None);
    assert_eq!(s.domain, None);
}

#[test]
fn parse_optional_settings_bool_case_insensitive() {
    let csv = format!(
        "{},enable_gfx,ignore_cert\n\
         win,rdp,10.0.0.50,3389,,,Windows,,gateway,TRUE,False",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(result.rows[0].settings.enable_gfx, Some(true));
    assert_eq!(result.rows[0].settings.ignore_cert, Some(false));
}

#[test]
fn parse_optional_settings_invalid_bool_and_depth() {
    let csv = format!(
        "{},enable_gfx,color_depth\n\
         win,rdp,10.0.0.50,3389,,,Windows,,gateway,maybe,999",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert!(result.rows.is_empty());
    assert_eq!(result.errors.len(), 1);
    assert!(
        result.errors[0].message.contains("invalid boolean 'maybe'"),
        "{}",
        result.errors[0].message
    );
    assert!(
        result.errors[0].message.contains("enable_gfx"),
        "{}",
        result.errors[0].message
    );
    assert!(
        result.errors[0].message.contains("invalid color_depth '999'"),
        "{}",
        result.errors[0].message
    );
}

#[test]
fn parse_optional_settings_private_key_column() {
    let csv = format!(
        "{},private_key\n\
         srv,ssh,10.0.0.1,22,,,Root,,server key,sk-ssh-ed25519-abc",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(
        result.rows[0].private_key.as_deref(),
        Some("sk-ssh-ed25519-abc")
    );
}

#[test]
fn parse_optional_settings_quoted_private_key_preserves_newlines() {
    let csv = format!(
        "{},private_key\n\
         srv,ssh,10.0.0.1,22,,,Root,,server key,\"-----BEGIN OPENSSH PRIVATE KEY-----\nabcdef\n-----END OPENSSH PRIVATE KEY-----\"",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &[]).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    let key = result.rows[0].private_key.clone().unwrap();
    assert!(key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(key.contains('\n'));
    assert!(key.ends_with("-----END OPENSSH PRIVATE KEY-----"));
}

#[test]
fn parse_optional_settings_unknown_column_rejected() {
    let csv = format!(
        "{},security,audio_pkg\n\
         win,rdp,10.0.0.50,3389,,,Windows,,gateway,nla,opus",
        HEADER
    );
    let err = csv_import::parse_rows(&csv, &[]).unwrap_err();
    assert_eq!(err.row, 0);
    assert!(err.message.contains("column 11"), "{}", err.message);
    assert!(err.message.contains("'audio_pkg'"), "{}", err.message);
    assert!(
        err.message.contains("optional settings column"),
        "{}",
        err.message
    );
}

#[test]
fn parse_optional_settings_duplicate_column_rejected() {
    let csv = format!(
        "{},security,domain,security\n\
         win,rdp,10.0.0.50,3389,,,Windows,,gateway,nla,corp,nla",
        HEADER
    );
    let err = csv_import::parse_rows(&csv, &[]).unwrap_err();
    assert_eq!(err.row, 0);
    assert!(
        err.message.contains("appears more than once"),
        "{}",
        err.message
    );
    assert!(err.message.contains("'security'"), "{}", err.message);
}

#[test]
fn parse_custom_and_optional_columns_mixed() {
    // A custom-field column may appear before optional settings columns.
    let defs = vec!["Environment".to_string(), "Owner".to_string()];
    let csv = format!(
        "{},Environment,security,Owner\n\
         web01,ssh,10.0.0.1,22,,,Prod,,desc,Production,nla,alice",
        HEADER
    );
    let result = csv_import::parse_rows(&csv, &defs).unwrap();
    assert_eq!(result.rows.len(), 1);
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(
        result.rows[0].custom_fields,
        vec![
            ("Environment".to_string(), "Production".to_string()),
            ("Owner".to_string(), "alice".to_string()),
        ]
    );
    assert_eq!(result.rows[0].settings.security.as_deref(), Some("nla"));
}

#[test]
fn render_template_matches_contract() {
    let template = csv_import::render_template(&[]);
    let lines: Vec<&str> = template.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(
        lines[0],
        format!(
            "{},domain,security,ignore_cert,color_depth,remote_app,enable_gfx,enable_drive,disable_copy,disable_paste,auth_pkg,kdc_url,prompt_credentials,private_key",
            HEADER
        )
    );
    // RDP example row: several settings filled in.
    assert!(lines[1].starts_with("RDP example,rdp,192.168.10.20,3389,Administrator,"));
    assert!(lines[1].contains("corp.example.com,nla,false,32,,"));
    assert!(lines[1].contains(",true,false,true,false,,,false"));
    assert!(lines[1].contains("leave blank whatever is not needed"));
    // Minimal SSH row: nothing beyond the fixed columns.
    assert!(lines[2].starts_with("SSH example,ssh,10.0.0.1,22,root,"));
    assert!(lines[2].contains("leave blank whatever is not needed"));

    // The template must round-trip through the parser.
    let result = csv_import::parse_rows(&template, &[]).unwrap();
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(result.rows.len(), 2);
    let r0 = &result.rows[0];
    assert_eq!(r0.name, "RDP example");
    assert_eq!(r0.folder, "Production/RDP");
    assert_eq!(r0.allowed_groups, vec!["group1", "group2"]);
    assert_eq!(r0.settings.domain.as_deref(), Some("corp.example.com"));
    assert_eq!(r0.settings.security.as_deref(), Some("nla"));
    assert_eq!(r0.settings.ignore_cert, Some(false));
    assert_eq!(r0.settings.color_depth, Some(32));
    assert_eq!(r0.settings.enable_gfx, Some(true));
    assert_eq!(r0.settings.disable_copy, Some(true));
    assert_eq!(r0.settings.disable_paste, Some(false));
    assert_eq!(r0.settings.remote_app, None);
    assert_eq!(r0.settings.auth_pkg, None);
    assert_eq!(r0.settings.kdc_url, None);
    assert_eq!(r0.settings.prompt_credentials, Some(false));
    assert_eq!(r0.private_key, None);
    let r1 = &result.rows[1];
    assert_eq!(r1.name, "SSH example");
    assert_eq!(r1.protocol, "ssh");
    assert_eq!(
        r1.settings,
        csv_import::RowSettings {
            domain: None,
            security: None,
            ignore_cert: None,
            color_depth: None,
            remote_app: None,
            enable_gfx: None,
            enable_drive: None,
            disable_copy: None,
            disable_paste: None,
            auth_pkg: None,
            kdc_url: None,
            prompt_credentials: None,
        }
    );
    assert_eq!(r1.private_key, None);
}

#[test]
fn render_template_with_custom_fields_round_trips() {
    let defs = vec!["Environment".to_string(), "Owner".to_string()];
    let template = csv_import::render_template(&defs);
    let lines: Vec<&str> = template.lines().collect();
    assert_eq!(
        lines[0],
        format!(
            "{},domain,security,ignore_cert,color_depth,remote_app,enable_gfx,enable_drive,disable_copy,disable_paste,auth_pkg,kdc_url,prompt_credentials,private_key,Environment,Owner",
            HEADER
        )
    );
    assert!(lines[1].ends_with(",Example value,Example value"));
    assert!(lines[2].ends_with(",,"));

    // The dynamic template must round-trip through the parser with the
    // same definitions.
    let result = csv_import::parse_rows(&template, &defs).unwrap();
    assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].name, "RDP example");
    assert_eq!(
        result.rows[0].custom_fields,
        vec![
            ("Environment".to_string(), "Example value".to_string()),
            ("Owner".to_string(), "Example value".to_string()),
        ]
    );
    // The minimal SSH row leaves custom fields blank.
    assert_eq!(
        result.rows[1].custom_fields,
        vec![
            ("Environment".to_string(), String::new()),
            ("Owner".to_string(), String::new()),
        ]
    );
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
    assert_eq!(json["updated"], 0);
    assert_eq!(json["unchanged"], 0);
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
async fn import_slugifies_friendly_names() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [
                    {
                        "name": "My Web Server!",
                        "protocol": "ssh",
                        "hostname": "10.0.0.1",
                        "port": 22
                    }
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);

    let folder = db::get_ab_folder(&db, "shared", "").unwrap();
    let entries = db::list_ab_entries(&db, folder.id).unwrap();
    assert_eq!(entries.len(), 1);
    // The stored identifier is the slug; the friendly name is display_name.
    assert_eq!(entries[0].name, "my-web-server");
    assert_eq!(entries[0].display_name, "My Web Server!");
}

#[tokio::test]
async fn import_stores_description_in_protocol_config() {
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
                        "folder": "Production",
                        "description": "Production web server, DMZ"
                    },
                    {
                        "name": "bare",
                        "protocol": "ssh",
                        "hostname": "10.0.0.2",
                        "port": 22,
                        "folder": "Production"
                    }
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 2);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let folder = db::get_ab_folder(&db, "shared", "Production").unwrap();
    let e1 = db::get_ab_entry(&db, folder.id, "web01").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&e1.protocol_config).unwrap();
    assert_eq!(cfg["description"], "Production web server, DMZ");

    let e2 = db::get_ab_entry(&db, folder.id, "bare").unwrap();
    let cfg2: serde_json::Value = serde_json::from_str(&e2.protocol_config).unwrap();
    assert!(cfg2.get("description").is_none());
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
                "mode": "create",
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
async fn import_create_mode_skips_existing_entries() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let folder_id = insert_entry(&db, "shared", "Existing", "dup", "");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "mode": "create",
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
async fn import_upsert_counts_identical_as_unchanged() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let folder_id = insert_entry(&db, "shared", "Existing", "dup", "Dup");

    // Same slug, identical importable fields → unchanged, no write.
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "dup", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "username": "root", "folder": "Existing"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["updated"], 0);
    assert_eq!(json["unchanged"], 1);
    assert_eq!(json["skipped"], 0);
    assert_eq!(db::list_ab_entries(&db, folder_id).unwrap().len(), 1);
}

#[tokio::test]
async fn import_upsert_updates_changed_existing() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let folder_id = insert_entry(&db, "shared", "Existing", "dup", "Dup");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{
                    "name": "dup",
                    "protocol": "ssh",
                    "hostname": "10.0.0.2",
                    "port": 2222,
                    "username": "admin",
                    "folder": "Existing",
                    "description": "moved"
                }]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["updated"], 1);
    assert_eq!(json["unchanged"], 0);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let entry = db::get_ab_entry(&db, folder_id, "dup").unwrap();
    assert_eq!(entry.hostname, "10.0.0.2");
    assert_eq!(entry.port, Some(2222));
    assert_eq!(entry.username, "admin");
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["description"], "moved");
}

#[tokio::test]
async fn import_update_mode_only_touches_existing() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let folder_id = insert_entry(&db, "shared", "Existing", "dup", "Dup");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "mode": "update",
                "rows": [
                    {"name": "dup", "protocol": "ssh", "hostname": "10.0.0.9", "port": 22, "folder": "Existing"},
                    {"name": "ghost", "protocol": "ssh", "hostname": "10.0.0.3", "port": 22, "folder": "Existing"}
                ]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["updated"], 1);
    assert_eq!(json["unchanged"], 0);
    assert_eq!(json["skipped"], 0);
    // Missing row is an error, not an import.
    let errors = json["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0]["row"], 2);
    assert!(errors[0]["error"]
        .as_str()
        .unwrap()
        .contains("no existing entry 'ghost' to update"));

    let entry = db::get_ab_entry(&db, folder_id, "dup").unwrap();
    assert_eq!(entry.hostname, "10.0.0.9");
    assert_eq!(db::list_ab_entries(&db, folder_id).unwrap().len(), 1);
}

#[tokio::test]
async fn import_upsert_keeps_password_on_empty_cell() {
    let key = "ab".repeat(32); // 64 hex chars = 32 bytes
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router_with_key(db.clone(), Some(key.clone()));
    let resp = router
        .clone()
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "hunter2", "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();

    // Re-import with an empty password cell and identical metadata: the
    // empty cell requests no change, so the row counts as unchanged.
    let resp = router
        .clone()
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "", "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["unchanged"], 1);
    assert_eq!(json["updated"], 0);

    // Now change the hostname with an empty password: metadata updates but
    // the stored credential must survive.
    let resp = router
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.2", "port": 22, "password": "", "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["updated"], 1);

    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();
    assert_eq!(entry.hostname, "10.0.0.2");
    let creds = db::list_ab_credentials(&db, entry.id).unwrap();
    assert_eq!(creds.len(), 1);
    let enc_key = persea::crypto::EncryptionKey::from_hex(&key).unwrap();
    let decrypted = persea::crypto::decrypt_value(&enc_key, &creds[0].credential_data).unwrap();
    assert_eq!(decrypted, "hunter2");
}

#[tokio::test]
async fn import_upsert_updates_password_when_nonempty() {
    let key = "ab".repeat(32);
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router_with_key(db.clone(), Some(key.clone()));
    let resp = router
        .clone()
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "oldpass", "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["imported"], 1);

    let resp = router
        .oneshot(admin_post(
            &admin_key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "sec", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "password": "newpass", "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["updated"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();
    let creds = db::list_ab_credentials(&db, entry.id).unwrap();
    let enc_key = persea::crypto::EncryptionKey::from_hex(&key).unwrap();
    let decrypted = persea::crypto::decrypt_value(&enc_key, &creds[0].credential_data).unwrap();
    assert_eq!(decrypted, "newpass");
}

#[tokio::test]
async fn import_upsert_skips_near_duplicates_on_creation() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    insert_entry(&db, "shared", "Root", "webserver01", "");

    // "web-server-01" slugifies differently but is fuzzy-equal to the
    // existing "webserver01" — creation must be blocked in both create and
    // upsert modes.
    let router = test_router(db.clone());
    let resp = router
        .clone()
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{"name": "web-server-01", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["skipped"], 1);
    let errors = json["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(errors[0]["error"]
        .as_str()
        .unwrap()
        .contains("near-duplicate of existing entry 'webserver01'"));

    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "mode": "create",
                "rows": [{"name": "web-server-01", "protocol": "ssh", "hostname": "10.0.0.1", "port": 22, "folder": "Root"}]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["skipped"], 1);
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
                    {"name": "", "protocol": "ssh", "hostname": "10.0.0.3", "port": 22},
                    {"name": "!!!", "protocol": "ssh", "hostname": "10.0.0.4", "port": 22}
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
    assert_eq!(errors.len(), 4);
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
    // A name that slugifies to nothing cannot become an identifier.
    assert_eq!(errors[3]["row"], 5);
    assert!(errors[3]["error"]
        .as_str()
        .unwrap()
        .contains("no usable characters"));

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
    assert_eq!(json["updated"], 0);
    assert_eq!(json["unchanged"], 0);
    assert_eq!(json["skipped"], 0);
    assert!(json["errors"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn import_invalid_mode_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({"mode": "bogus", "rows": []}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
    let json = body_json(resp).await;
    assert_eq!(json["passwords_dropped"], 1);

    let folder = db::get_ab_folder(&db, "shared", "").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "sec").unwrap();
    assert!(db::list_ab_credentials(&db, entry.id).unwrap().is_empty());
}

#[tokio::test]
async fn import_custom_fields_json() {
    let db = test_db();
    set_custom_fields(&db, &[("Environment", "text"), ("Owner", "text")]);
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let body = serde_json::json!({
        "rows": [{
            "name": "web01",
            "protocol": "ssh",
            "hostname": "10.0.0.1",
            "port": 22,
            "folder": "Root",
            "custom_fields": {"Environment": "Production", "Owner": "alice"}
        }]
    });

    let resp = router
        .clone()
        .oneshot(admin_post(&key, "/api/addressbook/import", body.clone()))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "web01").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["custom_fields"]["Environment"], "Production");
    assert_eq!(cfg["custom_fields"]["Owner"], "alice");

    // Identical re-import (same custom fields) counts as unchanged.
    let resp = router
        .clone()
        .oneshot(admin_post(&key, "/api/addressbook/import", body))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["unchanged"], 1);
    assert_eq!(json["updated"], 0);

    // A changed custom field counts as an update.
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{
                    "name": "web01",
                    "protocol": "ssh",
                    "hostname": "10.0.0.1",
                    "port": 22,
                    "folder": "Root",
                    "custom_fields": {"Environment": "Staging", "Owner": "alice"}
                }]
            }),
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["updated"], 1);
    let entry = db::get_ab_entry(&db, folder.id, "web01").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["custom_fields"]["Environment"], "Staging");
}

#[tokio::test]
async fn import_custom_fields_sequence_of_pairs_wire_shape() {
    // The connections-page UI sends custom fields as [[name, value], ...]
    // pairs (mirroring the CSV columns) — the JSON contract must accept that.
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{
                    "name": "web01",
                    "protocol": "ssh",
                    "hostname": "10.0.0.1",
                    "port": 22,
                    "folder": "Root",
                    "custom_fields": [["Environment", "Production"], ["Owner", "alice"]]
                }]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "web01").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["custom_fields"]["Environment"], "Production");
    assert_eq!(cfg["custom_fields"]["Owner"], "alice");
}

#[tokio::test]
async fn import_raw_csv_body() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let csv = format!(
        "{}\nweb01,ssh,10.0.0.1,22,root,secret,Production/Web,group1,Production web server\nportal,web,,443,,,Internal,,",
        HEADER
    );
    let resp = router
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 2);
    assert_eq!(json["updated"], 0);
    assert_eq!(json["unchanged"], 0);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let prod = db::get_ab_folder(&db, "shared", "Production/Web").unwrap();
    let e1 = db::get_ab_entry(&db, prod.id, "web01").unwrap();
    assert_eq!(e1.protocol, "ssh");
    assert_eq!(e1.hostname, "10.0.0.1");
    assert_eq!(e1.username, "root");
    assert_eq!(e1.allowed_groups, "group1");
    // No display_name column: the friendly name column IS the display name.
    assert_eq!(e1.display_name, "web01");

    let internal = db::get_ab_folder(&db, "shared", "Internal").unwrap();
    let e2 = db::get_ab_entry(&db, internal.id, "portal").unwrap();
    assert_eq!(e2.protocol, "web");
    assert_eq!(e2.port, Some(443));
}

#[tokio::test]
async fn import_raw_csv_legacy_header_rejected() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let csv = format!("{}\nweb,ssh,10.0.0.1,22,,,Root,Web 1,,", LEGACY_HEADER);
    let resp = router
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn import_raw_csv_mode_query() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    insert_entry(&db, "shared", "Root", "dup", "");

    // ?mode=create on a raw-CSV body skips the existing entry…
    let router = test_router(db.clone());
    let csv = format!("{}\ndup,ssh,10.0.0.1,22,,,Root,,", HEADER);
    let resp = router
        .clone()
        .oneshot(admin_csv_post(
            &key,
            "/api/addressbook/import?mode=create",
            &csv,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    assert_eq!(json["skipped"], 1);

    // …while the default upsert mode counts it as unchanged (the pre-seeded
    // entry matches the row's importable fields incl. username).
    let csv_identical = format!("{}\ndup,ssh,10.0.0.1,22,root,,Root,,", HEADER);
    let resp = router
        .oneshot(admin_csv_post(
            &key,
            "/api/addressbook/import",
            &csv_identical,
        ))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["unchanged"], 1);
    assert_eq!(json["skipped"], 0);
}

#[tokio::test]
async fn import_raw_csv_custom_field_columns() {
    let db = test_db();
    set_custom_fields(&db, &[("Environment", "text"), ("Owner", "text")]);
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let csv = format!(
        "{},Environment,Owner\nweb01,ssh,10.0.0.1,22,root,secret,Root,g1,desc,Production,alice",
        HEADER
    );
    let resp = router
        .clone()
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "web01").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["custom_fields"]["Environment"], "Production");
    assert_eq!(cfg["custom_fields"]["Owner"], "alice");

    // A column not in the configured definitions is rejected at the header.
    let bad = format!("{},Environment,Env\nx,ssh,10.0.0.1,22,,,Root,,,a,b", HEADER);
    let resp = router
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &bad))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn import_raw_csv_maps_optional_settings() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let csv = format!(
        "{},security,domain,color_depth,enable_gfx,ignore_cert\n\
         win,rdp,10.0.0.50,3389,Administrator,secret,Windows,,gateway,nla,corp.example.com,32,true,false",
        HEADER
    );
    let resp = router
        .clone()
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let folder = db::get_ab_folder(&db, "shared", "Windows").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "win").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["security"], "nla");
    assert_eq!(cfg["domain"], "corp.example.com");
    assert_eq!(cfg["color_depth"], 32);
    assert_eq!(cfg["enable_gfx"], true);
    assert_eq!(cfg["ignore_cert"], false);
    assert!(cfg.get("remote_app").is_none());
    assert!(cfg.get("auth_pkg").is_none());
}

#[tokio::test]
async fn import_json_settings_into_protocol_config() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_post(
            &key,
            "/api/addressbook/import",
            serde_json::json!({
                "rows": [{
                    "name": "win",
                    "protocol": "rdp",
                    "hostname": "10.0.0.50",
                    "port": 3389,
                    "folder": "Root",
                    "security": "nla",
                    "domain": "corp.example.com",
                    "color_depth": 24,
                    "enable_gfx": true,
                    "disable_copy": true
                }]
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["errors"].as_array().unwrap().len(), 0);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "win").unwrap();
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["security"], "nla");
    assert_eq!(cfg["domain"], "corp.example.com");
    assert_eq!(cfg["color_depth"], 24);
    assert_eq!(cfg["enable_gfx"], true);
    assert_eq!(cfg["disable_copy"], true);
}

#[tokio::test]
async fn import_raw_csv_settings_preserved_when_columns_absent() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    // No storage key: a non-empty password is dropped, so it cannot
    // participate in unchanged-detection — keep the cell empty.
    let csv = format!(
        "{},security,domain\n\
         win,rdp,10.0.0.50,3389,Administrator,,Windows,,gateway,nla,corp.example.com",
        HEADER
    );
    let resp = router
        .clone()
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(body_json(resp).await["imported"], 1);

    // Identical re-import: unchanged (settings match).
    let resp = router
        .clone()
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["unchanged"], 1);
    assert_eq!(json["updated"], 0);

    // Same row without the settings columns, changed hostname: updated,
    // the stored settings must survive (blank = no change).
    let plain = format!("{}\nwin,rdp,10.0.0.60,3389,Administrator,,Windows,,gateway", HEADER);
    let resp = router
        .oneshot(admin_csv_post(&key, "/api/addressbook/import", &plain))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["updated"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Windows").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "win").unwrap();
    assert_eq!(entry.hostname, "10.0.0.60");
    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap();
    assert_eq!(cfg["security"], "nla");
    assert_eq!(cfg["domain"], "corp.example.com");
}

#[tokio::test]
async fn import_raw_csv_private_key_encrypted_with_key() {
    let key = "ab".repeat(32);
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router_with_key(db.clone(), Some(key.clone()));
    let csv = format!(
        "{},private_key\n\
         srv,ssh,10.0.0.1,22,root,secret,Root,,server key,sk-ssh-ed25519-abc",
        HEADER
    );
    let resp = router
        .oneshot(admin_csv_post(&admin_key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["passwords_dropped"], 0);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "srv").unwrap();
    let creds = db::list_ab_credentials(&db, entry.id).unwrap();
    assert_eq!(creds.len(), 2);
    let pk = creds
        .iter()
        .find(|c| c.credential_type == "private_key")
        .unwrap();
    assert_ne!(pk.credential_data, "sk-ssh-ed25519-abc");
    let enc_key = persea::crypto::EncryptionKey::from_hex(&key).unwrap();
    let decrypted = persea::crypto::decrypt_value(&enc_key, &pk.credential_data).unwrap();
    assert_eq!(decrypted, "sk-ssh-ed25519-abc");
}

#[tokio::test]
async fn import_raw_csv_private_key_dropped_without_key() {
    // Guard against a PERSEA_STORAGE_KEY leaking in from the environment.
    std::env::set_var("PERSEA_STORAGE_KEY", "");
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    let router = test_router(db.clone());
    let csv = format!(
        "{},private_key\n\
         srv,ssh,10.0.0.1,22,root,,Root,,server key,sk-ssh-ed25519-abc",
        HEADER
    );
    let resp = router
        .oneshot(admin_csv_post(&admin_key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 1);
    assert_eq!(json["passwords_dropped"], 1);

    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    let entry = db::get_ab_entry(&db, folder.id, "srv").unwrap();
    assert!(db::list_ab_credentials(&db, entry.id).unwrap().is_empty());
}

#[tokio::test]
async fn import_raw_csv_private_key_failure_rolls_back_entry() {
    let db = test_db();
    let admin_key = create_admin(&db, "admin");
    // An unparsable storage key forces the credential store to fail; the
    // just-created entry must be rolled back (same as the password path).
    let router = test_router_with_key(db.clone(), Some("not-hex".to_string()));
    let csv = format!(
        "{},private_key\n\
         srv,ssh,10.0.0.1,22,root,secret,Root,,server key,sk-ssh-ed25519-abc",
        HEADER
    );
    let resp = router
        .oneshot(admin_csv_post(&admin_key, "/api/addressbook/import", &csv))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["imported"], 0);
    let errors = json["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0]["error"]
            .as_str()
            .unwrap()
            .contains("failed to parse encryption key"),
        "{}",
        errors[0]["error"]
    );
    let folder = db::get_ab_folder(&db, "shared", "Root").unwrap();
    assert!(db::list_ab_entries(&db, folder.id).unwrap().is_empty());
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
    assert_eq!(body_text(resp).await, csv_import::render_template(&[]));
}

#[tokio::test]
async fn template_includes_configured_custom_fields() {
    let db = test_db();
    set_custom_fields(&db, &[("Environment", "text"), ("Owner", "text")]);
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
    let template = body_text(resp).await;
    let header_line = template.lines().next().unwrap();
    assert_eq!(
        header_line,
        format!(
            "{},domain,security,ignore_cert,color_depth,remote_app,enable_gfx,enable_drive,disable_copy,disable_paste,auth_pkg,kdc_url,prompt_credentials,private_key,Environment,Owner",
            HEADER
        )
    );
    // The served template must round-trip through the parser with the same
    // definitions.
    let defs = vec!["Environment".to_string(), "Owner".to_string()];
    let result = csv_import::parse_rows(&template, &defs).unwrap();
    assert_eq!(result.rows.len(), 2);
    assert_eq!(result.rows[0].custom_fields.len(), 2);
    assert_eq!(result.rows[1].custom_fields.len(), 2);
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

#[test]
fn connections_page_shows_leave_blank_guidance() {
    let html =
        std::fs::read_to_string("templates/pages/connections.html").expect("template file exists");
    assert!(html.contains("Leave blank whatever is not needed"));
}
