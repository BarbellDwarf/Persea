//! Tests for per-protocol session defaults (admin Settings → Session →
//! Session defaults).
//!
//! Two layers:
//! - Settings API: the keys persist, round-trip, validate, and only admins
//!   can write them (in-memory DB, no server).
//! - End to end: against a live persea binary with a mock guacd, the
//!   stored defaults land on the guacd connect instruction when the
//!   request does not specify a value, request values win, and unset
//!   settings keep the code defaults (H.264/GFX on, security "any").

mod auth {
    pub use persea::auth::*;
}
mod db {
    pub use persea::db::*;
}
mod db_pool {
    pub use persea::db_pool::*;
}
mod error {
    pub use persea::error::*;
}
mod api {
    pub use persea::api::{AppState, SettingsBaseline};
}
mod net_util {
    pub use persea::net_util::*;
}
mod settings_merge {
    pub use persea::settings_merge::*;
}

#[path = "../src/api/settings.rs"]
mod settings;

use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{middleware, Extension, Router};
use persea::auth::TrustedProxies;
use persea::db::Db;
use persea::protocol::{Instruction, InstructionParser};
use serde_json::json;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tower::ServiceExt;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const ASSERT_DEADLINE: Duration = Duration::from_secs(15);

// ── Settings API (in-memory DB, no server) ──────────────────────────

fn test_db() -> Db {
    persea::db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn test_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/system/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn bare_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/system/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .layer(Extension(db))
}

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

fn admin_get(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {}", key))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
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

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn get_returns_code_defaults_when_nothing_stored() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["default_rdp_width"].as_u64(), Some(1920));
    assert_eq!(json["default_rdp_height"].as_u64(), Some(1080));
    assert_eq!(json["default_rdp_dpi"].as_u64(), Some(96));
    assert_eq!(json["default_rdp_security"].as_str().unwrap(), "any");
    assert_eq!(json["default_rdp_h264"].as_bool(), Some(true));
    assert_eq!(json["default_rdp_gfx"].as_bool(), Some(true));
    assert_eq!(json["default_rdp_drive"].as_bool(), Some(false));
    assert_eq!(json["default_ssh_width"].as_u64(), Some(1920));
    assert_eq!(json["default_ssh_height"].as_u64(), Some(1080));
    assert_eq!(json["default_vnc_color_depth"].as_u64(), Some(24));
    assert_eq!(json["default_vnc_disable_copy"].as_bool(), Some(false));
    assert_eq!(json["default_vnc_disable_paste"].as_bool(), Some(false));
}

#[tokio::test]
async fn config_table_matches_api_defaults() {
    // The canonical defaults table in src/config.rs and the settings API
    // defaults must agree: every key the table declares is a managed
    // setting whose unset GET value equals the table's value.
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    for (table_key, table_value) in persea::config::PROTOCOL_DEFAULT_KEYS {
        let got = &json[*table_key];
        match table_value.parse::<u64>() {
            Ok(n) => assert_eq!(
                got.as_u64(),
                Some(n),
                "default {table_key} must be a number {n}"
            ),
            Err(_) if *table_value == "true" || *table_value == "false" => assert_eq!(
                got.as_bool(),
                Some(*table_value == "true"),
                "default {table_key} must be boolean {table_value}"
            ),
            Err(_) => assert_eq!(
                got.as_str(),
                Some(*table_value),
                "default {table_key} must be string {table_value}"
            ),
        }
    }
}

#[tokio::test]
async fn put_round_trips_protocol_defaults_and_survives_fresh_router() {
    let db = test_db();
    let key = create_admin(&db, "admin");

    let router = test_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            json!({
                "default_rdp_width": 1280,
                "default_rdp_height": 800,
                "default_rdp_dpi": 120,
                "default_rdp_security": "nla",
                "default_rdp_h264": false,
                "default_rdp_gfx": false,
                "default_rdp_drive": true,
                "default_ssh_width": 200,
                "default_ssh_height": 60,
                "default_vnc_color_depth": 16,
                "default_vnc_disable_copy": true,
                "default_vnc_disable_paste": true,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let saved = body_json(resp).await;
    assert_eq!(saved["default_rdp_width"].as_u64(), Some(1280));
    assert_eq!(saved["default_rdp_security"].as_str().unwrap(), "nla");
    assert_eq!(saved["default_rdp_h264"].as_bool(), Some(false));
    assert_eq!(saved["default_rdp_drive"].as_bool(), Some(true));
    assert_eq!(saved["default_vnc_color_depth"].as_u64(), Some(16));

    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["default_rdp_width"].as_u64(), Some(1280));
    assert_eq!(json["default_rdp_security"].as_str().unwrap(), "nla");
    assert_eq!(json["default_rdp_h264"].as_bool(), Some(false));
    assert_eq!(json["default_rdp_gfx"].as_bool(), Some(false));
    assert_eq!(json["default_rdp_drive"].as_bool(), Some(true));
    assert_eq!(json["default_ssh_width"].as_u64(), Some(200));
    assert_eq!(json["default_ssh_height"].as_u64(), Some(60));
    assert_eq!(json["default_vnc_color_depth"].as_u64(), Some(16));
    assert_eq!(json["default_vnc_disable_copy"].as_bool(), Some(true));
    assert_eq!(json["default_vnc_disable_paste"].as_bool(), Some(true));
}

#[tokio::test]
async fn put_protocol_defaults_requires_admin() {
    let db = test_db();
    let router = bare_router(db);
    let resp = router
        .oneshot(admin_put(
            "no-such-key",
            "/api/system/settings",
            json!({"default_rdp_h264": false}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let json = body_json(resp).await;
    assert_eq!(json["error_code"].as_str().unwrap(), "FORBIDDEN");
}

#[tokio::test]
async fn put_rejects_bad_protocol_default_values() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = test_router(db.clone());

    for bad in [
        json!({"default_rdp_width": 0}),
        json!({"default_rdp_width": 9000}),
        json!({"default_rdp_dpi": 0}),
        json!({"default_vnc_color_depth": 64}),
        json!({"default_rdp_security": "psk"}),
        json!({"default_rdp_h264": "yes"}),
    ] {
        let resp = router
            .clone()
            .oneshot(admin_put(&key, "/api/system/settings", bad.clone()))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "body {:?} must be rejected",
            bad
        );
    }

    // Nothing was persisted.
    let router = test_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["default_rdp_width"].as_u64(), Some(1920));
    assert_eq!(json["default_rdp_security"].as_str().unwrap(), "any");
}

// ── End to end: defaults land on the guacd connect instruction ──────

mod support;

/// Double-submit CSRF: GET the app root, capture the `csrf_token` cookie
/// value, and echo it back as `X-CSRF-Token` on state-changing requests.
async fn fetch_csrf_token(client: &reqwest::Client, base: &str) -> String {
    let resp = client
        .get(format!("{base}/"))
        .send()
        .await
        .expect("GET / for CSRF token");
    let set_cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("csrf_token="))
        .unwrap_or_else(|| panic!("no csrf_token Set-Cookie in {:?}", resp.headers()));
    set_cookie
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("csrf_token=")
        .unwrap()
        .to_string()
}

async fn send_json(
    client: &reqwest::Client,
    method: reqwest::Method,
    url: &str,
    key: &str,
    body: &serde_json::Value,
    csrf: Option<&str>,
) -> (reqwest::StatusCode, String) {
    let mut request = client.request(method, url).bearer_auth(key).json(body);
    if let Some(tok) = csrf {
        request = request.header("X-CSRF-Token", tok);
        request = request.header("Cookie", format!("csrf_token={tok}"));
    }
    let resp = request
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {url} failed: {e}"));
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

/// What one mock-guacd connection observed.
#[derive(Debug, Default, Clone)]
struct MockConn {
    handshake_done: bool,
    eof: bool,
    connect_args: Vec<(String, String)>,
}

/// Mock guacd: reply `args` (with the given parameter names) to `select`,
/// `ready` to `connect`, record the connect args, and record EOF.
async fn mock_guacd(
    listener: tokio::net::TcpListener,
    results: Arc<Mutex<Vec<MockConn>>>,
    args_names: Vec<String>,
) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let results = results.clone();
        let args_names = args_names.clone();
        tokio::spawn(async move {
            let mut conn = MockConn::default();
            let mut parser = InstructionParser::new();
            let mut buf = [0u8; 4096];
            loop {
                match sock.read(&mut buf).await {
                    Ok(0) => {
                        conn.eof = true;
                        break;
                    }
                    Ok(n) => {
                        let text = String::from_utf8_lossy(&buf[..n]);
                        for parsed in parser.receive(&text) {
                            let Ok(instr) = parsed else { continue };
                            match instr.opcode.as_str() {
                                "select" => {
                                    let _ = sock
                                        .write_all(
                                            Instruction::new("args", args_names.clone())
                                                .encode()
                                                .as_bytes(),
                                        )
                                        .await;
                                }
                                "connect" => {
                                    let ready = Instruction::new("ready", vec!["mock-conn".into()]);
                                    let _ = sock.write_all(ready.encode().as_bytes()).await;
                                    conn.handshake_done = true;
                                    conn.connect_args = args_names
                                        .iter()
                                        .cloned()
                                        .zip(instr.args.iter().cloned())
                                        .collect();
                                    // Push a live record now: sessions hold
                                    // the guacd socket open, so EOF (and the
                                    // final push) only happens at teardown.
                                    results.lock().await.push(conn.clone());
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
            results.lock().await.push(conn);
        });
    }
}

struct TestEnv {
    base: String,
    key: String,
    csrf: String,
    client: reqwest::Client,
    guacd_results: Arc<Mutex<Vec<MockConn>>>,
    _tmp: PathBuf,
    _app: support::AppProc,
}

/// Boot persea with a mock guacd that requests the given connect args.
async fn boot(tag: &str, args_names: &[&str]) -> TestEnv {
    let marker = format!("pdt-{tag}-{}", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");

    let results = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock guacd");
    let guacd_addr = listener.local_addr().expect("guacd addr");
    tokio::spawn(mock_guacd(
        listener,
        results.clone(),
        args_names.iter().map(|s| s.to_string()).collect(),
    ));

    let db_path = tmp.join("admin.db").display().to_string();
    let booted = support::boot_persea(
        &marker,
        &config_path,
        &log_path,
        None,
        HEALTH_TIMEOUT,
        &|port: u16| {
            format!(
                "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{db_path}\"\nguacd_addr = \"{guacd_addr}\"\n[storage]\nencryption_key = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
            )
        },
    )
    .await;
    let csrf = fetch_csrf_token(&booted.client, &booted.base).await;

    TestEnv {
        base: booted.base,
        key: booted.key,
        csrf,
        client: booted.client,
        guacd_results: results,
        _tmp: tmp,
        _app: booted.app,
    }
}

/// POST a session-create body; returns (status, body).
async fn create_session(env: &TestEnv, body: &serde_json::Value) -> (reqwest::StatusCode, String) {
    send_json(
        &env.client,
        reqwest::Method::POST,
        &format!("{}/api/sessions", env.base),
        &env.key,
        body,
        Some(&env.csrf),
    )
    .await
}

/// PUT system settings; returns (status, body).
async fn put_settings(env: &TestEnv, body: &serde_json::Value) -> (reqwest::StatusCode, String) {
    send_json(
        &env.client,
        reqwest::Method::PUT,
        &format!("{}/api/system/settings", env.base),
        &env.key,
        body,
        Some(&env.csrf),
    )
    .await
}

/// The most recent live handshake's connect args (sessions hold the socket
/// open, so each completed handshake is pushed immediately).
async fn last_connect_args(env: &TestEnv) -> Vec<(String, String)> {
    let results = env.guacd_results.clone();
    let start = Instant::now();
    loop {
        let live: Vec<Vec<(String, String)>> = results
            .lock()
            .await
            .iter()
            .filter(|c| c.handshake_done && !c.eof)
            .map(|c| c.connect_args.clone())
            .collect();
        if let Some(last) = live.last() {
            return last.clone();
        }
        assert!(
            start.elapsed() < ASSERT_DEADLINE,
            "timed out waiting for mock guacd handshake"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn arg<'a>(args: &'a [(String, String)], name: &str) -> &'a str {
    args.iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("connect instruction missing arg {name}: {args:?}"))
}

const RDP_ARGS: &[&str] = &[
    "hostname",
    "port",
    "security",
    "width",
    "height",
    "dpi",
    "disable-gfx",
    "enable-h264",
];

const VNC_ARGS: &[&str] = &[
    "hostname",
    "port",
    "color-depth",
    "disable-copy",
    "disable-paste",
];

#[tokio::test]
async fn stored_defaults_apply_to_blank_requests_and_entries_win() {
    // One boot, one mock guacd: all three sessions land in the same
    // results list in order.
    let env = boot("blank", &[RDP_ARGS, VNC_ARGS].concat()).await;

    let (status, body) = put_settings(
        &env,
        &json!({
            "default_rdp_width": 1280,
            "default_rdp_height": 800,
            "default_rdp_dpi": 120,
            "default_rdp_security": "nla",
            "default_rdp_h264": false,
            "default_rdp_gfx": false,
            "default_vnc_color_depth": 16,
            "default_vnc_disable_copy": true,
            "default_vnc_disable_paste": true,
        }),
    )
    .await;
    assert_eq!(status, 200, "settings PUT failed: {body}");

    // 1. RDP request without any of the overridable fields: the stored
    //    global defaults land on the connect instruction.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "rdp",
            "hostname": "127.0.0.1",
            "port": 3389,
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(arg(&args, "width"), "1280");
    assert_eq!(arg(&args, "height"), "800");
    assert_eq!(arg(&args, "dpi"), "120");
    assert_eq!(arg(&args, "security"), "nla");
    assert_eq!(arg(&args, "enable-h264"), "false");
    assert_eq!(arg(&args, "disable-gfx"), "true");

    // 2. RDP request WITH its own values: the entry wins over the global
    //    defaults.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "rdp",
            "hostname": "127.0.0.1",
            "port": 3389,
            "username": "u",
            "password": "p",
            "width": 640,
            "height": 480,
            "dpi": 72,
            "security": "tls",
            "enable_h264": true,
            "enable_gfx": true,
        }),
    )
    .await;
    assert_eq!(status, 200, "RDP session create (override) failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(arg(&args, "width"), "640");
    assert_eq!(arg(&args, "height"), "480");
    assert_eq!(arg(&args, "dpi"), "72");
    assert_eq!(arg(&args, "security"), "tls");
    assert_eq!(arg(&args, "enable-h264"), "true");
    assert_eq!(arg(&args, "disable-gfx"), "false");

    // 3. VNC request without overrides: the stored VNC defaults land on
    //    the connect instruction.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "vnc",
            "hostname": "127.0.0.1",
            "port": 5900,
            "password": "p",
        }),
    )
    .await;
    assert_eq!(status, 200, "VNC session create failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(arg(&args, "color-depth"), "16");
    assert_eq!(arg(&args, "disable-copy"), "true");
    assert_eq!(arg(&args, "disable-paste"), "true");
}

#[tokio::test]
async fn unset_defaults_keep_code_defaults_on_the_wire() {
    // No settings stored: the create path must behave exactly as before —
    // H.264 and GFX on, security passthrough (guacd's "any" fallback).
    let env = boot("unset", RDP_ARGS).await;

    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "rdp",
            "hostname": "127.0.0.1",
            "port": 3389,
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(arg(&args, "width"), "1920");
    assert_eq!(arg(&args, "height"), "1080");
    assert_eq!(arg(&args, "dpi"), "96");
    assert_eq!(arg(&args, "security"), "any");
    assert_eq!(arg(&args, "enable-h264"), "true");
    assert_eq!(arg(&args, "disable-gfx"), "false");
}
