//! End-to-end session teardown tests (wayfinder/issue-batch-2/T11).
//!
//! Closing the owner's WebSocket (tab close) or terminating a session via
//! the API must ACTIVELY end the guacd connection: the mock guacd must see
//! the Guacamole `disconnect` instruction and/or a socket EOF, instead of
//! the connection staying open forever and the remote session running on
//! with no owner (an orphan).
//!
//! The mock guacd speaks just enough of the protocol for persea's handshake
//! (`args` in reply to `select`, `ready` in reply to `connect`) and then
//! records everything the proxy sends until EOF.

use axum::http::Request;
use futures_util::{SinkExt, StreamExt};
use persea::protocol::{Instruction, InstructionParser};
use serde_json::json;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const ASSERT_DEADLINE: Duration = Duration::from_secs(15);

// ── Test environment (mirrors tests/backend_tests.rs) ──────────────

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_persea")
}

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn create_admin_key(config_path: &PathBuf, admin_name: &str) -> String {
    let out = Command::new(binary())
        .arg("--config")
        .arg(config_path)
        .args(["add-admin", "--name", admin_name])
        .output()
        .expect("run persea add-admin");
    assert!(
        out.status.success(),
        "add-admin failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("API Key: "))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no API key in add-admin output: {stdout}"))
}

struct AppProc {
    child: Child,
}

impl AppProc {
    fn new(config_path: &PathBuf, log_path: &PathBuf) -> Self {
        let log_file = std::fs::File::create(log_path).expect("create log file");
        let child = Command::new(binary())
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn persea: {e}"));
        AppProc { child }
    }
}

impl Drop for AppProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

async fn wait_healthy(client: &reqwest::Client, base: &str, app: &mut AppProc, log_path: &PathBuf) {
    let deadline = tokio::time::Instant::now() + HEALTH_TIMEOUT;
    loop {
        let ok = match client.get(format!("{base}/api/health")).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };
        if ok {
            return;
        }
        if let Some(status) = app.child.try_wait().expect("wait on child") {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            panic!("persea exited early with {status}; log:\n{log}");
        }
        if tokio::time::Instant::now() >= deadline {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            panic!("persea did not become healthy within {HEALTH_TIMEOUT:?}; log:\n{log}");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

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

/// GET /api/sessions/{id} → `Some(status_string)` when the record exists,
/// `None` when it is gone (404 / not found).
async fn session_status(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    id: &str,
) -> Option<String> {
    let resp = client
        .get(format!("{base}/api/sessions/{id}"))
        .bearer_auth(key)
        .send()
        .await
        .expect("GET session");
    if !resp.status().is_success() {
        return None;
    }
    let v: serde_json::Value = resp.json().await.expect("session JSON");
    v.get("status").and_then(|s| s.as_str()).map(String::from)
}

/// Poll the session record until `pred` matches, or panic after the
/// deadline. Returns the matching status.
async fn wait_for_session_status(
    env: &TestEnv,
    session_id: &str,
    what: &str,
    pred: impl Fn(&str) -> bool,
) -> String {
    let deadline = Instant::now() + ASSERT_DEADLINE;
    loop {
        if let Some(st) = session_status(&env.client, &env.base, &env.key, session_id).await {
            if pred(&st) {
                return st;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {what} ({ASSERT_DEADLINE:?})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Poll until the session record is gone entirely, or panic after the
/// deadline.
async fn wait_for_session_gone(env: &TestEnv, session_id: &str) {
    let deadline = Instant::now() + ASSERT_DEADLINE;
    loop {
        if session_status(&env.client, &env.base, &env.key, session_id)
            .await
            .is_none()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for session record removal ({ASSERT_DEADLINE:?})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Mock guacd ─────────────────────────────────────────────────────

/// What one mock-guacd connection observed.
#[derive(Debug, Default, Clone)]
struct MockConn {
    /// `ready` was replied to `connect` (persea's handshake completed).
    handshake_done: bool,
    /// Number of `disconnect` instructions received from persea.
    disconnect_instructions: usize,
    /// Socket EOF was observed (persea actively closed the connection).
    eof: bool,
}

/// Mock guacd: reply `args` to `select`, `ready` to `connect`, echo the
/// client's `size` instruction back once the handshake is done (a marker
/// the test client waits for — proof the tunnel is live end-to-end), and
/// record everything until EOF.
async fn mock_guacd(listener: tokio::net::TcpListener, results: Arc<Mutex<Vec<MockConn>>>) {
    loop {
        let (mut sock, _) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => return,
        };
        let results = results.clone();
        tokio::spawn(async move {
            let mut conn = MockConn::default();
            let mut parser = InstructionParser::new();
            let mut buf = [0u8; 4096];
            let mut marker_sent = false;
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
                                    // Arg names persea knows how to fill.
                                    let args = Instruction::new(
                                        "args",
                                        vec![
                                            "hostname".into(),
                                            "port".into(),
                                            "username".into(),
                                            "password".into(),
                                            "width".into(),
                                            "height".into(),
                                            "dpi".into(),
                                        ],
                                    );
                                    let _ = sock.write_all(args.encode().as_bytes()).await;
                                }
                                "connect" => {
                                    let ready =
                                        Instruction::new("ready", vec!["mock-conn".into()]);
                                    let _ = sock.write_all(ready.encode().as_bytes()).await;
                                    conn.handshake_done = true;
                                }
                                "disconnect" => conn.disconnect_instructions += 1,
                                "size" => {
                                    // One marker echo so the test client can
                                    // sync on the live tunnel.
                                    if conn.handshake_done && !marker_sent {
                                        marker_sent = true;
                                        let _ = sock.write_all(instr.encode().as_bytes()).await;
                                    }
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

// ── Helpers ────────────────────────────────────────────────────────

/// Boot mock guacd + persea; returns the env plus the mock observations.
struct TestEnv {
    base: String,
    host: String,
    key: String,
    csrf: String,
    client: reqwest::Client,
    guacd_results: Arc<Mutex<Vec<MockConn>>>,
    _tmp: PathBuf,
    _app: AppProc,
}

async fn boot(tag: &str) -> TestEnv {
    let guacd_results = Arc::new(Mutex::new(Vec::new()));
    let guacd_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock guacd");
    let guacd_addr = guacd_listener.local_addr().expect("guacd addr");
    tokio::spawn(mock_guacd(guacd_listener, guacd_results.clone()));

    let marker = format!("t11-{tag}-{}", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");
    let port = free_port();
    std::fs::write(
        &config_path,
        format!(
            "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{}\"\nguacd_addr = \"{guacd_addr}\"\n",
            tmp.join("admin.db").display()
        ),
    )
    .expect("write config");

    let key = create_admin_key(&config_path, &marker);
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");
    let csrf = fetch_csrf_token(&client, &base).await;

    let mut app = AppProc::new(&config_path, &log_path);
    wait_healthy(&client, &base, &mut app, &log_path).await;

    TestEnv {
        base: base.clone(),
        host: format!("127.0.0.1:{port}"),
        key,
        csrf,
        client,
        guacd_results,
        _tmp: tmp,
        _app: app,
    }
}

/// Create an SSH ad-hoc session via the API and return its id.
async fn create_session(env: &TestEnv) -> String {
    let (status, body) = send_json(
        &env.client,
        reqwest::Method::POST,
        &format!("{}/api/sessions", env.base),
        &env.key,
        &json!({
            "session_type": "ssh",
            "hostname": "127.0.0.1",
            "port": 22,
            "username": "root",
            "password": "test",
            "width": 800,
            "height": 600,
            "dpi": 96,
        }),
        Some(&env.csrf),
    )
    .await;
    assert_eq!(status, 200, "POST /api/sessions failed: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("session create JSON");
    v["session_id"]
        .as_str()
        .expect("session_id in create response")
        .to_string()
}

/// Open the owner WebSocket with a fresh ws ticket.
async fn connect_ws(
    env: &TestEnv,
    session_id: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let (status, body) = send_json(
        &env.client,
        reqwest::Method::POST,
        &format!("{}/api/ws-ticket", env.base),
        &env.key,
        &json!({}),
        Some(&env.csrf),
    )
    .await;
    assert_eq!(status, 200, "POST /api/ws-ticket failed: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("ws-ticket JSON");
    let ticket = v["ticket"].as_str().expect("ticket in response").to_string();

    let tcp = tokio::net::TcpStream::connect(&env.host)
        .await
        .expect("tcp connect");
    let uri = format!("ws://{}/ws/{}?ticket={}", env.host, session_id, ticket);
    let request = Request::builder()
        .uri(uri)
        .header("Origin", format!("http://{}", env.host))
        .header("Host", &env.host)
        .body(())
        .expect("build ws request");
    let (ws, _) = tokio_tungstenite::client_async(request, tcp)
        .await
        .expect("ws upgrade");
    ws
}

/// Send a `size` instruction and wait for the mock guacd's marker echo —
/// proof that browser → persea → guacd → persea → browser is fully live.
async fn sync_on_live_tunnel(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) {
    let size = Instruction::new("size", vec!["800".into(), "600".into(), "96".into()]);
    ws.send(WsMessage::Text(size.encode().into()))
        .await
        .expect("send size");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
            .await
            .expect("timed out waiting for marker echo")
            .expect("ws stream ended before marker");
        if let WsMessage::Text(t) = msg {
            if t.contains("size,800,600,96") {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "marker echo never arrived within {ASSERT_DEADLINE:?}"
        );
    }
}

/// Wait for the first mock-guacd connection to reach EOF (i.e. persea
/// actively closed the socket), then return its record.
async fn finished_guacd_connection(env: &TestEnv) -> MockConn {
    let deadline = Instant::now() + ASSERT_DEADLINE;
    loop {
        let guard = env.guacd_results.lock().await;
        if let Some(c) = guard.iter().find(|c| c.eof) {
            return c.clone();
        }
        drop(guard);
        assert!(
            Instant::now() < deadline,
            "timed out waiting for mock guacd connection EOF ({ASSERT_DEADLINE:?})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── The tests ──────────────────────────────────────────────────────

/// Tab close (WebSocket dropped without a close frame): persea must write
/// the `disconnect` instruction and close the guacd socket (EOF reaches
/// guacd), and the session record must move out of "active".
#[tokio::test]
async fn tab_close_actively_ends_guacd_connection() {
    let env = boot("tabclose").await;
    let session_id = create_session(&env).await;

    let mut ws = connect_ws(&env, &session_id).await;
    sync_on_live_tunnel(&mut ws).await;

    // Simulate a tab close: drop the socket with no close frame.
    drop(ws);

    // The mock guacd must observe the disconnect instruction AND socket EOF.
    let conn = finished_guacd_connection(&env).await;
    assert!(conn.handshake_done, "handshake completed at mock guacd");
    assert!(
        conn.disconnect_instructions >= 1,
        "guacd must receive the disconnect instruction on tab close: {conn:?}"
    );
    assert!(conn.eof, "guacd socket must reach EOF on tab close: {conn:?}");

    // The session record leaves "active" (Disconnected — the reconnect
    // window; the record is reaped later). The remote session is dead
    // either way — that is what the socket assertions above prove.
    let status = wait_for_session_status(&env, &session_id, "session to leave active", |s| {
        s != "active"
    })
    .await;
    assert_eq!(status, "disconnected");
}

/// API terminate (DELETE /api/sessions/{id}) while the owner is connected:
/// the cancellation must make the proxy abort its I/O tasks so the guacd
/// socket closes (EOF reaches guacd) and the record is gone.
#[tokio::test]
async fn api_terminate_actively_ends_guacd_connection() {
    let env = boot("terminate").await;
    let session_id = create_session(&env).await;

    let mut ws = connect_ws(&env, &session_id).await;
    sync_on_live_tunnel(&mut ws).await;

    let (status, body) = send_json(
        &env.client,
        reqwest::Method::DELETE,
        &format!("{}/api/sessions/{}", env.base, session_id),
        &env.key,
        &json!({}),
        Some(&env.csrf),
    )
    .await;
    assert!(status.is_success(), "DELETE session failed: {status} {body}");

    let conn = finished_guacd_connection(&env).await;
    assert!(conn.handshake_done, "handshake completed at mock guacd");
    assert!(
        conn.eof,
        "guacd socket must reach EOF on API terminate: {conn:?}"
    );

    // The record is removed (delete_session is terminal → history "completed").
    wait_for_session_gone(&env, &session_id).await;

    // Drain the now-dead WebSocket so the test exits cleanly.
    let _ = tokio::time::timeout(Duration::from_secs(5), ws.next()).await;
}

/// Terminating a Pending session (owner never connected) must close the
/// held guacd stream — the socket reaches EOF at guacd too.
#[tokio::test]
async fn terminate_pending_session_closes_held_guacd_stream() {
    let env = boot("pending").await;
    let session_id = create_session(&env).await;

    let (status, body) = send_json(
        &env.client,
        reqwest::Method::DELETE,
        &format!("{}/api/sessions/{}", env.base, session_id),
        &env.key,
        &json!({}),
        Some(&env.csrf),
    )
    .await;
    assert!(status.is_success(), "DELETE session failed: {status} {body}");

    let conn = finished_guacd_connection(&env).await;
    assert!(conn.handshake_done, "handshake completed at mock guacd");
    assert!(
        conn.eof,
        "guacd socket must reach EOF when a pending session is terminated: {conn:?}"
    );

    wait_for_session_gone(&env, &session_id).await;
}
