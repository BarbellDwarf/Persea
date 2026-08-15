//! RDP client-name forwarding integration tests.
//!
//! Boots a live persea binary against a mock guacd (same pattern as
//! tests/hardening_tests.rs) and asserts the `client-name` connect arg:
//! - default template "{user}@{host}": reverse-DNS of the connecting
//!   client IP (127.0.0.1 resolves to "localhost" via /etc/hosts);
//! - custom template with the user + host tokens;
//! - `client_name_template = ""` disables the parameter (empty value,
//!   byte-for-byte what pre-feature builds sent);
//! - DNS failure falls back to the raw client IP with no delay;
//! - SSH and VNC sessions never carry a client name (RDP-only).

use persea::protocol::{Instruction, InstructionParser};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const ASSERT_DEADLINE: Duration = Duration::from_secs(15);

mod support;

// ── Mock guacd (mirrors tests/hardening_tests.rs) ───────────────────

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

// ── Boot helper (mirrors tests/hardening_tests.rs) ──────────────────

struct TestEnv {
    base: String,
    key: String,
    csrf: String,
    client: reqwest::Client,
    guacd_results: Arc<Mutex<Vec<MockConn>>>,
    _tmp: PathBuf,
    _app: support::AppProc,
}

async fn boot(tag: &str, extra_config: &str, args_names: &[&str]) -> TestEnv {
    let marker = format!("s26-{tag}-{}", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");

    let results = Arc::new(Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock guacd");
    let guacd_addr = listener.local_addr().expect("guacd addr").to_string();
    tokio::spawn(mock_guacd(
        listener,
        results.clone(),
        args_names.iter().map(|s| s.to_string()).collect(),
    ));

    let db_path = tmp.join("admin.db").display().to_string();
    let booted = support::boot_persea(
        "alice",
        &config_path,
        &log_path,
        None,
        HEALTH_TIMEOUT,
        &|port: u16| {
            format!(
                "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{db_path}\"\nguacd_addr = \"{guacd_addr}\"\n{extra_config}\n[storage]\nencryption_key = \"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\"\n"
            )
        },
    )
    .await;

    // Double-submit CSRF: GET the app root and echo the cookie back.
    let resp = booted
        .client
        .get(format!("{}/", booted.base))
        .send()
        .await
        .expect("GET / for CSRF token");
    let csrf = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|c| c.starts_with("csrf_token="))
        .unwrap_or_else(|| panic!("no csrf_token Set-Cookie in {:?}", resp.headers()))
        .split(';')
        .next()
        .unwrap()
        .strip_prefix("csrf_token=")
        .unwrap()
        .to_string();

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

async fn send_json(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    csrf: &str,
    body: &serde_json::Value,
    extra_headers: &[(&str, &str)],
) -> (reqwest::StatusCode, String) {
    let mut request = client
        .post(format!("{base}/api/sessions"))
        .bearer_auth(key)
        .header("X-CSRF-Token", csrf)
        .header("Cookie", format!("csrf_token={csrf}"))
        .json(body);
    for (k, v) in extra_headers {
        request = request.header(*k, *v);
    }
    let resp = request
        .send()
        .await
        .unwrap_or_else(|e| panic!("request to {base}/api/sessions failed: {e}"));
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    (status, text)
}

/// Poll the mock-guacd records for the most recent completed handshake
/// and return its connect args.
async fn last_connect_args(env: &TestEnv) -> Vec<(String, String)> {
    let start = std::time::Instant::now();
    loop {
        let live: Vec<Vec<(String, String)>> = env
            .guacd_results
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

// ── Tests ───────────────────────────────────────────────────────────

/// Arg names the mock guacd requests for an RDP connection, including
/// `client-name` so persea's connect instruction carries it.
const RDP_ARGS: &[&str] = &[
    "hostname",
    "port",
    "username",
    "password",
    "domain",
    "security",
    "client-name",
    "width",
    "height",
    "dpi",
    "enable-drive",
    "auth-pkg",
    "disable-gfx",
    "enable-h264",
];

fn rdp_body() -> serde_json::Value {
    json!({
        "session_type": "rdp",
        "hostname": "127.0.0.1",
        "port": 3389,
        "username": "u",
        "password": "p",
        "width": 800,
        "height": 600,
    })
}

#[tokio::test]
async fn default_template_sends_resolved_client_hostname() {
    // No [rdp] section: the default template "{user}@{host}" applies.
    // The connecting client is 127.0.0.1, which reverse-resolves to
    // "localhost" via /etc/hosts.
    let env = boot("default", "", RDP_ARGS).await;

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &rdp_body(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");

    let args = last_connect_args(&env).await;
    assert_eq!(
        arg(&args, "client-name"),
        "alice@localhost",
        "default template must expand user and host: {args:?}"
    );
}

#[tokio::test]
async fn custom_template_expands_user_and_host_tokens() {
    let env = boot(
        "custom",
        "[rdp]\nclient_name_template = \"{user}:{host}\"\n",
        RDP_ARGS,
    )
    .await;

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &rdp_body(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");

    let args = last_connect_args(&env).await;
    assert_eq!(
        arg(&args, "client-name"),
        "alice:localhost",
        "custom template must expand: {args:?}"
    );
}

#[tokio::test]
async fn empty_template_disables_client_name() {
    // Empty template: the connect arg must be an empty string — exactly
    // what pre-feature builds sent for the unknown parameter.
    let env = boot("disabled", "[rdp]\nclient_name_template = \"\"\n", RDP_ARGS).await;

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &rdp_body(),
        &[],
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");

    let args = last_connect_args(&env).await;
    assert_eq!(arg(&args, "client-name"), "", "disabled template: {args:?}");
}

#[tokio::test]
async fn dns_failure_falls_back_to_raw_client_ip() {
    // Trusted proxy: the real client is whatever X-Forwarded-For claims.
    // 203.0.113.7 is TEST-NET-3 (RFC 5737) — no PTR record exists, so the
    // reverse lookup fails and the raw IP must be used.
    let env = boot("xff", "trusted_proxies = [\"127.0.0.1\"]\n", RDP_ARGS).await;

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &rdp_body(),
        &[("X-Forwarded-For", "203.0.113.7")],
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");

    let args = last_connect_args(&env).await;
    assert_eq!(
        arg(&args, "client-name"),
        "alice@203.0.113.7",
        "DNS failure must fall back to the raw IP: {args:?}"
    );
}

#[tokio::test]
async fn ssh_and_vnc_sessions_never_carry_client_name() {
    // The mock requests "client-name" for SSH and VNC too: persea must
    // answer with an empty value (the parameter is RDP-only).
    let ssh_args: Vec<&str> = vec![
        "hostname",
        "port",
        "username",
        "password",
        "width",
        "height",
        "dpi",
        "client-name",
    ];
    let vnc_args: Vec<&str> = vec!["hostname", "port", "password", "color-depth", "client-name"];
    let mut all = ssh_args.clone();
    all.extend(vnc_args);
    let env = boot("other-protocols", "", &all).await;

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &json!({
            "session_type": "ssh",
            "hostname": "127.0.0.1",
            "port": 22,
            "username": "u",
            "password": "p",
        }),
        &[],
    )
    .await;
    assert_eq!(status, 200, "SSH session create failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(
        arg(&args, "client-name"),
        "",
        "SSH must not carry an RDP client name: {args:?}"
    );

    let (status, body) = send_json(
        &env.client,
        &env.base,
        &env.key,
        &env.csrf,
        &json!({
            "session_type": "vnc",
            "hostname": "127.0.0.1",
            "port": 5900,
            "password": "p",
        }),
        &[],
    )
    .await;
    assert_eq!(status, 200, "VNC session create failed: {body}");
    let args = last_connect_args(&env).await;
    assert_eq!(
        arg(&args, "client-name"),
        "",
        "VNC must not carry an RDP client name: {args:?}"
    );
}
