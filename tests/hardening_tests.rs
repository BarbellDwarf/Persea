//! Security + performance hardening integration tests (wayfinder/v1.2.0/S12).
//!
//! Covers, against a live persea binary with a mock guacd:
//! - S02: Proxmox session URLs are network-validated (169.254.169.254
//!   rejected even with a 0.0.0.0/0 allowlist).
//! - S06: web session URLs get the hardcoded cloud-metadata deny
//!   regardless of the configured allowlist.
//! - R01: new RDP sessions default enable_h264/enable_gfx to true.
//! - R02: session history insert is fire-and-forget (response not held up;
//!   the row still lands).
//! - R05: hostname targets parallelize DNS validation + guacd connect;
//!   a failed network check aborts the guacd handshake; guacd failure
//!   surfaces as a guacd error.
//! - R04: `last_instruction_boundary` fast-path correctness (small buffers
//!   ending in `;`, embedded semicolons, multibyte fallback, large
//!   buffers).
//!
//! H01 fingerprint forgery tests live in src/oidc.rs's test module (the
//! fingerprint helpers are private to that module).

use persea::protocol::{last_instruction_boundary, Instruction, InstructionParser};
use serde_json::json;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

const HEALTH_TIMEOUT: Duration = Duration::from_secs(30);
const ASSERT_DEADLINE: Duration = Duration::from_secs(15);

// ── Test environment (mirrors tests/teardown_tests.rs) ──────────────

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

// ── Mock guacd ─────────────────────────────────────────────────────

/// What one mock-guacd connection observed.
#[derive(Debug, Default, Clone)]
struct MockConn {
    /// `ready` was replied to `connect` (persea's handshake completed).
    handshake_done: bool,
    /// Socket EOF was observed (persea actively closed the connection).
    eof: bool,
    /// `connect` instruction args: (arg name, value) as requested by the
    /// mock's `args` instruction (used to observe RDP media defaults).
    connect_args: Vec<(String, String)>,
}

/// Mock guacd: reply `args` (with the given parameter names) to `select`,
/// `ready` to `connect`, record the connect args, and record EOF.
/// `reply_delay` slows the args reply so an aborted handshake is
/// observable (the connection stays half-open through the delay).
async fn mock_guacd(
    listener: tokio::net::TcpListener,
    results: Arc<Mutex<Vec<MockConn>>>,
    args_names: Vec<String>,
    reply_delay: Option<Duration>,
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
                                    if let Some(d) = reply_delay {
                                        tokio::time::sleep(d).await;
                                    }
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

// ── Boot helper ────────────────────────────────────────────────────

struct TestEnv {
    base: String,
    key: String,
    csrf: String,
    client: reqwest::Client,
    guacd_results: Option<Arc<Mutex<Vec<MockConn>>>>,
    _tmp: PathBuf,
    _app: support::AppProc,
}

/// Boot persea with a mock guacd (or `guacd_addr_override` when the test
/// needs a dead guacd endpoint). `extra_config` is appended verbatim to
/// config.toml; `args_names` is the mock's `args` instruction parameter
/// list; `reply_delay` slows the mock's args reply.
async fn boot(
    tag: &str,
    extra_config: &str,
    args_names: &[&str],
    reply_delay: Option<Duration>,
    guacd_addr_override: Option<String>,
) -> TestEnv {
    let marker = format!("s12-{tag}-{}", std::process::id());
    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");

    let (guacd_addr, guacd_results) = match guacd_addr_override {
        Some(addr) => (addr, None),
        None => {
            let results = Arc::new(Mutex::new(Vec::new()));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind mock guacd");
            let addr = listener.local_addr().expect("guacd addr");
            tokio::spawn(mock_guacd(
                listener,
                results.clone(),
                args_names.iter().map(|s| s.to_string()).collect(),
                reply_delay,
            ));
            (addr.to_string(), Some(results))
        }
    };

    let db_path = tmp.join("admin.db").display().to_string();
    let booted = support::boot_persea(
        &marker,
        &config_path,
        &log_path,
        None,
        HEALTH_TIMEOUT,
        &|port: u16| {
            format!(
                "listen_addr = \"127.0.0.1:{port}\"\ndb_path = \"{db_path}\"\nguacd_addr = \"{guacd_addr}\"\n{extra_config}"
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
        guacd_results,
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

// ── S02 + S06: SSRF / cloud-metadata denies ────────────────────────

#[tokio::test]
async fn proxmox_and_web_metadata_targets_rejected_even_with_wide_allowlist() {
    let env = boot(
        "ssrf",
        "web_allowed_networks = [\"0.0.0.0/0\"]\n",
        &[
            "hostname", "port", "username", "password", "width", "height", "dpi",
        ],
        None,
        None,
    )
    .await;

    // S02: Proxmox session pointed at cloud metadata must fail validation
    // even though 0.0.0.0/0 would allow it.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "proxmox",
            "proxmox_url": "https://169.254.169.254:8006",
            "proxmox_vmid": 100,
            "proxmox_token_id": "root@pam!t",
            "proxmox_token_secret": "s",
            "username": "root",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "metadata URL must be a validation error: {body}"
    );
    assert!(
        body.contains("blocked"),
        "expected metadata deny message, got: {body}"
    );

    // S02: a valid LAN URL passes the network validation — the failure
    // must come from the PVE broker (no real PVE here), not the checks.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "proxmox",
            "proxmox_url": "https://127.0.0.1:8006",
            "proxmox_vmid": 100,
            "proxmox_token_id": "root@pam!t",
            "proxmox_token_secret": "s",
            "username": "root",
            "proxmox_verify_tls": false,
        }),
    )
    .await;
    assert_eq!(status, 400, "LAN URL must pass validation: {body}");
    assert!(
        body.contains("node lookup failed"),
        "LAN URL should reach the PVE broker stage, got: {body}"
    );
    assert!(
        !body.contains("blocked"),
        "LAN URL must not trip the metadata deny: {body}"
    );

    // S06: web session targeting cloud metadata must be rejected even
    // with the wide allowlist.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "web",
            "url": "https://169.254.169.254/",
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "web metadata URL must be a validation error: {body}"
    );
    assert!(
        body.contains("blocked"),
        "expected metadata deny message, got: {body}"
    );

    // S06 control: a valid URL passes the network checks (fails later at
    // browser spawn, which is a sanitized infrastructure error).
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "web",
            "url": "https://127.0.0.1/",
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(
        status, 502,
        "valid URL must pass network checks and fail at browser spawn: {body}"
    );
    assert!(
        !body.contains("blocked"),
        "valid URL must not trip the metadata deny: {body}"
    );
}

// ── R01: RDP media defaults ────────────────────────────────────────

/// Arg names the mock guacd requests for an RDP connection, including the
/// media-pipeline toggles so persea's connect instruction carries them.
const RDP_ARGS: &[&str] = &[
    "hostname",
    "port",
    "username",
    "password",
    "width",
    "height",
    "dpi",
    "disable-gfx",
    "enable-h264",
];

async fn rdp_connect_args(env: &TestEnv, deadline: Duration) -> Vec<(String, String)> {
    let results = env.guacd_results.as_ref().expect("mock guacd");
    let start = Instant::now();
    loop {
        // Live handshake records: sessions hold the socket open, so each
        // completed handshake is pushed immediately; take the LAST one so
        // consecutive sessions are observed in order.
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
            start.elapsed() < deadline,
            "timed out waiting for mock guacd handshake"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn rdp_sessions_default_to_h264_and_gfx_on() {
    let env = boot("rdp", "", RDP_ARGS, None, None).await;

    // Defaults: no enable_h264 / enable_gfx in the request → both on.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "rdp",
            "hostname": "127.0.0.1",
            "port": 3389,
            "username": "u",
            "password": "p",
            "width": 800,
            "height": 600,
        }),
    )
    .await;
    assert_eq!(status, 200, "RDP session create failed: {body}");

    let args = rdp_connect_args(&env, ASSERT_DEADLINE).await;
    let get = |name: &str| -> String {
        args.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("connect instruction missing arg {name}: {args:?}"))
    };
    assert_eq!(get("disable-gfx"), "false", "GFX must default ON: {args:?}");
    assert_eq!(
        get("enable-h264"),
        "true",
        "H.264 must default ON: {args:?}"
    );

    // Explicit overrides still win.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "rdp",
            "hostname": "127.0.0.1",
            "port": 3389,
            "username": "u",
            "password": "p",
            "width": 800,
            "height": 600,
            "enable_h264": false,
            "enable_gfx": false,
        }),
    )
    .await;
    assert_eq!(status, 200, "RDP session create (override) failed: {body}");

    let args = rdp_connect_args(&env, ASSERT_DEADLINE).await;
    let get = |name: &str| -> String {
        args.iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("connect instruction missing arg {name}: {args:?}"))
    };
    assert_eq!(
        get("disable-gfx"),
        "true",
        "explicit GFX off must win: {args:?}"
    );
    assert_eq!(
        get("enable-h264"),
        "false",
        "explicit H.264 off must win: {args:?}"
    );
}

// ── R02: fire-and-forget session history insert ────────────────────

#[tokio::test]
async fn session_history_insert_lands_despite_fire_and_forget() {
    let env = boot(
        "hist",
        "",
        &[
            "hostname", "port", "username", "password", "width", "height", "dpi",
        ],
        None,
        None,
    )
    .await;

    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "ssh",
            "hostname": "127.0.0.1",
            "port": 22,
            "username": "root",
            "password": "test",
        }),
    )
    .await;
    assert_eq!(status, 200, "SSH session create failed: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("session create JSON");
    let session_id = v["session_id"]
        .as_str()
        .expect("session_id in create response")
        .to_string();

    // The insert is fire-and-forget, so it may land slightly after the
    // response; it must land. Poll the history endpoint.
    let deadline = Instant::now() + ASSERT_DEADLINE;
    loop {
        let (status, body) = send_json(
            &env.client,
            reqwest::Method::GET,
            &format!("{}/api/sessions/recent?limit=50", env.base),
            &env.key,
            &json!({}),
            None,
        )
        .await;
        assert_eq!(status, 200, "GET /api/sessions/recent failed: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("recent JSON");
        let found = v["recent"]
            .as_array()
            .map(|rows| {
                rows.iter()
                    .any(|r| r["session_id"].as_str() == Some(&session_id))
            })
            .unwrap_or(false);
        if found {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session history row never appeared (fire-and-forget insert lost?)"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── R05: parallel DNS + guacd connect ──────────────────────────────

#[tokio::test]
async fn hostname_target_network_failure_aborts_guacd_connect() {
    // "localhost" resolves via /etc/hosts (offline-safe) to 127.0.0.1,
    // which is NOT in 10.0.0.0/8: the DNS/allowlist branch fails after a
    // real resolution. The mock guacd delays its args reply by 3s, so a
    // guacd handshake that is NOT aborted would complete and be observed.
    let env = boot(
        "abort",
        "ssh_allowed_networks = [\"10.0.0.0/8\"]\n",
        &[
            "hostname", "port", "username", "password", "width", "height", "dpi",
        ],
        Some(Duration::from_secs(3)),
        None,
    )
    .await;

    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "ssh",
            "hostname": "localhost",
            "port": 22,
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "off-allowlist hostname must be rejected: {body}"
    );
    assert!(
        body.contains("allowed network"),
        "expected allowlist rejection, got: {body}"
    );

    // Give a non-aborted handshake (3s delay) ample time to complete.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let results = env.guacd_results.expect("mock guacd");
    let conns = results.lock().await.clone();
    assert!(
        conns.len() <= 1,
        "expected at most one aborted guacd connection, got {conns:?}"
    );
    assert!(
        conns.iter().all(|c| !c.handshake_done),
        "guacd handshake completed despite DNS failure — abort missing: {conns:?}"
    );
}

#[tokio::test]
async fn guacd_failure_returns_guacd_error_for_hostname_and_ip_targets() {
    // Dead guacd endpoint: bind then drop the listener so the port is free.
    let dead_listener = TcpListener::bind("127.0.0.1:0").expect("bind dead guacd port");
    let dead_addr = dead_listener.local_addr().expect("dead guacd addr");
    drop(dead_listener);

    let env = boot(
        "guacderr",
        "",
        &[
            "hostname", "port", "username", "password", "width", "height", "dpi",
        ],
        None,
        Some(dead_addr.to_string()),
    )
    .await;

    // Hostname target: parallel path — DNS passes (localhost is in the
    // default allowlist), the guacd error must surface.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "ssh",
            "hostname": "localhost",
            "port": 22,
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(
        status, 502,
        "guacd connect failure must surface as an error: {body}"
    );

    // IP target: sequential path unchanged — same failure mode.
    let (status, body) = create_session(
        &env,
        &json!({
            "session_type": "ssh",
            "hostname": "127.0.0.1",
            "port": 22,
            "username": "u",
            "password": "p",
        }),
    )
    .await;
    assert_eq!(
        status, 502,
        "guacd connect failure must surface for IP targets too: {body}"
    );
}

// ── R04: instruction-boundary fast path ────────────────────────────

#[test]
fn boundary_fast_path_small_complete_instructions() {
    // The SSH common case: one small complete instruction. The fast path
    // must resolve it to the buffer end.
    let s = b"4.size,3.800,3.600;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
    let s = b"3.nop;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_multiple_complete_instructions() {
    let s = b"4.size,3.800,3.600;3.nop;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_never_claims_partial_instruction_with_trailing_semicolon() {
    // Regression guard for the naive "ends with ';'" heuristic: the
    // trailing `;` here is DATA inside an unfinished 11-char element, not
    // a terminator. Small (< 1 KiB) and ends in ';' — exactly the case a
    // naive fast path would get wrong.
    let s = b"9.clipboard,1.0,11.hello;";
    assert_eq!(last_instruction_boundary(s), None);
}

#[test]
fn boundary_fast_path_embedded_semicolon_complete_instruction() {
    // A complete instruction whose element data contains `;`: the walk
    // uses declared lengths, so the boundary is the real terminator.
    let s = b"9.clipboard,1.0,11.hello;world;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_multibyte_data_falls_back_to_full_scan() {
    // Non-ASCII data disables the fast path (lengths count chars, not
    // bytes); the full scan still finds the correct boundary.
    let s = "9.clipboard,1.0,4.café;".as_bytes();
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_large_buffer_uses_full_scan() {
    // ≥ 1 KiB complete instruction: outside the fast-path scope, the full
    // scan must still return the exact boundary.
    let payload = "x".repeat(1200);
    let big = format!(
        "3.img,3.jpg,3.100,3.100,3.100,3.100,{}.{};",
        payload.len(),
        payload
    );
    assert!(big.len() >= 1024, "test buffer must exceed fast-path scope");
    let s = big.as_bytes();
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_complete_then_partial_tail() {
    // Complete instruction followed by a truncated one whose data ends
    // in ';': the boundary is the first instruction only.
    let s = b"3.nop;9.clipboard,1.0,11.hello;";
    assert_eq!(last_instruction_boundary(s), Some(6));
}

#[test]
fn boundary_fast_path_zero_length_element() {
    let s = b"0.,4.ping,13.1234567890123;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_instruction_with_binary_digit_data() {
    // Element data that itself starts with digits must not confuse the
    // structural walk (it skips data by declared length, never re-parses).
    let s = b"3.siz,1.0,1.5;";
    assert_eq!(last_instruction_boundary(s), Some(s.len()));
}

#[test]
fn boundary_fast_path_encoded_roundtrip_instructions() {
    // Everything Instruction::encode produces must round-trip through the
    // fast path for the complete buffer.
    for instr in [
        Instruction::new("size", vec!["800".into(), "600".into()]),
        Instruction::new("nop", vec![]),
        Instruction::new("key", vec!["x".into(), "1".into()]),
        Instruction::new("clipboard", vec!["text".into(), "1".into(), "a;b;c".into()]),
        Instruction::new(
            "img",
            vec![
                "jpg".into(),
                "1".into(),
                "2".into(),
                "3".into(),
                "4".into(),
                "5".into(),
                "data".into(),
            ],
        ),
    ] {
        let encoded = instr.encode();
        let bytes = encoded.as_bytes();
        assert!(
            bytes.len() < 1024,
            "test instruction too large for fast-path scope"
        );
        assert_eq!(
            last_instruction_boundary(bytes),
            Some(bytes.len()),
            "encoded instruction must resolve to its own end: {encoded:?}"
        );
    }
}
