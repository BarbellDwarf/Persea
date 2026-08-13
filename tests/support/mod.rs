//! Shared test harness helpers for the integration test binaries.
//!
//! The boot path in the full-stack test files (teardown_tests,
//! backend_tests, hardening_tests) spawns a real persea child process
//! against a port chosen with the old bind-then-release trick, which
//! raced with other test binaries running in parallel: another binary
//! could grab the port between release and persea's bind, persea exited
//! EADDRINUSE, and the boot failed.
//!
//! [`boot_persea`] closes that race two ways:
//! 1. The port is RESERVED with a held `TcpListener` for the whole
//!    pre-spawn window (config write, `persea add-admin`), and released
//!    only right before the server child is spawned, so no other test can
//!    steal it during that span.
//! 2. If the child still exits before becoming healthy (the residual
//!    release→bind window, or any other early failure), the boot is
//!    retried with a FRESH port, up to [`BOOT_ATTEMPTS`] times.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub const BOOT_ATTEMPTS: usize = 3;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_persea")
}

/// A port kept reserved by holding a bound `TcpListener` on it. While the
/// listener is alive no other process can bind the port; call
/// [`release()`](Self::release) immediately before spawning persea so the
/// child can bind it.
pub struct ReservedPort {
    listener: Option<TcpListener>,
    port: u16,
}

impl ReservedPort {
    pub fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let port = listener.local_addr().expect("local addr").port();
        ReservedPort {
            listener: Some(listener),
            port,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Release the reservation so the child process can bind the port.
    pub fn release(&mut self) {
        self.listener = None;
    }
}

/// A spawned persea server process; killed on drop.
pub struct AppProc {
    pub child: Child,
}

impl AppProc {
    pub fn new(config_path: &PathBuf, log_path: &PathBuf) -> Self {
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

/// Poll `/api/health` until persea responds, the child exits early, or
/// `health_timeout` elapses.
async fn wait_healthy(
    client: &reqwest::Client,
    base: &str,
    app: &mut AppProc,
    log_path: &PathBuf,
    health_timeout: Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + health_timeout;
    loop {
        let ok = match client.get(format!("{base}/api/health")).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        };
        if ok {
            return Ok(());
        }
        if let Some(status) = app.child.try_wait().expect("wait on child") {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            return Err(format!("persea exited early with {status}; log:\n{log}"));
        }
        if tokio::time::Instant::now() >= deadline {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            return Err(format!(
                "persea did not become healthy within {health_timeout:?}; log:\n{log}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Everything a booted persea gives a test.
pub struct Booted {
    pub base: String,
    pub key: String,
    pub client: reqwest::Client,
    pub app: AppProc,
}

/// Spawn persea against a reserved port and wait for health.
///
/// `write_config` renders config.toml for the chosen port. When
/// `admin_key` is `None`, `persea add-admin` is run once (first attempt
/// only) and its API key is returned; pass `Some(key)` to reuse an
/// existing admin on later boots.
///
/// If the child exits before becoming healthy (the EADDRINUSE port-steal
/// race, or any other early failure), the attempt is torn down and
/// retried with a fresh port, up to `BOOT_ATTEMPTS` times.
/// `health_timeout` bounds each attempt's health poll (backend tests use
/// longer timeouts for slow remote databases).
pub async fn boot_persea<F>(
    admin_name: &str,
    config_path: &PathBuf,
    log_path: &PathBuf,
    admin_key: Option<String>,
    health_timeout: Duration,
    write_config: &F,
) -> Booted
where
    F: Fn(u16) -> String,
{
    let client = reqwest::Client::new();
    let mut reserved = ReservedPort::bind();
    let mut key = admin_key;
    let mut last_err = String::new();
    for attempt in 1..=BOOT_ATTEMPTS {
        let port = reserved.port();
        std::fs::write(config_path, write_config(port)).expect("write config");
        if key.is_none() {
            key = Some(create_admin_key(config_path, admin_name));
        }
        let base = format!("http://127.0.0.1:{port}");
        reserved.release();
        let mut app = AppProc::new(config_path, log_path);
        match wait_healthy(&client, &base, &mut app, log_path, health_timeout).await {
            Ok(()) => {
                return Booted {
                    base: base.clone(),
                    key: key.expect("key set"),
                    client,
                    app,
                };
            }
            Err(err) => {
                last_err = err;
                drop(app);
                if attempt == BOOT_ATTEMPTS {
                    break;
                }
                reserved = ReservedPort::bind();
            }
        }
    }
    panic!(
        "persea failed to become healthy after {BOOT_ATTEMPTS} attempts \
         (last failure: {last_err})"
    );
}
