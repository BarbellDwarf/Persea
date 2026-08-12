//! Backend database integration tests (SQLx multi-backend).
//!
//! Proves the Postgres and MySQL backends are real stores: with `db_url`
//! set, the persea binary actually persists data in the configured backend
//! and that state survives a restart. Driven by env vars:
//!
//! - `TEST_DATABASE_URL_POSTGRES` — a postgres:// URL (runs the Postgres test)
//! - `TEST_DATABASE_URL_MYSQL` — a mysql:// URL (runs the MySQL test)
//!
//! Each test spawns the real `persea` binary with a config whose `db_url`
//! points at the backend under test, drives write+read round trips through
//! the HTTP API (user create/list, settings PUT/GET, address book folder +
//! entry CRUD), verifies the rows PHYSICALLY live in the backend's tables
//! via a direct SQLx connection to the same URL (the "no silent SQLite
//! fallback" proof), then kills and restarts the app against the same
//! database and re-verifies persistence.
//!
//! When the env var is unset the test skips with a visible message, so local
//! `cargo test` (SQLite-only) stays exactly as fast as before.

use serde_json::json;
use sqlx::{MySqlPool, PgPool, Row};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const POSTGRES_URL_ENV: &str = "TEST_DATABASE_URL_POSTGRES";
const MYSQL_URL_ENV: &str = "TEST_DATABASE_URL_MYSQL";
const HEALTH_TIMEOUT: Duration = Duration::from_secs(90);

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_persea")
}

#[tokio::test]
async fn postgres_backend_round_trip_and_persistence() {
    run_backend_test("postgres", POSTGRES_URL_ENV, "postgresql").await;
}

#[tokio::test]
async fn mysql_backend_round_trip_and_persistence() {
    run_backend_test("mysql", MYSQL_URL_ENV, "mysql").await;
}

macro_rules! check_rows_in_backend {
    ($pool:expr, $users_q:expr, $folders_q:expr, $entries_q:expr, $email:expr, $folder:expr, $entry:expr, $site_title:expr, $settings_q:expr $(,)?) => {{
        let row = sqlx::query($users_q)
            .bind(&$email)
            .bind(&$email)
            .fetch_one($pool)
            .await
            .unwrap();
        let count: i64 = row.get(0);
        assert!(
            count > 0,
            "user {} not found in the backend users table",
            $email
        );

        let row = sqlx::query($settings_q).fetch_one($pool).await.unwrap();
        let value: String = row.get(0);
        assert_eq!(
            value, $site_title,
            "site_title row in the backend system_settings table is wrong"
        );

        let row = sqlx::query($folders_q)
            .bind(&$folder)
            .fetch_one($pool)
            .await
            .unwrap();
        let count: i64 = row.get(0);
        assert!(
            count > 0,
            "folder {} not found in the backend address_book_folders table",
            $folder
        );

        let row = sqlx::query($entries_q)
            .bind(&$entry)
            .fetch_one($pool)
            .await
            .unwrap();
        let count: i64 = row.get(0);
        assert!(
            count > 0,
            "entry {} not found in the backend address_book_entries table",
            $entry
        );

        let row = sqlx::query("SELECT COUNT(*) FROM audit_events")
            .fetch_one($pool)
            .await
            .unwrap();
        let count: i64 = row.get(0);
        assert!(
            count > 0,
            "no audit rows landed in the backend audit_events table"
        );
    }};
}

async fn run_backend_test(label: &str, url_env: &str, expected_backend: &str) {
    let Some(db_url) = std::env::var(url_env).ok().filter(|u| !u.is_empty()) else {
        eprintln!(
            "SKIPPED {label} backend test: {url_env} is not set \
             (set it to a {label}:// URL to run this test)"
        );
        return;
    };
    eprintln!("backend test: running against {label} ({db_url})");

    let marker = format!("r104-{label}-{}", std::process::id());
    let email = format!("{marker}@example.test");
    let folder_name = format!("folder-{marker}");
    let entry_name = format!("entry-{marker}");
    let site_title = format!("site-{marker}");
    let admin_name = format!("admin-{marker}");

    let tmp = std::env::temp_dir().join(&marker);
    std::fs::create_dir_all(&tmp).expect("create scratch dir");
    let config_path = tmp.join("config.toml");
    let log_path = tmp.join("persea.log");
    let port = free_port();
    std::fs::write(
        &config_path,
        format!(
            "listen_addr = \"127.0.0.1:{port}\"\ndb_url = \"{db_url}\"\ndb_path = \"{}\"\n",
            tmp.join("admin.db").display()
        ),
    )
    .expect("write config");

    let key = create_admin_key(&config_path, &admin_name);

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{port}");

    let mut app = AppProc::new(&config_path, &log_path);
    wait_healthy(&client, &base, &mut app, &log_path).await;
    assert_backend_health(&client, &base, &key, expected_backend).await;

    round_trips(
        &client,
        &base,
        &key,
        &email,
        &folder_name,
        &entry_name,
        &site_title,
    )
    .await;
    assert_rows_in_backend(
        &db_url,
        expected_backend,
        &email,
        &folder_name,
        &entry_name,
        &site_title,
    )
    .await;

    terminate(&mut app);
    eprintln!("backend test: restarted persea against {label}");

    let mut app2 = AppProc::new(&config_path, &log_path);
    wait_healthy(&client, &base, &mut app2, &log_path).await;
    assert_backend_health(&client, &base, &key, expected_backend).await;

    let users = get_json(&client, &base, "/api/users", Some(&key)).await;
    assert!(
        users.to_string().contains(&email),
        "user created before restart is gone after restart: {users}"
    );
    let settings = get_json(&client, &base, "/api/system/settings", Some(&key)).await;
    assert_eq!(
        settings["site_title"], site_title,
        "site_title set before restart is gone after restart: {settings}"
    );
    let folders = get_json(&client, &base, "/api/addressbook/folders", Some(&key)).await;
    assert!(
        folders.to_string().contains(&folder_name),
        "address book folder created before restart is gone after restart: {folders}"
    );
    let entries_path = format!("/api/addressbook/folders/shared/{folder_name}/entries");
    let entries = get_json(&client, &base, &entries_path, Some(&key)).await;
    assert!(
        entries.to_string().contains(&entry_name),
        "address book entry created before restart is gone after restart: {entries}"
    );
    assert_rows_in_backend(
        &db_url,
        expected_backend,
        &email,
        &folder_name,
        &entry_name,
        &site_title,
    )
    .await;

    terminate(&mut app2);
    std::fs::remove_dir_all(&tmp).ok();
    eprintln!("backend test: PASSED against {label}");
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

async fn round_trips(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    email: &str,
    folder_name: &str,
    entry_name: &str,
    site_title: &str,
) {
    let csrf = fetch_csrf_token(client, base).await;
    let (status, body) = send_json(
        client,
        reqwest::Method::POST,
        &format!("{base}/api/users"),
        key,
        &json!({
            "email": email,
            "name": email,
            "role": "operator",
            "password": "backend-ci-passw0rd-2026",
        }),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, 201, "POST /api/users failed: {body}");
    let users = get_json(client, base, "/api/users", Some(key)).await;
    assert!(
        users.to_string().contains(email),
        "created user not visible via API: {users}"
    );

    let (status, body) = send_json(
        client,
        reqwest::Method::PUT,
        &format!("{base}/api/system/settings"),
        key,
        &json!({"site_title": site_title}),
        Some(&csrf),
    )
    .await;
    assert_eq!(status, 200, "PUT /api/system/settings failed: {body}");
    let settings = get_json(client, base, "/api/system/settings", Some(key)).await;
    assert_eq!(
        settings["site_title"], site_title,
        "site_title not persisted via API: {settings}"
    );

    let (status, body) = send_json(
        client,
        reqwest::Method::POST,
        &format!("{base}/api/addressbook/folders"),
        key,
        &json!({"name": folder_name, "allowed_groups": []}),
        Some(&csrf),
    )
    .await;
    assert!(
        status.is_success(),
        "POST address book folder failed: {status} {body}"
    );
    let (status, body) = send_json(
        client,
        reqwest::Method::POST,
        &format!("{base}/api/addressbook/folders/shared/{folder_name}/entries"),
        key,
        &json!({"name": entry_name, "type": "ssh", "hostname": "10.0.0.1"}),
        Some(&csrf),
    )
    .await;
    assert!(
        status.is_success(),
        "POST address book entry failed: {status} {body}"
    );

    let folders = get_json(client, base, "/api/addressbook/folders", Some(key)).await;
    assert!(
        folders.to_string().contains(folder_name),
        "folder not visible via API: {folders}"
    );
    let entries_path = format!("/api/addressbook/folders/shared/{folder_name}/entries");
    let entries = get_json(client, base, &entries_path, Some(key)).await;
    assert!(
        entries.to_string().contains(entry_name),
        "entry not visible via API: {entries}"
    );
}

async fn assert_rows_in_backend(
    db_url: &str,
    expected_backend: &str,
    email: &str,
    folder_name: &str,
    entry_name: &str,
    site_title: &str,
) {
    match expected_backend {
        "postgresql" => {
            let pool = PgPool::connect(db_url)
                .await
                .expect("direct connection to Postgres");
            check_rows_in_backend!(
                &pool,
                "SELECT COUNT(*) FROM users WHERE email = $1 OR username = $1",
                "SELECT COUNT(*) FROM address_book_folders WHERE name = $1",
                "SELECT COUNT(*) FROM address_book_entries WHERE name = $1",
                email,
                folder_name,
                entry_name,
                site_title,
                "SELECT value FROM system_settings WHERE key = 'site_title'",
            );
        }
        "mysql" => {
            let pool = MySqlPool::connect(db_url)
                .await
                .expect("direct connection to MySQL");
            check_rows_in_backend!(
                &pool,
                "SELECT COUNT(*) FROM users WHERE email = ? OR username = ?",
                "SELECT COUNT(*) FROM address_book_folders WHERE name = ?",
                "SELECT COUNT(*) FROM address_book_entries WHERE name = ?",
                email,
                folder_name,
                entry_name,
                site_title,
                "SELECT value FROM system_settings WHERE `key` = 'site_title'",
            );
        }
        other => panic!("unexpected expected_backend: {other}"),
    }
}

async fn assert_backend_health(
    client: &reqwest::Client,
    base: &str,
    key: &str,
    expected_backend: &str,
) {
    let health = get_json(client, base, "/api/health", Some(key)).await;
    let pool = &health["checks"]["db_pool"];
    assert_eq!(
        pool["status"], "up",
        "deep db_pool health check not up: {health}"
    );
    assert_eq!(
        pool["backend"], expected_backend,
        "db_pool reports backend {:?} — expected {expected_backend} (no silent SQLite fallback): {health}",
        pool["backend"]
    );
}

async fn get_json(
    client: &reqwest::Client,
    base: &str,
    path: &str,
    key: Option<&str>,
) -> serde_json::Value {
    let mut request = client.get(format!("{base}{path}"));
    if let Some(k) = key {
        request = request.bearer_auth(k);
    }
    let resp = request
        .send()
        .await
        .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    assert!(status.is_success(), "GET {path} returned {status}: {text}");
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("invalid JSON from {path}: {e}: {text}"))
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

fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

fn terminate(app: &mut AppProc) {
    let pid = app.child.id() as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if app.child.try_wait().expect("wait on child").is_some() {
            return;
        }
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = app.child.kill();
    let _ = app.child.wait();
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
