//! U04: feature-toggle persistence and enforcement.
//!
//! Three layers, mirroring how the toggles flow through the app:
//! 1. The settings API persists `desktop_kiosk` / `desktop_transfers` /
//!    `desktop_pairing` (and the existing `enable_*` toggles) as booleans
//!    in `system_settings`, defaulting to ON when absent, admin-only PUT.
//! 2. `FeatureFlags::from_settings` (the plumbing that gates the sidebar,
//!    the connections entry-type dropdown, and the sessions ad-hoc
//!    dropdown) flips with the stored values and defaults to all-ON.
//! 3. The request-time page gates 404 when a toggle is off: the real
//!    recordings/tunnels page handlers self-gate via `read_toggle`, and
//!    the tokens pages are gated by the `feature_gate` middleware.
//! 4. The admin settings page renders with the five-section submenu bar
//!    (Session / Features / Storage / Security / Updates), keeps every
//!    toggle and field, and stays CSP-clean (nonce'd script, no inline
//!    handlers).
//!
//! The handlers and the settings module live in the binary crate's module
//! graph, so they are included directly (`#[path]`) with crate-root shims
//! for the `crate::` paths they use, following the pattern of
//! `tests/settings_api_tests.rs`.

mod api {
    pub use persea::api::{AppState, SettingsBaseline, SiteTitle, ThemeData};
}
mod audit {
    pub use persea::audit::*;
}
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
mod password {
    pub use persea::password::*;
}
mod settings_merge {
    pub use persea::settings_merge::*;
}
mod templates {
    pub use persea::templates::*;
}

/// Stand-in for the binary crate's `CspNonce(String)`.
#[derive(Clone)]
pub struct CspNonce(pub String);

#[path = "../src/handlers/account.rs"]
#[allow(dead_code)]
mod account;
#[path = "../src/handlers/pages.rs"]
#[allow(dead_code)]
mod pages;
#[path = "../src/api/settings.rs"]
#[allow(dead_code)]
mod settings;

use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use axum::routing::get;
use axum::{middleware, Extension, Router};
use persea::api::ThemeData;
use persea::auth::TrustedProxies;
use persea::db::Db;
use persea::templates::{AppLayoutTemplate, FeatureFlags};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

fn test_db() -> Db {
    persea::db::init_db(std::path::Path::new(":memory:")).unwrap()
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn test_theme() -> ThemeData {
    ThemeData {
        admin_preset: "dark".into(),
        admin_colors: persea::config::builtin_presets()
            .first()
            .map(|(_, c)| c.clone())
            .expect("builtin presets exist"),
        logo_url: None,
        presets: HashMap::new(),
    }
}

/// Store a setting exactly as the settings API would.
fn set_setting(db: &Db, key: &str, value: &str) {
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS system_settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL DEFAULT '',
            updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO system_settings (key, value, updated_at)
         VALUES (?1, ?2, CURRENT_TIMESTAMP)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
        rusqlite::params![key, value],
    )
    .unwrap();
}

// ── 1. Settings API: persistence and defaults ─────────────────────────────

fn create_admin(db: &Db, name: &str) -> String {
    db::add_admin(db, name, None, None).unwrap()
}

/// Mirrors the real route wiring: `require_auth` middleware + extensions.
fn settings_router(db: Db) -> Router {
    Router::new()
        .route(
            "/api/system/settings",
            get(settings::get_settings).put(settings::put_settings),
        )
        .layer(middleware::from_fn(persea::auth::require_auth))
        .layer(Extension(TrustedProxies(Vec::new())))
        .layer(Extension(db))
}

fn admin_get(key: &str, path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .extension(fake_addr())
        .body(axum::body::Body::empty())
        .unwrap()
}

fn admin_put(key: &str, path: &str, body: serde_json::Value) -> Request<axum::body::Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
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
async fn desktop_toggles_default_on_when_unset() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = settings_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    for k in ["desktop_kiosk", "desktop_transfers", "desktop_pairing"] {
        assert_eq!(json[k].as_bool(), Some(true), "key {k}");
    }
}

#[tokio::test]
async fn desktop_toggles_persist_and_survive_a_fresh_router() {
    let db = test_db();
    let key = create_admin(&db, "admin");

    let router = settings_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({
                "desktop_kiosk": false,
                "desktop_transfers": false,
                "desktop_pairing": false,
                "enable_rdp": false,
                "enable_vdi": false,
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let saved = body_json(resp).await;
    assert_eq!(saved["desktop_kiosk"].as_bool(), Some(false));
    assert_eq!(saved["desktop_transfers"].as_bool(), Some(false));
    assert_eq!(saved["desktop_pairing"].as_bool(), Some(false));

    // A fresh router over the same DB must see the stored values.
    let router = settings_router(db);
    let resp = router
        .oneshot(admin_get(&key, "/api/system/settings"))
        .await
        .unwrap();
    let json = body_json(resp).await;
    assert_eq!(json["desktop_kiosk"].as_bool(), Some(false));
    assert_eq!(json["desktop_transfers"].as_bool(), Some(false));
    assert_eq!(json["desktop_pairing"].as_bool(), Some(false));
    assert_eq!(json["enable_rdp"].as_bool(), Some(false));
    assert_eq!(json["enable_vdi"].as_bool(), Some(false));
}

#[tokio::test]
async fn desktop_toggles_round_trip_back_on() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = settings_router(db.clone());
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"desktop_pairing": true}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json["desktop_pairing"].as_bool(), Some(true));
}

#[tokio::test]
async fn desktop_toggle_put_requires_admin() {
    let db = test_db();
    let router = settings_router(db);
    let resp = router
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri("/api/system/settings")
                .header(header::CONTENT_TYPE, "application/json")
                .extension(fake_addr())
                .body(axum::body::Body::from(
                    serde_json::to_string(&serde_json::json!({"desktop_kiosk": false})).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn desktop_toggle_rejects_non_boolean() {
    let db = test_db();
    let key = create_admin(&db, "admin");
    let router = settings_router(db);
    let resp = router
        .oneshot(admin_put(
            &key,
            "/api/system/settings",
            serde_json::json!({"desktop_kiosk": "maybe"}),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── 2. FeatureFlags plumbing (sidebar + dropdown gates) ───────────────────

#[test]
fn feature_flags_default_all_on_when_settings_absent() {
    let f = FeatureFlags::from_settings(&[]);
    for (label, v) in [
        ("rdp", f.rdp),
        ("vdi", f.vdi),
        ("api_keys", f.api_keys),
        ("ssh_tunnels", f.ssh_tunnels),
        ("recordings", f.recordings),
    ] {
        assert!(v, "flag {label} must default on");
    }
}

#[test]
fn feature_flags_flip_with_stored_toggles() {
    let stored = vec![
        ("enable_rdp".to_string(), "false".to_string()),
        ("enable_vdi".to_string(), "false".to_string()),
        ("enable_api_keys".to_string(), "false".to_string()),
        ("enable_ssh_tunnels".to_string(), "false".to_string()),
        ("enable_recordings".to_string(), "false".to_string()),
    ];
    let f = FeatureFlags::from_settings(&stored);
    assert!(!f.rdp);
    assert!(!f.vdi);
    assert!(!f.api_keys);
    assert!(!f.ssh_tunnels);
    assert!(!f.recordings);
    // Untouched flags stay on.
    assert!(f.spice);
    assert!(f.proxmox);
    assert!(f.vmware);
    assert!(f.web_sessions);
}

async fn render_page(page: &str, features: FeatureFlags) -> String {
    let ctx = AppLayoutTemplate {
        site_title: "persea".into(),
        logo_url: String::new(),
        is_admin: true,
        active_page: "connections".into(),
        csp_nonce: "test".into(),
    };
    let resp =
        persea::templates::run_with_features(
            Arc::new(features),
            async move { ctx.render_page(page) },
        )
        .await;
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn connections_entry_type_dropdown_gates_rdp_and_vdi() {
    let html = render_page(
        "pages/connections.html",
        FeatureFlags {
            rdp: false,
            vdi: false,
            ..Default::default()
        },
    )
    .await;
    // The gated options carry the plain labels; the ungated RDP "security
    // mode" dropdown renders "RDP (standard encryption)" instead.
    assert!(
        !html.contains("<option value=\"rdp\">RDP</option>"),
        "rdp option must be gated off"
    );
    assert!(
        !html.contains("<option value=\"vdi\">VDI</option>"),
        "vdi option must be gated off"
    );
    assert!(
        !html.contains("<option value=\"vdi\">VDI (Docker)</option>"),
        "vdi (Docker) option must be gated off"
    );
    // ssh/vnc have no toggles and must always render.
    assert!(html.contains("<option value=\"ssh\">"));
    assert!(html.contains("<option value=\"vnc\">"));
}

#[tokio::test]
async fn connections_entry_type_dropdown_shows_options_when_enabled() {
    let html = render_page("pages/connections.html", FeatureFlags::default()).await;
    assert!(
        html.contains("<option value=\"rdp\">"),
        "rdp option must render when on"
    );
    assert!(
        html.contains("<option value=\"vdi\">"),
        "vdi option must render when on"
    );
}

#[tokio::test]
async fn sessions_adhoc_dropdown_gates_vdi() {
    let html = render_page(
        "pages/sessions.html",
        FeatureFlags {
            vdi: false,
            ..Default::default()
        },
    )
    .await;
    assert!(
        !html.contains("VDI (Docker)"),
        "vdi ad-hoc option must be gated off (the protocol FILTER keeps VDI: historical sessions stay filterable)"
    );
}

#[tokio::test]
async fn sessions_adhoc_dropdown_shows_vdi_when_enabled() {
    let html = render_page("pages/sessions.html", FeatureFlags::default()).await;
    assert!(
        html.contains("value=\"vdi\""),
        "vdi ad-hoc option must render when on"
    );
}

// ── 3. Request-time page gates (404 like a missing page) ──────────────────

/// Mirrors main.rs `feature_gate` middleware.
#[derive(Clone)]
struct FeatureGate(&'static str);

async fn feature_gate(
    Extension(db): Extension<Db>,
    Extension(gate): Extension<FeatureGate>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    if persea::settings_merge::read_toggle(&db, gate.0, true) {
        return next.run(request).await;
    }
    persea::templates::render_error_page(
        StatusCode::NOT_FOUND,
        "The page you requested could not be found",
        "test-nonce",
    )
}

/// Real handlers + the same middleware stack main.rs composes, without
/// `require_auth` (these tests exercise the feature gates, not auth).
fn gated_page_router(db: Db) -> Router {
    let gated_tunnels = Router::new()
        .route("/admin/tunnels.html", get(pages::admin_tunnels_page))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_ssh_tunnels")))
        .layer(Extension(db.clone()));
    let gated_recordings = Router::new()
        .route("/recordings.html", get(pages::recordings_page))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_recordings")))
        .layer(Extension(db.clone()));
    let gated_tokens = Router::new()
        .route("/tokens.html", get(account::tokens_page))
        .route("/account/tokens.html", get(account::tokens_page))
        .layer(middleware::from_fn(feature_gate))
        .layer(Extension(FeatureGate("enable_api_keys")))
        .layer(Extension(db.clone()));

    gated_tunnels
        .merge(gated_recordings)
        .merge(gated_tokens)
        .layer(Extension(persea::api::SiteTitle("persea".into())))
        .layer(Extension(test_theme()))
        .layer(Extension(CspNonce("test".into())))
        .layer(Extension(persea::auth::AuthIdentity::User {
            email: "admin@example.com".into(),
            name: "Admin".into(),
            role: "admin".into(),
            groups: vec![],
        }))
}

fn page_get(path: &str) -> Request<axum::body::Body> {
    Request::builder()
        .uri(path)
        .header(header::ACCEPT, "text/html")
        .body(axum::body::Body::empty())
        .unwrap()
}

#[tokio::test]
async fn recordings_page_404s_when_enable_recordings_is_off() {
    let db = test_db();
    set_setting(&db, "enable_recordings", "false");
    let router = gated_page_router(db);
    let resp = router.oneshot(page_get("/recordings.html")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tunnels_page_404s_when_enable_ssh_tunnels_is_off() {
    let db = test_db();
    set_setting(&db, "enable_ssh_tunnels", "false");
    let router = gated_page_router(db);
    let resp = router
        .oneshot(page_get("/admin/tunnels.html"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn tokens_pages_404_when_enable_api_keys_is_off() {
    let db = test_db();
    set_setting(&db, "enable_api_keys", "false");
    let router = gated_page_router(db);
    for path in ["/tokens.html", "/account/tokens.html"] {
        let resp = router.clone().oneshot(page_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "path {path}");
    }
}

#[tokio::test]
async fn gated_pages_render_when_toggles_are_on_or_absent() {
    let router = gated_page_router(test_db());
    for path in [
        "/recordings.html",
        "/admin/tunnels.html",
        "/tokens.html",
        "/account/tokens.html",
    ] {
        let resp = router.clone().oneshot(page_get(path)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "path {path}");
    }
}

// ── 4. Admin settings page render smoke tests (tab structure) ─────────────

async fn render_settings_page() -> String {
    render_page("pages/admin/settings.html", FeatureFlags::default()).await
}

#[tokio::test]
async fn settings_page_renders_five_section_tabs() {
    let html = render_settings_page().await;
    assert!(html.contains("role=\"tablist\""), "tablist must render");
    assert_eq!(html.matches("role=\"tab\"").count(), 5, "exactly five tabs");
    for tab in ["Session", "Features", "Storage", "Security", "Updates"] {
        assert!(
            html.contains(&format!(">{tab}</button>")),
            "tab {tab} must render"
        );
    }
    // Exactly one tab is selected: the default Session tab. (The style
    // block also contains `[aria-selected="true"]`, so assert the false
    // count and the session tab markup directly.)
    assert_eq!(
        html.matches("aria-selected=\"false\"").count(),
        4,
        "the other four tabs must be unselected"
    );
    assert!(
        html.contains("id=\"tab-session\" aria-controls=\"panel-session\" aria-selected=\"true\""),
        "session tab must be the selected one"
    );
}

#[tokio::test]
async fn settings_page_defaults_to_session_panel_and_hides_the_rest() {
    let html = render_settings_page().await;
    for panel in ["session", "features", "storage", "security", "updates"] {
        assert!(
            html.contains(&format!("id=\"panel-{panel}\"")),
            "panel {panel} must render"
        );
    }
    // Only the Session panel is visible on load; the other four start hidden.
    assert!(
        !html.contains("id=\"panel-session\" hidden"),
        "session panel must be visible by default"
    );
    assert_eq!(
        html.matches("tabindex=\"-1\" hidden").count(),
        4,
        "the four non-default panels must start hidden"
    );
}

#[tokio::test]
async fn settings_page_keeps_every_toggle_and_field() {
    let html = render_settings_page().await;
    let toggles = [
        "enable_rdp",
        "enable_ssh_tunnels",
        "enable_api_keys",
        "enable_recordings",
        "enable_web_sessions",
        "enable_spice",
        "enable_proxmox",
        "enable_vmware",
        "enable_vdi",
        "enable_file_transfer",
        "desktop_kiosk",
        "desktop_transfers",
        "desktop_pairing",
        "vault_enabled",
        "db_only_mode",
    ];
    for toggle in toggles {
        assert!(
            html.contains(&format!("id=\"{toggle}\"")),
            "toggle {toggle} must render"
        );
        assert!(
            html.contains(&format!("id=\"{toggle}-hidden\"")),
            "hidden value field for {toggle} must render"
        );
    }
    for name in [
        "listen_addr",
        "guacd_addr",
        "tls_cert_path",
        "tls_key_path",
        "session_max_duration_secs",
        "max_concurrent_sessions",
        "session_history_retention_days",
        "custom_fields",
    ] {
        assert!(
            html.contains(&format!("name=\"{name}\"")),
            "field {name} must render"
        );
    }
    // The collapsible Features group and the custom-fields editor stay wired.
    assert!(
        html.contains("id=\"features-group\""),
        "features group must render"
    );
    assert!(
        html.contains("id=\"custom-fields-editor\""),
        "custom-fields editor must render"
    );
    assert!(
        html.contains("id=\"add-custom-field\""),
        "add-field button must render"
    );
}

#[tokio::test]
async fn settings_page_is_csp_clean() {
    let html = render_settings_page().await;
    assert!(
        html.contains("nonce=\"test\""),
        "script block must carry the CSP nonce"
    );
    for attr in ["onclick=", "onchange=", "onsubmit=", "onkeydown="] {
        assert!(
            !html.contains(attr),
            "inline handler {attr} must not appear"
        );
    }
}
