//! Integration tests for the S10 session-UX batch: V09 connection reason
//! (required/optional/length at the create handler), the recent-sessions
//! endpoint (scoping, ordering, limit), the V10 `logged_out` status
//! transitions, and the disconnect-vs-logout semantics on the terminate
//! handler (history event + map removal).

use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use persea::api::{create_session, delete_session, recent_connections, AppState};
use persea::auth::{AuthIdentity, TrustedProxies};
use persea::config::{Config, SessionConfig};
use persea::db::{self, Db};
use persea::error::AppError;
use persea::session::{
    CreateSessionRequest, Session, SessionEventKind, SessionManager, SessionStatus, SessionType,
};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

fn test_identity(name: &str, role: &str) -> AuthIdentity {
    AuthIdentity::User {
        email: format!("{}@example.com", name),
        name: name.to_string(),
        role: role.to_string(),
        groups: Vec::new(),
    }
}

fn fake_addr() -> ConnectInfo<SocketAddr> {
    ConnectInfo("127.0.0.1:8080".parse::<SocketAddr>().unwrap())
}

fn empty_headers() -> HeaderMap {
    HeaderMap::new()
}

fn trusted() -> Extension<TrustedProxies> {
    Extension(TrustedProxies(Vec::new()))
}

fn new_manager(db: Option<Db>) -> AppState {
    let tmp = std::env::temp_dir().join(format!("persea-session-ux-test-{}", Uuid::new_v4()));
    let mut config = Config::default();
    config.recording_path = Some(tmp.join("recordings"));
    match db {
        Some(db) => Arc::new(SessionManager::new_with_db(config, None, db)),
        None => Arc::new(SessionManager::new(config, None)),
    }
}

fn test_session(id: Uuid, created_by: &str, status: SessionStatus) -> Session {
    Session {
        id,
        session_type: SessionType::Ssh,
        status,
        created_at: chrono::Utc::now(),
        hostname: "test-host".into(),
        username: "alice".into(),
        url: None,
        banner: None,
        guacd_stream: None,
        connection_id: "conn-test".into(),
        share_token: "owner-secret".into(),
        width: 1024,
        height: 768,
        active_connections: 0,
        created_by: created_by.to_string(),
        cancel: tokio_util::sync::CancellationToken::new(),
        browser_session: None,
        deferred_params: None,
        drive_path: None,
        drive_enabled: false,
        tunnels: Vec::new(),
        container_id: None,
        container_name: None,
        recording_enabled: false,
        address_book_entry: None,
        address_book_folder: None,
        entry_display_name: None,
        max_recordings: None,
        login_script_handle: None,
        shadow_tokens: Vec::new(),
        share_allowed: false,
        fullscreen_on_connect: false,
        autohide_side_tabs: false,
        last_activity: std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp()),
        source_ip: None,
        user_id: Some(created_by.to_string()),
    }
}

fn ssh_req(hostname: Option<&str>) -> CreateSessionRequest {
    let mut req = CreateSessionRequest::default();
    req.hostname = hostname.map(str::to_string);
    req
}

// ── V09: reason_required enforcement at the create handler ────────────

#[tokio::test]
async fn create_without_reason_is_rejected_400_when_required() {
    let mut config = Config::default();
    config.session = Some(SessionConfig {
        reason_required: true,
    });
    let tmp = std::env::temp_dir().join(format!("persea-session-ux-{}", Uuid::new_v4()));
    config.recording_path = Some(tmp.join("recordings"));
    let manager: AppState = Arc::new(SessionManager::new(config, None));

    let err = create_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "poweruser"))),
        Some(trusted()),
        Json(ssh_req(Some("127.0.0.1"))),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(ref m) if m.contains("reason")),
        "got {:?}",
        err
    );
}

#[tokio::test]
async fn create_with_reason_passes_the_reason_gate_when_required() {
    let mut config = Config::default();
    config.session = Some(SessionConfig {
        reason_required: true,
    });
    let tmp = std::env::temp_dir().join(format!("persea-session-ux-{}", Uuid::new_v4()));
    config.recording_path = Some(tmp.join("recordings"));
    let manager: AppState = Arc::new(SessionManager::new(config, None));

    let mut req = ssh_req(Some("127.0.0.1"));
    req.reason = Some("Maintenance".into());
    let err = create_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "poweruser"))),
        Some(trusted()),
        Json(req),
    )
    .await
    .unwrap_err();
    // The reason gate passed — the failure is the (absent) guacd
    // connection, not a validation rejection.
    assert!(
        matches!(err, AppError::Session(_)),
        "expected guacd failure, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_without_reason_is_allowed_when_optional() {
    let manager = new_manager(None);
    let err = create_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "poweruser"))),
        Some(trusted()),
        Json(ssh_req(Some("127.0.0.1"))),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Session(_)),
        "reason must be optional by default, got {:?}",
        err
    );
}

#[tokio::test]
async fn create_with_overlong_reason_is_rejected_400() {
    let manager = new_manager(None);
    let mut req = ssh_req(Some("127.0.0.1"));
    req.reason = Some("x".repeat(501));
    let err = create_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "poweruser"))),
        Some(trusted()),
        Json(req),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(ref m) if m.contains("500")),
        "got {:?}",
        err
    );
}

#[tokio::test]
async fn blank_reason_counts_as_missing_when_required() {
    let mut config = Config::default();
    config.session = Some(SessionConfig {
        reason_required: true,
    });
    let tmp = std::env::temp_dir().join(format!("persea-session-ux-{}", Uuid::new_v4()));
    config.recording_path = Some(tmp.join("recordings"));
    let manager: AppState = Arc::new(SessionManager::new(config, None));

    let mut req = ssh_req(Some("127.0.0.1"));
    req.reason = Some("   ".into());
    let err = create_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "poweruser"))),
        Some(trusted()),
        Json(req),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Validation(_)),
        "whitespace-only reason must be rejected, got {:?}",
        err
    );
}

#[test]
fn reason_required_defaults_to_false() {
    assert!(!Config::default().session_reason_required());
    let mut config = Config::default();
    config.session = Some(SessionConfig {
        reason_required: true,
    });
    assert!(config.session_reason_required());
}

// ── V09: reason lands in session history ──────────────────────────────

#[test]
fn reason_is_stored_and_returned_by_history_query() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    db::insert_session_history(
        &db, "s1", "ssh", "host1", None, "alice", "alice", None, None, None,
    )
    .unwrap();
    db::update_session_history_reason(&db, "s1", "Password rotation").unwrap();
    let (rows, _) = db::query_session_history(&db, None, None, None, None, None, 10, 0).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["reason"].as_str(), Some("Password rotation"));
    assert_eq!(rows[0]["status"].as_str(), Some("active"));
}

// ── V10: recent-connections endpoint ──────────────────────────────────

fn seed_history(db: &Db, id: &str, user: &str, hostname: &str) {
    db::insert_session_history(db, id, "ssh", hostname, None, "u", user, None, None, None).unwrap();
}

#[tokio::test]
async fn recent_sessions_are_scoped_to_the_current_user() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    // A like-named user must not leak into (or displace) alice's rows.
    seed_history(&db, "a1", "alice", "host-alice-1");
    seed_history(&db, "b1", "alice2", "host-bobby");
    seed_history(&db, "a2", "alice", "host-alice-2");

    let _manager = new_manager(Some(db.clone()));
    let res = recent_connections(
        Some(Extension(test_identity("alice", "operator"))),
        Extension(db),
        Query(persea::api::RecentSessionsQuery { limit: Some(10) }),
    )
    .await
    .unwrap();
    let recent = res.0["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 2, "got {:?}", res.0);
    for row in recent {
        assert_eq!(row["created_by"].as_str(), Some("alice"));
        assert!(row["hostname"].as_str().unwrap().starts_with("host-alice"));
    }
}

#[tokio::test]
async fn recent_sessions_are_newest_first_and_limited() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    for i in 0..15 {
        seed_history(
            &db,
            &format!("s{:02}", i),
            "alice",
            &format!("host-{:02}", i),
        );
    }
    // Space the started_at values so ordering is deterministic.
    {
        let conn = db.lock().unwrap();
        for i in 0..15 {
            conn.execute(
                "UPDATE session_history SET started_at = ?1 WHERE session_id = ?2",
                rusqlite::params![
                    format!("2026-01-{:02} 00:00:00", (i % 28) + 1),
                    format!("s{:02}", i)
                ],
            )
            .unwrap();
        }
    }
    let _manager = new_manager(Some(db.clone()));
    let res = recent_connections(
        Some(Extension(test_identity("alice", "operator"))),
        Extension(db.clone()),
        Query(persea::api::RecentSessionsQuery { limit: Some(10) }),
    )
    .await
    .unwrap();
    let recent = res.0["recent"].as_array().unwrap();
    assert_eq!(recent.len(), 10, "limit must cap at 10, got {:?}", res.0);
    let ids: Vec<&str> = recent
        .iter()
        .map(|r| r["session_id"].as_str().unwrap())
        .collect();
    // started_at "2026-01-15" (i=14) is the newest; assert strictly
    // descending by the seeded timestamps.
    for pair in ids.windows(2) {
        let earlier = started_at_of(&db, pair[1]);
        let later = started_at_of(&db, pair[0]);
        assert!(
            later >= earlier,
            "rows must be newest first: {} ({}) before {} ({})",
            pair[0],
            later,
            pair[1],
            earlier
        );
    }
    // Every row carries a client_url for live rejoin.
    assert!(recent[0]["client_url"]
        .as_str()
        .unwrap()
        .starts_with("/client/"));
}

fn started_at_of(db: &Db, session_id: &str) -> String {
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT started_at FROM session_history WHERE session_id = ?1",
        rusqlite::params![session_id],
        |row| row.get(0),
    )
    .unwrap()
}

#[tokio::test]
async fn recent_sessions_require_authentication() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    let manager = new_manager(Some(db.clone()));
    let err = recent_connections(
        None,
        Extension(db),
        Query(persea::api::RecentSessionsQuery::default()),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
    let _ = manager;
}

// ── V10: logged_out status + transitions ──────────────────────────────

#[test]
fn logged_out_is_terminal_and_serializes_lowercase() {
    assert!(SessionStatus::LoggedOut.is_terminal());
    assert_eq!(
        serde_json::to_string(&SessionStatus::LoggedOut).unwrap(),
        "\"logged_out\""
    );
    assert!(!SessionStatus::Disconnected.is_terminal());
}

#[tokio::test]
async fn disconnect_keeps_the_session_and_does_not_clobber_logged_out() {
    let manager = new_manager(None);
    let id = manager
        .seed_session_for_testing(test_session(Uuid::new_v4(), "alice", SessionStatus::Active))
        .await;
    manager.disconnect_session(id).await;
    let info = manager.get_session(id).await.expect("session stays in map");
    assert_eq!(info.status, SessionStatus::Disconnected);

    // A logged-out session must not be downgraded by a racing browser
    // teardown (disconnect_session only transitions Active).
    let id2 = manager
        .seed_session_for_testing(test_session(
            Uuid::new_v4(),
            "alice",
            SessionStatus::LoggedOut,
        ))
        .await;
    manager.disconnect_session(id2).await;
    assert_eq!(
        manager.get_session(id2).await.unwrap().status,
        SessionStatus::LoggedOut
    );
}

#[tokio::test]
async fn terminate_records_logged_out_history_and_removes_the_session() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    let manager = new_manager(Some(db.clone()));
    let id = manager
        .seed_session_for_testing(test_session(Uuid::new_v4(), "alice", SessionStatus::Active))
        .await;
    db::insert_session_history(
        &db,
        &id.to_string(),
        "ssh",
        "test-host",
        None,
        "alice",
        "alice",
        None,
        None,
        None,
    )
    .unwrap();

    let res = delete_session(
        State(manager.clone()),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "operator"))),
        Some(trusted()),
        Path(id),
    )
    .await;
    assert_eq!(res.unwrap(), axum::http::StatusCode::NO_CONTENT);

    // In-memory: gone from the manager map.
    assert!(
        manager.get_session(id).await.is_none(),
        "session must be removed after logout"
    );

    // History: the distinct logged_out event, not completed/disconnected.
    let (rows, _) =
        db::query_session_history(&db, Some("alice"), None, None, None, None, 10, 0).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["status"].as_str(), Some("logged_out"));
    assert!(rows[0]["ended_at"].as_str().is_some());

    // Event feed: a session_ended carrying the logged_out status.
    let (_cursor, events) = manager.replay_events(0);
    let ended: Vec<_> = events
        .iter()
        .filter(|e| e.event == SessionEventKind::SessionEnded && e.session_id == id)
        .collect();
    assert!(!ended.is_empty(), "no session_ended event published");
    assert!(
        ended.iter().any(|e| e.status == SessionStatus::LoggedOut),
        "session_ended must carry logged_out, got {:?}",
        ended.iter().map(|e| &e.status).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn terminate_missing_session_is_404() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();
    let manager = new_manager(Some(db.clone()));
    let err = delete_session(
        State(manager),
        fake_addr(),
        empty_headers(),
        Some(Extension(test_identity("alice", "operator"))),
        Some(trusted()),
        Path(Uuid::new_v4()),
    )
    .await
    .unwrap_err();
    assert!(
        matches!(err, AppError::Session(ref m) if m.contains("not found")),
        "got {:?}",
        err
    );
}

// ── Template render smoke tests (V03 tab bar, V09 reason, V10 recent) ──

async fn render_bytes(resp: axum::response::Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn client_page_renders_with_tab_bar_and_switcher() {
    let tmpl = persea::templates::ClientTemplate {
        site_title: "persea".into(),
        csp_nonce: "test-nonce".into(),
    };
    let html = render_bytes(tmpl.into_response()).await;
    assert!(html.contains("id=\"tab-bar\""), "tab bar missing");
    assert!(
        html.contains("id=\"session-switcher\""),
        "Ctrl+K switcher missing"
    );
    assert!(
        html.contains("desktop-hidden"),
        "desktop-mode class missing"
    );
    assert!(
        html.contains("perseaDesktop"),
        "bridge handler registration missing"
    );
}

#[tokio::test]
async fn sessions_page_renders_with_reason_field_and_recent_strip() {
    let ctx = persea::templates::AppLayoutTemplate {
        site_title: "persea".into(),
        logo_url: String::new(),
        is_admin: true,
        active_page: "sessions".into(),
        csp_nonce: "test-nonce".into(),
    };
    let resp = persea::templates::run_with_features(
        Arc::new(persea::templates::FeatureFlags::default()),
        async move { ctx.render_page("pages/sessions.html") },
    )
    .await;
    let html = render_bytes(resp).await;
    assert!(
        html.contains("session-reason-preset"),
        "reason dropdown missing"
    );
    assert!(html.contains("recent-ended"), "recent strip missing");
    assert!(
        html.contains("api/sessions/recent"),
        "recent endpoint missing"
    );
}

#[tokio::test]
async fn connections_page_renders_with_reason_control_and_recent_section() {
    let ctx = persea::templates::AppLayoutTemplate {
        site_title: "persea".into(),
        logo_url: String::new(),
        is_admin: true,
        active_page: "connections".into(),
        csp_nonce: "test-nonce".into(),
    };
    let resp = persea::templates::run_with_features(
        Arc::new(persea::templates::FeatureFlags::default()),
        async move { ctx.render_page("pages/connections.html") },
    )
    .await;
    let html = render_bytes(resp).await;
    assert!(
        html.contains("detail-reason-preset"),
        "reason dropdown missing"
    );
    assert!(
        html.contains("Recently Connected"),
        "recent section missing"
    );
    assert!(
        html.contains("status-logged_out"),
        "logged_out pill missing"
    );
}
