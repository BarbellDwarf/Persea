//! Integration tests for the session event feed (S02): manager publish
//! points, replay cursors, owner scoping, the per-user SSE cap, and
//! disconnect cleanup.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::Extension;
use persea::api::events::{self, EventsQuery};
use persea::api::AppState;
use persea::auth::AuthIdentity;
use persea::error::AppError;
use persea::session::{Session, SessionEventKind, SessionManager, SessionStatus, SessionType};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

fn test_identity(name: &str, role: &str) -> AuthIdentity {
    AuthIdentity::User {
        email: format!("{}@example.com", name),
        name: name.to_string(),
        role: role.to_string(),
        groups: Vec::new(),
    }
}

fn new_manager() -> AppState {
    new_manager_with_idle(0)
}

fn new_manager_with_idle(idle_timeout_secs: u64) -> AppState {
    let tmp = std::env::temp_dir().join(format!("persea-events-test-{}", Uuid::new_v4()));
    let mut config = persea::config::Config::default();
    config.recording_path = Some(tmp.join("recordings"));
    config.session_idle_timeout_secs = idle_timeout_secs;
    Arc::new(SessionManager::new(config, None))
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

async fn seed_session(m: &SessionManager, status: SessionStatus, created_by: &str) -> Uuid {
    m.seed_session_for_testing(test_session(Uuid::new_v4(), created_by, status))
        .await
}

fn replay_query(since: Option<u64>, all: Option<bool>) -> axum::extract::Query<EventsQuery> {
    axum::extract::Query(EventsQuery {
        since,
        replay: Some(true),
        all,
    })
}

async fn call_replay(
    m: &AppState,
    identity: Option<AuthIdentity>,
    query: axum::extract::Query<EventsQuery>,
) -> axum::response::Response {
    events::session_events(
        State(m.clone()),
        HeaderMap::new(),
        query,
        identity.map(Extension),
    )
    .await
    .unwrap()
}

async fn replay_body(res: axum::response::Response) -> Vec<serde_json::Value> {
    let body = axum::body::to_bytes(res.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn each_transition_publishes_exactly_one_event() {
    let m = new_manager();
    let id = seed_session(&m, SessionStatus::Active, "alice").await;

    // Active → Disconnected publishes one status_changed.
    m.disconnect_session(id).await;
    let (cursor, events) = m.replay_events(0);
    assert_eq!(cursor, 1);
    assert_eq!(events.len(), 1, "unexpected events: {:?}", events);
    assert_eq!(events[0].event, SessionEventKind::StatusChanged);
    assert_eq!(events[0].status, SessionStatus::Disconnected);
    assert_eq!(events[0].session_id, id);
    assert_eq!(events[0].created_by, "alice");

    // Duplicate notify: a second disconnect is not a transition.
    m.disconnect_session(id).await;
    assert_eq!(m.replay_events(0).1.len(), 1);

    // Disconnected → Completed publishes one session_ended.
    m.complete_session(id).await;
    let events = m.replay_events(0).1;
    assert_eq!(events.len(), 2, "unexpected events: {:?}", events);
    assert_eq!(events[1].event, SessionEventKind::SessionEnded);
    assert_eq!(events[1].status, SessionStatus::Completed);
    m.complete_session(id).await;
    assert_eq!(m.replay_events(0).1.len(), 2);

    // Completed → Error publishes one more session_ended; an already
    // errored session publishes nothing.
    m.error_session(id).await;
    let events = m.replay_events(0).1;
    assert_eq!(events.len(), 3, "unexpected events: {:?}", events);
    assert_eq!(events[2].event, SessionEventKind::SessionEnded);
    assert_eq!(events[2].status, SessionStatus::Error);
    m.error_session(id).await;
    assert_eq!(m.replay_events(0).1.len(), 3);
}

#[tokio::test]
async fn session_started_event_publishes_via_helper() {
    let m = new_manager();
    let session = test_session(Uuid::new_v4(), "alice", SessionStatus::Pending);
    m.publish_session_started(&session);
    let (cursor, events) = m.replay_events(0);
    assert_eq!(cursor, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, SessionEventKind::SessionStarted);
    assert_eq!(events[0].status, SessionStatus::Pending);
    assert_eq!(events[0].session_id, session.id);
    assert_eq!(events[0].created_by, "alice");
    assert_eq!(events[0].session_type, SessionType::Ssh);
}

#[tokio::test]
async fn terminate_and_idle_reap_publish_ended() {
    let m = new_manager();
    let id = seed_session(&m, SessionStatus::Active, "alice").await;
    assert!(m.delete_session(id).await);
    let events = m.replay_events(0).1;
    assert_eq!(events.len(), 1, "unexpected events: {:?}", events);
    assert_eq!(events[0].event, SessionEventKind::SessionEnded);
    assert_eq!(events[0].status, SessionStatus::Completed);

    // Idle-reap funnels through delete_session and must publish too.
    let m = new_manager_with_idle(1);
    let mut session = test_session(Uuid::new_v4(), "bob", SessionStatus::Active);
    session.last_activity = std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp() - 100);
    m.seed_session_for_testing(session).await;
    assert_eq!(m.reap_idle_sessions().await, 1);
    let events = m.replay_events(0).1;
    assert_eq!(events.len(), 1, "unexpected events: {:?}", events);
    assert_eq!(events[0].event, SessionEventKind::SessionEnded);
    assert_eq!(events[0].status, SessionStatus::Completed);
    assert_eq!(events[0].created_by, "bob");
}

#[tokio::test]
async fn handler_replay_from_cursor_returns_only_newer() {
    let m = new_manager();
    for _ in 0..3 {
        m.publish_session_started(&test_session(
            Uuid::new_v4(),
            "alice",
            SessionStatus::Pending,
        ));
    }
    let res = call_replay(
        &m,
        Some(test_identity("alice", "viewer")),
        replay_query(Some(1), None),
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.headers().get("x-event-cursor").unwrap(), "3");
    let events = replay_body(res).await;
    assert_eq!(events.len(), 2, "unexpected events: {:?}", events);
    assert_eq!(events[0]["id"], 2);
    assert_eq!(events[1]["id"], 3);
    assert_eq!(events[0]["event"], "session_started");
    assert!(events[0]["session_id"].is_string());
    assert!(events[0]["timestamp"].is_string());
}

#[tokio::test]
async fn handler_replay_scoped_to_owner_unless_admin_all() {
    let m = new_manager();
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    m.publish_session_started(&test_session(Uuid::new_v4(), "bob", SessionStatus::Pending));

    // Owner sees only their own events.
    let res = call_replay(
        &m,
        Some(test_identity("alice", "viewer")),
        replay_query(None, None),
    )
    .await;
    assert_eq!(res.headers().get("x-event-cursor").unwrap(), "3");
    let events = replay_body(res).await;
    assert_eq!(events.len(), 2, "unexpected events: {:?}", events);
    assert!(events.iter().all(|e| e["created_by"] == "alice"));

    // Admin without ?all=true sees only their own (none here).
    let res = call_replay(
        &m,
        Some(test_identity("root", "admin")),
        replay_query(None, None),
    )
    .await;
    let events = replay_body(res).await;
    assert_eq!(events.len(), 0, "unexpected events: {:?}", events);

    // Admin with ?all=true sees everything.
    let res = call_replay(
        &m,
        Some(test_identity("root", "admin")),
        replay_query(None, Some(true)),
    )
    .await;
    let events = replay_body(res).await;
    assert_eq!(events.len(), 3, "unexpected events: {:?}", events);
}

#[tokio::test]
async fn unauthenticated_request_is_forbidden() {
    let m = new_manager();
    let err = events::session_events(
        State(m),
        HeaderMap::new(),
        axum::extract::Query(EventsQuery::default()),
        None,
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Forbidden(_)), "got {:?}", err);
}

#[tokio::test]
async fn sse_slot_claim_release_roundtrip() {
    let m = new_manager();
    assert!(m.try_claim_sse_subscription("alice"));
    assert!(!m.try_claim_sse_subscription("alice"));
    assert!(m.try_claim_sse_subscription("bob"));
    m.release_sse_subscription("alice");
    assert!(m.try_claim_sse_subscription("alice"));
    m.release_sse_subscription("bob");
}

#[tokio::test]
async fn handler_rejects_second_concurrent_sse_and_cleans_up() {
    let m = new_manager();
    let identity = test_identity("alice", "viewer");

    let res1 = events::session_events(
        State(m.clone()),
        HeaderMap::new(),
        axum::extract::Query(EventsQuery::default()),
        Some(Extension(identity.clone())),
    )
    .await
    .unwrap();
    assert_eq!(res1.status(), StatusCode::OK);
    assert_eq!(
        res1.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    assert_eq!(
        res1.headers().get(header::CACHE_CONTROL).unwrap(),
        "no-cache"
    );

    // Second concurrent stream for the same user is rejected; a replay
    // (no live slot) is not.
    let err = events::session_events(
        State(m.clone()),
        HeaderMap::new(),
        axum::extract::Query(EventsQuery::default()),
        Some(Extension(identity.clone())),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, AppError::Conflict(_)), "got {:?}", err);
    let replay = events::session_events(
        State(m.clone()),
        HeaderMap::new(),
        replay_query(None, None),
        Some(Extension(identity.clone())),
    )
    .await
    .unwrap();
    assert_eq!(replay.status(), StatusCode::OK);

    // Dropping the response closes the stream; the slot is released and
    // a new stream is accepted.
    drop(res1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let res3 = events::session_events(
        State(m.clone()),
        HeaderMap::new(),
        axum::extract::Query(EventsQuery::default()),
        Some(Extension(identity)),
    )
    .await
    .unwrap();
    assert_eq!(res3.status(), StatusCode::OK);
}

#[tokio::test]
async fn produce_events_catches_up_from_cursor() {
    let m = new_manager();
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    m.publish_session_started(&test_session(Uuid::new_v4(), "bob", SessionStatus::Pending));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<persea::session::SessionEvent>(16);
    let handle = tokio::spawn({
        let m = m.clone();
        async move {
            events::produce_events(&m, "alice", false, Some(1), tx).await;
        }
    });

    // Catch-up from cursor 1 retains only bob's event (id 2), which is
    // filtered out; a live alice event (id 3) arrives next.
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("live event timed out")
        .expect("channel closed early");
    assert_eq!(ev.id, 3);
    assert_eq!(ev.event, SessionEventKind::SessionStarted);
    assert_eq!(ev.created_by, "alice");

    // Nothing else is queued: bob's events never reach alice's stream.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), rx.recv())
            .await
            .is_err(),
        "unexpected extra event"
    );

    // Dropping the receiver (client disconnect) ends the producer task.
    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("producer task did not end")
        .unwrap();
}

#[tokio::test]
async fn produce_events_fresh_stream_skips_history() {
    let m = new_manager();
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));

    let (tx, mut rx) = tokio::sync::mpsc::channel::<persea::session::SessionEvent>(16);
    let handle = tokio::spawn({
        let m = m.clone();
        async move {
            events::produce_events(&m, "alice", false, None, tx).await;
        }
    });

    // Retained history (ids 1-2) is skipped; nothing arrives.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), rx.recv())
            .await
            .is_err(),
        "fresh stream must not replay history"
    );

    // A live event (id 3) is delivered.
    m.publish_session_started(&test_session(
        Uuid::new_v4(),
        "alice",
        SessionStatus::Pending,
    ));
    let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("live event timed out")
        .expect("channel closed early");
    assert_eq!(ev.id, 3);

    // Dropping the receiver (client disconnect) ends the producer task.
    drop(rx);
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("producer task did not end")
        .unwrap();
}

#[tokio::test]
async fn info_carries_last_activity_and_ended_at() {
    let m = new_manager();
    let id = seed_session(&m, SessionStatus::Active, "alice").await;

    // Live session: last_activity present, ended_at absent.
    let sessions = m.list_sessions().await;
    let info = sessions.iter().find(|s| s.session_id == id).unwrap();
    assert!(
        info.last_activity.is_some(),
        "last_activity missing: {info:?}"
    );
    assert!(info.ended_at.is_none(), "ended_at set while live: {info:?}");

    // Terminal session: ended_at present.
    m.complete_session(id).await;
    let sessions = m.list_sessions().await;
    let info = sessions.iter().find(|s| s.session_id == id).unwrap();
    assert_eq!(info.status, SessionStatus::Completed);
    assert!(info.ended_at.is_some(), "ended_at missing: {info:?}");
}

#[test]
fn session_info_last_activity_derivation() {
    let mut session = test_session(Uuid::new_v4(), "alice", SessionStatus::Pending);
    session.last_activity = std::sync::atomic::AtomicI64::new(0);
    let info = session.info();
    assert!(info.last_activity.is_none());
    assert!(info.ended_at.is_none());
    session.touch_activity();
    assert!(session.info().last_activity.is_some());
}
