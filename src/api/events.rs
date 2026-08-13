//! Session lifecycle event feed: SSE stream + cursor replay.
//!
//! `GET /api/sessions/events` serves two modes from one endpoint:
//!
//! - **SSE** (`text/event-stream`, the default): live events with `id:`
//!   cursors. A `Last-Event-ID` header (or `?since=`) resumes from the
//!   retained log; without one the stream delivers only events published
//!   after connect. A `: ping` comment keeps idle connections alive.
//! - **Replay** (JSON array, when `?replay=true` or `Accept:
//!   application/json`): retained events with id > `?since=` (all retained
//!   when omitted), plus an `X-Event-Cursor` header with the latest id so
//!   polling clients can track their position.
//!
//! Ownership mirrors `GET /api/sessions`: non-admins receive only events
//! for sessions they created; admins pass `?all=true` for everything. At
//! most one concurrent SSE stream per user (a second attempt gets 409).

use super::AppState;
use crate::auth::AuthIdentity;
use crate::error::AppError;
use crate::session::{SessionEvent, SessionManager};
use axum::extract::Query;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use serde::Deserialize;
use std::convert::Infallible;
use std::sync::Arc;

/// Query parameters for `GET /api/sessions/events`.
#[derive(Deserialize, Default)]
pub struct EventsQuery {
    /// Replay retained events with id greater than this cursor. For SSE
    /// connections the `Last-Event-ID` header takes precedence.
    pub since: Option<u64>,
    /// Force replay mode (JSON array) instead of the SSE stream.
    pub replay: Option<bool>,
    /// Include every user's events; only honored for admins.
    pub all: Option<bool>,
}

/// `GET /api/sessions/events`: session lifecycle event feed (SSE stream
/// by default, JSON replay with `?replay=true` or `Accept:
/// application/json`). Cookie or Bearer auth; owner-scoped like
/// `GET /api/sessions` (`?all=true` for admins); at most one concurrent
/// SSE stream per user (409 when the slot is taken).
pub async fn session_events(
    State(manager): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Response, AppError> {
    // Fail closed: the router's require_auth middleware blocks anonymous
    // callers, but the handler must not silently pass when the identity
    // is absent.
    let Some(Extension(id)) = identity else {
        return Err(AppError::Forbidden("authentication required".into()));
    };
    let owner = id.display_name().to_string();
    let show_all = q.all.unwrap_or(false) && id.has_role("admin");
    let since = q.since.or_else(|| {
        headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
    });

    let wants_replay = q.replay.unwrap_or(false)
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("application/json"))
            .unwrap_or(false);

    if wants_replay {
        return Ok(replay_response(
            &manager,
            since.unwrap_or(0),
            &owner,
            show_all,
        ));
    }
    sse_response(&manager, since, &owner, show_all)
}

/// Replay mode: JSON array of retained events visible to the caller,
/// with the latest cursor in `X-Event-Cursor`.
fn replay_response(manager: &SessionManager, since: u64, owner: &str, show_all: bool) -> Response {
    let (cursor, events) = manager.replay_events(since);
    let visible: Vec<SessionEvent> = events
        .into_iter()
        .filter(|e| show_all || e.created_by == owner)
        .collect();
    (
        StatusCode::OK,
        [("x-event-cursor", cursor.to_string())],
        axum::Json(visible),
    )
        .into_response()
}

/// SSE mode: claim the per-user slot, then stream retained events after
/// `resume_from` (when the client sent `?since=` / `Last-Event-ID`)
/// followed by live events until the client disconnects. The claim is
/// released when the stream task ends (client gone, manager dropped), so
/// a dropped connection never leaks its slot.
fn sse_response(
    manager: &AppState,
    resume_from: Option<u64>,
    owner: &str,
    show_all: bool,
) -> Result<Response, AppError> {
    let Some(claim) = SseClaim::try_acquire(manager, owner) else {
        return Err(AppError::Conflict(
            "already connected to the session event stream — close the existing connection first"
                .into(),
        ));
    };
    let (tx, rx) = tokio::sync::mpsc::channel::<SessionEvent>(64);
    let manager_task = manager.clone();
    let owner_task = owner.to_string();
    tokio::spawn(async move {
        let _claim = claim;
        produce_events(&manager_task, &owner_task, show_all, resume_from, tx).await;
    });
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|event| (Ok::<_, Infallible>(sse_frame(&event)), rx))
    });
    Ok(Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response())
}

/// Stream lifecycle events into `tx`, until the receiver is dropped or
/// the manager is dropped. With `resume_from` (a `Last-Event-ID` /
/// `?since=` cursor) retained events after that cursor are delivered
/// first; without it the stream skips history and delivers only events
/// published after subscribe. Events are filtered to `owner`'s sessions
/// unless `show_all` is set.
///
/// The watch receiver is subscribed before the retained log is read, and
/// every loop iteration re-reads the log by the last processed cursor,
/// so an event published between the two is neither missed nor delivered
/// twice.
pub async fn produce_events(
    manager: &SessionManager,
    owner: &str,
    show_all: bool,
    resume_from: Option<u64>,
    tx: tokio::sync::mpsc::Sender<SessionEvent>,
) {
    let mut rx = manager.subscribe_events();
    let mut last_seen = match resume_from {
        // Catch-up: retained events after the resume cursor arrive first.
        Some(since) => {
            let mut last = since;
            for event in manager.replay_events(since).1 {
                last = event.id;
                if show_all || event.created_by == owner {
                    if tx.send(event).await.is_err() {
                        return;
                    }
                }
            }
            last
        }
        // Fresh stream: the subscribe-time cursor is the boundary, so
        // only events published after connect are delivered.
        None => *rx.borrow(),
    };
    loop {
        tokio::select! {
            _ = tx.closed() => return,
            changed = rx.changed() => {
                if changed.is_err() {
                    return;
                }
                for event in manager.replay_events(last_seen).1 {
                    last_seen = event.id;
                    if show_all || event.created_by == owner {
                        if tx.send(event).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Build the SSE frame for one lifecycle event (`id:`, `event:`, `data:`).
fn sse_frame(event: &SessionEvent) -> Event {
    Event::default()
        .id(event.id.to_string())
        .event(event.event.as_str())
        .data(serde_json::to_string(event).unwrap_or_default())
}

/// Owns a per-user SSE slot; releases it on drop, so stream teardown
/// (client disconnect, task cancellation) always frees the slot.
struct SseClaim(Arc<SessionManager>, String);

impl SseClaim {
    fn try_acquire(manager: &AppState, owner: &str) -> Option<SseClaim> {
        manager
            .try_claim_sse_subscription(owner)
            .then(|| SseClaim(manager.clone(), owner.to_string()))
    }
}

impl Drop for SseClaim {
    fn drop(&mut self) {
        self.0.release_sse_subscription(&self.1);
    }
}
