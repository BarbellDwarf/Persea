# Ticket: Async session history DB insert

wayfinder:task
Priority: P2

## Question

`insert_session_history()` in `session/create.rs:1131` runs synchronously on the session creation task. If SQLite is slow (disk I/O), this delays the HTTP response to the browser, adding 1-5ms to time-to-first-pixel.

Wrap the DB insert in `tokio::task::spawn_blocking` so it doesn't block the session creation response. Fire-and-forget is acceptable — session history is audit-only and a late insert is harmless.

## Deliverable

Updated `create.rs` with async DB insert. Test: session creation returns immediately. DB insert completes in background. All session tests pass.
