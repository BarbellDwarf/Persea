# Map: UI Fixes + Session UX + High Availability

## Destination

Fix remaining layout/theme issues, add session-switching and connection-reason features, full-screen recordings, and document a high-availability architecture.

## Notes

- Items 1-7 are implementation work (clear scope). Items 3, 7.5, 8, 9 require design decisions.
- stop-slop: all prose direct, no filler.

## Decisions so far

- **Session switching**: Combination — tab bar for quick switching + Ctrl+K overlay for power users. Two access paths to the same session list.
- **Connection reason**: Dropdown of common reasons (Maintenance, Password rotation, Troubleshooting, etc.) plus free-text field. Stored in `session_history.reason` column. Admin-toggleable: `reason_required` setting (off / optional / required).
- **Disconnect vs Logout**: Disconnect ends the active WebSocket but keeps the session record for reconnection. Logout terminates the session AND clears the record. Stored as distinct events in session_history.

## Not yet specified

- Connection-reason field design: per-session vs per-entry, where to store it, who can see it
- Session switching UX: sidebar, overlay, tab behavior
- HA architecture: stateless frontend vs stateful sessions, database replication, guacd clustering
- Recordings fullscreen: native fullscreen API vs larger modal, controls layout

## Out of scope

- Target server administration (guacd internals, connection pooling beyond per-session)
