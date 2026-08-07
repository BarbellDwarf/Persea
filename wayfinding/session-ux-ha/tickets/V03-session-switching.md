# Ticket: Session switching — connect to new server while connected

wayfinder:task
Priority: P2

## Decision

Combination approach: **tab bar** for quick switching + **Ctrl+K overlay** for power users.

## Question

Implement the session switching UX as decided:

### Tab bar
- A tab strip at the top of the client page showing all active sessions for the current user
- Each tab shows: protocol badge + hostname + status dot (green=active, yellow=pending, gray=disconnected)
- Click a tab to switch to that session (the display area swaps, WebSocket connection stays alive on the background tab)
- Active tab highlighted, inactive tabs dimmed
- Close button (x) on each tab to disconnect that session
- New tab added when `connectEntry()` succeeds

### Ctrl+K overlay
- `Ctrl+K` (or `Cmd+K` on macOS) opens a full-screen overlay
- Searchable list of all sessions (active + pending)
- Type to filter, arrow keys to navigate, Enter to switch, Escape to close
- Each entry shows: protocol badge + hostname + user + status + time since last activity

### Implementation
- Session state stored in `window.__activeSessions` (populated from `/api/sessions` periodic fetch)
- Tab bar rendered in `client.html` above the toolbar
- Overlay rendered as a modal with backdrop
- Both share the same session list data source
- Switching: save current display state, swap display element content, reattach keyboard/mouse listeners

## Deliverable

- Tab bar visible in the client page with active sessions
- Ctrl+K opens searchable overlay
- Clicking a session switches without disconnecting
- Close button on tabs disconnects the session
