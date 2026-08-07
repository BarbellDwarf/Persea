# Ticket: Per-session concurrent viewer limits on share tokens

wayfinder:task
Priority: P3

## Question

WebSocket share tokens (`websocket.rs`) allow unlimited concurrent viewers. A shared session can be opened by hundreds of browser tabs simultaneously. Add a configurable per-session viewer limit (default: 10) enforced at the `ws_handler` level. Track `active_connections` (already incremented) and reject new share connections when the limit is reached.

## Deliverable

Updated `websocket.rs` with viewer limit check. Config option `[session] max_viewers_per_share`. Test: opening more than the limit returns a clear error to the browser.
