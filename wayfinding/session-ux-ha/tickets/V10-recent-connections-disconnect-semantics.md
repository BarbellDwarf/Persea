# Ticket: Recent connections + disconnect vs logout semantics

wayfinder:task
Priority: P1

## Question

The Connections page needs a "Recently Connected" section showing servers the user recently connected to, for quick reconnection. Two distinct actions need clear semantics:

- **Disconnect**: ends the active session but keeps the session record available for reconnection (e.g., RDP reconnect to same desktop, SSH reconnect to same shell if tmux)
- **Logout**: terminates the session AND removes the user's access (clears the session record, invalidates any reconnect tokens)

## Deliverable

1. **Recent connections section**: Show on the Connections page the last N connections the current user made, with a "Reconnect" button. Data from `session_history` (recent entries with `created_by = current_user`).
2. **Disconnect vs Logout split**: 
   - "Disconnect" button on the session toolbar → ends the active WebSocket but keeps session alive for reconnect
   - "Logout" button → terminates session + clears reconnect data
   - In the sessions page list, show the distinction (status: disconnected vs logged-out)
3. Store disconnect/logout as distinct events in session_history

## Files to touch
- `templates/pages/connections.html` (recent connections section)
- `templates/pages/client.html` (disconnect vs logout buttons)
- `templates/pages/sessions.html` (status display)
- `src/session/types.rs` (session status enum)
- `src/websocket.rs` (disconnect handling)
- `src/session/manager.rs` (logout handling)
