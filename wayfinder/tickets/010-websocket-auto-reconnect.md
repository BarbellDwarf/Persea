# Ticket: WebSocket Auto-Reconnect

**Type:** grilling
**Labels:** ui-ux, wayfinder:grilling

## Question

Should the Guacamole client implement automatic WebSocket reconnection?

### Current state:
- `client.html` line 1656-1669: `tunnel.onstatechange` handles `CLOSED` state by showing "Connection lost" overlay
- Reconnect button creates a **new session** against the same Connections entry — not a WebSocket reconnect
- No automatic reconnection with backoff
- Apache Guacamole's webapp has auto-reconnect with exponential backoff

### Impact:
- Network blip causes full session disconnect
- Server restart kills all sessions with no recovery path
- Users must manually click reconnect and lose unsaved work in the remote desktop

### Considerations:
- Reconnecting to the same guacd session vs creating a new one
- Preserving clipboard state across reconnects
- Handling in-flight instructions during disconnect
- Backoff strategy (exponential with jitter)
- Max retry count and user notification

### Decision needed:

1. Auto-reconnect: implement or keep manual?
2. Reconnect strategy: same session (guacd must support) or new session with same params?
3. Backoff: exponential with jitter, or simpler approach?
4. Max retries before showing permanent disconnect?
