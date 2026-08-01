# Ticket: Graceful Shutdown & Session Draining

**Type:** grilling
**Labels:** reliability, wayfinder:grilling

## Question

How should the server handle graceful shutdown with active sessions?

### Current state:
- `src/main.rs:1262-1267`: `axum::serve().with_graceful_shutdown()` waits for ctrl_c, then immediately stops
- Active WebSocket sessions are abruptly terminated
- No configurable shutdown timeout
- guacd killed with bare `kill` in Docker — may not flush recordings

### Missing:
- Signal active sessions to disconnect gracefully
- Wait for in-flight instructions to complete
- Flush recording files before exit
- Configurable shutdown timeout
- Docker: `kill -TERM` + wait instead of bare `kill`

### Decision needed:

1. Shutdown strategy: immediate stop, drain with timeout, or signal-then-wait?
2. Timeout: configurable via config file, or fixed default?
3. Session notification: close WebSocket with proper close frame, or let TCP timeout?
4. Recording flush: wait for guacd to finish writing, or accept potential data loss?
