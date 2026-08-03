# Ticket: Session Management

wayfinder:research
Blocked by: 003 (Auth DB Schema), 009 (User Identity Model)

## Question

How should persea implement enterprise session management?

Sessions need idle timeouts, max duration limits, concurrent session controls, and proper cleanup. Currently sessions are in-memory (HashMap) with a basic reaper.

Key decisions needed:

1. **Session storage** — Move from in-memory HashMap to DB for HA/persistence? Or keep in-memory with DB for audit only?
2. **Idle timeout** — Configurable per-role. 15 min for sensitive environments (ISO 27001), 30 min for standard (NIST AAL2). What gets terminated? WebSocket + guacd connection.
3. **Max session duration** — Configurable. 8-12 hours standard, 1-4 hours privileged. Force reconnection after expiry.
4. **Concurrent session limits** — Per-user configurable. Default: unlimited. Admin can set per-role.
5. **Session binding** — Tie session to client IP? Or allow roaming?
6. **Reauthentication** — Require re-auth before sensitive operations (connection to critical systems) even if session is active.
7. **Session cleanup** — What happens on timeout? Close WebSocket, disconnect guacd, clean up browser processes, remove drive mounts.
8. **Session listing** — Users see own sessions. Admins see all sessions. Active session count per user.
9. **Graceful disconnect** — Handle network drops vs intentional disconnects. Session resume window?

## Research: Enterprise Session Management

### Current State

Sessions live in-memory (`HashMap<Uuid, Arc<Mutex<Session>>>`) with a basic `reap_expired_sessions()` that checks `created_at` against `session_max_duration_secs`. Session history goes to SQLite `session_history` table but only records: session_id, session_type, hostname, port, username, created_by, started_at, ended_at, duration_secs, recording_file, status. No idle timeout exists. No concurrent session limits.

---

### 1. Session Metadata Schema

**Current `session_history` table fields:**
- `session_id`, `session_type`, `hostname`, `port`, `username`, `created_by`
- `started_at`, `ended_at`, `duration_secs`, `recording_file`, `status`
- `address_book_entry`, `address_book_folder`, `entry_display_name`

**Missing fields needed for enterprise:**
- `source_ip` — client IP for audit trail (ISO 27001 A.9.4.2 requires recording log-on source)
- `target_host` — already have `hostname` (same thing)
- `thumbnail_path` — stored on disk at `recording_path/thumbnails/{id}.jpg`, not in DB
- `idle_timeout_mins` — per-session override (for VDI sessions with `container_idle_timeout_mins`)
- `max_duration_mins` — per-session override
- `terminated_reason` — why session ended: `user_disconnect`, `idle_timeout`, `max_duration`, `admin_kill`, `error`, `network_drop`
- `user_agent` — browser/client identifier
- `protocol_details` — JSONB/TEXT for protocol-specific metadata (SSH key used, RDP domain, VDI image, etc.)

**Recommendation:** Add `source_ip`, `terminated_reason`, `user_agent` to `session_history`. Keep `thumbnail_path` as derived from `recording_path/thumbnails/{session_id}.jpg`. Add optional `protocol_details TEXT` for extensibility.

**Schema addition (migration):**
```sql
ALTER TABLE session_history ADD COLUMN source_ip TEXT;
ALTER TABLE session_history ADD COLUMN terminated_reason TEXT;
ALTER TABLE session_history ADD COLUMN user_agent TEXT;
ALTER TABLE session_history ADD COLUMN protocol_details TEXT;
```

---

### 2. Idle Timeout Implementation

**What counts as "idle"?**

For a Guacamole-style proxy, two layers of activity:
1. **WebSocket activity** — user sending keystrokes/mouse/clipboard to browser. The WebSocket is the control channel.
2. **guacd traffic** — guacd sending screen updates back. This is server→client, not user activity.

**Recommendation:** Track **WebSocket input events** (keyboard, mouse, clipboard paste) as activity. Screen updates from guacd do NOT count as user activity (the user may have walked away while a video plays).

**Implementation:**
- Add `last_activity_at: DateTime<Utc>` to `Session` struct
- Update `last_activity_at` on every WebSocket input message (key, mouse, clipboard)
- Background reaper task runs every 60 seconds:
  ```rust
  async fn reap_idle_sessions(&self) {
      let now = Utc::now();
      for (id, session) in sessions.iter() {
          let session = session.lock().await;
          if session.status != SessionStatus::Active { continue; }
          let idle = now.signed_duration_since(session.last_activity_at);
          if idle > Duration::from_secs(idle_timeout_secs) {
              // Terminate gracefully
          }
      }
  }
  ```
- `idle_timeout_secs` comes from config, overridable per-session (VDI `container_idle_timeout_mins`)

**Graceful termination sequence:**
1. Set `terminated_reason = "idle_timeout"`
2. Cancel the session's `CancellationToken` (signals WebSocket proxy to stop)
3. Close WebSocket connection (send close frame)
4. Disconnect from guacd (drop `GuacdStream`)
5. Clean up browser processes (`cleanup_browser`)
6. Stop VDI container if applicable
7. Clean up drive mounts
8. Update DB: `ended_at = now`, `duration_secs`, `terminated_reason`
9. Emit audit log entry

**NIST alignment:** AAL2 requires 30 min idle timeout. AAL3 requires 15 min. Make this configurable per-role.

---

### 3. Max Duration Enforcement

**Current implementation:** `reap_expired_sessions()` checks `created_at + session_max_duration_secs` and calls `delete_session()`. This works but lacks nuance.

**Recommendation:**
- Background reaper task (same 60-second loop as idle reaper)
- On max duration hit: **force disconnect** with `terminated_reason = "max_duration"`
- Send a warning to the client 5 minutes before expiry (WebSocket control message)
- No "grace period" — force disconnect for compliance (NIST AAL2: 24h overall, AAL3: 12h overall)

**Configurable per-role:**
```toml
[session_limits]
default_max_duration_mins = 480    # 8 hours
privileged_max_duration_mins = 240  # 4 hours for admin sessions
idle_timeout_mins = 30              # NIST AAL2 default
```

**What about re-authentication?** NIST AAL2 allows reauthentication with password+session_secret when overall timeout hasn't expired. For a remote access tool, implement a "session resume" endpoint that validates the original OIDC token is still valid and extends `max_duration` by another cycle. But the idle timeout always applies regardless.

---

### 4. Concurrent Session Limits

**How to enforce:**
- On session creation (`create_session`), count active sessions for `created_by` user
- Query: `SELECT COUNT(*) FROM sessions WHERE created_by = ? AND status IN ('active', 'pending')`
- If count >= limit, reject with HTTP 409 and message "Concurrent session limit reached"
- Configurable per-user or per-role

**Implementation in `SessionManager`:**
```rust
pub async fn check_concurrent_limit(&self, user: &str) -> Result<(), SessionError> {
    let limit = self.config.session_max_concurrent_per_user; // 0 = unlimited
    if limit == 0 { return Ok(()); }
    let sessions = self.sessions.read().await;
    let count = sessions.values().filter(|s| {
        // Must lock to check created_by and status
        // Consider maintaining a separate counter for performance
    }).count();
    if count >= limit {
        return Err(SessionError::ConcurrentLimit);
    }
    Ok(())
}
```

**Performance optimization:** Maintain a `HashMap<String, AtomicU32>` of user→active_count that increments on create, decrements on disconnect. Avoids scanning the full session map.

**Admin bypass:** Yes, admins should bypass limits. Check role before enforcing:
```rust
if user_role == "admin" { return Ok(()); }
```

**Teleport's approach:** `max_connections` per role limits concurrent SSH connections per user. Audit events emitted when limit is exceeded.

---

### 5. Session Cleanup

**On any session termination (timeout, disconnect, error, admin kill):**

1. **Cancel CancellationToken** — signals all async tasks (WebSocket proxy, recording writer)
2. **Close WebSocket** — send close frame, drop connection
3. **Disconnect guacd** — drop `GuacdStream` (guacd closes the protocol connection)
4. **Clean browser processes** — `BrowserManager::kill()` (already implemented)
5. **Stop VDI container** — `VdiDriver::stop_container()` (already implemented)
6. **Clean drive mounts** — `drive::cleanup_session_dir()` (already implemented)
7. **Abort login script** — `login_script_handle.abort()` (already implemented)
8. **Shutdown SSH tunnels** — `tunnel::shutdown_chain()` (already implemented)
9. **Update DB** — set `ended_at`, `duration_secs`, `terminated_reason`, `status`
10. **Remove from in-memory map** — after delay (`session_cleanup_delay_secs`)
11. **Emit audit event** — structured log with all metadata

**Existing `cleanup_browser()` handles steps 4-8. Need to add step 9 (DB update) and step 10 (configurable retention).**

---

### 6. Session Listing

**API endpoints:**
- `GET /api/sessions` — list user's own sessions (filtered by `created_by`)
- `GET /api/sessions/all` — admin only, all sessions
- `GET /api/sessions/:id` — specific session info
- `DELETE /api/sessions/:id` — kill session (admin or owner)

**Response shape (already defined as `SessionInfo`):**
```json
{
  "session_id": "uuid",
  "session_type": "ssh|web|rdp|vnc|vdi|spice|proxmox",
  "status": "active|pending|completed|error|expired",
  "created_at": "2026-01-01T00:00:00Z",
  "hostname": "target-host",
  "username": "target-user",
  "created_by": "user@example.com",
  "active_connections": 1,
  "thumbnail_url": "/api/sessions/{id}/thumbnail",
  "client_url": "/client/{id}",
  "ws_url": "/ws/{id}"
}
```

**Add to `SessionInfo`:**
- `source_ip: Option<String>`
- `idle_timeout_mins: Option<u64>`
- `max_duration_mins: Option<u64>`
- `last_activity_at: Option<DateTime<Utc>>`
- `terminated_reason: Option<String>`

**Admin view:** Add pagination (`?page=1&per_page=50`), filtering (`?user=alice&status=active&type=ssh`), sorting (`?sort=started_at&order=desc`).

**DB query for listing:**
```sql
-- User's own sessions
SELECT * FROM session_history 
WHERE created_by = ? 
ORDER BY started_at DESC 
LIMIT ? OFFSET ?;

-- Admin: all sessions
SELECT * FROM session_history 
WHERE started_at > datetime('now', '-7 days')
ORDER BY started_at DESC 
LIMIT ? OFFSET ?;

-- Active session count per user
SELECT created_by, COUNT(*) as cnt 
FROM session_history 
WHERE status = 'active' 
GROUP BY created_by;
```

---

### 7. NIST Session Timeout Requirements (SP 800-63B)

| Requirement | AAL1 | AAL2 | AAL3 |
|---|---|---|---|
| **Overall max duration** | ≤30 days | ≤24 hours | ≤12 hours |
| **Idle timeout** | Not required (MAY) | ≤1 hour (SHOULD) | ≤15 minutes (SHOULD) |
| **Reauthentication** | Password or MFA | MFA (same as initial) | MFA (same as initial) |
| **Reauth on idle** | Not required | After 30+ min idle | After 15+ min idle |

**Key NIST language:**
- AAL1: "An inactivity timeout MAY be applied but is not required"
- AAL2: "The inactivity timeout SHOULD be no more than 1 hour"
- AAL3: "The inactivity timeout SHOULD be no more than 15 minutes"

**Recommendation for persea:** Default to AAL2 (30 min idle, 8h max). Make configurable per deployment. For high-security deployments, allow AAL3 presets (15 min idle, 12h max).

**ISO 27001 A.9.4.2 (now A.8.5 in 2022 revision):**
- Requires secure log-on procedures including session timeout
- Best practice: 15 minutes or less for sensitive environments
- Must terminate idle sessions automatically
- Must log successful and failed access attempts

---

### 8. Graceful Disconnect

**Network drop vs intentional disconnect:**

**Current behavior:** WebSocket close triggers `disconnect_viewer()` which decrements `active_connections`. When owner disconnects, session goes to `Completed` status.

**Recommended behavior:**

- **Intentional disconnect** (user clicks "Disconnect" or closes tab): WebSocket sends close frame → `disconnect_viewer()` → if owner, `complete_session()`
- **Network drop** (browser crashes, WiFi dies): WebSocket ping/pong fails after timeout → same as intentional disconnect
- **Session resume window:** Do NOT resume sessions across reconnects. Reason:
  - Security: reconnection from a different IP/device should require re-auth
  - Complexity: guacd connection state is tied to the WebSocket
  - Guacamole's approach: no resume, reconnect creates new session
  - Teleport's approach: no resume for SSH sessions

**Implementation:**
- WebSocket ping every 30 seconds, pong timeout 10 seconds
- On pong timeout: treat as network drop, begin cleanup
- No resume window — user must create new session (with full auth)
- Log the disconnection reason in audit trail

**Exception for VDI containers:** VDI containers persist after disconnect (controlled by `idle_timeout_mins` in VDI config). User can reconnect to same container. This is different from session resume — the container is a separate entity.

---

### Implementation Priority

1. **Add `last_activity_at` to Session struct** + update on WebSocket input
2. **Add `source_ip`, `terminated_reason` to session_history** (DB migration)
3. **Background reaper task** (idle + max duration) — single tokio task, 60s interval
4. **Concurrent session limits** — AtomicU32 counter per user
5. **Enhanced SessionInfo** — add idle/max/source_ip fields
6. **Admin session listing** — paginated, filterable API
7. **Warning before max duration** — WebSocket control message at T-5min
8. **Configurable presets** — AAL1/AAL2/AAL3 profile templates

### References

- NIST SP 800-63B §5.2: https://pages.nist.gov/800-63-4/sp800-63b.html
- Apache Guacamole `api-session-timeout`: https://guacamole.apache.org/doc/gug/configuring-guacamole.html
- Teleport `client_idle_timeout`: https://goteleport.com/docs/zero-trust-access/management/security/client-timeout
- ISO 27001:2022 Annex A 8.5 (secure authentication) + A.8.16 (monitoring activities)
- Teleport concurrent session control: https://goteleport.com/blog/ssh-session-control
