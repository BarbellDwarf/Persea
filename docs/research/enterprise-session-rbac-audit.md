# Enterprise Session Management, RBAC, and Audit Patterns for persea

> **Design record.** This is a historical design document: the research that decided which enterprise features persea would build, and how. It is not a user guide: see [Roles and Access Control](../roles-and-access-control.md) for session lifecycle and RBAC, and [Security](../security-hardening.md#audit-log-tamper-evident-hash-chain) for the audit log.

## What this document is

Before persea had session limits, per-connection permissions, or tamper-evident audit logs, this document surveyed how four reference systems handle the problem: Apache Guacamole (the product persea replaces), Teleport, HashiCorp Boundary, plus the NIST 800-53 / 800-63B and SOC 2 compliance frameworks, and decided what persea should build and how.

**What was decided and shipped:**

- **Idle timeout and maximum duration live at the session-proxy layer, not the HTTP session layer.** Closing the WebSocket must tear down the guacd connection with it. Shipped as `session_idle_timeout_secs` (sessions silent past the timeout are reaped) and `session_max_duration_secs` (hard cap, default 8 hours, matching Boundary's default).
- **Connection-level permissions, not just roles.** Beyond the four-tier role hierarchy (admin > poweruser > operator > viewer), access to individual connections and folders is granted per group via object permissions (`read`, `connect`, `update`, `delete`, `administer`), with recursive inheritance through group nesting. Shipped as the RBAC layer (`src/rbac.rs`).
- **A tamper-evident audit log.** Every security-relevant event is chained with SHA-256 hashes so any alteration is detectable. Shipped as the hash-chain audit log (`src/audit.rs`).
- **Password policy aligned with NIST 800-63B.** Argon2id hashing (OWASP parameters), a minimum length of 15 characters, and reuse history (the last 5 hashes per user are kept; reusing one is rejected). Account lockout after repeated failures. Shipped (`src/password.rs`, `src/auth_providers/database.rs`).
- **Login-time MFA.** A TOTP second factor layered on top of primary authentication, per the two-phase model in the research. Shipped via the auth chain.

**What did not ship** (still future work, not implemented): syslog/SIEM forwarding in CEF/LEEF format, just-in-time (JIT) access requests with approval workflows, per-session MFA re-prompts, time-of-day access windows, and keystroke-level session recording. Vault-backed storage of connection credentials did ship, but through persea's own vault client rather than the "credential injection" workflow researched here.

---

Research compiled from Apache Guacamole, Teleport, HashiCorp Boundary, NIST 800-53, NIST 800-63B, and SOC 2 documentation.

---

## 1. Session Management for Remote Access Tools

### Apache Guacamole

**Session Recording:**
- Two modes: **graphical recording** (screen capture to `.guac` files, playable via `guacenc`) and **text recording** (typescripts for SSH, compatible with `scriptreplay`)
- Recordings are per-connection, configured by setting `recording-path` and `recording-name` parameters on each connection
- Files named with `${HISTORY_UUID}` for lookup by the recording storage extension
- Recording options: `recording-exclude-output`, `recording-exclude-mouse`, `recording-include-keys`, `recording-write-existing`
- Never overwrites existing recordings (appends numeric suffix)
- guacamole-recording-storage extension provides in-browser playback

**Idle Timeout:**
- `api-session-timeout` (default 60 minutes) controls **authentication token** expiry, NOT remote desktop connection idle timeout
- Guacamole considers an open remote desktop connection as "user activity" regardless of mouse/keyboard input: so `api-session-timeout` does NOT close idle remote sessions
- Remote desktop idle timeout must be configured on the **target server** (e.g., Windows Group Policy "Idle session limit", SSH `ClientAliveInterval`/`ClientAliveCountMax`)
- **Key insight for persea**: idle timeout must be implemented at the WebSocket/guacd level, not at the HTTP session level

**Max Duration / Concurrent Sessions:**
- No built-in max session duration or concurrent session limit in open-source Guacamole
- Active sessions view shows all connected sessions; admins can kill them manually
- Connection sharing is per-connection (toggle "enable connection sharing")

**Session Binding:**
- Sessions are bound to the authenticated user (shown in connection history)
- Source IP is logged per session

### Teleport

**Session Recording:**
- Four recording modes: `node-sync`, `node`, `proxy-sync`, `proxy`
  - `node` (default): recording at SSH node, async
  - `proxy`: recording at proxy, decrypts SSH traffic: tamper-resistant from agent side
  - `*-sync` variants: synchronous, blocks session until recording is flushed
- Enhanced session recording: eBPF-based, captures commands, disk access, network connections
- Recordings stored as structured JSON events + video, in S3/GCS
- Recordings are identity-attributed at capture time
- RBAC controls who can view recordings via `where` clauses on `session` resources
- Session recording can be configured per-role via `record_session` option

**Per-Session MFA:**
- Enabled via `require_session_mfa: true` on role
- Can be set cluster-wide or per-role (logical OR: if any role requires it, MFA is enforced)
- `mfa_verification_interval` controls re-verification frequency
- Applies to resources in the role's `allow` section only

**Session Limits:**
- `max_session_ttl`: maximum certificate lifetime (controls how long a session can live)
- `max_connections`: total session channels per connection (default 10)
- `disconnect_expired_cert`: terminate sessions when cert expires

### HashiCorp Boundary

**Session Brokering:**
- Three credential workflows:
  1. **User-managed**: user knows the credential (not recommended)
  2. **Credential brokering**: Vault returns credential to user, user enters it
  3. **Credential injection** (Enterprise): Vault injects credential directly into session, user never sees it
- Sessions are scoped to organizations/projects
- `session_max_seconds`: per-target max session duration (default 28800 = 8 hours)
- `session_connection_limit`: max connections per session (-1 = unlimited)

**Session Termination:**
- Permissions evaluated only at session establishment: role changes don't affect existing sessions
- Sessions terminated when: user disconnects, max duration reached, admin cancels, or credential expires

**Scope-Based Access:**
- Global → Organization → Project hierarchy
- Roles assigned at any scope, permissions cascade down
- Grant strings: `id=;type=;actions=;output_fields=`

### Best Practices for persea

**Session Binding:**
- Tie every session to the authenticated identity (user email + OIDC subject)
- Log source IP at session creation and enforce CIDR allowlists per connection
- Consider Teleport's approach: embed identity in session metadata, not just log it

**Idle Timeout Implementation:**
- Track last WebSocket activity timestamp per session
- On timeout: close WebSocket → sends disconnect to guacd → guacd closes protocol connection
- What gets terminated: **both**: the WebSocket proxy connection AND the guacd TCP connection
- The guacd connection is a child of the WebSocket; closing the parent kills the child
- Implement at the proxy layer (persea websocket.rs), not at HTTP session level

**Max Duration:**
- Hard cap per-session (configurable, default 8 hours like Boundary)
- Separate from idle timeout: forces re-authentication even for active sessions

---

## 2. RBAC for Remote Access

### Apache Guacamole Permission Model

Two layers:

1. **System Permissions** (global capabilities):
   - `ADMINISTER_SYSTEM`: full admin access
   - `CREATE_USER`: create users
   - `UPDATE_USER`: modify users
   - `DELETE_USER`: delete users
   - `CREATE_CONNECTION`: create connections
   - `UPDATE_CONNECTION`: modify connections
   - `DELETE_CONNECTION`: delete connections
   - `CREATE_USER_GROUP` / `UPDATE_USER_GROUP` / `DELETE_USER_GROUP`
   - `CREATE_CONNECTION_GROUP` / `UPDATE_CONNECTION_GROUP` / `DELETE_CONNECTION_GROUP`
   - `ADMINISTER_SESSIONS`: kill active sessions

2. **Object Permissions** (per-connection or per-connection-group):
   - `READ`: view the connection
   - `UPDATE`: modify the connection
   - `DELETE`: delete the connection
   - `ADMINISTER`: change permissions on the connection
   - `CONNECT`: actually connect to the remote desktop/server

**Key design**: You can have `CREATE_CONNECTION` system permission but only `CONNECT` on specific connections. Separation of "can create" from "can connect to what".

### Teleport RBAC

Role YAML structure:
```yaml
kind: role
metadata:
  name: developer
spec:
  options:
    max_session_ttl: 8h
    require_session_mfa: true
  allow:
    node_labels:
      env: [dev, staging]
      team: backend
    logins: [ubuntu, "{{internal.logins}}"]
    rules:
      - resources: ["session"]
        verbs: ["list", "read"]
  deny:
    node_labels:
      env: production
```

**Key concepts:**
- **Label-based access**: nodes tagged with labels, roles match labels
- **Login allowlists**: which OS users you can connect as
- **Deny rules**: always enforced, override allow
- **`where` clauses**: filter sessions by metadata (e.g., `session.created_by == user.email`)
- **`max_session_ttl`**: certificate lifetime limit
- **Per-session MFA**: `require_session_mfa: true`
- **`pin_source_ip`**: bind certificate to login IP (Enterprise)

### HashiCorp Boundary

- **Global → Organization → Project** scope hierarchy
- **Roles** assigned at any scope, permissions apply to descendants
- **Grant strings**: `id=;type=;actions=output_fields`
- **Resources**: targets, host-catalogs, credential-stores, sessions, etc.
- **Actions**: list, read, update, delete, authorize-session, etc.
- **`authorize-session`**: the critical permission: who can connect to what
- **Managed groups**: auto-populated from IdP group membership

### persea Role Assessment

Current roles: `admin` (4) > `poweruser` (3) > `operator` (2) > `viewer` (1)

**Is this sufficient?** Mostly yes, but needs refinement:

| Role | Current | Recommended |
|------|---------|-------------|
| admin | Full access | Full access + connection management |
| poweruser | Ad-hoc sessions + connections | Ad-hoc sessions + connections connect |
| operator | Connections connect only | Connections connect only (no ad-hoc) |
| viewer | Read-only | Read-only (no connect) |

**Missing: connection-level permissions.** Currently role-based only, not connection-based. Need:
- Per-connection or per-folder `CONNECT` permission (like Guacamole's object permissions)
- Group-based connection access (connect to connections in folders matching your groups)
- Time-based access restrictions (Boundary-style `session_max_seconds` per target)

**Recommendation**: Add a `connection_permissions` table:
```sql
CREATE TABLE connection_permissions (
    id INTEGER PRIMARY KEY,
    connection_entry TEXT NOT NULL,  -- Vault entry path
    allowed_groups TEXT,             -- comma-separated OIDC groups
    max_session_secs INTEGER,       -- per-connection max duration
    allowed_hours TEXT,              -- time window (e.g., "09:00-17:00")
    created_at TEXT
);
```

---

## 3. Audit Logging for Compliance

### NIST 800-53 AU-2 / AU-3 Required Events

**AU-2** mandates logging these event types for remote access:
1. Authentication events: logon success/failure, logoff
2. Privilege use: privileged command execution
3. Security-relevant file/object events: access, modification
4. User/group management: add, delete, modify, disable, lock
5. Policy changes: security or audit policy changes
6. Session events: session start/end, connection attempts
7. System events: startup, shutdown, errors

**AU-3** specifies what each audit record must contain:
- **Event type** (what happened)
- **Timestamp** (when)
- **Source location** (where in the system)
- **Outcome** (success/failure)
- **Identity** (who: user, process)
- **Additional context** (source IP, target resource, session ID)

### SOC 2 Requirements (CC6.1, CC6.6, CC6.7)

- CC6.1: Logical access controls: restrict who can access what
- CC6.6: Restrict remote access: system boundary protection
- CC6.7: Monitor and control remote access: session logging, audit trails
- Evidence required: session logs showing who connected, when, which device, session activity

### Apache Guacamole Audit Model

**connection_history table:**
- user, connection name, start time, duration, recording availability
- Filterable/sortable in admin UI

**user_history** (implied by session management):
- Tracks active sessions with: user, duration, source IP, connection name

**Key limitations:**
- No structured JSON events: just database rows
- No syslog/SIEM integration built-in
- Recordings are proprietary format (`.guac`)

### Recommended persea SQLite Audit Log Schema

Based on AU-2/AU-3 requirements:

```sql
-- Unified audit event log (AU-2, AU-3 compliant)
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    event_type TEXT NOT NULL,        -- 'auth.login', 'auth.logout', 'auth.failure',
                                     -- 'session.start', 'session.end', 'session.idle_timeout',
                                     -- 'connection.connect', 'connection.disconnect',
                                     -- 'admin.user.create', 'admin.user.modify',
                                     -- 'admin.connection.create', 'admin.connection.modify',
                                     -- 'admin.api_key.create', 'admin.api_key.rotate',
                                     -- 'system.startup', 'system.error'
    severity TEXT NOT NULL DEFAULT 'info',  -- 'info', 'warn', 'error', 'critical'
    user_email TEXT,                  -- authenticated user
    user_role TEXT,                   -- role at time of event
    source_ip TEXT,                   -- client IP (AU-3: source)
    target_resource TEXT,             -- what was accessed (connection name, user email, etc.)
    session_id TEXT,                  -- correlation ID for session events
    outcome TEXT NOT NULL,            -- 'success', 'failure', 'denied'
    details TEXT,                     -- JSON blob for additional context (never secrets)
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ae_timestamp ON audit_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_ae_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_ae_user ON audit_events(user_email);
CREATE INDEX IF NOT EXISTS idx_ae_session ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_ae_outcome ON audit_events(outcome);
```

### Syslog/CEF/LEEF Format for SIEM Integration

**CEF (Common Event Format)**, preferred for Splunk, ArcSight, QRadar:
```
CEF:0|persea|persea|1.0|session.start|Session Started|5|src=10.0.0.1 suser=admin@example.com destinationServiceName=ssh-target1 cs1=uuid-here cs1Label=sessionId cs2=ssh cs2Label=sessionType
```

**LEEF (Log Event Extended Format)**, IBM QRadar native:
```
LEEF:1.0|persea|persea|1.0|session.start|devTime=2024-01-15T10:30:00Z|src=10.0.0.1 usrName=admin@example.com sessionId=uuid-here sessionType=ssh target=ssh-target1
```

**Implementation recommendation:**
- Add `syslog_enabled`, `syslog_host`, `syslog_port`, `syslog_format` to config
- Use `tracing` + `tracing-subscriber` with a syslog layer
- Structured JSON log to file for local querying
- Optional CEF/LEEF formatting for syslog output

### Tamper-Resistant Logging Patterns

1. **Append-only tables**: SQLite doesn't support append-only natively, but:
   - Never `DELETE` from audit tables (only mark as archived)
   - Use `audit_events` as a write-only table in normal operation
   - Retention cleanup via separate archival process

2. **Hash chain** (recommended for SOC 2 / NIST):
   ```sql
   -- Add previous_hash column
   ALTER TABLE audit_events ADD COLUMN previous_hash TEXT;
   ALTER TABLE audit_events ADD COLUMN event_hash TEXT;
   ```
   Each event's hash = SHA-256(timestamp + event_type + user + details + previous_hash)
   Verify chain integrity on-demand

3. **Separate audit database** (optional, high-security):
   - Write audit events to a separate SQLite file
   - Run on a different disk/mount point
   - Forward to remote syslog/S3 simultaneously

4. **WAL mode + fsync**: Enable WAL journal mode and `PRAGMA synchronous=FULL` for crash-safe writes

---

## 4. Password Policies

### Apache Guacamole Password Management

- Password policies configured via database auth extension
- Supports: password expiry, password history (prevent reuse), account lockout
- Lockout: configurable number of failed attempts, lockout duration
- No built-in breached password screening

### NIST 800-63B Requirements (Rev 4, mid-2025)

**Key requirements:**
1. **Minimum length**: 8 characters minimum, 15 characters recommended for single-factor
2. **Maximum length**: support at least 64 characters
3. **No mandatory complexity rules**: no forced uppercase, numbers, symbols
4. **No forced rotation**: only rotate on suspected compromise
5. **Breach screening**: MUST check new passwords against blocklist of compromised/common passwords
6. **Blocklist contents**: breached passwords, dictionary words, repetitive/sequential chars, context-specific words (service name, username)
7. **Account lockout**: limit consecutive failed attempts (NIST recommends >= 10 before lockout)
8. **Rate limiting**: implement rate limiting, adjust based on context (IP, location, device)
9. **No password hints**: cannot store hints accessible to unauthenticated users
10. **No knowledge-based auth**: security questions are prohibited
11. **Paste support**: enable paste in password fields (for password managers)
12. **Storage**: salted cryptographic hashing (PBKDF2, Argon2, bcrypt)

### persea Implementation

**Current state:** persea uses SHA-256 for API key hashing (not password-based auth). No local password policy exists since OIDC handles authentication.

**If adding local password auth:**

```sql
-- Password policy table
CREATE TABLE password_policy (
    id INTEGER PRIMARY KEY DEFAULT 1,
    min_length INTEGER NOT NULL DEFAULT 15,
    max_length INTEGER NOT NULL DEFAULT 64,
    require_breach_check INTEGER NOT NULL DEFAULT 1,
    lockout_attempts INTEGER NOT NULL DEFAULT 10,
    lockout_duration_mins INTEGER NOT NULL DEFAULT 30,
    progressive_delay INTEGER NOT NULL DEFAULT 1,  -- 1=progressive, 0=fixed
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Failed login attempts
CREATE TABLE login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    outcome TEXT NOT NULL,  -- 'success', 'failure'
    failure_reason TEXT,    -- 'invalid_password', 'account_locked', 'account_disabled'
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_la_user ON login_attempts(user_email, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_la_ip ON login_attempts(source_ip, created_at DESC);

-- Password history (for breach check, not forced rotation)
CREATE TABLE password_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**Account Lockout: Progressive vs Permanent**

NIST recommends **progressive delay**, not permanent lockout:
- 1st-5th failure: no delay
- 6th-7th: 30 second delay
- 8th-9th: 5 minute delay
- 10th+: 30 minute lockout
- Reset counter after 30 minutes of no failed attempts

**Recommendation**: Progressive delay for API/auth endpoints, configurable via `password_policy` table.

---

## 5. Connection Policies

### IP Allowlisting (Already Implemented)

persea already has CIDR allowlists per admin API key. Need to extend:
- Per-connection IP allowlists (stored in Vault or SQLite)
- Per-user IP restrictions
- Time-based access windows

### Time-Based Access Control

**Patterns from Teleport/Boundary:**
- Teleport: `max_session_ttl` per role (limits how long a session can live)
- Boundary: `session_max_seconds` per target (limits per-connection duration)
- Time-of-day restrictions: not built into either, but achievable via policy engines

**Implementation for persea:**

```sql
-- Time-based access rules
CREATE TABLE access_windows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_entry TEXT,           -- NULL = global rule
    allowed_groups TEXT,             -- comma-separated OIDC groups
    allowed_days TEXT NOT NULL,      -- comma-separated: "mon,tue,wed,thu,fri"
    start_hour INTEGER NOT NULL,     -- 0-23 UTC
    end_hour INTEGER NOT NULL,       -- 0-23 UTC
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### Just-In-Time Access

**Pattern from Boundary/Teleport:**
- Boundary: users request access → approval → temporary credential → auto-revoke
- Teleport: Access Requests with Slack/PagerDuty approval workflows

**persea JIT implementation:**
1. User requests access to a connection (POST /api/jit-request)
2. Admin approves (or auto-approve for low-risk connections)
3. Time-bound permission created (e.g., 4-hour window)
4. Permission auto-expires
5. Full audit trail of request → approval → usage → expiry

**Storage:**
```sql
CREATE TABLE jit_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email TEXT NOT NULL,
    connection_entry TEXT NOT NULL,
    requested_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',  -- 'pending', 'approved', 'denied', 'expired', 'revoked'
    reason TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

---

## Summary: What shipped vs what remains

### Shipped (implemented)

1. **Idle timeout at the WebSocket/proxy level**: last-activity tracking terminates both the WebSocket and the guacd connection
2. **Max session duration**: hard cap (default 8 hours), independent of idle timeout
3. **Concurrent session limits**: global and per-user caps
4. **Connection-level permissions**: group-based object permissions (read/connect/update/delete/administer) on connections and folders, with recursive group inheritance
5. **Hash-chain audit log**: SHA-256 chained events with on-demand verification
6. **Password policy**: Argon2id with OWASP parameters, 15-character minimum, reuse history, account lockout after repeated failures
7. **Login-time MFA**: TOTP second factor in the auth chain

### Not implemented (future work)

8. **Syslog forwarding**: structured JSON / CEF / LEEF to a remote SIEM
9. **Time-based access windows**: time-of-day restrictions on connections
10. **JIT access requests**: approval workflows with auto-expiring permissions
11. **Per-session MFA**: OIDC re-authentication prompts on sensitive connections
12. **Keystroke-level session recording**: command capture (Teleport eBPF model)

---

## Sources

- Apache Guacamole Manual v1.6.0: https://guacamole.apache.org/doc/gug/configuring-guacamole.html
- Apache Guacamole Administration: https://guacamole.apache.org/doc/gug/administration.html
- Teleport Session Recording: https://goteleport.com/docs/reference/architecture/session-recording
- Teleport RBAC: https://goteleport.com/docs/enroll-resources/server-access/rbac
- Teleport Per-Session MFA: https://goteleport.com/docs/zero-trust-access/authentication/per-session-mfa
- HashiCorp Boundary Security Model: https://developer.hashicorp.com/boundary/docs/secure/security-model
- HashiCorp Boundary Credential Management: https://developer.hashicorp.com/boundary/docs/credentials
- NIST SP 800-53 Rev 5: https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-63B Rev 4: https://pages.nist.gov/800-63-4/sp800-63b.html
- NIST 800-63B Password Guidelines: https://netwrix.com/en/resources/blog/nist-password-guidelines
- SOC 2 Access Control: https://truvocyber.com/blog/soc2-access-control-on-prem
- SOC 2 Logging: https://www.konfirmity.com/blog/soc-2-logging-and-monitoring
