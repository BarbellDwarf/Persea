# API Reference

> **Audience:** developers and integration engineers building clients or
> scripts against persea.
> **Next:** [NetBox Integration](netbox.md) for a concrete
> `GET /api/connect` integration example.

persea exposes a JSON API under `/api/` for automation: creating
sessions, managing the address book, administering users, reading audit
logs, and checking health. The web UI itself is built on these same
endpoints, so anything the UI can do, a script can do.

This document is organised by task. It covers the endpoints most people
need to script, check health, list connections, create sessions,
manage users, and summarises the rest.

## Authentication

Every request to `/api/*` (except the few endpoints noted as public)
must authenticate one of three ways:

1. **API key**: `Authorization: Bearer <key>` or `X-API-Key: <key>`
   header. Admin API keys are created in the admin UI; users can create
   their own tokens (see [Tokens](#user-api-tokens-self-service)).
   Admins can disable API-key auth entirely via the `enable_api_keys`
   system setting.
2. **User API token**: the same headers, with a personal token
   (`rgu_...`). The token's effective role is the *lower* of the user's
   current role and the token's `max_role` cap, so a demoted user's
   tokens lose power immediately.
3. **Login session cookie**: `persea_session`, set by the web login.
   Useful in browsers; for scripts, an API key is simpler.

## CSRF requirement

All state-changing requests (POST, PUT, DELETE, PATCH) must also carry
an `X-CSRF-Token` header whose value exactly matches the `csrf_token`
cookie. Every response sets a `csrf_token` cookie, so the workflow for
a script is: make one request to receive the cookie, then echo it back
as the header:

```bash
# 1. Learn the CSRF token from a GET request (it sets the cookie)
curl -s -c /tmp/persea-cookies.txt https://persea.example.com/api/health

# 2. Read it back and send it with every state-changing request
CSRF=$(awk '$6 == "csrf_token" {print $7}' /tmp/persea-cookies.txt)
curl -s -b /tmp/persea-cookies.txt \
     -H "X-CSRF-Token: $CSRF" \
     -H "Authorization: Bearer $API_KEY" \
     -H "Content-Type: application/json" \
     -d '{"session_type":"ssh","hostname":"10.0.0.1"}' \
     https://persea.example.com/api/sessions
```

A missing or mismatched token returns `403` with
`{"error": "CSRF token missing or invalid"}`. GET/HEAD/OPTIONS are
exempt. The `csrf_token` cookie is deliberately readable by page
JavaScript (that is how the web UI echoes it back); `HttpOnly` is only
set on the session cookie.

## Error response format

Every API endpoint returns errors in a unified JSON shape:

```json
{
  "error": "human-readable message",
  "code": 404,
  "error_code": "NOT_FOUND"
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `error` | string | Human-readable error message |
| `code` | integer | The HTTP status code, repeated in the body |
| `error_code` | string | Machine-readable error category |

| `error_code` | HTTP status | Meaning |
|--------------|-------------|---------|
| `NOT_FOUND` | 404 | Requested resource does not exist |
| `VALIDATION_ERROR` | 400 | Bad request / validation failure |
| `CONFLICT` | 409 | State conflict (e.g. session not active, duplicate mapping) |
| `BAD_GATEWAY` | 502 | Upstream failure (guacd, Vault, browser, VDI, tunnel, Proxmox, vSphere) |
| `UNAUTHORIZED` | 401 | Missing or invalid authentication |
| `FORBIDDEN` | 403 | Authenticated but not allowed |
| `SERVICE_UNAVAILABLE` | 503 | Feature not enabled or backend unavailable |
| `GATEWAY_TIMEOUT` | 504 | Upstream timed out (e.g. VDI container readiness) |
| `PAYLOAD_TOO_LARGE` | 413 | Request body over the 64 KB limit (4 MB for address-book import, 2 MB for logo upload) |
| `INTERNAL_ERROR` | 500 | Server-side failure (also the fallback for any unmapped status) |

Two middleware-level rejections return the same JSON shape but with
only the `error` field: the CSRF layer (403, see above) and the
WebSocket Origin check (`cross-origin WebSocket request rejected` /
`WebSocket upgrade requires Origin header`, both 403).

## Roles

Endpoints require a minimum role. The four roles, strongest first:
`admin`, `poweruser`, `operator`, `viewer`. Requirements below are
stated relative to these names; a role requirement is always "or
higher" (an admin can do everything).

## Health and metrics

### `GET /api/health`: is the server alive?

No authentication required for the shallow check:
`{"status": "ok"}`. Authenticated requests with **operator** role or
higher get a deep check: guacd TCP connect, database query, Vault
health (when configured), recording-disk usage, and the active session
count, reported as `{"status": "healthy"|"degraded", "checks": {...}}`
with per-check `status` and `latency_ms`.

```bash
curl -s https://persea.example.com/api/health
# → {"status":"ok"}

curl -s -H "Authorization: Bearer $API_KEY" https://persea.example.com/api/health
# → {"status":"healthy","checks":{"guacd":{"status":"up",...},...},"uptime_seconds":1234,"active_sessions":3}
```

### `GET /metrics`: Prometheus metrics

Prometheus text exposition format, **unauthenticated**: `persea_sessions_active`,
`persea_sessions_total`, `persea_requests_total`, `persea_errors_total`,
`persea_uptime_seconds`. Because it is unauthenticated, do not expose
`/metrics` to untrusted networks: scrape it via a reverse-proxy ACL or
on the loopback interface.

## Identity

### `GET /api/auth/status`: what is this server?

No authentication. Returns whether OIDC is enabled, the site title,
whether drive/file transfer is configured, and the available theme
presets. Useful for integration code that must adapt to the server.

### `GET /api/me`: who am I?

Requires authentication. Returns the current user's name, email, role,
group memberships, auth source, and whether Vault is configured.

### `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`

Browser flow: `/auth/login` redirects to the OIDC provider (when
configured), `/auth/callback` completes the login, `POST /auth/logout`
clears the session cookie (CSRF-protected, form field `csrf_token` or
`X-CSRF-Token` header). (`POST /auth/login` is the local database
login form; the UI uses it, scripts normally don't need to.)

## Sessions

Sessions are the heart of persea: a session is a connection to one
target (SSH, RDP, VNC, SPICE, Proxmox, web browser, or VDI container).
Creating a session only opens the connection to the target; a browser
then attaches over a WebSocket to stream it (see
[Connecting to a session](#connecting-to-a-session)).

### `POST /api/sessions`: create a session

Requires **poweruser** role or higher. The body selects the session
type and target. Examples:

```bash
# SSH with a password
curl -s -X POST https://persea.example.com/api/sessions \
  -H "Authorization: Bearer $API_KEY" -H "X-CSRF-Token: $CSRF" \
  -H "Content-Type: application/json" \
  -d '{"session_type":"ssh","hostname":"10.0.0.1","username":"root","password":"secret"}'

# SSH with an ephemeral keypair (public key returned in banner_text)
#   {"session_type":"ssh","hostname":"10.0.0.1","username":"root","generate_keypair":true}

# RDP
#   {"session_type":"rdp","hostname":"10.0.0.1","username":"Administrator","password":"secret","ignore_cert":true}

# VNC
#   {"session_type":"vnc","hostname":"10.0.0.1","password":"vnc-secret"}

# Web browser session
#   {"session_type":"web","url":"https://example.com"}

# RDP reached through an SSH bastion (jump_hosts works for any type)
#   {"session_type":"rdp","hostname":"10.10.10.1","username":"Administrator","password":"secret",
#    "jump_hosts":[{"hostname":"bastion.example.com","username":"jump-user","password":"jump-pass"}]}
```

Common fields (all optional unless noted):

| Field | Used by | Meaning |
|-------|---------|---------|
| `session_type` | all (required) | `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, or `vdi` |
| `hostname` | SSH/RDP/VNC | Target hostname or IP |
| `port` | SSH/RDP/VNC | Target port (defaults: SSH=22, RDP=3389, VNC=5900) |
| `username` / `password` | SSH/RDP/VNC | Credentials |
| `private_key` | SSH | OpenSSH PEM private key |
| `generate_keypair` | SSH | Generate an ephemeral Ed25519 keypair; the public key is returned in `banner_text` |
| `url` | web | Target URL for browser sessions |
| `domain` | RDP | Windows domain |
| `security` | RDP | `tls`, `nla`, or `rdp` |
| `ignore_cert` | RDP | Ignore TLS certificate errors |
| `jump_hosts` | all | Ordered chain of SSH bastion hops; each hop connects through the previous one; the last forwards to the target. Each hop takes `hostname`, `port` (default 22), `username`, and `password` or `private_key`. |
| `enable_recording` | all | Override the global recording setting for this session |
| `disable_copy` / `disable_paste` | all | Disable clipboard copy/paste for the session |
| `width`, `height`, `dpi` | all | Display geometry |
| `banner` | all | Banner message shown before the session starts |

Legacy single jump host fields (`jump_host`, `jump_port`,
`jump_username`, ...) are still accepted for backward compatibility but
`jump_hosts` takes precedence.

**Response:**

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "client_url": "/client/550e8400-e29b-41d4-a716-446655440000",
  "ws_url": "/ws/550e8400-e29b-41d4-a716-446655440000",
  "share_url": "/client/550e8400-e29b-41d4-a716-446655440000?token=abc123"
}
```

- `client_url` opens the session in the built-in client page.
- `ws_url` is the raw WebSocket endpoint for custom clients.
- `share_url` (present only when sharing is allowed) lets a second
  viewer **join** an active session: it is not owner access.

### `GET /api/sessions`: list sessions

Any authenticated user sees their own sessions; `?all=true` as an
**admin** lists every user's. Optional `limit` truncates the result
(most recent first).

### `GET /api/sessions/{id}`: session details

The session owner or an **admin**.

### `DELETE /api/sessions/{id}` (or `POST /api/sessions/{id}/terminate`): end a session

Requires **operator** role or higher; non-admins can only terminate
their own sessions.

### `POST /api/sessions/{id}/shadow`: take over a session

Admins can shadow (watch or take over) another user's active session.

### `GET /api/sessions/{id}/banner`

Gets a session's banner text. Authenticates via share token rather than
credentials: this is how the ephemeral-keypair banner page works.

## Connecting to a session (owner vs. join)

Creating a session does not display anything; a browser attaches over a
WebSocket to stream it. The two connection roles are the most common
source of integration confusion:

- The **first** connection to a freshly created session is the **owner**
  connection. It requires an authenticated identity with **operator**
  role or higher.
- A **share token** (`share_url`) only lets a second viewer **join** a
  session that is already active. It is not an identity and cannot open
  the owner connection.

If the owner connection is not authenticated, persea rejects the
WebSocket with 403, no browser attaches, and guacd eventually reports
`User is not responding` (its timeout for a session whose client never
arrived, roughly 15 seconds after creation).

### `POST /api/ws-ticket`: hand a session to a browser without exposing your API key

Exchange an API key or login session for a **single-use, 30-second**
WebSocket ticket that inherits the caller's identity:

```
POST /api/ws-ticket
Authorization: Bearer <api-key>
→ { "ticket": "wst_1a2b3c..." }
```

Then send the browser to `/client/{id}?ticket=wst_...`. This is the
recommended pattern for headless integrations, where the browser has no
persea login of its own:

1. `POST /api/sessions` (Bearer API key) to create the session.
2. `POST /api/ws-ticket` (Bearer API key) to mint a ticket.
3. Send the browser to `client_url?ticket=<ticket>`.

The single-use, 30-second ticket is safe to place in a URL; the durable
API key never leaves the backend. Because guacd drops a session whose
client has not attached within ~15 seconds, mint the ticket and open
the browser promptly after creating the session (on a reload, mint a
fresh ticket).

### Custom clients

To build your own client, open the WebSocket at `ws_url` with the
`guacamole` sub-protocol and a `?ticket=<ticket>` query parameter, then
speak the [Guacamole protocol](https://guacamole.apache.org/doc/gug/guacamole-protocol.html).
This is the same endpoint the built-in client uses. WebSocket upgrades
are validated against a strict Origin check (cross-origin requests are
rejected) and rate-limited unconditionally.

## Address book (connections)

The address book stores named, reusable connections in folders. Entries
have stored credentials (in the database or Vault), so users connect
without typing passwords.

### Listing connections

```bash
# All folders you can see
curl -s -H "Authorization: Bearer $API_KEY" \
  https://persea.example.com/api/addressbook/folders

# Entries in a folder (scope is "shared" or "instance")
curl -s -H "Authorization: Bearer $API_KEY" \
  https://persea.example.com/api/addressbook/folders/shared/production/entries

# Everything at once (flat list, handy for search UI)
curl -s -H "Authorization: Bearer $API_KEY" \
  https://persea.example.com/api/addressbook
```

Folders can restrict access to certain groups; admins see all folders.
Nested folder names are encoded with `%2F` in URLs: see
[Reverse Proxies](reverse-proxies.md) if your reverse proxy breaks
those paths.

### Connecting from an entry

`POST /api/addressbook/folders/{scope}/{folder}/entries/{entry}/connect`
creates a session from a stored entry. Requires **operator** role and
folder group access. Credentials (including jump-host credentials) are
read server-side from the stored entry; nothing sensitive is sent to
the browser.

The optional body overrides or supplies credentials at connect time,
useful for entries with `prompt_credentials` enabled:

```json
{
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "user-password",
  "domain": "CORP.EXAMPLE.COM",
  "width": 1920,
  "height": 1080
}
```

Prompted credentials are used for that session only and are never
stored. Jump-host credentials always come from the stored entry and
cannot be overridden at connect time.

### Managing folders and entries (admin)

| Endpoint | Purpose |
|----------|---------|
| `POST /api/addressbook/folders` | Create a folder: `{"scope":"shared","name":"production","allowed_groups":["engineering"]}` |
| `PUT` / `DELETE /api/addressbook/folders/{scope}/{folder}` | Update / delete a folder (delete removes all its entries) |
| `POST /api/addressbook/folders/{scope}/{folder}/entries` | Create an entry: `{"name":"prod-db","type":"ssh","hostname":"db.internal.example.com","username":"admin","password":"secret"}` |
| `PUT` / `DELETE /api/addressbook/folders/{scope}/{folder}/entries/{entry}` | Update / delete an entry. Updates are read-modify-write: omitted credential fields are preserved from the stored entry. |
| `POST /api/addressbook/import` | Bulk-import entries from CSV (see the import template at `GET /api/addressbook/import-template`) |

Entry `type` values match session types. Additional entry fields
mirror the session fields (`jump_hosts`, `allowed_domains` for web
sessions, `prompt_credentials`, `enable_recording`, clipboard controls,
display geometry, and the `spice_*` / `proxmox_*` fields). The
`proxmox_token_secret` is write-only: read endpoints never return it
(a `has_proxmox_token_secret` boolean indicates whether one is stored),
and it is preserved on update when omitted.

## Quick connect (`POST /api/connect`)

A convenience endpoint for external integrations (e.g. NetBox Custom
Links). Creates a session and redirects the browser to the client page;
if the user is not authenticated and OIDC is configured, it redirects
to SSO login and back. POST-only (a GET could be triggered cross-site).

- **Ad-hoc mode** (poweruser+): `/api/connect?hostname=10.0.1.50&protocol=ssh`
- **Connections mode** (operator+): `/api/connect?scope=shared&folder=production&entry=web-server-01`

Ad-hoc parameters: `protocol` (`ssh`, `rdp`, `vnc`, `web`; default
`ssh`), `hostname`, `port`, `username`, `url` (web sessions),
`width`/`height`/`dpi`. No credentials are passed in the URL for
ad-hoc mode; if the target requires authentication, the user sees
guacd's login prompt. If the entry has `prompt_credentials` or no
stored password, the endpoint returns an inline credential form instead
; the user's input is POSTed back and used for that session only.

## Users and roles (admin)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/users` | List all users |
| `POST /api/users` | Create a user (`{"name":"...","email":"...","password":"...","role":"operator"}`): the password is checked against the password policy |
| `PUT /api/users/{email}/role` | Set a role: `{"role":"poweruser"}` (roles: `admin`, `poweruser`, `operator`, `viewer`) |
| `POST /api/users/{email}/disable` / `enable` | Block / unblock login |
| `DELETE /api/users/{email}` | Delete a user (their tokens are cascade-deleted) |
| `DELETE /api/users/{email}/sessions` | Force-logout: delete all the user's auth sessions |

Role mapping from identity-provider groups (admin only):

| Endpoint | Purpose |
|----------|---------|
| `GET` / `POST /api/admin/group-mappings` | List / create group-to-role mappings, e.g. `{"oidc_group":"engineering","role":"poweruser"}` (409 if the group already has a mapping) |
| `PUT` / `DELETE /api/admin/group-mappings/{id}` | Update / delete a mapping |
| `GET /api/auth/known-groups` | Groups seen on the identity provider |

## User API tokens

Personal tokens let OIDC users call the API from scripts without
sharing their login session or an admin API key.

| Endpoint | Who | Purpose |
|----------|-----|---------|
| `POST /api/me/tokens` | poweruser+ | Create a personal token: `{"name":"my-ci-token","max_role":"operator","expires_at":"2026-12-31T23:59:59Z"}`. The plaintext token (`rgu_...`) is returned **once** at creation and cannot be retrieved again. |
| `GET /api/me/tokens` | any user | List your own tokens (metadata only) |
| `DELETE /api/me/tokens/{id}` | poweruser+ | Revoke a token (immediately invalid) |
| `POST /api/admin/user-tokens` | admin | Create a token for any user: `{"email":"...","name":"...","max_role":"operator","expires_at":"..."}`: useful for operators who cannot create their own |
| `GET /api/admin/user-tokens` | admin | List all tokens across all users |
| `DELETE /api/admin/user-tokens/{id}` | admin | Revoke any token |
| `GET /api/admin/token-audit` | admin | Token audit log (`limit`, `email` query params) |

## Recordings and typescripts

| Endpoint | Role | Purpose |
|----------|------|---------|
| `GET /api/recordings` | poweruser+ | List recording files |
| `GET /api/recordings/{name}` | poweruser+ | Serve a recording for playback (filename validated against path traversal) |
| `DELETE /api/recordings/{name}` | admin | Delete a recording |
| `GET /api/typescripts` | poweruser+ | List SSH typescripts (name/size/time only: the text content is deliberately not downloadable through the API; see [Configuration](configuration.md#ssh-typescript-recording)) |

## Audit log

The audit log is a tamper-evident SHA-256 hash chain: every event
contains a hash of the previous event, so altering any record breaks
the chain and flags every subsequent event.

| Endpoint | Role | Purpose |
|----------|------|---------|
| `GET /api/audit/events` | admin (Audit permission) | Query audit events |
| `GET /api/audit/verify` | admin (Audit permission) | Verify the hash chain: `{"status":"verified"|"broken", "events_scanned":..., "errors":[...]}` |
| `GET /api/audit/export` | admin (Audit permission) | Filtered CSV/JSON export of the audit log for compliance. |

See [Security Hardening](security-hardening.md#audit-log) for how to
read the verification result.

## Reports (admin)

Session analytics for the Reports page:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/reports/sessions` | Session list with filters |
| `GET /api/reports/sessions/csv` | CSV export of session data |
| `GET /api/reports/top-connections` / `top-users` | Most-used connections / users |
| `GET /api/reports/summary` | Aggregate summary |
| `GET /api/reports/activity` | Activity timeline |

## Administration

| Endpoint | Purpose |
|----------|---------|
| `GET /api/system/status` | System status overview |
| `GET` / `PUT /api/system/settings` | System settings (including `enable_api_keys`) |
| `GET /api/auth/providers` + CRUD under `/api/auth/providers/{id}` | Manage configured auth providers (create, update, enable/disable, reorder, test) |
| `GET` / `POST /api/admin/groups`, `/api/admin/groups/{id}` | Manage user groups and their role mappings |
| `GET` / `POST /api/admin/rbac/groups` + permissions under `/api/admin/rbac/connections/{id}/permissions` | Connection-level permission management |
| `GET` / `POST /api/admin/jump-hosts` + `/api/admin/jump-hosts/{id}` | Manage named SSH jump hosts; `POST .../test` tests reachability |
| `GET /api/admin/tunnels/active` | List currently active tunnels |
| `POST /api/upload-logo` | Upload a custom logo (2 MB limit) |
| `GET /api/login-scripts` | List available login scripts |
| `POST /api/ssh/probe-host-key` | Fetch a host's SSH host key (for entry setup) |
| `GET /api/admin/token-audit`, `GET /api/admin/addressbook-audit` | Token / address-book audit trails |

## vSphere (VMware)

| Endpoint | Purpose |
|----------|---------|
| `GET /api/vsphere/vms` | List VMs from the vCenter inventory |
| `POST /api/vsphere/vms/{vm_id}/power` | Power action on a VM |
| `GET /api/vsphere/vms/{vm_id}/connect` | Create a session to a VM (protocol auto-detected from the guest OS) |

## VDI containers

| Endpoint | Purpose |
|----------|---------|
| `GET /api/vdi/containers` | List running VDI containers |
| `GET /api/vdi/containers/{name}/thumbnail` | Container screen thumbnail |
