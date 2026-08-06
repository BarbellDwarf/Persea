# API Reference

> **Audience:** developers and integration engineers building clients, scripts, or NetBox/webhook integrations against persea.
> **Next:** [NetBox Integration](netbox.md) for a concrete `GET /api/connect` integration example.

All API endpoints are under `/api/`. Authentication is via `Authorization: Bearer <api-key>` header, `X-API-Key: <key>` header, or OIDC session cookie.

## Error response format

Every API endpoint returns errors in a unified JSON shape:

```json
{
  "error": "human-readable message",
  "code": 404,
  "error_code": "NOT_FOUND"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `error` | string | Human-readable error message |
| `code` | integer | The HTTP status code, repeated in the body |
| `error_code` | string | Machine-readable error category (see table below) |

`error_code` values are derived from the HTTP status:

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
| `PAYLOAD_TOO_LARGE` | 413 | Request body over the 64 KB limit |
| `INTERNAL_ERROR` | 500 | Server-side failure (also the fallback for any unmapped status) |

The HTTP status is set per error variant (`src/error.rs`). The mapping is:

| Error variant | HTTP status | Meaning |
|---------------|-------------|---------|
| `Auth` | 401 | Authentication failed or missing |
| `Forbidden` | 403 | Insufficient role / permissions |
| `Conflict` | 409 | State conflict |
| `Validation` | 400 | Invalid request body or parameters |
| `Session` | 404 / 400 / 409 / 502 | Message-dependent: "not found" → 404, "validation" → 400, "not active" → 409, otherwise 502 |
| `Guacd` | 502 | guacd unreachable or protocol error |
| `Vault` | 404 / 403 / 503 / 400 / 502 | Message-dependent: "not found" → 404, "forbidden"/"access denied" → 403, "unavailable" → 503, "invalid name" → 400, otherwise 502 |
| `Browser` | 502 | Web browser session backend failure |
| `Vdi` | 503 / 504 / 502 | "not enabled" → 503, "timeout" → 504, otherwise 502 |
| `Tunnel` | 502 | SSH tunnel chain failure |
| `Protocol` | 502 | Guacamole protocol error |
| `Drive` | 500 | Drive / file transfer failure |
| `Pve` | 502 | Proxmox VE API failure |
| `Vsphere` | 502 | VMware vSphere API failure |
| `Internal` | 500 | Unexpected server error |

Two middleware-level rejections return the same JSON shape but with only the `error` field (no `code`/`error_code`): the CSRF layer (`{"error": "CSRF token missing or invalid"}` with 403 — see [Security](security.md#csrf-protection)) and the WebSocket Origin check (`{"error": "cross-origin WebSocket request rejected"}` / `{"error": "WebSocket upgrade requires Origin header"}` with 403).

## Health

### `GET /api/health`

No authentication required for the shallow check, which returns `{"status": "ok"}` when the server is running.

Authenticated requests with **operator** role or higher get a deep check: guacd TCP connect, database `SELECT 1`, Vault `/v1/sys/health` (when configured), recording-disk usage, and the active session count. The response is `{"status": "healthy"|"degraded", "checks": {...}, "uptime_seconds": ..., "active_sessions": ...}`. Each check object reports `status` (`up`/`down`/`ok`/`warning`/`unavailable`) and `latency_ms`; the disk check reports `usage_percent`. See [Troubleshooting](troubleshooting.md) for how to read the results.

## Metrics

### `GET /metrics`

Prometheus text exposition format, **unauthenticated**. Five metrics are exposed:

| Metric | Type | Description |
|--------|------|-------------|
| `persea_sessions_active` | gauge | Currently active sessions |
| `persea_sessions_total` | counter | Total sessions created |
| `persea_requests_total` | counter | Total HTTP requests |
| `persea_errors_total` | counter | Total 5xx responses |
| `persea_uptime_seconds` | gauge | Server uptime in seconds |

Because it is unauthenticated, do not expose `/metrics` to untrusted networks (scrape it via a reverse-proxy ACL or on the loopback interface).

## Quick Connect

### `GET /api/connect`

Quick-connect endpoint for external integrations (e.g., NetBox Custom Links). Creates a session and redirects to the client page. If the user is not authenticated and OIDC is configured, redirects to SSO login and back after authentication.

**Ad-hoc mode** (poweruser+):

    /api/connect?hostname=10.0.1.50&protocol=ssh

**Connections mode** (operator+):

    /api/connect?scope=shared&folder=production&entry=web-server-01

| Parameter | Type | Description |
|-----------|------|-------------|
| `protocol` | string | `ssh`, `rdp`, `vnc`, or `web` (default: ssh) |
| `hostname` | string | Target hostname or IP |
| `port` | integer | Target port (uses protocol default if omitted) |
| `username` | string | Username (optional) |
| `url` | string | Target URL (web sessions) |
| `scope` | string | Connections scope: `shared` or `instance` |
| `folder` | string | Connections folder name |
| `entry` | string | Connections entry name |
| `width` | integer | Display width in pixels |
| `height` | integer | Display height in pixels |
| `dpi` | integer | Display DPI |

When `scope`, `folder`, and `entry` are all provided, the endpoint connects via the connections (credentials from the [Vault or DB backend](configuration.md#storage-section)). Otherwise it creates an ad-hoc session. No credentials are passed in the URL for ad-hoc mode. If the target requires authentication, the user will see guacd's login prompt.

If the connections entry has `prompt_credentials: true` or has no stored password/key, the endpoint returns an inline credential form instead of creating the session immediately. The user enters credentials, which are POSTed to the connect endpoint and used for that session only (never stored).

See [NetBox Integration](netbox.md) for usage with NetBox Custom Links.

## Sessions

### `POST /api/sessions`

Create a new session. Requires **poweruser** role or higher.

**SSH session (password):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "port": 22,
  "username": "root",
  "password": "secret"
}
```

**SSH session (ephemeral keypair):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "generate_keypair": true
}
```

The response includes the public key in the `banner_text` field. The SSH connection is deferred until the user clicks "Continue" on the banner page.

**SSH session (private key):**

```json
{
  "session_type": "ssh",
  "hostname": "10.0.0.1",
  "username": "root",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
}
```

**RDP session:**

```json
{
  "session_type": "rdp",
  "hostname": "10.0.0.1",
  "port": 3389,
  "username": "Administrator",
  "password": "secret",
  "ignore_cert": true,
  "domain": "EXAMPLE"
}
```

**RDP session with Kerberos NLA:**

```json
{
  "session_type": "rdp",
  "hostname": "fileserver.corp.example.com",
  "port": 3389,
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "secret",
  "domain": "CORP.EXAMPLE.COM",
  "security": "nla",
  "auth_pkg": "kerberos",
  "kdc_url": "https://dc.corp.example.com/KdcProxy"
}
```

**VNC session:**

```json
{
  "session_type": "vnc",
  "hostname": "10.0.0.1",
  "port": 5900,
  "password": "vnc-secret"
}
```

**Web browser session:**

```json
{
  "session_type": "web",
  "url": "https://example.com"
}
```

**Web session with autofill and domain restriction:**

```json
{
  "session_type": "web",
  "url": "https://www.saucedemo.com",
  "username": "standard_user",
  "password": "secret_sauce",
  "autofill": "[{\"url\":\"https://www.saucedemo.com\",\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}]",
  "allowed_domains": ["saucedemo.com"],
  "disable_copy": true
}
```

The `autofill` field is a JSON string containing an array of objects with `url`, `username`, and `password`. The placeholders `$USERNAME` and `$PASSWORD` are substituted with the session's credentials. Multiple entries support SSO redirect chains where credentials are needed on different domains.

**Session with multi-hop SSH tunnel (any type):**

```json
{
  "session_type": "rdp",
  "hostname": "10.10.10.1",
  "port": 3389,
  "username": "Administrator",
  "password": "secret",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    },
    {
      "hostname": "internal-gw.corp.local",
      "port": 22,
      "username": "gw-user",
      "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n..."
    }
  ]
}
```

**Web session with SSH tunnel:**

```json
{
  "session_type": "web",
  "url": "https://internal-app.corp.local:8443/dashboard",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    }
  ]
}
```

For web sessions, the tunnel forwards to the URL's host and port (inferred from the scheme: 80 for HTTP, 443 for HTTPS, or explicit port in the URL). The URL is rewritten to `{scheme}://127.0.0.1:{tunnel_port}{path}` for Chromium. HTTPS targets will show certificate warnings since the hostname changes.

The `jump_hosts` array defines an ordered chain of SSH bastion hops. Each hop connects through the previous hop's tunnel. The final hop forwards to the session target. Jump hosts are supported for all session types.

**Legacy single jump host fields** (`jump_host`, `jump_port`, `jump_username`, `jump_password`, `jump_private_key`) are still accepted for backward compatibility but `jump_hosts` takes precedence when both are provided.

**All session fields:**

| Field | Type | Used by | Description |
|-------|------|---------|-------------|
| `session_type` | string | All | `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, or `vdi` (required) |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port (defaults: SSH=22, RDP=3389, VNC=5900) |
| `username` | string | SSH, RDP | Username for authentication |
| `password` | string | SSH, RDP, VNC | Password (VNC uses this as the VNC password) |
| `private_key` | string | SSH | OpenSSH PEM private key |
| `generate_keypair` | boolean | SSH | Generate an ephemeral Ed25519 keypair |
| `url` | string | Web | Target URL for web browser session |
| `domain` | string | RDP | Windows domain |
| `security` | string | RDP | `tls`, `nla`, or `rdp` |
| `ignore_cert` | boolean | RDP | Ignore TLS certificate errors |
| `auth_pkg` | string | RDP | NLA auth package: `kerberos`, `ntlm`, or empty (negotiate) |
| `kdc_url` | string | RDP | Kerberos KDC or KDC Proxy URL |
| `kerberos_cache` | string | RDP | Path to Kerberos credential cache (advanced) |
| `color_depth` | integer | RDP | Color depth in bits (8, 16, 24, 32) |
| `enable_drive` | boolean | RDP, SSH | Enable file transfer / drive redirection |
| `disable_copy` | boolean | All | Disable clipboard copy (server → client) |
| `disable_paste` | boolean | All | Disable clipboard paste (client → server) |
| `autofill` | string | Web | JSON array of autofill credentials (see below) |
| `allowed_domains` | array | Web | Domain allowlist — browser can only reach these domains |
| `login_script` | string | Web | Login script filename (relative to `login_scripts_dir`) |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (see below) |
| `width` | integer | All | Display width in pixels |
| `height` | integer | All | Display height in pixels |
| `dpi` | integer | All | Display DPI |
| `banner` | string | All | Banner message shown before session starts |

**SPICE fields** (`session_type: spice`, direct connection to a SPICE server):

| Field | Type | Description |
|-------|------|-------------|
| `hostname` | string | SPICE server hostname or IP (required) |
| `port` | integer | SPICE port (default 5900) |
| `password` | string | SPICE password / ticket |
| `spice_tls` | boolean | Connect using TLS |
| `spice_tls_port` | integer | TLS port, when different from `port` |
| `spice_ca_cert` | string | PEM CA certificate for TLS verification |
| `spice_cert_subject` | string | Expected TLS certificate subject |
| `spice_proxy` | string | SPICE proxy URL, e.g. `http://host:3128` |
| `ignore_cert` | boolean | Accept any TLS certificate (insecure) |
| `color_depth` | integer | Color depth in bits |

**Proxmox VE console fields** (`session_type: proxmox`, SPICE brokered through the PVE API):

| Field | Type | Description |
|-------|------|-------------|
| `proxmox_url` | string | PVE API base URL including scheme and port, e.g. `https://pve.example.com:8006` (required) |
| `proxmox_vmid` | integer | VM id whose console to open (required) |
| `proxmox_node` | string | Cluster node hosting the VM. Optional: auto-resolved from the VM id (via `/cluster/resources`) when left blank |
| `proxmox_token_id` | string | API token id, formatted `user@realm!tokenname` |
| `proxmox_token_secret` | string | API token secret (the UUID half) |
| `proxmox_verify_tls` | boolean | Verify the PVE / SPICE-proxy TLS certificate (default false; PVE ships a self-signed cluster cert) |

The token needs `VM.Console` (and `VM.Audit` for node auto-detect) on the target VM. persea calls the PVE `spiceproxy` API at connect to fetch a one-time SPICE ticket, so nothing sensitive is stored beyond the token.

**Jump host object fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `hostname` | string | Yes | SSH bastion hostname |
| `port` | integer | No | SSH port (default: 22) |
| `username` | string | Yes | SSH username |
| `password` | string | No | SSH password |
| `private_key` | string | No | OpenSSH PEM private key |

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

- `client_url` opens the session in the built-in client (see [Connecting to a session](#connecting-to-a-session)).
- `ws_url` is the raw WebSocket endpoint for a custom client.
- `share_url` is present only when sharing is allowed; its `token` lets a second viewer **join** an active session (it is not owner access).

### `GET /api/sessions`

List all sessions. Requires **operator** role or higher.

### `GET /api/sessions/:id`

Get session details. Requires **operator** role or higher.

### `DELETE /api/sessions/:id`

Terminate a session. Requires **operator** role or higher. Non-admins can only delete their own sessions.

### `GET /api/sessions/:id/banner`

Get session banner text. Authenticates via share token (not credentials). Used for the ephemeral keypair banner display.

## Connecting to a session

Creating a session (`POST /api/sessions`) only opens the connection to the target; it does **not** display anything. A browser then attaches over a WebSocket to stream the session. The two connection roles (owner and join) are the most common source of integration confusion.

### Owner vs. join

- The **first** connection to a freshly created session is the **owner** connection. It requires an authenticated identity with the **operator** role or higher.
- A **share token** (`share_url`) only lets a second viewer **join** a session that is already active. It is not an identity and cannot open the owner connection.

If the owner connection is not authenticated, persea rejects the WebSocket with `403`, no browser attaches, and guacd eventually reports `User is not responding` (its timeout for a session whose client never arrived, roughly 15 seconds after creation). If you see `User is not responding`, the browser did not connect as an authenticated owner.

### Authenticating the owner connection

The built-in client (`client_url`) authenticates the owner WebSocket one of three ways:

1. **OIDC session cookie** — the user is logged into persea in that browser. Open `client_url` and the cookie authenticates.
2. **`sessionStorage.persea_api_key`** — the client exchanges the key for a single-use ticket before connecting.
3. **A ws-ticket in the URL** — `client_url?ticket=<ticket>`. Used for headless integrations (below).

### `POST /api/ws-ticket`

Exchange an API key or OIDC session for a **single-use, short-lived** WebSocket ticket. Requires an authenticated identity with **operator** role or higher.

```
POST /api/ws-ticket
Authorization: Bearer <api-key>
```

```json
{ "ticket": "wst_1a2b3c..." }
```

The ticket is valid for 30 seconds, may be used once, and inherits the caller's role. Present it on the WebSocket as `/ws/{id}?ticket=<ticket>`, or on the built-in client as `/client/{id}?ticket=<ticket>` (the page GET does not consume it; the WebSocket does).

### Headless API integration

When the browser has no persea login of its own (no OIDC cookie), a backend that holds an API key can still hand off a ready-to-open session without exposing that key to the browser:

1. `POST /api/sessions` (Bearer API key) to create the session.
2. `POST /api/ws-ticket` (Bearer API key) to mint a ticket.
3. Send the browser to `client_url?ticket=<ticket>` (i.e. `/client/{id}?ticket=wst_...`).

The single-use, 30-second ticket is safe to place in a URL; the durable API key never leaves the backend. Because guacd drops a session whose client has not attached within ~15 seconds, mint the ticket and open the browser promptly after creating the session (on a reload, mint a fresh ticket).

### Custom clients

To build your own client, open the WebSocket at `ws_url` with the `guacamole` sub-protocol and a `?ticket=<ticket>` query parameter, then speak the [Guacamole protocol](https://guacamole.apache.org/doc/gug/guacamole-protocol.html). This is the same endpoint the built-in client uses.

## Recordings

### `GET /api/recordings`

List all recording files. Requires **operator** role or higher.

### `GET /api/recordings/:name`

Serve a recording file for playback. Requires **operator** role or higher. Filename is validated against path traversal.

### `DELETE /api/recordings/:name`

Delete a recording file. Requires **admin** role.

## Users (admin only)

### `GET /api/users`

List all OIDC users.

### `PUT /api/users/:email/role`

Set a user's role.

```json
{
  "role": "poweruser"
}
```

Valid roles: `admin`, `poweruser`, `operator`, `viewer`.

### `DELETE /api/users/:email`

Delete a user.

### `POST /api/users/:email/disable`

Disable a user (blocks login).

### `POST /api/users/:email/enable`

Re-enable a disabled user.

### `DELETE /api/users/:email/sessions`

Force-logout a user by deleting all their auth sessions.

## Group-to-Role Mappings (admin only)

### `GET /api/admin/group-mappings`

List all group-to-role mappings.

### `POST /api/admin/group-mappings`

Create a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "poweruser"
}
```

Returns 409 Conflict if a mapping for the group already exists.

### `PUT /api/admin/group-mappings/:id`

Update a mapping.

```json
{
  "oidc_group": "engineering",
  "role": "admin"
}
```

### `DELETE /api/admin/group-mappings/:id`

Delete a mapping.

## Connections (Vault or DB backend)

### `GET /api/addressbook/folders`

List visible folders. Filtered by OIDC group membership (admins see all).

### `GET /api/addressbook/folders/:scope/:folder/entries`

List entries in a folder. Scope is `shared` or `instance`. Requires folder group access.

### `POST /api/addressbook/folders/:scope/:folder/entries/:entry/connect`

Create a session from an connections entry. Reads credentials (including jump host credentials) from the stored entry (Vault or DB backend) server-side and creates a session. Requires **operator** role and folder group access.

Optional body to override or supply credentials at connect time:

```json
{
  "username": "jdoe@CORP.EXAMPLE.COM",
  "password": "user-password",
  "domain": "CORP.EXAMPLE.COM",
  "banner": "Custom banner message",
  "width": 1920,
  "height": 1080,
  "dpi": 96
}
```

Prompted credentials are used for the current session only and are never stored. Jump host credentials always come from the Vault entry and cannot be overridden at connect time.

### `POST /api/addressbook/folders` (admin)

Create a folder.

```json
{
  "scope": "shared",
  "name": "production",
  "allowed_groups": ["engineering", "devops"],
  "description": "Production servers"
}
```

### `PUT /api/addressbook/folders/:scope/:folder` (admin)

Update folder configuration (allowed_groups, description).

### `DELETE /api/addressbook/folders/:scope/:folder` (admin)

Delete a folder and all its entries.

### `POST /api/addressbook/folders/:scope/:folder/entries` (admin)

Create a connection entry. The body includes a `name` field plus all entry fields:

```json
{
  "name": "prod-db",
  "type": "ssh",
  "hostname": "db.internal.example.com",
  "port": 22,
  "username": "admin",
  "password": "secret",
  "jump_hosts": [
    {
      "hostname": "bastion.example.com",
      "port": 22,
      "username": "jump-user",
      "password": "jump-pass"
    }
  ]
}
```

**Connections entry fields:**

| Field | Type | Used by | Description |
|-------|------|---------|-------------|
| `type` | string | All | `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, or `vdi` |
| `hostname` | string | SSH, RDP, VNC | Target hostname or IP |
| `port` | integer | SSH, RDP, VNC | Target port |
| `username` | string | SSH, RDP | Username |
| `password` | string | SSH, RDP, VNC | Password |
| `private_key` | string | SSH | OpenSSH PEM private key |
| `url` | string | Web | Target URL |
| `domain` | string | RDP | Windows domain |
| `security` | string | RDP | Security mode |
| `ignore_cert` | boolean | RDP | Ignore certificate errors |
| `auth_pkg` | string | RDP | NLA auth package |
| `kdc_url` | string | RDP | Kerberos KDC URL |
| `color_depth` | integer | RDP | Color depth |
| `enable_drive` | boolean | RDP, SSH | Enable file transfer |
| `disable_copy` | boolean | All | Disable clipboard copy (server → client) |
| `disable_paste` | boolean | All | Disable clipboard paste (client → server) |
| `autofill` | string | Web | JSON array of autofill credentials |
| `allowed_domains` | array | Web | Domain allowlist for the browser session |
| `login_script` | string | Web | Login script filename |
| `display_name` | string | All | Friendly display name (shown as banner) |
| `prompt_credentials` | boolean | All | Prompt user for credentials at connect time |
| `jump_hosts` | array | All | Multi-hop SSH tunnel chain (same format as session creation) |

For `spice` and `proxmox` entries, the `spice_*` and `proxmox_*` fields listed under [`POST /api/sessions`](#post-apisessions) apply here too. The `proxmox_token_secret` is write-only: it is never returned by the read endpoints (a `has_proxmox_token_secret` boolean indicates whether one is stored), and it is preserved on update when omitted.

### `PUT /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Update a connection entry. Uses read-modify-write: reads the existing entry from the storage backend (Vault or DB), merges incoming fields on top. Credentials (`password`, `private_key`) that are omitted from the request are preserved from the existing entry. Jump host credentials are merged per-hop by index.

### `DELETE /api/addressbook/folders/:scope/:folder/entries/:entry` (admin)

Delete a connection entry.

## User API Tokens (self-service)

User API tokens allow OIDC users to authenticate via API key for automation and scripting. Tokens inherit the user's identity and are subject to role restrictions.

### `POST /api/me/tokens`

Create a personal API token. Requires **poweruser** role or higher. Only available to OIDC-authenticated users (not API key admins).

```json
{
  "name": "my-ci-token",
  "max_role": "operator",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

- `name` — required, 1-100 characters, must be unique per user
- `max_role` — optional, caps the token's effective role (cannot exceed the user's current role)
- `expires_at` — optional, ISO 8601 timestamp

**Response:**

```json
{
  "id": 1,
  "name": "my-ci-token",
  "token": "rgu_a1b2c3d4e5f6...",
  "max_role": "operator",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

The `token` field is the plaintext token. It is only returned once at creation and cannot be retrieved again.

### `GET /api/me/tokens`

List your own tokens. Available to any OIDC user (operator+). Returns token metadata only (never the plaintext token).

### `DELETE /api/me/tokens/:id`

Revoke one of your own tokens. Requires **poweruser** role or higher. The token is immediately invalidated.

## User API Tokens (admin)

Admins can manage tokens for any user, including creating tokens for operators who cannot create their own.

### `POST /api/admin/user-tokens`

Create a token for any OIDC user. Requires **admin** role.

```json
{
  "email": "operator@example.com",
  "name": "operator-automation",
  "max_role": "operator",
  "expires_at": "2026-06-30T23:59:59Z"
}
```

Response is the same as `POST /api/me/tokens`.

### `GET /api/admin/user-tokens`

List all user tokens across all users. Requires **admin** role.

### `DELETE /api/admin/user-tokens/:id`

Revoke any user token. Requires **admin** role.

### `GET /api/admin/token-audit`

View the token audit log. Requires **admin** role.

**Query parameters:**

- `limit` — max entries to return (default: 200, max: 1000)
- `email` — filter by user email

Returns an array of audit events with fields: `created_at`, `user_email`, `token_name`, `action`, `ip_addr`, `details`.

## Authentication

### `GET /api/auth/status`

No authentication required. Returns whether OIDC is enabled and the site title.

```json
{
  "oidc_enabled": true,
  "site_title": "persea"
}
```

### `GET /api/me`

Returns current user info. Requires authentication.

```json
{
  "name": "User Name",
  "email": "user@example.com",
  "role": "operator",
  "groups": ["engineering"],
  "auth_type": "oidc",
  "vault_enabled": true,
  "vault_configured": true
}
```

### `GET /auth/login`

Redirects to OIDC provider for authentication.

### `GET /auth/callback`

OIDC callback endpoint. Handles token exchange, user creation/update, and session creation.

### `GET /auth/logout`

Clears the session cookie and deletes the auth session.
