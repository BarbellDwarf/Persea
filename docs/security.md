# Security

> **Audience:** operators and admins hardening a persea deployment.
> **Next:** [Roles and Access Control](roles-and-access-control.md) for the role and permission model.

## TLS encryption

### Client-facing HTTPS

When `cert_path` and `key_path` are set in the `[tls]` section, persea serves HTTPS using rustls, a modern, memory-safe TLS implementation. The install script generates a self-signed certificate by default.

```toml
[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
```

If you're behind a TLS-terminating reverse proxy (e.g. Traefik, HAProxy, nginx), you can omit `cert_path`/`key_path` and persea will serve plain HTTP.

Generate a certificate:

```bash
persea generate-cert --hostname your-hostname.example.com --out-dir /opt/persea/tls
```

### guacd TLS

The connection between persea and guacd can also be encrypted with TLS. When `guacd_cert_path` is set, persea connects to guacd over TLS, trusting the specified certificate. This is independent of server HTTPS. You can use guacd TLS without serving HTTPS yourself.

**Full HTTPS + guacd TLS:**
```toml
[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
guacd_cert_path = "/opt/persea/tls/cert.pem"
```

**HTTP server + guacd TLS** (behind a reverse proxy):
```toml
[tls]
guacd_cert_path = "/opt/persea/tls/guacd-cert.pem"
```

guacd must be started with matching TLS flags:

```bash
guacd -b 127.0.0.1 -l 4822 -L info -f -C /opt/persea/tls/cert.pem -K /opt/persea/tls/key.pem
```

The install script configures both sides automatically.

## Network allowlists (SSRF protection)

All session targets are validated against CIDR allowlists before connections are made. Hostnames are resolved and every returned IP must match at least one allowed CIDR range.

```toml
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
rdp_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
vnc_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
web_allowed_networks = ["127.0.0.0/8", "::1/128"]
```

**Default: localhost only**. All four default to `["127.0.0.0/8", "::1/128"]`, preventing SSRF attacks out of the box.

## Authentication

persea supports a pluggable authentication chain. Providers are tried in config order, and the first success wins. An optional TOTP second factor can be layered on top. See [Roles and Access Control](roles-and-access-control.md) for the full role system.

### API key authentication

- Keys are 256-bit random values (64 hex characters)
- Stored as SHA-256 hashes in SQLite. The plaintext key is only shown once at creation
- Supported in `Authorization: Bearer <key>`, `X-API-Key: <key>` headers, and `?key=<key>` query parameter (WebSocket fallback)
- Optional IP allowlist (comma-separated CIDR ranges)
- Optional expiry timestamp (ISO 8601)
- API key admins always have full admin-level access

### OIDC session authentication

- Session tokens are 256-bit random values, stored in SQLite with a TTL
- Cookie: `persea_session` with `HttpOnly`, `Secure` (when TLS enabled), `SameSite=Lax`
- Configurable TTL (default: 24 hours)
- PKCE and nonce validation on every login flow
- Works with any OIDC provider (Authentik, Keycloak, Okta, Azure AD, Google, etc.)

### LDAP authentication

- Bind+search against any LDAP/AD server
- Supports ldaps://, StartTLS, and configurable TLS verification
- Group resolution via memberOf or direct group search
- Configurable user attributes (display name, email)

### RADIUS authentication

- RFC 2865 compliant PAP, CHAP, and MSCHAPv2 protocols
- Configurable as primary authenticator or MFA step
- Access-Challenge handling for MFA flows
- UDP communication with configurable retries and timeout

### SAML 2.0 authentication

- Full SP-side SAML flow: metadata parsing, signed AuthnRequests, ACS callback validation
- Supports both URL-based and file-based IdP metadata
- Signature verification with configurable strict mode
- Group extraction from SAML attributes

### Database (local password) authentication

- Argon2id password hashing with OWASP-recommended parameters
- Constant-time hash comparison to prevent timing attacks
- User enumeration prevention via dummy hash computation on unknown accounts
- See [Password policies](#password-policies) below

### User API token authentication

User API tokens provide OIDC users with long-lived API credentials for automation and scripting, without sharing their OIDC session or admin API keys.

**Token format and storage:**

- Tokens are 60 hex characters with a `rgu_` prefix (e.g., `rgu_a1b2c3...`)
- Stored as SHA-256 hashes in SQLite. The plaintext token is shown once at creation and cannot be retrieved
- The `rgu_` prefix allows secret scanners and log monitoring tools to identify leaked tokens
- Token validation uses constant-time hash comparison (SHA-256 matching via SQLite query) to prevent timing attacks

**Effective role computation:**

When a user API token authenticates, the effective role is computed as `min(user_current_role, token_max_role)`. This means:
- If an admin demotes a user from poweruser to operator, all their existing tokens are immediately restricted to operator-level access
- The `max_role` cap on a token cannot grant more access than the user currently has
- Role evaluation happens at authentication time, not at token creation time

**Token lifecycle security:**

| Control | Implementation |
|---------|---------------|
| Creation | poweruser+ self-service; admin can create for any user |
| Revocation | immediate; hash deleted from database |
| Expiry | optional ISO 8601 timestamp, checked at authentication time |
| Disabled users | tokens for disabled users are automatically rejected |
| User deletion | all tokens cascade-deleted when user is removed |
| Cleanup | expired tokens are purged hourly by background task |

**Attack surface and mitigations:**

| Threat | Mitigation |
|--------|-----------|
| Token theft / leakage | `rgu_` prefix enables automated secret scanning; short token lifetime recommended; tokens can be revoked immediately |
| Privilege escalation via token | effective role is always `min(user_role, max_role)` — demoting the user restricts all their tokens |
| Brute-force token guessing | 240 bits of entropy (60 hex chars); rate limiting at 2 req/sec per IP |
| Token abuse after user offboarding | user deletion cascade-deletes all tokens; disabling a user blocks all their tokens |
| Lateral movement from stolen token | tokens inherit the user's identity — all actions are logged with the user's email and client IP |
| Audit evasion | all token create/revoke/use events are logged in `token_audit_log` with IP addresses |

**Audit logging:**

All token operations are recorded in a dedicated `token_audit_log` table:
- **created** — token creation (by self-service or admin), with max_role and expiry details
- **revoked** — token revocation (by owner or admin), logged with revoker identity
- **admin_revoked** — admin revocation of another user's token

Audit logs are retained for 90 days and cleaned up hourly. Admins can view the log via the Admin UI or `GET /api/admin/token-audit`.

## CSRF protection

All state-changing requests (POST, PUT, DELETE, PATCH) must carry an `X-CSRF-Token` header that exactly matches the `csrf_token` cookie (double-submit pattern, `src/csrf.rs`). GET/HEAD/OPTIONS are exempt.

- Every response sets a `csrf_token` cookie: `Path=/; SameSite=Lax` (plus `Secure` over HTTPS). It is deliberately **not** `HttpOnly`, so page JavaScript can read it and echo it back as `X-CSRF-Token` (htmx and `fetch()` are patched to do this automatically in `templates/base.html`)
- A mismatch or missing pair returns `403` with `{"error": "CSRF token missing or invalid"}`
- API clients must therefore make a first request to learn the cookie, then send it back — see the curl example in [Troubleshooting > CSRF 403 errors](troubleshooting.md#csrf-403-errors)

## Rate limiting

Per-IP rate limiting uses `tower_governor` with the resolved client IP (honoring `trusted_proxies` for X-Forwarded-For):

| Endpoint group | Rate | Burst | Active when |
|---------------|------|-------|-------------|
| API routes | 20/sec | 100 | `rate_limit = true` |
| Session creation | 2/sec | 10 | `rate_limit = true` |
| WebSocket connections | 5/sec | 50 | **always** |

The API and session-creation limits are off by default (`rate_limit = false`) — when behind a rate-limiting reverse proxy or access gateway (HAProxy, Knocknoc), limiting is typically done upstream. The WebSocket limit is unconditional and applies even with `rate_limit = false`, so bursts of reconnects (or many users behind one NAT) can still be throttled; the upgrade fails with 429.

## Security headers

All responses include the following headers:

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` (when TLS enabled) |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

## Audit logging

persea logs security-relevant events via the `tracing` framework:

- Authentication failures (API key, user token, OIDC, LDAP, RADIUS, SAML, database)
- Session creation, connection, and termination
- WebSocket connect/disconnect events
- Admin operations (user management, key rotation)
- Client IP addresses (resolved via trusted proxies)

Additionally, user API token operations are logged to a persistent `token_audit_log` database table (see [User API token authentication](#user-api-token-authentication) above). This provides a queryable audit trail for token creation, revocation, and usage. Logs are retained for 90 days.

### Hash chain audit logging

persea maintains a SHA-256 hash chain for audit events, providing tamper evidence. Each event includes a hash of the previous event, forming an append-only chain:

- Events include: event type, timestamp, user ID, source IP, outcome, details, and session ID
- Each event hash is computed from canonical JSON (sorted keys, no whitespace) of all fields plus the previous hash
- The hash chain is written on every audit event; verification tooling is not yet wired into a CLI command or UI
- A broken chain indicates tampering. The event at the break point and all subsequent events are flagged

**Verification result:**
```
Chain status: Verified
Events scanned: 1,234
Errors: 0
```

Or on tamper detection:
```
Chain status: Broken
Events scanned: 567
Errors:
  Event #234: hash mismatch (expected abc123, got def456)
  Event #235: prev_hash mismatch (expected def456, got ...)
```

## Password policies

Local database authentication uses Argon2id with OWASP-recommended parameters:

| Parameter | Value | Notes |
|-----------|-------|-------|
| Memory | 46 MiB | OWASP minimum recommendation |
| Iterations | 3 | Cost factor |
| Parallelism | 1 | Thread count |
| Output | 32 bytes | PHC-encoded hash string |

Passwords are stored as PHC-encoded Argon2id hashes containing all parameters. Verification uses the stored parameters, so there's no need to supply the same params at verify time.

**Additional password security:**
- Constant-time comparison prevents timing attacks
- User enumeration prevention: unknown usernames trigger a dummy hash computation
- No password complexity rules enforced server-side (recommended to enforce via IdP or policy)
- Passwords are never logged or included in error messages

## Account lockout

Failed authentication attempts are tracked per-user. After a configurable number of failed attempts, the account is temporarily locked with progressive delay:

| Failed attempts | Lockout duration |
|----------------|------------------|
| 5 | 30 seconds |
| 10 | 5 minutes |
| 15+ | 30 minutes |

Lockout state is per-user and resets on successful authentication. The lockout counter is not exposed to users (no "N attempts remaining" messages) to prevent enumeration.

## RBAC (Role-Based Access Control)

persea implements two layers of access control:

### System permissions

System-wide permissions not tied to specific objects:

| Permission | Description |
|-----------|-------------|
| `administer` | Full system administration |
| `create_session` | Create ad-hoc sessions |
| `create_connection` | Create new connections |
| `create_connection_group` | Create connection groups |
| `create_user_group` | Create user groups |
| `audit` | View and verify audit logs |

### Object permissions (connection-level)

Fine-grained permissions on individual connections and connection groups:

| Permission | Description |
|-----------|-------------|
| `read` | View connection details |
| `connect` | Create sessions from this connection |
| `update` | Modify connection settings |
| `delete` | Remove the connection |
| `administer` | Full control over the connection |

Permissions can be granted to users or groups directly on connections, or inherited from parent groups. Group membership is resolved from OIDC claims, LDAP, or SAML attributes.

See [Roles and Access Control](roles-and-access-control.md) for the full RBAC model.

## Session security

- **Pending timeout**: sessions that don't receive a WebSocket connection within 60 seconds (configurable) are automatically cleaned up
- **Maximum duration**: active sessions are terminated after 8 hours (configurable) to prevent abandoned sessions
- **Session ownership**: non-admin users can only terminate their own sessions
- **Share tokens**: read-only or collaborative access via time-limited share URLs

## Clipboard control

Clipboard copy (server → client) and paste (client → server) can be independently disabled per connections entry. This uses guacd's native `disable-copy` and `disable-paste` parameters, which work for all session types (SSH, RDP, VNC, and web browser sessions).

Use cases:
- **Disable copy**: prevents users from copying data out of sensitive sessions (data loss prevention)
- **Disable paste**: prevents users from pasting potentially malicious content into remote sessions
- **Disable both**: fully isolates the clipboard between the local browser and the remote session

## Web session hardening

Web browser sessions (headless Chromium on Xvnc) include several security layers:

### Chromium managed policy

A managed policy is installed at `/etc/chromium/policies/managed/persea.json` that restricts Chromium's capabilities. **This policy is global**. It affects all Chromium instances on the machine, not just persea sessions. Do not install persea on a machine where you want to use Chromium for normal browsing.

Policies applied:

| Policy | Value | Effect |
|--------|-------|--------|
| `AllowFileSelectionDialogs` | `false` | Blocks file open/save dialogs (prevents filesystem browsing) |
| `PasswordManagerEnabled` | `true` | Allows autofill to work |
| `ImportSavedPasswords` | `false` | Blocks password import UI (which exposes a file browser) |
| `DeveloperToolsAvailability` | `0` | DevTools/CDP allowed (needed for login scripts). Users can't access DevTools UI — `chrome://*` is in URLBlocklist. |
| `DownloadRestrictions` | `3` | Blocks all downloads |
| `PrintingEnabled` | `false` | Disables printing |
| `EditBookmarksEnabled` | `false` | Prevents bookmark editing |
| `BrowserSignin` | `0` | Disables browser sign-in |
| `SyncDisabled` | `true` | Disables Chrome Sync |
| `ExtensionInstallBlocklist` | `["*"]` | Blocks all extension installation |
| `URLBlocklist` | `file://*`, `chrome://*`, etc. | Blocks dangerous URL schemes |

### Per-entry domain allowlisting

Connections entries can specify an `allowed_domains` list. When set, Chromium can only reach those domains (plus localhost). All other domains are blocked via Chromium's `--host-rules` flag, which prevents DNS resolution for non-allowed hosts.

Subdomains are automatically included, so adding `example.com` allows `*.example.com` as well.

**Important:** The `allowed_domains` field restricts which domains the browser can reach. This is separate from the server-side `web_allowed_networks` CIDR allowlist, which controls which target hosts persea will connect to when creating sessions. Both can be active simultaneously:

- `web_allowed_networks` — server-side CIDR filter applied at session creation time (controls what the persea server is allowed to connect to)
- `allowed_domains` — client-side DNS restriction applied inside Chromium at runtime (controls what sites the user can navigate to within the browser session)

### Profile isolation

Each web session gets a unique Chromium profile directory (UUID-based path in `/tmp/`). The profile is created fresh before launch and deleted when the session ends. Credentials stored in the autofill database exist only for the duration of the session.

### Sandbox

Chromium runs with its normal sandbox enabled (via the SUID `chrome-sandbox` helper). The `--no-sandbox` flag is not used.

## TLS hot-reload

TLS certificates can be rotated without restarting persea:

- **File watcher**: inotify/kqueue monitors the certificate and key files for changes
- **SIGHUP**: send `SIGHUP` to the persea process to force immediate reload
- **Admin UI**: upload new certificates via the admin settings page

When a change is detected, persea reloads the certificate and key from disk and begins serving the new TLS configuration on subsequent connections. Existing connections are not interrupted.

## Multi-database encryption at rest

When using MySQL, PostgreSQL, or SQLite via `db_url`, connection credentials can be encrypted at rest using AES-256-GCM:

```toml
[storage]
encryption_key = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
```

Encrypted values are prefixed with `enc:v1:` for future key rotation support. The encryption key can also be provided via the `PERSEA_STORAGE_KEY` environment variable.

**What is encrypted:**
- Connection passwords
- SSH private keys
- Proxmox token secrets
- Any credential field marked as sensitive in connection entries

**What is not encrypted:**
- Connection hostnames, ports, and protocol settings
- User accounts and roles (stored in the admin database)
- Session recordings and audit logs

**Key management:**
- The encryption key is never logged or included in API responses
- Key rotation requires re-encrypting all stored credentials (a migration tool is provided)
- For maximum security, store the key in a secrets manager and pass via environment variable

## File permissions

| Path | Mode | Owner |
|------|------|-------|
| Drive directories | 0750 (rwxr-x---) | persea:persea |
| LUKS device file | 0600 (rw-------) | persea:persea |
| Recording files | 0640 (rw-r-----) | persea:persea |
| Recording directory | 0750 (rwxr-x---) | persea:persea |
| TLS private key | 0600 (rw-------) | persea:persea |

## SQL injection protection

All database queries use parameterised statements (rusqlite's `params!` macro for the SQLite admin database, SQLx bind parameters for the multi-backend pool). No string concatenation is used in SQL queries.

## Path traversal protection

Recording file access validates filenames to block path traversal (`/`, `\`, `..`). The Vault connections also validates entry and folder names (alphanumeric, hyphens, underscores, dots only; length 1-64).

## XSS protection

The web UI uses DOM API methods (`createElement`, `textContent`, `appendChild`) instead of `innerHTML` for user-supplied content. Combined with the CSP header, this prevents cross-site scripting.

## Body size limits

HTTP request bodies are limited to 64KB to prevent memory exhaustion attacks.

## Trusted proxy support

When `trusted_proxies` is configured, persea extracts the real client IP from the `X-Forwarded-For` header for connections originating from trusted proxy CIDRs. This ensures correct IP-based rate limiting and audit logging behind reverse proxies.

```toml
trusted_proxies = ["127.0.0.1/32"]
```

## Credential handling

- **Vault credentials**: connections entries are read server-side from Vault. Connection passwords and private keys are never sent to the browser.
- **DB credentials**: with the DB storage backend, credentials are AES-256-GCM encrypted at rest (`enc:v1:` prefix) with the key from `[storage].encryption_key` or `PERSEA_STORAGE_KEY`, and decrypted server-side at connect time. See [Multi-database encryption at rest](#multi-database-encryption-at-rest).
- **SSH tunnel credentials**: jump host passwords and private keys are stored alongside the connections entry (Vault or encrypted DB). They are read server-side when establishing the tunnel chain and are never sent to the browser. For ad-hoc sessions, jump host credentials are provided in the session creation request and exist only in memory during tunnel setup.
- **API keys**: only the SHA-256 hash is stored. The plaintext key is shown once at creation and cannot be retrieved.
- **User API tokens**: same SHA-256 hash storage as admin API keys. The `rgu_` prefix enables secret scanning. Plaintext shown once at creation only.
- **OIDC client secret**: can be provided via `OIDC_CLIENT_SECRET` environment variable instead of the config file.
- **LUKS encryption key**: stored in Vault, passed to cryptsetup via stdin (never on the command line or on disk).
- **Ephemeral SSH keys**: the private key exists only in memory during the guacd handshake. It is never stored on disk or returned by the API.
