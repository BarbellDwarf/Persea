# Security Hardening

> **Audience:** operators and admins hardening a persea deployment.
> **Next:** [Roles and Access Control](roles-and-access-control.md) for the role and permission model.

This guide walks through persea's security features in the order you
should think about them: **what each one protects, how to turn it on,
and how to check it is actually working.** Everything here is on by
default or documented where it is not.

## TLS encryption

*What it protects:* the connection between browsers and persea (session
credentials, keystrokes, screen data) and the connection between persea
and guacd (the same data, on the backend leg).

### Browser-facing HTTPS

*How to enable:* set `cert_path` and `key_path` in the `[tls]` section.
persea then serves HTTPS using rustls, a modern, memory-safe TLS
implementation.

```toml
[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
```

Generate a certificate:

```bash
persea generate-cert --hostname your-hostname.example.com --out-dir /opt/persea/tls
```

The install script generates a self-signed certificate by default. If
you're behind a TLS-terminating reverse proxy (nginx, Caddy, Traefik,
HAProxy), omit `cert_path`/`key_path` and let persea serve plain HTTP
on loopback — see [Reverse Proxies](reverse-proxies.md).

*How to check:* browse to the site and confirm the padlock; or
`curl -skI https://your-host` and look for a successful TLS handshake.

### guacd TLS

*What it protects:* the connection between persea and guacd. Worth
encrypting when they talk over a network; on the same host it is less
critical.

*How to enable:* set `guacd_cert_path` — persea then connects to guacd
over TLS, trusting that certificate. This is independent of server
HTTPS (you can encrypt the guacd leg while a proxy handles the browser
leg), and guacd must be started with matching TLS flags:

```bash
guacd -b 127.0.0.1 -l 4822 -L info -f -C /opt/persea/tls/cert.pem -K /opt/persea/tls/key.pem
```

The install script configures both sides automatically.

### TLS certificate hot-reload

*What it protects:* you can rotate certificates without a service
restart, so short-lived certificates (Let's Encrypt) don't force
downtime.

*How to use:* replace the files, then send `SIGHUP` to the persea
process. It re-reads `tls.cert_path`/`tls.key_path`, validates the pair
(certificate parse, key parse, and key-matches-certificate), and
atomically swaps the served certificate for **new connections**;
existing connections keep their established session. If the new files
are invalid, persea logs the error and keeps serving the previous
certificate. There is no file watcher and no admin-UI upload — SIGHUP
is the only trigger.

## Cookies and the `Secure` attribute

*What it protects:* session hijacking. The login session cookie
(`persea_session`) is set with `HttpOnly; Secure; SameSite=Lax` — the
`HttpOnly` flag keeps page JavaScript from reading it, `Secure` keeps
it from being sent over plain HTTP, and `SameSite=Lax` stops it being
attached to cross-site requests.

*How to enable:* `Secure` is added automatically whenever persea
believes the connection is HTTPS — either persea's own TLS, or a
trusted proxy's `X-Forwarded-Proto: https` (see
[Reverse Proxies](reverse-proxies.md) for the `trusted_proxies`
requirement).

**The self-signed-cert caveat (important).** Browsers refuse to send
`Secure` cookies over a connection whose certificate is invalid —
*even after you click through the certificate warning*. So a
self-signed cert with `secure_cookies = true` (the default) breaks
login completely. If you serve a self-signed certificate, set:

```toml
[tls]
secure_cookies = false
```

`install.sh` and the Docker image set this automatically when they
generate their own self-signed cert; set it by hand if you supplied
your own cert. With a real CA-issued certificate, leave it `true`.

*How to check:* log in and inspect the cookie — in the browser dev
tools or:

```bash
curl -sk -D - -o /dev/null https://your-host/ | grep -i set-cookie
```

The session cookie should carry `HttpOnly; Secure; SameSite=Lax` (or
no `Secure` when `secure_cookies = false`).

## Authentication methods

*What it protects:* the front door. persea supports a pluggable chain
of methods, tried in config order — first success wins — with an
optional TOTP second factor on top. See [Configuration](configuration.md#auth-section)
for the exact keys.

| Method | When you'd use it | Notes |
|--------|-------------------|-------|
| **Database** (local passwords) | Small installs without an identity provider | Argon2id hashing with OWASP-recommended parameters (46 MiB memory, 3 iterations); constant-time comparison; dummy-hash computation on unknown accounts to hinder username enumeration |
| **OIDC** | Single sign-on with an existing IdP (Authentik, Keycloak, Okta, Azure AD, Google, ...) | PKCE and nonce validation on every login; 24 h session TTL by default (`auth_session_ttl_secs`) |
| **LDAP / AD** | Corporate directories | Bind+search; supports `ldaps://`, StartTLS, and group resolution |
| **RADIUS** | Organisations with an existing RADIUS server | PAP/CHAP/MSCHAPv2; can serve as first factor or MFA step |
| **SAML 2.0** | Enterprise single sign-on | Enterprise feature — see [Licensing](licensing.md) |
| **API key** | Scripts and integrations | See below |

### TOTP / MFA

*What it protects:* accounts whose password alone is not enough —
stolen or weak credentials can't log in without the second factor.

*How to enable:* configure the TOTP provider and pick an enforcement
policy:

```toml
[auth.totp]
issuer = "persea"
enforcement = "All"   # Off | AdminsOnly | All
```

Users enroll by scanning a QR code into an authenticator app (Google
Authenticator, Authy, ...). TOTP enforcement is an Enterprise feature
(see [Licensing](licensing.md)).

*How to check:* log out and log back in — you should be prompted for a
six-digit code.

## Account lockout

*What it protects:* brute-force password guessing.

*How it works (on by default):* failed authentication attempts are
tracked per user and source IP. After **5 failed attempts within a
rolling 15-minute window**, the account is locked: further attempts
are rejected while more than 5 recent failures remain. The counter
resets on successful authentication. Users are not told "N attempts
remaining" — the lockout counter is deliberately not exposed, so an
attacker can't tell a real account from a fake one.

*How to check:* deliberately enter a wrong password 5 times; the 6th
attempt (even with the right password) is rejected until failures age
out of the window.

## API keys and user tokens

*What they protect:* programmatic access. Two kinds exist:

- **Admin API keys** — created in the admin UI. 256-bit random values
  stored as SHA-256 hashes; the plaintext is shown once at creation.
- **User API tokens** — self-service tokens for OIDC users
  (`rgu_`-prefixed, 60 hex chars, also stored as SHA-256 hashes).
  The `rgu_` prefix lets secret scanners recognise a leaked token. The
  effective role is always `min(user_role, token_max_role)`, so a
  demoted user's tokens lose power immediately, and tokens are
  cascade-deleted when the user is removed.

*How to enable / harden:*

- **IP allowlists and expiry** are set per key/token at creation: a
  key can be restricted to CIDR ranges and given an ISO 8601 expiry.
  Use both for anything long-lived.
- **Kill switch:** an admin can disable API-key authentication entirely
  via the `enable_api_keys` system setting (Admin → Settings). With it
  off, a request presenting only an API key is rejected outright.
- **Rotate early:** expired tokens are purged hourly by a background
  task; revocation is immediate (the hash is deleted).

*How to check:* `GET /api/admin/token-audit` (admin) shows the token
audit trail — creation, revocation, and use events with IP addresses,
retained for 90 days.

## CSRF protection

*What it protects:* cross-site request forgery — a malicious page
tricking a logged-in browser into performing state-changing requests
against persea.

*How it works (on by default):* all state-changing requests (POST,
PUT, DELETE, PATCH) must carry an `X-CSRF-Token` header that exactly
matches the `csrf_token` cookie (the "double-submit" pattern). Every
response sets a fresh `csrf_token` cookie; it is deliberately **not**
`HttpOnly`, so page JavaScript can read it and echo it back — the web
UI's htmx and `fetch()` calls do this automatically. A mismatch
returns `403` with `{"error": "CSRF token missing or invalid"}`.

*For API scripts:* make one request to learn the cookie, then send it
back — see the curl workflow in [API Reference](api.md#csrf-requirement).

*How to check:* send a POST without the header and confirm the 403.

## Rate limiting

*What it protects:* brute force and resource exhaustion.

*How it works:* per-IP limits using the resolved client IP (honouring
`trusted_proxies`):

| Endpoint group | Rate | Burst | Active when |
|---------------|------|-------|-------------|
| API routes | 20/sec | 100 | `rate_limit = true` |
| Session creation | 2/sec | 10 | `rate_limit = true` |
| WebSocket connections | 5/sec | 50 | **always** |

The API and session-creation limits are off by default
(`rate_limit = false`) because behind a rate-limiting reverse proxy or
access gateway (HAProxy, Knocknoc) limiting is done upstream. The
WebSocket limit is unconditional — bursts of reconnects (or many users
behind one NAT) can still be throttled with a 429.

## Security headers

*What they protect:* browser-level attacks — cross-site scripting
(XSS), clickjacking, MIME-sniffing, and downgrade attacks.

*How it works (on by default):* every response carries:

| Header | Value |
|--------|-------|
| Content-Security-Policy | `default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self' 'unsafe-inline'; connect-src 'self' wss: ws:; img-src 'self' data: https:; font-src 'self'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Strict-Transport-Security | `max-age=31536000; includeSubDomains` (when TLS enabled) |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| Permissions-Policy | `camera=(), microphone=(), geolocation=()` |

Every page gets a fresh per-request CSP nonce, and inline scripts in
the UI carry it (`nonce="{csp_nonce}"`), so an attacker who manages to
inject a `<script>` tag can't run it — their script lacks the nonce.
Inline styles are allowed intentionally, for enterprise compatibility.

*How to check:* `curl -skI https://your-host/` and look for the
headers above.

## Network allowlists (SSRF protection)

*What it protects:* "server-side request forgery" — a user tricking the
server into connecting to hosts it shouldn't, such as internal
infrastructure the browser itself can't reach.

*How it works (on by default):* session targets are validated against
CIDR allowlists before any connection is made. Hostnames are resolved
and **every** returned IP must match at least one allowed range.

| Key | Default |
|-----|---------|
| `ssh_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` |
| `rdp_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` |
| `vnc_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` |
| `web_allowed_networks` | `["127.0.0.0/8", "::1/128"]` |

SSH/RDP/VNC can reach private networks plus loopback out of the box;
web browser sessions are loopback-only by default. Tighten these to
exactly what your users need:

```toml
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8"]
```

Web browser sessions have a second, complementary control: the
per-entry `allowed_domains` list restricts which domains Chromium can
resolve at runtime (`example.com` also allows `*.example.com`). The
server-side CIDR list controls what persea will connect to at session
creation; the browser-side list controls what the user can navigate to
inside the session. Both can be active at once.

## Audit log (tamper-evident hash chain)

*What it protects:* accountability. Security-relevant events —
authentication failures, session creation/termination, WebSocket
connect/disconnect, admin operations — are written to an audit log
with the client IP. If someone alters a record, the log proves it.

*How it works:* persea maintains a SHA-256 hash chain. Each event
includes a hash of the previous event, computed from canonical JSON of
all fields; altering any record breaks the chain at that point and
flags it plus every subsequent event.

*How to check:* two ways.

1. **Admin UI** — Admin → Audit shows the log and a chain-verification
   result:
   ```
   Chain status: Verified
   Events scanned: 1,234
   Errors: 0
   ```
   Or on tamper detection:
   ```
   Chain status: Broken
   Errors:
     Event #234: hash mismatch (expected abc123, got def456)
     Event #235: prev_hash mismatch (expected def456, got ...)
   ```
2. **API** — `GET /api/audit/verify` (admin) returns the same verdict
   as JSON, which makes it easy to script nightly verification.

Compliance exports (filtered CSV/JSON download of the audit log) are an
Enterprise feature gated by the license — basic viewing and tamper
verification stay free. See [Licensing](licensing.md).

## Credential storage

*What it protects:* stored secrets — connection passwords, SSH private
keys, API keys.

| Credential | How it is protected |
|------------|---------------------|
| Address-book credentials (DB backend) | AES-256-GCM encrypted at rest with `[storage].encryption_key` (or `PERSEA_STORAGE_KEY`); encrypted values carry an `enc:v1:` prefix. Unencrypted if no key is set — set one. |
| Address-book credentials (Vault backend) | Stored in Vault/OpenBao KV v2; the server reads them at connect time and they never reach the browser. |
| Admin API keys / user tokens | Only SHA-256 hashes stored; plaintext shown once at creation. |
| OIDC client secret | `OIDC_CLIENT_SECRET` environment variable keeps it out of the config file. |
| LUKS drive key | Stored in Vault, passed to cryptsetup via stdin — never on the command line or disk. |
| Ephemeral SSH keys | Exist only in memory during the guacd handshake; never stored or returned by the API. |

*How to check:* `[storage] encryption_key` set, Vault reachable, and —
for a spot audit — `GET /api/audit/verify` and the token audit log.

## Password policy

*What it protects:* the weakest passwords in your database-accounts.

*How it works (on by default):* Argon2id hashing with OWASP-recommended
parameters (46 MiB memory, 3 iterations, parallelism 1, 32-byte
output, PHC-encoded), a **15-character minimum** (`[password]
min_length`), and reuse prevention: the last 5 password hashes per user
are kept (`[password] history`), and reusing one is rejected. Policy is
enforced wherever a password is set: the admin users API, the CLI
`create-user` command, and the account password-change endpoint.
Passwords are never logged or included in error messages.

## Enterprise license gates

*What they protect:* enterprise features — SAML SSO, fine-grained RBAC,
TOTP/MFA enforcement, audit-log compliance exports, encrypted session
recording, and high availability — are locked behind the commercial
license key (or the 30-day evaluation period). Without a license, the
UI shows these features as **Locked** and their endpoints refuse with a
license error. See [Licensing](licensing.md) for the full picture.

## File permissions

*What it protects:* recorded sessions, transferred files and TLS keys
on disk.

| Path | Mode | Owner |
|------|------|-------|
| Drive directories | 0750 (rwxr-x---) | persea:persea |
| LUKS device file | 0600 (rw-------) | persea:persea |
| Recording files | 0640 (rw-r-----) | persea:persea |
| Recording directory | 0750 (rwxr-x---) | persea:persea |
| TLS private key | 0600 (rw-------) | persea:persea |

## Hardening built into the web layer

These are on by default and need no configuration:

- **SQL injection** — all queries use parameterised statements; no
  string concatenation in SQL.
- **Path traversal** — recording file access validates filenames
  (blocks `/`, `\`, `..`); address-book entry/folder names are
  restricted to alphanumerics, hyphens, underscores and dots (1–64
  chars).
- **XSS** — the UI builds user content with DOM APIs
  (`createElement`, `textContent`, ...) rather than `innerHTML`, on top
  of the CSP header.
- **Body size limits** — request bodies capped at 64 KB (4 MB for
  address-book CSV import, 2 MB for logo upload).
- **WebSocket Origin check** — upgrades are rejected when the `Origin`
  header doesn't match the `Host` (or when it is missing), preventing
  cross-site WebSocket hijacking.
- **Session hygiene** — pending sessions (no browser attached) expire
  after 60 s; active sessions are terminated after 8 h
  (`session_max_duration_secs`); non-admins can only terminate their
  own sessions; share links are time-limited join-only tokens.

## Session-level controls

- **Clipboard control:** copy (server → client) and paste (client →
  server) can be disabled independently per connection entry —
  `disable_copy`/`disable_paste` — useful for data-loss prevention and
  for stopping users pasting malicious content into remote sessions.
- **Web browser sessions** get extra hardening: a managed Chromium
  policy (installed at `/etc/chromium/policies/managed/persea.json`)
  that blocks downloads, printing, file dialogs, extensions, sign-in
  and sync; per-entry domain allowlisting; a fresh, per-session
  Chromium profile (deleted when the session ends); and the normal
  Chromium sandbox. Note the policy is **global** — it affects all
  Chromium instances on that machine, so don't install persea on a
  machine where Chromium is used for normal browsing.
