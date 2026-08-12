# Configuration

> **Audience:** operators and admins configuring persea.
> **Next:** [Security](security-hardening.md) for hardening, or the [API Reference](api.md) for endpoints.

persea is configured with a TOML file. Every setting has a sensible
default, so a fresh install works with no configuration at all. This
document explains what each section controls and when you would change
it; `config.example.toml` in the repository root is the same reference
with full comments.

## How configuration is loaded: three layers

persea merges configuration from three sources, in order: the first
one wins:

1. **Built-in defaults.** Compiled into the binary. Everything in this
   document's tables under "Default" is a built-in default.
2. **The TOML file.** Pass one explicitly with `--config`, or place it
   at `/opt/persea/config.toml` (persea checks that path automatically).
   Values in the file override the built-in defaults.
3. **Environment variables.** Any config key can be set as an
   environment variable prefixed with `PERSEA_`. Section keys use a
   double underscore: `PERSEA_TLS__CERT_PATH` sets `[tls] cert_path`.
   Environment variables beat the config file, which makes them handy
   for secrets and for Docker/systemd deployments. A few variables
   don't follow this scheme (for example `OIDC_CLIENT_SECRET` and
   `VAULT_SECRET_ID`); they are listed in the
   [environment variables section](#environment-variables).

To run with a config file:

```bash
persea --config /opt/persea/config.toml serve
```

## Server settings

These control how persea listens on the network, where it stores its
data, and how it presents itself. Most installs only need `site_title`
(and possibly `db_url`, if you use a managed database instead of the
default SQLite file).

| Key | Default | What it controls |
|-----|---------|------------------|
| `listen_addr` | `127.0.0.1:8089` | Address and port persea listens on. Loopback only by default: intended for use behind a reverse proxy. Change to `0.0.0.0:8089` (or `0.0.0.0:443` with TLS) to expose persea directly. |
| `guacd_addr` | `127.0.0.1:4822` | TCP address of the guacd daemon, the component that translates SSH/RDP/VNC traffic. Change only if guacd runs on another host. |
| `static_path` | `./static` | Directory with the web UI's static files (CSS, JS, logos). |
| `db_path` | `./persea.db` | SQLite database file used when `db_url` is not set. Holds users, API keys, auth sessions, the address book, audit log and history. |
| `db_url` | *(unset)* | Use a managed database instead of the SQLite file: `postgres://...`, `mysql://...`, or `sqlite://...`. When set, ALL app data lives in that database (migrations run automatically at startup) and `db_path` is ignored. See [Multi-database backend](#multi-database-backend). |
| `site_title` | `Persea` | Title shown in the browser tab and page header. |
| `instance_id` | `<hostname>-<pid>` | Stable name for this instance in a multi-instance (HA) fleet; marks which instance owns each live session. Must be unique across the fleet; set a fixed value per host if you run HA (see [High Availability](high-availability.md)). |
| `ha_base_url` | *(unset)* | Public base URL of this instance (for example `https://persea-1.example.com`). The target of cross-instance join/shadow redirects in HA mode. See [High Availability](high-availability.md). |

## License key

persea ships in a free edition and an Enterprise edition. Enterprise
features are unlocked by a commercial license key, or by the built-in
30-day evaluation period. See [Licensing](licensing.md) for details.

| Key | Default | What it controls |
|-----|---------|------------------|
| `license_key` | *(unset)* | Commercial license key, format `PSEA-<base64>`. When absent, enterprise features are available during the 30-day evaluation period. |

```toml
license_key = "PSEA-XXXX-XXXX-XXXX-XXXX"
```

Or via environment variable:

```bash
PERSEA_LICENSE_KEY=PSEA-XXXX-XXXX-XXXX-XXXX
```

The license status is also visible in the admin UI (Admin → License,
`/admin/license.html`).

## Session limits and timeouts

These bound how many sessions can run and how long they may live. The
timeouts protect you from abandoned sessions burning resources: a
pending session that never receives a browser connection, an active
session nobody is touching, or a session that has simply run too long.

| Key | Default | What it controls |
|-----|---------|------------------|
| `max_sessions` | `500` | Maximum concurrent sessions of all types. `0` = unlimited. |
| `max_sessions_per_user` | `50` | Maximum concurrent sessions per user. `0` = unlimited. |
| `max_viewers` | `10` | Maximum viewers that may join a session via a share link. |
| `session_pending_timeout_secs` | `60` | How long a session that has not received a WebSocket connection survives before being cleaned up. |
| `session_idle_timeout_secs` | `1800` (30 min) | Sessions whose last client activity is older than this are terminated (recorded as `idle-timeout` in session history). Client keepalive pings do not count as activity. `0` = disable idle reaping (max duration still applies). |
| `session_max_duration_secs` | `28800` (8 h) | Maximum active session duration; longer sessions are terminated. `0` = disabled. |
| `auth_session_ttl_secs` | `86400` (24 h) | How long a login session (browser cookie) stays valid before the user must sign in again. |
| `session_cleanup_delay_secs` | `300` | How long finished sessions stay in memory before cleanup. Does not affect the session history stored in the database. |
| `session_history_retention_days` | `90` | How many days session history is kept in the database. `0` = keep forever. |
| `shutdown_timeout_secs` | `30` | Graceful shutdown window: after SIGTERM/SIGINT the server stops accepting new connections and waits this long for active sessions to drain before forcing exit. |

## Password policy

| Key | Default | What it controls |
|-----|---------|------------------|
| `[password] min_length` | `15` | Minimum password length, enforced wherever a password is set: the admin users API, the CLI `create-user` command, and the account password-change endpoint. |
| `[password] history` | `5` | How many recent password hashes are kept per user. A new password matching any of the last `history` passwords is rejected. `0` = disable reuse checking. |

```toml
[password]
min_length = 15
history = 5
```

## Connection allowlists (SSRF protection)

These CIDR ranges decide which hosts sessions are *allowed* to connect
to: SSH, RDP, and VNC targets are validated against the list before
any connection is attempted (hostnames are resolved and every returned
IP must match). They protect you against "server-side request forgery"
(SSRF): a user tricking the server into connecting to something it
shouldn't, such as internal infrastructure the browser itself could not
reach.

| Key | Default | What it controls |
|-----|---------|------------------|
| `ssh_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` | Allowed SSH session targets: private (RFC 1918) networks plus loopback. |
| `rdp_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` | Allowed RDP session targets: private networks plus loopback. |
| `vnc_allowed_networks` | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128"]` | Allowed VNC session targets: private networks plus loopback. |
| `web_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed hosts for web browser session URLs: loopback only by default. Use `["0.0.0.0/0", "::/0"]` to allow any host. |

To reach targets on other networks (for example a VPN range or a public
jump server), add the CIDR to the relevant list:

```toml
ssh_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "172.20.0.0/16"]
```

**Note:** these are top-level TOML keys and must appear *before* any
`[section]` header. Keys placed after a section header are scoped to
that section and silently ignored.

## Trusted proxies and rate limiting

If persea sits behind a reverse proxy (see [Reverse Proxies](reverse-proxies.md)),
the proxy is the one that sees the real client IP. `trusted_proxies`
tells persea which proxy addresses to trust for the `X-Forwarded-For`
header, so client IPs appear correctly in audit logs, session history
and rate-limit decisions. It also gates `X-Forwarded-Proto`, which
controls whether session cookies get the `Secure` attribute when persea
itself serves plain HTTP.

| Key | Default | What it controls |
|-----|---------|------------------|
| `trusted_proxies` | `[]` | CIDRs of reverse proxies whose `X-Forwarded-For`/`X-Forwarded-Proto` headers to trust. Usually `["127.0.0.1/32"]` for a same-host proxy. |
| `rate_limit` | `false` | Enable persea's own per-IP API rate limiting. Usually left off when a rate-limiting reverse proxy or access gateway (HAProxy, Knocknoc) sits in front. |

```toml
trusted_proxies = ["127.0.0.1/32"]
```

Without `trusted_proxies`, every request from behind the proxy looks
like it comes from the proxy's own IP, and a client-supplied
`X-Forwarded-Proto` header from an untrusted source is ignored, so
cookies may not get `Secure` even though the browser is on HTTPS.

## `[tls]` section

Controls TLS for the web server and/or for the connection to guacd.
There is no `enabled` switch; the presence of the fields controls the
behaviour:

- **Server HTTPS:** provide both `cert_path` and `key_path` and persea
  serves HTTPS itself. Omit them to serve plain HTTP (the usual setup
  behind a TLS-terminating reverse proxy). persea warns at startup when
  TLS is not configured at all, because credentials and session tokens
  would travel unencrypted.
- **guacd TLS:** provide `guacd_cert_path` and persea connects to guacd
  over TLS, trusting that certificate. Independent of server HTTPS,
  you can encrypt the guacd leg while a proxy handles the browser leg.

| Key | Default | What it controls |
|-----|---------|------------------|
| `cert_path` | *(unset)* | HTTPS certificate file (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `key_path` | *(unset)* | HTTPS private key file (PEM). |
| `guacd_cert_path` | *(unset)* | Certificate to trust for the guacd TLS connection. The same self-signed cert can serve both purposes. |
| `secure_cookies` | `true` | Whether session cookies carry the `Secure` attribute. Set to `false` when serving a **self-signed** certificate: browsers refuse to send `Secure` cookies over connections with invalid certificates, which breaks login even after you click through the certificate warning. `install.sh` and the Docker image set this automatically when they generate their own self-signed cert; set it by hand if you generated or supplied the cert yourself. Leave `true` for a real CA-issued certificate. |

Generate a self-signed certificate with:

```bash
persea generate-cert --hostname your-hostname.example.com --out-dir /opt/persea/tls
```

**Examples:**

HTTPS + guacd TLS (self-hosted):
```toml
[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
guacd_cert_path = "/opt/persea/tls/cert.pem"
```

HTTP server + guacd TLS (behind a reverse proxy):
```toml
[tls]
guacd_cert_path = "/opt/persea/tls/guacd-cert.pem"
```

HTTPS only (guacd on localhost, no TLS needed):
```toml
[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
```

## `[oidc]` section

OpenID Connect is the single sign-on path: users log in against an
existing identity provider (Authentik, Keycloak, Okta, Azure AD,
Google, ...) with a button on the login page. When OIDC is configured,
API key authentication continues to work alongside it.

| Key | Default | What it controls |
|-----|---------|------------------|
| `issuer_url` | *(required)* | Your provider's issuer URL. Must match the discovered issuer **exactly**, including default ports and trailing slashes: `https://idp.example.com/` and `https://idp.example.com` can be treated as different issuers. Check your provider's `.well-known/openid-configuration` for the canonical value. |
| `client_id` | *(required)* | OIDC client ID registered with the provider. |
| `client_secret` | *(required)* | OIDC client secret. Prefer the `OIDC_CLIENT_SECRET` environment variable over putting it in the config file. |
| `redirect_uri` | *(required)* | Where the provider sends users after login: `https://your-host/auth/callback`. |
| `default_role` | `operator` | Role assigned to new users on first login. Options: `admin`, `poweruser`, `operator`, `viewer`. |
| `groups_claim` | `groups` | Name of the JWT claim that carries group memberships. |
| `extra_scopes` | `[]` | Extra OIDC scopes to request beyond `openid/email/profile` (for example `["groups"]`). |
| `ca_cert` | *(unset)* | Path to a CA certificate (PEM) for verifying the provider: use when your IdP uses a private/internal CA not in the system trust store. |
| `tls_skip_verify` | `false` | Skip TLS verification for OIDC connections. Debugging only: exposes the client secret and tokens to man-in-the-middle attacks. |

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/persea/"
client_id = "your-client-id"
client_secret = "your-client-secret"   # or set OIDC_CLIENT_SECRET env var
redirect_uri = "https://your-host/auth/callback"
```

## `[auth]` section

The pluggable authentication chain. Providers are tried in the order
listed in `methods`; the first one that succeeds wins. An optional TOTP
second factor can be layered on top of any primary method.

| Key | Default | What it controls |
|-----|---------|------------------|
| `methods` | `["database"]` | Ordered list of primary auth methods. Available: `database`, `ldap`, `oidc`, `saml`, `radius`, `api_key`. |
| `ldap` | - | LDAP/Active Directory provider config (below). |
| `radius` | - | RADIUS provider config (below). |
| `saml` | - | SAML 2.0 provider config (below). |
| `totp` | - | TOTP MFA second factor config (below). |

Example, LDAP primary with TOTP MFA for everyone:
```toml
[auth]
methods = ["ldap", "database"]

[auth.ldap]
url = "ldaps://ldap.example.com:636"
bind_dn = "cn=binduser,dc=example,dc=com"
bind_password = "..."
user_search_base = "ou=users,dc=example,dc=com"
user_search_filter = "(uid={})"

[auth.totp]
issuer = "persea"
enforcement = "All"
```

## `[auth.ldap]` section

LDAP/Active Directory authentication. persea binds with a service
account, searches for the user, then verifies their password, and can
optionally resolve group memberships.

| Key | Default | What it controls |
|-----|---------|------------------|
| `url` | *(required)* | LDAP server URL, e.g. `ldap://ldap.example.com:389` or `ldaps://ldap.example.com:636`. |
| `bind_dn` | *(required)* | Service account DN used for the initial bind. |
| `bind_password` | *(required)* | Service account password. |
| `user_search_base` | *(required)* | Base DN under which users are searched, e.g. `ou=users,dc=example,dc=com`. |
| `user_search_filter` | *(required)* | Search filter with `{}` as the username placeholder, e.g. `(uid={})` or `(sAMAccountName={})`. |
| `group_search_base` | - | Base DN for group searches. If omitted, groups are not resolved (users get no group memberships). |
| `group_search_filter` | - | Group search filter with `{}` as the user DN placeholder, e.g. `(member={})`. |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (self-signed directory certs). |
| `starttls` | `false` | Use StartTLS instead of `ldaps://`: connect on port 389 and upgrade to TLS in-band. |
| `connect_timeout_secs` | `10` | Connection timeout in seconds. |
| `display_name_attr` | `cn` | LDAP attribute for the user's display name. |
| `email_attr` | `mail` | LDAP attribute for the user's email address. |

## `[auth.radius]` section

RADIUS authentication (RFC 2865), for organisations that already run a
RADIUS server (often for WiFi/VPN). Supports PAP, CHAP and MSCHAPv2,
and can act as the primary authenticator or as an MFA step.

| Key | Default | What it controls |
|-----|---------|------------------|
| `hostname` | *(required)* | RADIUS server hostname or IP. |
| `port` | `1812` | RADIUS server port. |
| `shared_secret` | *(required)* | Shared secret for RADIUS communication. |
| `timeout_secs` | `5` | Request timeout in seconds. |
| `retries` | `3` | Retries on timeout. |
| `nas_identifier` | `persea` | NAS identifier reported to the RADIUS server. |
| `nas_ip` | *(unset)* | NAS IP address reported to the RADIUS server. |
| `auth_protocol` | `pap` | Authentication protocol: `pap`, `chap`, or `mschapv2`. |
| `mode` | `primary` | Provider mode: `primary` (first factor) or `mfa` (second factor). |

## `[auth.saml]` section

SAML 2.0 single sign-on. persea acts as the Service Provider: it parses
the IdP's metadata, signs its authentication requests, and validates
the signed response. Enterprise feature (see [Licensing](licensing.md)).

| Key | Default | What it controls |
|-----|---------|------------------|
| `idp_metadata_url` | - | URL of the IdP metadata endpoint (XML). Either this or `idp_metadata_file` is required. |
| `idp_metadata_file` | - | Local path to the IdP metadata XML file (alternative to the URL). |
| `entity_id` | *(required)* | SP entity ID: must match what is registered at the IdP. |
| `acs_url` | *(required)* | Assertion Consumer Service URL: where the IdP POSTs the login response. |
| `certificate` | - | Base64-encoded SP X.509 certificate (for signing AuthnRequests). |
| `private_key` | - | PEM-encoded SP private key (for signing AuthnRequests). |
| `groups_attribute` | - | SAML attribute name to extract group memberships from. |
| `strict_mode` | `true` | When true, reject responses with missing or expired assertions. |

## `[auth.totp]` section

TOTP (time-based one-time password) MFA: users enroll by scanning a QR
code into an authenticator app (Google Authenticator, Authy, ...) and
then must enter a six-digit code at login. The TOTP provider layers on
top of the primary auth method. Enterprise feature when enforced (see
[Licensing](licensing.md)).

| Key | Default | What it controls |
|-----|---------|------------------|
| `issuer` | `persea` | Issuer name shown in authenticator apps. |
| `digits` | `6` | Number of TOTP digits. |
| `period` | `30` | TOTP period in seconds. |
| `skew` | `1` | Clock skew tolerance: how many periods ahead/behind to accept. |
| `enforcement` | `Off` | Enforcement policy: `Off` (optional), `AdminsOnly` (required for admin/poweruser), `All` (required for everyone). |

**Enforcement policies:**
- `Off`: enrollment optional; users who enrolled are verified.
- `AdminsOnly`: required for admin and poweruser roles.
- `All`: required for all users.

## Multi-database backend

By default persea stores everything in a single SQLite file. With
`db_url` you can instead use PostgreSQL or MySQL (or SQLite through a
different driver), needed for multi-instance high availability, and
nice-to-have for shared infrastructure:

```toml
# PostgreSQL
db_url = "postgres://user:password@localhost:5432/persea"

# MySQL
db_url = "mysql://user:password@localhost:3306/persea"

# SQLite via SQLx (alternative to the default rusqlite path)
db_url = "sqlite:///opt/persea/data/persea.db?mode=rwc"
```

When `db_url` is set, the database IS the store: users, auth sessions,
API keys, address book, audit, settings and history all live in the
configured backend, and the schema migrations run automatically at
startup (the database user needs CREATE/DDL privileges). `db_path` is
only used in legacy mode, when `db_url` is absent. Connection
parameters like TLS go in the URL, e.g.
`postgres://user:password@dbhost:5432/persea?sslmode=require`.

## `[storage]` section

Controls where address-book (connections) credentials live and how they
are encrypted.

| Key | Default | What it controls |
|-----|---------|------------------|
| `backend` | `db` | Storage backend: `db` (default) stores folder/entry metadata *and* credentials in the database; `vault` keeps credentials in Vault with metadata in the database. |
| `encryption_key` | *(unset)* | 64-character hex string (32 bytes) for AES-256-GCM encryption of credentials at rest in the database. Can also be set via the `PERSEA_STORAGE_KEY` environment variable. |

When `encryption_key` is set, stored connection credentials are
encrypted with AES-256-GCM. Encrypted values are prefixed with
`enc:v1:` so keys can be rotated in the future. Generate a key with
`openssl rand -hex 32`.

```toml
[storage]
backend = "db"
encryption_key = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
```

Or via environment variable:
```bash
PERSEA_STORAGE_KEY=aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344
```

## `[vault]` section

Optional external secrets store (HashiCorp Vault or OpenBao). Used when
`[storage] backend = "vault"`, for the LUKS drive key, and for multiple
Vault setups. With the default `db` backend, Vault is not required for
connections at all.

Credentials never reach the browser: persea reads them server-side and
creates sessions directly. Authentication uses AppRole; the secret ID
is provided via the `VAULT_SECRET_ID` environment variable.

| Key | Default | What it controls |
|-----|---------|------------------|
| `addr` | *(required)* | Vault server address. |
| `role_id` | *(required)* | AppRole role ID. |
| `mount` | `secret` | KV v2 mount path. |
| `base_path` | `persea` | Base path under the mount. |
| `namespace` | *(unset)* | Vault Enterprise / OpenBao namespace. |
| `instance_name` | *(unset)* | Instance name for instance-scoped entries. |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (dev only). |
| `ca_cert` | *(unset)* | Path to a custom CA certificate (PEM) for verifying the Vault server. |
| `client_cert` | *(unset)* | Path to a client certificate (PEM) for mTLS. |
| `client_key` | *(unset)* | Path to the client private key (PEM). Required if `client_cert` is set. |

```toml
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "persea"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Multiple Vault backends (disaster recovery)

By default the single `[vault]` serves both the shared and the
instance (local) address-book scopes. For disaster recovery across a
fleet you can give each scope its own Vault, so one being unreachable
cannot take the other down with it. Add either or both of the optional
blocks below; each takes the same keys as `[vault]`.

| Block | Serves | Secret ID env var |
|-------|--------|-------------------|
| `[vault]` | Default/fallback for any scope without a dedicated backend; also the home of the LUKS key | `VAULT_SECRET_ID` |
| `[vault_shared]` | The `shared` scope | `VAULT_SHARED_SECRET_ID` |
| `[vault_local]` | The `instance` (local) scope | `VAULT_LOCAL_SECRET_ID` |

A bare `[vault]` with no overrides behaves exactly like a single-Vault
deployment, so nothing changes for existing installs. Each backend
connects, retries and renews its token independently; if a dedicated
backend is unreachable, that scope shows as temporarily unavailable in
the Connections tree while the others keep working.

When `[vault_local]` is used, set its `instance_name` to the value the
data was originally stored under, so the `instance/<name>/` paths line
up. Splitting an existing single-Vault deployment is a one-time copy
with the `vault-migrate` subcommand (see the [migration guide](migration.md)).

```toml
# Primary/local Vault (always reachable on this instance)
[vault]
addr = "https://127.0.0.1:8200"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
instance_name = "dc1"

# Optional central Vault shared across the fleet
[vault_shared]
addr = "https://vault-central.example.com:8200"
role_id = "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy"
```

Related top-level setting:

| Key | Default | What it controls |
|-----|---------|------------------|
| `user_credentials_default_scope` | `local` | Where a new per-user credential variable is stored when more than one backend is configured: `local` (stays on this instance, survives a central outage) or `shared` (propagates fleet-wide). Ignored with a single Vault. |

## `[recording]` section

Controls session recording and automatic disk management. When
enabled, every session is recorded as a replayable Guacamole stream.
Rotation keeps disk usage in check by deleting the oldest recordings.

| Key | Type | Default | What it controls |
|-----|------|---------|------------------|
| `path` | string | `./recordings` | Directory for recording files. Overrides the legacy top-level `recording_path` key. |
| `enabled` | bool | `true` | Master switch for recording. |
| `max_disk_percent` | integer | `80` | When disk usage exceeds this percent, delete the oldest recordings. `0` = disabled. |
| `max_recordings` | integer | `1000` | Keep at most this many recordings globally. `0` = unlimited. |
| `rotation_interval_secs` | integer | `300` | How often (seconds) the rotation check runs. |
| `typescript_path` | string | *(unset)* | Directory for SSH typescript (raw terminal text) files. Unset = disabled. See below. |
| `typescript_name` | string | `{connection}-{user}-{date}-{time}` | Filename template for typescripts. Tokens listed below. |
| `create_typescript_path` | bool | `false` | Let guacd create `typescript_path` if it does not exist. |

```toml
[recording]
enabled = true
max_disk_percent = 80
max_recordings = 1000
rotation_interval_secs = 300
```

### SSH typescript recording

The graphical recording above captures the session as a replayable
Guacamole stream. For SSH sessions you can additionally write a
**typescript**: a plain-text log of the full terminal output,
compatible with the standard `script` / `scriptreplay` tools and
trivially greppable, aimed at audit and compliance (a human-readable
record of what was typed and seen on a switch or server).

Typescript recording is **per-connection opt-in and off by default**.
Two things are required: `typescript_path` must be set here (the global
"where"), and the individual connection entry must have **Enable
typescript recording for this session** ticked in its Recording
Settings (Connections page, SSH entries only). A connection with the
box unticked, or any session that is not SSH, writes no typescript.
Ad-hoc SSH sessions from the Sessions page have no entry and so never
record a typescript.

The typescript is produced by guacd, so `typescript_path` must be
writable by the guacd process. On a standard install guacd runs as the
same `persea` user as the main service, so a path it owns just works;
`create_typescript_path = true` lets guacd create the directory. guacd
writes two files per session: `NAME` and `NAME.timing`.

When typescripts exist, the Recordings page shows a **SSH Typescripts**
section (poweruser+) listing each one with its name, size and time.
This is **list-only by design**: the text content is never downloadable
through the web UI (a typescript can contain passwords typed at prompts
or secrets printed to screen), so a poweruser can confirm a session was
recorded while retrieving the actual log still requires direct access
to the persea host or storage.

```toml
[recording]
typescript_path = "/opt/persea/data/typescripts"
typescript_name = "{connection}-{user}-{date}-{time}"
create_typescript_path = true
```

**Filename tokens.** guacd does not template typescript names itself
(it uses the name verbatim and only appends a numeric suffix to avoid
overwriting an existing file), so persea expands its own tokens in
`typescript_name` before handing the name over:

| Token | Expands to |
|-------|-----------|
| `{user}` | Session username |
| `{connection}` | Address-book entry name (falls back to the hostname for ad-hoc sessions) |
| `{host}` | Target hostname |
| `{date}` | Connect date, UTC `YYYYMMDD` |
| `{time}` | Connect time, UTC `HHMMSS` |
| `{session}` | First 8 characters of the session id |

Substituted values are sanitised to `[A-Za-z0-9_-]` (everything else
becomes `-`), so usernames like `alice@example.com` and free-text entry
names always reduce to a safe basename with no path separators.
Unknown `{tokens}` are left untouched.

> **Note:** these are persea's own tokens, not guacd's, and they are
> unrelated to [credential variables](credential-variables.md) (which
> use `$name` syntax and apply only to connection-entry credential
> fields). guacd's own `${GUAC_*}` tokens are **not** interpreted for
> typescripts.

Keystroke logging inside the *graphical* recording (guacd's
`recording-include-keys`, parseable by `guaclog`) is a separate
mechanism that depends on guacd-driven graphical recording, which
persea does not use (it records the proxied stream itself). It is
therefore not wired up; the typescript is the supported text-audit
path.

#### Encryption at rest (LUKS)

Typescripts are written in plain text. For encryption at rest with no
extra infrastructure, point `typescript_path` at a subdirectory of the
LUKS-encrypted drive volume persea already manages (see the
[`[drive]` section](#drive-section)). persea opens and mounts that
volume at startup (key fetched from Vault) and unmounts it at shutdown,
so the directory is available whenever persea is running, and the files
are encrypted on the block device at rest (powered off, disk theft,
block-device backups).

```toml
[drive]
drive_path = "/mnt/persea-drives"
luks_device = "/dev/disk/by-uuid/..."   # your LUKS volume
luks_key_path = "secret/persea/luks"  # Vault KV path holding the key

[recording]
typescript_path = "/mnt/persea-drives/typescripts"
create_typescript_path = true
```

This is the recommended way to protect typescripts at rest today. Note
its limits: while persea is running the volume is mounted, so the files
are plain text to anyone with host access (the same threat model as the
drive feature), and it is one key for the whole volume rather than
per-connection.

## `[drive]` section

Enables file transfer in sessions: RDP drive redirection (a per-session
directory appears as a "Shared Drive" in the remote Windows session)
and SSH SFTP (files transfer directly between browser and target SSH
server; nothing is stored on the persea host for SSH).

| Key | Default | What it controls |
|-----|---------|------------------|
| `enabled` | `false` | Enable drive/file transfer. |
| `drive_path` | `./drives` | Base directory for per-session storage (RDP). |
| `drive_name` | `Shared Drive` | Name shown in the remote RDP session. |
| `allow_download` | `true` | Allow file download from the remote session. |
| `allow_upload` | `true` | Allow file upload to the remote session. |
| `cleanup_on_close` | `true` | Delete the session drive directory on disconnect. |
| `retention_secs` | `0` | Delay before cleanup (`0` = immediate). |
| `luks_device` | *(unset)* | LUKS container file path: encrypts the drive volume at rest. |
| `luks_name` | `persea-drives` | Device-mapper name. |
| `luks_key_path` | *(unset)* | Vault KV path for the LUKS encryption key. |

```toml
[drive]
enabled = true
drive_path = "/mnt/persea-drives"
drive_name = "Shared Drive"
allow_download = true
allow_upload = true
cleanup_on_close = true
retention_secs = 0
```

## `[rdp]` section

Defaults applied to every RDP session unless the address book entry (or
the ad-hoc connect request) overrides the same field.

| Key | Default | What it controls |
|-----|---------|------------------|
| `default_auth_pkg` | `ntlm` | NLA/CredSSP authentication package. `ntlm` is the default because Kerberos requires a KDC reachable via DNS (usually over TCP) and its failure mode is a silent hang. Set `kerberos` only if you run AD-integrated hosts with working Kerberos; `negotiate` means Kerberos-first with NTLM fallback and has the same silent-hang risk. |

```toml
[rdp]
default_auth_pkg = "ntlm"
```

## Browser session settings

Web browser sessions run a headless Chromium on a per-session Xvnc
virtual display, streamed to the user over VNC. These settings control
the process paths and the resource ranges: the defaults support up to
100 concurrent web sessions.

| Key | Default | What it controls |
|-----|---------|------------------|
| `xvnc_path` | `Xvnc` | Path to the Xvnc binary (from tigervnc-standalone-server). |
| `chromium_path` | `chromium` | Path to the Chromium binary. |
| `display_range_start` | `100` | First X display number (`:100` = port 6100). |
| `display_range_end` | `199` | Last X display number. |
| `cdp_port_range_start` | `9200` | First Chrome DevTools Protocol port (used for login scripts). |
| `cdp_port_range_end` | `9299` | Last CDP port. |
| `login_scripts_dir` | `/opt/persea/scripts` | Directory containing login scripts. |
| `login_script_timeout_secs` | `120` | Maximum runtime for a login script before it is killed. |

## SSH session settings

| Key | Default | What it controls |
|-----|---------|------------------|
| `ssh_scrollback` | `10000` | SSH terminal scrollback lines. |
| `ssh_tmux_detach` | `false` | When true, SSH sessions start under a tmux wrapper (`tmux attach-session -d \|\| tmux new-session`) instead of a plain shell. On reconnect, `-d` detaches any stale client a dead connection left attached, so the user never lands on a frozen tmux screen. Requires tmux on the remote host. |

## `[vdi]` section

Enables VDI (Virtual Desktop Infrastructure) sessions: each user gets
an ephemeral Linux desktop in a Docker container, accessed via xrdp
through guacd. Containers persist for `idle_timeout_mins` after
disconnect so users can reconnect quickly.

**Prerequisites:** Docker installed on the host, and the `persea` user
in the `docker` group. See [VDI Desktop Containers](vdi.md) for full
setup.

| Key | Type | Default | What it controls |
|-----|------|---------|------------------|
| `enabled` | bool | `false` | Enable VDI sessions. |
| `docker_socket` | string | `/var/run/docker.sock` | Docker daemon socket path. |
| `default_cpu_limit` | float | `0` | Default CPU limit for containers (fractional cores, e.g. `2.0`). `0` = no limit. |
| `default_memory_limit` | integer | `0` | Default memory limit in MB. `0` = no limit. |
| `ready_timeout_secs` | integer | `30` | Seconds to wait for xrdp to become ready in a new container. |
| `port_range_start` | integer | *(none)* | First localhost port Docker may bind VDI RDP to. Must be set together with `port_range_end`; unset, Docker picks any random port. |
| `port_range_end` | integer | *(none)* | Last localhost port Docker may bind VDI RDP to. |
| `container_hook_script` | string | *(none)* | Optional hook script, called as `<script> up <port> <container_id> <container_name>` before readiness checks and `<script> down <port> <container_id> <container_name>` before removal. |
| `container_hook_timeout_secs` | integer | `10` | Seconds to wait for the hook script. |
| `idle_timeout_mins` | integer | `60` | Minutes a container persists after the last session disconnect. `0` = remove immediately. |
| `allowed_images` | list | `[]` | Allowed Docker images (exact match). Empty = allow all. |
| `home_base` | string | *(none)* | Base directory for persistent user home dirs: each user gets `{home_base}/{username}` mounted as `/home/{username}` in the container. Unset = ephemeral home dirs. |

```toml
[vdi]
enabled = true
idle_timeout_mins = 60
# port_range_start = 39000
# port_range_end = 39999
# container_hook_script = "/opt/persea/vdi-container-hook.sh"
# container_hook_timeout_secs = 10
home_base = "/vdi-homes"
# allowed_images = ["myregistry/desktop:latest"]
```

## `[vsphere]` section

VMware vSphere integration: persea connects to vCenter via the vSphere
REST API (vSphere 7.0.3+) to list VMs and auto-detect the right
protocol (RDP for Windows, SSH for Linux, VNC otherwise) based on the
guest OS. See [integrations.md](integrations.md) for setup.

| Key | Default | What it controls |
|-----|---------|------------------|
| `vcenter_addr` | *(required)* | vCenter Server URL, e.g. `https://vcenter.example.com/sdk`. |
| `username` | *(required)* | vSphere username, e.g. `administrator@vsphere.local`. |
| `password_env` | `VSPHERE_PASSWORD` | Name of the environment variable holding the password (never stored in the config file). |
| `insecure` | `false` | Skip TLS certificate verification (dev/test only). |
| `refresh_interval_secs` | `300` | How often the VM inventory refreshes (seconds). |

Optional per-VM guest credential overrides (keyed by VM name or ID):

```toml
[vsphere]
vcenter_addr = "https://vcenter.example.com/sdk"
username = "administrator@vsphere.local"
# password from env: VSPHERE_PASSWORD

[vsphere.vm_credentials]
"web-server-01" = { username = "deploy", password_env = "WEB_DEPLOY_PASS" }
```

## `[theme]` section

Customises the web UI appearance: base preset, individual colours, and
logo. All fields are optional.

```toml
[theme]
preset = "aurora"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

Built-in presets: `aurora` (default), `dark`, `light`, `high-contrast`,
`terminal`, `nord`, `corporate`, `jaguar`. Every colour value is a CSS
colour string (hex, `rgb()`, `hsl()`, or named).

**See [themes.md](themes.md) for the full reference**: every
overridable field, the per-user theme picker, and how to author your
own themes as `.toml` files under `<static_path>/themes/` (no
recompile needed).

Place the logo file in the `static_path` directory (e.g.
`/opt/persea/static/acme-logo.png`). In Docker, mount it as a volume:
```
-v /path/to/acme-logo.png:/opt/persea/static/acme-logo.png:ro
```

## Environment variables

Every config key can also be set as an environment variable with the
`PERSEA_` prefix, nesting section keys with `__` (e.g.
`PERSEA_STORAGE__ENCRYPTION_KEY`, `PERSEA_TLS__CERT_PATH`,
`PERSEA_LISTEN_ADDR`). The table below lists the variables that do
**not** follow that scheme:

| Variable | What it does |
|----------|--------------|
| `OIDC_CLIENT_SECRET` | Overrides the OIDC client secret from the config file. |
| `VAULT_SECRET_ID` | Vault AppRole secret ID for `[vault]`. |
| `VAULT_SHARED_SECRET_ID` | Vault AppRole secret ID for `[vault_shared]` (only if configured). |
| `VAULT_LOCAL_SECRET_ID` | Vault AppRole secret ID for `[vault_local]` (only if configured). |
| `PERSEA_STORAGE_KEY` | 64-char hex encryption key for DB credential storage (alternative to `[storage].encryption_key`). |
| `PERSEA_LICENSE_KEY` | Commercial license key (alternative to the `license_key` config option). |
| `VSPHERE_PASSWORD` | VMware vSphere password: the default variable referenced by `[vsphere].password_env` (override the name with `password_env` if you prefer another variable). |
| `RUST_LOG` | Log level (e.g. `info`, `debug`, `persea=debug`). |
| `RUST_LOG_FORMAT` | Log format: `text` (default) or `json` for JSON lines (structured logging). Equivalent to the `--log-format` CLI flag, which takes precedence. |

### Setting environment variables for systemd

The shipped systemd unit (`persea.service`) already includes
`EnvironmentFile=-/opt/persea/env` (the `-` prefix means the file is
optional: the service starts even if it does not exist). To provide
secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`, just create
the env file:

**1. Create the env file** with your secrets:

```bash
cat > /opt/persea/env <<'EOF'
VAULT_SECRET_ID=your-vault-secret-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
EOF
chmod 600 /opt/persea/env
chown persea:persea /opt/persea/env
```

**2. Restart:**

```bash
sudo systemctl restart persea
```

No drop-in override is needed: the shipped unit loads
`/opt/persea/env` already. If you are using a custom unit or a Docker
deployment, load the file yourself (e.g. `-e` flags for Docker, or a
drop-in with `EnvironmentFile=/opt/persea/env`).

### Verifying the environment

To confirm the env file is loaded:

```bash
sudo systemctl show persea | grep EnvironmentFile
```

You should see:

```
EnvironmentFile=/opt/persea/env
```
