# Configuration Reference

persea reads a TOML configuration file. All settings have sensible defaults and are optional.

```bash
persea --config /opt/persea/config.toml serve
```

See `config.example.toml` for a fully commented reference.

## Server settings

| Key | Default | Description |
|-----|---------|-------------|
| `listen_addr` | `127.0.0.1:8089` | Address and port to listen on |
| `guacd_addr` | `127.0.0.1:4822` | guacd TCP address |
| `recording_path` | `./recordings` | Session recording directory |
| `static_path` | `./static` | Static web files directory |
| `db_path` | `./persea.db` | SQLite database path (used when `db_url` is not set) |
| `db_url` | — | Multi-backend database URL: `postgres://...`, `mysql://...`, or `sqlite://...` (see [Multi-database backend](#multi-database-backend)) |
| `site_title` | `persea` | Browser tab and page header title |
| `max_sessions` | `500` | Maximum concurrent sessions (all types). 0 = unlimited |
| `max_sessions_per_user` | `50` | Maximum concurrent sessions per user. 0 = unlimited |

## Session timeouts

| Key | Default | Description |
|-----|---------|-------------|
| `session_pending_timeout_secs` | `60` | Seconds before pending sessions expire |
| `session_max_duration_secs` | `28800` (8h) | Maximum active session duration |
| `auth_session_ttl_secs` | `86400` (24h) | OIDC auth session cookie TTL |

## Browser session settings

| Key | Default | Description |
|-----|---------|-------------|
| `xvnc_path` | `Xvnc` | Path to Xvnc binary |
| `chromium_path` | `chromium` | Path to Chromium binary |
| `display_range_start` | `100` | First X display number |
| `display_range_end` | `199` | Last X display number |
| `cdp_port_range_start` | `9200` | First Chrome DevTools Protocol port (for login scripts) |
| `cdp_port_range_end` | `9299` | Last CDP port |
| `login_scripts_dir` | `/opt/persea/scripts` | Directory containing login scripts |
| `login_script_timeout_secs` | `120` | Maximum runtime for login scripts before they are killed |

## SSH session settings

| Key | Default | Description |
|-----|---------|-------------|
| `ssh_scrollback` | `10000` | SSH terminal scrollback lines |
| `ssh_tmux_detach` | `false` | When true, SSH sessions start under a tmux wrapper (`tmux attach-session -d \|\| tmux new-session`) instead of a plain shell. On reconnect, `-d` detaches any stale client a dead connection left attached, so the user never lands on a frozen tmux screen. Requires tmux on the remote host. |

## Connection allowlists

CIDR ranges controlling which hosts sessions can connect to. All default to localhost only.

**Important:** These are top-level TOML keys and must appear *before* any `[section]` header. Keys placed after a section header (e.g., `[tls]`) are scoped to that section and will be ignored.

| Key | Default | Description |
|-----|---------|-------------|
| `ssh_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed SSH targets |
| `rdp_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed RDP targets |
| `vnc_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed VNC targets |
| `web_allowed_networks` | `["127.0.0.0/8", "::1/128"]` | Allowed web session URL hosts |

## Trusted proxies

| Key | Default | Description |
|-----|---------|-------------|
| `trusted_proxies` | `[]` | CIDRs of reverse proxies whose X-Forwarded-For to trust |
| `rate_limit` | `false` | Enable API rate limiting. Not needed when behind a rate-limiting reverse proxy. |
| `session_history_retention_days` | `90` | Days to keep session history in the database. 0 = keep forever. |

## `[tls]` section

Configures TLS for the web server and/or the guacd connection. There is no `enabled` toggle, the presence of the relevant fields controls behaviour:

- **Server HTTPS**: Provide both `cert_path` and `key_path` to serve HTTPS. Omit them to serve plain HTTP (useful behind a TLS-terminating reverse proxy like Traefik/HAProxy).
- **guacd TLS**: Provide `guacd_cert_path` to connect to guacd over TLS. This is independent of server HTTPS.

All fields are optional. The `[tls]` section can contain any combination.

| Key | Description |
|-----|-------------|
| `cert_path` | HTTPS certificate path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `key_path` | HTTPS private key path (PEM). Both `cert_path` and `key_path` must be set for HTTPS. |
| `guacd_cert_path` | Trust certificate for guacd TLS connection (independent of server HTTPS) |

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

Enables OpenID Connect authentication. When configured, the web UI shows a login button. API key auth continues to work alongside OIDC.

| Key | Default | Description |
|-----|---------|-------------|
| `issuer_url` | — | OIDC provider issuer URL (required) |
| `client_id` | — | OIDC client ID (required) |
| `client_secret` | — | OIDC client secret (or use `OIDC_CLIENT_SECRET` env var) |
| `redirect_uri` | — | Redirect URI: `https://your-host/auth/callback` (required) |
| `default_role` | `operator` | Role assigned to new users on first login |
| `groups_claim` | `groups` | JWT claim name containing group memberships |
| `extra_scopes` | `[]` | Additional OIDC scopes to request |
| `ca_cert` | — | Path to CA certificate (PEM) for verifying the OIDC provider |
| `tls_skip_verify` | `false` | Skip TLS verification (debugging only — exposes secrets to MITM) |

**Note:** `issuer_url` must match the discovered issuer URI **exactly**, including default ports and trailing slashes. For example, `https://idp.example.com/` and `https://idp.example.com` may be treated as different issuers. Check your provider's `.well-known/openid-configuration` for the canonical value.

## `[auth]` section

Configures the pluggable authentication chain. Providers are tried in the order listed in `methods`. The first provider to succeed wins. An optional TOTP second factor can be layered on top.

| Key | Default | Description |
|-----|---------|-------------|
| `methods` | `["database"]` | Ordered list of primary auth methods. Available: `database`, `ldap`, `oidc`, `saml`, `radius`, `api_key` |
| `ldap` | — | LDAP provider config (see below) |
| `radius` | — | RADIUS provider config (see below) |
| `saml` | — | SAML provider config (see below) |
| `totp` | — | TOTP MFA second-factor config (see below) |

Example, LDAP primary with TOTP MFA:
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

LDAP/Active Directory authentication. Performs a bind+search to authenticate users and optionally resolve group memberships.

| Key | Default | Description |
|-----|---------|-------------|
| `url` | — | LDAP server URL, e.g. `ldap://ldap.example.com:389` or `ldaps://ldap.example.com:636` (required) |
| `bind_dn` | — | Service account bind DN, e.g. `cn=admin,dc=example,dc=com` (required) |
| `bind_password` | — | Service account password (required) |
| `user_search_base` | — | Base DN for user searches, e.g. `ou=users,dc=example,dc=com` (required) |
| `user_search_filter` | — | Search filter with `{}` as username placeholder, e.g. `(uid={})` or `(sAMAccountName={})` (required) |
| `group_search_base` | — | Base DN for group searches. If omitted, groups are not resolved |
| `group_search_filter` | — | Group search filter with `{}` as user DN placeholder, e.g. `(member={})` |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (for self-signed certs) |
| `starttls` | `false` | Use StartTLS instead of ldaps:// (connects on port 389, upgrades to TLS) |
| `connect_timeout_secs` | `10` | Connection timeout in seconds |
| `display_name_attr` | `cn` | LDAP attribute for the user's display name |
| `email_attr` | `mail` | LDAP attribute for the user's email |

## `[auth.radius]` section

RADIUS authentication (RFC 2865). Supports PAP, CHAP, and MSCHAPv2 protocols. Can operate as primary authenticator or MFA step.

| Key | Default | Description |
|-----|---------|-------------|
| `hostname` | — | RADIUS server hostname or IP (required) |
| `port` | `1812` | RADIUS server port |
| `shared_secret` | — | Shared secret for RADIUS communication (required) |
| `timeout_secs` | `5` | Request timeout in seconds |
| `retries` | `3` | Number of retries on timeout |
| `nas_identifier` | `persea` | NAS identifier string |
| `nas_ip` | — | NAS IP address (reported to RADIUS server) |
| `auth_protocol` | `pap` | Authentication protocol: `pap`, `chap`, or `mschapv2` |
| `mode` | `primary` | Provider mode: `primary` (first-factor) or `mfa` (second-factor) |

## `[auth.saml]` section

SAML 2.0 Service Provider authentication. Handles the full SP-side flow: metadata parsing, signed AuthnRequest, and SAMLResponse validation.

| Key | Default | Description |
|-----|---------|-------------|
| `idp_metadata_url` | — | URL of the IdP metadata endpoint (XML). Either this or `idp_metadata_file` is required |
| `idp_metadata_file` | — | Local path to IdP metadata XML file (alternative to URL) |
| `entity_id` | — | SP entity ID — must match what's registered at the IdP (required) |
| `acs_url` | — | Assertion Consumer Service URL — where the IdP POSTs the response (required) |
| `certificate` | — | Base64-encoded SP X.509 certificate (for signing AuthnRequests) |
| `private_key` | — | PEM-encoded SP private key (for signing AuthnRequests) |
| `groups_attribute` | — | SAML attribute name to extract group memberships from |
| `strict_mode` | `true` | When true, reject responses with missing or expired assertions |

## `[auth.totp]` section

TOTP (Time-based One-Time Password) MFA second factor. Users enroll via QR code scanning in authenticator apps (Google Authenticator, Authy, etc.). The TOTP provider is layered on top of the primary auth method.

| Key | Default | Description |
|-----|---------|-------------|
| `issuer` | `persea` | Issuer name shown in authenticator apps |
| `digits` | `6` | Number of TOTP digits |
| `period` | `30` | TOTP period in seconds |
| `skew` | `1` | Clock skew tolerance (how many periods ahead/behind to accept) |
| `enforcement` | `Off` | Enforcement policy: `Off` (optional), `AdminsOnly` (required for admin/poweruser), `All` (required for everyone) |

**Enforcement policies:**
- `Off`, TOTP enrollment is optional; users who have enrolled are verified
- `AdminsOnly`, TOTP is required for admin and poweruser roles
- `All`, TOTP is required for all users

## Multi-database backend

persea supports MySQL, PostgreSQL, and SQLite via SQLx. Set `db_url` in the config to use a multi-backend database:

```toml
# PostgreSQL
db_url = "postgres://user:password@localhost:5432/persea"

# MySQL
db_url = "mysql://user:password@localhost:3306/persea"

# SQLite via SQLx (alternative to the default rusqlite path)
db_url = "sqlite:///opt/persea/data/persea.db?mode=rwc"
```

When `db_url` is set, the SQLx pool is initialised alongside the existing rusqlite `Db`. The `db_path` setting is still used for the admin database (users, API keys, sessions, tokens).

**Note:** Migrations are per-backend. The schema DDL lives in `migrations/postgres/`, `migrations/mysql/`, and `migrations/sqlite/`.

## `[storage]` section

Controls credential encryption for DB-only mode (when not using Vault).

| Key | Default | Description |
|-----|---------|-------------|
| `encryption_key` | — | 64-character hex string (32 bytes) for AES-256-GCM encryption of credentials at rest in the database. Can also be set via the `PERSEA_STORAGE_KEY` environment variable |

When `encryption_key` is set, connection credentials stored in the database are encrypted with AES-256-GCM. Encrypted values are prefixed with `enc:v1:` for future key rotation support.

```toml
[storage]
encryption_key = "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344"
```

Or via environment variable:
```bash
PERSEA_STORAGE_KEY=aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344
```

## `[vsphere]` section

VMware vSphere integration for VM inventory and OS-aware protocol routing. Connects to vCenter via the vSphere REST API (vSphere 7.0.3+) to enumerate VMs and auto-detect the right Guacamole protocol (RDP/SSH/VNC) based on the guest OS identifier. See [integrations.md](integrations.md) for setup.

| Key | Default | Description |
|-----|---------|-------------|
| `vcenter_addr` | — | vCenter Server URL, e.g. `https://vcenter.example.com/sdk` (required) |
| `username` | — | vSphere username, e.g. `administrator@vsphere.local` (required) |
| `password_env` | `VSPHERE_PASSWORD` | Name of the environment variable holding the password (never stored in config) |
| `insecure` | `false` | Skip TLS certificate verification (dev/test only) |
| `refresh_interval_secs` | `300` | How often to refresh the VM inventory (seconds) |

Optional per-VM guest credential overrides (keyed by VM name or ID):

```toml
[vsphere]
vcenter_addr = "https://vcenter.example.com/sdk"
username = "administrator@vsphere.local"
# password from env: VSPHERE_PASSWORD

[vsphere.vm_credentials]
"web-server-01" = { username = "deploy", password_env = "WEB_DEPLOY_PASS" }
```

## `[vault]` section

Enables the Vault-backed connections. Requires `VAULT_SECRET_ID` environment variable.

| Key | Default | Description |
|-----|---------|-------------|
| `addr` | — | Vault server address (required) |
| `role_id` | — | AppRole role ID (required) |
| `mount` | `secret` | KV v2 mount path |
| `base_path` | `persea` | Base path under the mount |
| `namespace` | — | Vault Enterprise / OpenBao namespace |
| `instance_name` | — | Instance name for instance-scoped entries |
| `tls_skip_verify` | `false` | Skip TLS certificate verification (dev only) |
| `ca_cert` | — | Path to custom CA certificate (PEM) for verifying the Vault server |
| `client_cert` | — | Path to client certificate (PEM) for mTLS |
| `client_key` | — | Path to client private key (PEM) for mTLS (required if `client_cert` is set) |

### Multiple Vault backends (disaster recovery)

By default the single `[vault]` serves both the shared and instance (local)
address-book scopes. For DR across a fleet you can give each scope its own Vault
so that one being unreachable cannot take the other down with it. Add either or
both of the optional blocks below; each takes the same keys as `[vault]`.

| Block | Serves | Secret ID env var |
|-------|--------|-------------------|
| `[vault]` | Default/fallback for any scope without a dedicated backend; also the home of the LUKS key | `VAULT_SECRET_ID` |
| `[vault_shared]` | The `shared` scope | `VAULT_SHARED_SECRET_ID` |
| `[vault_local]` | The `instance` (local) scope | `VAULT_LOCAL_SECRET_ID` |

A bare `[vault]` with no overrides behaves exactly as a single-Vault deployment,
so nothing changes for existing installs. Each backend connects, retries, and
renews its token independently. If a dedicated backend is unreachable, that
scope is shown as temporarily unavailable in the Connections tree while the
other scopes keep working.

When `[vault_local]` is used, set its `instance_name` to the value the data was
originally stored under, so the `instance/<name>/` paths line up. Splitting an
existing single-Vault deployment is a one-time copy with the `vault-migrate`
subcommand (see the [migration guide](migration.md)).

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

| Key | Default | Description |
|-----|---------|-------------|
| `user_credentials_default_scope` | `local` | Where a new per-user credential variable is stored when more than one backend is configured: `local` (stays on this instance, survives a central outage) or `shared` (propagates fleet-wide). Ignored with a single Vault. |

## `[drive]` section

Enables file transfer for RDP (drive redirection) and SSH (SFTP).

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable drive/file transfer |
| `drive_path` | `./drives` | Base directory for per-session storage |
| `drive_name` | `Shared Drive` | Name shown in remote RDP session |
| `allow_download` | `true` | Allow file download from remote |
| `allow_upload` | `true` | Allow file upload to remote |
| `cleanup_on_close` | `true` | Delete session drive directory on disconnect |
| `retention_secs` | `0` | Delay before cleanup (0 = immediate) |
| `luks_device` | — | LUKS container file path |
| `luks_name` | `persea-drives` | Device-mapper name |
| `luks_key_path` | — | Vault KV path for LUKS encryption key |

## `[theme]` section

Customises the UI appearance, base preset, individual colours, and logo. All fields are optional. A minimal example:

```toml
[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

**See [themes.md](themes.md) for the full reference**: built-in preset list, every overridable field, the per-user picker, and how to author your own themes as `.toml` files under `<static_path>/themes/` (no recompile needed).

Place the logo file in the `static_path` directory (e.g. `/opt/persea/static/acme-logo.png`). In Docker, mount it as a volume:
```
-v /path/to/acme-logo.png:/opt/persea/static/acme-logo.png:ro
```

## `[recording]` section

Controls session recording behaviour and disk management.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `path` | string | `recording_path` | Path for recording files. Overrides the top-level `recording_path`. |
| `enabled` | bool | `true` | Whether recording is enabled globally. |
| `max_disk_percent` | integer | `80` | Delete oldest recordings when disk usage exceeds this percent. 0 = disabled. |
| `max_recordings` | integer | `0` | Keep at most this many recordings globally. 0 = unlimited. |
| `rotation_interval_secs` | integer | `300` | How often (seconds) to run the rotation check. |
| `typescript_path` | string | (unset) | Directory for SSH typescript (raw terminal text) files. Unset = disabled. See below. |
| `typescript_name` | string | `{connection}-{user}-{date}-{time}` | Filename template for typescripts. Tokens listed below. |
| `create_typescript_path` | bool | `false` | Ask guacd to create `typescript_path` if it does not exist. |

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
**typescript**: a plain-text log of the full terminal output, compatible
with the standard `script` / `scriptreplay` tools and trivially
greppable. This is aimed at audit and compliance (a human-readable record
of what was typed and seen on a switch or server).

Typescript recording is **per-connection opt-in and off by default**. Two
things are required: `typescript_path` must be set here (the global "where"),
and the individual connection entry must have **Enable typescript recording
for this session** ticked in its Recording Settings (Connections page, SSH
entries only). A connection with the box unticked, or any session that is not
SSH, writes no typescript. Ad-hoc SSH sessions from the Sessions page have no
entry and so never record a typescript.

The typescript is produced by guacd, so `typescript_path` must be writable by
the guacd process. On a standard install guacd runs as the same `persea`
user as the main service, so a path it owns just works; `create_typescript_path
= true` lets guacd create the directory. guacd writes two files per session,
`NAME` and `NAME.timing`.

When typescripts exist, the Recordings page shows a **SSH Typescripts**
section (poweruser+) listing each one with its name, size, and time. This
is **list-only by design**: the text content is never downloadable through
the web UI (a typescript can contain passwords typed at prompts or secrets
printed to screen), so a poweruser can confirm a session was recorded
while retrieving the actual log still requires direct access to the
persea host or storage.

```toml
[recording]
typescript_path = "/opt/persea/data/typescripts"
typescript_name = "{connection}-{user}-{date}-{time}"
create_typescript_path = true
```

**Filename tokens.** guacd does not template typescript names itself (it
uses the name verbatim and only appends a numeric suffix to avoid
overwriting an existing file). persea therefore expands its own tokens
in `typescript_name` before handing it over, so each file is identifiable:

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
names are always reduced to a safe basename with no path separators.
Unknown `{tokens}` are left untouched.

> **Note:** these are persea's own tokens, not guacd's, and they are
> unrelated to [credential variables](credential-variables.md) (which use
> `$name` syntax and apply only to connection-entry credential fields).
> guacd's own `${GUAC_*}` tokens are **not** interpreted for typescripts.

Keystroke logging in the *graphical* recording (guacd's
`recording-include-keys`, parseable by `guaclog`) is a separate mechanism
that depends on guacd-driven graphical recording, which persea does not
use (it records the proxied stream itself). It is therefore not wired up;
the typescript is the supported text-audit path.

#### Encryption at rest (LUKS)

Typescripts are written in plain text. For encryption at rest with no extra
infrastructure, point `typescript_path` at a subdirectory of the
LUKS-encrypted drive volume persea already manages (see the
[`[drive]` section](#drive-section)). persea opens and mounts that volume at
startup (key fetched from Vault) and unmounts it at shutdown, so the directory
is available whenever persea is running, and the files are encrypted on the
block device at rest (powered off, disk theft, block-device backups).

```toml
[drive]
drive_path = "/mnt/persea-drives"
luks_device = "/dev/disk/by-uuid/..."   # your LUKS volume
luks_key_path = "secret/persea/luks"  # Vault KV path holding the key

[recording]
typescript_path = "/mnt/persea-drives/typescripts"
create_typescript_path = true
```

This is the recommended way to protect typescripts at rest today. Note its
limits: while persea is running the volume is mounted, so the files are
plain text to anyone with host access (the same threat model as the drive
feature), and it is one key for the whole volume rather than per-connection.
Per-file, per-connection-key encryption is tracked as a separate feature
request, pending demand.

## `[vdi]` section

Enables VDI (Virtual Desktop Infrastructure) sessions using Docker containers. Each user gets an ephemeral Linux desktop in a Docker container, accessed via xrdp through guacd.

**Prerequisites:** Docker must be installed on the host and the `persea` user must be in the `docker` group. See [VDI Desktop Containers](vdi.md) for full setup.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable VDI sessions. |
| `docker_socket` | string | `/var/run/docker.sock` | Docker daemon socket path. |
| `default_cpu_limit` | float | `0` | Default CPU limit for containers (fractional cores, e.g. 2.0). 0 = no limit. |
| `default_memory_limit` | integer | `0` | Default memory limit in MB. 0 = no limit. |
| `ready_timeout_secs` | integer | `30` | Seconds to wait for xrdp to become ready in a new container. |
| `port_range_start` | integer | *(none)* | First localhost port Docker may bind VDI RDP to. Must be set with `port_range_end`. |
| `port_range_end` | integer | *(none)* | Last localhost port Docker may bind VDI RDP to. Must be set with `port_range_start`. |
| `container_hook_script` | string | *(none)* | Optional VDI container hook script. Called as `<script> up <port> <container_id> <container_name>` before readiness checks and `<script> down <port> <container_id> <container_name>` before removal. |
| `container_hook_timeout_secs` | integer | `10` | Seconds to wait for the VDI container hook script. |
| `idle_timeout_mins` | integer | `60` | Minutes a container persists after last session disconnect. 0 = remove immediately. |
| `allowed_images` | list | `[]` | Allowed Docker images (exact match). Empty = allow all. |
| `home_base` | string | *(none)* | Base directory for persistent user home dirs. Each user gets `{home_base}/{username}` mounted into the container. |

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

## Environment variables

| Variable | Description |
|----------|-------------|
| `OIDC_CLIENT_SECRET` | Override OIDC client secret from config file |
| `VAULT_SECRET_ID` | Vault AppRole secret ID for `[vault]` |
| `VAULT_SHARED_SECRET_ID` | Vault AppRole secret ID for `[vault_shared]` (only if configured) |
| `VAULT_LOCAL_SECRET_ID` | Vault AppRole secret ID for `[vault_local]` (only if configured) |
| `PERSEA_STORAGE_KEY` | 64-char hex encryption key for DB credential storage (alternative to `[storage].encryption_key`) |
| `VSPHERE_PASSWORD` | VMware vSphere password (alternative to `[vsphere].password_env`) |
| `RUST_LOG` | Log level (e.g., `info`, `debug`, `persea=debug`) |
| `RUST_LOG_FORMAT` | Log format: `text` (default) or `json` for JSON lines (structured logging). Equivalent to the `--log-format` CLI flag, which takes precedence. |

### Setting environment variables for systemd

The shipped systemd unit (`persea.service`) does not include an `EnvironmentFile` directive by default. To provide secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`, create a systemd drop-in override:

**1. Create the env file** with your secrets:

```bash
cat > /opt/persea/env <<'EOF'
VAULT_SECRET_ID=your-vault-secret-id
OIDC_CLIENT_SECRET=your-oidc-client-secret
EOF
chmod 600 /opt/persea/env
chown persea:persea /opt/persea/env
```

**2. Create a systemd override** to load the env file:

```bash
sudo systemctl edit persea
```

This opens an editor. Add the following:

```ini
[Service]
EnvironmentFile=/opt/persea/env
```

Save and close. This creates a drop-in file at `/etc/systemd/system/persea.service.d/override.conf`.

**3. Reload and restart:**

```bash
sudo systemctl daemon-reload
sudo systemctl restart persea
```

The override persists across package upgrades, `dpkg` will not overwrite files in the `.d/` directory.

### Verifying the environment

To confirm the env file is loaded:

```bash
sudo systemctl show persea | grep EnvironmentFile
```

You should see:

```
EnvironmentFile=/opt/persea/env
```
