# CLAUDE.md — Project state for rustguac

## What this project is

rustguac is a lightweight Rust replacement for the Apache Guacamole Java webapp. It proxies the Guacamole protocol over WebSockets between web browsers and guacd (the C daemon from guacamole-server). Supports SSH, RDP, VNC, SPICE, Proxmox, VMware, web browser sessions (headless Chromium on Xvnc), and VDI desktop containers (Docker).

## Architecture

- **Rust binary** (`rustguac`) — axum web server, session manager, WebSocket proxy
- **guacd** — built from apache/guacamole-server source, handles SSH/VNC/RDP/SPICE protocol translation
- **Xvnc + Chromium** — spawned per web-browser session, streamed via VNC through guacd
- **Docker** — VDI containers spawned per-user, connected via RDP through guacd

## Key files

### Core
- `src/main.rs` — entry point, CLI (clap), server setup, route wiring
- `src/config.rs` — TOML config loading with defaults, AuthConfig struct
- `src/error.rs` — unified AppError enum with HTTP status mapping

### Auth system
- `src/auth.rs` — API key auth middleware (SHA-256, IP allowlists, expiry), role system, session cookie validation
- `src/auth_provider.rs` — AuthProvider trait, Capabilities bitflags, AuthResult, AuthRequest, UserInfo
- `src/auth_chain.rs` — AuthChain: priority-ordered provider chain with MFA support
- `src/auth_providers/` — Individual auth provider implementations:
  - `database.rs` — Local password auth (Argon2id)
  - `ldap.rs` — LDAP/AD bind+search auth
  - `saml.rs` — SAML 2.0 SP (quick-xml + ring signatures)
  - `radius.rs` — RADIUS PAP (UDP client, challenge/response)
  - `totp.rs` — TOTP MFA second factor
- `src/oidc.rs` — OIDC authentication (login, callback, logout, group extraction)
- `src/password.rs` — Argon2id hashing/verification (OWASP params)
- `src/totp.rs` — TOTP management (enrollment, QR codes, verification, recovery codes)
- `src/crypto.rs` — AES-256-GCM credential encryption

### Database
- `src/db.rs` — SQLite admin database (rusqlite), user/session/token/audit tables
- `src/db_pool.rs` — SQLx multi-backend pool (PostgreSQL/MySQL/SQLite), DbPool enum, dispatch macros
- `migrations/` — Per-backend schema DDL (15 tables)

### API
- `src/api/` — REST API endpoints:
  - `sessions.rs` — session CRUD, thumbnails, shadow tokens
  - `address_book.rs` — folder/entry management, connect
  - `users.rs` — user listing, role management, session management
  - `admin.rs` — system status, group mappings, token audit
  - `reports.rs` — session analytics, CSV export
- `src/handlers/` — Page handlers and new API endpoints:
  - `auth.rs` — login, MFA, SAML ACS/metadata handlers
  - `pages.rs` — connections, sessions, recordings page handlers
  - `account.rs` — profile, tokens, TOTP page handlers
  - `tunnels.rs` — jump host CRUD API
  - `rbac.rs` — RBAC group/permission management API

### Session management
- `src/session/` — session state machine:
  - `types.rs` — Session, SessionType, SessionStatus, activity tracking
  - `manager.rs` — SessionManager: storage, idle/max reaper, concurrent limits
  - `create.rs` — session creation, guacd handshake, protocol branching

### Enterprise features
- `src/audit.rs` — SHA-256 hash chain audit logging, tamper evidence
- `src/rbac.rs` — RBAC: system permissions + connection-level object permissions, recursive group CTE
- `src/db_migrate.rs` — Vault→DB migration tool (661 lines, BFS walk, encrypted credentials)

### Protocol
- `src/guacd.rs` — TCP connection to guacd, Guacamole protocol handshake
- `src/protocol.rs` — Guacamole wire format parser/encoder
- `src/websocket.rs` — WebSocket <-> guacd TCP bridge, recording tee

### Hypervisors
- `src/pve.rs` — Proxmox VE API (SPICE, VNC, LXC, serial, xterm.js, VM lifecycle)
- `src/vsphere.rs` — VMware vSphere REST API (VM inventory, OS detection, RDP/SSH routing)

### UI
- `templates/` — 19 HTML templates (minijinja + htmx + Tailwind CSS):
  - `base.html`, `layouts/app.html` — base layout with sidebar
  - `partials/sidebar.html`, `partials/header.html` — navigation components
  - `pages/login.html` — auth form + SSO buttons
  - `pages/connections.html` — 70/30 split folder tree + details
  - `pages/sessions.html` — active sessions table with auto-refresh
  - `pages/recordings.html` — recording playback
  - `pages/client.html` — Guacamole client with auto-hide toolbar
  - `pages/admin/` — users, auth providers, audit, settings, reports, tunnels
  - `pages/account/` — profile, tokens, TOTP enrollment
  - `pages/docs.html` — documentation viewer

### Other
- `src/browser.rs` — Xvnc + Chromium process lifecycle
- `src/vdi/mod.rs` + `src/vdi/docker.rs` — Docker VDI driver
- `src/vault.rs` — Vault/OpenBao KV v2 client
- `src/drive.rs` — LUKS file transfer
- `src/tunnel.rs` — SSH tunnel (russh)
- `src/recording.rs` — recording rotation
- `src/metrics.rs` — Prometheus metrics
- `src/templates.rs` — minijinja template rendering
- `dev.sh` — development script
- `install.sh` — bare-metal Debian 13 installer
- `Dockerfile` — multi-stage build

## Configuration

TOML config file. Key settings: `listen_addr`, `guacd_addr`, `db_url` (for MySQL/PostgreSQL), `recording_path`, `static_path`.

### Database backends

Supports MySQL, PostgreSQL, and SQLite via SQLx. Set `db_url` in config:

```toml
db_url = "postgres://user:pass@localhost/rustguac"  # or mysql://, sqlite://
```

Without `db_url`, uses SQLite with the `db_path` setting (legacy mode).

### Authentication

Configurable auth provider chain via `[auth]` section:

```toml
[auth]
methods = ["oidc", "ldap", "database"]  # priority order

[auth.ldap]
url = "ldaps://ldap.example.com:636"
bind_dn = "cn=binduser,dc=example,dc=com"
user_search_base = "ou=users,dc=example,dc=com"
user_search_filter = "(uid={username})"

[auth.radius]
hostname = "10.0.0.1"
auth_port = 1812

[auth.saml]
idp_metadata_url = "https://idp.example.com/metadata"
entity_id = "rustguac"
acs_url = "https://rustguac.example.com/auth/saml/acs"

[auth.totp]
issuer = "rustguac"
enforcement = "AdminsOnly"  # Off, AdminsOnly, All
```

Available methods: `oidc`, `ldap`, `database`, `api_key`, `radius`, `saml`, `totp`

### Vault / Connections (optional)

Optional `[vault]` section for credential storage. Without Vault, use DB-only mode:

```toml
[storage]
encryption_key = "aabbccdd..."  # 64-char hex, or RGUAC_STORAGE_KEY env var
```

Vault config (when using Vault):

```toml
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "rustguac"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### OIDC

```toml
[oidc]
issuer_url = "https://auth.example.com/realms/corp"
client_id = "rustguac"
redirect_uri = "https://rustguac.example.com/auth/callback"
groups_claim = "groups"
```

### Proxmox VE

```toml
[proxmox]
addr = "https://pve.example.com:8006"
username = "root@pam"
token_id = "rustguac"
token_secret = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### VMware vSphere

```toml
[vsphere]
enabled = true
vcenter_addr = "vcenter.example.com"
username = "administrator@vsphere.local"
# password from env: VSPHERE_PASSWORD
```

## Roles

4-tier hierarchy: `admin` (4) > `poweruser` (3) > `operator` (2) > `viewer` (1)

- **admin**: full access, user/connection/permission management
- **poweruser**: ad-hoc session creation + connections connect
- **operator**: connections connect only (no ad-hoc sessions)
- **viewer**: read-only

### RBAC (Connection-level permissions)

- System permissions: Administer, CreateSession, CreateConnection, Audit
- Object permissions: Read, Connect, Update, Delete, Administer (per connection/group)
- Recursive group inheritance via CTE

## Session types

- **SSH** — password, private key, ephemeral Ed25519 keypair
- **RDP** — Kerberos/NTLM NLA, RemoteApp, GFX pipeline, H.264
- **VNC** — password auth, multi-monitor
- **SPICE** — TLS, CA verification, SPICE proxy
- **Proxmox VE** — SPICE, VNC, LXC, serial, xterm.js, VM lifecycle
- **VMware** — vSphere inventory, OS detection, RDP/SSH routing
- **Web** — Xvnc + Chromium (optional, disabled by default)
- **VDI** — Docker containers with xrdp (optional, disabled by default)

## Enterprise features

- **Password policies**: Argon2id (NIST 800-63B), 15-char minimum, breach screening (HIBP), history tracking
- **Account lockout**: Progressive delay (30s → 5min → 30min) after 5 failed attempts
- **Audit logging**: SHA-256 hash chain with tamper evidence, CLI verification, admin UI verification
- **Session management**: Idle timeout, max duration, concurrent limits, activity tracking
- **RBAC**: System + object permissions, recursive group inheritance
- **TLS hot-reload**: File watcher (inotify/kqueue) + SIGHUP + admin UI upload
- **Multi-DB**: MySQL, PostgreSQL, SQLite via SQLx enum dispatch

## Deployment

- **Bare metal**: `sudo ./install.sh` on Debian 13
- **Docker**: `docker build -t rustguac .`
- **First run**: Setup wizard at `/setup` auto-detects environment

## Build notes

- guacd is built from `../guacamole-server` (apache/guacamole-server)
- Debian 13 ships freerdp3-dev. guacamole-server 1.6.1+ has FreeRDP 3 auto-detection.
- **Patches required:** See `patches/README.md` for FreeRDP 3.15+ fixes.
- SQLx: `cargo sqlx prepare` for offline compile-time checking (per-backend)

## Testing

- `cargo test` — unit tests + integration tests (144+ tests)
- `tests/auth_integration.rs` — auth flow integration tests
- `tests/test_browser_session.sh` — browser session smoke test
