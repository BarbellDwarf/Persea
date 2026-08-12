# AGENTS.md — Project state for persea

## What this project is

persea is a lightweight Rust replacement for the Apache Guacamole Java webapp. It proxies the Guacamole protocol over WebSockets between web browsers and guacd (the C daemon from guacamole-server). Supports SSH, RDP, VNC, SPICE, Proxmox, VMware, web browser sessions (headless Chromium on Xvnc), and VDI desktop containers (Docker).

## Architecture

- **Rust binary** (`persea`) — axum web server, session manager, WebSocket proxy
- **guacd** — built from apache/guacamole-server source, handles SSH/VNC/RDP/SPICE protocol translation
- **Xvnc + Chromium** — spawned per web-browser session, streamed via VNC through guacd
- **Docker** — VDI containers spawned per-user, connected via RDP through guacd

## Key files

### Core
- `src/main.rs` — entry point, CLI (clap), server setup, route wiring
- `src/config.rs` — config loading via the `config` crate (layered: defaults → TOML file → `PERSEA_` env vars)
- `src/error.rs` — unified AppError enum with HTTP status mapping, HTML/JSON error rendering split
- `src/templates.rs` — minijinja template rendering, error page template

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
- `src/csrf.rs` — CSRF double-submit middleware, cookie helpers

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
  - `tokens.rs` — API token management
  - `settings.rs` — system settings GET/PUT
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
- `src/db_migrate.rs` — Vault→DB migration tool (BFS walk, encrypted credentials)

### Protocol
- `src/guacd.rs` — TCP connection to guacd, Guacamole protocol handshake
- `src/protocol.rs` — Guacamole wire format parser/encoder
- `src/websocket.rs` — WebSocket <-> guacd TCP bridge, recording tee

### Hypervisors
- `src/pve.rs` — Proxmox VE API (SPICE, VNC, LXC, serial, xterm.js, VM lifecycle)
- `src/vsphere.rs` — VMware vSphere REST API (VM inventory, OS detection, RDP/SSH routing)

### UI
- `templates/` — HTML templates (minijinja + htmx + Tailwind CSS):
  - `base.html`, `layouts/app.html` — base layout with sidebar
  - `partials/sidebar.html`, `partials/header.html` — navigation components
  - `pages/login.html` — auth form + SSO buttons (uses `redirect: 'follow'` + `resp.redirected` + `resp.url` for full error specificity)
  - `pages/connections.html` — folder tree + details panel
  - `pages/sessions.html` — active sessions table with auto-refresh
  - `pages/recordings.html` — recording playback
  - `pages/client.html` — Guacamole client with auto-hide toolbar
  - `pages/error.html` — styled error page (404/401/403/500)
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
- `dev.sh` — development script
- `install.sh` — bare-metal Debian 13 installer
- `Dockerfile` — multi-stage build

## Configuration

Config is loaded via the `config` crate with three layers (highest wins):
1. **Built-in defaults** (in `src/config.rs` `default_toml()`)
2. **TOML file** (`--config config.toml`, or `/opt/persea/config.toml` in Docker)
3. **Environment variables** — `PERSEA_` prefix, nested keys via `__`

### Environment variables

Every config option can be set via env var. Examples:

| Config key | Env var | Default |
|------------|---------|---------|
| `listen_addr` | `PERSEA_LISTEN_ADDR` | `127.0.0.1:8089` |
| `guacd_addr` | `PERSEA_GUACD_ADDR` | `127.0.0.1:4822` |
| `db_path` | `PERSEA_DB_PATH` | `./persea.db` |
| `site_title` | `PERSEA_SITE_TITLE` | `persea` |
| `session_max_duration_secs` | `PERSEA_SESSION_MAX_DURATION_SECS` | `28800` |
| `storage.encryption_key` | `PERSEA_STORAGE__ENCRYPTION_KEY` | unset |
| `storage.backend` | `PERSEA_STORAGE__BACKEND` | `db` |
| `recording.max_recordings` | `PERSEA_RECORDING__MAX_RECORDINGS` | `1000` |
| `tls.cert_path` | `PERSEA_TLS__CERT_PATH` | unset |

Full reference: `docs/deployment-guide.md` → "Environment Variables" section.

### Database backends

Supports MySQL, PostgreSQL, and SQLite via SQLx. Set `db_url` in config:

```toml
db_url = "postgres://user:pass@localhost/persea"  # or mysql://, sqlite://
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
entity_id = "persea"
acs_url = "https://persea.example.com/auth/saml/acs"

[auth.totp]
issuer = "persea"
enforcement = "AdminsOnly"  # Off, AdminsOnly, All
```

Available methods: `oidc`, `ldap`, `database`, `api_key`, `radius`, `saml`, `totp`

### Vault / Connections (optional)

Optional `[vault]` section for credential storage. Without Vault, use DB-only mode:

```toml
[storage]
encryption_key = "aabbccdd..."  # 64-char hex, or PERSEA_STORAGE_KEY env var
```

Vault config (when using Vault):

```toml
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "persea"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### OIDC

```toml
[oidc]
issuer_url = "https://auth.example.com/realms/corp"
client_id = "persea"
redirect_uri = "https://persea.example.com/auth/callback"
groups_claim = "groups"
```

### Proxmox VE

```toml
[proxmox]
addr = "https://pve.example.com:8006"
username = "root@pam"
token_id = "persea"
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

- **Password policies**: Argon2id (NIST 800-63B), enforced 15-char minimum (`password.min_length`), reuse history — the last 5 hashes per user are stored (`password.history`) and reusing one is rejected
- **Account lockout**: account lockout after 5 failed attempts
- **Audit logging**: SHA-256 hash chain with tamper evidence, verification via admin UI and API
- **Session management**: idle timeout (sessions silent past `session_idle_timeout_secs` are reaped with an "idle-timeout" history status; 0 disables), max duration, concurrent limits
- **RBAC**: System + object permissions, recursive group inheritance
- **TLS hot-reload**: SIGHUP re-reads `tls.cert_path`/`tls.key_path` and atomically swaps the served certificate for new connections; a failed reload logs the error and keeps serving the previous certificate
- **Multi-DB**: MySQL, PostgreSQL, SQLite via SQLx enum dispatch
- **Security hardening**: 3 full security audits remediated (see `wayfinder/security-audit-round3/` for the audit trail)

## Deployment

- **Bare metal**: `sudo ./install.sh` on Debian 13
- **Docker**: `docker build -t persea .`
- **First run**: Setup wizard at `/setup` auto-detects environment
- **Beta image**: `gh workflow run beta.yml --ref <branch>` → `ghcr.io/<repo>:beta`

## Build notes

- guacd is built from the maintained fork `BarbellDwarf/persea-guacamole-server`, branch `persea-1.6.1-freerdp3` (apache/guacamole-server pinned at `de97609` with the former `patches/` quilt applied as one commit per patch). See `patches/README.md`.
- Debian 13 ships freerdp3-dev. guacamole-server 1.6.1+ has FreeRDP 3 auto-detection.
- SQLx: `cargo sqlx prepare` for offline compile-time checking (per-backend)

## Testing

- `cargo test` — unit tests + integration tests (1200+ tests across lib + integration binaries)
- `tests/security_regression.rs` — security regression tests (XSS, LDAP, CSV, lockout, SAML, RADIUS)
- `tests/api_handler_tests.rs` — API handler integration tests
- `tests/auth_integration.rs` — auth flow integration tests
- `tests/playwright/` — Playwright E2E tests (54+ tests, Desktop + Mobile Chrome)
- `tests/test_browser_session.sh` — browser session smoke test
- **CI** (`.github/workflows/ci.yml`): check, fmt, clippy, test, audit, integration — all must pass

## Rules for agents

### Git discipline

- **Never run `git reset`, `git checkout .`, or `git stash`** — these destroy parallel work. If the tree has unexpected changes, leave them alone and work around them.
- **Never leave uncommitted work** — commit or `WIP:` before stopping.
- **Commit messages**: Conventional Commits (`fix:`, `feat:`, `docs:`, `style:`, `test:`).
- **Push after commit** — the branch is shared.

### Verification

- **`cargo check` is NOT enough** — it doesn't compile test code or check formatting. Always run `cargo test` and `cargo fmt --check` too.
- **CI must be green** (`gh run list`) before moving on.
- **Tests are guardrails** — if your change breaks a test, your change is wrong. Fix your change, not the test (unless the test is genuinely stale — then note it and ask).

### Security

- **Never introduce XSS** — escape all user data in templates (use `escapeHtml`/`escapeAttr` from `static/js/utils.js`).
- **Never log secrets** — API keys, passwords, tokens stay out of logs.
- **Fail closed** — role checks must reject when identity is `None` (`.ok_or(Forbidden)?` pattern).
- **Constant-time comparisons** — use `subtle::ConstantTimeEq` for secrets.
- **CSRF** — all state-changing requests need the `X-CSRF-Token` header or form field.
- **CSP** — inline scripts need `nonce="{{ csp_nonce }}"`; inline styles are allowed (`style-src 'unsafe-inline'` is intentional for enterprise compatibility).

### Known pitfalls (do not reintroduce)

- **Login page**: a plain `<form method="POST" action="/auth/login">` — NOT a `fetch()`-based submit. Chromium does not reliably send cookies on a fetch-followed redirect (even with `credentials:'same-origin'`); a real browser navigation always does. Do not reintroduce a fetch-based login handler.
- **Cookie format**: `HttpOnly; Secure; SameSite=Lax` — never `HttpOnly;; Secure SameSite` (double semicolon breaks parsing).
- **`SecureCookies::init()` must be called at startup** (`src/main.rs`, from `config.tls.secure_cookies`) — without it, `SecureCookies::enabled()` defaults to `true` and the `secure_cookies = false` config option (required for self-signed certs — browsers block `Secure` cookies over an untrusted-cert connection even after the user clicks through the warning) is silently ignored no matter what's in config. This exact bug shipped once already (the `init()` call was written as a comment, never as code) and broke login for every self-signed-cert deployment. `install.sh` and the Docker entrypoint both auto-append `secure_cookies = false` when they generate their own self-signed cert; anyone supplying their own cert must set it by hand (documented in `config.example.toml`).
- **Config defaults**: `default_toml()` in `src/config.rs` must emit ALL sections — missing sections silently reset defaults (e.g. `max_recordings` → 0).
- **Theme**: `initTheme()` only applies a preset when the user explicitly chose one (`localStorage.persea_theme`) — otherwise app.css defaults (green) show.
- **Static pages**: pages are served from templates, NOT `static/*.html` — the static files are legacy and must not be re-added to the disk-served list in `main.rs`.

## Subagent Work Contract

When dispatching implementation work to subagents, follow the contract in
`docs/agents/subagent-contract.md`:

- **Edits first, single verifier** — subagents edit + commit without
  building; the dispatcher runs one verification pass (`cargo check` +
  `cargo test` + `cargo fmt --check`) after all agents land.
- **Disjoint files only** — no two agents touch the same file.
- **Never `git reset`/`stash`/`checkout .`** in a parallel batch — it
  destroys other agents' work.
- **Never leave uncommitted work** — commit or `WIP:` before stopping.
- **CI must be green** (`gh run list`) before moving on.

## Wayfinder planning

- `wayfinder/` — planning artifacts (gitignored, local only — do NOT commit)
- `wayfinder/security-audit-round3/` — current security audit tickets (R01-R20)
- Tickets are numbered per round: R01-R13 (round 3 security), R14-R20 (config, login, error pages, process)
- Each ticket: `wayfinder:task`, priority, phase, finding, fix, files, deliverable
