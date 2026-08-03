# Map: Apache Guacamole Parity + Enterprise Ready

## Destination

Bring persea to feature parity with Apache Guacamole's auth stack (LDAP, Database, SAML, RADIUS, TOTP), make Vault optional with DB as the primary store, add VMware/Proxmox hypervisor integration, redesign the UI to be professional and modern, and harden for enterprise use (password policies, audit logging, RBAC, session management).

## Notes

- Rust/Axum codebase. SQLite today, MySQL+PostgreSQL needed.
- guacd handles protocol translation (SSH/RDP/VNC/SPICE). persea is the web frontend + session manager.
- Existing auth: OIDC + API keys. Existing Vault: address book (connections) + credentials.
- SQLx for multi-backend. `ldap3` for LDAP. `saml-rs`/`samael` for SAML. `radius-tokio` for RADIUS. `totp-rs` for TOTP. `argon2` for password hashing.
- NIST 800-63B for password policies. SOC 2 / NIST 800-53 for audit.
- UI: htmx + Askama + Tailwind CSS. Expandable sidebar, two sections (user + admin), professional design.
- Proxmox: already has SPICE. Expand to VNC + LXC + lifecycle.
- VMware: vSphere inventory + guest OS detection + RDP/SSH routing via guacd.

## Decisions so far

### Foundation (Tickets 001, 002 — RESOLVED)

- **Multi-DB Backend (001)** — SQLx with enum-based `DbPool` (`Postgres(PgPool)` / `MySQL(MySqlPool)` / `SQLite(SqlitePool)`). Connect via URL scheme detection. `db_dispatch!` macro reduces match boilerplate. Per-backend migration directories (`migrations/postgres/`, `migrations/mysql/`, `migrations/sqlite/`). Use `TEXT` for PKs (UUIDs), timestamps, enums for maximum portability. `query!()` for common queries, `query()` (runtime-checked) for backend-specific. sqlx built-in pool (no deadpool/bb8). UPSERT syntax is NOT portable — backend-specific SQL required. Placeholder syntax: `?` for MySQL/SQLite, `$N` for PostgreSQL. `QueryBuilder` handles placeholder differences automatically. **IMPLEMENTED:** `src/db_pool.rs` (DbPool enum, connect, migrations, dispatch macros), `Cargo.toml` (sqlx deps), `migrations/{sqlite,postgres,mysql}/001-init.sql` (15 tables), `src/config.rs` (db_url field), wired into main.rs.
- **Auth Provider Architecture (002)** — Single `AuthProvider` trait with `Capabilities` bitflags (`AUTHENTICATE | MFA | REDIRECT | STORE_PASSWORDS | RESOLVE_GROUPS | AUTO_CREATE_USER`). `AuthResult` enum: `Success { subject, display_name, groups, role }` / `Failure(msg)` / `Redirect(url)` / `Unavailable(msg)`. `AuthChain` holds `Vec<Box<dyn AuthProvider>>` in config order. Two-phase: primary auth → optional TOTP second factor. Redirect providers (OIDC/SAML) get dedicated routes (`/auth/login`, `/auth/callback`, `/auth/saml/acs`) bypassing middleware. Inline providers (LDAP/DB/API key/RADIUS) go through `POST /auth/login` handler. Extractor-based auth (`FromRequestParts`) + `middleware::from_fn` per-route-group. `auth_pending_mfa` table for MFA state bridging. Config: `[auth]` section with `methods` list, each provider gets `[auth.ldap]`, `[auth.saml]`, etc. Simple `match` on method names (not factory pattern — can refactor later if plugin support needed). **IMPLEMENTED:** `src/auth_provider.rs` (trait, Capabilities, AuthResult, AuthRequest, UserInfo), `src/auth_chain.rs` (AuthChain, from_config, authenticate), wired into main.rs. 22 tests pass.

### Schema + Auth Methods (Tickets 003-008, 010 — RESOLVED)

- **Auth DB Schema (003)** — 15 tables total (Guacamole's 23 → 15). Core: `users` (unified across auth sources, `auth_source` + `external_id`), `connections` (JSON params), `connection_groups` (hierarchical, scope), `connection_permissions` (user/group + permission). New: `auth_pending_mfa` (MFA bridging), `audit_events` (hash chain with `prev_hash`), `auth_providers` (multi-source config in DB), `recovery_codes`, `totp_secrets`. TEXT PKs with UUIDv7, timestamps as ISO 8601 TEXT, Argon2id password hashes, enums as TEXT with app validation.
- **Database Auth (004)** — Argon2id via RustCrypto. OWASP params: 46 MiB memory, 3 iterations, 1 parallelism. PHC string format auto-handles parameter migration. Progressive lockout: 5 attempts → 30s → 5min → 30min. Transparent hash migration: verify old SHA-256 on login → re-hash with Argon2id. HIBP k-anonymity for breach screening (SHA-1 prefix → API → local suffix match). Auto-create accounts on first SSO login with `password_hash = NULL`, default role `"viewer"`. **IMPLEMENTED:** `src/password.rs` (hash/verify, Argon2id OWASP params, PHC format), `src/auth_providers/database.rs` (DatabaseProvider, constant-time dummy hash on unknown user, auto-migrate hashes). 11 tests pass.
- **LDAP Auth (005)** — `ldap3` 0.12.1 confirmed. `features = ["tls-rustls-ring"]`. Direct bind (DN = `{attr}={username},{base}`) and search bind (service account searches for DN first). STARTTLS via `set_starttls(true)` on port 389, or `ldaps://` for TLS on 636. AD groups via `memberOf` + nested group OID `1.2.840.113556.1.4.1941`. Connection-per-request acceptable for auth (~10-50ms). Auto-create DB user on first LDAP login with `can_change_password = false`. **IMPLEMENTED:** `src/auth_providers/ldap.rs` (LdapProvider, LdapConfig, search bind, group resolution, TLS/STARTTLS). 10 tests pass.
- **SAML Auth (006)** — `gamlastan` v0.7.0 (pure-Rust, zero C deps, 263/263 SPID conformance). SP metadata generation, ACS handler (POST endpoint, base64 decode, `parse_secure()` XXE-safe). Signature: RSA-SHA256 mandatory. Skip SLO for v1 (broken in most IdPs). IdP metadata from URL or file with auto-refresh. Strict mode: `SecurityConfig::strict()` enables all mandatory checks. **IMPLEMENTED (stub):** `src/auth_providers/saml.rs` (SamlProvider, SamlConfig, parse_saml_response, extract_groups, generate_sp_metadata). Returns Unavailable until SAML crate confirmed. 11 tests pass.
- **RADIUS Auth (007)** — `radius-tokio` v0.1 (Tokio-native, RFC-complete). PAP first (simplest). Access-Challenge handling via `ChallengeStore` (short-lived HashMap, same pattern as WsTicketStore). RadSec for encrypted transport. Dual role: `mode = "primary"` or `mode = "mfa"`. NAS attributes auto-detected. Shared secret from env var. PEAP/EAP-TTLS via `radius-tokio-eap` companion (Phase 2). **IMPLEMENTED (stub):** `src/auth_providers/radius.rs` (RadiusProvider, RadiusConfig, ChallengeStore, NAS attribute builders). Returns Unavailable until radius-tokio confirmed. 11 tests pass.
- **TOTP MFA (008)** — `totp-rs` v5.7. QR code generation via `get_qr_png()`. Multiple devices per user (phone + hardware token). Recovery codes: 10 codes, SHA-256 hashed, single-use. Enforcement: `Off` / `AdminsOnly` / `All`. Clock drift: `skew: 1` (±30s). Admin controls: reset secret, disable TOTP. API: enroll → confirm → disable → recovery codes. **IMPLEMENTED:** `src/totp.rs` (generate_enrollment, verify_code, TotpConfig, TotpEnforcement), `src/auth_providers/totp.rs` (TotpProvider with MFA capability). DB functions for TOTP secret storage. Tests pass.
- **User Identity Model (009)** — Email as universal linking key (lowercase, auto-link on match when verified or source is trusted). Groups from login source only (not merged across sources). Configurable `role_precedence` for future cross-source. Auth-synced fields (name, email) overwritten on login; users can override display name locally. Multiple concurrent sessions allowed. Check enabled status on every login, no background polling initially. Auto-create accounts on first login from any source.
- **Vault Optional (011)** — All-or-nothing per deployment: `[vault]` present = Vault mode, absent = DB-only mode. AES-256-GCM encryption for 6 credential fields (`password`, `private_key`, `container_password`, `proxmox_token_secret`, `jump_password`, `jump_private_key`). Key from `[storage] encryption_key` or `RGUAC_STORAGE_KEY` env var. `db-migrate-from-vault` CLI subcommand: BFS walk Vault, encrypt credentials, write to DB. Idempotent (skip already-migrated). Minimal DB-only config: `listen_addr`, `guacd_addr`, `[storage] encryption_key`. **IMPLEMENTED:** `src/crypto.rs` (AES-256-GCM encrypt/decrypt, 8 tests), `src/db_migrate.rs` (cmd_db_migrate_from Vault, 661 lines, BFS walk, encrypted credentials, idempotent). CLI subcommand wired.
- **Audit Logging (012)** — Hash chain in DB. Sequential `INTEGER PRIMARY KEY AUTOINCREMENT` IDs for unambiguous chain order. Each event: `id`, `event_type`, `timestamp` (ISO 8601 UTC), `user_id`, `source_ip`, `outcome`, `details` (JSON), `session_id`, `prev_hash`, `event_hash`. Genesis event: `prev_hash = "0"`. Canonical JSON (sorted keys, no whitespace) for hash computation. 25+ event types covering auth, session, connection, admin, system events. Shard-aware retention: archive old events, insert `system.audit.chain_start` with hash anchor to previous chain. CLI: `persea audit-verify` with progress bar. Admin UI: "Verify Now" button, status badge, results table. Query API with filters (user, date, type, outcome). CSV/JSON export with hash chain for independent verification. **IMPLEMENTED:** `src/audit.rs` (AuditEvent, log_event, compute_event_hash, verify_chain, ChainVerification, EventBuilder). 295 lines.
- **Session Management (013)** — In-memory for live state (WebSocket, guacd streams, cancellation tokens). DB for audit trail (`session_history` with `source_ip`, `terminated_reason`, `user_agent`). Track `last_activity_at` on WebSocket input events (not guacd screen updates). Single background reaper task (60s interval) checks idle + max duration. No session resume (new session on reconnect). Concurrent limits via `AtomicU32` counter per user, admin bypass. NIST timeouts: AAL2 = ≤24h max, ≤1h idle. ISO 27001 = 15 min for sensitive. **IMPLEMENTED:** `src/session/types.rs` (AtomicI64 last_activity, source_ip, user_id), `src/session/manager.rs` (update_activity, get_idle_sessions, get_expired_sessions, get_user_session_count, check_concurrent_limit, save_session_metadata), `src/session/mod.rs` (spawn_reaper background task).
- **RBAC Connection Perms (014)** — Guacamole two-tier model: system permissions (from role) + object permissions (per-connection). Role = coarse gate (who can use admin UI). Object perms = fine-grained (READ/CONNECT/UPDATE/DELETE/ADMINISTER per connection/group). Organizational groups only (balancing deferred). Recursive CTE for group→member permission propagation. Explicit user permissions override group grants. Admin UI: checkbox matrix per connection/group. Default permissions configurable in TOML. Extractor-based permission checks in axum. **IMPLEMENTED:** `src/rbac.rs` (SystemPermission, ObjectPermission, ConnectionGroup, PermissionEntry, create_group, delete_group, add_user_to_group, grant_connection_permission, check_connection_permission with recursive CTE, list_connection_permissions). DB migration for rbac tables.

### Hypervisors + UI (Tickets 015-018 — RESOLVED)

- **Proxmox Expansion (015)** — VNC: `POST /nodes/{node}/qemu/{vmid}/vncproxy` → ticket + port. guacd connects directly via TCP (no WebSocket needed). Tickets expire ~40s. LXC: identical endpoints under `/lxc/{vmid}/`. Serial: `POST .../termproxy`. xterm.js: `POST .../xtermjs` (WebSocket). VM lifecycle: `POST .../status/start|stop|shutdown|suspend`. Inventory: `GET /cluster/resources?type=vm`. **IMPLEMENTED:** `src/pve.rs` (fetch_vnc_config, fetch_serial_config, fetch_xtermjs_config, list_all_vms, power_action, VncConfig, SerialConfig, XtermConfig, PveVm, PveVmType).
- **VMware vSphere (016)** — `vim_rs` crate for Rust vSphere client. SOAP auth: `RetrieveServiceContent` → `Login` → session cookie. VM inventory via `PropertyCollector` (name, powerState, guestId, ipAddress). Guest OS detection: `guest.guestId` → protocol mapping (win*→RDP, linux*→SSH, other→VNC). IP from `guest.ipAddress` (requires VMware Tools). Guest credentials from Vault or per-VM config. guacd connects to guest IP directly. No MKS protocol. **IMPLEMENTED (stub):** `src/vsphere.rs` (VsphereClient, VmInfo, detect_protocol, power_action, VmCache with TTL). Returns error until vim_rs confirmed. 8 tests pass.
- **UI Redesign (017)** — htmx + Askama + Tailwind CSS. Template hierarchy: `base.html` → `layouts/app.html` → `pages/*.html` + `partials/*.html`. Detect `HX-Request` header for partial vs full page. `hx-boost="true"` for SPA-like navigation. Dark mode: `class` strategy with `localStorage`. Sidebar: expandable sections with Heroicons. Data tables: server-side sort/filter/pagination. Guacamole client: iframe embed. Design: near-black backgrounds, gray-900 surfaces, single accent color, monospace data, dense tables.
- **SSH Tunnel Management UI (018)** — Admin UI for configuring jump host chains. Visual chain builder, test connectivity button, active tunnels view.

### Auth Architecture
- **Auth methods** — LDAP, Database, SAML, RADIUS, TOTP + existing OIDC and API keys.
- **Auth chain** — Flat priority, admin-configurable via UI (drag-to-reorder on Settings → Auth page). Two-phase: primary auth → optional TOTP second factor.
- **Auth config storage** — Tier 1: DB (UI-managed, no restart). Tier 2: config file (restart required). Auth provider settings (host, bind DN, client ID, etc.) live in DB, managed through admin UI.
- **Login page** — Password form (handles LDAP/DB/RADIUS dynamically) + SSO buttons below (OIDC/SAML, renamable by admin). RADIUS shows dynamic MFA field on Access-Challenge.
- **User identity** — Email-based linking across auth sources. Auto-create accounts on first login. `(auth_source, external_id)` primary lookup, email fallback.

### Infrastructure
- **DB backends** — MySQL + PostgreSQL + SQLite via SQLx enum-based `DbPool`. `query!()` for common SQL, `query()` for backend-specific. UPSERT syntax backend-specific.
- **guacd** — Embedded (spawn child process, lifecycle management) or external (TCP connection). Config-driven. Embedded is default for new installs.
- **Vault** — Optional. Credentials only. Connections/sessions/server info in DB. `persea db-migrate-from-vault` CLI subcommand for migration.
- **TLS** — Three sources: mounted files (Let's Encrypt, K8s secrets), admin UI upload, self-signed generation. Hot-reload via file watcher (inotify/kqueue) + SIGHUP.
- **Environment detection** — Auto-detect IPs, Docker container, guacd binary, existing TLS certs. First-run setup wizard pre-fills from detection.

### UI
- **Tech stack** — htmx + Askama templates + Tailwind CSS. Server-rendered HTML with htmx for dynamic interactions. No SPA, no build step.
- **Layout** — Expandable sidebar. User section (servers/sessions/active sessions). Admin section (Settings → Admin: users/groups/auth/audit/reports/docs). Account section (profile/API keys/TOTP).
- **First-run setup** — Web UI wizard on first boot. Collects: listen address, DB connection, guacd mode, TLS, admin account, feature flags. Writes config file. Not shown again.
- **Feature flags** — Browser sessions, VDI, Proxmox, VMware, session recording, SSH tunnels. Presented during setup wizard, admin-toggleable via Settings → Features page after.

### Features
- **Session recording** — Keep `.guac` format. Supplementary formats (video export) deferred to future update.
- **Browser sessions** — Optional, disabled by default. Xvnc + Chromium stack stays as-is when enabled.
- **VDI** — Optional, disabled by default. Docker-based VDI stays as-is when enabled.
- **SSH tunnels** — Add tunnel management UI. Admin can configure jump host chains, test connectivity, view active tunnels.
- **Session management** — Metadata in DB (audit trail, listing across restarts). Live connections stay in-memory. Idle timeout, max duration, concurrent limits configurable.
- **Proxmox** — Expand from SPICE-only to VNC + LXC + serial + xterm.js + VM lifecycle.
- **VMware** — vSphere inventory, guest OS detection, RDP/SSH routing via guacd. No proprietary MKS protocol.

### Enterprise Security
- **Password hashing** — Argon2id (NIST 800-63B). 15-char minimum, no forced rotation, breach screening via HIBP k-anonymity.
- **Account lockout** — Progressive delay (30s → 5min → 30min) after 5 failed attempts.
- **Password history** — Remember 24 passwords. Configurable.
- **Audit log** — Hash chain in DB (tamper evidence). Verification in CLI + admin UI. Structured events: auth, session, connection, admin actions.
- **RBAC** — 4-tier hierarchy (admin > poweruser > operator > viewer) + connection-level permissions (read/connect/admin per connection/group).
- **Migration** — CLI subcommands: `db-migrate-schema` (SQLite → new schema), `db-migrate-from-vault` (Vault → DB).

## Ticket Dependency Graph

```
Phase 1: Foundation
  001 Multi-DB Backend ──────────────────────────────┐
  002 Auth Provider Architecture ────────────────────┤
                                                      │
Phase 2: Schema + Auth Methods                        ▼
  003 Auth DB Schema ◄── 001, 002
  004 Database Auth ◄── 003, 002
  005 LDAP Auth ◄── 003, 002
  006 SAML Auth ◄── 003, 002
  007 RADIUS Auth ◄── 003, 002
  008 TOTP MFA ◄── 003, 002, 004
  009 User Identity Model ◄── 003, 002, 004-008
  010 Password Security ◄── 003, 004

Phase 3: Enterprise Features
  011 Vault Optional ◄── 003, 001
  012 Audit Logging ◄── 003, 009
  013 Session Management ◄── 003, 009
  014 RBAC Connection Perms ◄── 003, 009, 002

Phase 4: Hypervisors
  015 Proxmox Expansion ◄── 003, 013
  016 VMware vSphere ◄── 003, 013

Phase 5: UI
  017 UI Redesign ◄── 009, 002, 014
  018 SSH Tunnel Management UI ◄── 003, 013
```

## Not yet specified

- Syslog forwarding for SIEM (deferred — hash chain in DB is sufficient for v1)
- WebAuthn/FIDO2 as TOTP successor (future effort)
- Kerberos/SPNEGO (RADIUS typically handles this)
- Concurrency model for DB connection pools under load
- Horizontal scaling / multi-instance deployment (future effort)

## Out of scope

- WebAuthn/FIDO2 (natural follow-up, separate effort)
- Full Keycloak-style flow engine (flat chain covers use cases)
- Session recording format changes (`.guac` stays, supplementary formats deferred)
- Horizontal scaling / multi-instance (future effort)
