# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-08-08

### Added

- **Session Management**
  - Disconnect vs Logout split: disconnect keeps session for reconnection, logout terminates
  - Recent connections section on Connections page
  - Sessions open in new browser tabs instead of navigating away
  - File transfer for RDP and SSH sessions (admin-toggleable)
  - Connection reason field (dropdown + free text, admin-toggleable)
  - Session toolbar fixes: protocol badge reads actual session type, disconnect confirmation

- **Security Hardening**
  - Three comprehensive security audits with 23+ findings remediated
  - SAML XML-DSig: real Exclusive C14N, digest verification, InResponseTo + Audience checks
  - SSH Trust-On-First-Use: auto-pin first use, verify subsequent, persistent known_hosts
  - CSRF double-submit protection on all requests
  - WebSocket Origin validation and connection rate limiting
  - Per-session concurrent viewer limits
  - Login rate limiting (always-on, independent of global rate_limit)
  - Failed login attempt tracking with progressive lockout
  - MFA lockout bypass fixed — TOTP verification now checks lockout state

- **Admin Features**
  - Admin settings page with feature toggles for every protocol (RDP, SSH, Web, VDI, Proxmox, VMware)
  - Auth provider management API (OIDC/LDAP/SAML/RADIUS/database)
  - Group management with folder permission counts
  - CSV connection import with downloadable template

- **UI/UX**
  - Dark/Light/Auto theme toggle with OS preference detection
  - Connections page redesigned with sidebar folders and detail panel
  - Recordings fullscreen playback with larger player
  - Admin pages: Auth Providers, Groups, Reports buttons wired and functional

- **Infrastructure**
  - High availability architecture documented
  - CSP nonce wired into all inline scripts
  - Docker: TLS cert generated at runtime, admin key saved to file (chmod 600)
  - 50+ regression tests for security findings

### Fixed

- **Critical Security**
  - Stored XSS in admin Users page — all user data now escaped
  - vSphere power_action had no role check + unsanitized vm_id — now requires operator role + charset validation
  - Token admin endpoints (list/audit) were fail-open — now fail-closed
  - MFA brute-force — lockout check added before TOTP verification
  - RADIUS response authenticator comparison now uses constant-time equality
  - LDAP filter injection — escape applied at all 3 interpolation sites

- **High Security**
  - CSP `style-src` now allows inline styles (enterprise-standard, `unsafe-inline` for styles only)
  - 6 static pages migrated to templates (sessions, recordings, admin, tokens, reports, docs)
  - Connections page served from template instead of broken static file
  - Proxmox TLS verification defaults to true
  - Browser network allowlist defaults to loopback-only
  - Failed login lockout wired into auth handlers
  - Chromium Login Data store no longer populated in VDI sessions
  - Error responses sanitized to prevent information leakage
  - Admin API key no longer printed to stdout in Docker

- **UI Fixes**
  - Dark mode toggle now properly applies theme colors for each mode
  - Sidebar minimize button functional
  - Connections page gap between sidebar and content eliminated
  - Session toolbar protocol badge reads actual session type
  - Modal drag-to-select no longer closes the modal and loses form progress
  - Auth Providers, Groups, Reports admin pages buttons wired correctly

- **Tests**
  - `config_defaults` LDAP test restored (was corrupted by M01)
  - `session_summary` test assertions updated to match current function
  - `boundary_partial` protocol test fixed (fast-path false positive removed)
  - `settings_api_tests` updated for current `enable_vdi` default

### Changed

- Connection credentials encryption now enforced (warns loudly if no key set)
- Recording retention defaults to 1000 (was unlimited)
- Error responses return generic messages, full details logged server-side
- Browser sessions block `file://` and metadata IP ranges by default
- Admin settings feature toggles default: VDI enabled, file transfer disabled

### Security

See `docs/high-availability.md` for architecture details and
`wayfinder/security-audit-round3/` for the full audit trail.


## [1.0.3] - 2026-08-06

### Added

- CSRF double-submit protection with `X-CSRF-Token` header on all requests.
- WebSocket Origin validation and connection rate limiting.
- DB-backed address book with AES-256-GCM encryption of stored credentials
  (`[storage] backend = "db"`, default), making Vault optional for connections.
- VMware vSphere integration: REST API for VM inventory and power operations,
  connections page UI with guest-OS-based RDP/SSH routing, setup wizard detection.
- Deep health check with latency, Vault/disk checks, and uptime metrics.
- Prometheus metrics endpoint (`/metrics`).
- Graceful shutdown with session drain.
- Startup config validation.
- JSON logging via `RUST_LOG_FORMAT=json`.
- Optional `[vault_shared]` and `[vault_local]` backends for dedicated
  fleet-wide and per-host Vaults (`VAULT_SHARED_SECRET_ID` / `VAULT_LOCAL_SECRET_ID`).
- Admin settings API (`GET`/`PUT /api/system/settings`) with persistence and
  form feedback.
- Auth provider management API with OIDC/LDAP/SAML/RADIUS/database types,
  addable through the admin auth page; DB-configured providers join the auth
  chain at startup.
- Local group management (`/admin/groups.html`) with auth-provider group
  mapping and folder permission counts.
- CSV connection import (`POST /api/addressbook/import`) with downloadable
  template (`GET /api/addressbook/import-template`).
- Connections page: create/edit/delete folders and entries, folder
  permissions, scope-aware search, and import modal.
- `storage.encryption_key` config value honored (env `PERSEA_STORAGE_KEY`
  remains the fallback).

### Changed

- Split god-modules into `src/api/` and `src/session/`.
- Unified error handling with `AppError` and standardized error responses
  across handlers.
- Split `CreateSessionRequest` into protocol sub-structs
  (`SshParams`, `RdpParams`, `VncParams`, `WebParams`, `VdiParams`, `SpiceParams`,
  `ProxmoxParams`) while preserving the flat JSON wire format.
- Updated dependencies.
- Version bumped to 1.0.2.
- Dev lints (missing_docs, clippy::unwrap_used) silenced in release builds.

### Fixed

- CSRF cookie wiring: dropped `HttpOnly` so JavaScript can read and resend the
  `X-CSRF-Token` (double-submit pattern).
- Docker image build and container health check (guacd pin, embedded templates,
  `guacd.conf`, TLS-aware healthcheck).
- Deprecation warning firing on the default `recording_path`; empty
  `recording_path` treated as unset.
- CI lint jobs and deb packaging paths (stale `rustguac` paths).
- 500 on session summary with an empty session history table
  (`COALESCE` on the `active_now` aggregate).
- 502 error-log spam on every page load when vSphere is unconfigured
  (`/api/vsphere/vms` now returns 200 with `configured: false`).

## [1.0.1] - 2026-08-04

### Added

- CSRF double-submit cookie and VDI `chpasswd` injection fix.
- DB-backed address book: `[storage]` config with `db` backend, address book
  CRUD operations, and DB migration (`ticket 022`).
- VMware vSphere integration: config section, REST handlers, router wiring,
  setup guide (`ticket 021`).
- Unit tests for tunnel, drive, and recording modules.
- Clippy `unwrap_used` and `missing_docs` lint enforcement.

### Changed

- Final wayfinder ticket gap closure (`#2`).
- Frontend refactors: deduplicated `escapeHtml`/`escapeAttr` across templates.
- Docs overhaul: anti-AI writing rules applied across all guides, README
  rewritten with comprehensive feature list, name-origin story added.
- GHCR-only Docker images with `.zip` packages for release artifacts.

### Fixed

- Vault mTLS tests: SAN extensions on generated certs, extfile for v3 certs,
  correct CI integration test port.
- Theme toggle class replacement and profile page `DOMContentLoaded` guard.
- `/api/me` now returns `auth_source` from the database, not the identity type.
- Removed rustup cache mount from Dockerfile that overwrote the toolchain.
- CI: all clippy warnings, fmt, and test failures resolved.

## [1.0.0] - 2026-08-03

### Added

- Initial release of Persea, a lightweight Rust replacement for Apache
  Guacamole: browser-based SSH, RDP, VNC, SPICE, Proxmox VE consoles, web
  browsing, and VDI desktop containers through guacd. Single binary plus
  guacd; no Java, no Tomcat.
- All 20 wayfinder tickets completed:
  - Security hardening: API key salting, OIDC fingerprint, CSP, WebSocket rate limiting.
  - Architecture: API handler split, session split, unified error handling.
  - Testing: mock traits, proptest, 25 API handler tests.
  - UI/UX: sidebar layout, responsive design, accessibility.
  - WebSocket auto-reconnect.
  - Performance: DB indexes, async DNS, streaming CSV export, `BytesMut`.
  - DevOps: systemd hardening, Docker healthcheck, RPM build.
  - Config validation, `Role` enum and code-quality cleanup, graceful shutdown
    with session drain, deep health check plus Prometheus metrics, standardized
    error responses, CI/CD pipeline, clippy lint pass.

### Changed

- Renamed the project from RustGuac to Persea across the codebase, docs,
  packaging, and CI.
- New Persea logo and favicon.
- Frontend converted to shared `app.css` classes with ARIA attributes.

### Fixed

- Full-width content layout and centered on ultrawide displays.
- CSP allowing CDN scripts/styles, htmx auth headers, users table loading via
  fetch, profile data loading.
- Resolved merge conflict markers in templates and a reports.html merge conflict.
- All compilation errors and guacd test expectations fixed (25 tests passing).
