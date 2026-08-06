# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CSRF double-submit protection with `X-CSRF-Token` header on all requests.
- Salted hashing for API keys at rest.
- WebSocket Origin validation and connection rate limiting.
- DB-backed address book with AES-256-GCM encryption of stored credentials
  (`[storage] backend = "db"`, default), making Vault optional for connections.
- VMware vSphere integration: REST API for VM inventory and power operations,
  connections page UI with guest-OS-based RDP/SSH routing, setup wizard detection.
- Deep health check with latency, Vault/disk checks, and uptime metrics.
- Prometheus metrics endpoint (`/metrics`).
- Graceful shutdown with session drain.
- WebSocket auto-reconnect.
- Accessibility and responsive UI overhaul (ARIA attributes, focus indicators,
  mobile navigation).
- Startup config validation.
- JSON logging via `RUST_LOG_FORMAT=json`.
- Optional `[vault_shared]` and `[vault_local]` backends for dedicated
  fleet-wide and per-host Vaults (`VAULT_SHARED_SECRET_ID` / `VAULT_LOCAL_SECRET_ID`).

### Changed

- Split god-modules into `src/api/` and `src/session/`.
- Unified error handling with `AppError` and standardized error responses
  across handlers.
- Split `CreateSessionRequest` into protocol sub-structs
  (`SshParams`, `RdpParams`, `VncParams`, `WebParams`, `VdiParams`, `SpiceParams`,
  `ProxmoxParams`) while preserving the flat JSON wire format.
- Updated dependencies.

### Fixed

- CSRF cookie wiring: dropped `HttpOnly` so JavaScript can read and resend the
  `X-CSRF-Token` (double-submit pattern).
- Docker image build and container health check (guacd pin, embedded templates,
  `guacd.conf`, TLS-aware healthcheck).
- Deprecation warning firing on the default `recording_path`.
- CI lint jobs and deb packaging paths (stale `rustguac` paths).

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
