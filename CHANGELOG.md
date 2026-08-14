# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Release checklist (delete this comment before tagging v1.0.0):
- [ ] `cargo test` + `cargo fmt --check` green on the final commit
- [ ] CI green for the final push (`gh run list`)
- [ ] Tag `v1.0.0` (annotated) and push it
- [ ] Release workflow green (deb/rpm/Windows artifacts, guacd pin untouched)
- [ ] Push the beta image + beta pre-release (`gh workflow run beta.yml --ref main`) after the tag
-->

## [1.0.0] - 2026-08-14

Initial release. The server is a lightweight Rust replacement for the
Apache Guacamole webapp: SSH, RDP, VNC, SPICE, Proxmox and VMware
sessions from any browser, with enterprise auth (OIDC, SAML, LDAP,
RADIUS, TOTP), RBAC, audit logging, and packaging for Debian, RHEL 10
and Windows — plus the APIs the persea desktop shell needs (session
events, drive uploads, device pairing, the capability probe, and the
Tauri IPC bridge).

### Added

- **Session events SSE** — `GET /api/sessions/events` streams session
  lifecycle events over SSE with `id:` cursors and `Last-Event-ID`
  resume, and serves JSON replay with `?replay=true` for polling
  clients. Ownership mirrors `GET /api/sessions`: owners see their own,
  admins pass `?all=true`; at most one concurrent SSE stream per user.
- **RDP drive upload REST** — `PUT /api/sessions/{id}/drive-files/{name}`
  streams a raw request body into an open RDP drive file (no multipart),
  capped at 4 GiB with per-session concurrency limiting; the desktop
  shell's drag-drop transfers ride on it.
- **Device pairing flow** — OAuth-style device-code flow for the
  desktop shell: anonymous `POST /api/desktop/pair` (rate-limited) hands
  out a single-use 8-char code (SHA-256 stored only), a logged-in user
  confirms it via `POST /api/desktop/confirm` under CSRF, and
  `GET /api/desktop/pair/status` mints an ordinary, revocable user token
  to the paired device exactly once. Auth-method-agnostic: pairing binds
  to whichever identity confirms.
- **Anonymous version + capabilities probe** — `GET /api/auth/status`
  now reports the server version and compiled-in capabilities
  (`drive_upload`, `session_events`, `desktop_pairing`,
  `desktop_bridge`, `kiosk_allowed`, `desktop_transfers`) so the
  desktop shell can gate features per server. Capability flags are
  compiled-in constants; the admin-gated toggles default ON.
- **Desktop bridge CSP/IPC** — `allow_bridge` config plus CSP scheme
  allowances and a desktop-mode flag so the Tauri shell's remote-origin
  IPC works through the webview without loosening browser-mode
  security.
- **Version update alert** — a background check task polls the GitHub
  releases API (air-gap-able), `/api/auth/status` carries
  `latest_version` / `update_available`, and the admin UI shows a
  banner when a newer version exists.
- **Admin/session UX** — settings reorganized into a submenu bar with
  tabbed sections; per-protocol connection defaults in the admin UI;
  RDP client-name forwarding with DNS resolution; session tab
  switching, connection reasons, and recent/disconnect semantics.
- **Web branding** — leaf logo, tile favicon, and a live favicon with a
  state dot (login fallback included); canonical web UI screenshot set
  with a regeneration workflow.
- **RHEL 10 RPM** — the server ships as a native RPM for RHEL 10 /
  EL10 (guacd from the maintained fork, `ffmpeg-free` libs, hostname
  fallback for minimal containers); Windows server release with native
  service, NSIS installer, and first-run `--init` bootstrap; beta
  channel ships deb + rpm alongside the Docker image.
- **HA seams docs** — share-viewer capability errors and the bytes
  buffer carry are documented; `GET /api/sessions/recent` wires recent
  connection semantics.

### Changed

- **rusqlite 0.32 → 0.35** — with the audit log re-verified against the
  new API surface.
- **Repo moved to the persea-grove org** — URLs, guacd fork references,
  and package metadata follow; Ko-Fi funding link added.

### Fixed

- **RDP drive file open under subdirectories** — no more ENOENT for
  files nested in drive folders.
- **Background task JoinHandle double-poll** — eliminated a panic path
  in task shutdown.
- **Test harness port race** — teardown tests no longer bind-then-release
  with a race window.

### Security

- **Hardening pass** — Proxmox SSRF guards (metadata blocklist),
  OIDC callback HMAC validation, TLS warning on insecure connections,
  safe RDP defaults, and parallel DNS resolution with timeouts.
- **CodeQL remediations** — 5 alerts resolved (test-vector and guarded
  XSS suppressions); login page lost its CSP-blocked reset link.


This release is the "make every claim real" round: the marketing said things
that were not implemented, so we implemented them — the multi-backend
database, protocol lockdown switches, password policy, idle timeout, TLS
hot-reload, branding, CLA enforcement — and removed or rewrote everything we
chose not to ship (HIBP screening, the RDP relay, progressive lockout, CLI
audit verification).

### Added

- **Real multi-backend storage** — `db_url` is no longer a health-ping
  only: with `postgres://`, `mysql://`, or `sqlite://` set, ALL core stores
  (users, auth sessions, API keys, address book, audit, system settings,
  session history, RBAC, TOTP secrets, jump hosts) route through the SQLx
  pool. Migrations run automatically at startup (per-backend schema, all
  three kept in sync). No code path silently falls back to SQLite when
  `db_url` is set; without it, the legacy SQLite file behaves exactly as
  before. Verified by CI on every push against live Postgres and MySQL,
  including restart persistence and direct-DB row assertions.
- **First-run setup on the configured backend** — the setup wizard
  connects, migrates, and installs the pool, then creates the first admin in
  the configured backend (`db_url` field in the wizard). CLI `create-user`
  / `add-admin` are backend-aware too.
- **Protocol lockdown switches enforced** — the Settings `enable_*`
  toggles (`enable_rdp`, `enable_ssh_tunnels`, `enable_api_keys`,
  `enable_recordings`, `enable_web_sessions`, `enable_spice`,
  `enable_proxmox`, `enable_vmware`, `enable_vdi`, `enable_file_transfer`)
  now actually lock down: disabled protocols are rejected at session
  creation with a clear error, API-key auth is refused at the middleware,
  drive/SFTP and the recording tee are gated per session. Defaults are
  enabled, so existing deployments are unaffected.
- **Password policy** — enforced 15-character minimum
  (`password.min_length`) and per-user reuse history (`password.history`,
  default 5 hashes, Argon2id-verified, DB-backed) at every password set
  point: admin users API, CLI `create-user`, setup wizard, and a new
  `POST /api/me/password` change endpoint. The breach-screening (HIBP)
  claims are gone — no external service calls.
- **Session idle timeout** — sessions silent past
  `session_idle_timeout_secs` (default 1800, `0` disables) are reaped with a
  distinguishable `"idle-timeout"` history status. Only real client input
  counts as activity — the server's own keepalive pings do not.
- **TLS hot-reload** — SIGHUP re-reads `tls.cert_path` /
  `tls.key_path` and atomically swaps the served certificate for new
  connections; a failed reload logs the error and keeps serving the previous
  certificate. The docs now describe only this mechanism (the file-watcher
  and admin-upload claims were removed).
- **Branding reaches the UI** — `site_title`, `logo_url`, and
  `primary_color` from settings now drive the sidebar, login/setup pages,
  and the accent color across the app (logo upload writes to
  `static/uploads/logo/`). Live preview in the branding admin page; theme
  presets still win when a user explicitly chose one.
- **Recordings: encrypted-at-rest files are watchable** — the
  recordings listing, playback, and delete now handle `.guac.enc` files
  (listing showed only plain `.guac` before).
- **Connection details** — the details panel shows grouped
  fields (Connection / Access / Advanced) plus created/updated timestamps;
  every connection can carry a human description end-to-end (modal → API →
  panel → CSV import/export); folder rows show name + count with scope in
  the tooltip only.
- **CLA enforcement** — contributions are now verified CLA-covered:
  a signature registry (`cla/signed/`), a CI check that fails unsigned
  PRs, and a PR template acknowledgment. The fictional "CLA Assistant bot"
  claim is gone.
- **Maintained guacd fork** — guacd builds from
  `BarbellDwarf/persea-guacamole-server` (branch `persea-1.6.1-freerdp3`)
  instead of re-applying a 10-patch quilt: Dockerfile, install.sh, the
  release workflow, and the deb/rpm build scripts consume the fork. The
  fork carries the FreeRDP 3.x compile fixes, Kerberos NLA, H.264
  passthrough, RDP resize fixes, SPICE, and multi-monitor as one commit per
  patch.
- **RDP entry UX** — explicit Domain field, security /
  auth-package selector with guacd error surfacing, and protocol switches
  in the entry modal now reset to the correct default port without
  clobbering manually entered values.
- **Kerberos NLA in the Docker image** — krb5.conf generation and
  krb5 tooling so Kerberos-authenticated RDP works from the container.

### Changed

- **License: AGPL-3.0 → Apache-2.0** — persea is now Apache-2.0,
  free for everyone: no license keys, no enterprise feature gates, no
  evaluation period. See [LICENSE](LICENSE) and [CLA.md](CLA.md). All
  contributors must sign the CLA.
- **Connections page layout** — the folder pane gets real width
  (clamp 260–360px), a rebalanced three-pane layout, and proper ellipsis;
  mobile stacking unchanged.
- **Settings page handlers are CSP-safe** — inline `onchange` /
  `onclick` handlers moved into the nonced script block; toggles now
  actually sync and the save confirmation works.
- **Account lockout wording** — documented as "lockout after 5 failed
  attempts" (the progressive-delay ladder was fiction).
- **Audit verification wording** — documented as admin UI + API (the
  CLI-verification claim was fiction).
- **Docs scrub** — personal/environment references removed from README,
  docs, and CHANGELOG; claims now match code.
- **HA documentation honest** — spike runbook records what is real
  (standalone guacd plain + TLS, multi-backend persistence, shared data
  across instances) and what is not yet (cross-instance session sharing —
  the enterprise HA work).

### Fixed

- **Docker first-run crashed on filesystems without chmod support** —
  the entrypoint's `chmod 600` on `admin-key.txt` failed with EPERM on
  Windows/WSL bind mounts (`/mnt/g/...`, 9p, virtiofs), and `set -e` killed
  the script before the admin key was created — so the DB never initialized
  and every container restart looped on "First run detected". The chmod is
  now best-effort with a clear warning; POSIX filesystems still get
  `chmod 600`.
- **Connect failure no longer redirects to login** — failed /
  cancelled sessions keep you on the Connections page instead of bouncing
  to the login form.
- **Entry modal port default** — switching protocols no longer
  carries SSH's port 22 into RDP (or vice versa).
- **Recordings `.guac.enc` invisible to the UI** — encrypted
  recordings are listed, playable, and deletable.
- **CodeQL/security findings** — global-setup logging fixed;
  client-side XSS sink hardened.
- **Settings page saved wrong toggle values** — CSP was blocking
  every inline handler; toggles now save what the admin actually set.

### Removed

- **RDP relay feature** — the loopback relay with
  proxy/fallback/direct modes and its socat dependency are gone; sessions
  connect directly to the target. The admin "connection mode" setting was
  removed.
- **HIBP / breach-screening claims** — no external service, no
  claim.
- **`patches/` quilt from the repo** — replaced by the maintained
  fork; a pointer README remains.

### Security

- **API key disable** — `enable_api_keys = false` now rejects
  API-key authentication at the middleware (admin keys and user tokens).
- **CSRF-safe settings handlers** — no inline handlers remain on the
  settings/branding admin pages.
- **CLA gate** — unsigned contributions fail CI.


### Added

- **Release hardening**
