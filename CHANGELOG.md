# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2026-08-29

### Security

- Force-logout now revokes all of a user's API tokens (scoped desktop
  tokens included) alongside their sessions, with a dedicated audit
  event — closing the "logged out but token still works" gap on the
  admin force-logout path (#270)

### Fixed

- Storage-key bootstrap consolidated into one implementation with a new
  `persea ensure-storage-key` CLI subcommand; fixes a first-boot crash
  loop when config files carry an indented `encryption_key` (the old
  shell installers injected a duplicate key) — install.sh, the Docker
  entrypoint, install-release.sh, and both RPM/deb postinsts now route
  through it (#271)
- Spice, Proxmox, and VDI address-book entries could not be connected
  from the quick-connect link surface (HTTP 400 "Unknown session type");
  both connect paths now build identical session parameters for all
  entry types (#280)
- Active-session counts no longer contradict each other between the
  Reports, Connections, and Sessions pages; stale "active" rows left
  behind by restarts or crashes are closed on shutdown and swept at
  startup (#273)

### Changed

- Audit log now shows usernames instead of numeric IDs, readable
  timestamps, and structured detail rows in the admin Audit Log; CSV
  export gains a username column (#272)
- API-key request path no longer reads the system_settings table twice
  per request (in-memory flag cache; per-instance view — see known
  limitation) (#276)

### Known limitations

- In multi-instance (HA) deployments, settings-flag changes propagate to
  other instances on their restart rather than immediately (#289)

<!--
Release checklist (delete this comment before tagging v1.1.1):
- [ ] `cargo test` + `cargo fmt --check` green on the final commit
- [ ] CI green for the final push (`gh run list`)
- [ ] Tag `v1.1.1` (annotated) and push it
- [ ] Release workflow green (deb/rpm/Windows artifacts, guacd pin untouched)
- [ ] Push the beta image + beta pre-release (`gh workflow run beta.yml --ref main`) after the tag
-->

## [1.0.2] - 2026-08-17

Admin CLI iteration.

### Added

- **`persea set-password --email <email>`** — reset an existing user's
  password from the server box. Validates the password policy (minimum
  length, reuse history) identically to the change-password API, updates
  the hash, records the reuse-history entry, and clears the
  failed-login lockout. `--password` for scripts, otherwise a hidden
  prompt; the password is never printed.
- **`persea unlock-user --email <email>`** — clear the failed-login
  lockout without changing the password (lockout-DoS recovery).

### Fixed

- `persea create-user` no longer echoes the plaintext password to
  stdout.

## [1.0.1] - 2026-08-16

Security and correctness release: the full 2026-08-14 review stack, new
logo, docs examples, CI/action and dependency updates.

### Added

- **New logo** — web UI (login page, favicons, live state-dot variant)
  and the inline sidebar/login art, from the new brand tile.
- **Deployment examples** — `docs/examples/`: docker-compose files for
  SQLite, PostgreSQL, and MySQL backends, a complete nginx reverse-proxy
  config (TLS termination, WebSocket upgrade headers), and a guided
  Let's Encrypt section with a SIGHUP renew hook that uses persea's TLS
  hot-reload.

### Fixed

- **TOTP MFA login was impossible**: the MFA page script was blocked by
  CSP (no nonce) and the fallback POST failed CSRF. Enrollment modes
  (AdminsOnly/All) are now actually enforced, and no session is minted
  before a verified factor.
- **SAML SSO was dead**: the ACS endpoint rejected every IdP POST
  (CSRF) and the login button hit a GET on a POST-only route. Also
  hardened: per-flow request IDs, consumed-assertion replay protection,
  a refusal to run `strict_mode=false` with a configured cert, a cap on
  the deflate-bomb decompression, per-IP ACS rate limiting, and
  audience/NotOnOrAfter/Recipient validation in strict mode.
- **Address-book ACL bypasses**: quick-connect skipped entry ACLs and
  RBAC Connect grants; folder ACL inheritance could open restricted
  parents; database-provider users were denied every folder; folder
  Connect grants now cascade to entries and subfolders; folder
  inheritance defaults to on for API-created folders.
- **Browser-session SSRF block inverted**: the Chromium `--host-rules`
  EXCLUDE re-enabled localhost and cloud-metadata access from web
  sessions; the metadata block now holds regardless of allowlist.
- **VDI**: home bind-mount path traversal via `container_username`;
  container-name collisions let colliding users reuse each other's
  containers; VDI thumbnail ownership now uses the container hash
  scheme.
- **Session takeover**: the WebSocket owner path checked role only, so
  any operator could hijack another user's pending/disconnected
  session. Ownership and session quotas are keyed on the stable
  identity (email/sub), not the display name.
- **Shadow (view-only) viewers could type and transfer files** from
  monitored sessions: input and file-transfer opcodes are now filtered
  and guacd joins shadow connections read-only.
- **Recordings**: an owner reconnect destroyed the previous segment
  (now appended); playback loaded whole files into RAM (now streamed);
  the streaming decrypt verifies the GCM tag before releasing any
  plaintext; audit-chain writes were serialized on the SQLx backends.
- **Reaping**: reconnectable Disconnected sessions were removed by the
  cleanup reaper; pending sessions that timed out stayed "active" in
  history forever; idle reaps recorded duration 0.
- **Session limits**: the global cap counted terminal states and raced
  concurrent creates; now counts only live sessions under the insert
  lock; the guacd handshake on session creation has a 15 s timeout.
- **XSS**: stored XSS in the audit-events fragment; template autoescape
  was disabled globally (site_title/logo_url/setup reflections); audit
  CSV exports lacked formula neutralization; backslash open redirects
  in `next`/RelayState are rejected.
- **Protocol framing**: lengths were byte-counted where guacd counts
  characters, mis-framing non-ASCII connect arguments.
- **Drive uploads**: slowloris body streams (now idle-timed) and a
  symlink-swap write (O_NOFOLLOW + fd verification).
- **Tunnels**: the documented OpenSSH public-key `host_key` never
  matched the fingerprint comparison; both formats are accepted now.
- **Connection details panel** showed raw backend enum values for RDP
  security mode, authentication package, folder scope, and the protocol
  badge; the edit modal's frontend names are shown instead.
- Stale `tailwind.min.css` (missing classes current templates use).

### Changed

- **Storage key required at startup**: the server refuses to run with
  the DB backend and no `[storage].encryption_key` / `PERSEA_STORAGE_KEY`
  (credentials would sit in plaintext). `install.sh` and the Docker
  entrypoint generate one; existing installs must add it (see
  deployment guide).
- **Session targets default to loopback-only** (`127.0.0.0/8`, `::1/128`)
  instead of all RFC1918 space, matching the documented default.
- `/api/connect` and `/auth/logout` are POST-only; logout is
  CSRF-protected.
- Cross-user reports/recordings exports are admin-only; powerusers see
  their own sessions.
- `/admin/*` page shells require the admin role; `/metrics` and
  `/api/docs` are admin-only.
- Auth-chain misconfiguration fails startup instead of silently falling
  back to database-only auth.
- VDI container names carry a per-user hash; jump-host chains are
  capped at 8 hops.
- Credential variables no longer fall back to plaintext reads; `--init`
  creates the static directory and hardens directory permissions;
  `generate-cert` chmods the TLS key 0600.
- Packaged config and DB files are no longer world-readable (0600/0640
  across deb, RPM, install.sh, install-release.sh, and the Docker
  entrypoint); the setup wizard preserves an existing storage key and
  writes one when absent; release tarballs ship the binaries, guacd,
  and install-release.sh; the Windows installer removes Users read
  access from ProgramData.
- The CSRF form-peek is capped at 64 KiB; `/api/me/password` is
  rate-limited; the RADIUS challenge store prunes expired entries.
- GitHub Actions bumped (`actions/setup-node` v7,
  `peter-evans/create-pull-request` v8); CI boot steps supply the
  storage key.
- Dependencies: `config` 0.15.25, `tokio-tungstenite` 0.30,
  `thiserror` 2.0.20, `async-trait` 0.1.92.

### Security

The fixes above close: stored XSS and CSV injection, CSRF gaps, the
inverted SSRF block, VDI path traversal, session hijacking, plaintext
credential fallbacks, LDAP user enumeration (uniform errors/timing),
non-constant-time comparisons (CSRF/OIDC state), OIDC fingerprint
spoofing via forwarded headers, RADIUS hostname misconfiguration, SAML
replay/identity-spoofing paths, the SAML deflate-bomb decompression,
shadow-viewer file exfiltration, backslash open redirects, and
world-readable config/DB files holding the storage encryption key.

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
  and package metadata follow; Ko-Fi and GitHub Sponsors funding links added.

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
  `persea-grove/persea-guacamole-server` (branch `persea-1.6.1-freerdp3`)
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
