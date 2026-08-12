# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!--
Release checklist (delete this comment before tagging v1.1.1):
- [ ] Enterprise HA lands — amend "High availability" entries below
- [ ] `cargo test` + `cargo fmt --check` green on the final commit
- [ ] CI green for the final push (`gh run list`)
- [ ] Tag `v1.1.1` (annotated) and push it
- [ ] Regenerate Playwright visual snapshots (connections page changed)
- [ ] Re-run Playwright E2E suite (`tests/playwright`)
- [ ] Update `screenshots/screenshots.md` if the new connections UI is captured there
- [ ] Bump the asset cache-bust version in `templates/base.html` if more static files change
- [ ] Push the beta image (`gh workflow run beta.yml --ref v1.1.1`) after the tag
-->

## [1.1.1] - 2026-08-12

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

- **License: Apache 2.0 → AGPL-3.0** — persea is dual-licensed under
  AGPL-3.0 (open source) with a commercial license exception. See
  [LICENSE](LICENSE), [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md), and
  [CLA.md](CLA.md). All contributors must sign the CLA.
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
- **License gates live** — SAML, TOTP enforcement, RBAC, audit-retention
  export, and encrypted recordings are enforced via the enterprise license;
  the admin license API/page manages keys. (HA gate `FEAT_HA` lands with
  the enterprise HA work.)

### Enterprise licensing

- License keys (`PSEA-...`, Ed25519-signed) validate at startup and gate
  enterprise features; evaluation period included; the admin License page
  shows status and accepts keys. Validation is covered by 14 unit tests
  (tamper, expiry, wrong-key, feature checks).

## [1.1.0] - 2026-08-09

### Added

- **Release hardening**
