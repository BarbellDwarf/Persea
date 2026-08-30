# persea v1.1.1

persea v1.1.1 is a security and correctness release: force-logout now invalidates all of a user's tokens, quick-connect links work for all entry types, and session counters are consistent across every page.

## Highlights

**Security: force-logout closes the token gap**

When an admin force-logs out a user, all of that user's API tokens — including scoped desktop tokens — are now revoked immediately. A dedicated audit event is written. Before this fix, a force-logout ended the sessions but left tokens valid, allowing reconnection without re-authentication.

**Quick-connect works for all entry types**

Spice, Proxmox, and VDI address-book entries now open successfully from quick-connect links. A parameter mismatch between the quick-connect surface and the full connect path caused an HTTP 400 "Unknown session type" error. Both paths now construct session parameters identically.

**Session counts are consistent everywhere**

The active-session counts on the Reports, Connections, and Sessions pages now agree. Stale "active" rows left behind by service restarts or crashes are closed on shutdown and swept at startup.

**Audit log improvements**

The admin Audit Log now shows usernames instead of numeric IDs, human-readable timestamps, and structured detail rows. CSV exports include a username column.

**Settings flag reads halved**

Every authenticated API request that needs to check a system setting (such as whether a feature is enabled) no longer queries the database twice for that flag. The value is cached in memory per instance. Note: in multi-instance (HA) deployments, flag changes propagate to other instances on their restart rather than immediately.

## Fixed

- Force-logout now revokes all user API tokens and writes a dedicated audit event (#270)
- Quick-connect links for Spice, Proxmox, and VDI entries return HTTP 200 instead of HTTP 400 (#280)
- Active-session counts are consistent across Reports, Connections, and Sessions pages (#273)
- Storage-key bootstrap is consolidated into one `persea ensure-storage-key` subcommand; install.sh, Docker entrypoint, install-release.sh, and RPM/deb postinsts all call it — no more first-boot crash loops from duplicate keys (#271)
- API-key path no longer reads system_settings twice per request (#276)

## Upgrade notes

- No schema migrations required; existing databases upgrade in place on first start.
- No config migration required; storage-key handling is fully backward-compatible.
- The new `persea ensure-storage-key` CLI subcommand is called automatically by all official installers; no manual action needed.


# persea v1.1.0

persea v1.1.0 is a large UI and enterprise release: a redesigned web UI, scoped API tokens, LDAP login fixes, session credential forwarding, and PowerShell remoting over SSH.

## New

### Web UI refresh

- **Redesigned connections page**: folder tree with a details panel, inline connect, and a consolidated top bar for search, view, and actions.
- **Left-rail navigation everywhere**, including Security and My Profile sections that previously used stacked cards. Sidebar collapses to icons.
- **Settings reorganized** into a tabbed layout with a storage tab, and tabs scroll horizontally on narrow screens without jumping the page.
- **Entry modal polish** and a design-consistency pass across buttons, modals, tables, and forms.
- **Auto-size**: the client requests a resize matched to the local viewport, with server-side support.
- **Personal folders**: users can organize their own connections with a per-user folder schema, API, and UI.
- **Security center**: dedicated security page with admin sections for lockouts, sessions, and audit verification; RDP security defaults are configurable per connection.
- **User management**: admins edit users in place, and every user gets profile self-service (name, password change, TOTP enrollment).
- **Docs page**: all guides render in-app with working heading anchors, a two-level collapsible nav menu, cross-page links, and full-width content.
- **Recordings**: seeking jumps directly to the requested position instead of replaying the timeline.
- Refreshed canonical screenshots throughout the docs.

### Scoped API tokens

API tokens minted from an interactive login can now carry far less standing risk:

- **Issuance after interactive login** (`stack/scoped-token`): a browser session can request a token scoped to chosen permissions with an expiry, instead of reusing a long-lived secret.
- **LDAP re-validation**: tokens for LDAP-backed accounts re-check the directory account state, so disabling a user cuts token access too.
- **Compliance mode**: an instance setting that forbids long-lived tokens entirely for environments that require interactive-only access.
- **Session continuity**: invalidating a user's sessions invalidates their derived tokens, closing the "logged out but token still works" gap.

### Session credential forwarding

- **Transient encrypted credential forwarding** (opt-in via `[auth] forward_session_credentials`): credentials entered at connect time live only for the session's lifetime, encrypted at rest, so reconnects do not need re-entry.
- **Connect fallback ordering and auth-failure classification**: when guacd reports an authentication failure (status 1006/769), the server classifies it and the web client prompts for credentials instead of surfacing a raw disconnect.

### Remote access

- **PowerShell remoting over SSH**: Windows targets execute PowerShell through the SSH channel, with command execution surfaced in the session UI.
- **LDAP login hardening**: user resolution walks the configured auth chain (DN-aware lookup) instead of assuming a single bind pattern, and group memberships discovered at login are recorded on the user record for RBAC.

## Fixed

- **Docker docs build**: `build.rs` sees `docs/` inside the dependency-cache stage, so documentation builds no longer break container images.
- **`.deb` staging path**: composite build action translates runner paths for container jobs; package assembly no longer fails on path translation.
- **SAML login button**: tolerant flag deserializer (serde_urlencoded rejected `"1"` for booleans) restores IdP-initiated login.
- **Tab-scroll jump**: switching settings tabs no longer scrolls the page.
- **Recording seek restore**: aborted seeks restore the display stream cleanly.

## Platform

- Advanced CodeQL workflow with full-coverage Rust scanning; dependency bumps across the tree including `h2` 0.4.16.
- Multi-backend tests (MySQL, PostgreSQL, SQLite) run per pull request, plus an OpenLDAP integration harness for auth tests.

## Upgrade notes

- New optional config: `[auth] forward_session_credentials` (default off), `compliance_mode` system setting, `[auth.totp] enforcement`.
- No schema-breaking migrations; existing databases upgrade in place on first start.
