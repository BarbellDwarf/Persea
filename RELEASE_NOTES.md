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
