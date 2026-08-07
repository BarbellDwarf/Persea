# Map: Enterprise Security Hardening + Session Responsiveness

## Destination

Eliminate known vulnerabilities, close auth/session/crypto weaknesses, bring all dependencies to current releases, and improve RDP/SSH session responsiveness — enough that the app is auditable without a penetration test finding the basics.

## Notes

- Rust/Axum 1.x + SQLite. guacd handles protocol translation; persea is the web frontend and session manager.
- Threat model: multi-tenant enterprise with OIDC/LDAP users, Vault or DB credential storage, recording, VDI.
- Security findings from full code audit: 0 Critical, 0 High in app code; 5 Medium, 7 Low. Transitive deps: 2 HIGH CVEs (russh).
- Responsiveness: biggest wins are H.264 default, async DB writes, BytesMut carry buffer.

## Decisions so far

- All 26 tickets implemented and verified. Each has a git commit on the 1.1.0 branch.
- CSP nonce wired into all inline scripts across 18 template files + CSRF body fallback for remote devices.
- Dark/light/auto mode toggle applies actual theme colors via CSS variables.
- Admin settings: feature toggles for every protocol (RDP, SSH Tunnels, API Keys, Recordings, Web, VDI, Proxmox, VMware).
- Connections page: sidebar folders, 320px detail panel, full-width entries, collapsible nav sidebar.
- Recordings: CSP-compliant player (event delegation), protocol/duration/date fixes, verified with 1.2MB RDP recording.
- Reports: Top Connections/Users rendered as proper tables, activity chart, CSV export.
- Auth: all protected pages require login; docs protected; logout available for all auth methods.

## Not yet specified

(none — all tickets resolved)

## Out of scope

- Full penetration test (requires external scope + test environment)
- OWASP Top 10 compliance certification (audit, not cert)
- Infrastructure hardening (Docker/OS-level — outside persea's repo)
- Performance work beyond the proxy/session-creation path (guacd internals, target server tuning)
