# Map: Enterprise Security Hardening + Session Responsiveness

## Destination

Eliminate injection vectors, close auth/session/crypto weaknesses, bring all dependencies to current releases, and measure+improve RDP/SSH session responsiveness — enough that the app is auditable without a penetration test finding the basics.

## Notes

- Rust/Axum 1.x + SQLite today. guacd handles protocol translation; persea is the web frontend and session manager.
- Threat model: multi-tenant enterprise with OIDC/LDAP users, Vault or DB credential storage, recording, and VDI.
- stop-slop: all prose in this map's tickets and reports stays direct. No adverbs, no filler phrases, no passive voice.

## Decisions so far

- **Conditional Secure cookies** — Session cookies set `Secure` only when TLS is in play (`X-Forwarded-Proto: https`). Allows plain-HTTP LAN access while keeping the flag in production. Implemented across login, OIDC, MFA, and logout flows. Verified: cookies served without `Secure` over plain HTTP, login works from LAN IP.
- **Persea branding capitalization** — All user-facing "persea" corrected to "Persea". TOTP issuer, sidebar, login, docs, config defaults all updated.
- **Proxmox token validation** — Server-side rejects empty token ID / secret with a clear message before calling the PVE API, eliminating the raw 401 for malformed entries.
- **RDP ignore_cert UI** — Entry form now includes "Ignore TLS certificate errors" for RDP/SPICE types. Wired through `build_protocol_config` → `CreateSessionRequest` → guacd `ignore-cert`. Verified: TLS error eliminated for self-signed cert; connection advances to authentication.
- **Error visibility** — `lastSessionError` captures the guacd error instruction message and surfaces it in the Session Ended overlay for all end states (completed, error, expired), not just the `error` status. Verified: "Authentication failure (invalid credentials?)" now visible to the user.

## Not yet specified

- SQL injection audit scope — parameterized queries vs string interpolation across all handlers
- XSS audit — template rendering, JSON responses, error messages containing user input
- SSRF vectors — user-supplied URLs in Web/Proxmox entries, jump host targets
- Rate limiting gaps — login brute force, API token enumeration, session fixation vectors
- WebSocket auth timing — window between ticket mint and WS connection
- Session recording security — who can view recordings, retention, access control on playback endpoint
- Dependency audit surface — which crates are outdated, which have known CVEs

## Out of scope

- Full penetration test (requires external scope + test environment)
- OWASP Top 10 compliance certification (audit, not cert)
- Infrastructure hardening (Docker/OS-level — outside persea's repo)
