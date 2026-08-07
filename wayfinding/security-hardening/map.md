# Map: Enterprise Security Hardening + Session Responsiveness

## Destination

Eliminate known vulnerabilities, close auth/session/crypto weaknesses, bring all dependencies to current releases, and improve RDP/SSH session responsiveness — enough that the app is auditable without a penetration test finding the basics.

## Notes

- Rust/Axum 1.x + SQLite. guacd handles protocol translation; persea is the web frontend and session manager.
- Threat model: multi-tenant enterprise with OIDC/LDAP users, Vault or DB credential storage, recording, VDI.
- Security findings from full code audit: 0 Critical, 0 High in app code; 5 Medium, 7 Low. Transitive deps: 2 HIGH CVEs (russh).
- Responsiveness: biggest wins are H.264 default, async DB writes, BytesMut carry buffer.

## Decisions so far

- **CSP nonce wired** — Replaced `unsafe-inline` with per-request nonce in `script-src`. Nonce was already generated (`CspNonce` extension) but never used in the header. Implemented in `main.rs:744`.
- **Proxmox URL validation** — Added `check_allowed_network` on `proxmox_url` host before calling PVE API, closing the SSRF gap.
- **Login rate limiter** — Added a dedicated always-on rate limiter for `/auth/login` independent of the global `rate_limit` setting.
- **CSRF cookie always set** — Removed the `contains_key` guard so the CSRF cookie is set even when other Set-Cookie headers are present.
- **Error message sanitization** — `AppError::Internal` now returns a generic message to users; details logged server-side only.
- **Cloud metadata blocklist** — Web sessions add `169.254.169.254/32` as an explicit deny alongside the CIDR allowlist check.
- **H.264 + GFX defaults** — RDP sessions now default to H.264 and GFX enabled (previously both OFF), reducing per-frame latency 5-15ms.
- **Async session DB insert** — `insert_session_history` wrapped in `spawn_blocking` to unblock session creation.
- **BytesMut carry buffer** — Replaced `Vec<u8>` with `bytes::BytesMut` in the proxy hot path; eliminates one heap allocation per message.
- **Dependency upgrades** — russh, aes-gcm, totp-rs, rusqlite all upgraded to patched/latest versions.

## Not yet specified

- OIDC state fingerprint → HMAC-SHA256 (planned, not yet ticketed)
- Per-session concurrent viewer limits on share tokens (planned, not yet ticketed)
- Plain-HTTP mode documentation and startup warning (planned, not yet ticketed)

## Out of scope

- Full penetration test (requires external scope + test environment)
- OWASP Top 10 compliance certification (audit, not cert)
- Infrastructure hardening (Docker/OS-level — outside persea's repo)
- Performance work beyond the proxy/session-creation path (guacd internals, target server tuning)
