# Ticket: RADIUS Auth Method

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture)

## Question

How should persea implement RADIUS authentication?

RADIUS is standard in enterprise network environments. It delegates authentication to a RADIUS server (often FreeRADIUS or NPS), which typically wraps TOTP/MFA. persea sends Access-Request and handles Access-Accept/Reject/Challenge.

Key decisions needed:

1. **RADIUS crate** — `radius-tokio` (Tokio-native, EAP support via companion crate) vs `radius-rs` (simpler, PAP/CHAP only). Enterprise needs EAP (PEAP, EAP-TTLS).
2. **Protocol support** — PAP (minimum), CHAP, MSCHAPv2, EAP-TTLS, EAP-TLS. Which to implement?
3. **RADIUS attributes sent** — User-Name, User-Password, NAS-IP-Address, NAS-Port. Configurable NAS-IP?
4. **Challenge/response** — When RADIUS sends Access-Challenge, present prompt to user (for MFA). How does this work in the web UI?
5. **Shared secret management** — Stored in config or DB? Encrypted?
6. **Timeout/retry** — Configurable timeout (default 60s) and retries (default 5).
7. **TLS for RADIUS** — RadSec (RADIUS over TLS) support? `radius-tokio` supports it.
8. **Dual role** — RADIUS can act as primary auth (full delegation) or as second factor (after LDAP/DB). Config-driven.

## Research needed

- `radius-tokio` crate API and EAP companion
- RADIUS protocol: Access-Request/Response, Challenge handling
- Apache Guacamole's RADIUS extension
- FreeRADIUS configuration for Guacamole-style integration
