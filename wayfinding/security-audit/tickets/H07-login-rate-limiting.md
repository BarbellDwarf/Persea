# Ticket: No rate limiting or lockout on local/LDAP/RADIUS login + TOTP

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/main.rs:1810-1821` — `auth_pages` router (`/auth/login`, `/auth/mfa`) has no `GovernorLayer`, unlike OIDC routes (`1901-1916`, 1 req/s burst 5, IP-keyed). No failed-attempt counter exists in `db.rs`. Brute-force and TOTP guessing are possible.

## Overlap

**Existing ticket S03** (`security-hardening/tickets/S03-login-rate-limiting.md`) claims an always-on login rate limiter was added. Verify that S03 actually:
1. Applied `GovernorLayer` to `/auth/login` and `/auth/mfa` routes
2. Added a persistent failed-attempt counter with progressive lockout
3. The lockout applies to TOTP MFA (not just password)

If S03 only added rate limiting but not lockout, extend it. If S03 fully resolved this, mark as verified/duplicate.

## Files

- `src/main.rs:1810-1821` — `auth_pages` router
- `src/db.rs` — failed-attempt counter (if needed)
- `src/auth_pages.rs` — login/MFA handlers

## Deliverable

`/auth/login` and `/auth/mfa` have always-on rate limiting. Failed-attempt counter with progressive lockout (e.g., 5 failures → 15min lock, 10 failures → 1hr lock). TOTP attempts counted separately. `cargo check` passes.
