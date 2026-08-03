# Ticket: Database Auth Method

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture)

## Question

How should persea implement database-backed authentication with enterprise password policies?

This is the foundation auth method — local username/password stored in the DB. It supports TOTP enrollment (MFA requires a local account) and serves as fallback when no external IdP is available.

Key decisions needed:

1. **Password hashing** — Argon2id via RustCrypto `argon2` crate (NIST 800-63B recommended). Default parameters?
2. **Password policies** — Minimum length (15 chars NIST), complexity rules (NIST says no forced composition), breach screening (HIBP k-anonymity), history tracking (24 passwords per CIS).
3. **Account lockout** — Progressive delay (30s → 5min → 30min) after 5 failed attempts (CIS). Not permanent lockout.
4. **Password expiry** — NIST says no forced rotation. But some compliance frameworks require it. Make configurable.
5. **Password change flow** — Users can change own password. Admins can reset. Must verify old password for self-change.
6. **Auto-create accounts** — When SSO (OIDC/SAML) authenticates a user, auto-create a DB record for TOTP storage and permission management.

## Research needed

- Argon2id recommended parameters (memory, iterations, parallelism)
- HIBP k-anonymity API implementation pattern
- NIST 800-63B Rev 4 password requirements (finalized 2025)
- Apache Guacamole's password policy implementation
