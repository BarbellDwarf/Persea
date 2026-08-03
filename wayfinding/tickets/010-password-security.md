# Ticket: Password Security

wayfinder:research
Blocked by: 003 (Auth DB Schema), 004 (Database Auth)

## Question

How should persea implement enterprise password security?

NIST 800-63B Rev 4 (finalized 2025) sets the standard. Password policies must balance security with usability.

Key decisions needed:

1. **Hashing** — Argon2id (RustCrypto `argon2` crate). Default parameters: 19 MiB memory, 2 iterations, 1 parallelism. Confirm.
2. **Minimum length** — 15 chars when password is sole authenticator, 8 chars with MFA (NIST).
3. **Complexity** — No forced composition rules (NIST). But support optional complexity config for compliance frameworks that still require it.
4. **Breach screening** — HIBP k-anonymity API: SHA-1 prefix → API check → local suffix match. Block breached passwords.
5. **Password history** — Remember 24 passwords (CIS). Store hashes in `password_history` table. Prevent reuse.
6. **Lockout** — Progressive delay: 30s → 5min → 30min after 5 failed attempts. Not permanent.
7. **Expiry** — Configurable. NIST says no forced rotation. But make it optional for compliance.
8. **Password change** — Self-service with old password verification. Admin reset without old password.
9. **Banned password list** — Block common passwords ("password", "123456", company name, username). Optional config.

## Research needed

- Argon2id recommended parameters (memory, iterations, parallelism)
- HIBP k-anonymity API implementation
- NIST 800-63B Rev 4 final requirements
- Apache Guacamole's password policy configuration
