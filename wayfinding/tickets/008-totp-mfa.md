# Ticket: TOTP MFA

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture), 004 (Database Auth — needs user table)

## Question

How should persea implement TOTP-based multi-factor authentication?

TOTP is the baseline MFA for enterprise. Users enroll by scanning a QR code, then enter a 6-digit code on login. TOTP secrets are stored locally in the DB regardless of auth source (LDAP users still need local TOTP storage).

Key decisions needed:

1. **TOTP crate** — `totp-rs` (feature-complete: SHA-256/512, QR codes, Steam, skew window). Confirm.
2. **Enrollment flow** — Generate random 160-bit secret → base32 encode → `otpauth://` URI → render QR. User confirms with valid code.
3. **Recovery codes** — Generate 10-12 one-time-use codes, SHA-256 hash, store hashed. Guacamole doesn't have recovery codes — should we?
4. **Configuration** — Issuer name, digits (6/7/8), period (30s), algorithm (SHA-1/256/512).
5. **Clock drift** — Allow ±1 timestep skew for verification.
6. **Admin controls** — Admin can reset TOTP secret, disable TOTP for a user.
7. **Per-user enforcement** — Configurable: optional for all, required for admins, required for all.
8. **QR code rendering** — Server-side SVG/PNG generation? Or client-side JavaScript?
9. **Multiple devices** — Allow multiple TOTP registrations per user (phone + hardware token)?

## Research needed

- `totp-rs` crate API and QR code generation
- RFC 6238 TOTP implementation requirements
- Recovery code patterns (Generate, hash, store, verify)
- Apache Guacamole's TOTP implementation
