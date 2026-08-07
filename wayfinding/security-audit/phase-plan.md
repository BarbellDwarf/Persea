# Phase Plan — Security Audit Remediation

## Phase 1 — Critical (P0)

| Ticket | Files | Can parallel? |
|--------|-------|---------------|
| C01: Admin users XSS | `templates/pages/admin/users.html` | Yes (disjoint) |
| C02: SAML canonicalization | `src/auth_providers/saml.rs` | Yes |
| C03: vSphere power_action | `src/api/vsphere.rs`, `src/vsphere.rs`, `src/main.rs` | Yes |

All 3 can run in parallel — disjoint files.

## Phase 2 — High (P1)

| Ticket | Files | Can parallel? |
|--------|-------|---------------|
| H04: CSP nonce + SRI | `src/main.rs`, `templates/layouts/base.html`, all templates | Depends on S01 verification |
| H05: Proxmox SSRF | `src/session/create.rs`, `src/api/sessions.rs` | Depends on S02 verification |
| H06: Docker TLS key | `Dockerfile`, entrypoint script | Yes (disjoint) |
| H07: Rate limiting | `src/main.rs`, `src/auth_pages.rs`, `src/db.rs` | Depends on S03 verification |
| H08: Credential encryption | `src/main.rs`, `src/api/address_book.rs` | Yes (disjoint) |
| H09: Chromium credentials | `src/browser.rs` | Yes |
| H10: Recording encryption | `src/recording.rs`, `src/crypto.rs`, `src/api/recordings.rs` | Yes |
| H11: CSV injection | `src/db.rs`, `src/api/reports.rs` | Yes |

H04/H05/H07 need S01/S02/S03 verification first (check if already fixed).
H06/H08/H09/H10/H11 are independent — can run in parallel.
H11 and M03 both touch `src/error.rs` — run sequentially or coordinate.

## Phase 3 — Medium (P2)

| Ticket | Files | Can parallel? |
|--------|-------|---------------|
| M01: LDAP injection | `src/auth_providers/ldap.rs` | Yes (disjoint) |
| M02: Fail-open role checks | `src/api/users.rs`, `src/api/reports.rs` | Yes |
| M03: Error message leaks | `src/error.rs` | After H11 (same file) |
| M04: SSH TOFU | `src/tunnel.rs` | Yes |
| M05: Chromium sandbox | `src/browser.rs`, `Dockerfile` | After H09 (same file) |
| M06: Browser URL allowlist | `src/browser.rs`, `src/session/create.rs` | After M05 (same file) |
| M07: RADIUS constant-time | `src/auth_providers/radius.rs` | Yes |

M05/M06 chain on H09 (browser.rs). M03 chains on H11 (error.rs not touched by H11, but db.rs is). Run M01/M02/M04/M07 in parallel, then M03/M05/M06.

## Phase 4 — Low (P3)

| Ticket | Files | Can parallel? |
|--------|-------|---------------|
| L01: Recording retention | `src/config.rs`, `config.example.toml` | Yes |
| L02: Audit hash-chain docs | `src/audit.rs`, `docs/deployment-guide.md` | Yes |
| L03: Dead code removal | `src/db_migrate.rs` | Yes |
| L04: Regression tests | `tests/` | After all fixes (tests reference fixed code) |
| L05: Cargo audit | `.cargo/audit.toml` | Yes |

L01/L02/L03/L05 can run in parallel. L04 waits for all fixes.

## Verification overlap — existing security-hardening tickets

These existing tickets on 1.1.0 may already address the finding. **Verify before implementing:**

| Finding | Existing ticket | What to check |
|---------|-----------------|---------------|
| H04: CSP nonce | S01-csp-nonce-wiring.md | Was `'unsafe-inline'` removed? Do all scripts have nonces? |
| H05: Proxmox SSRF | S02-proxmox-url-validation.md | Is `check_allowed_network` applied to `proxmox_url`? |
| H07: Rate limiting | S03-login-rate-limiting.md | Is GovernorLayer on `/auth/login`? Is there lockout? |
| M03: Error leaks | S05-error-message-sanitization.md | Does `AppError::Internal` return generic text? |

If verified as fixed → skip the ticket. If incomplete → fix the gaps.

## Agent assignments

| Agent | Phase | Tickets | Constraint |
|-------|-------|---------|------------|
| A | 1 | C01 + C02 + C03 | Parallel, disjoint files |
| B | 2 (verify) | S01/S02/S03/S05 verification | Must run first to skip/keep H04/H05/H07/M03 |
| C | 2 (independent) | H06 + H08 + H10 + H11 | Parallel with B |
| D | 2 (browser) | H09 | After B clears H04 |
| E | 3 | M01 + M02 + M04 + M07 | Parallel, disjoint files |
| F | 3 (browser) | M05 + M06 | After H09 |
| G | 4 | L01 + L02 + L03 + L05 | Parallel |
| H | 4 (tests) | L04 | After all fixes |
