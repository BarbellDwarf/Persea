# Ticket: Upgrade totp-rs (MEDIUM CVE)

wayfinder:task
Priority: P0

## Question

totp-rs has RUSTSEC-2022-0018: timing attack vulnerability in TOTP comparison. persea uses totp-rs for MFA.

Upgrade totp-rs to >= 5.5.0 (or latest 5.x). Verify `cargo audit` clears. Run MFA-related tests.

## Deliverable

Updated Cargo.lock. Zero totp-rs advisories. MFA tests pass.
