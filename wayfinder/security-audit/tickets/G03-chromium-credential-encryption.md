# Ticket: H09 gap — Chromium credential "encryption" still uses public key

wayfinder:task
Priority: P1
Phase: High

## Gap

Prior fix only added `--disable-autofill` (disables form-autofill for addresses/payments), not the password-manager Login Data store this finding is about.

- `src/browser.rs:621-644` (`encrypt_chromium_password`) still uses `PBKDF2("peanuts","saltysalt",1,SHA1)` + fixed IV
- Still actively called from `populate_login_data` / `BrowserManager::spawn`

## Fix (choose one)

1. **Stop populating Login Data entirely** — don't call `populate_login_data` for VDI sessions. Users enter credentials manually. Appropriate for ephemeral sessions.
2. **Encrypt profile directory** — before Chromium touches it, encrypt entire ephemeral profile with app's AES-256-GCM key (`src/crypto.rs`). Decrypt on session start, re-encrypt on session end.

## Files

- `src/browser.rs:621-644` — `encrypt_chromium_password`
- `src/browser.rs` — `populate_login_data` / `BrowserManager::spawn`

## Deliverable

Chromium no longer stores credentials using public fallback key, OR profile directory encrypted at rest. `cargo check` passes. VDI sessions still work.
