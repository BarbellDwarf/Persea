# Ticket: Chromium "encrypted" credentials use public fallback key

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/browser.rs:608-632` — `encrypt_chromium_password` uses PBKDF2("peanuts", "saltysalt", 1, SHA1) + all-zero IV — Chromium's own published Linux fallback scheme. Effectively plaintext to anyone with profile-directory/backup access.

## Fix

Don't rely on Chromium's `os_crypt` fallback. Options:

1. **Disable autofill for sensitive fields**: Set `--disable-autofill` or `--password-store=basic` to prevent Chromium from storing credentials at all. VDI sessions are ephemeral — autofill is a liability, not a feature.
2. **Protect the profile directory**: Before Chromium touches it, encrypt the entire profile directory with the app's own AES-256-GCM key (from `src/crypto.rs`). Decrypt on session start, re-encrypt on session end. This protects all Chromium state, not just passwords.
3. **Use the OS keyring**: If running as a non-root user, Chromium can use libsecret/KWallet. But this requires the container to have keyring access.

Option 1 is simplest and most appropriate for ephemeral VDI sessions.

## Files

- `src/browser.rs:608-632` — `encrypt_chromium_password`

## Deliverable

Chromium autofill credential storage disabled for VDI sessions, OR profile directory encrypted at rest. `cargo check` passes. Chromium still functions normally for browsing.
