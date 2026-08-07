# Ticket: Credential encryption-at-rest is opt-in, not mandatory

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/main.rs:357-367` — Only warns to stderr if `[storage].encryption_key` / `PERSEA_STORAGE_KEY` is unset. Credentials are then stored plaintext (`src/api/address_book.rs:544-563`). The hard-fail behavior for a malformed key (`main.rs:370-377`) exists but doesn't apply to the missing-key case.

## Fix

Refuse to start (or refuse to persist connection credentials) when no encryption key is configured. Two options:

1. **Hard fail on startup**: If no encryption key is set, print an error and exit with code 1. Match the existing behavior for malformed keys.
2. **Soft fail with block**: Allow the server to start but block any `POST`/`PUT` to the address book that would store credentials. Return a clear error: "Encryption key required. Set `[storage].encryption_key` or `PERSEA_STORAGE_KEY`."

Option 1 is simpler and safer. Option 2 allows read-only access to existing data.

## Files

- `src/main.rs:357-367` — encryption key check
- `src/api/address_book.rs:544-563` — credential storage

## Deliverable

Server refuses to start without an encryption key, OR blocks credential storage without one. `cargo check` passes. Startup without key produces clear error message.
