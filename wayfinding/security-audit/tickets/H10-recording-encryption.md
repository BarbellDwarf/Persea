# Ticket: Session recordings stored unencrypted at rest

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/recording.rs` — `.guac` files capture full session content (typed passwords, viewed documents) as plaintext. No encryption anywhere. Readable by anyone with filesystem/backup access.

## Fix

Encrypt recordings at rest using the existing `src/crypto.rs` AES-256-GCM primitive. Implementation:

1. On recording finalize (`recording.rs` — the `finalize` method), encrypt the `.guac` file contents with AES-256-GCM using the storage encryption key. Write to a `.guac.enc` file, delete the plaintext `.guac`.
2. On playback (`recordings` API), decrypt the `.guac.enc` file in memory before streaming to the Guacamole client.
3. Add a config option `[recording] encrypt_at_rest = true` (default: true when encryption key is set).
4. Handle migration: if old plaintext recordings exist, they remain readable but new ones are encrypted.

## Files

- `src/recording.rs` — finalize + playback
- `src/crypto.rs` — existing AES-256-GCM primitives
- `src/api/recordings.rs` — playback endpoint

## Deliverable

New recordings encrypted at rest. Playback decrypts transparently. Old recordings still readable. `cargo check` passes. Config option documented.
