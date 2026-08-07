# Ticket: Dead code in db_migrate.rs — plaintext fallback on encryption failure

wayfinder:task
Priority: P3
Phase: Low

## Finding

`src/db_migrate.rs:391-410` — `serialize_entry_params` has a plaintext-fallback-on-encryption-failure branch. The function is dead code (never called — the live path `insert_ab_entry` correctly propagates errors).

## Fix

Delete `serialize_entry_params` entirely. If it's ever wired in, the failure path should hard-error instead of falling back to plaintext.

## Files

- `src/db_migrate.rs:391-410`

## Deliverable

Dead function removed. `cargo check` passes. No references to the function anywhere in the codebase.
