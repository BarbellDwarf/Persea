# Ticket: M04 gap — SSH TOFU completely untouched

wayfinder:task
Priority: P2
Phase: Medium

## Gap

- `src/tunnel.rs:130-146` (`check_server_key`) still unconditionally accepts any unpinned host key with only a `warn!`
- `src/session/create.rs:107` constructs jump hosts with `host_key: None` for legacy path

## Fix

Implement real trust-on-first-use:
1. On first connect: accept key, persist it (known_hosts file or database)
2. On subsequent connects: compare presented key against pinned key — hard-fail on mismatch
3. Expose "Verify Host Key" UI action that pins/unpins keys

## Files

- `src/tunnel.rs:130-146` — `check_server_key`
- `src/session/create.rs:107` — jump host construction

## Deliverable

First connection pins key automatically. Subsequent connections verify against pinned key. Mismatch = hard failure. `cargo check` passes.
