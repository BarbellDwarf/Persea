# Ticket: SSH TOFU host-key acceptance — no enforcement

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/tunnel.rs:137-146` — Accepts any unpinned host key with only a `warn!` log. Pinning is a manual, opt-in "Verify Host Key" UI action, never enforced. Users can connect to any host without verifying its identity.

## Fix

Two options:

1. **Fail closed on first use**: Require explicit host-key pinning before first connect. The first connection to a new host returns an error with the host key fingerprint, and the user must confirm via a "Verify Host Key" button before the connection proceeds.
2. **UI warning banner** (minimum fix): On every unpinned connection, show a prominent warning banner at the top of the session: "⚠️ Host key not verified — this connection may be intercepted." The banner persists until the user clicks "Verify."

Option 1 is stronger. Option 2 is a pragmatic minimum.

## Files

- `src/tunnel.rs:137-146` — host-key acceptance

## Deliverable

Unpinned host keys require explicit user confirmation before connecting, OR a persistent warning banner is shown. `cargo check` passes.
