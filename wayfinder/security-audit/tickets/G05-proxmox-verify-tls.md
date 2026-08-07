# Ticket: H05 gap — Proxmox verify_tls defaults false

wayfinder:task
Priority: P1
Phase: High

## Gap

Network allowlist correctly wired. Only remaining gap:

`src/session/create.rs:455`:
```rust
let broker_verify = proxmox_verify_tls.unwrap_or(false); // still false
```

## Fix

Change to `unwrap_or(true)`. Require explicit opt-out for TLS verification.

## Files

- `src/session/create.rs:455`

## Deliverable

Proxmox TLS verification defaults to true. `cargo check` passes.
