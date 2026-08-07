# Ticket: M07 gap — RADIUS constant-time comparison untouched

wayfinder:task
Priority: P2
Phase: Medium

## Gap

`src/auth_providers/radius.rs:231` still uses plain equality:
```rust
computed[..] == response[4..20]  // NOT constant-time
```

The `subtle` crate is already a dependency and used elsewhere.

## Fix

```rust
use subtle::ConstantTimeEq;
computed[..].ct_eq(&response[4..20]).into()
```

## Files

- `src/auth_providers/radius.rs:231`

## Deliverable

RADIUS comparison uses constant-time comparison. `cargo check` passes.
