# Ticket: RADIUS response-authenticator comparison not constant-time

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/auth_providers/radius.rs:231` — Uses plain slice equality for response-authenticator comparison. The rest of the codebase uses `subtle::ConstantTimeEq` (e.g., `session/mod.rs` for token comparison). Low real-world exploitability over UDP timing, but inconsistency is a code-quality issue.

## Fix

Swap in `subtle::ConstantTimeEq`:
```rust
use subtle::ConstantTimeEq;
if response_authenticator.ct_eq(&expected).into() {
    // valid
}
```

## Files

- `src/auth_providers/radius.rs:231`

## Deliverable

RADIUS comparison uses constant-time comparison. `cargo check` passes.
