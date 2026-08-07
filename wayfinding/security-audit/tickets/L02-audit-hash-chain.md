# Ticket: Audit hash-chain has no external anchor

wayfinder:task
Priority: P3
Phase: Low

## Finding

`src/audit.rs` — Hash-chain is tamper-*evident* only. DB-write access lets someone regenerate a valid chain forward from a tampering point. No external anchor or signature.

## Fix

This is a design limitation, not a bug. Document the limitation in the audit module docs and in `docs/deployment-guide.md`. For enterprise buyers, add a roadmap item for optional external anchoring (sign+ship chain heads to a separate system, or WORM storage).

Optional implementation: add a `rotate_anchor` function that exports the current chain head hash, signs it with a configurable key, and stores the signed anchor in a separate file/table. This is a feature, not a bug fix.

## Files

- `src/audit.rs` — documentation
- `docs/deployment-guide.md` — enterprise deployment notes

## Deliverable

Audit module docs explain tamper-evident vs tamper-proof. Deployment guide notes the limitation. `cargo check` passes.
