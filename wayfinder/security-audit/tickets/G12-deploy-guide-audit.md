# Ticket: L02 gap — Deployment guide needs audit limitation notes

wayfinder:task
Priority: P3
Phase: Low

## Gap

`src/audit.rs` module docs done (lines 1-21). `docs/deployment-guide.md` untouched.

## Fix

Add section to `docs/deployment-guide.md` covering:
- Audit hash chain is tamper-EVIDENT, not tamper-PROOF
- DB-write access allows regenerating valid chain from tampering point
- Recommended compensating controls: external anchoring (sign chain heads), SIEM streaming, WORM storage

## Files

- `docs/deployment-guide.md`

## Deliverable

Deployment guide documents audit limitations and compensating controls.
