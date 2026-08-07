# Ticket: Upgrade russh (HIGH CVEs)

wayfinder:task
Priority: P0

## Question

russh has two HIGH-severity RustSec advisories (RUSTSEC-2026-0154 and RUSTSEC-2026-0153): unbounded 32-bit allocation in SSH packet handling and unchecked CryptoVec allocation growth. Both allow OOM via malformed SSH packets. russh is used for SSH tunneling (jump hosts).

Upgrade russh to the latest patched version. Verify that `cargo audit` clears both advisories after the upgrade. Run `cargo check` and `cargo test` to confirm nothing breaks.

## Deliverable

Updated Cargo.lock with patched russh. `cargo audit` output showing zero HIGH findings for russh. All tests pass.
