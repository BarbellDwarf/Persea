# Ticket: Verify RUSTSEC advisories in .cargo/audit.toml

wayfinder:task
Priority: P3
Phase: Low

## Finding

`.cargo/audit.toml` ignores two RUSTSEC advisories (rsa Marvin timing side-channel via `openidconnect`/`russh`, unmaintained `rustls-pemfile`). Need to verify the documented rationale still holds and confirm `cargo audit`/`cargo clippy` run clean in CI.

## Fix

1. Run `cargo audit` and verify the ignored advisories still have the documented rationale
2. Run `cargo clippy` and confirm clean
3. If the advisories are now fixed (new crate versions), remove them from `audit.toml`
4. If not fixed, verify the ignore reasons are still valid

## Files

- `.cargo/audit.toml`

## Deliverable

`cargo audit` and `cargo clippy` run clean. Ignored advisories verified or removed. CI runs both checks.
