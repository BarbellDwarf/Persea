# Ticket: H07 gap — Lockout functions exist but are never called

wayfinder:task
Priority: P1
Phase: High

## Gap

Rate limiting (GovernorLayer) working. Failed-attempt tracking functions exist but are dead code:

- `record_failed_login_attempt`, `record_successful_login`, `count_recent_failures`, `is_locked_out` (`src/db.rs:956-995`) — defined, only called in tests

## Fix

Wire into auth handlers:
- `login_submit` failure branch (~line 338-361): call `record_failed_login_attempt` on bad password, check `is_locked_out` before attempting auth
- `login_submit` success branch: call `record_successful_login`
- `mfa_submit` invalid-code branch (~line 528-530): call `record_failed_login_attempt`

## Files

- `src/handlers/auth.rs:338-361,528-530` — login/mfa handlers
- `src/db.rs:956-995` — lockout functions (already exist)

## Deliverable

Failed login attempts tracked. Lockout enforced after 5 failures in 15 minutes. Successful login clears counter. `cargo check` passes.
