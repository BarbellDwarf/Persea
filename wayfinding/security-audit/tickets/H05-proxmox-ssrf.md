# Ticket: SSRF via ad-hoc Proxmox sessions

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/session/create.rs:433-516` — Ad-hoc Proxmox sessions accept request-supplied `proxmox_url` / token / `verify_tls` (defaults `false`). These drive server-side outbound calls with distinguishable error classes returned to the caller. Gated only by `has_role("poweruser")` (`src/api/sessions.rs:44`).

## Overlap

**Existing ticket S02** (`security-hardening/tickets/S02-proxmox-url-validation.md`) claims `check_allowed_network` was added. Verify that S02 actually:
1. Validates the parsed host from `proxmox_url` against `check_allowed_network`
2. Blocks `169.254.169.254` and RFC1918 ranges unless explicitly allowlisted
3. Defaults `verify_tls` to `true` (not `false`)

If S02 is incomplete, fix the gaps. The audit found this is still exploitable — the validation may not have been applied to the Proxmox path.

## Files

- `src/session/create.rs:433-516` — Proxmox session creation
- `src/api/sessions.rs:44` — role gate

## Deliverable

Ad-hoc Proxmox target validated against network allowlist. `verify_tls` defaults to `true`. `cargo check` passes. Test with `proxmox_url` pointing at `169.254.169.254` — returns validation error.
