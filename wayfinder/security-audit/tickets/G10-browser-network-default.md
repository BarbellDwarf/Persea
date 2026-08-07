# Ticket: M06 gap — Browser network default range too permissive

wayfinder:task
Priority: P2
Phase: Medium

## Gap

Scheme blocking and literal `169.254.169.254` block are real. Remaining gap:

`src/config.rs:1290-1298` — `web_allowed_networks` defaults to all of RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) plus loopback.

## Fix

1. Default to loopback-only: `["127.0.0.0/8", "::1/128"]`
2. Require explicit opt-in for private-network ranges
3. Hardcode-block full `169.254.0.0/16` range and known IPv6 metadata equivalents (e.g. AWS `fd00:ec2::254`) unconditionally — not just the single literal IPv4 address

## Files

- `src/config.rs:1290-1298` — default networks

## Deliverable

Default browser network allowlist is loopback-only. Full metadata range blocked. `cargo check` passes.
