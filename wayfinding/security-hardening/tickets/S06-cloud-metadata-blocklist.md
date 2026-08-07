# Ticket: Cloud metadata blocklist for web sessions

wayfinder:task
Priority: P3

## Question

Web sessions use `check_allowed_network` against `web_allowed_networks` (default: private ranges). When operators widen the allowlist, cloud metadata endpoints (`169.254.169.254/32`) become reachable. Add an explicit deny for cloud metadata IPs as defense-in-depth.

In `session/create.rs`, after the `check_allowed_network` pass for web sessions, add a secondary check against a hardcoded deny list: `["169.254.169.254/32"]`. This applies regardless of the configured allowlist.

## Deliverable

Updated `session/create.rs` Web branch. Test: web session with URL targeting `169.254.169.254` returns a validation error even when `web_allowed_networks = ["0.0.0.0/0"]`.
