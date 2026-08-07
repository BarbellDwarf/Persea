# Ticket: No URL/scheme allow-list for browser sessions by default

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/browser.rs:98-106,291-333` — `allowed_domains`/`--host-rules` is opt-in per address-book entry. Unset by default, so a "web" session can be pointed at `file://` URIs or internal/cloud-metadata addresses, visible over VNC.

## Fix

Default-deny non-http(s) schemes and RFC1918/link-local/metadata ranges unless explicitly allow-listed:

1. In `session/create.rs` Web branch, after parsing the URL, reject if scheme is not `http` or `https`.
2. Add a hardcoded deny list for cloud metadata IPs (`169.254.169.254/32`) and link-local ranges, even if `web_allowed_networks` includes them.
3. If `allowed_domains` is not set for the entry, apply a default host-rules that blocks `localhost`, `127.0.0.1`, and metadata IPs.

This overlaps with S06 (`security-hardening/tickets/S06-cloud-metadata-blocklist.md`) but extends it to also block `file://` and default-deny internal ranges.

## Files

- `src/browser.rs:98-106,291-333` — URL handling
- `src/session/create.rs` — Web branch URL validation

## Deliverable

`file://` and other non-http(s) schemes rejected by default. RFC1918/link-local/metadata IPs blocked unless explicitly allowlisted. `cargo check` passes.
