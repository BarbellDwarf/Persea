# Ticket: Proxmox URL network validation

wayfinder:task
Priority: P1

## Question

The Proxmox session branch (`session/create.rs:439-441`) accepts a user-supplied `proxmox_url` and connects to it without calling `check_allowed_network()`. An attacker with session-creation permissions could point the URL at cloud metadata (`169.254.169.254`) or internal services.

Add `check_allowed_network` validation on the parsed host/port from `proxmox_url` before connecting. Reuse `parse_host_port` (already used for jump-host tunneling) to extract the host. If no explicit Proxmox allowlist exists, use `web_allowed_networks` as the fallback.

## Deliverable

Updated `session/create.rs` Proxmox branch. Test with a `proxmox_url` pointing at `169.254.169.254` — should return a validation error. Test with a valid LAN URL — should pass.
