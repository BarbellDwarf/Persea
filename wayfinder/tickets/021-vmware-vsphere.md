# Ticket: VMware vSphere Integration

**Type:** task
**Labels:** virtualization, wayfinder:task

## Current state

`src/vsphere.rs` contains vSphere REST API client code:
- `VsphereConfig` struct with `vcenter_addr`, `username`, `password`
- Session auth via `POST /rest/com/vmware/cis/session`
- VM listing via `GET /rest/vcenter/vm`
- VM power operations and console ticket retrieval

The module is imported in `src/main.rs` (`mod vsphere;`) and config exists (`vsphere: Option<VsphereConfig>` in config.rs), but no routes are wired up. The code is dead.

## What needs doing

1. Wire vSphere routes into the router (session listing, VM console, power operations)
2. Add vSphere entries to the connections page (similar to Proxmox VE)
3. Add OS detection to route sessions to RDP (Windows) or SSH (Linux)
4. Add VMware config section to config.example.toml
5. Write integration tests for vSphere API client
6. Update docs/integrations.md with VMware setup instructions
7. Add vSphere to the setup wizard detection

## Dependencies

- Requires vCenter Server with REST API access
- Uses HTTPS with basic auth (no API tokens)
- Console access requires VM console ticket from vCenter

## Acceptance criteria

- Can list VMs from vCenter via persea UI
- Can open a console to a VM (RDP for Windows, SSH for Linux)
- Config section documented in config.example.toml
- Integration tests pass
