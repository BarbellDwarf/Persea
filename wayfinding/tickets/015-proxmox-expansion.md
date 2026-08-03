# Ticket: Proxmox Integration Expansion

wayfinder:research
Blocked by: 003 (Auth DB Schema), 013 (Session Management)

## Question

How should persea expand its Proxmox VE integration beyond SPICE?

Currently: SPICE-only brokering via `PveBroker::fetch_spice_config()`. The Proxmox API supports VNC, serial terminal, and xterm.js consoles. LXC containers have the same endpoints.

Key decisions needed:

1. **VNC console** — `POST /nodes/{node}/qemu/{vmid}/vncproxy` → VNC endpoint. guacd speaks VNC natively.
2. **LXC support** — Same endpoints under `/nodes/{node}/lxc/{vmid}/`. SPICE, VNC, serial, xterm.js.
3. **Serial terminal** — `POST /nodes/{node}/qemu/{vmid}/termproxy` → serial console.
4. **xterm.js console** — `POST /nodes/{node}/qemu/{vmid}/xtermjs` → WebSocket shell.
5. **VM lifecycle** — Start, stop, suspend, shutdown via API. UI buttons for power management.
6. **VM inventory** — List all VMs/containers across cluster. Status, CPU, memory, disk.
7. **Connection type selection** — Let user choose: SPICE, VNC, serial, xterm.js. Or auto-detect based on protocol support.
8. **Authentication** — Current API token auth. Support PAM/LDAP via Proxmox?

## Research

- [Proxmox VE API Research](../research/015-proxmox-api-research.md) — full API reference, VNC auth flow, serial/xterm.js framing, LXC endpoints, lifecycle, inventory
