# Ticket: VMware vSphere Integration

wayfinder:research
Blocked by: 003 (Auth DB Schema), 013 (Session Management)

## Question

How should persea integrate with VMware vSphere for VM inventory and OS-aware protocol routing?

The approach: use vSphere API for inventory + guest OS detection, then route via guacd using standard protocols (RDP for Windows, SSH for Linux). No proprietary MKS protocol.

Key decisions needed:

1. **vSphere API client** — SOAP API for inventory + management. Which Rust crate? `quick-xml` for SOAP parsing?
2. **Authentication** — Session-based via `vmware-session-id` header. Support SSO/LDAP/certificate auth.
3. **VM inventory** — List VMs with name, status, OS, IP, cluster, host. `RetrievePropertiesEx` on VirtualMachine managed objects.
4. **Guest OS detection** — `guest.guestOs` field. Map to protocol: Windows → RDP, Linux → SSH, other → VNC.
5. **IP detection** — `guest.ipAddress` requires VMware Tools. Handle missing Tools gracefully.
6. **Protocol routing** — Detect OS → set protocol params → hand off to guacd. RDP: need hostname/IP, port 3389. SSH: need hostname/IP, port 22.
7. **VM lifecycle** — Power on/off, suspend, shutdown via API. Useful for management.
8. **Credentials** — How to get guest OS credentials? Config per-VM? Integration with vault/DB credential store?
9. **Network reachability** — guacd host must be able to reach guest IPs. Document this requirement.
10. **VMware Horizon** — Separate effort? Or include Horizon connection brokering?

## Research needed

- vSphere SOAP API: session management, VM listing, guest info retrieval
- vSphere REST API capabilities (can it do everything needed?)
- How mRemoteNG and Royal TSX handle VMware integration
- VMware Tools requirements for guest IP/OS detection
