# Ticket: SSH Tunnel Management UI

wayfinder:research
Blocked by: 003 (Auth DB Schema), 013 (Session Management)

## Question

How should persea add a UI for managing SSH tunnel (jump host) configurations?

Currently, jump host chains are configured per-connection in the address book. The admin wants a dedicated UI for managing jump host configurations, testing connectivity, and viewing active tunnels.

Key decisions needed:

1. **Jump host configuration** — Admin defines reusable jump host entries (hostname, port, user, auth method). These reference existing connections in the address book.
2. **Chain builder UI** — Visual or form-based interface for building multi-hop chains. Drag-to-reorder hops. Test connectivity button.
3. **Active tunnels view** — List of currently active SSH tunnels with status (connecting, connected, error), source/destination, user, duration.
4. **Tunnel health** — How to detect tunnel health? Heartbeat? Process monitoring? Connection state from `russh`?
5. **Integration with connections** — When creating/editing a connection, admin selects a pre-configured tunnel chain instead of entering jump hosts manually.
6. **Per-user tunnel access** — Who can use which tunnels? RBAC integration — connection permissions already cover this if tunnels are tied to connections.

## Research needed

- How the current `src/tunnel.rs` manages jump host chains
- How `russh` exposes connection state
- How Teleport/Boundary handle tunnel/jump host management UIs
