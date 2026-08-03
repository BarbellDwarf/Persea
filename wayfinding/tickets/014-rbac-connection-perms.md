# Ticket: RBAC with Connection Permissions

wayfinder:research
Blocked by: 003 (Auth DB Schema), 009 (User Identity Model), 002 (Auth Provider Architecture)

## Question

How should persea implement role-based access control with connection-level permissions?

Currently persea has a 4-tier role hierarchy (admin > poweruser > operator > viewer) but no connection-level permissions. Any poweruser can connect to any connection. Enterprise needs: who can connect to what.

Key decisions needed:

1. **Permission model** — Apache Guacamole pattern: system permissions (CREATE_CONNECTION, ADMINISTER) + object permissions (READ, UPDATE, DELETE, CONNECT on specific connections). Confirm.
2. **Connection groups** — Organizational groups (logical grouping) + Balancing groups (load balancing). Which to support?
3. **Permission inheritance** — Group-level permissions inherit to members. User-level overrides?
4. **Sharing profiles** — Allow users to share connections with limited (read-only) credentials. Needed?
5. **Admin roles** — Separate "connection admin" from "user admin"? Or single admin role?
6. **Permission UI** — Admin UI to manage permissions per connection/group/user.
7. **API for permission checks** — Middleware checks permissions before connection creation/management.
8. **Default permissions** — New users get what permissions? Configurable default role.

## Research needed

- Apache Guacamole's permission model (system + object permissions)
- Teleport's label-based RBAC with deny-wins semantics
- How to structure permission checks in axum (middleware vs extractor)
