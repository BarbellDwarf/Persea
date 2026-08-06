# Roles and Access Control

> **Audience:** admins managing roles, group mappings, and API tokens.
> **Next:** [Security](security.md) for authentication and hardening, or [API Reference](api.md) for the user/token endpoints.

## Role hierarchy

persea implements a 4-tier role hierarchy:

| Role | Level | Description |
|------|-------|-------------|
| **admin** | 4 | Full access — manage users, connections, recordings, sessions, group mappings, RBAC, all API tokens |
| **poweruser** | 3 | Ad-hoc session creation + connections connect + self-service API tokens |
| **operator** | 2 | Connections connect only (no ad-hoc sessions); can view own API tokens |
| **viewer** | 1 | Read-only — view sessions and recordings; no API token access |

Roles are hierarchical: each role includes all permissions of lower roles. For example, a poweruser can do everything an operator can, plus create ad-hoc sessions.

## Connection-level RBAC

Beyond the 4-tier role hierarchy, persea supports fine-grained, connection-level permissions. This allows granting specific users or groups access to individual connections without elevating their system-wide role.

### System permissions

System-wide permissions (not tied to specific objects):

| Permission | Description | Typical role |
|-----------|-------------|-------------|
| `administer` | Full system administration | admin |
| `create_session` | Create ad-hoc sessions | poweruser+ |
| `create_connection` | Create new connections | admin |
| `create_connection_group` | Create connection groups | admin |
| `create_user_group` | Create user groups | admin |
| `audit` | View and verify audit logs | admin |

### Object permissions

Fine-grained permissions on individual connections and connection groups:

| Permission | Description |
|-----------|-------------|
| `read` | View connection details |
| `connect` | Create sessions from this connection |
| `update` | Modify connection settings |
| `delete` | Remove the connection |
| `administer` | Full control over the connection |

### Permission inheritance

Permissions are inherited through the connection group hierarchy:

- **Direct grants**: a permission granted on a connection applies to that connection only
- **Group inheritance**: a permission granted on a connection group applies to all connections within it (recursively)
- **User + group grants**: permissions can be granted to individual users or to groups
- **Group membership**: resolved from OIDC claims, LDAP memberOf, or SAML attributes

Example: granting `connect` on the "Engineering" group gives all members of that group (and subgroups) the ability to create sessions from any connection in the Engineering tree.

### Permission evaluation

When a user attempts an action, permissions are evaluated as follows:

1. **System role check**: does the user's role (admin/poweruser/operator/viewer) allow this action?
2. **Object permission check**: does the user have the required object permission on this specific connection or group?
3. **Group membership**: are any of the user's groups granted this permission via inheritance?

Admins bypass all object permission checks — they always have full access.

## Authentication paths

persea supports three authentication methods, tried in order: admin API key, user API token, OIDC session cookie.

### API key admins

API key holders always have full **admin** access (level 4). There is no way to restrict an API key to a lower role. API keys are intended for automation, CI/CD, and system administration.

```bash
# Create an API key admin
persea add-admin --name automation

# With IP restrictions and expiry
persea add-admin --name ci-bot \
  --allowed-ips "10.0.0.0/8,192.168.1.0/24" \
  --expires "2026-12-31T00:00:00Z"
```

### User API tokens

User API tokens authenticate as the OIDC user who owns the token, with an effective role capped by the token's `max_role`. Tokens use the same `Authorization: Bearer <token>` header as admin API keys, and persea tries admin keys first, then user tokens. See [User API tokens](#user-api-tokens) below for details.

### OIDC / LDAP / SAML / database users

Users authenticating via any primary provider (OIDC, LDAP, SAML, or local database) are assigned a role through three mechanisms (in order of precedence):

1. **Group-to-role mappings**: evaluated on every login. If the user's groups match any mappings, the highest matching role is applied.
2. **Manual role assignment**: admins can set a user's role via CLI, API, or the Admin page.
3. **Default role**: new users get the `default_role` from OIDC config on first login (default: `operator`).

## Endpoint access control

### Session management

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/sessions` | poweruser | Create ad-hoc sessions |
| `GET /api/sessions` | operator | List all sessions |
| `GET /api/sessions/:id` | operator | View session details |
| `DELETE /api/sessions/:id` | operator | Non-admins can only delete their own sessions |

### Connections

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/addressbook/folders` | operator | Filtered by OIDC group membership |
| `GET /api/addressbook/folders/:scope/:folder/entries` | operator | Requires folder group access |
| `POST .../entries/:entry/connect` | operator | Creates session from connections entry |
| `POST /api/addressbook/folders` | admin | Create folders |
| `PUT /api/addressbook/folders/:scope/:folder` | admin | Update folder config |
| `DELETE /api/addressbook/folders/:scope/:folder` | admin | Delete folders |
| `POST .../entries` | admin | Create entries |
| `PUT .../entries/:entry` | admin | Update entries |
| `DELETE .../entries/:entry` | admin | Delete entries |

### Recordings

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/recordings` | operator | List recordings |
| `GET /api/recordings/:name` | operator | Download/play recording |
| `DELETE /api/recordings/:name` | admin | Delete recording |

### User management

| Endpoint | Required role |
|----------|--------------|
| `GET /api/users` | admin |
| `PUT /api/users/:email/role` | admin |
| `DELETE /api/users/:email` | admin |
| `POST /api/users/:email/disable` | admin |
| `POST /api/users/:email/enable` | admin |
| `DELETE /api/users/:email/sessions` | admin |

### Group-to-role mappings

| Endpoint | Required role |
|----------|--------------|
| `GET /api/admin/group-mappings` | admin |
| `POST /api/admin/group-mappings` | admin |
| `PUT /api/admin/group-mappings/:id` | admin |
| `DELETE /api/admin/group-mappings/:id` | admin |

### RBAC (connection-level permissions)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/rbac/groups` | admin | List connection groups |
| `POST /api/rbac/groups` | admin | Create connection group |
| `PUT /api/rbac/groups/:id` | admin | Update connection group |
| `DELETE /api/rbac/groups/:id` | admin | Delete connection group |
| `GET /api/rbac/permissions` | admin | List all permission grants |
| `POST /api/rbac/permissions` | admin | Grant a permission |
| `DELETE /api/rbac/permissions/:id` | admin | Revoke a permission |
| `GET /api/rbac/user-groups` | admin | List user groups |
| `POST /api/rbac/user-groups` | admin | Create user group |
| `DELETE /api/rbac/user-groups/:id` | admin | Delete user group |
| `POST /api/rbac/user-groups/:id/members` | admin | Add member to user group |
| `DELETE /api/rbac/user-groups/:id/members/:user` | admin | Remove member from user group |

### User API tokens (self-service)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/me/tokens` | poweruser | Create a personal API token |
| `GET /api/me/tokens` | operator | List own tokens (metadata only) |
| `DELETE /api/me/tokens/:id` | poweruser | Revoke own token |

Operators can view their tokens (created by an admin on their behalf) but cannot create or revoke them.

### User API tokens (admin)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/admin/user-tokens` | admin | Create token for any user |
| `GET /api/admin/user-tokens` | admin | List all user tokens |
| `DELETE /api/admin/user-tokens/:id` | admin | Revoke any user token |
| `GET /api/admin/token-audit` | admin | View token audit log |

### Public endpoints

| Endpoint | Auth required | Notes |
|----------|--------------|-------|
| `GET /api/health` | None | Always returns 200 |
| `GET /api/auth/status` | None | Returns OIDC enabled status |
| `GET /api/me` | Any authenticated | Returns current user info |

## Folder access control

Connections folders have group-based access control. Each folder has an `allowed_groups` list stored in its `.config` entry in Vault or the database.

- **Admins** bypass group checks and see all folders
- **Operators and powerusers** see only folders where their OIDC groups intersect with the folder's `allowed_groups`
- If `allowed_groups` is empty, all authenticated users can see the folder
- Folders the user cannot access are **hidden** from the tree, not shown-then-denied. This applies at every level, including subfolders.
- A folder the user cannot access directly is still shown if they can access one of its descendants, so a deeper grant is never orphaned out of the tree. Access of a child can be granted independently of its parent (see Inheritance below).

### Inheritance

A subfolder created with `inherit_from_parent: true` (the default for new subfolders) grants access to anyone who can access its parent. A subfolder with its own non-empty `allowed_groups` and `inherit_from_parent: false` is gated solely by its own list, independent of the parent.

### Connection groups (RBAC)

Beyond folder access control, persea supports a separate RBAC system for connection-level permissions:

- **Connection groups** are hierarchical containers for connections (similar to folders but for RBAC)
- **User groups** map to OIDC/LDAP/SAML group memberships
- **Permission grants** assign system or object permissions to users or groups on specific connection groups or connections

This allows scenarios like:
- Granting a support team `connect` permission on the "Production Servers" group without elevating them to poweruser
- Giving a contractor read-only access to specific connections without access to the full address book
- Inheriting permissions through the connection group tree for automatic access management

### Example

A folder with `allowed_groups: ["engineering", "devops"]`:
- A user with OIDC groups `["engineering", "marketing"]` **can** access it (engineering matches)
- A user with OIDC groups `["marketing", "sales"]` **cannot** access it (no match)
- An admin **can** always access it regardless of groups

## Group-to-role mappings

Admins can configure automatic role assignment based on OIDC group membership. This is managed in the Admin page or via the API.

### How it works

1. When a user logs in via OIDC, their group memberships are extracted from the JWT
2. Each group is checked against the `group_role_mappings` table
3. If any groups match, the **highest role** among all matches is applied
4. If no groups match, the user's existing role is preserved

### Example

| OIDC Group | Mapped Role |
|-----------|-------------|
| `sysadmin` | admin |
| `engineering` | poweruser |
| `support` | operator |

A user with groups `["engineering", "support"]` would get `poweruser` (the higher of the two matching roles).

## User API tokens

User API tokens allow OIDC users to authenticate via bearer token for automation and scripting (e.g., creating ad-hoc sessions via CI/CD, or integrating with monitoring tools).

### Who can create tokens

| User role | Self-service | Admin creates for them |
|-----------|-------------|----------------------|
| admin | Yes | Yes |
| poweruser | Yes | Yes |
| operator | No | Yes |
| viewer | No | No |

The primary use case is powerusers creating tokens for service account automation, and admins creating tokens for select operators who need API access.

### Effective role

Each token has an optional `max_role` cap. When the token is used to authenticate, the effective role is:

```
effective_role = min(user_current_role, token_max_role)
```

This means:
- A poweruser who creates a token with `max_role: operator` gets operator-level access when using that token
- If an admin later demotes the user to operator, the token's effective access drops accordingly
- The `max_role` can never grant more access than the user currently has

### Token management UI

- **Tokens page** (`/tokens.html`) — self-service for powerusers and admins to create, view, and revoke their own tokens. Operators can view tokens created for them.
- **Admin page** (`/admin.html`) — admins can create tokens for any user, view all tokens across all users, revoke any token, and view the audit log.

## User management CLI

```bash
# List all OIDC users
persea list-users

# Set a user's role
persea set-role --email user@example.com --role poweruser

# Disable a user (blocks login)
persea disable-user --email user@example.com

# Re-enable a user
persea enable-user --email user@example.com

# Delete a user
persea delete-user --email user@example.com
```

## Admin UI for permission management

The admin page provides a visual interface for managing RBAC:

- **Connection Groups** — create, edit, and delete connection groups; set descriptions and parent groups
- **Permission Grants** — grant or revoke system and object permissions on connection groups and individual connections
- **User Groups** — manage user groups and their members; map groups to connection group permissions
- **Audit Log** — view the hash chain audit log and verify chain integrity

Access the admin page at `/admin.html` (requires admin role).

## Admin (API key) management CLI

```bash
# Create an admin
persea add-admin --name myadmin

# With IP restrictions
persea add-admin --name myadmin --allowed-ips "10.0.0.0/8,192.168.1.0/24"

# With expiry
persea add-admin --name myadmin --expires "2026-12-31T00:00:00Z"

# List admins
persea list-admins

# Disable/enable
persea disable-admin --name myadmin
persea enable-admin --name myadmin

# Rotate key (generates new key, invalidates old immediately)
persea rotate-key --name myadmin

# Delete
persea delete-admin --name myadmin
```
