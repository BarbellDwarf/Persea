# Roles and Access Control

> **Audience:** admins managing roles, group mappings, and API tokens.
> **Next:** [Security](security-hardening.md) for authentication and hardening, or [API Reference](api.md) for the user/token endpoints.

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
- **Group membership**: for RBAC connection groups, membership is assigned explicitly by admins; for folder access, membership of local groups is resolved from OIDC claims, LDAP memberOf, or SAML attributes

Example: granting `connect` on a connection to the "Engineering" group lets every member of that group — including members of its subgroups in the connection-group tree — create sessions from that connection.

### Permission evaluation

When a user attempts an action, permissions are evaluated as follows:

1. **System role check**: does the user's role (admin/poweruser/operator/viewer) allow this action?
2. **Object permission check**: does the user have the required object permission on this specific connection or group?
3. **Group membership**: are any of the user's groups granted this permission via inheritance?

Admins bypass all object permission checks — they always have full access.

Object permissions are enforced at connect time: when a non-admin starts a session from a connections entry, persea checks the `connect` permission (direct grant or inherited through group membership) and **fails closed** with `No permission to connect to this entry` if no grant matches (`src/api/address_book.rs`). A connection with no grants at all is therefore connectable only by admins. The folder-access check still applies first — an RBAC grant cannot bypass folder or entry `allowed_groups`.

## Authentication paths

The API middleware accepts three credential types, tried in order: admin API key, user API token, and session cookie. The session cookie (`persea_session`) is issued by the web UI's login flow, so it covers users from **every** login provider — local database (email + password), OIDC, LDAP, SAML, and RADIUS — not just OIDC.

### API key admins

API key holders always have full **admin** access (level 4). There is no way to restrict an API key to a lower role. API keys are intended for automation, CI/CD, and system administration. Send them as `Authorization: Bearer <key>` or `X-API-Key: <key>` (both are accepted, `src/auth.rs`).

```bash
# Create an API key admin
persea add-admin --name automation

# With IP restrictions and expiry
persea add-admin --name ci-bot \
  --allowed-ips "10.0.0.0/8,192.168.1.0/24" \
  --expires "2026-12-31T00:00:00Z"
```

### User API tokens

User API tokens authenticate as the user who owns the token (from any provider), with an effective role capped by the token's `max_role`. Tokens use the same `Authorization: Bearer <token>` header as admin API keys, and persea tries admin keys first, then user tokens. See [User API tokens](#user-api-tokens) below for details.

### OIDC / LDAP / SAML / database users

Users authenticating via any primary provider (OIDC, LDAP, SAML, or local database) are assigned a role through three mechanisms (in order of precedence):

1. **Group-to-role mappings** (OIDC logins): evaluated on every OIDC login. If the user's groups match any mappings, the highest matching role is applied.
2. **Manual role assignment**: admins can set a user's role via CLI, API, or the Admin page.
3. **Default role**: new OIDC users get the `default_role` from the `[oidc]` config on first login (default: `operator`).

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
| `GET /api/addressbook/folders` | operator | Filtered by group membership |
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

All RBAC endpoints require the **admin** role **and** the enterprise RBAC license — without the license they return `403`. Grants are made per connection; `entity_id` is `u:<user-id>` or `g:<group-id>` and `permission` is one of the object permissions.

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/admin/rbac/groups` | admin | List connection groups |
| `POST /api/admin/rbac/groups` | admin | Create connection group (`name`, `parent_id?`, `description?`) |
| `DELETE /api/admin/rbac/groups/{id}` | admin | Delete group (children are unparented, not deleted) |
| `POST /api/admin/rbac/groups/{id}/members` | admin | Add member (`user_id`) |
| `DELETE /api/admin/rbac/groups/{id}/members/{user_id}` | admin | Remove member |
| `GET /api/admin/rbac/connections/{id}/permissions` | admin | List grants on a connection |
| `POST /api/admin/rbac/connections/{id}/permissions` | admin | Grant (`entity_id`, `permission`) |
| `DELETE /api/admin/rbac/connections/{id}/permissions` | admin | Revoke (same body as grant) |

### User API tokens (self-service)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/me/tokens` | poweruser | Create a personal API token |
| `GET /api/me/tokens` | Any signed-in user | List own tokens (metadata only) |
| `DELETE /api/me/tokens/:id` | poweruser | Revoke own token |

Operators and viewers can view tokens created for them by an admin, but only powerusers and admins can create or revoke their own.

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
- **Operators and powerusers** see only folders where their auth-provider groups intersect with the folder's `allowed_groups`
- If `allowed_groups` is empty, all authenticated users can see the folder
- Folders the user cannot access are **hidden** from the tree, not shown-then-denied. This applies at every level, including subfolders.
- A folder the user cannot access directly is still shown if they can access one of its descendants, so a deeper grant is never orphaned out of the tree. Access of a child can be granted independently of its parent (see Inheritance below).

### Inheritance

A subfolder created with `inherit_from_parent: true` (the default for new subfolders) grants access to anyone who can access its parent. A subfolder with its own non-empty `allowed_groups` and `inherit_from_parent: false` is gated solely by its own list, independent of the parent.

### Connection groups (RBAC)

Beyond folder access control, persea supports a separate RBAC system for connection-level permissions:

- **Connection groups** are hierarchical containers (each has a `parent_id`); a group granted `connect` on a connection passes that access on to its members
- **Membership is explicit** — admins add users (by numeric user ID) to a connection group. It is *not* derived from OIDC/LDAP/SAML groups; those feed the folder-access `local_groups` instead
- **Permission grants** are made on individual connections: `entity_id` is `u:<user-id>` or `g:<group-id>`, and the permission is one of the object permissions. `connect` is the permission enforced at session start
- A user's effective access is the union of their direct grants and the grants on groups they belong to, inherited up the connection-group tree (recursive CTE in `src/rbac.rs`)

This allows scenarios like:
- Granting a support team `connect` on the "Production Servers" group without elevating them to poweruser
- Requiring an extra `connect` grant for sensitive entries on top of normal folder access
- Inheriting permissions through the connection group tree for automatic access management

Fine-grained RBAC is an enterprise feature: the management API (`/api/admin/rbac/*`) rejects calls without the RBAC license (`FEAT_RBAC`, `src/handlers/rbac.rs`). The connect-time enforcement check itself is not license-gated.

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

User API tokens allow signed-in users to authenticate via bearer token for automation and scripting (e.g., creating ad-hoc sessions via CI/CD, or integrating with monitoring tools).

### Who can create tokens

| User role | Self-service | Admin creates for them |
|-----------|-------------|----------------------|
| admin | Yes | Yes |
| poweruser | Yes | Yes |
| operator | No | Yes |
| viewer | No | Yes (capped at `viewer`) |

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

- **Tokens page** (`/tokens.html`, also `/account/tokens.html`) — self-service for powerusers and admins to create, view, and revoke their own tokens. Operators and viewers can view tokens created for them.
- **Admin token endpoints** (API only, no UI) — `/api/admin/user-tokens` (create tokens for any user, list all, revoke any) and `/api/admin/token-audit` (token audit log). See the [API Reference](api.md).

## User management CLI

```bash
# List all users
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

RBAC is managed partly in the UI and partly via the admin API:

- **Connect permissions (RBAC)** — the Connections page's entry editor (admin only) has a "Connect permissions (RBAC)" section for granting or revoking `connect` access on that entry to groups or users. Connection groups themselves are created via the API (`POST /api/admin/rbac/groups`).
- **Admin → Groups** (`/admin/groups.html`) — manages the *local groups* used for folder access and group-to-role mappings (with provider-group mappings). These are a separate concept from RBAC connection groups.
- **Audit Log** — `/admin/audit.html` shows the hash chain audit log and chain-integrity verification.

Admin pages live at `/admin.html` and `/admin/users.html` (both require the admin role).

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
