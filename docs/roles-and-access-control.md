# Roles and Access Control

This page explains who can do what in persea: the four roles, the
connection-level permission system, folder access, groups, and how to set it
all up. It's aimed at admins, but anyone can read it to understand their
limits.

There are two separate layers of access control, and they work together:

1. **Roles**: a coarse, system-wide level (viewer → operator → poweruser →
   admin) that decides what a user can do at all.
2. **Object permissions**: fine-grained grants on individual connections or
   folders, for cases where roles are too blunt.

---

## The four roles

| Role | What the person can do | Example |
|------|------------------------|---------|
| **viewer** | The most limited level: can sign in and view their own profile. Data access (sessions, recordings, connections) starts at operator; the viewer level is useful as a safe default for accounts you don't want using the system. | A placeholder account that must never open any session. |
| **operator** | Open existing connections (in folders they have access to), and view sessions and recordings. Cannot create sessions from scratch. | A helpdesk person who opens the pre-configured servers for a customer. |
| **poweruser** | Everything an operator can do, plus create ad-hoc sessions from the Sessions page and manage their own API tokens. | An engineer who spins up a throwaway SSH session to a new box. |
| **admin** | Full access: manage users, roles, connections, folders, recordings, sessions, group mappings, permissions, and all API tokens. | The person who owns the deployment. |

Roles are hierarchical: each role includes everything below it. A poweruser
can do everything an operator can, plus the poweruser extras.

### What each role can do, concretely

| Action | viewer | operator | poweruser | admin |
|--------|:------:|:--------:|:---------:|:-----:|
| Sign in / own profile | ✓ | ✓ | ✓ | ✓ |
| View sessions page / session history | | ✓ | ✓ | ✓ |
| View & play recordings | | | ✓ | ✓ |
| Delete recordings | | | | ✓ |
| Open connections from the address book | | ✓ | ✓ | ✓ |
| Create ad-hoc sessions | | | ✓ | ✓ |
| Create/manage connections & folders | | | | ✓ |
| Manage users, roles, groups, mappings | | | | ✓ |
| Own API tokens (self-service) | | | ✓ | ✓ |
| All API tokens (any user) | | | | ✓ |

(Data APIs: sessions, connections, recordings start at **operator**; list/play
recordings additionally requires **poweruser**, and deleting recordings
requires **admin**. A viewer can sign in but gets no data back from the API.)

---

## How roles are decided

A user's role comes from three places, in this order of precedence:

1. **Group-to-role mappings**: if the user's groups (from OIDC, LDAP, or
   SAML) match a mapping, the highest matching role applies. Re-evaluated on
   every OIDC login.
2. **Manual assignment**: an admin sets the role directly (Admin page, API,
   or CLI).
3. **Default role**: brand-new users start with the `default_role` from the
   `[oidc]` config (default: `operator`).

---

## Folder access

The address book is organised into folders. Each folder has an `allowed_groups`
list, the group names (from your identity provider) that may see it.

- **Admins** see all folders.
- **Operators and powerusers** see only folders where one of their groups is
  in `allowed_groups`.
- An **empty** `allowed_groups` means every authenticated user can see the
  folder.
- Folders you can't access are **hidden** from the tree (not shown-then-
  denied), at every level including subfolders.
- A folder you can't access directly is still shown if you can access one of
  its descendants, so a deeper grant is never orphaned out of the tree.

**Inheritance:** a subfolder created with **inherit from parent** on (the
default) is visible to anyone who can see its parent. A subfolder with its own
non-empty `allowed_groups` and inheritance off is gated solely by its own
list.

**Example:** a folder with `allowed_groups: ["engineering", "devops"]`:

- A user with groups `["engineering", "marketing"]`: **can** access it.
- A user with groups `["marketing", "sales"]`: **cannot**.
- An admin: **always can**.

---

## Connection-level permissions (RBAC)

Beyond roles, you can grant specific permissions on a single connection (or
folder of connections) to a specific user or group. This lets a support team
connect to production servers without becoming powerusers, or require an extra
grant for sensitive entries on top of normal folder access.

### System permissions

System-wide permissions (not tied to a single object):

| Permission | What it grants | Who typically has it |
|-----------|----------------|----------------------|
| `administer` | Full system administration | admin |
| `create_session` | Create ad-hoc sessions | poweruser+ |
| `create_connection` | Create new connections | admin |
| `create_connection_group` | Create connection groups | admin |
| `create_user_group` | Create user groups | admin |
| `audit` | View and verify audit logs | admin |

### Object permissions

Per-connection (or per-folder) grants:

| Permission | What it grants |
|-----------|----------------|
| `read` | View the connection's details |
| `connect` | Start a session from this connection |
| `update` | Modify the connection's settings |
| `delete` | Remove the connection |
| `administer` | Full control over the connection |

### How permissions combine

- **Direct grants**: a permission on a connection applies to that connection.
- **Group grants**: a permission on a connection group (a tree of
  connections) applies to everything inside it, recursively.
- **User + group targets**: grants go to individual users or to groups.
- **Inheritance**: a `connect` grant on a group reaches every member of the
  group's subgroups in the tree.

When a non-admin starts a session from an entry, persea checks the `connect`
grant (direct or inherited) and **fails closed** with "No permission to
connect to this entry" if none matches: an entry with no grants at all is
connectable only by admins. Folder access is checked first; an RBAC grant
cannot bypass a folder's `allowed_groups`. Admins bypass all object permission
checks.

### Connection groups (RBAC groups)

Connection groups are hierarchical containers you create and manage via the
admin API (`/api/admin/rbac/groups`):

- Each group has a `parent_id`; grants inherit up the tree.
- **Membership is explicit**: admins add users by numeric user ID. It is
  *not* derived from your IdP's groups; provider groups feed folder access
  instead (see below).
- Permission grants reference `u:<user-id>` or `g:<group-id>`.

**Example:** grant `connect` on the "Production Servers" group to the support
team's connection group: every member can open those servers without any
role change.

> Fine-grained RBAC is an enterprise feature: the management API returns 403
> without the license (included in the 30-day evaluation). The connect-time
> enforcement check itself is not license-gated, so existing grants keep
> working.

---

## Groups from your identity provider

persea maps group memberships from your login provider into the folder-access
and role system:

- **OIDC**: the `groups` claim from the ID token (configurable via
  `groups_claim`).
- **LDAP**: resolved from your directory via `group_search_base` /
  `group_search_filter`.
- **SAML**: the attribute named in `groups_attribute`.

These provider groups are what folder `allowed_groups` and group-to-role
mappings match against. On the **Admin → Groups** page you can see the groups
persea has observed and set up mappings from them.

### Group-to-role mappings

Admins can configure automatic role assignment from group membership:

1. A user logs in via OIDC; their group memberships are read from the token.
2. Each group is checked against the configured mappings.
3. The **highest role** among all matching mappings is applied.

| OIDC Group | Mapped Role |
|-----------|-------------|
| `sysadmin` | admin |
| `engineering` | poweruser |
| `support` | operator |

A user in both `engineering` and `support` gets **poweruser** (the higher of
the two).

---

## API access

API keys and user tokens authenticate to the REST API as a bearer token.

### Admin API keys

Created with the CLI (see below). API key holders **always get full admin
access**: there's no way to scope a key to a lower role. Keys are for
automation, CI/CD, and administration. Send them as
`Authorization: Bearer <key>` or `X-API-Key: <key>`.

```bash
# Create an API key admin
persea add-admin --name automation

# With IP restrictions and expiry
persea add-admin --name ci-bot \
  --allowed-ips "10.0.0.0/8,192.168.1.0/24" \
  --expires "2026-12-31T00:00:00Z"
```

### User API tokens

User tokens authenticate **as the owning user**, with an effective role
capped by the token's `max_role`:

```
effective_role = min(user_current_role, token_max_role)
```

- A poweruser who creates a token with `max_role: operator` gets operator
  access through that token.
- If the user is later demoted, the token's access drops with them.
- A token can never grant more than the user currently has.

| User role | Can create their own | Admin can create for them |
|-----------|:--------------------:|:-------------------------:|
| admin | Yes | Yes |
| poweruser | Yes | Yes |
| operator | No | Yes |
| viewer | No | Yes (capped at viewer) |

The primary use case: powerusers creating tokens for service-account
automation, and admins creating tokens for select operators who need API
access. Operators and viewers can *view* tokens an admin created for them.

---

## Setting it up in the admin UI

**1. Create users and set roles**, Admin → Users (`/admin/users.html`): add
users, change roles, disable accounts, and see who logged in from where.

**2. Map groups to roles**, Admin page (`/admin.html`): once people have
logged in, the groups persea has seen appear here; map them to roles so
membership assigns roles automatically.

**3. Manage provider groups**, Admin → Groups (`/admin/groups.html`):
inspect the local groups used for folder access and group-to-role mappings.
(These are different from RBAC connection groups.)

**4. Restrict folders**, when creating/editing a folder in the Connections
page, set its `allowed_groups` and inheritance options.

**5. Grant connection permissions**, the Connections page's entry editor
(admin only) has a **Connect permissions (RBAC)** section for granting or
revoking `connect` on that entry to groups or users. Connection groups
themselves are created via the admin API (`POST /api/admin/rbac/groups`).

**6. Check the audit log**, Admin → Audit Log (`/admin/audit.html`): the
hash-chain audit trail with chain-integrity verification.

**7. Let powerusers automate**: they create their own tokens on the Tokens
page (`/tokens.html`, also under Account).

---

## CLI commands

```bash
# Users
persea list-users
persea set-role --email user@example.com --role poweruser
persea disable-user --email user@example.com
persea enable-user --email user@example.com
persea delete-user --email user@example.com

# Admin API keys
persea add-admin --name myadmin
persea list-admins
persea disable-admin --name myadmin
persea enable-admin --name myadmin
persea rotate-key --name myadmin     # new key, old invalidated immediately
persea delete-admin --name myadmin
```

---

## API endpoint reference

All endpoints require authentication (API key, user token, or session
cookie).

### Sessions

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `POST /api/sessions` | poweruser | Create ad-hoc sessions |
| `GET /api/sessions` | operator | List all sessions |
| `GET /api/sessions/:id` | operator | View details |
| `DELETE /api/sessions/:id` | operator | Non-admins can only delete their own |

### Connections (address book)

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/addressbook/folders` | operator | Filtered by group membership |
| `GET /api/addressbook/folders/:scope/:folder/entries` | operator | Requires folder group access |
| `POST .../entries/:entry/connect` | operator | Start a session from an entry |
| `POST /api/addressbook/folders` | admin | Create folders |
| `PUT /api/addressbook/folders/:scope/:folder` | admin | Update folder config |
| `DELETE /api/addressbook/folders/:scope/:folder` | admin | Delete folders |
| `POST/PUT/DELETE .../entries[...]` | admin | Create/update/delete entries |

### Recordings

| Endpoint | Required role | Notes |
|----------|--------------|-------|
| `GET /api/recordings` | poweruser | List recordings |
| `GET /api/recordings/:name` | poweruser | Play/download |
| `DELETE /api/recordings/:name` | admin | Delete |

### User management

| Endpoint | Required role |
|----------|--------------|
| `GET /api/users` | admin |
| `PUT /api/users/:email/role` | admin |
| `DELETE /api/users/:email` | admin |
| `POST /api/users/:email/disable` / `enable` | admin |
| `DELETE /api/users/:email/sessions` | admin |

### Group-to-role mappings

| Endpoint | Required role |
|----------|--------------|
| `GET/POST /api/admin/group-mappings` | admin |
| `PUT/DELETE /api/admin/group-mappings/:id` | admin |

### RBAC (connection permissions)

All require **admin** *and* the enterprise RBAC feature (otherwise 403).
Grants use `entity_id` = `u:<user-id>` or `g:<group-id>` and an object
permission name.

| Endpoint | Purpose |
|----------|---------|
| `GET/POST /api/admin/rbac/groups` | List/create connection groups |
| `DELETE /api/admin/rbac/groups/{id}` | Delete a group (children are unparented, not deleted) |
| `POST/DELETE /api/admin/rbac/groups/{id}/members/{user_id}` | Add/remove members |
| `GET/POST /api/admin/rbac/connections/{id}/permissions` | List/grant permissions on a connection |
| `DELETE /api/admin/rbac/connections/{id}/permissions` | Revoke (same body as grant) |

### User API tokens

| Endpoint | Required role | Purpose |
|----------|--------------|---------|
| `POST /api/me/tokens` | poweruser | Create a personal token |
| `GET /api/me/tokens` | Any signed-in user | List own tokens (metadata only) |
| `DELETE /api/me/tokens/:id` | poweruser | Revoke own token |
| `POST /api/admin/user-tokens` | admin | Create a token for any user |
| `GET /api/admin/user-tokens` | admin | List all user tokens |
| `DELETE /api/admin/user-tokens/:id` | admin | Revoke any token |
| `GET /api/admin/token-audit` | admin | Token audit log |

### Public endpoints

| Endpoint | Notes |
|----------|-------|
| `GET /api/health` | Always 200: for load balancers |
| `GET /api/auth/status` | OIDC-enabled status |
| `GET /api/me` | Current user info |
