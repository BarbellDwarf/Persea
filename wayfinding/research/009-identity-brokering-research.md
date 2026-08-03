# Research: Multi-Source User Identity Unification

Source: Grafana, GitLab, Keycloak analysis

## Summary of Findings

All three products solve the same fundamental problem: one human = one user record, regardless of how they authenticate. The consensus across all three:

- **Email is the universal linking key** — but must be verified/trusted
- **Primary lookup is (provider, external_id)**, fallback is email match
- **Auto-link on email match** is the default when email is trusted
- **Group/role sync happens at login time** for most sources; background polling is optional/enterprise
- **Disabled users are only enforced at next login** for most systems

---

## 1. Email-Based Linking

### Grafana
- **Primary key**: `(auth_module, user_id)` — e.g., `(ldap, uid=alice,ou=...)` or `(generic_oauth, sub claim)`
- **Email fallback**: Disabled by default! Requires `oauth_allow_insecure_email_lookup: true` to link users across OAuth providers by email
- **Security concern**: Grafana explicitly warns this "can lower security" — must configure `allowed_domains`, `allowed_groups` to prevent unauthorized access
- **Case sensitivity**: Grafana 9.3 introduced a CLI tool to merge "zombie" accounts created by case-different emails (`alice@corp.com` vs `Alice@corp.com`)
- **Verified email**: OAuth providers return email; LDAP returns whatever `mail` attribute is set. No explicit "email verified" flag check for linking

### GitLab
- **Primary key**: `(provider, uid)` per OmniAuth identity
- **Email-based auto-link**: `auto_link_user: ["openid_connect", "google_oauth2"]` — links by email match on login
- **LDAP auto-link**: When LDAP user logs in for the first time, if their LDAP email matches an existing GitLab user's primary email, the LDAP DN is associated with that user (no confirmation needed)
- **SAML auto-link**: `auto_link_saml_user: true` — same email-match behavior
- **Verified email**: GitLab requires the email to be the user's *primary* email address. Only primary email is matched

### Keycloak
- **Primary key**: `(broker, broker_user_id)` stored in `user_federation_provider` linkage
- **Email-based linking**: Default behavior — when a user logs in via a new IdP with the same email as an existing Keycloak user, Keycloak prompts "Account already exists" and offers to link
- **Duplicate emails**: Can be disabled via `Realm Settings > Login > Duplicate emails: Off` (default). When off, same email auto-links
- **Trust Email**: Per-IdP setting — "Trust Email" means email from that IdP is trusted without verification
- **Verified email**: Keycloak has `emailVerified` field. Can be set per-IdP whether to trust the email verification from the IdP

### Recommendation for persea
- **Primary lookup**: `(auth_source, external_id)` — fast, unambiguous
- **Email fallback**: Enable by default, but require email to be "verified" or from a trusted source
- **Trust model**: OIDC providers that return `email_verified: true` → auto-link. LDAP → link if email matches and LDAP is configured as trusted source. Database password → email is always verified (user confirmed during signup)
- **Case normalization**: Always lowercase emails before comparison. This prevents the Grafana zombie-account problem

---

## 2. Account Linking Flow

### Grafana
- **Automatic**: When `oauth_allow_insecure_email_lookup` is enabled, email match auto-links
- **No manual linking UI**: Users cannot manually add auth methods to their account
- **Conflict**: Two users with same email from different providers → duplicate entry error (issue #20889). The identity conflict CLI tool merges them

### GitLab
- **Automatic**: `auto_link_user` config enables auto-linking by email on first login
- **Manual linking**: Users can manually add an OmniAuth identity to their existing account via the admin UI (`/admin/users/:id`). The flow: "Enable OmniAuth for an existing user"
- **Conflict**: Without `auto_link_user`, same email → 422 error "Email has already been taken"
- **SAML-specific**: `auto_link_saml_user` is a separate config toggle

### Keycloak
- **Automatic**: Default first broker login flow checks for existing user by email. If found, prompts to link
- **Manual linking**: Users can link additional IdPs from their Account Console → "Federated Identities" tab. This is a first-class feature
- **Conflict**: When `duplicate_emails` is off (default), same email → auto-link. When on → separate accounts
- **Admin linking**: Admin can manually link an IdP identity to any user via admin console

### Recommendation for persea
- **Automatic linking on email match** — this is the right default. GitLab and Keycloak both do this
- **No manual linking UI initially** — adds complexity. Auto-link covers 95% of cases
- **Conflict handling**: If two *existing* users have same email (shouldn't happen with proper auto-link), block login and log error. Admin resolves manually
- **Future**: Could add "Linked Accounts" page in user settings (like Keycloak) for manual linking

---

## 3. Group Resolution Across Sources

### Grafana
- **Login-time sync**: Groups are re-evaluated on every login from the authoritative source
- **LDAP**: First matching group_dn in config wins (order matters in TOML). If user matches multiple mappings, the topmost wins
- **OAuth**: Role mapping via `role_attribute_path` (JMESPath) — single expression, single source
- **Team sync**: Enterprise feature — maps IdP groups to Grafana teams. Synced on login
- **No cross-source merge**: Grafana does not merge groups from OIDC + LDAP. Each user has one auth module, and groups come from that module only
- **No precedence config**: There's no "if OIDC says admin and LDAP says viewer, take highest" — it's one source per login

### GitLab
- **LDAP groups → GitLab groups**: Enterprise feature with background sync. LDAP group membership maps to GitLab group membership
- **OmniAuth groups**: Mapped via `groups_attribute` in provider config
- **No cross-source merge**: User authenticates via one source at a time. Groups come from that source
- **Priority**: LDAP groups take precedence for LDAP users. OmniAuth groups for OAuth users. No conflict because a user is either LDAP or OAuth at any given moment

### Keycloak
- **Realm roles + client roles**: Keycloak has its own role system. IdP groups can be mapped to Keycloak roles via mappers
- **LDAP group mapper**: Maps LDAP groups to Keycloak roles/groups. Can be "read-only" (LDAP is authoritative) or "writable"
- **Cross-source**: Keycloak can have multiple LDAP/OIDC federations. Users from different sources all land in the same Keycloak role system
- **No automatic merge**: A user authenticated via OIDC gets OIDC group mappings; via LDAP gets LDAP group mappings. No automatic "take highest"

### Recommendation for persea
- **Per-source group mapping** — each auth source has its own group→role mapping config
- **Merge strategy: Union** — if user logs in via OIDC and OIDC says admin, AND LDAP also says admin, effective role is admin. Merge all groups from the login source
- **Precedence config**: `role_precedence: ["oidc", "ldap", "database"]` — if sources disagree, first source in list wins
- **Simplest approach** (recommended): Groups are resolved from the **login source only**. Don't try to merge across sources. If OIDC says admin and user logs in via OIDC, they're admin. If they log in via LDAP and LDAP says viewer, they're viewer. This matches Grafana/GitLab/Keycloak behavior
- **Caveat**: Store the "effective role" per-login, not globally. Different logins can yield different roles

---

## 4. External Group Sync

### Grafana
- **Login-time only** (OSS): "Currently the synchronization only happens when a user logs in, unless LDAP is used with the active background synchronization"
- **Background sync** (Enterprise): `sync_cron = "0 1 * * *"` with `active_sync_enabled = true`. Syncs every N minutes/hours. Removed users are auto-disabled, removed users are logged out
- **Team sync** (Enterprise): Also login-time or background sync

### GitLab
- **LDAP sync**: Background process (`gitlab-rake gitlab:ldap:sync`). Groups synced periodically
- **OmniAuth**: Login-time only. No background sync for OAuth groups

### Keycloak
- **LDAP sync modes**: 
  - `IMPORT` (default): Import users on first login, then periodic sync
  - `SYNC`: Always check LDAP on queries (no import)
  - `NO_SYNC`: Never sync after initial import
- **Periodic sync**: `full_sync_period` and `changed_sync_period` in seconds. Default: changed users every hour, full sync every 24 hours
- **Group sync**: Periodic group sync is an open feature request (issue #9609). Currently groups sync only during user sync, not independently

### Recommendation for persea
- **Login-time sync as default** — simplest, no background process needed
- **Optional background sync for LDAP**: Configurable `sync_interval_secs`. Default: disabled (login-time only). Enable for environments where group changes should propagate immediately
- **OIDC**: Login-time only (OIDC tokens are short-lived, groups come from the token at auth time)
- **Database auth**: No sync needed (groups are local)

---

## 5. User Profile Management

### Grafana
- **User-editable**: Name, email, theme preference, timezone
- **Admin-editable**: Everything above + login, role, org, auth modules
- **LDAP-synced fields**: Name, email, login — overwritten on every LDAP login (authoritative source)
- **OAuth-synced fields**: Name, email, login — synced on login based on `sync_profile_from_provider` config

### GitLab
- **User-editable**: Name, email, avatar, bio, location, organization
- **Admin-editable**: Everything + username, role, organization membership
- **LDAP-synced**: Username, email, name, two_factor_auth — synced on login
- **Protected fields**: Username, email, two_factor_auth from LDAP cannot be changed by user

### Keycloak
- **User-editable**: First name, last name, email (configurable via User Profile)
- **Admin-editable**: Everything + username, groups, roles, federation links
- **LDAP-synced**: Configurable per-attribute via mappers. Common: username, email, firstName, lastName

### Recommendation for persea
- **User-editable**: Display name, theme preference, TOTP (always local regardless of auth source)
- **Admin-editable**: All of above + email, role overrides
- **Auth-source-synced**: On login, update display name and email from auth source (if source is trusted). User can override display name locally
- **Never synced**: Password (always local), TOTP secrets (always local), API keys

---

## 6. Session Unification

### Grafana
- **Multiple sessions allowed**: Users can have multiple active sessions from different browsers/devices
- **Single sign-out**: Optional — `signout_redirect_url` config. Logout from Grafana logs out from IdP session
- **No session conflict**: Different auth sources don't conflict — a user is a user

### GitLab
- **Multiple sessions allowed**: No limit on concurrent sessions
- **Session management**: Users can view/revoke active sessions from profile
- **No auth-source conflict**: Sessions are tied to user ID, not auth source

### Keycloak
- **Multiple sessions allowed**: Default behavior
- **Session management**: Full session management UI — view all active sessions, revoke individually
- **Single sign-out**: Full SSO/SLO support via OIDC backchannel logout
- **SSO Session**: Configurable timeout, idle timeout, max sessions per user

### Recommendation for persea
- **Allow multiple sessions** — all three products do this, and it's the expected UX
- **Session storage**: Session tied to `user_id`, not auth source
- **Single sign-out**: Implement OIDC logout endpoint. When user logs out of persea, redirect to IdP logout URL
- **Optional**: Config `max_sessions_per_user` to prevent session abuse (e.g., max 5)

---

## 7. Account Lifecycle

### Grafana
- **LDAP disabled users**: Background sync (Enterprise) auto-disables accounts. User is logged out, account shows "disabled" label. Permissions preserved if re-enabled
- **OAuth**: No lifecycle management. If user is deleted in IdP, they can still log in until Grafana admin disables them
- **No periodic check**: Without background sync, disabled users are only caught at next login attempt

### GitLab
- **LDAP block**: Users removed from LDAP are "blocked" on next sync. They cannot sign in but their data is preserved
- **OmniAuth**: No lifecycle management. User exists until manually removed
- **Periodic sync**: `gitlab-rake gitlab:ldap:check` runs periodically, blocks removed users

### Keycloak
- **LDAP sync**: Removed LDAP users are disabled in Keycloak on next periodic sync (`changed_sync_period`)
- **User Enabled mapper**: `msad-user-account-control` mapper syncs the "enabled" flag from AD/LDAP
- **No immediate enforcement**: If a user is disabled in LDAP, they can still use an active Keycloak session until it expires. Next login attempt will fail
- **Periodic sync catches**: Background sync disables orphaned accounts

### Recommendation for persea
- **Login-time check**: On every login, verify user still exists/enabled in auth source. If disabled → deny login, return "account disabled" message
- **No periodic background check** (initially): Login-time enforcement is sufficient. A disabled LDAP user will be caught on their next login attempt
- **Active sessions**: If a user is disabled in the external source, their existing sessions remain valid until they expire. This is the standard behavior (Grafana, GitLab, Keycloak all do this)
- **Optional future enhancement**: Background job that periodically checks LDAP for disabled users and disables their persea accounts. Configurable interval

---

## Implementation Schema

```sql
-- Core user record (one per human)
CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,  -- lowercase, canonical
    display_name TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now')),
    is_active   INTEGER NOT NULL DEFAULT 1
);

-- Auth identities (one per auth source per user)
CREATE TABLE user_identities (
    id              INTEGER PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id),
    auth_source     TEXT NOT NULL,  -- 'oidc', 'ldap', 'database'
    external_id     TEXT NOT NULL,  -- provider-specific ID (sub, DN, etc.)
    email_verified  INTEGER NOT NULL DEFAULT 0,
    last_login_at   TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(auth_source, external_id)
);

-- Auth source config
CREATE TABLE auth_sources (
    id              INTEGER PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,  -- 'google-corp', 'ldap-main'
    source_type     TEXT NOT NULL,  -- 'oidc', 'ldap', 'database'
    config          TEXT NOT NULL,  -- JSON blob
    trust_email     INTEGER NOT NULL DEFAULT 0,
    auto_create     INTEGER NOT NULL DEFAULT 1,
    role_precedence INTEGER NOT NULL DEFAULT 0,  -- lower = higher priority
    enabled         INTEGER NOT NULL DEFAULT 1
);

-- Group mappings per auth source
CREATE TABLE group_mappings (
    id          INTEGER PRIMARY KEY,
    source_id   INTEGER NOT NULL REFERENCES auth_sources(id),
    group_name  TEXT NOT NULL,  -- OIDC group claim value or LDAP DN
    role        TEXT NOT NULL,  -- 'admin', 'poweruser', 'operator', 'viewer'
    UNIQUE(source_id, group_name)
);
```

## Login Flow

```
1. User authenticates via auth_source (OIDC/LDAP/database)
2. Extract: email, external_id, groups, email_verified
3. Lookup: user_identities WHERE (auth_source, external_id) → found?
   YES → update last_login_at, proceed to step 6
   NO  → proceed to step 4
4. Lookup: users WHERE email = ? (if email_verified or source is trusted)
   YES → create user_identities row linking existing user to this source
   NO  → if auto_create: create users + user_identities rows
         else: deny login
5. User record established
6. Resolve groups from auth_source's group_mappings
7. Compute effective role (highest role from login source's mappings)
8. Create session with (user_id, effective_role, auth_source)
```
