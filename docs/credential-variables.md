# Credential Variables

This page explains the two ways persea keeps per-user credentials so users
don't have to type passwords on every connect:

1. **Preset credentials**: one username + password per user, saved on the
   profile page, used as a fallback for entries that carry no credentials of
   their own.
2. **Credential variables**: named placeholders (`$corp_password`) that
   address book entries reference instead of real secrets; each user's values
   are substituted in at connect time.

Both keep secrets out of the browser: persea resolves them server-side, and
the UI never shows stored values back.

---

## Preset credentials

**What they are.** A single username and password a user saves on their
**My Profile** page (the "My Credentials" card). Think of it as "my usual
login".

**How they're used.** When a connection entry has no credentials of its own
(an admin left username/password blank), persea falls back to the user's
preset. If the user has no preset either, they're asked for credentials at
connect time. This is handy for accounts with rotating passwords: the entry
stays blank and each user keeps their own current password up to date.

**Security.** The password is encrypted at rest with the storage encryption
key (`[storage].encryption_key` / `PERSEA_STORAGE_KEY`): saving a preset
password requires that key to be configured, otherwise the save is refused
with a clear error. The API never returns the stored password, only whether
one exists, so it can't be shown back in the UI.

---

## Credential variables

**What they are.** Names that stand for secrets, like environment variables
but for credentials. An admin writes `$corp_username` and `$corp_password`
into an entry's credential fields instead of real values; each user's saved
values are substituted when a session starts. This is a similar experience to
LDAP credential passthrough in Apache Guacamole: log in once, sessions just
work, without persea needing to talk to LDAP.

### Naming rules

A variable starts with `$` and follows the pattern `$<domain>_<suffix>`:

| Pattern | Purpose |
|---------|---------|
| `$<domain>_username` | Username |
| `$<domain>_password` | Password |
| `$<domain>_domain` | AD/Windows domain |
| `$<domain>_key` | SSH private key |

The `<domain>` is a logical name the admin chooses to group related
credentials, for example `corp`, `jumpcloud`, `lab`, or `cloud-prod`.
Several entries can reference the same domain, so a user configures their
credentials once and every entry picks them up.

Allowed characters: lowercase letters, numbers, underscores, and hyphens.
Example references: `$corp_username`, `$jump-host_password`,
`$cloud-prod_key`.

### Where variables can be used

Variables are expanded at connect time in these entry fields:

| Field | Applies to | Notes |
|-------|------------|-------|
| `username` | SSH, RDP, VNC, Web | Authentication username for the target |
| `password` | SSH, RDP, VNC, Web | Authentication password for the target |
| `domain` | RDP | AD/Windows domain |
| `private_key` | SSH | SSH private key contents |
| `container_username` | VDI | VDI container login (only when set explicitly on the entry) |
| `container_password` | VDI | VDI container login (only when set explicitly on the entry) |

An entry can mix variables with static values, for example an RDP entry with
a fixed hostname and port but `$ad_username`, `$ad_password`, `$ad_domain`
for credentials.

### How users set their values

Values live in the per-user credential store and are managed through the API
(`GET/PUT /api/me/credentials`, operator role or higher). A user can save any
subset of the variables at a time and come back for the rest. The API accepts
only valid variable names, and when listing credentials it returns them
**masked**: you can see which variables have values, never the values
themselves.

### What happens at connect time

When a session starts from an entry that references variables, persea looks
up the user's stored values and substitutes them:

- **All variables set**: the session launches with them, no prompting.
- **Some missing**: the connect fails with an error naming the missing
  variables (e.g. "missing credential variables: corp_username,
  corp_password"), and the user sets them and tries again.
- **Entry has no variables**: normal behaviour: stored credentials, preset
  credentials, or a prompt.

---

## Storage and security

- **Never sent to the browser.** Variable resolution happens server-side; the
  browser only ever sees the session stream.
- **Vault mode** (`[storage].backend = "vault"`): each user's values live in
  Vault KV v2 at `<base_path>/users/<sanitized_email>`, variable names as
  keys, values as plaintext within Vault's own protection. The Vault policy
  must allow read/write there (see below).
- **DB mode** (`[storage].backend = "db"`, the default): variable values are
  stored in the database's `user_credentials` table, encrypted with the
  storage encryption key (AES-256-GCM). The Vault→DB migration command moves
  values between the two (see [Migration](migration.md)).

### Required Vault policy

In Vault mode, in addition to the connections policy, the persea policy needs:

```hcl
# User credential variables (read/write own credentials)
path "secret/data/persea/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}
path "secret/metadata/persea/users/*" {
  capabilities = ["list", "read", "delete"]
}
```

### Shared and local credentials (multiple Vaults)

When more than one Vault backend is configured (see
[Configuration](configuration.md#multiple-vault-backends-disaster-recovery)),
each credential can be stored in the **shared** Vault (propagates to every
site) or kept **local** to this instance. The default scope for new
credentials is set by `user_credentials_default_scope` (`local` by default).
Reads merge both backends: a local value wins over a shared one of the same
name.

Trade-off to be aware of: a credential kept in the shared Vault can't be
resolved while that Vault is unreachable, so a connection referencing it
fails even if the target and the local Vault are up. Keep credentials a site
must never lose (for example break-glass logins) **local**.

With a single Vault there's only one store and the shared/local distinction
doesn't apply.

---

## API endpoints

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| `GET` | `/api/me/preset-credentials` | Any signed-in user | Read own preset credentials (values masked, presence flags only) |
| `PUT` | `/api/me/preset-credentials` | Any signed-in user | Save/update/clear own preset credentials |
| `GET` | `/api/me/credentials` | Operator+ | List own credential variables (values masked) |
| `PUT` | `/api/me/credentials` | Operator+ | Save/update own credential variables |
| `GET` | `/api/credential-variables` | Operator+ | List all variables used across entries the user can access |
