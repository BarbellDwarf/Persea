# Integrations

This page covers the external systems persea can be wired into: identity
providers for login (LDAP, SAML, OIDC, RADIUS, TOTP), external secrets stores
(Vault/OpenBao), hypervisors (Proxmox VE, VMware vSphere), SSH bastion chains,
Kerberos RDP authentication, encrypted drive storage, and front-door proxies
(HAProxy, Knocknoc).

Every section follows the same shape: **What it is** (plain terms), **When to
use it**, **Setup** (exact config keys), **Verify**, and **Common problems**.

If a setting doesn't exist on this page, it's probably in
[Configuration](configuration.md), which lists every `config.toml` key.

---

## How login works with several providers

persea tries the auth methods you list in `[auth].methods` **in order, first
match wins**. A user who isn't found by method 1 is tried against method 2,
and so on. All the password-based providers (database, LDAP, RADIUS) share the
same username + password form on the login page; OIDC and SAML get their own
buttons. API-key auth is independent and works alongside all of them.

```toml
[auth]
methods = ["ldap", "database"]   # try LDAP first, fall back to local accounts
```

Available method names: `database`, `ldap`, `radius`, `saml`, `oidc`, plus
`totp` as a second factor (see [TOTP](#totp-second-factor)). The database
provider is always available, so a reasonable setup keeps `database` last as a
fallback.

---

## LDAP / Active Directory login

**What it is.** Lets people log in with their existing company account
(Active Directory, OpenLDAP, FreeIPA, anything that speaks LDAP). No separate
persea passwords to manage.

**When to use it.** Your organisation already has a directory. Users log in
with their normal username and password, and you can control access by
directory group membership.

**How it works.** When someone submits the login form, persea connects to your
LDAP server, binds with a service account, searches for the username, then
tries to log in as that user with the password they typed. The user's password
is only sent to your LDAP server: it is not stored by persea.

### Setup

```toml
[auth]
methods = ["ldap", "database"]

[auth.ldap]
url = "ldaps://ldap.example.com:636"           # ldap:// or ldaps://
bind_dn = "cn=binduser,dc=example,dc=com"      # service account that may search
bind_password = "s3rvice-secret"               # its password
user_search_base = "ou=users,dc=example,dc=com" # where to look for users (alias: search_base)
user_search_filter = "(uid={})"                # how to find the user; {} is the typed username (alias: search_filter)
group_search_base = "ou=groups,dc=example,dc=com"   # optional: where groups live
group_search_filter = "(member={})"            # optional: {} is the user's DN
```

Optional keys:

| Key | Default | What it does |
|-----|---------|-------------|
| `starttls` (alias `start_tls`) | `false` | Upgrade a plain `ldap://` connection to TLS instead of using `ldaps://` |
| `tls_skip_verify` | `false` | Skip certificate checks (dev/test with self-signed certs only) |
| `connect_timeout_secs` | `10` | Seconds before a connection attempt gives up |
| `display_name_attr` | `cn` | LDAP attribute holding the display name |
| `email_attr` | `mail` | LDAP attribute holding the email address |

For Active Directory, the search filter is usually `(sAMAccountName={})`.

**Groups.** When `group_search_base` and `group_search_filter` are both set,
persea resolves the user's group memberships. Groups are used for two things:
folder access (see [Roles and Access Control](roles-and-access-control.md))
and automatic role assignment (group-to-role mappings on the Admin page).

### Verify

1. Restart persea (`sudo systemctl restart persea`).
2. Log in on the web UI with a real directory account.
3. Check the log for the bind sequence:

```bash
journalctl -u persea | grep -i ldap
```

You should see the service bind succeed and the user search find one entry.

### Common problems

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| Login fails with a bind error | Wrong `bind_dn` / `bind_password` | Check the service account can bind and search |
| "No LDAP user found" | `user_search_filter` doesn't match the username format | For AD use `(sAMAccountName={})`; test with `ldapsearch` |
| "Ambiguous: N LDAP users matched" | The filter matches more than one account | Make the filter unique per user |
| TLS handshake failure | Self-signed or internal CA | Set `starttls = true` or add the CA to the system trust store; `tls_skip_verify = true` is for debugging only |
| Groups never resolve | `group_search_base` / `group_search_filter` missing or wrong | Both must be set; the filter's `{}` is replaced with the user's DN |

---

## SAML single sign-on

**What it is.** Browser-based single sign-on: users click "Login", get
redirected to your identity provider (Okta, Entra ID, ADFS, Keycloak,
SimpleSAMLphp, ...), authenticate there, and are sent back already logged in.
SAML is the XML-based SSO protocol that many enterprise IdPs still require.

**When to use it.** Your organisation uses a SAML identity provider and you
can't use OIDC (persea's simpler, recommended protocol). If your IdP supports
both, prefer OIDC.

### Setup

**1. Register persea as a service provider (SP) at your IdP.** You'll need two
values from the IdP: its **metadata URL** (an XML document describing it) and
the entity ID it expects from persea. At the IdP, register:

- **Entity ID**: your chosen `entity_id` (e.g. `persea`)
- **ACS URL** (Assertion Consumer Service: where the IdP posts the login
  response): `https://your-host/auth/saml/acs`

**2. Configure persea:**

```toml
[auth]
methods = ["saml", "database"]

[auth.saml]
idp_metadata_url = "https://idp.example.com/metadata"  # or idp_metadata_file = "/etc/persea/idp-metadata.xml"
entity_id = "persea"
acs_url = "https://your-host/auth/saml/acs"
groups_attribute = "groups"   # optional: SAML attribute carrying group memberships
```

Optional keys:

| Key | What it does |
|-----|-------------|
| `idp_metadata_file` | Local path to the IdP metadata XML (alternative to `idp_metadata_url`) |
| `certificate` | Base64-encoded SP X.509 certificate, if you want persea to sign its login requests |
| `private_key` | PEM private key matching `certificate` |
| `strict_mode` | `true` (default): reject responses with missing or expired assertions |
| `groups_attribute` | SAML attribute name to read group memberships from (for folder access and group-to-role mappings) |

### Verify

1. Restart persea.
2. `curl https://your-host/auth/saml/metadata`: persea serves its SP metadata
   here; check the ACS URL and entity ID match what you registered at the IdP.
3. Click the SAML button on the login page and complete a login.

### Common problems

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| Login fails with an audience error | The `entity_id` doesn't match what the IdP has registered | Register the same value at both ends |
| Responses rejected | Clock skew between persea and the IdP | Synchronise clocks (NTP) |
| Metadata won't parse | The URL returns HTML or an auth page instead of XML | Download the XML and use `idp_metadata_file` |

---

## OIDC single sign-on

**What it is.** OpenID Connect, the modern, JSON-based SSO protocol. Users
click "Login", authenticate at your identity provider (Authentik, Keycloak,
Okta, Entra ID/Azure AD, Google, ...), and are returned logged in. Works with
any standards-compliant OIDC provider.

**When to use it.** Your identity provider supports OIDC. This is persea's
recommended SSO option, simpler to set up than SAML and the most commonly
supported.

### Setup

1. Register an application with your OIDC provider.
2. Set the redirect URI to `https://your-host/auth/callback`.
3. Note the client ID and client secret.
4. Add the `[oidc]` section to your config:

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/persea/"
client_id = "your-client-id"
client_secret = "your-client-secret"
redirect_uri = "https://your-host/auth/callback"
default_role = "operator"
groups_claim = "groups"
extra_scopes = ["groups"]
```

| Key | Default | What it does |
|-----|---------|-------------|
| `issuer_url` | - | Your provider's issuer URL (from its OIDC discovery document) |
| `client_id` / `client_secret` | - | The application credentials from your provider |
| `redirect_uri` | - | Must match what you registered (usually `https://your-host/auth/callback`) |
| `default_role` | `operator` | Role a brand-new user gets on first login |
| `groups_claim` | `groups` | Name of the ID-token claim carrying group memberships |
| `extra_scopes` | `[]` | Extra OAuth scopes to request (e.g. `["groups"]`) |
| `ca_cert` | - | PEM file of a private/internal CA used by your IdP |
| `tls_skip_verify` | `false` | Skip certificate checks: debugging only; exposes your client secret and tokens to interception |

**Client secret via environment variable.** Recommended for production; the
env var wins over the config file:

```bash
echo 'OIDC_CLIENT_SECRET=your-secret' >> /opt/persea/env
chmod 600 /opt/persea/env
```

**Groups.** persea reads the `groups_claim` from the ID token and uses it for
folder access and automatic role assignment (see
[Roles and Access Control](roles-and-access-control.md)). If your provider
needs an extra scope to include groups in the token, add it to
`extra_scopes`. (Exception: Microsoft Entra ID, see below.)

### Login flow, end to end

1. User clicks **Login** on the web UI.
2. Browser is redirected to the provider (with PKCE, a protocol-level proof of
   possession).
3. After authentication, the provider redirects to `/auth/callback`.
4. persea validates the token, extracts user info and groups.
5. The user record is created or updated in the database.
6. Group-to-role mappings are evaluated (highest matching role wins).
7. A session cookie is set and the user lands in the application.

**Logout.** `POST /auth/logout` clears the session cookie and deletes the auth
session from the database (CSRF-protected).

### Authentik setup guide

Authentik is a recommended open-source identity provider.

**1. Create a `groups` scope mapping** (Authentik doesn't ship one by default,
so the `groups` scope can't be selected on the provider until it exists):

- **Customisation > Property Mappings > Create**
- Type: **Scope Mapping** (under OAuth2/OpenID)
- Name: `persea groups`; Scope name: `groups`
- Expression:

  ```python
  return {
      "groups": [group.name for group in request.user.ak_groups.all()],
  }
  ```

**2. Create a provider:** **Applications > Providers > Create**, type
**OAuth2/OpenID Connect**. Name `persea`, pick your authorization flow (e.g.
`default-provider-authorization-implicit-consent`), client type
**Confidential**, redirect URI `https://your-persea-host/auth/callback`. Under
**Advanced protocol settings**, select `openid`, `email`, `profile` **and the
`persea groups` mapping**.

**3. Create an application:** **Applications > Applications > Create**, name
and slug `persea`, select the provider, launch URL `https://your-persea-host/`.

**4. Note the Client ID / Client Secret** from the provider page. The issuer
URL is `https://authentik.example.com/application/o/persea/`.

**5. Configure persea:**

```toml
[oidc]
issuer_url = "https://authentik.example.com/application/o/persea/"
client_id = "your-client-id"
redirect_uri = "https://your-persea-host/auth/callback"
default_role = "operator"
groups_claim = "groups"
extra_scopes = ["groups"]
```

```bash
echo 'OIDC_CLIENT_SECRET=your-client-secret' >> /opt/persea/env
chmod 600 /opt/persea/env
sudo systemctl restart persea
```

**6. (Optional) Group-to-role mappings:** create groups in Authentik (e.g.
`persea-admins`, `persea-operators`), assign users, then map the groups to
roles on the persea Admin page. See
[Roles and Access Control](roles-and-access-control.md).

### Microsoft Entra ID (Azure AD) setup guide

Entra ID works via OIDC, but its groups handling is different from
Authentik/Keycloak and trips people up.

> **Key difference:** Entra ID has **no `groups` OAuth scope**. Groups arrive
> as a **claim** in the ID token, configured per app registration. Copying
> `extra_scopes = ["groups"]` from the Authentik config fails at login with:
>
> ```
> AADSTS650053: The application asked for scope 'groups' that doesn't exist on the resource '00000003-0000-0000-c000-000000000000'
> ```

**1. Register the app:** **Microsoft Entra ID > App registrations > New
registration**. Name `persea`, account type of your choice, redirect URI type
**Web**, value `https://your-persea-host/auth/callback`. Note the
**Application (client) ID** and **Directory (tenant) ID**.

**2. Create a client secret:** under **Certificates & secrets > Client
secrets**, note the **Value** (shown only once).

**3. Add a groups claim to the ID token** (this replaces Authentik's `groups`
scope): **Token configuration > Add groups claim**, tick **ID token**, pick
the group set (usually **Security groups**). Under **Group ID**, keep the
default (group **object IDs**, stable across renames) or choose
**sAMAccountName** if you prefer group names; if you pick names, your
group-to-role mappings must use those names.

**4. Configure persea:**

```toml
[oidc]
issuer_url = "https://login.microsoftonline.com/{tenant-id}/v2.0"
client_id = "{application-client-id}"
redirect_uri = "https://your-persea-host/auth/callback"
default_role = "operator"
groups_claim = "groups"
# DO NOT set extra_scopes = ["groups"] for Entra: groups come from the
# claim configured in step 3. Leave extra_scopes unset unless you need
# other Entra scopes.
```

```bash
echo 'OIDC_CLIENT_SECRET={your-client-secret}' >> /opt/persea/env
chmod 600 /opt/persea/env
sudo systemctl restart persea
```

Use the `v2.0` issuer URL: the v1 endpoint won't return the claims persea
expects.

**5. (Optional) Group-to-role mappings:** after a first successful login your
groups appear in the **seen groups** list on the Admin page; map them to roles
from there.

### Outbound HTTP proxy (egress)

If persea must reach your identity provider through an outbound HTTP proxy
(for example Squid), no config option is needed; the OIDC client honours the
standard proxy environment variables:

```bash
cat >> /opt/persea/env <<'EOF'
HTTPS_PROXY=http://squid.internal:3128
HTTP_PROXY=http://squid.internal:3128
NO_PROXY=127.0.0.1,localhost,.internal
EOF
systemctl restart persea
```

Notes:

- The proxy URL scheme is `http://` (your connection to Squid) even when the
  issuer is `https`; persea tunnels through the proxy with an HTTP `CONNECT`.
- Variables are read once at startup, so restart after changing them.
- **Vault shares the same variables**: if your Vault is internal, add its
  host to `NO_PROXY`. Connections to guacd are local TCP and never proxied.
- **TLS interception (SSL bump):** if Squid re-signs TLS, persea must trust
  Squid's CA; add it to the system trust store or point persea at it:

  ```toml
  [oidc]
  ca_cert = "/etc/persea/squid-ca.pem"
  ```

  Do **not** use `tls_skip_verify = true` to work around a bump; it disables
  certificate verification entirely and exposes your client secret and tokens
  to man-in-the-middle. A plain `CONNECT` tunnel without bump passes the
  provider's certificate through untouched and needs nothing extra.

### OIDC troubleshooting

- **`AADSTS650053: scope 'groups' doesn't exist`**: you have
  `extra_scopes = ["groups"]` for Entra. Remove it (see the Entra guide).
- **No groups after login**: check the groups claim is configured at the
  provider and that you're using the `v2.0` Entra issuer.
- **Groups appear as object IDs, not names**: that's Entra's default. Use the
  object IDs in your mappings, or switch the claim to `sAMAccountName`.
- **Login works but `default_role` isn't applied**: `default_role` only fires
  when no group-to-role mapping matches. For a single-user test, set
  `default_role = "admin"` temporarily to bootstrap.

---

## RADIUS authentication

**What it is.** Authenticates usernames and passwords against a RADIUS server, the same protocol your VPN, Wi-Fi, and network gear probably already use.
persea speaks RADIUS over UDP (RFC 2865) with PAP, CHAP, or MS-CHAPv2, and can
also act as a second factor using the RADIUS challenge/response flow.

**When to use it.** Your organisation authenticates against RADIUS
infrastructure (often built on FreeRADIUS or a vendor appliance) and you want
the same credentials to work here. RADIUS-as-MFA is handy when you already
push one-time codes through RADIUS (e.g. Duo-style Access-Challenge).

### Setup

```toml
[auth]
methods = ["radius", "database"]

[auth.radius]
hostname = "10.0.0.1"          # RADIUS server
port = 1812                    # default 1812 (alias: auth_port)
shared_secret = "your-secret"  # shared between persea and the RADIUS server (alias: secret)
timeout_secs = 5               # request timeout (alias: timeout)
retries = 3                    # retries on timeout
nas_identifier = "persea"      # NAS identifier reported to the server
# nas_ip = "10.1.2.3"          # NAS IP reported to the server (optional)
# auth_protocol = "pap"        # pap (default), chap, or mschapv2
# mode = "primary"             # primary (default) or mfa
```

**RADIUS as a second factor:** set `mode = "mfa"` and list `radius` in
`methods` after a primary provider, the password is checked first, then
persea runs the RADIUS Access-Challenge flow (one-time codes, push prompts)
before the login completes.

### Verify

1. Restart persea.
2. Log in with a test account.
3. On the RADIUS server, watch for the Access-Request from persea followed by
   Access-Accept (good) or Access-Reject (bad credentials or wrong secret).

### Common problems

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| Every login rejected | Wrong `shared_secret` | Confirm it matches the RADIUS client entry for persea |
| Timeouts | RADIUS unreachable or UDP blocked | Check UDP port 1812 both ways |
| Works in a RADIUS client test tool but not persea | NAS attributes expected by your server | Set `nas_identifier` / `nas_ip` to values your server expects |

---

## TOTP second factor

**What it is.** Time-based one-time passwords, the 6-digit codes from an
authenticator app (Google Authenticator, Aegis, 1Password, ...). Each user
enrolls a secret, and every login asks for a fresh code.

**When to use it.** You want a second factor on top of passwords, either
voluntarily for everyone, or enforced (admins only, or everyone).

### Setup

```toml
[auth]
methods = ["database", "totp"]   # totp is the second factor; order among the rest doesn't matter for it

[auth.totp]
issuer = "persea"     # shown in the authenticator app
digits = 6            # code length
period = 30           # seconds per code
skew = 1              # how many periods ahead/behind are accepted
enforcement = "Off"   # Off | AdminsOnly | All
```

**How enrollment works:** users generate a QR code on their
**account/TOTP page**, scan it into their authenticator app, and confirm with
one code. After the first factor succeeds, the login flow redirects to a
code-entry page.

**Enforcement levels:**

| Setting | Effect |
|---------|--------|
| `Off` (default) | No one is required to enroll; users can opt in themselves |
| `AdminsOnly` | Every admin login requires a TOTP code |
| `All` | Every user's login requires a TOTP code |

### Verify

1. Restart persea.
2. Enroll a test account (account/TOTP page) and log in: you should be asked
   for a code after the password.
3. Enter a wrong code to confirm it is rejected.

### Common problems

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| Codes rejected | Phone clock is off | Sync the phone's clock; TOTP tolerates ~±1 period (`skew`) |
| No code prompt after password | Enforcement is `Off` | Users must enroll themselves; enforcement needs `AdminsOnly` or `All` |
| Can't enroll | Recovery codes not saved | Save the recovery codes shown during enrollment: they're the way back in if the app is lost |

---

## Vault / OpenBao for connection credentials

**What it is.** An external secrets manager (HashiCorp Vault or the open-source
OpenBao) that stores the passwords, keys, and other secrets used by address
book entries. persea authenticates to Vault with AppRole (a machine
credential: a `role_id` that lives in config plus a rotating `secret_id` in
the environment).

**When to use it.** You already run Vault and want connection credentials to
live there instead of persea's database, or you need credentials shared
across several persea instances, or separated per instance. **You don't need
Vault at all by default:** the address book is database-first, and credentials
are encrypted at rest (AES-256-GCM) whenever `[storage].encryption_key` is
set (see [Configuration](configuration.md#storage-section)). Switch to Vault
only if you want an external store:

```toml
[storage]
backend = "vault"   # "db" (default) or "vault"
```

Either way, credentials are read server-side and never sent to the browser.
The setup below describes Vault mode; the "Entry types", "Name validation",
and "Credential prompting" sections apply in both modes.

### Quickstart script

For a fresh single-host install, `contrib/vault-quickstart.sh` automates the
manual steps below. It auto-detects the `vault` or `bao` CLI and supports
three modes:

| Mode | What it does | Use it for |
|------|-------------|------------|
| (default) | Provisions an existing Vault using `$VAULT_ADDR` and `$VAULT_TOKEN` | Already-deployed Vault |
| `--dev` | Spawns an in-memory dev-mode server and provisions it | Demos, throwaway development |
| `--local` | Installs Vault or OpenBao as a systemd service with file storage and on-disk auto-unseal | Single-host persea deployments |

```bash
# Bootstrap an existing Vault:
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.xxxxxxxx
./contrib/vault-quickstart.sh

# Install Vault locally with auto-unseal (after `apt install vault`):
sudo ./contrib/vault-quickstart.sh --local

# Same with OpenBao:
sudo ./contrib/vault-quickstart.sh --cli bao --local
```

The script does **not** install Vault/OpenBao itself; install one from your
distribution or upstream first. Afterwards it prints the `[vault]` block for
`config.toml` and the `VAULT_SECRET_ID` line for the systemd env file.

> **`--local` security caveat:** the unseal key is stored on disk
> (`/etc/vault.d/unseal-key` or `/etc/openbao/unseal-key`, mode 0400
> root:root). Anyone who can read it owns the secret store. That trade is
> acceptable for single-host persea boxes (where root already means total
> compromise) but not for higher-stakes deployments: there, use cloud-KMS
> auto-unseal: [Vault](https://developer.hashicorp.com/vault/docs/configuration/seal)
> | [OpenBao](https://openbao.org/docs/configuration/seal/).

### Vault from zero: complete setup guide

Walk through every step from a bare server to a working persea + Vault
integration, skipping whatever is already done.

**1. Install Vault** (Debian/Ubuntu, HashiCorp APT repo):

```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
vault --version
```

**2. Initialise Vault.** For dev/test, one key share suffices (NOT for
production):

```bash
vault operator init -key-shares=1 -key-threshold=1
```

Save the output: the **Unseal Key** (needed after every restart) and the
**Root Token** (initial admin access). For production/HA use 5 shares with
threshold 3:

```bash
vault operator init -key-shares=5 -key-threshold=3
```

**3. Unseal Vault** after every restart, then confirm it's open:

```bash
vault operator unseal <unseal-key>
vault status   # should show Sealed: false
```

**4. Enable the KV v2 secrets engine:**

```bash
vault secrets enable -path=secret kv-v2
```

**5. Create a policy for persea**, `persea-policy.hcl`:

```hcl
# Connections entries: create, read, update, soft-delete
path "secret/data/persea/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Folder/entry listing and permanent deletion
# KV v2 permanent deletes go through the metadata/ path, not data/
path "secret/metadata/persea/*" {
  capabilities = ["list", "read", "delete"]
}
```

```bash
vault policy write persea persea-policy.hcl
```

> **Both paths are required.** A common mistake is omitting `delete` on the
> metadata path, which causes "vault access denied" errors when deleting
> entries or folders.

**6. Enable AppRole auth** and create a role for persea:

```bash
vault auth enable approle

vault write auth/approle/role/persea \
    token_policies="persea" \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_ttl=0

# role_id  -> goes in config.toml
vault read auth/approle/role/persea/role-id

# secret_id -> goes in the environment (VAULT_SECRET_ID)
vault write -f auth/approle/role/persea/secret-id
```

**7. Configure persea:**

```toml
[storage]
backend = "vault"

[vault]
addr = "https://vault.example.com:8200"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# mount = "secret"          # KV v2 mount (default)
# base_path = "persea"      # base path (default)
# namespace = "my-ns"       # Vault Enterprise / OpenBao namespaces
# instance_name = "prod-1"  # instance-scoped entries (multi-instance)
```

```bash
echo 'VAULT_SECRET_ID=<secret_id>' > /opt/persea/env
chmod 600 /opt/persea/env
```

**8. Verify:**

```bash
# Put a test entry
vault kv put secret/persea/shared/test-folder/test-entry \
    type=ssh hostname=localhost port=22 username=testuser

# Check persea logs for successful Vault auth
journalctl -u persea | grep -i vault
# Expected: "Vault: authenticated via AppRole, token TTL=3600s"

# Open the Connections page: you should see test-folder with test-entry inside
```

### mTLS (client certificates)

If your Vault/OpenBao server requires mutual TLS, add certificate paths to
`[vault]`:

```toml
[vault]
addr = "https://openbao.example.com:8200"
role_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
ca_cert = "/opt/persea/certs/vault-ca.pem"
client_cert = "/opt/persea/certs/vault-client.pem"
client_key = "/opt/persea/certs/vault-client-key.pem"
```

| Field | What it is |
|-------|-----------|
| `ca_cert` | Custom CA (PEM) for verifying the Vault server: for private/self-signed CAs |
| `client_cert` | Client certificate (PEM) presented to Vault for mTLS |
| `client_key` | Client private key (PEM); required when `client_cert` is set |

Keep the files readable by the `persea` user with tight permissions:

```bash
mkdir -p /opt/persea/certs
cp ca.pem client.pem client-key.pem /opt/persea/certs/
chown persea:persea /opt/persea/certs/*
chmod 600 /opt/persea/certs/client-key.pem
chmod 644 /opt/persea/certs/ca.pem /opt/persea/certs/client.pem
```

### Vault Enterprise / OpenBao namespaces

With namespaces in use, set `namespace` so persea sends the
`X-Vault-Namespace` header on every request:

```toml
[vault]
namespace = "admin"
```

All Vault CLI commands must target the same namespace:

```bash
vault namespace exec -namespace=admin -- vault auth enable approle
vault namespace exec -namespace=admin -- vault policy write persea persea-policy.hcl
```

Without the field, persea talks to the root namespace; an AppRole in a
sub-namespace then fails with 403.

### KV v2 path structure

| Path | What lives there |
|------|-----------------|
| `persea/shared/<folder>/.config` | Folder metadata: `{"allowed_groups":[...], "description":"..."}` |
| `persea/shared/<folder>/<entry>` | Connection entry (shared across all instances) |
| `persea/instance/<name>/<folder>/<entry>` | Instance-specific entry (requires `instance_name`) |

### AppRole token management

persea manages Vault tokens automatically: authenticates via AppRole on
startup, renews tokens at 50% of their TTL, falls back to full
re-authentication on a 403, and retries every 30 seconds if Vault is down at
startup (not fatal).

### Multiple instances sharing one Vault

With `instance_name` set, persea sees both shared entries and entries scoped
to its instance: `shared/` entries are visible to every instance,
`instance/<name>/` entries only to the named one, so a fleet can share common
entries while keeping instance-specific ones. Multiple Vault backends (a
central `[vault_shared]` plus a per-host `[vault_local]`) are covered in
[Configuration](configuration.md#multiple-vault-backends-disaster-recovery).

### Entry types

Address book entries can be SSH, RDP, VNC, Web, SPICE, VDI, or Proxmox
connections. Each entry stores: connection type and target (hostname, port,
URL), credentials (username, password, private key), protocol-specific
settings, plus:

- **Multi-hop SSH tunnel chain**: optional ordered list of SSH bastion hosts
  (all session types)
- **Prompt for credentials**: ask the user for credentials at connect time,
  even when stored credentials exist
- **NLA auth package** (RDP): force Kerberos or NTLM for NLA
- **KDC URL** (RDP): Kerberos KDC/proxy URL
- **Disable copy / Disable paste**: per-entry clipboard control (all types)
- **Autofill** (Web): pre-populate Chromium's autofill database, with
  `$USERNAME`/`$PASSWORD` placeholders and multiple URLs for SSO redirect
  chains
- **Allowed domains** (Web): restrict which domains the browser can reach
- **Login script** (Web): server-side script that runs after Chromium spawns
  for complex login automation

### Name validation

Folder and entry names allow alphanumeric characters, hyphens, underscores,
and dots only, 1–64 characters. `/`, `\`, and `..` are blocked to prevent path
traversal in Vault.

### Credential prompting

Entries can prompt users for credentials at connect time, useful for entries
without stored credentials (e.g. RDP servers where each user has their own AD
account: the admin stores just hostname/port) or stored credentials as a
fallback. The prompt appears when the entry has **Prompt for credentials**
enabled, **or** when it has no stored password or private key. Prompted
credentials are **never stored**; used for the current session only. For web
sessions they feed autofill (`$USERNAME`/`$PASSWORD`) and login scripts (see
[Web Browser Sessions](web-sessions.md)).

---

## Proxmox VE

**What it is.** Streams the console of a Proxmox VE virtual machine or LXC
container straight into the browser, through the PVE API; users don't need
accounts on the PVE host, just an entry in the address book. persea negotiates
the right console (VNC/SPICE/serial) with PVE automatically.

**When to use it.** Your VMs and containers run on Proxmox VE and you want
one-click console access from persea.

### Setup

**1. Create an API token in PVE** (Datacenter → Permissions → API Tokens). The
token ID has the form `user@realm!tokenname` (e.g. `root@pam!persea`). Grant
it at minimum: **Sys.Audit** on `/`, and **VM.Audit** + **VM.Console** on the
VMs it should reach.

**2. Create an address book entry** of type **Proxmox VE console** with:

| Field | Example |
|-------|---------|
| Proxmox API URL | `https://pve.example.com:8006` |
| VM ID | `100` (shown in the PVE UI next to the VM name) |
| Node | leave blank (auto-detected) |
| API token ID | `root@pam!persea` |
| API token secret | the token's secret value |
| Verify TLS | on (leave on unless PVE uses a self-signed cert you don't want to trust) |

These settings are stored per entry (`proxmox_url`, `proxmox_node`,
`proxmox_vmid`, `proxmox_token_id`, `proxmox_token_secret`,
`proxmox_verify_tls`); there is no global Proxmox config section.

### Verify

1. Save the entry and click **Connect** on the Connections page.
2. The VM console should stream in the browser. The session shows up in the
   Sessions page and in recordings/reports like any other session.

### Common problems

| Problem | Likely cause | Fix |
|---------|-------------|-----|
| 401/403 from PVE | Token permissions too narrow | Add Sys.Audit, VM.Audit, VM.Console for the VM(s) |
| Connection refused | Wrong API URL or port | Confirm `https://<host>:8006` is reachable from the persea server |
| Certificate error | PVE uses a self-signed cert | Uncheck **Verify TLS** on the entry (or add PVE's CA to the system trust store) |
| Console hangs / blank | VM powered off or no console agent | Power the VM on; check the VM ID is right |

---

## VMware vSphere

**What it is.** Connects to vCenter Server over the vSphere REST API, lists
your VMs on the Connections page, and auto-detects the right protocol for
each one: Windows VMs open through RDP, Linux/BSD/Solaris through SSH,
everything else through VNC. guacd connects to the guest IP directly.

**When to use it.** Your virtual machines run on vSphere and you want an
inventory-driven Connections page instead of hand-maintaining entries.

### Setup

**1. Create a vSphere user** (or reuse one) with at least these privileges on
the target VMs:

- `VirtualMachine.Inventory.List` (to see VMs)
- `VirtualMachine.Interact.PowerOn` / `PowerOff` / `Reset` / `Suspend` (VM
  lifecycle from the inventory)

**2. Put the password in the environment** (not in config):

```bash
echo 'VSPHERE_PASSWORD=your-vcenter-password' >> /opt/persea/env
chmod 600 /opt/persea/env
```

**3. Add the section to config.toml:**

```toml
[vsphere]
vcenter_addr = "https://vcenter.example.com/sdk"
username = "administrator@vsphere.local"
# password_env = "VSPHERE_PASSWORD"  # default, matches step 2
# insecure = false                   # true for self-signed certs (dev/test)
# refresh_interval_secs = 300        # VM inventory refresh (5 min)
```

**4. Restart persea.**

### Configuration reference

| Field | Default | What it is |
|-------|---------|-----------|
| `vcenter_addr` | (required) | vCenter SDK URL (ends in `/sdk`) |
| `username` | (required) | vSphere username (e.g. `administrator@vsphere.local`) |
| `password_env` | `VSPHERE_PASSWORD` | Name of the environment variable holding the password |
| `insecure` | `false` | Skip TLS certificate verification (dev/test only) |
| `refresh_interval_secs` | `300` | How often to refresh the VM inventory (seconds) |

**Per-VM credential overrides**, for VMs whose guest OS user differs from
the global vSphere credentials:

```toml
[vsphere.vm_credentials]
"web-server-01" = { username = "deploy", password_env = "WEB_DEPLOY_PASS" }
"db-server-02" = { username = "admin", password_env = "DB_ADMIN_PASS" }
```

VMs without an override use the global username and password.

### Protocol detection

persea maps the guest OS reported by vCenter to a protocol automatically:

| Guest OS family | Protocol | Port |
|----------------|----------|------|
| Windows (`win*`) | RDP | 3389 |
| Linux (`linux*`, `ubuntu*`, `debian*`, `rhel*`, ...) | SSH | 22 |
| BSD, Solaris | SSH | 22 |
| Everything else | VNC | 5900 |

### Using the inventory

With `[vsphere]` configured, the Connections page shows a **vSphere Virtual
Machines** section listing every VM with its power state, guest OS, and IP
address. Per VM:

- **Connect** opens a session to the guest IP via the detected protocol. The
  VM must be powered on and report a guest IP (VMware Tools).
- Guest credentials come from the matching `[vsphere.vm_credentials]` override
  (keyed by VM name or ID), falling back to the global credentials.
- The list refreshes on page load; use **Refresh** to re-fetch.

The connect flow is server-side: the session appears in the Sessions page and
in recordings/reports like any other connection.

### Verify and troubleshoot

**Verify:** open the Connections page: the VM list should populate within a
refresh interval. **Cannot connect to vCenter:** check `vcenter_addr` ends
with `/sdk` and HTTPS is reachable; for self-signed certs set `insecure = true`
or add vCenter's CA to the system trust store. **Empty VM list:** the vSphere
user needs `VirtualMachine.Inventory.List` at the right scope (datacenter,
cluster, or folder). **No IP address:** VMware Tools must be installed and
running in the guest.

---

## SSH tunnels / multi-hop jump hosts

**What it is.** Routes any session type (SSH, RDP, VNC, web browser) through
one or more SSH bastion hosts, in sequence, for reaching machines on isolated
networks from the persea server.

**When to use it.** The target isn't directly reachable from persea, e.g. an
RDP server on a separate network segment behind a bastion chain.

### How it works

Each hop opens an SSH connection and a `direct-tcpip` port forward to the next
hop:

```
persea -> [SSH] bastion-1:22 -> [SSH] bastion-2:22 -> [TCP] target:3389
```

Hops are set up in order (each must connect before the next starts) and torn
down in reverse when the session ends.

### Configuration

**Connections entries:** in the entry editor, click **Add Jump Host** to add
hops. Each hop has its own credentials. A visual flow diagram shows the path.
Hop credentials are stored with the entry's other credentials and never sent
to the browser; editing an entry preserves existing hop passwords/keys when
the form omits them.

**Ad-hoc sessions:** powerusers get the same multi-hop card (SSH Tunnel
section, **Add Jump Host**) when creating sessions from the Sessions page.

**Per-hop fields:**

| Field | What it is |
|-------|-----------|
| `hostname` | SSH bastion hostname (required) |
| `port` | SSH port (default 22) |
| `username` | SSH username (required) |
| `password` | SSH password |
| `private_key` | OpenSSH PEM private key |

Provide at least one of `password` or `private_key` per hop.

### Supported session types

| Session type | Jump hosts | Notes |
|-------------|-----------|-------|
| SSH | Yes | Tunnel forwards to the SSH target |
| RDP | Yes | Tunnel forwards to the RDP target |
| VNC | Yes | Tunnel forwards to the VNC target |
| Web | Yes | Tunnel forwards to the URL's host:port (80 for HTTP, 443 for HTTPS); the URL passed to Chromium is rewritten to `{scheme}://127.0.0.1:{tunnel_port}{path}` |

**Web session caveat:** HTTPS targets will show certificate warnings because
the hostname no longer matches the certificate. The original URL is still
displayed in the session list.

### Compatibility and errors

Legacy flat fields (`jump_host`, `jump_port`, `jump_username`,
`jump_password`, `jump_private_key`) are still accepted and normalised into a
single-element `jump_hosts` array (which wins when both are present). Tunnel
errors name the failing hop ("hop 2"), and when any hop fails all previously
established hops are torn down cleanly.

---

## RDP Kerberos NLA authentication

**What it is.** Lets RDP sessions authenticate to Windows with Kerberos
instead of NTLM. Microsoft is phasing out NTLM, and accounts in the Active
Directory **Protected Users** group can't use NTLM at all, so Kerberos is
required to reach them.

**When to use it.** Your RDP targets are domain-joined Windows machines and
you have Kerberos working (reachable KDC). Otherwise the default NTLM
negotiation is fine.

### How it works

FreeRDP doesn't implement Kerberos itself; it delegates to the system's MIT
Kerberos libraries (via WinPR's SSPI layer), so persea's guacd reads
`/etc/krb5.conf`, uses the system credential cache, and honours `KRB5_CONFIG`
and `KRB5_TRACE`. Username and password are still required; Kerberos replaces
the wire protocol (NTLM → Kerberos), not the credential input.

### Per-entry configuration

| Setting | Values | What it does |
|---------|--------|-------------|
| **NLA Auth Package** | `(default)`, `ntlm`, `kerberos` | Force a specific NLA method; default negotiates |
| **KDC URL** | URL | KDC or KDC-proxy URL; overrides DNS SRV and krb5.conf for KDC discovery |
| **Prompt for credentials** | checkbox | Ask the user for username/password/domain at connect time |

### Prerequisites

- **Packages:** on Debian 13 the Kerberos runtime libraries already come in
  with FreeRDP 3. Install `krb5-user` only if you want `kinit`/`klist` for
  testing.
- **Network:** TCP 88 from guacd to the Domain Controller (AS-REQ/TGS-REQ);
  TCP 443 to a KDC proxy if you use `kdc-url`; TCP 3389 to the RDP target.
- **Clock sync:** Kerberos tolerates ~5 minutes of skew: keep NTP on.
- **DNS:** the RDP target hostname **must be an FQDN** (e.g.
  `fileserver.corp.example.com`), because Kerberos builds the service
  principal (`TERMSRV/host@REALM`) from it. IPs and short names fail. For
  automatic KDC discovery the domain needs an SRV record:
  `_kerberos._tcp.EXAMPLE.COM. SRV 0 0 88 dc1.example.com.`
- The guacd server itself does **not** need to be domain-joined: only network
  access to the KDC.

### KDC discovery: three options

In priority order:

1. **KDC Proxy URL** (simplest across networks): set the entry's **KDC URL**
   to your KDC proxy (e.g. `https://dc.example.com/KdcProxy`). Bypasses DNS
   SRV and krb5.conf entirely; Windows Server's KDC Proxy Service can serve
   this role.
2. **DNS SRV records** (simplest on-network): if the guacd host uses the
   domain's DNS and the SRV records exist, nothing more is needed.
3. **`/etc/krb5.conf`** (explicit): when SRV records aren't available and
   there's no proxy:

   ```ini
   [libdefaults]
       default_realm = EXAMPLE.COM
       dns_lookup_kdc = false
       dns_lookup_realm = false
       udp_preference_limit = 1

   [realms]
       EXAMPLE.COM = {
           kdc = tcp/dc1.example.com
           admin_server = dc1.example.com
       }
       example.com = {
           kdc = tcp/dc1.example.com
           admin_server = dc1.example.com
       }

   [domain_realm]
       .example.com = EXAMPLE.COM
       example.com = EXAMPLE.COM
   ```

   Notes: define realms in **both uppercase and lowercase** (GSSAPI on Linux
   is case-sensitive); use `tcp/` prefixes to force TCP; and remember **a
   broken krb5.conf is worse than none**; stale entries can hang FreeRDP 3
   indefinitely during authentication.

### Username format

Use UPN format (`user@EXAMPLE.COM`), more reliable with GSSAPI on Linux than
`DOMAIN\user`. The **Domain** field takes the AD domain name (`EXAMPLE.COM`).

### Example entry

- **Type**: RDP; **Hostname**: `fileserver.corp.example.com` (FQDN);
  **Port**: 3389; **Security**: NLA; **NLA Auth Package**: Kerberos;
  **KDC URL**: `https://dc.corp.example.com/KdcProxy` (if the KDC isn't
  directly reachable); **Prompt for credentials**: checked; **Domain**:
  `CORP.EXAMPLE.COM`

Users are then prompted for username, password, and domain, and the session
authenticates via Kerberos NLA.

### Troubleshooting

Enable Kerberos tracing to see what's happening:

```bash
echo 'KRB5_TRACE=/dev/stderr' >> /opt/persea/env
sudo systemctl restart persea
journalctl -u persea -f
```

Test Kerberos by hand from the guacd server:

```bash
dig SRV _kerberos._tcp.EXAMPLE.COM
kinit user@EXAMPLE.COM && klist
xfreerdp3 /v:server.example.com /u:user@EXAMPLE.COM /d:EXAMPLE.COM \
  /auth-pkg-list:'!ntlm,kerberos' /cert:ignore
```

| Problem | Cause | Fix |
|---------|-------|-----|
| Connection hangs indefinitely | Broken krb5.conf with unreachable KDCs | Fix/delete krb5.conf, or use `kdc-url` |
| "Authentication failed" | Wrong username format, unreachable KDC, wrong domain | Use UPN (`user@REALM`), verify KDC connectivity |
| "Clock skew too great" | Time off by > 5 minutes | `timedatectl set-ntp true` |
| Kerberos fails, no NTLM fallback | `kerberos` auth package disables NTLM | Fix Kerberos, or use default (negotiate) for fallback |
| "Cannot resolve host"/SPN failure | Hostname is an IP or short name | Use the FQDN matching the AD computer object |

---

## PowerShell remoting over SSH

**What it is.** A connection entry type that opens a PowerShell session on a
Windows host over SSH. persea connects to the host's OpenSSH server and
launches the configured PowerShell binary (default `pwsh.exe`), giving the
user an interactive PowerShell prompt in the terminal client.

**When to use it.** You manage Windows servers from the command line and the
hosts run Windows OpenSSH. WinRM-based remoting is on the roadmap (persea
v1.3.0, tracked in persea-guacamole-server#16); this entry type is the SSH
transport only.

### Windows host setup

**1. Install OpenSSH Server** on the Windows host (PowerShell as
Administrator):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic
```

**2. Make sure the firewall allows port 22:**

```powershell
New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

**3. Set the default shell to PowerShell** (optional but recommended, so
plain SSH logins also land in PowerShell):

```powershell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
  -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -PropertyType String -Force
```

The entry type launches the configured binary explicitly, so this step is
only needed for plain SSH sessions to the host.

### Using the entry type in persea

1. Open **Connections** → select a folder → **+ Add Entry**.
2. Choose **PowerShell (SSH)** as the type. Hostname and port (22) are
   filled in like an SSH entry; the **PowerShell binary** field defaults to
   `pwsh.exe` and can point at any executable on the host (for example
   `C:\Program Files\PowerShell\7\pwsh.exe`).
3. Enter the Windows account credentials (or leave blank to use your preset
   credentials / be asked at connect time).
4. **Connect** opens a terminal session: persea connects over SSH and runs
   the configured binary as the session command.

The entry behaves like an SSH entry for everything else: private keys,
jump hosts, SFTP file transfer, clipboard controls, and typescript
recording all work the same way.

### Feature toggle

PowerShell (SSH) entries are gated by the **PowerShell (SSH)** toggle under
**Settings → Features** (setting key `enable_powershell_ssh`, default on).
When disabled, the type disappears from the entry form, and both entry
creation and session creation reject the type.

### WinRM roadmap

WinRM-based PowerShell remoting (the `winrm` transport) is planned for
persea v1.3.0. It needs a guacd patch (persea-guacamole-server#16) to speak
the WinRM protocol; this entry type covers the SSH transport until then.

---

## Drive / file transfer / LUKS encryption

**What it is.** File transfer for RDP and SSH sessions. RDP gets a virtual
drive (a per-session folder on the persea server mounted into the Windows
session); SSH gets SFTP, which runs browser ⇄ target directly; no files are
stored on the persea server. The RDP drive storage can sit on a
LUKS-encrypted volume whose key lives in Vault.

### RDP drive redirection

```toml
[drive]
enabled = true
drive_path = "/mnt/persea-drives"
drive_name = "Shared Drive"
allow_download = true
allow_upload = true
cleanup_on_close = true
retention_secs = 0
```

- Each session gets its own directory under `drive_path` (named with the
  session UUID) mounted as a virtual drive in the Windows session.
- Upload and download can be enabled/disabled independently.
- Files are temporary: the session directory is deleted when the session ends
  (configurable).

**Cleanup behaviour:**

| Setting | Default | What it does |
|---------|---------|-------------|
| `cleanup_on_close` | `true` | Remove the per-session drive directory when the session ends; `false` leaves the files (still in the per-session UUID subdirectory) |
| `retention_secs` | `0` | When cleanup is on, delay before removal; `0` = immediate. Has no effect when `cleanup_on_close = false` |

Files never persist *across* sessions even with cleanup off; there's no
"personal drive" model; the flag only controls whether finished-session files
linger on disk.

### SSH SFTP

SFTP runs directly between the browser and the target SSH server via guacd;
no files touch the persea server.

### LUKS-encrypted drive storage

The `drive_path` volume can be a LUKS container. The encryption key is read
from Vault, and the volume is unlocked only while persea runs:

```toml
[drive]
enabled = true
drive_path = "/mnt/persea-drives"
luks_device = "/opt/persea/drives.luks"
luks_name = "persea-drives"
luks_key_path = "persea/luks-key"
```

**Lifecycle:** on startup persea reads the key from Vault KV, opens the
container (`cryptsetup open --type luks --key-file=-`), mounts it at
`drive_path`, and sets ownership for the persea user. On shutdown it unmounts
and closes the container. The key is passed via stdin, never on the command
line or disk.

**Setup:** run `sudo /opt/persea/bin/drive-setup.sh`: it creates the
container file, generates a random key, stores it in Vault, and installs the
sudoers rules the persea user needs for `cryptsetup`/`mount`/`umount`/`chown`.

---

## HAProxy reverse proxy

**What it is.** A production front-door example (in `haproxy.example.cfg`)
with TLS termination, HTTP→HTTPS redirect, real client IPs, WebSocket
support, health checks, slowloris protection, and HSTS. For nginx, Caddy,
Apache, and Traefik, see [reverse-proxies.md](reverse-proxies.md), and mind
the `%2F` gotcha documented there if you hit 404s on nested subfolders.

### Minimal example

```
frontend https
    bind *:443 ssl crt /etc/ssl/private/persea.pem alpn h2,http/1.1
    bind *:80
    http-request redirect scheme https unless { ssl_fc }
    http-request del-header X-Forwarded-For
    option forwardfor
    default_backend persea

backend persea
    option httpchk GET /api/health
    server persea 127.0.0.1:8089 ssl verify none check inter 30s
```

persea must trust HAProxy's IP for correct client-IP logging:

```toml
trusted_proxies = ["127.0.0.1/32"]
```

### Double TLS

In the default config, traffic is encrypted twice on loopback: HAProxy
terminates the client's TLS, then re-encrypts to persea (persea's own
self-signed cert). Belt-and-suspenders for environments where even loopback
should be encrypted.

---

## Knocknoc zero-trust access

**What it is.** [Knocknoc](https://knocknoc.io) provides identity-aware network
access control in front of persea: a `knocknoc-agent` adds and removes client
IPs on HAProxy ACLs, so only authenticated users can even see the login page.

### How it works

1. User authenticates through Knocknoc (SSO, MFA, ...).
2. `knocknoc-agent` adds the user's IP to HAProxy ACL #600 via the admin
   socket.
3. HAProxy allows access to the front page (`/`) only for those IPs.
4. The user then logs in via persea's own auth layer (e.g. OIDC).
5. When the Knocknoc session expires, the IP is removed.

### What is gated

Only the front page (`/`) is gated. Everything else passes through to
persea's own authentication, so callbacks and share links keep working even
when the user hasn't gone through Knocknoc:

- `/api/*`: API key or session auth
- `/auth/*`: OIDC/SAML login flows
- `/ws/*`: WebSocket connections
- `/share/*`: share links (share-token auth)

### HAProxy configuration

```
# Admin socket for knocknoc-agent
stats socket /run/haproxy/admin.sock mode 0660 level admin

# Dynamic ACL (ACL ID 600 must match Knocknoc config)
acl knoc_persea src -u 600
acl is_root path /

# Gate only the front page
use_backend persea if is_persea is_root knoc_persea
use_backend denied   if is_persea is_root
use_backend persea if is_persea
```

### Verifying ACL state

```bash
echo "show acl #600" | socat stdio /run/haproxy/admin.sock
```
