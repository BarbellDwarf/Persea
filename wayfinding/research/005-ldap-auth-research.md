# Research: LDAP/Active Directory Authentication in Rust

## Summary

persea needs LDAP bind-then-search authentication for enterprise deployments. The `ldap3` crate (0.12.1) is the right choice — Tokio async, pure-Rust, AD-compatible. This document covers all 9 questions from the ticket with concrete code examples and config recommendations.

---

## 1. ldap3 Crate API

### Dependencies

```toml
[dependencies]
ldap3 = { version = "0.12.1", default-features = false, features = ["tls-rustls-ring"] }
```

Use `tls-rustls-ring` (not the default `tls`/native-tls) for consistent cross-platform behavior with the existing `rustls` dependency in persea.

### Core API Pattern

```rust
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use ldap3::result::Result as LdapResult;

// 1. Open async connection
let settings = LdapConnSettings::new()
    .set_conn_timeout(std::time::Duration::from_secs(5))
    .set_starttls(true);  // or false for ldaps://

let (conn, mut ldap) = LdapConnAsync::from_url_with_settings(
    &settings,
    &url::Url::parse("ldap://dc.example.com:389")?,
).await?;
ldap3::drive!(conn);  // spawn background I/O task

// 2. Simple bind
let result = ldap.simple_bind("cn=service,ou=svc,dc=example,dc=com", "secret").await?;
result.success()?;  // returns LdapResult — check rc == 0

// 3. Search
let (entries, _res) = ldap.search(
    "ou=users,dc=example,dc=com",
    Scope::Subtree,
    "(sAMAccountName=jdoe)",
    vec!["cn", "mail", "memberOf"],
).await?.success()?;

for entry in entries {
    let e = SearchEntry::construct(entry);
    println!("DN: {}", e.dn);
    println!("memberOf: {:?}", e.attrs.get("memberOf"));
}

// 4. Unbind (cleanup)
ldap.unbind().await?;
```

### Paged Results

```rust
use ldap3::controls::PagedResults;

// Request paged results — 500 entries per page
let (entries, _res) = ldap
    .search(
        "ou=users,dc=example,dc=com",
        Scope::Subtree,
        "(objectClass=user)",
        vec!["cn", "mail"],
    )
    .await?
    .success()?;
// ldap3 handles paging automatically when using search() with controls
```

For explicit paging control, use the `PagedResults` control:

```rust
use ldap3::controls::{PagedResults, Control};

// Page through results explicitly
let page_size: u32 = 500;
let mut cookie = Vec::new();
let mut all_entries = Vec::new();

loop {
    let ctrl = PagedResults::new(page_size, cookie.clone());
    let (entries, res) = ldap
        .search(
            "ou=users,dc=example,dc=com",
            Scope::Subtree,
            "(objectClass=user)",
            vec!["cn", "mail"],
        )
        .await?
        .success()?;

    all_entries.extend(entries);

    // Parse result controls for next cookie
    if let Some(Control::PagedResults(pr)) = res.controls.iter().find_map(|c| {
        if let Control::PagedResults(_) = c { Some(c) } else { None }
    }) {
        if pr.cookie.is_empty() {
            break;  // No more pages
        }
        cookie = pr.cookie;
    } else {
        break;
    }
}
```

### Timeout

```rust
// Per-operation timeout
ldap.with_timeout(std::time::Duration::from_secs(10))
    .search(...).await?;
```

---

## 2. Direct Bind vs Search Bind

### Direct Bind

User DN is constructed by concatenating a fixed base DN with the username attribute:

```
DN = {username_attribute}={username},{user_base_dn}
```

Config:
```toml
[ldap]
user_base_dn = "ou=Users,dc=example,dc=com"
username_attribute = "sAMAccountName"
# No search_bind_dn needed — DN is derived directly
```

Code:
```rust
// Direct bind: construct DN from config
let user_dn = format!("{}={},{}", username_attribute, ldap_escape(username), user_base_dn);
let result = ldap.simple_bind(&user_dn, password).await?;
result.success()?;
```

**Pros**: Simple, no service account needed.  
**Cons**: Users MUST be direct children of `user_base_dn`. No flexibility in directory structure.

### Search Bind

Service account binds first, searches for the user's DN, then re-binds as the user:

```
Step 1: Bind as service account
Step 2: Search for DN using filter
Step 3: Unbind, re-bind as user DN
```

Config:
```toml
[ldap]
user_base_dn = "ou=Users,dc=example,dc=com"
username_attribute = "sAMAccountName"
search_bind_dn = "cn=guac-svc,ou=ServiceAccounts,dc=example,dc=com"
search_bind_password_env = "LDAP_BIND_PASSWORD"  # or inline
search_filter = "(&(objectClass=user)(sAMAccountName={username}))"
```

Code:
```rust
// Step 1: Bind as service account
ldap.simple_bind(&search_bind_dn, &search_bind_password).await?.success()?;

// Step 2: Search for user DN
let filter = search_filter.replace("{username}", &ldap_escape(&username));
let (entries, _) = ldap.search(
    &user_base_dn,
    Scope::Subtree,
    &filter,
    vec!["dn"],
).await?.success()?;

if entries.len() != 1 {
    return Err("User not found or ambiguous".into());
}
let user_dn = SearchEntry::construct(entries.into_iter().next().unwrap()).dn;

// Step 3: Unbind and re-bind as user
ldap.unbind().await?;
let (conn2, mut ldap2) = LdapConnAsync::from_url_with_settings(&settings, &url).await?;
ldap3::drive!(conn2);
ldap2.simple_bind(&user_dn, password).await?.success()?;
```

**Guacamole pattern**: Guacamole uses `ldap-search-bind-dn` for search bind and falls back to direct bind when omitted. persea should follow the same pattern — config-driven, both modes supported.

**Recommendation**: Support both modes. Default to search bind (more flexible). Direct bind when `search_bind_dn` is absent.

---

## 3. STARTTLS vs ldaps://

### STARTTLS

Upgrades a plain TCP connection (port 389) to TLS mid-session:

```rust
// STARTTLS on ldap:// (port 389)
let settings = LdapConnSettings::new()
    .set_starttls(true);

let (conn, mut ldap) = LdapConnAsync::from_url_with_settings(
    &settings,
    &url::Url::parse("ldap://dc.example.com:389")?,
).await?;
```

### ldaps://

Direct TLS from the start (port 636):

```rust
// ldaps:// — just use the ldaps URL, no starttls needed
let (conn, mut ldap) = LdapConnAsync::new("ldaps://dc.example.com:636").await?;
```

### Skip TLS verification (dev only)

```rust
let settings = LdapConnSettings::new()
    .set_no_tls_verify(true);  // DANGER: no cert verification
```

### Config

```toml
[ldap]
encryption_method = "starttls"  # "none", "starttls", or "ssl"
tls_skip_verify = false         # DANGER: only for dev/self-signed
```

**Recommendation**: Default to `starttls`. `ssl` for LDAPS. `none` only for dev. Provide `tls_skip_verify` for self-signed certs.

---

## 4. Active Directory Patterns

### sAMAccountName vs userPrincipalName

| Attribute | Example | Use Case |
|-----------|---------|----------|
| `sAMAccountName` | `jdoe` | Pre-Win2000, short name, most common for login |
| `userPrincipalName` | `jdoe@example.com` | Email-format, used for UPN login |
| `cn` | `John Doe` | Display name, NOT unique |
| `distinguishedName` | `CN=John Doe,OU=Users,DC=example,DC=com` | Full path, unique |

**Recommendation**: Default `username_attribute = "sAMAccountName"`. Allow override for UPN (`userPrincipalName`) or OpenLDAP (`uid`).

### Group Membership Query

AD `memberOf` attribute (direct groups):
```
(memberOf=CN=GuacAdmins,OU=Groups,DC=example,DC=com)
```

Nested group resolution — AD uses OID `1.2.840.113556.1.4.1941`:
```
(memberOf:1.2.840.113556.1.4.1941:=CN=GuacAdmins,OU=Groups,DC=example,DC=com)
```

This matches if the user is a member of `GuacAdmins` directly OR via any nested group chain.

Code:
```rust
// Nested group membership filter (AD-specific OID)
let filter = format!(
    "(&(objectClass=user)(sAMAccountName={}))",
    ldap_escape(&username)
);
let (entries, _) = ldap.search(
    &user_base_dn,
    Scope::Subtree,
    &filter,
    vec!["memberOf", "cn", "mail", "distinguishedName"],
).await?.success()?;
```

**Recommendation**: Expose `nested_group_resolution = true/false` in config. When true, use the AD OID in the memberOf filter.

---

## 5. Group Mapping

### Query Groups

```rust
// Get all groups a user belongs to
let user_dn = "CN=John Doe,OU=Users,DC=example,DC=com";

// Method 1: Read memberOf attribute from user entry
let (entries, _) = ldap.search(
    &user_dn,
    Scope::Base,
    "(objectClass=*)",
    vec!["memberOf"],
).await?.success()?;

let member_of: Vec<String> = SearchEntry::construct(entries.into_iter().next().unwrap())
    .attrs
    .get("memberOf")
    .cloned()
    .unwrap_or_default();

// Method 2: Search groups where user is member (OpenLDAP/memberUid)
let (groups, _) = ldap.search(
    &group_base_dn,
    Scope::Subtree,
    &format!("(&(objectClass=groupOfNames)(member={}))", user_dn),
    vec!["cn"],
).await?.success()?;
```

### Config

```toml
[ldap]
group_base_dn = "ou=Groups,dc=example,dc=com"
group_name_attribute = "cn"   # attribute containing the group name
group_search_filter = "(objectClass=group)"

# Map LDAP group names to persea roles
[ldap.role_mapping]
"GuacAdmins" = "admin"
"GuacPowerUsers" = "poweruser"
"GuacOperators" = "operator"
"GuacViewers" = "viewer"
```

### Role Resolution

```rust
fn resolve_role(member_of: &[String], role_mapping: &HashMap<String, String>) -> String {
    // Check from highest role to lowest
    for (group_dn, role) in role_mapping {
        if member_of.iter().any(|dn| dn.eq_ignore_ascii_case(group_dn)) {
            return role.clone();
        }
    }
    "viewer".to_string()  // default role
}
```

**Recommendation**: Extract the CN from each memberOf DN and match against configured role mapping. Highest matched role wins.

---

## 6. User Search Filter

Restrict which LDAP users can log in:

```toml
[ldap]
# Only allow members of GuacUsers group to log in
user_search_filter = "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN=GuacUsers,OU=Groups,DC=example,DC=com))"
```

In search bind mode, this filter is combined with the username filter:
```rust
let combined_filter = format!(
    "(&{}({}={}))",
    user_search_filter,
    username_attribute,
    ldap_escape(&username)
);
```

In direct bind mode, the filter is used as a pre-check before attempting the bind:
```rust
// Direct bind with filter check
let combined_filter = format!(
    "(&{}({}={}))",
    user_search_filter,
    username_attribute,
    ldap_escape(&username)
);

// Quick search to verify user matches filter
let (entries, _) = ldap.search(
    &user_base_dn,
    Scope::Subtree,
    &combined_filter,
    vec!["dn"],
).await?.success()?;

if entries.is_empty() {
    return Err("User does not match login filter".into());
}
```

**Guacamole pattern**: `ldap-user-search-filter` defaults to `(objectClass=*)` — all users allowed. Configurable per deployment.

---

## 7. Connection Pooling

### Option A: bb8-ldap (Recommended)

There's a dedicated crate `bb8-ldap` that implements `bb8::ManageConnection` for ldap3:

```toml
[dependencies]
bb8 = "0.8"
bb8-ldap = "0.4"
```

```rust
use bb8::Pool;
use bb8_ldap::LdapConnectionManager;

let manager = LdapConnectionManager::new("ldap://dc.example.com:389")?
    .with_connection_settings(
        LdapConnSettings::new()
            .set_starttls(true)
            .set_conn_timeout(Duration::from_secs(5))
    )
    .with_bind_credentials(
        "cn=guac-svc,ou=ServiceAccounts,dc=example,dc=com",
        &service_password
    )
    .with_connect_timeout(Duration::from_secs(5))
    .with_validation_timeout(Duration::from_secs(3));

let pool = Pool::builder()
    .max_size(10)
    .min_idle(Some(2))
    .max_lifetime(Some(Duration::from_secs(300)))
    .build(manager)
    .await?;

// Get a connection from the pool
let mut conn = pool.get().await?;
let (entries, _) = conn.search(...).await?.success()?;
```

### Option B: deadpool-ldap

```toml
[dependencies]
deadpool-ldap = { version = "0.2", features = ["tls-rustls"] }
```

### Option C: Connection-per-request (Acceptable for LDAP)

LDAP is stateless per-bind. For persea's auth flow (one bind + search per login), connection-per-request is fine:

```rust
async fn authenticate_user(config: &LdapConfig, username: &str, password: &str) -> Result<LdapUser> {
    let (conn, mut ldap) = LdapConnAsync::from_url_with_settings(
        &settings, &url
    ).await?;
    ldap3::drive!(conn);

    // bind + search + unbind
    let result = ldap.simple_bind(&user_dn, password).await?;
    // ...
    ldap.unbind().await?;
    // conn drops here
}
```

**Recommendation**: Start with connection-per-request. Add `bb8-ldap` pooling only if login latency becomes a problem. LDAP bind+search is fast (~10-50ms). The pool is mainly useful for the service account search bind path.

### Why Connection-Per-Request Works

1. LDAP auth is a short-lived operation (bind → search → unbind)
2. LDAP connections don't hold server-side state after unbind
3. TCP connection overhead (~1-5ms) is negligible vs LDAP latency
4. No connection health-check complexity

---

## 8. Account Auto-Create

On first LDAP login, create a local DB record for TOTP storage and permission management.

### Fields to Populate

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,        -- from LDAP sAMAccountName
    display_name TEXT,                    -- from LDAP cn
    email TEXT,                           -- from LDAP mail
    auth_source TEXT NOT NULL,            -- 'local', 'ldap', 'oidc'
    role TEXT NOT NULL DEFAULT 'viewer',  -- from LDAP group mapping
    can_change_password BOOLEAN DEFAULT 1, -- 0 for LDAP users
    totp_secret TEXT,                     -- set via TOTP setup UI
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

### Auto-Create Flow

```rust
async fn upsert_ldap_user(db: &Db, ldap_user: &LdapUser) -> Result<User> {
    let user = db.get_user_by_username(&ldap_user.username)?;

    match user {
        Some(mut existing) => {
            // Update display_name, email, role from LDAP
            existing.display_name = ldap_user.display_name.clone();
            existing.email = ldap_user.email.clone();
            existing.role = ldap_user.role.clone();
            existing.updated_at = Utc::now().to_rfc3339();
            db.update_user(&existing)?;
            Ok(existing)
        }
        None => {
            // Create new user
            let new_user = User {
                username: ldap_user.username.clone(),
                display_name: ldap_user.display_name.clone(),
                email: ldap_user.email.clone(),
                auth_source: "ldap".to_string(),
                role: ldap_user.role.clone(),
                can_change_password: false,  // LDAP users can't change password here
                totp_secret: None,
                created_at: Utc::now().to_rfc3339(),
                updated_at: Utc::now().to_rfc3339(),
            };
            db.create_user(&new_user)?;
            Ok(new_user)
        }
    }
}
```

**Guacamole pattern**: Guacamole auto-creates LDAP users in its database on first login. Group membership and permissions are synced from LDAP. persea should follow the same pattern.

---

## 9. Password Changes

LDAP users authenticate against LDAP — password changes in persea are meaningless.

### Disable Password Change UI

```rust
// In user model
pub can_change_password: bool,

// In API response for LDAP users
fn user_response(user: &User) -> serde_json::Value {
    json!({
        "username": user.username,
        "role": user.role,
        "auth_source": user.auth_source,
        "can_change_password": user.auth_source == "local",
        "can_change_totp": true,  // TOTP is stored locally even for LDAP users
    })
}
```

### Frontend Check

```html
<!-- connections.html -->
<button id="change-password-btn"
        style="display: none;"
        data-can-change="{{ user.can_change_password }}">
    Change Password
</button>
```

### Password Policy

For LDAP users, persea should NOT store or validate passwords at all. The `auth_source` field determines the authentication path:

```rust
async fn authenticate(db: &Db, config: &Config, username: &str, password: &str) -> Result<User> {
    let user = db.get_user_by_username(username)?;

    match user.auth_source.as_str() {
        "local" => {
            // Verify against local hash
            verify_local_password(user, password)?;
        }
        "ldap" => {
            // Bind against LDAP server
            ldap_bind(config.ldap(), username, password).await?;
        }
        "oidc" => {
            return Err("OIDC users must log in via OIDC".into());
        }
        _ => return Err("Unknown auth source".into()),
    }

    Ok(user)
}
```

---

## Recommended Config Structure

```toml
# LDAP authentication
[ldap]
enabled = true
url = "ldap://dc.example.com:389"  # or ldaps:// for SSL
encryption_method = "starttls"       # "none", "starttls", "ssl"
tls_skip_verify = false

# User search
user_base_dn = "ou=Users,dc=example,dc=com"
username_attribute = "sAMAccountName"

# Search bind (service account)
search_bind_dn = "cn=guac-svc,ou=ServiceAccounts,dc=example,dc=com"
# search_bind_password_env = "LDAP_BIND_PASSWORD"  # preferred

# User search filter (restrict login eligibility)
user_search_filter = "(objectClass=user)"

# Group search
group_base_dn = "ou=Groups,dc=example,dc=com"
group_name_attribute = "cn"
group_search_filter = "(objectClass=group)"
nested_group_resolution = true

# Role mapping
[ldap.role_mapping]
"GuacAdmins" = "admin"
"GuacPowerUsers" = "poweruser"
"GuacOperators" = "operator"
# Default: "viewer"

# Connection settings
connect_timeout_secs = 5
search_timeout_secs = 10
```

---

## Implementation Order

1. **LdapConfig struct** — deserialize the TOML section above
2. **LdapAuthProvider** — implements `AuthProvider` trait:
   - `authenticate(username, password) -> Result<LdapUser>`
   - `resolve_user_dn()` (direct or search bind)
   - `fetch_groups()` — query memberOf, resolve role
3. **Account auto-create** — `upsert_ldap_user()` on first login
4. **Password disable** — gate `can_change_password` on `auth_source`
5. **Connection pool** — optional `bb8-ldap` wrapper for search bind path
6. **STARTTLS/TLS** — wire `LdapConnSettings` from config
7. **Admin UI** — LDAP config in admin panel, group mapping editor

---

## Cargo.toml Addition

```toml
# LDAP authentication
ldap3 = { version = "0.12.1", default-features = false, features = ["tls-rustls-ring"] }
url = "2"  # already in dependencies

# Optional: connection pooling
# bb8 = "0.8"
# bb8-ldap = "0.4"
```

---

## References

- ldap3 crate: https://docs.rs/ldap3/latest/ldap3/
- ldap3 GitHub: https://github.com/inejge/ldap3
- bb8-ldap: https://docs.rs/bb8-ldap
- Apache Guacamole LDAP auth: https://guacamole.apache.org/doc/gug/ldap-auth.html
- AD nested group OID: 1.2.840.113556.1.4.1941 (LDAP_MATCHING_RULE_IN_CHAIN)
