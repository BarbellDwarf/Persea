# Auth Provider Architecture for persea

> **Design record.** This is a historical design document: the research that led to persea's pluggable authentication chain. It is not a user guide — see [Configuration](../configuration.md#auth-section) for how auth is configured and [Roles and Access Control](../roles-and-access-control.md) for the role/permission model.

## What this document is

Before persea had multiple ways to log in, this document worked out how authentication should be structured. The question was: persea can authenticate users against a local database, an LDAP/AD directory, an OIDC identity provider, RADIUS, or a TOTP app — how should the code be organised so that each of these is a self-contained module and the behaviour of the whole is predictable?

**What was decided:**

- One `AuthProvider` trait (an interface every login method implements) with **capability flags** — a provider advertises what it can do (password auth, redirect to an external identity provider, MFA, group resolution, user auto-provisioning) and the rest of the system adapts.
- Providers are tried **in order** — the config's `methods = [...]` list, first success or redirect wins. This mirrors Apache Guacamole's "poll all providers" pattern.
- **MFA is layered** — at most one second-factor provider (TOTP) runs after the primary provider succeeds.
- **No plugin system** — persea is a single binary; the trait exists for clean code organisation, not for third-party extensions.

**What shipped, and how it differs from the proposal:** the trait, capability flags, ordered chain, and MFA layering all shipped as designed. Two details evolved during implementation: the proposed `AuthResult` struct became an enum (`Success` / `Failure` / `Redirect` / `Unavailable`), and the proposed provider registry became a `from_config` builder on the chain itself. Two proposals did **not** ship: per-provider session lifetimes, and a reauthentication middleware for sensitive operations (session expiry is governed by the global `auth_session_ttl_secs` setting instead).

---

## State at the time of writing (before this design shipped)

persea had two auth mechanisms in a single `auth.rs` + `oidc.rs`:
- **API key auth** — `Authorization: Bearer <key>` or `X-API-Key` header, validated against SQLite `admins` and `user_api_tokens` tables
- **OIDC session cookie** — `persea_session` cookie, validated against `auth_sessions` table
- **WebSocket tickets** — single-use tokens for API-key users connecting via WebSocket

The `AuthIdentity` enum carried the identity through the request:
```rust
pub enum AuthIdentity {
    ApiKey(String),
    User { email: String, role: String, groups: Vec<String> },
}
```

Middleware (`require_auth` / `optional_auth`) tried API key first, then session cookie. No abstraction layer for adding new providers.

---

## 1. Trait-Based Auth Provider Design

### Recommended `AuthProvider` Trait

```rust
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Unique identifier for a provider instance (e.g. "ldap-corp", "oidc-keycloak").
pub type ProviderId = String;

/// The result of a successful authentication.
#[derive(Clone, Debug)]
pub struct AuthResult {
    /// External identity ID (email, username, subject claim).
    pub subject: String,
    /// Display name (may differ from subject).
    pub display_name: String,
    /// Resolved role after group-to-role mapping.
    pub role: String,
    /// Group memberships from the provider.
    pub groups: Vec<String>,
    /// Which provider produced this result.
    pub provider_id: ProviderId,
    /// How the user authenticated (for audit logging).
    pub auth_method: String,
}

/// Capabilities this provider supports. Middleware checks these to decide
/// which auth paths to offer (e.g. don't show "forgot password" for OIDC).
#[derive(Debug, Clone, Default)]
pub struct ProviderCapabilities {
    /// Provider can verify username/password inline.
    pub supports_password_auth: bool,
    /// Provider can change passwords.
    pub supports_password_change: bool,
    /// Provider can reset/forgot passwords.
    pub supports_password_reset: bool,
    /// Provider requires redirect to external IdP (OIDC, SAML).
    pub requires_redirect: bool,
    /// Provider supports TOTP/second-factor.
    pub supports_totp: bool,
    /// Provider can look up users by external ID.
    pub supports_user_lookup: bool,
    /// Provider can enumerate group memberships.
    pub supports_group_resolution: bool,
    /// Provider can auto-create accounts on first login.
    pub supports_auto_create: bool,
}

/// Error type for auth provider operations.
#[derive(Debug)]
pub enum AuthError {
    /// Credentials are invalid.
    InvalidCredentials,
    /// Account is disabled/locked.
    AccountDisabled(String),
    /// Provider is temporarily unreachable.
    ProviderUnavailable(String),
    /// Internal error.
    Internal(String),
    /// User not found.
    UserNotFound,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidCredentials => write!(f, "invalid credentials"),
            Self::AccountDisabled(reason) => write!(f, "account disabled: {reason}"),
            Self::ProviderUnavailable(msg) => write!(f, "provider unavailable: {msg}"),
            Self::Internal(msg) => write!(f, "internal error: {msg}"),
            Self::UserNotFound => write!(f, "user not found"),
        }
    }
}

/// Core auth provider trait. Every provider (LDAP, DB, OIDC, RADIUS, etc.)
/// implements this.
#[async_trait]
pub trait AuthProvider: Send + Sync + fmt::Debug {
    /// Unique identifier for this provider instance.
    fn id(&self) -> &str;

    /// Human-readable name for UI display.
    fn display_name(&self) -> &str;

    /// What this provider can do.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Authenticate with username + password. Returns `Err` on failure,
    /// `Ok(None)` if this provider doesn't handle this user (fall through).
    async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthResult>, AuthError>;

    /// Look up a user by external ID (e.g. OIDC subject, LDAP DN).
    async fn lookup_user(
        &self,
        external_id: &str,
    ) -> Result<Option<AuthResult>, AuthError>;

    /// Resolve group memberships for a user.
    async fn resolve_groups(
        &self,
        subject: &str,
    ) -> Result<Vec<String>, AuthError>;

    /// Auto-create a local user account from SSO claims.
    /// Called on first OIDC/SAML login when no local user exists.
    async fn auto_create_user(
        &self,
        result: &AuthResult,
    ) -> Result<(), AuthError>;
}
```

### Why Not Separate Traits Per Capability

Guacamole uses a single `AuthenticationProvider` interface. Keycloak splits `Authenticator` from `CredentialProvider` from `UserStorageProvider`. For persea, a **single trait with capability flags** is better because:

1. **Simpler registration** — one provider, one struct, one `dyn AuthProvider`
2. **Capability flags let middleware decide** — check `capabilities().requires_redirect` instead of downcasting
3. **Providers can be incomplete** — return `Err(AuthError::Internal("not supported"))` or `Ok(None)` for methods they don't implement
4. **Matches Guacamole's model** — `SimpleAuthenticationProvider` is a single class; persea is a single binary, not a plugin system

---

## 2. Apache Guacamole Auth Extension Pattern

### Key Interfaces

```
AuthenticationProvider (interface)
├── getIdentifier() → String
├── authenticateUser(Credentials) → AuthenticatedUser
├── getUserContext(AuthenticatedUser) → UserContext
├── updateAuthenticatedUser(...)
├── updateCredentials(...)
└── getResource() → Object (REST extension point)

SimpleAuthenticationProvider (abstract base class)
├── getAuthorizedConfigurations(Credentials) → Map<String, GuacamoleConfiguration>
└── authenticateUser(Credentials) → AuthenticatedUser

Credentials (value object)
├── getUsername()
├── getPassword()
├── getParameters() → Map<String, String>
└── getRequest() → HttpServletRequest

AuthenticatedUser (interface)
├── getIdentifier() → String
└── getCredentials() → Credentials

UserContext (interface)
├── getConnectionDirectory() → Directory<Connection>
├── getConnectionGroupDirectory() → Directory<ConnectionGroup>
├── getUserDirectory() → Directory<User>
└── getActiveConnectionDirectory() → Directory<ActiveConnection>
```

### Key Design Patterns

1. **Poll-all-providers** — Guacamole polls ALL installed providers in lexicographic order. First non-`null` result wins. This is the "chain of responsibility" pattern.
2. **Decoupled auth from data** — An auth provider only needs to authenticate; it can delegate user/connection storage to another provider (e.g. the JDBC extension).
3. **Credentials object** — Wraps username, password, and arbitrary HTTP request parameters. Providers extract what they need.
4. **UserContext** — After auth, the provider returns a context that provides access to directories (users, connections, groups). This is the "session scope" concept.

### What persea Should Borrow

- **Poll-all pattern**: Try each configured provider until one succeeds
- **Separation of auth from storage**: Auth provider just authenticates; user upsert is a separate step
- **Credentials abstraction**: Don't pass raw headers — pass a structured credentials object
- **UserContext equivalent**: The `AuthIdentity` already serves this role

---

## 3. Keycloak Auth SPI Pattern

### Core Interfaces

```
Provider (base interface)
├── close()

ProviderFactory<T: Provider> (base factory)
├── create(KeycloakSession) → T
├── init(Config)
├── postInit(KeycloakSessionFactory)
├── close()
├── getId() → String
├── getOrder() → int
└── isProviderAvailable(Config) → boolean

Authenticator (extends Provider)
├── authenticate(AuthenticationFlowContext)
├── action(AuthenticationFlowContext)
├── requiresUser() → boolean
├── configuredFor(AuthenticationFlowContext) → boolean
└── setRequiredActions(AuthenticationFlowContext)

AuthenticatorFactory (extends ProviderFactory<Authenticator>)
├── create(KeycloakSession) → Authenticator
├── getDisplayType() → String
├── getReferenceCategory() → String
├── isConfigurable() → boolean
├── getRequirementChoices() → List<ConfigProperty>
├── isUserSetupAllowed() → boolean
└── createProtocolMapper(...) / getHelpText() / etc.
```

### Key Design Patterns

1. **Factory + Provider separation** — Factory is singleton (created once), Provider is per-request (created via `factory.create(session)`). This avoids holding request-scoped state in the factory.
2. **ServiceLoader discovery** — Providers register via `META-INF/services/` files. Keycloak scans at startup.
3. **Flow-based composition** — Multiple authenticators are composed into "authentication flows" (sequences of steps). Each step can be REQUIRED, ALTERNATIVE, OPTIONAL, or CONDITIONAL.
4. **Configurable via Admin Console** — Factories expose `ConfigProperty` lists that the admin console renders as forms.

### What persea Should Borrow

- **Factory pattern for provider registration** — `AuthProviderFactory` creates `AuthProvider` instances. Factories are cheap to create; providers hold state.
- **Capability/requirement metadata** — Providers advertise what they need (redirect? password form? TOTP?) so the UI can adapt.
- **NOT the flow system** — Keycloak's flow system is overkill for persea. A simple "try providers in order" or "primary + optional second factor" is sufficient.

---

## 4. Rust-Specific Patterns

### dyn Trait vs Enum Dispatch

| Criterion | `dyn AuthProvider` | `enum AuthProviderEnum` |
|---|---|---|
| Known set of types | Works | Best (match-based, no vtable) |
| Open set (plugins) | Best | Can't add new variants |
| Hot path (millions/sec) | 3-4x slower (vtable indirection) | Near-static dispatch speed |
| Auth middleware (cold path) | Fine — auth happens once per request | Fine |
| Binary size | Smaller (one code path) | Larger (monomorphized per variant) |
| Object safety | Required | N/A |

**Recommendation: Use `dyn AuthProvider`.** Auth is a cold path (once per HTTP request, not in a tight loop). The 3-4x vtable cost is irrelevant. `dyn Trait` also lets you:
- Keep providers in a `Vec<Box<dyn AuthProvider>>`
- Add new providers without changing the enum
- Keep each provider in its own module/crate

### Config Structure

```toml
# Primary auth methods (at least one required)
[auth]
# Order matters: first matching provider wins
methods = ["oidc", "api_key"]
# Fallback when no provider matches
default_role = "viewer"

[auth.oidc]
issuer_url = "https://keycloak.example.com/realms/corp"
client_id = "persea"
client_secret = "..."  # or OIDC_CLIENT_SECRET env var
redirect_uri = "https://persea.example.com/auth/callback"
default_role = "operator"
groups_claim = "groups"
extra_scopes = ["groups"]

[auth.ldap]
url = "ldaps://ldap.example.com:636"
bind_dn = "cn=readonly,dc=example,dc=com"
bind_password = "..."  # or LDAP_BIND_PASSWORD env var
user_search_base = "ou=users,dc=example,dc=com"
user_search_filter = "(uid={username})"
group_search_base = "ou=groups,dc=example,dc=com"
group_search_filter = "(member={dn})"
start_tls = false
tls_skip_verify = false

[auth.radius]
server = "radius.example.com:1812"
shared_secret = "..."  # or RADIUS_SHARED_SECRET env var
timeout_secs = 5

[auth.database]
# Uses existing SQLite users table for password auth
enabled = true
# Password hash algorithm: bcrypt, argon2, sha256
hash_algorithm = "bcrypt"

[auth.totp]
# Second-factor TOTP (applied after primary auth)
enabled = true
issuer = "persea"
digits = 6
period_secs = 30
window = 1  # allow ±1 period drift
```

### Provider Registration at Startup

```rust
pub struct AuthRegistry {
    providers: Vec<Box<dyn AuthProvider>>,
    /// Map of provider_id → provider for quick lookup
    index: HashMap<String, usize>,
}

impl AuthRegistry {
    pub async fn from_config(config: &Config) -> Result<Self, String> {
        let mut providers: Vec<Box<dyn AuthProvider>> = Vec::new();

        // Always register API key auth (built-in, not configurable)
        providers.push(Box::new(ApiKeyProvider::new(db.clone())));

        // Register configured providers
        for method in &config.auth.methods {
            match method.as_str() {
                "oidc" => {
                    if let Some(ref oidc_config) = config.auth.oidc {
                        let provider = OidcProvider::new(oidc_config).await?;
                        providers.push(Box::new(provider));
                    }
                }
                "ldap" => {
                    if let Some(ref ldap_config) = config.auth.ldap {
                        let provider = LdapProvider::new(ldap_config).await?;
                        providers.push(Box::new(provider));
                    }
                }
                "radius" => {
                    if let Some(ref radius_config) = config.auth.radius {
                        let provider = RadiusProvider::new(radius_config);
                        providers.push(Box::new(provider));
                    }
                }
                "database" => {
                    if let Some(ref db_config) = config.auth.database {
                        let provider = DatabaseAuthProvider::new(db.clone(), db_config);
                        providers.push(Box::new(provider));
                    }
                }
                _ => {
                    return Err(format!("Unknown auth method: {}", method));
                }
            }
        }

        let index = providers.iter().enumerate()
            .map(|(i, p)| (p.id().to_string(), i))
            .collect();

        Ok(Self { providers, index })
    }

    /// Try each provider in order until one succeeds.
    pub async fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResult, AuthError> {
        for provider in &self.providers {
            if !provider.capabilities().supports_password_auth {
                continue;
            }
            match provider.authenticate(username, password).await {
                Ok(Some(result)) => return Ok(result),
                Ok(None) => continue, // Provider doesn't handle this user
                Err(AuthError::InvalidCredentials) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(AuthError::InvalidCredentials)
    }

    /// Get provider by ID.
    pub fn get(&self, id: &str) -> Option<&dyn AuthProvider> {
        self.index.get(id).map(|&i| self.providers[i].as_ref())
    }

    /// Get all providers that require redirect (for login page rendering).
    pub fn redirect_providers(&self) -> Vec<&dyn AuthProvider> {
        self.providers.iter()
            .filter(|p| p.capabilities().requires_redirect)
            .map(|p| p.as_ref())
            .collect()
    }

    /// Get all providers that support password auth (for login form).
    pub fn password_providers(&self) -> Vec<&dyn AuthProvider> {
        self.providers.iter()
            .filter(|p| p.capabilities().supports_password_auth)
            .map(|p| p.as_ref())
            .collect()
    }
}
```

---

## 5. Middleware Integration with axum

### Two-Phase Model

Phase 1: **Primary Auth** — Establish identity (API key, session cookie, password form, OIDC redirect, SAML redirect)

Phase 2: **Second Factor** — TOTP/OTP after primary auth succeeds (if configured)

### Middleware Architecture

```rust
/// The main auth middleware. Tries providers in order.
pub async fn require_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    let db = request.extensions().get::<Db>().cloned().unwrap();
    let registry = request.extensions().get::<Arc<AuthRegistry>>().cloned().unwrap();
    let trusted = request.extensions().get::<TrustedProxies>().cloned().unwrap();
    let ip = client_ip(request.headers(), addr.ip(), &trusted.0);

    // Path 1: API key (always available, no config needed)
    if let Some(identity) = try_api_key(&request, &db, ip).await {
        request.extensions_mut().insert(identity);
        return next.run(request).await;
    }

    // Path 2: WebSocket ticket
    if let Some(identity) = try_ws_ticket(&request).await {
        request.extensions_mut().insert(identity);
        return next.run(request).await;
    }

    // Path 3: Session cookie
    if let Some(identity) = try_session_cookie(&request, &db).await {
        request.extensions_mut().insert(identity);
        return next.run(request).await;
    }

    // No auth — 401
    (StatusCode::UNAUTHORIZED, Json(json!({
        "error": "authentication required"
    }))).into_response()
}
```

### Handling Redirect vs Inline Providers

```rust
/// Auth response from providers that need redirects (OIDC, SAML).
pub enum AuthResponse {
    /// Identity resolved inline — continue processing.
    Identity(AuthResult),
    /// Need to redirect to external IdP. Contains redirect URL + state.
    Redirect {
        url: String,
        state: String,
        cookies: Vec<(String, String)>,
    },
    /// Need to show a TOTP form.
    TotpChallenge {
        session_token: String,
        pending_identity: AuthResult,
    },
}
```

For OIDC/SAML, the login flow becomes:
1. `GET /auth/login?provider=oidc` → provider returns `AuthResponse::Redirect`
2. User authenticates at IdP
3. `GET /auth/callback` → exchange code, get `AuthResponse::Identity`
4. Optionally check if TOTP is needed → `AuthResponse::TotpChallenge`
5. Create session cookie, redirect to dashboard

### Passing Identity Through Request

```rust
// In middleware:
request.extensions_mut().insert(AuthIdentity::User {
    email: result.subject,
    role: result.role,
    groups: result.groups,
});

// In handler:
async fn handler(
    auth: AuthIdentity,  // axum extractor from request extensions
) -> impl IntoResponse {
    if !auth.has_role("operator") {
        return StatusCode::FORBIDDEN.into_response();
    }
    // ...
}
```

### The axum-login Pattern (for reference)

`axum-login` uses `AuthnBackend` trait with a single backend. persea's `AuthRegistry` is essentially a multi-backend wrapper around the same concept. The key difference: persea needs to support both inline (API key, session cookie, LDAP) and redirect (OIDC, SAML) auth, which `axum-login` doesn't handle natively.

---

## 6. Session Management

### Current Schema

SQLite `auth_sessions` table:
- `id` (INTEGER PRIMARY KEY)
- `user_id` (INTEGER → users.id)
- `session_token` (TEXT UNIQUE)
- `created_at` (TEXT)
- `expires_at` (TEXT)

### Recommended Enhancements

```sql
-- Add provider tracking
ALTER TABLE auth_sessions ADD COLUMN provider_id TEXT;
ALTER TABLE auth_sessions ADD COLUMN auth_method TEXT;
ALTER TABLE auth_sessions ADD COLUMN last_verified_at TEXT;

-- Add reauthentication tracking for sensitive operations
CREATE TABLE auth_reauth (
    id INTEGER PRIMARY KEY,
    session_id INTEGER REFERENCES auth_sessions(id) ON DELETE CASCADE,
    operation TEXT NOT NULL,  -- e.g. "change_password", "delete_connection"
    verified_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
```

### Session Expiry by Provider

Different providers should have different session TTLs:

```rust
impl AuthRegistry {
    /// Get session TTL for a given provider.
    pub fn session_ttl(&self, provider_id: &str) -> u64 {
        self.get(provider_id)
            .map(|p| match p.capabilities().requires_redirect {
                true => 86400,  // 24h for SSO
                false => 3600, // 1h for password auth
            })
            .unwrap_or(3600)
    }
}
```

### Reauthentication for Sensitive Operations

```rust
/// Middleware for operations that require recent authentication.
/// Checks that the session was verified within the last N minutes.
pub async fn require_reauth(
    Extension(database): Extension<Db>,
    request: Request,
    next: Next,
) -> Response {
    let session = extract_session(&request);
    let operation = extract_operation(&request); // e.g. from URL path

    let db_clone = database.clone();
    let verified = tokio::task::spawn_blocking(move || {
        db::check_reauth(&db_clone, &session, &operation)
    }).await.unwrap();

    match verified {
        Ok(true) => next.run(request).await,
        Ok(false) => {
            // Redirect to reauth page
            Redirect::to("/auth/reauth").into_response()
        }
        Err(_) => {
            (StatusCode::UNAUTHORIZED, Json(json!({
                "error": "reauthentication required"
            }))).into_response()
        }
    }
}
```

---

## 7. Module Structure

```
src/
├── auth/
│   ├── mod.rs              # AuthIdentity, role_level, require_auth, optional_auth
│   ├── provider.rs         # AuthProvider trait, AuthResult, AuthError, ProviderCapabilities
│   ├── registry.rs         # AuthRegistry — provider collection, lookup, iteration
│   ├── providers/
│   │   ├── mod.rs
│   │   ├── api_key.rs      # ApiKeyProvider (built-in, always available)
│   │   ├── database.rs     # DatabaseAuthProvider (SQLite password auth)
│   │   ├── oidc.rs         # OidcProvider (redirect-based SSO)
│   │   ├── ldap.rs         # LdapProvider (LDAP/AD bind auth)
│   │   ├── radius.rs       # RadiusProvider (RADIUS PAP auth)
│   │   └── totp.rs         # TotpProvider (second-factor TOTP)
│   ├── session.rs          # Session management (create, validate, expiry)
│   ├── reauth.rs           # Reauthentication middleware
│   └── ws_ticket.rs        # WebSocket ticket store
```

### Migration Path

1. Extract `auth.rs` → `auth/mod.rs` (keep existing API)
2. Create `auth/provider.rs` with the trait
3. Create `auth/registry.rs`
4. Move API key logic to `auth/providers/api_key.rs`
5. Move session cookie logic to `auth/providers/database.rs` (or keep in registry)
6. Move OIDC logic from `oidc.rs` → `auth/providers/oidc.rs`
7. Add new providers (LDAP, RADIUS, TOTP) as needed

---

## 8. Key Recommendations

1. **Use `dyn AuthProvider`** — Auth is cold path, open set of providers, no performance concern
2. **Single trait with capability flags** — Simpler than splitting into Authenticator/CredentialProvider/UserStorage like Keycloak
3. **Poll-all pattern from Guacamole** — Try providers in order, first success wins
4. **Factory pattern from Keycloak** — `AuthProviderFactory` creates per-request providers (not critical for persea since providers are stateless, but good for future)
5. **Keep `AuthIdentity` enum** — It's the equivalent of Guacamole's `AuthenticatedUser` and already works
6. **Add provider metadata to sessions** — Track which provider authenticated each session for audit and TTL management
7. **Two-phase auth** — Primary (password/SSO) → Optional TOTP, checked via middleware chain
8. **Config-driven registration** — `[auth]` section in TOML, providers registered at startup based on `methods = [...]` list
9. **Redirect providers get their own routes** — `/auth/login?provider=oidc`, `/auth/callback` — these don't go through `require_auth`
10. **Reauthentication for sensitive ops** — Separate middleware that checks recent auth verification
