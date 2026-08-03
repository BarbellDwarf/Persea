# Auth Provider Architecture — Research Findings

## 1. AuthProvider Trait Design

### Reference Systems Studied

**Apache Guacamole `AuthenticationProvider`** (Java interface):
- `getCredentialsProvider()` — returns credentials provider for the auth type
- `authenticateUser(AuthenticationProvider context, Credentials credentials)` — validates credentials, returns AuthenticatedUser
- `getAuthorizedConnections(AuthenticatedUser user)` — returns connection list (ties auth to connection resolution)
- Each provider is self-contained: handles its own credential type, user lookup, and connection resolution

**Keycloak Authenticator SPI** (Java):
- `authenticate(AuthenticationFlowContext)` — called during flow execution; calls `context.success()` or `context.failure()`
- `action(AuthenticationFlowContext)` — called on form submission (2nd phase)
- `requiresUser()` — does this authenticator need an existing user?
- `configuredFor(RealmModel, UserModel)` — is the user configured for this auth method?
- `getRequiredActions()` — returns required actions to trigger
- `CredentialProvider` — separate interface for credential validation
- Factory pattern: `AuthenticatorFactory` creates `Authenticator` instances per-flow

**axum-login `AuthnBackend`** (Rust trait):
```rust
#[async_trait]
pub trait AuthnBackend: Send + Sync + Clone + 'static {
    type User: AuthUser;
    type Credentials: Clone + Send + Sync;
    type Error: Into<Box<dyn Error + Send + Sync>>;

    async fn authenticate(
        &self,
        credentials: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error>;

    async fn get_user(
        &self,
        user_id: &UserId<Self>,
    ) -> Result<Option<Self::User>, Self::Error>;
}
```
- `AuthUser` trait: `fn id()`, `fn session_auth_hash()` for session validation
- `AuthzBackend`: optional trait for `get_authorities()` (permissions)
- Session management via `tower-sessions` (cookie-backed)
- `AuthSession` acts as both session store and extractor in handlers

### Proposed `AuthProvider` Trait for persea

```rust
use async_trait::async_trait;
use std::fmt;

/// Bitflags advertising what a provider can do.
bitflags::bitflags! {
    pub struct Capabilities: u32 {
        const AUTHENTICATE       = 0b0000_0001; // Can authenticate users (password, token, etc.)
        const MFA                = 0b0000_0010; // Is a second-factor authenticator (TOTP, etc.)
        const REDIRECT           = 0b0000_0100; // Redirects to external IdP (OIDC, SAML)
        const STORE_PASSWORDS    = 0b0000_1000; // Can verify/provide password hashes
        const RESOLVE_GROUPS     = 0b0001_0000; // Returns group memberships
        const AUTO_CREATE_USER   = 0b0010_0000; // Can auto-provision users
    }
}

/// The outcome of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded. Contains identity info.
    Success {
        subject: String,       // unique identifier (email, username, sub)
        display_name: String,
        groups: Vec<String>,
        /// If provider resolved a role, include it.
        role: Option<String>,
    },
    /// Authentication failed (bad credentials, etc.).
    Failure(String),
    /// Provider needs more input — redirect the user.
    /// Contains the URL to redirect to.
    Redirect(String),
    /// Provider is not available (upstream error, misconfig).
    Unavailable(String),
}

/// A trait for anything that can authenticate users.
///
/// All methods have default impls so providers only override what they support.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Provider's config key (e.g. "oidc", "ldap", "database", "api_key", "totp").
    fn id(&self) -> &str;

    /// What this provider can do.
    fn capabilities(&self) -> Capabilities;

    /// Primary authentication: validate credentials and return identity.
    /// For redirect providers (OIDC/SAML), return `AuthResult::Redirect(url)`.
    /// For inline providers (LDAP, DB, API key), return `Success` or `Failure`.
    async fn authenticate(
        &self,
        request: &AuthRequest,
    ) -> AuthResult;

    /// Verify a second factor (TOTP code, WebAuthn assertion, etc.).
    /// Only called on providers with `Capabilities::MFA`.
    /// Returns true if the factor is valid for the given subject.
    async fn verify_second_factor(
        &self,
        _subject: &str,
        _factor_data: &str,
    ) -> bool {
        false
    }

    /// Look up a user by identifier (for session refresh / user info).
    /// Only needed by providers that can resolve user info independently.
    async fn lookup_user(&self, _subject: &str) -> Option<UserInfo> {
        None
    }

    /// Whether this provider requires a username+password form.
    /// True for LDAP, Database. False for API key, OIDC (redirect).
    fn has_inline_login_form(&self) -> bool {
        false
    }
}

/// Context passed to authenticate().
#[derive(Debug, Clone)]
pub struct AuthRequest {
    pub client_ip: std::net::IpAddr,
    pub username: Option<String>,
    pub password: Option<String>,
    /// For OIDC/SAML: the callback URL params.
    pub callback_params: Option<std::collections::HashMap<String, String>>,
    /// For API key / bearer token.
    pub bearer_token: Option<String>,
    /// Raw request headers for providers that need them.
    pub headers: std::collections::HashMap<String, String>,
}

/// User info returned by providers that support user lookup.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub subject: String,
    pub display_name: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
}
```

## 2. Capability Flags

Capabilities serve multiple purposes:

| Capability | Who has it | Used for |
|---|---|---|
| `AUTHENTICATE` | LDAP, Database, OIDC, SAML, RADIUS, API key | Filter providers eligible for primary auth |
| `MFA` | TOTP, WebAuthn | Trigger second factor after primary auth |
| `REDIRECT` | OIDC, SAML | Handle redirect flow (not inline form) |
| `STORE_PASSWORDS` | Database, LDAP | Password change, password policy enforcement |
| `RESOLVE_GROUPS` | LDAP, OIDC, Database | Populate user groups for role resolution |
| `AUTO_CREATE_USER` | OIDC, LDAP, SAML | Auto-provision users on first login |

The middleware uses capabilities to:
- Determine which providers to present on the login page (`has_inline_login_form()` + `AUTHENTICATE`)
- Know if MFA is needed after primary auth (`MFA` in the chain)
- Route callback requests to the right redirect provider (`REDIRECT`)

## 3. Flat Priority Chain

### Design

```rust
/// An ordered chain of auth providers. First match wins.
pub struct AuthChain {
    /// Primary providers in config order. Each is tried in sequence.
    providers: Vec<Box<dyn AuthProvider>>,
    /// Optional second-factor provider (TOTP). Applied after primary auth.
    mfa_provider: Option<Box<dyn AuthProvider>>,
}

impl AuthChain {
    /// Build from config. `methods` list determines order.
    pub fn from_config(config: &AuthConfig, shared: &SharedDeps) -> Result<Self, String> {
        let mut providers: Vec<Box<dyn AuthProvider>> = Vec::new();
        let mut mfa: Option<Box<dyn AuthProvider>> = None;

        for method_name in &config.methods {
            match method_name.as_str() {
                "oidc" => {
                    let cfg = config.oidc.as_ref().ok_or("oidc configured but [auth.oidc] missing")?;
                    providers.push(Box::new(OidcProvider::new(cfg, shared).await?));
                }
                "ldap" => {
                    let cfg = config.ldap.as_ref().ok_or("ldap configured but [auth.ldap] missing")?;
                    providers.push(Box::new(LdapProvider::new(cfg, shared).await?));
                }
                "database" => {
                    let cfg = config.database.as_ref().ok_or("database configured but [auth.database] missing")?;
                    providers.push(Box::new(DatabaseProvider::new(cfg, shared)?));
                }
                "api_key" => {
                    providers.push(Box::new(ApiKeyProvider::new(shared)?));
                }
                "radius" => {
                    let cfg = config.radius.as_ref().ok_or("radius configured but [auth.radius] missing")?;
                    providers.push(Box::new(RadiusProvider::new(cfg)?));
                }
                "saml" => {
                    let cfg = config.saml.as_ref().ok_or("saml configured but [auth.saml] missing")?;
                    providers.push(Box::new(SamlProvider::new(cfg, shared).await?));
                }
                "totp" => {
                    let cfg = config.totp.as_ref().ok_or("totp configured but [auth.totp] missing")?;
                    if mfa.is_some() {
                        return Err("only one MFA provider allowed".into());
                    }
                    mfa = Some(Box::new(TotpProvider::new(cfg, shared)?));
                }
                other => return Err(format!("unknown auth method: {other}")),
            }
        }

        Ok(Self { providers, mfa_provider: mfa })
    }

    /// Try each provider in order. Return first success.
    pub async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        for provider in &self.providers {
            let result = provider.authenticate(request).await;
            match &result {
                AuthResult::Success { .. } | AuthResult::Redirect(_) => return result,
                AuthResult::Failure(_) | AuthResult::Unavailable(_) => continue,
            }
        }
        AuthResult::Failure("no provider could authenticate".into())
    }
}
```

### Config Structure

```toml
[auth]
methods = ["oidc", "ldap", "api_key"]  # order = priority

[auth.oidc]
issuer_url = "https://auth.example.com/realms/corp"
client_id = "persea"
client_secret = "..."
redirect_uri = "https://persea.example.com/auth/callback"
groups_claim = "groups"
default_role = "operator"

[auth.ldap]
url = "ldaps://ldap.example.com:636"
bind_dn = "cn=binduser,dc=example,dc=com"
bind_password_env = "LDAP_BIND_PASSWORD"
user_search_base = "ou=users,dc=example,dc=com"
user_search_filter = "(uid={username})"
group_search_base = "ou=groups,dc=example,dc=com"
group_search_filter = "(member={dn})"

[auth.database]
# Uses existing SQLite DB for password validation
password_field = "password_hash"

[auth.api_key]
# No config needed — uses existing API key table in SQLite

[auth.radius]
host = "radius.example.com"
port = 1812
secret_env = "RADIUS_SECRET"

[auth.saml]
idp_metadata_url = "https://idp.example.com/metadata"
entity_id = "persea"
acs_url = "https://persea.example.com/auth/saml/callback"

[auth.totp]
# TOTP second factor — applied after primary auth
issuer = "persea"
digits = 6
period = 30
```

## 4. Two-Phase Model

### Phase 1: Primary Auth → Phase 2: Optional TOTP

```rust
/// State machine for multi-phase authentication.
#[derive(Debug, Clone)]
pub enum AuthPhase {
    /// No auth attempted yet.
    Initial,
    /// Primary auth succeeded. Subject is known.
    /// If MFA is configured and user has TOTP enrolled, need second factor.
    PrimaryComplete {
        subject: String,
        display_name: String,
        groups: Vec<String>,
        role: Option<String>,
        /// Whether MFA is required for this user.
        requires_mfa: bool,
    },
    /// MFA verified. Session can be created.
    Complete {
        subject: String,
        display_name: String,
        groups: Vec<String>,
        role: Option<String>,
    },
}

/// Orchestrates the two-phase auth flow.
pub async fn auth_flow(
    chain: &AuthChain,
    request: &AuthRequest,
    db: &Db,
) -> AuthPhase {
    // Phase 1: primary auth
    let result = chain.authenticate(request).await;

    match result {
        AuthResult::Success { subject, display_name, groups, role } => {
            // Check if this user has TOTP enrolled
            let has_totp = chain.mfa_provider.is_some()
                && db::user_has_totp(db, &subject).unwrap_or(false);

            if has_totp {
                // Return PrimaryComplete with requires_mfa = true
                // Frontend shows TOTP input
                AuthPhase::PrimaryComplete {
                    subject,
                    display_name,
                    groups,
                    role,
                    requires_mfa: true,
                }
            } else {
                // No MFA needed — done
                AuthPhase::Complete {
                    subject,
                    display_name,
                    groups,
                    role,
                }
            }
        }
        AuthResult::Redirect(url) => {
            // Redirect to IdP — callback will resume at Phase 1 result
            AuthPhase::Initial // caller handles redirect
        }
        AuthResult::Failure(msg) | AuthResult::Unavailable(msg) => {
            AuthPhase::Initial // caller handles error
        }
    }
}
```

### Session Storage for Multi-Phase

The `auth_sessions` table needs a `phase` column or a temporary `pending_mfa_subject` in a short-lived store:

```sql
CREATE TABLE auth_pending_mfa (
    token TEXT PRIMARY KEY,     -- random token set as cookie during MFA prompt
    subject TEXT NOT NULL,
    display_name TEXT NOT NULL,
    groups_json TEXT NOT NULL,
    role TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL  -- short TTL (5 min)
);
```

Flow:
1. Primary auth succeeds, user needs MFA → store pending state in `auth_pending_mfa`, set cookie `persea_mfa_pending=<token>`
2. User submits TOTP code → middleware reads cookie, looks up pending state, calls `mfa_provider.verify_second_factor()`
3. On success → delete pending, create full session
4. On failure → delete pending, return 401

## 5. Redirect vs Inline Providers

### How the Middleware Handles Both

The key insight: **redirect providers don't go through the middleware at all for Phase 1**. They have dedicated HTTP handlers.

```
Browser → GET /auth/login
  → router checks: is OIDC configured?
    → yes: redirect to OIDC IdP
    → no: show login form (LDAP/database/RADIUS)

Browser → POST /auth/login (username + password)
  → middleware tries each inline provider in chain order
    → LDAP bind? Database password check? RADIUS?
    → first success wins

Browser → GET /auth/callback (OIDC/SAML callback)
  → callback handler exchanges code for tokens
  → creates session

Browser → POST /auth/mfa (TOTP code)
  → middleware verifies second factor
  → creates session
```

### Concrete Middleware Pattern

```rust
/// Extractor-based auth — per-handler, not global.
///
/// `require_auth` checks: session cookie, API key, or MFA-complete state.
/// `optional_auth` does the same but passes through without identity.
///
/// Phase 1 (login form submission) goes through a SEPARATE handler
/// that calls into the auth chain. This handler is NOT middleware —
/// it's a regular axum handler on POST /auth/login.
pub async fn require_auth(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: Request,
    next: Next,
) -> Response {
    // 1. Check session cookie (existing pattern)
    // 2. Check API key / bearer token (existing pattern)
    // 3. If neither → 401
}

/// Login handler — Phase 1 of auth.
pub async fn login_handler(
    State(state): State<AppState>,
    Form(creds): Form<LoginCredentials>,
) -> Response {
    let request = AuthRequest {
        client_ip: /* from headers */,
        username: Some(creds.username),
        password: Some(creds.password),
        callback_params: None,
        bearer_token: None,
        headers: HashMap::new(),
    };

    let phase = auth_flow(&state.auth_chain, &request, &state.db).await;

    match phase {
        AuthPhase::Complete { subject, display_name, groups, role } => {
            // Create session, set cookie, redirect
        }
        AuthPhase::PrimaryComplete { requires_mfa: true, subject, .. } => {
            // Store pending MFA state, redirect to /auth/mfa
        }
        AuthPhase::Initial => {
            // Auth failed
        }
        _ => unreachable!(),
    }
}
```

### Why Extractor-Based (Not Global Middleware)

**Current codebase already uses this pattern** — `require_auth` and `optional_auth` are middleware functions applied per-route or per-route-group in `main.rs`. This is the right approach because:

1. **Different routes need different auth**: `/api/*` requires auth, `/auth/login` must NOT require auth, `/` is optional
2. **Redirect providers need dedicated handlers**: OIDC `/auth/login` → redirect, `/auth/callback` → handle callback. These routes must NOT go through `require_auth`
3. **Static files need optional auth**: `static/client.html` should work without auth for the landing page
4. **Global middleware would block login routes**: You'd need to exclude login/auth routes from the middleware, which is messy

The `axum-login` crate uses `login_required!` macro which generates per-route middleware — same pattern. Their `AuthSession` extractor pulls auth state directly from request extensions.

### Recommended Pattern for persea

```rust
// In main.rs — router construction:
let auth_routes = Router::new()
    .route("/login", post(login_handler))      // Phase 1: username+password
    .route("/callback", get(oidc_callback))     // OIDC callback
    .route("/saml/acs", post(saml_acs))         // SAML ACS
    .route("/mfa", get(mfa_form))               // TOTP input form
    .route("/mfa", post(mfa_verify))            // TOTP verification
    .route("/logout", post(logout_handler));

let api_routes = Router::new()
    .route("/sessions", get(list_sessions))
    .route("/sessions", post(create_session))
    .layer(middleware::from_fn(require_auth));    // ← per-group

let admin_routes = Router::new()
    .route("/users", get(list_users))
    .route("/users", put(update_user))
    .layer(middleware::from_fn(require_auth));    // ← admin also needs auth

let app = Router::new()
    .nest("/auth", auth_routes)                   // no auth middleware
    .nest("/api", api_routes)                     // has auth middleware
    .nest("/admin", admin_routes)                 // has auth middleware
    .route("/", get(|| async { Redirect::to("/connections.html") }))
    .layer(middleware::from_fn(optional_auth));    // optional for static
```

## 6. axum Middleware Patterns

### Extractor vs Layer

| Pattern | How it works | When to use |
|---|---|---|
| **Layer-based middleware** (`tower::layer`) | Wraps entire router, runs for ALL requests | Rate limiting, logging, CORS |
| **From-fn middleware** (`middleware::from_fn`) | Per-route-group, runs for matched routes | Auth, which needs route-level control |
| **Extractor** (`FromRequestParts`) | Pulls data from request extensions | Getting auth identity inside handlers |

**Best pattern for persea**: `middleware::from_fn` for auth enforcement + `FromRequestParts` extractor for identity access.

```rust
/// Axum extractor that pulls AuthIdentity from request extensions.
/// Usage in handlers: `async fn handler(identity: Option<AuthIdentity>) -> ...`
impl FromRequestParts<AppState> for AuthIdentity {
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions
            .get::<AuthIdentity>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)
    }
}
```

This matches what `axum-login` does: `AuthSession` is an extractor that reads from request extensions, and the `AuthManager` layer sets those extensions.

## 7. Provider Registration

### Factory Pattern (from Keycloak SPI)

Keycloak uses `ProviderFactory<T>` that creates per-request `Provider` instances:

```java
public interface ProviderFactory<P extends Provider> {
    P create(KeycloakSession session);
    void init(Config.Scope config);
    void postInit(KeycloakSessionFactory factory);
    void close();
    String getId();
}
```

### Rust Adaptation

For persea, providers are singletons (cold path, no per-request creation needed). But a factory-like pattern helps with config parsing and construction:

```rust
/// Factory trait for constructing providers from config.
#[async_trait]
pub trait AuthProviderFactory: Send + Sync {
    /// The provider ID this factory creates (e.g. "ldap", "oidc").
    fn id(&self) -> &str;

    /// Construct the provider from config + shared dependencies.
    async fn build(
        &self,
        config: &AuthProviderConfig,
        shared: &SharedDeps,
    ) -> Result<Box<dyn AuthProvider>, String>;
}

/// Registry of all known factories. Populated at startup.
pub struct ProviderRegistry {
    factories: HashMap<String, Box<dyn AuthProviderFactory>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        let mut factories: HashMap<String, Box<dyn AuthProviderFactory>> = HashMap::new();
        factories.insert("oidc".into(), Box::new(OidcFactory));
        factories.insert("ldap".into(), Box::new(LdapFactory));
        factories.insert("database".into(), Box::new(DatabaseFactory));
        factories.insert("api_key".into(), Box::new(ApiKeyFactory));
        factories.insert("radius".into(), Box::new(RadiusFactory));
        factories.insert("saml".into(), Box::new(SamlFactory));
        factories.insert("totp".into(), Box::new(TotpFactory));
        Self { factories }
    }

    pub async fn build_chain(
        &self,
        config: &AuthConfig,
        shared: &SharedDeps,
    ) -> Result<AuthChain, String> {
        let mut providers = Vec::new();
        let mut mfa = None;

        for method_name in &config.methods {
            let factory = self.factories.get(method_name)
                .ok_or_else(|| format!("unknown auth method: {method_name}"))?;

            let provider_config = config.provider_config(method_name)?;
            let provider = factory.build(&provider_config, shared).await?;

            if provider.capabilities().contains(Capabilities::MFA) {
                mfa = Some(provider);
            } else {
                providers.push(provider);
            }
        }

        Ok(AuthChain { providers, mfa_provider: mfa })
    }
}
```

### Why Not Pure Instantiation From Config

Direct `match` on method names (the simple approach in section 3) is fine for a fixed set of providers. The factory pattern is better when:
- You want to add providers without modifying the main config parsing code
- You want to test providers in isolation
- You might eventually support dynamic plugin loading

**Recommendation**: Start with the simple `match` approach (section 3). Refactor to factory pattern if/when plugin support is needed.

## 8. Complete Config Structure

```toml
# ── Authentication ──────────────────────────────────────
[auth]
# Ordered list of authentication methods. First successful match wins.
# Available: "oidc", "ldap", "database", "api_key", "radius", "saml"
# Special: "totp" is always Phase 2 (second factor), not in the primary chain.
methods = ["oidc", "ldap", "api_key"]

# Session TTL after successful authentication (seconds). Default: 86400 (24h).
session_ttl_secs = 86400

# Where to redirect after login (default: /connections.html).
post_login_redirect = "/connections.html"

# Where to redirect for login (default: /).
login_url = "/"

[auth.oidc]
issuer_url = "https://auth.example.com/realms/corp"
client_id = "persea"
# client_secret: set in config or via OIDC_CLIENT_SECRET env var
redirect_uri = "https://persea.example.com/auth/callback"
groups_claim = "groups"
extra_scopes = ["groups"]
default_role = "operator"
tls_skip_verify = false
ca_cert = null

[auth.ldap]
url = "ldaps://ldap.example.com:636"
# bind_password: set via LDAP_BIND_PASSWORD env var
bind_dn = "cn=persea,ou=service,dc=example,dc=com"
user_search_base = "ou=users,dc=example,dc=com"
user_search_filter = "(uid={username})"
user_name_attribute = "uid"
group_search_base = "ou=groups,dc=example,dc=com"
group_search_filter = "(member={user_dn})"
group_name_attribute = "cn"
tls_skip_verify = false
ca_cert = null
# StartTLS support (for plain LDAP on port 389)
starttls = false

[auth.database]
# Uses the existing SQLite DB's users table for password validation.
# No additional config needed — reads password_hash from users table.
enabled = true

[auth.api_key]
# API key auth via Authorization: Bearer <key> or X-API-Key header.
# Uses existing admins and user_api_tokens tables. No additional config.
enabled = true

[auth.radius]
host = "radius.example.com"
port = 1812
# shared_secret: set via RADIUS_SECRET env var
timeout_secs = 5
nas_identifier = "persea"

[auth.saml]
idp_metadata_url = "https://idp.example.com/metadata"
idp_metadata_file = null  # alternative: local file path
entity_id = "persea"
acs_url = "https://persea.example.com/auth/saml/acs"
certificate = null  # path to SP certificate PEM
private_key = null  # path to SP private key PEM
groups_attribute = "groups"

[auth.totp]
# Second-factor provider. Applied after primary auth succeeds.
# Only shown/enforced for users with a TOTP secret enrolled.
enabled = false
issuer = "persea"
digits = 6
period = 30
# Number of time steps to allow clock skew (default: 1)
max_drift_steps = 1
```

## 9. Module Structure

```
src/
├── auth/
│   ├── mod.rs              # Re-exports, AuthIdentity, role helpers (existing)
│   ├── chain.rs            # AuthChain: ordered provider chain, from_config()
│   ├── extractors.rs       # AuthIdentity extractor, OptionalAuthIdentity
│   ├── middleware.rs        # require_auth, optional_auth (existing, refactored)
│   ├── session.rs          # AuthSession creation/validation, pending MFA store
│   ├── provider.rs         # AuthProvider trait, Capabilities, AuthResult, AuthRequest
│   └── providers/
│       ├── mod.rs          # Re-exports
│       ├── oidc.rs         # OidcProvider (wraps existing oidc.rs logic)
│       ├── ldap.rs         # LdapProvider (ldap3 crate)
│       ├── database.rs     # DatabaseProvider (password hash from SQLite)
│       ├── api_key.rs      # ApiKeyProvider (wraps existing key validation)
│       ├── radius.rs       # RadiusProvider (radius-client crate)
│       ├── saml.rs         # SamlProvider (saml-rs or quick-xml)
│       └── totp.rs         # TotpProvider (totp-rs crate)
├── oidc.rs                 # Existing OIDC logic → moves to providers/oidc.rs
├── auth.rs                 # Existing auth middleware → splits into auth/
```

### Migration Path

Phase 1 (existing):
- `auth.rs` — middleware + AuthIdentity + role helpers
- `oidc.rs` — OIDC login/callback handlers

Phase 2 (new):
1. Create `auth/provider.rs` with trait + types
2. Create `auth/providers/api_key.rs` — extract API key validation from `auth.rs`
3. Create `auth/chain.rs` — AuthChain with config parsing
4. Refactor `auth.rs` → `auth/middleware.rs` + `auth/extractors.rs`
5. Move `oidc.rs` → `auth/providers/oidc.rs` (keep handler functions)
6. Add remaining providers: ldap, database, radius, saml, totp

## 10. Key References

| Source | What it teaches |
|---|---|
| `axum-login` crate (v0.18) | `AuthnBackend` trait shape, `AuthSession` as extractor, tower-sessions integration |
| Keycloak Authenticator SPI | Factory + per-request provider pattern, flow-based auth (REQUIRED/ALTERNATIVE/CREDENTIAL) |
| Guacamole `AuthenticationProvider` | Credential provider separation, user + connection resolution in one interface |
| persea `src/auth.rs` | Existing `require_auth`/`optional_auth` pattern, `AuthIdentity` enum, session cookie handling |
| persea `src/oidc.rs` | OIDC login/callback flow, PKCE, state cookie binding, group extraction |
| persea `src/config.rs` | TOML config loading pattern, env var secret override, validation |
