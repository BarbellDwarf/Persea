# Ticket: Auth Provider Architecture

wayfinder:research
Blocked by: nothing (Phase 1 — can start immediately)

## Question

How should persea structure its auth system to support LDAP, Database, SAML, RADIUS, TOTP, OIDC, and API keys?

The research recommends:
- Single `AuthProvider` trait with capability flags
- `dyn AuthProvider` (cold path, vtable cost irrelevant)
- Flat priority chain: providers in config order, first success wins
- Two-phase: primary auth → optional TOTP second factor
- Module structure: `auth/provider.rs`, `auth/registry.rs`, `auth/providers/*.rs`

Key decisions needed:

1. **Trait design** — What methods does `AuthProvider` need? `authenticate()`, `lookup_user()`, `resolve_groups()`, `auto_create_user()`, `capabilities()`?
2. **Provider registration** — `AuthProviderFactory` pattern? Or direct instantiation from config?
3. **Config structure** — `[auth]` section with `methods = ["oidc", "api_key"]` list? Each provider gets `[auth.ldap]`, `[auth.radius]`, etc.?
4. **Middleware integration** — Extractor-based (per-handler) or global middleware? Current code uses `require_auth` and `optional_auth` middleware.
5. **Redirect vs inline providers** — SAML and OIDC redirect to IdPs. LDAP/DB/ API key validate inline. How does the middleware handle both?
6. **Session management** — Where does the auth session live? Current: SQLite `auth_sessions` table. Does this change with multi-DB?

## Research needed

- How Apache Guacamole's `AuthenticationProvider` interface works
- How Keycloak's `Authenticator` SPI works
- Axum auth middleware patterns (extractor-based vs layer-based)
- How `axum-login` crate structures multi-backend auth
