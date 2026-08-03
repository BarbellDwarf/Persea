# Ticket: SAML 2.0 Auth Method

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture)

## Question

How should persea implement SAML 2.0 Service Provider integration?

Enterprise environments use SAML 2.0 for SSO alongside OIDC. persea needs to act as a Service Provider (SP), handle ACS (Assertion Consumer Service) callbacks, validate SAML responses, and extract user attributes.

Key decisions needed:

1. **SAML crate** — `saml-rs`/`opensaml` (pure-Rust, no C deps) vs `samael` (more downloads, requires C libs `xmlsec1`/`libxml2`). Tradeoff: purity vs maturity.
2. **SP metadata generation** — Generate SP metadata XML with entity ID, ACS URL, certificate.
3. **ACS handler** — POST endpoint to receive `SAMLResponse`, decode base64, validate signature, extract attributes.
4. **Signature validation** — XML-DSig validation. Which algorithm support? (RSA-SHA256 minimum).
5. **Attribute mapping** — Configurable mapping from SAML assertion attributes to username, email, groups.
6. **Group extraction** — SAML group attribute → persea roles. Configurable attribute name.
7. **Logout** — SLO (Single Logout) support? Or just local session termination?
8. **IdP metadata** — Load from URL or file. Auto-refresh?
9. **Strict mode** — Certificate validation, audience restriction, NotBefore/NotOnOrAfter checks.

## Research needed

- `samael` vs `saml-rs` vs `opensaml` crate comparison (maintenance, API, C deps)
- SAML 2.0 SP implementation requirements (ACS URL, entity ID, signature validation)
- Apache Guacamole's SAML extension
- How other Rust web apps handle SAML SP (e.g., ecosystem projects)
