# Ticket: LDAP Auth Method

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture)

## Question

How should persea implement LDAP/Active Directory authentication?

Enterprise environments use LDAP/AD as their primary identity store. persea needs to bind-then-search against LDAP, map groups to roles, and support both direct bind and search bind modes.

Key decisions needed:

1. **LDAP crate** — `ldap3` (0.12.1, Tokio async, pure-Rust, AD-compatible). Confirm.
2. **Bind modes** — Direct bind (DN derived from base + username) vs search bind (service account searches for DN first). Support both, config-driven.
3. **STARTTLS** — Required for production. Support `none`, `ssl`, `starttls` encryption methods.
4. **Group mapping** — LDAP groups → persea roles. How to query group membership? `memberOf` overlay? Nested group resolution?
5. **Connection pooling** — `ldap3` has no built-in pooling. Use `deadpool` or `bb8` wrapping `LdapConnAsync`?
6. **User search filter** — Configurable filter to restrict which LDAP users can log in (e.g., `(memberOf=CN=GuacUsers,...)`).
7. **Account auto-create** — On first LDAP login, auto-create DB user record for TOTP storage and permission management.
8. **Password changes** — LDAP auth means password changes happen in LDAP, not in persea. Disable password change UI for LDAP users.

## Research needed

- `ldap3` crate API: bind, search, STARTTLS, paged results
- Active Directory specific patterns (sAMAccountName, userPrincipalName, nested groups)
- LDAP connection pooling patterns in Rust
- Apache Guacamole's LDAP extension implementation
