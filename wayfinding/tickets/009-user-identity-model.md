# Ticket: User Identity Model

wayfinder:research
Blocked by: 003 (Auth DB Schema), 002 (Auth Provider Architecture), 004-008 (all auth methods)

## Question

How should persea unify user identity across multiple auth sources?

A user might authenticate via OIDC one day, LDAP the next, or database password as fallback. The system needs to know they're the same person. Group mappings must work across sources.

Key decisions needed:

1. **Linking key** — Email as universal linking key (all auth methods provide email). Primary lookup: `(auth_source, external_id)`. Fallback: email match.
2. **Auto-create accounts** — On first login from any source, auto-create DB user record. Configurable (`auto_create_accounts: true/false`).
3. **Account linking** — Can a user manually link additional auth methods? (e.g., "I also want to log in via LDAP"). Or is it automatic on email match?
4. **Group resolution** — Check OIDC groups, then LDAP groups, merge. Group-to-role mappings per source.
5. **Conflicting roles** — If OIDC says admin and LDAP says viewer, which wins? Highest role? Last login source?
6. **User profile** — What fields are editable by the user vs admin? Display name, email, preferences?
7. **Session unification** — One active session per user? Or allow multiple sessions from different auth sources?
8. **External group sync** — Login-time only (like Grafana) or background polling?

## Research needed

- How Grafana unifies users across OAuth/LDAP/SAML
- How GitLab handles OmniAuth + LDAP user linking
- How Keycloak handles identity brokering (IdP linking)
