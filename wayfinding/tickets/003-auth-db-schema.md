# Ticket: Auth Database Schema

wayfinder:research
Blocked by: 001 (Multi-DB Backend), 002 (Auth Provider Architecture)

## Question

What database schema does persea need for multi-method authentication, user identity, and connection storage?

Currently: SQLite with `admins`, `oidc_users`, `auth_sessions`, `api_tokens`, `group_mappings`, `audit_log` tables. Connections live in Vault.

Needed: Unified user table that works across auth sources (LDAP, SAML, OIDC, database, RADIUS). Connection storage in DB (replacing Vault as primary store). Password policies, TOTP secrets, group mappings.

Key decisions needed:

1. **User table design** — `id`, `username`, `email`, `display_name`, `auth_source`, `external_id`, `password_hash`, `totp_secret`, `disabled`, `expired`, `expiry_date`, `failed_attempts`, `locked_until`, `created_at`, `last_login`
2. **Connection table design** — Migrate from Vault address-book structure to relational tables. `connections`, `connection_groups`, `connection_params`, `connection_permissions`.
3. **Password history table** — `password_history` with `user_id`, `password_hash`, `password_salt`, `created_at`
4. **Auth session table** — Current `auth_sessions` works but needs multi-DB portability
5. **Group mapping table** — Map external groups (LDAP DN, SAML attribute, OIDC claim) to persea roles
6. **Audit event table** — Structured events with hash chain for tamper evidence

## Research

- [x] Apache Guacamole's full schema (23 tables) — analyzed, 10 essential adapted
- [x] NIST AU-2/AU-3 audit event requirements — hash-chain audit_events table designed
- [x] Connection storage for multi-DB — JSON params column on connections table (not normalized)
- [x] Complete portable DDL for PostgreSQL, MySQL, SQLite — see research doc

**Full research**: `wayfinding/003-auth-db-schema-research.md`

**Schema**: 15 tables, portable DDL, migration plan from current SQLite tables.
