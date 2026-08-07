# Ticket: Add regression tests for highest-severity modules

wayfinder:task
Priority: P3
Phase: Low

## Finding

`tests/` has no integration tests exercising `auth_providers/{ldap,saml,radius}.rs`, `pve.rs`, `vsphere.rs`, or the RBAC permission CTE. These are exactly the modules with the highest-severity findings above.

## Fix

Add regression tests alongside each Phase 1-3 fix so the specific vulnerability class can't silently regress:

1. **C01 (XSS)**: Test that `renderUserRow` escapes `<script>` in user.name/email
2. **C02 (SAML)**: Test that canonicalized XML matches expected output for known input
3. **C03 (vSphere)**: Test that `power_action` rejects viewer role, rejects malformed vm_id
4. **M01 (LDAP)**: Test that `ldap_escape` escapes `*`, `(`, `)`, `\`, NUL
5. **M02 (Fail-open)**: Test that handlers return Forbidden when identity is None
6. **H11 (CSV)**: Test that `csv_escape_field` prefixes `=`/`+`/`-`/`@` fields

These are unit/integration tests — no external dependencies needed.

## Files

- `tests/` directory — new test files

## Deliverable

Regression tests for each vulnerability class. `cargo test` passes. Tests are in the repo.
