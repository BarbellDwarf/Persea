# Ticket: M01 gap — LDAP escape only applied at 1 of 3 sites

wayfinder:task
Priority: P2
Phase: Medium

## Gap

`ldap_escape()` exists (line 81-88) and is applied in `lookup_user` (line 332), but:

- `find_user` (line 145) — the actual login-path filter — still interpolates raw `username`
- `resolve_groups` (line 205) — still interpolates raw `user_dn`

## Fix

Apply `ldap_escape()` at both remaining sites:

```rust
// Line 145:
let filter = self.config.user_search_filter.replace("{}", &ldap_escape(username));

// Line 205:
Some(f) => f.replace("{}", &ldap_escape(user_dn)),
```

## Files

- `src/auth_providers/ldap.rs:145,205`

## Deliverable

All 3 interpolation sites use `ldap_escape()`. `cargo check` passes. LDAP auth works with special-character usernames.
