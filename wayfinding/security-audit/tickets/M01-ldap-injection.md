# Ticket: LDAP injection via unescaped filter interpolation

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/auth_providers/ldap.rs:136,196,323` — Raw `username`/`user_dn` interpolated into LDAP search filters via `.replace("{}", ...)` with no RFC 4515 escaping. Bounded by the subsequent real bind, but enables search-scope manipulation/enumeration.

## Fix

Add an `ldap_escape()` helper that escapes RFC 4515 special characters: `*`, `(`, `)`, `\`, NUL. Apply at every filter-interpolation site:

```rust
fn ldap_escape(input: &str) -> String {
    input.replace('\\', "\\5c")
         .replace('*', "\\2a")
         .replace('(', "\\28")
         .replace(')', "\\29")
         .replace('\0', "\\00")
}
```

Then: `.replace("{}", &ldap_escape(&username))` at lines 136, 196, 323.

## Files

- `src/auth_providers/ldap.rs:136,196,323` — filter interpolation sites

## Deliverable

All LDAP filter interpolations use `ldap_escape()`. `cargo check` passes. LDAP auth still works with normal and special-character usernames.
