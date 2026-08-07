# Ticket: Fail-open role checks in admin handlers

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/api/users.rs:40-44,58-62,118-122` (`list_users`, `create_user`, `set_user_role`) and `src/api/reports.rs:359-370` (`delete_recording`) use `if let Some(...) = identity { if !has_role {...} }`, silently skipping the check when `identity` is `None`. Sibling handlers use the fail-closed pattern: `.map().unwrap_or(false)` or `match ... _ => Forbidden`.

Currently mitigated by outer `require_auth` middleware (`main.rs:1748`), but this is a defense-in-depth violation.

## Fix

Convert every instance to the fail-closed pattern. Replace:
```rust
if let Some(identity) = &identity {
    if !identity.has_role("admin") {
        return Err(AppError::Forbidden);
    }
}
```
With:
```rust
let identity = identity.as_ref().ok_or(AppError::Forbidden)?;
if !identity.has_role("admin") {
    return Err(AppError::Forbidden);
}
```

## Files

- `src/api/users.rs:40-44,58-62,118-122`
- `src/api/reports.rs:359-370`

## Deliverable

All role checks are fail-closed. No silent skip when identity is None. `cargo check` passes.
