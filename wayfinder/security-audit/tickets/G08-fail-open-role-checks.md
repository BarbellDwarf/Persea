# Ticket: M02 gap — Fail-open role checks completely untouched

wayfinder:task
Priority: P2
Phase: Medium

## Gap

All 4 functions byte-for-byte unchanged:

```rust
// Current (fail-open):
if let Some(Extension(ref id)) = identity {
    if !id.has_role("admin") {
        return Err(AppError::Forbidden(...));
    }
}
```

Skips check when `identity` is `None`.

## Affected functions

- `src/api/users.rs:40-44` — `list_users`
- `src/api/users.rs:58-62` — `create_user`
- `src/api/users.rs:118-122` — `set_user_role`
- `src/api/reports.rs:428-434` — `delete_recording`

## Fix

Convert to fail-closed pattern (already used by sibling handlers in same files):

```rust
let id = identity.as_ref()
    .map(|Extension(id)| id)
    .ok_or(AppError::Forbidden("authentication required".into()))?;
if !id.has_role("admin") {
    return Err(AppError::Forbidden("admin role required".into()));
}
```

## Files

- `src/api/users.rs:40-44,58-62,118-122`
- `src/api/reports.rs:428-434`

## Deliverable

All 4 handlers are fail-closed. No silent skip when identity is None. `cargo check` passes.
