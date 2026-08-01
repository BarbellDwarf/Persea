# Ticket: Error Handling Unification

**Type:** grilling
**Labels:** architecture, wayfinder:grilling

## Question

Should the codebase adopt `thiserror`/`anyhow` or keep manual error types?

### Current state:
- 10+ modules define their own error types with manual `Display`/`Error` impls
- No unified error strategy: some use enums, some use `String`, some use `rusqlite::Result`
- API handlers map errors to HTTP status via 30+ inline match blocks
- Some error types missing `Display` impl (`SessionError`)
- Some missing `#[must_use]` on error types
- `config.rs` returns raw `String` errors from `toml::from_str`

### Options:
1. **Adopt `thiserror`** for domain errors — reduces boilerplate, standardizes `Display`/`Error`
2. **Adopt `anyhow`** for application-level errors — good for `main.rs`, handlers
3. **Keep manual but consolidate** — single `AppError` enum with `From` impls for each module error
4. **Hybrid** — `thiserror` for library errors (protocol, vault), `anyhow` for app-level

### Related issues:
- `role_level()` defined identically in `auth.rs:116` and `db.rs:1430`
- Cookie extraction duplicated across `auth.rs:159` and `oidc.rs:522`
- Admin role validation string repeated in 4 places

### Decision needed:

1. Error library: `thiserror`, `anyhow`, hybrid, or keep manual?
2. Centralized `AppError` enum or per-module errors with `From` conversions?
3. Consolidate duplicated functions (`role_level`, cookie extraction, role validation)?
