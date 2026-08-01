# Ticket: God Module Split — api.rs (4,984 lines)

**Type:** grilling
**Labels:** architecture, wayfinder:grilling

## Question

How should the 4,984-line `api.rs` god module be拆分?

### Current state:
- 55+ handler functions spanning sessions, recordings, reports, users, groups, tokens, address book, VDI, system status, docs, quick-connect
- `VaultBackends` struct and scope routing lives here instead of `vault.rs`
- `VaultCell`, `VaultState`, 7 marker types (`OidcEnabled`, `VaultConfigured`, etc.) defined here
- 30+ inline match blocks converting errors to HTTP responses (no centralized mapping)
- Role-check boilerplate repeated 20+ times

### Candidate split:
- `api/sessions.rs` — session CRUD, shadow, thumbnails
- `api/address_book.rs` — folder/entry CRUD, connect
- `api/users.rs` — user management, roles, groups
- `api/tokens.rs` — API token CRUD, audit
- `api/reports.rs` — session reports, CSV export, leaderboards
- `api/admin.rs` — system status, health, docs
- `api/vdi.rs` — VDI container listing, thumbnails
- `api/mod.rs` — shared types, error mapping, `AppState` alias

### Related decisions:
- Move `VaultBackends` to `vault.rs`
- Extract `require_role()` helper to eliminate 20+ duplicated role checks
- Create centralized error-to-HTTP mapping (one `impl IntoResponse` for all error types)
- Move `VaultCell`, `VaultState`, marker types to a `state.rs` or keep in `api/mod.rs`

### Decision needed:

1. Module boundary: by resource (sessions, users, tokens) or by concern (CRUD, auth, reporting)?
2. Where do shared types (`AppState`, marker types, `VaultBackends`) live?
3. Error mapping: centralized `From<AppError> for StatusCode` or per-module?
4. Should role checks become axum middleware/layer instead of per-handler boilerplate?
