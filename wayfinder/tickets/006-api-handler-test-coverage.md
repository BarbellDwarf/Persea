# Ticket: API Handler Test Coverage

**Type:** task
**Labels:** testing, wayfinder:task

## Question

How to add test coverage for the 55+ untested API handler functions?

### Current state:
- `api.rs` has 4,984 lines with zero handler tests
- Only helper functions tested (HTML escaping, recording name safety, credential partitioning)
- No request/response cycle tests
- No authentication middleware integration tests
- No rate limiting integration tests

### What needs testing:
1. **Session CRUD** — create, list, get, delete, shadow, thumbnail
2. **Address book** — folder/entry CRUD, connect flow
3. **User management** — list, create, disable, enable, delete, role changes
4. **Token management** — create, list, revoke, audit
5. **Reports** — session summary, CSV export, leaderboards
6. **Auth middleware** — 401/403 responses, key validation, IP allowlist
7. **WebSocket ticket** — creation, single-use validation

### Approach options:
- `axum::test` — built-in test utilities for axum handlers
- `tower::ServiceExt::oneshot` — lower-level request simulation
- In-process server with `reqwest` client
- Mock DB (`:memory:` SQLite) + mock Vault

### Decision needed:

1. Test framework: `axum::test` vs `tower::ServiceExt` vs full server?
2. Mock strategy for Vault and guacd in handler tests?
3. How to structure test fixtures (shared AppState setup)?
