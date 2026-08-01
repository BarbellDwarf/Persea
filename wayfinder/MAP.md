# Wayfinder Map: rustguac Codebase Improvement

## Destination

A production-hardened, well-tested, accessible, documented codebase ready for community contribution and scale. The end state: every module has tests, every API endpoint has integration coverage, every page is WCAG AA accessible, security findings are resolved, god modules are拆分, and a contributor can onboard from `CONTRIBUTING.md` alone.

## Notes

- Rust codebase: 22,897 lines across 21 source files
- Axum web server, WebSocket proxy to guacd, session manager
- Supports SSH/RDP/VNC/SPICE/Proxmox/Web/VDI session types
- Uses Vault for address book, SQLite for admin DB, OIDC for auth
- 6 parallel audits completed: architecture, security, docs, UI/UX, code quality, testing

## Decisions so far

### Immediate Fixes (AI Slop & UI Consistency)
- Emoji removed from client.html clipboard tab
- "please" removed from 2 messages, "Note:" stripped from 2 technical messages
- CSS type badges added for SPICE and Proxmox
- client.html VDI/SPICE/Proxmox color variables added
- sessions.html type display changed from plain text to `.type-badge` styled pills

### Playwright Test Suite
- **55 tests, all passing** (Desktop Chrome)
- 8 spec files covering: admin, auth, connections, recordings, sessions, visual regression
- Session form validation: SSH/RDP/VNC/VDI payloads, keypair toggle, jump host cards
- Role-based visibility: admin vs unauthenticated navigation
- Visual regression: screenshots for all 6 pages + mobile variants
- Auth flow: API key injection via sessionStorage before navigation

### Phase 1: Architecture Refactoring
- **Error handling**: `src/error.rs` created with `AppError` enum, 12 variants, `IntoResponse` maps to correct HTTP status codes, `From` impls for all module error types
- **API split**: `src/api.rs` (4,984 lines) → `src/api/` directory with 7 files (mod.rs, sessions.rs, address_book.rs, users.rs, tokens.rs, reports.rs, admin.rs) — zero changes needed in main.rs due to `pub use` re-exports
- **Session split**: `src/session.rs` (2,826 lines) → `src/session/` directory with 4 files (mod.rs, types.rs, manager.rs, create.rs) — all imports resolve unchanged

### Phase 2: Security Hardening
- **API key hashing**: Added per-key 16-byte salt with `salt:hash` format, backward-compatible with legacy unsalted hashes
- **Auth**: Removed `?key=` query parameter fallback entirely
- **WebSocket**: Added 64 MiB message size limit, Origin header now required (empty Origin rejected)
- **Safety**: Added `// SAFETY:` comments to unsafe blocks, documented Vault token memory risk

### Phase 4: UI/UX Accessibility
- `lang="en"` added to all 9 HTML files
- `<meta name="viewport">` added to all 9 HTML files
- `aria-live="polite"` on error/status divs in 4 pages
- `aria-label` on 6 clipboard panel buttons in client.html
- `--text-dim` contrast improved from #666 to #999
- 4 modals in connections.html got `role="dialog"`, `aria-modal="true"`, `aria-labelledby`

### Phase 5: DevOps
- `LimitNOFILE=65535` in systemd service
- Systemd hardening directives (ProtectSystem, NoNewPrivileges, etc.)
- RPM build: `--with-spice`, `--disable-guacclip`, guacd commit pin
- Rate limit docs corrected to match code

### UI/UX Deep Audit Fixes
- **Modal focus traps**: `static/js/modal.js` — Escape key closes, Tab wraps inside
- **Touch targets**: `--ctl-sm` increased 38px → 44px (WCAG minimum)
- **Disabled button contrast**: color improved to #bbb, opacity 0.6
- **Focus indicators**: `:focus-visible` outline on buttons/links
- **Responsive breakpoints**: `@media` for 768px/480px in rustguac.css
- **Table overflow**: `.table-wrap` class, applied to 5 pages
- **Modal mobile**: `min-width: min(440px, 95vw)`
- **Connections sidebar**: stacks on mobile
- **Client panels**: responsive `min(380px, 90vw)`
- **Nav flex-wrap**: wraps on narrow screens
- **Session/group-delete**: confirmation dialogs added
- **Hidden nav items**: `aria-hidden="true"`

### Terminal Rendering
- **Scrollback**: 1,000 → 10,000, now configurable via `ssh_scrollback`
- **LANG env**: `LANG=en_US.UTF-8` injected into SSH sessions
- **ble.sh docs**: limitations documented in web-sessions.md

### Documentation Fixes (Round 2)
- **Deployment guide**: 3 wrong config key sections fixed
- **Troubleshooting**: `docs/troubleshooting.md` created
- **Install verification**: section added to installation.md
- **VDI ready_timeout_secs**: default corrected 30 → 120
- **Rust version**: standardized to 1.80+
- **CONTRIBUTING.md**: clone URL fixed

### Dependency Updates
- `rusqlite`: 0.31 → 0.32 (latest stable-compatible)
- `thiserror`: 1 → 2
- 24 semver-compatible packages via `cargo update`

### Implementation Phases (12 Remaining Decisions)

**Phase 1 — Foundation**
- Mock traits: `src/testing.rs` with `MockVault`, `MockDocker`, `MockGuacdConnection`
- `#[must_use]` on all 10 error enums
- Consolidated `role_level()`, cookie extraction, `VALID_ROLES` constant

**Phase 2 — Error handling migration**
- 48 handlers migrated to `Result<Json<Value>, AppError>`
- 13 handlers kept as `impl IntoResponse` (non-JSON returns)
- Error match blocks replaced with `?` operator

**Phase 3 — Config & health**
- Startup validation: listen_addr, guacd_addr, CIDR entries, display range
- Default allowed networks: RFC 1918 + localhost + ::1
- Deep health check: unauthenticated = shallow, authenticated = guacd + DB probe

**Phase 4 — Observability**
- `src/metrics.rs`: atomic counters for sessions/requests/errors
- `/metrics` endpoint: Prometheus text format
- `TraceLayer`: request logging at INFO level
- `MetricsLayer`: automatic request/error counting

**Phase 5 — Frontend**
- JS extraction: `theme.js`, `auth.js`, `utils.js` (105 lines shared)
- 8 HTML files updated to use external scripts
- WebSocket auto-reconnect: exponential backoff, 5 attempts, informative status

**Phase 6 — Reliability**
- Graceful session drain with configurable `shutdown_timeout_secs`
- TMUX session detection and detach on SSH disconnect

**Phase 7 — Property-based testing**
- 14 proptest properties: protocol parser, vault path validation
- `proptest = "1"` added to dev-dependencies

**Phase 8 — Vault documentation**
- "Vault from Zero" guide: install → init → unseal → KV v2 → policy → AppRole
- Vault troubleshooting: 6 common failure modes with diagnostic commands
- Namespace documentation: when to use, CLI examples
- Deployment guide Step 6 expanded with inline checklist

## Not yet specified

- Whether to migrate API handlers to return `Result<T, AppError>` (error.rs exists but handlers still use inline error mapping)
- Whether to add `#[must_use]` to all error types across modules
- Whether to consolidate duplicated functions (`role_level`, cookie extraction, role validation) into shared helpers
- Prometheus metrics endpoint design
- Deep health check implementation (guacd + DB + Vault connectivity)
- WebSocket auto-reconnect with exponential backoff
- Frontend JS extraction to external files (bundle strategy)
- Session drain on graceful shutdown
- Config validation at startup (address parsing, CIDR validation)
- Request logging middleware (tower-http TraceLayer)
- Property-based testing (proptest) for parsers
- Mock traits for Vault/Docker/guacd in tests

## Out of scope

*(nothing ruled out yet — full audit map)*

---

## Tickets

See `tickets/` directory for individual decision tickets.
