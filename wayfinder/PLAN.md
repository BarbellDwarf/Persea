# Implementation Plan — Remaining Decisions

## Dependency Graph

```
Phase 1: Foundation (no cross-conflicts)
  #12 Mock traits ──────────────────────┐
  #2  #[must_use] on errors ───────────┤
  #3  Consolidate duplicated functions ─┤
                                        │
Phase 2: Error handling migration       │
  #1  Handlers → Result<T, AppError> ◄──┘ (needs #2, #12 for clean From impls)

Phase 3: Config & Health                │
  #9  Config validation + default IPs   │
  #5  Deep health check                 │

Phase 4: Observability                  │
  #4  Prometheus metrics (auth'd)       │
  #10 Request logging TraceLayer        │

Phase 5: Frontend                       │
  #7  JS extraction (theme/auth/utils)  │
  #6  WebSocket auto-reconnect          │

Phase 6: Reliability                    │
  #8  Session drain + TMUX awareness    │

Phase 7: Testing                        │
  #11 Property-based testing            │ (needs #12 mock traits)

Phase 8: Documentation                  │
  Vault from-zero guide                 │
  Vault troubleshooting                 │
  Namespace docs                        │
```

## Conflict Avoidance

| Phase | Primary files touched | Risk |
|-------|----------------------|------|
| 1 | `src/db.rs`, `src/auth.rs`, `src/oidc.rs`, `src/vdi/mod.rs` (new trait), `tests/` | Low — different modules |
| 2 | `src/api/*.rs` handlers only | Medium — many files in api/ |
| 3 | `src/config.rs`, `src/api/admin.rs` | Low |
| 4 | `src/main.rs` (router), `src/api/admin.rs` | Low |
| 5 | `static/*.html`, `static/js/` (new files) | Medium — many HTML files |
| 6 | `src/main.rs`, `src/websocket.rs` | Low |
| 7 | `tests/` only | Low |
| 8 | `docs/` only | Low |

## Per-Phase File Locks

Phases 1-4 touch Rust source. Phases 5 touches HTML/JS. Phases 6-7 touch Rust/tests. Phase 8 touches docs. No cross-phase file conflicts as long as phases execute sequentially.
