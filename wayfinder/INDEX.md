# Wayfinder Ticket Index — rustguac Improvement Map

## Ticket Dependency Graph

```
Priority 1 (Security & Critical Architecture):
  001-security-hardening ─────────────────────────────────┐
  002-god-module-api-split ───────────────────────────────┤
  003-god-module-session-split ───────────────────────────┤
  004-error-handling-unification ─────────────────────────┤
                                                          │
Priority 2 (Testing & Reliability):                       │
  005-testing-strategy-security-critical ◄────────────────┤
  006-api-handler-test-coverage ◄── 002, 004 ────────────┤
  016-graceful-shutdown ──────────────────────────────────┤
  017-health-check-observability ─────────────────────────┤
                                                          │
Priority 3 (UI/UX & Frontend):                            │
  007-ui-ux-accessibility-overhaul ───────────────────────┤
  008-frontend-code-quality ◄── 007 ─────────────────────┤
  009-responsive-design-mobile ◄── 007 ──────────────────┤
  010-websocket-auto-reconnect ───────────────────────────┤
                                                          │
Priority 4 (Code Quality & DevOps):                       │
  011-documentation-gaps ────────────────────────────────┤
  012-performance-concurrency ◄── 002, 003 ──────────────┤
  013-devops-deployment ─────────────────────────────────┤
  014-config-validation ─────────────────────────────────┤
  015-code-quality-anti-patterns ◄── 002, 003, 004 ─────┤
  018-error-response-consistency ◄── 002, 004 ───────────┤
  019-cicd-pipeline-hardening ───────────────────────────┤
  020-rust-code-quality-lints ───────────────────────────┘
```

## Blocking Relationships

| Ticket | Blocked By | Reason |
|--------|------------|--------|
| 006-api-handler-test-coverage | 002-god-module-api-split | Can't test handlers before split |
| 006-api-handler-test-coverage | 004-error-handling-unification | Need unified error types for test assertions |
| 008-frontend-code-quality | 007-ui-ux-accessibility-overhaul | Accessibility fixes should land before refactor |
| 009-responsive-design-mobile | 007-ui-ux-accessibility-overhaul | Viewport/lang fixes are prerequisite |
| 012-performance-concurrency | 002-god-module-api-split | DB patterns affected by module boundaries |
| 012-performance-concurrency | 003-god-module-session-split | Session manager refactoring affects lock patterns |
| 015-code-quality-anti-patterns | 002-god-module-api-split | Role validation consolidation depends on split |
| 015-code-quality-anti-patterns | 003-god-module-session-split | CreateSessionRequest restructure depends on split |
| 015-code-quality-anti-patterns | 004-error-handling-unification | Error types need to be settled first |
| 018-error-response-consistency | 002-god-module-api-split | Error mapping depends on module structure |
| 018-error-response-consistency | 004-error-handling-unification | Need unified error types |

## Unblocked Frontier (can start now)

These tickets have no dependencies and can be worked on immediately:

| Ticket | Type | Effort |
|--------|------|--------|
| 001-security-hardening | research + task | Large |
| 002-god-module-api-split | grilling | Large |
| 003-god-module-session-split | grilling | Large |
| 004-error-handling-unification | grilling | Medium |
| 005-testing-strategy-security-critical | research | Medium |
| 007-ui-ux-accessibility-overhaul | grilling | Medium |
| 010-websocket-auto-reconnect | grilling | Medium |
| 011-documentation-gaps | task | Medium |
| 013-devops-deployment | research | Medium |
| 014-config-validation | research | Small |
| 016-graceful-shutdown | grilling | Medium |
| 017-health-check-observability | grilling | Medium |
| 019-cicd-pipeline-hardening | task | Medium |
| 020-rust-code-quality-lints | task | Small |

## Recommended Attack Order

**Phase 1 — Foundation (unblocks most other work):**
1. `004-error-handling-unification` — unblocks 006, 015, 018
2. `002-god-module-api-split` — unblocks 006, 012, 015, 018
3. `003-god-module-session-split` — unblocks 012, 015

**Phase 2 — Security & Quality:**
4. `001-security-hardening` — independent, high value
5. `015-code-quality-anti-patterns` — now unblocked
6. `014-config-validation` — quick win

**Phase 3 — Testing:**
7. `005-testing-strategy-security-critical` — research first
8. `006-api-handler-test-coverage` — now unblocked

**Phase 4 — UI/UX:**
9. `007-ui-ux-accessibility-overhaul` — independent
10. `008-frontend-code-quality` — after accessibility
11. `009-responsive-design-mobile` — after accessibility
12. `010-websocket-auto-reconnect` — independent

**Phase 5 — DevOps & Observability:**
13. `013-devops-deployment` — independent
14. `016-graceful-shutdown` — independent
15. `017-health-check-observability` — independent
16. `019-cicd-pipeline-hardening` — independent

**Phase 6 — Documentation & Polish:**
17. `011-documentation-gaps` — independent
18. `020-rust-code-quality-lints` — independent
19. `018-error-response-consistency` — now unblocked
