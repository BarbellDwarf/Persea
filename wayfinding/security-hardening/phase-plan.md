# 1.1.0 Phase Plan — Conflict-Free Subagent Assignments

## Updated file conflict map

```
session/create.rs  ← S02 + R01 + R02 + R05 + S06
                    → ONE agent, sequential in-file edits

main.rs            ← S01 + S03 + H03 + U03
                    → 4 independent sections (CSP, rate-limit, startup, auth middleware)

websocket.rs       ← R03 + H02
                    → 2 different sections

Cargo.toml/lock    ← D01-D05
                    → sequential, one agent

csrf.rs            ← S04
error.rs           ← S05
protocol.rs        ← R04
oidc.rs            ← H01
config.example.toml← H03
docs/              ← H03

connections.html   ← U01 (standalone rewrite)
header.html + theme.js ← U02 + U05 (same files, same agent)
admin/settings.html ← U04 (standalone)
admin/reports.html + reports.rs ← U06 + U07 (same backend file, same agent)
```

## Phases (6 → 8 after adding UI tickets)

| Phase | Tickets | Files | Agents | Phase |
|-------|---------|-------|--------|-------|
| 1 | D01-D05 | Cargo.toml/lock | 1 | sequential (same lockfile) |
| 2 | S02+R01+R02+R05+S06 | session/create.rs | 1 | sequential (same file) |
| 3 | S01+S03+S04+H01+H03+U03 | main.rs + csrf.rs + oidc.rs + config + docs | 1 | main.rs 4 spots + 3 independent |
| 4 | R03+R04+H02+S05 | websocket.rs + protocol.rs + error.rs | 1 | 3 independent files |
| 5 | U02+U05 | header.html + theme.js | 1 | same files (additive) |
| 6 | U01 | connections.html | 1 | standalone rewrite |
| 7 | U06+U07 | admin/reports.html + reports.rs + recordings.html | 1 | reports.rs shared, templates separate |
| 8 | U04 | admin/settings.html + sidebar.html + backend | 1 | standalone + sidebar |
| 9 | Verification | — | 1 | docker rebuild + smoke test |

**Parallelism: Phases 2–8 all run simultaneously after Phase 1.**

```
Phase 1 (deps) ─────────────────────────────────────────────┐
                                                             │
Phase 2 (session/create.rs) ────────────────────────────────┤
Phase 3 (main.rs + csrf + oidc + docs + auth) ─────────────┤
Phase 4 (websocket + protocol + error) ─────────────────────┤
Phase 5 (dark mode + theme) ────────────────────────────────┤
Phase 6 (connections layout) ───────────────────────────────┤
Phase 7 (reports + recordings) ─────────────────────────────┤
Phase 8 (admin settings + sidebar) ─────────────────────────┘
                                                             │
                                                    Phase 9 (rebuild)
```

**Wall time: ~20-25 min** (Phase 1 ~5 min, then 7 parallel agents ~15-20 min, then rebuild ~5 min).

## Total commits: 26

| Phase | Commits | Tickets |
|-------|---------|---------|
| 1 | 5 | D01-D05 |
| 2 | 5 | S02, R01, R02, R05, S06 |
| 3 | 6 | S01, S03, S04, H01, H03, U03 |
| 4 | 4 | R03, R04, H02, S05 |
| 5 | 2 | U02, U05 |
| 6 | 1 | U01 |
| 7 | 2 | U06, U07 |
| 8 | 1 | U04 |
| **Total** | **26** | |

## Updated agent instructions

Each agent:
1. Commits to `1.1.0` branch directly
2. One commit per ticket (conventional prefix + ticket ID)
3. `cargo check` after each commit (where applicable)
4. Never touches files outside its assigned list
5. Pulls latest before starting (handles parallel commits from other phases)
