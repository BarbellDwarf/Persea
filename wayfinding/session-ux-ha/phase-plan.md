# Phase Plan — Session UX + HA Tickets

## Ticket → Phase Map

| Phase | Tickets | Files | Can parallel? |
|-------|---------|-------|---------------|
| 1 | V01 (connections gap) + V06 (sidebar minimize) | app.css, header.html, connections.html | Yes (same files) |
| 2 | V02 (dark mode toggle) | theme.js, app.css | Yes |
| 3 | V05 (admin pages) | admin/auth.html, admin/groups.html, admin/reports.html | Yes |
| 4 | V07 (session toolbar) | client.html | Yes |
| 5 | V04 (recordings fullscreen) | recordings.html | Yes |
| 6 | V08 (file transfer) | client.html, create.rs, config.rs, settings.html | After V07 (same client.html) |
| 7 | V10 (recent connections + disconnect) | connections.html, client.html, sessions.html, types.rs, manager.rs | After V07, V11 |
| 8 | V11 (new tab) | connections.html, sessions.html | Yes |
| 9 | V03 + V09 (grilling: session switching, connection reason) | Design decisions | HITL — requires user input |
| 10 | V12 (HA docs) | docs/high-availability.md | AFK research |
| 11 | Verification + rebuild | Docker | After all code |

## Parallelism

After V06+V01 (Phase 1), phases 2-5 run in parallel (disjoint files).
Phase 6 (V08) depends on V07 (same client.html).
Phase 7 (V10) depends on V07 (client.html disconnect) + V11 (new tab).
Phase 8 (V11) runs in parallel with phases 2-5.
Phase 9 requires grilling — must wait for user decisions.
Phase 10 (V12) is independent AFK research — can run alongside anything.

## Agent assignments

| Agent | Phase | Tickets | Constraint |
|-------|-------|---------|------------|
| A | 1 | V01 + V06 | Single agent, sequential edits |
| B | 2 | V02 | Single agent |
| C | 3 | V05 | Single agent |
| D | 4+5 | V07 + V04 | Sequential (V07 first, then V04) |
| E | 8 | V11 | Yes, independent |
| F | 10 | V12 | AFK research, independent |
| G | 6 | V08 | After V07 |
| H | 7 | V10 | After V07 + V11 |

Phases A-F run in parallel. Phases G-H wait for their dependencies.
