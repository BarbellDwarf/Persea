# Ticket: Documentation Gaps

**Type:** task
**Labels:** documentation, wayfinder:task

## Question

What documentation is missing and what should be added?

### Findings from documentation audit:

**Missing entirely:**
- `CONTRIBUTING.md` — development setup, code style, testing, PR process
- `CHANGELOG.md` — version history (currently tracked via GitHub releases only)
- `contrib/README.md` — index of contrib scripts
- Database schema documentation (SQLite schema in `db.rs` inline only)
- Frontend architecture docs (4,000+ lines of JS in HTML files)
- Centralized API error reference

**Missing from existing docs:**
- `CLAUDE.md` lines 115-121: SPICE and Proxmox session types not mentioned
- `config.example.toml`: missing `[vdi]` section, typescript recording fields, `user_credentials_default_scope`
- `docs/deployment-guide.md` line 47: uses `ghcr.io` but README uses Docker Hub — inconsistent
- `docs/security.md` line 140: rate limit table contradicts code (1/sec vs 2/sec)

**Missing module docs:**
- `src/config.rs` — no `//!` module doc comment (1,717 lines)
- `src/session.rs` — no `//!` module doc comment (2,826 lines)
- `src/main.rs` — no `//!` module doc comment (entry point)

**Frontend documentation gap:**
- No `<!-- -->` comments in HTML files
- No JSDoc in JavaScript (inline in HTML)
- `connections.html` has 4,258 lines with zero contributor-facing comments

### Decision needed:

1. Priority: `CONTRIBUTING.md` first, or fill code-level gaps?
2. Frontend docs: inline comments or extract to separate doc?
3. Database schema: separate `docs/schema.md` or inline in `db.rs`?
4. Changelog: manual `CHANGELOG.md` or automated from conventional commits?
