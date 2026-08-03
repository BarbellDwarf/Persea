# Ticket: Multi-Database Backend Support

wayfinder:research
Blocked by: nothing (Phase 1 — can start immediately)

## Question

How should persea support MySQL, PostgreSQL, and SQLite as database backends?

Currently the codebase uses SQLite directly via `rusqlite`. Enterprise deployments need MySQL or PostgreSQL. The research recommends SQLx with enum-based dispatch (`DbPool` enum with `Postgres`/`MySQL`/`SQLite` variants).

Key decisions needed:

1. **SQLx vs SeaORM vs Diesel** — SQLx is recommended (raw SQL, async, `Any` driver, smallest dep tree). Confirm.
2. **Enum dispatch vs dyn trait** — enum-based `DbPool` with exhaustive matching. Confirm.
3. **Schema portability** — auto-increment PKs differ per backend (`AUTOINCREMENT` vs `SERIAL` vs `IDENTITY`). Need per-backend DDL or conditional schema.
4. **Migration strategy** — per-backend migration directories selected at runtime. SQLx `migrate!()` macro.
5. **UPSERT syntax** — `ON CONFLICT` (PostgreSQL/SQLite) vs `ON DUPLICATE KEY` (MySQL). Need backend-specific queries or use SQLx's `OnConflict` builder.
6. **Connection pooling** — sqlx's built-in pool or deadpool/bb8?

Research should confirm SQLx is the right choice and document the schema differences across backends.

## Research needed

- SQLx compile-time checking story for multi-DB
- Real Rust projects that support MySQL + PostgreSQL + SQLite simultaneously
- Migration tooling options (sqlx-migrate vs refinery vs sea-orm-migration)
- Concrete SQL portability issues for the current persea schema
