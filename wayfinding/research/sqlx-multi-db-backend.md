# Research: SQLx Multi-Database Backend Patterns

Ticket: `001-multi-db-backend.md`

## 1. SQLx `Any` Driver — Runtime Backend Switching

### How it works

The `Any` driver (`sqlx::any`) is a **runtime-generic database driver** that selects the actual backend at runtime based on the connection URL scheme. From docs.rs/sqlx:

```rust
use sqlx::any::install_default_drivers;
use sqlx::AnyPool;

// Must install drivers first — panics without this
install_default_drivers();

// Runtime selection based on URL scheme
let pool = AnyPool::connect("sqlite://file.db").await?;
// Or:
let pool = AnyPool::connect("postgres://localhost/mydb").await?;
// Or:
let pool = AnyPool::connect("mysql://localhost/mydb").await?;
```

### Can you write one set of queries across all backends?

**Partially.** The `Any` driver supports the **intersection** of SQL syntax. The `query!()` macro does **not** work with `Any` — it requires a specific backend. You must use `sqlx::query()` (runtime-checked) or `sqlx::query_scalar()`.

What works across all backends:
- Basic `SELECT`, `INSERT`, `UPDATE`, `DELETE`
- Parameterized queries using `?` placeholders (Any driver translates to backend-specific syntax)
- Basic types: `i32`, `i64`, `f32`, `f64`, `String`, `Vec<u8>`, `bool`

What does NOT work:
- `query!()` / `query_as!()` macros (require compile-time database connection)
- UPSERT syntax (PostgreSQL `ON CONFLICT` vs MySQL `ON DUPLICATE KEY` vs SQLite `ON CONFLICT`)
- Backend-specific functions (`NOW()`, `datetime('now')`, `RETURNING` clause)
- JSON operations, array types, enums, custom types
- `INSERT ... RETURNING` (PostgreSQL-only)

### Limitations

1. **No compile-time checking** — `query!()` macro doesn't work with `Any`
2. **No backend-specific features** — stuck at the lowest common denominator
3. **Type erasure** — `AnyRow` requires manual column access by index or name, no type-safe mapping
4. **Driver registration** — must call `install_drivers()` or `install_default_drivers()` before any `AnyPool`/`AnyConnection` use
5. **Performance overhead** — dynamic dispatch layer on top of the actual driver

**Verdict:** The `Any` driver is useful for simple CRUD, tools, and admin interfaces where you need one binary for multiple backends. For an application with complex queries, **enum-based dispatch is better**.

---

## 2. Enum-Based DbPool Pattern

This is the recommended approach for multi-backend applications. Source: SQLx GitHub discussions, community patterns.

### Implementation

```rust
use sqlx::PgPool;
use sqlx::MySqlPool;
use sqlx::SqlitePool;

pub enum DbPool {
    Postgres(PgPool),
    MySQL(MySqlPool),
    SQLite(SqlitePool),
}

pub enum DbKind {
    Postgres,
    MySQL,
    SQLite,
}

impl DbPool {
    pub fn kind(&self) -> DbKind {
        match self {
            DbPool::Postgres(_) => DbKind::Postgres,
            DbPool::MySQL(_) => DbKind::MySQL,
            DbPool::SQLite(_) => DbKind::SQLite,
        }
    }

    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        if url.starts_with("postgres") {
            Ok(DbPool::Postgres(PgPool::connect(url).await?))
        } else if url.starts_with("mysql") {
            Ok(DbPool::MySQL(MySqlPool::connect(url).await?))
        } else if url.starts_with("sqlite") {
            Ok(DbPool::SQLite(SqlitePool::connect(url).await?))
        } else {
            Err(sqlx::Error::Configuration(
                format!("Unsupported database URL scheme: {}", url).into(),
            ))
        }
    }
}
```

### Query dispatch pattern

```rust
// Example: insert a session
pub async fn insert_session(pool: &DbPool, session: &Session) -> Result<(), sqlx::Error> {
    match pool {
        DbPool::Postgres(pg) => {
            sqlx::query(
                "INSERT INTO sessions (id, username, created_at) VALUES ($1, $2, $3)"
            )
            .bind(&session.id)
            .bind(&session.username)
            .bind(session.created_at)
            .execute(pg)
            .await?;
        }
        DbPool::MySQL(mysql) => {
            sqlx::query(
                "INSERT INTO sessions (id, username, created_at) VALUES (?, ?, ?)"
            )
            .bind(&session.id)
            .bind(&session.username)
            .bind(session.created_at)
            .execute(mysql)
            .await?;
        }
        DbPool::SQLite(sqlite) => {
            sqlx::query(
                "INSERT INTO sessions (id, username, created_at) VALUES (?, ?, ?)"
            )
            .bind(&session.id)
            .bind(&session.username)
            .bind(session.created_at)
            .execute(sqlite)
            .await?;
        }
    }
    Ok(())
}
```

### Cleaner pattern with a macro or helper trait

```rust
// Macro to reduce match boilerplate
macro_rules! db_dispatch {
    ($pool:expr, |$conn:ident| $body:expr) => {
        match $pool {
            DbPool::Postgres($conn) => $body,
            DbPool::MySQL($conn) => $body,
            DbPool::SQLite($conn) => $body,
        }
    };
}

// Usage:
pub async fn insert_session(pool: &DbPool, session: &Session) -> Result<(), sqlx::Error> {
    db_dispatch!(pool, |conn| {
        sqlx::query("INSERT INTO sessions (id, username, created_at) VALUES (?, ?, ?)")
            .bind(&session.id)
            .bind(&session.username)
            .bind(session.created_at)
            .execute(conn)
            .await?;
    });
    Ok(())
}
```

**Note:** The placeholder syntax differs: PostgreSQL uses `$1, $2, $3` while MySQL and SQLite use `?`. The macro approach still requires backend-specific SQL strings for non-trivial queries. For parameterized queries, use `?` everywhere — SQLx's MySQL and SQLite drivers accept `?`, while PostgreSQL requires `$N`. This is the **biggest ergonomic pain point**.

### Alternative: use `QueryBuilder` for dynamic SQL

```rust
use sqlx::QueryBuilder;

// Build queries dynamically
let mut builder = QueryBuilder::new("INSERT INTO sessions (id, username, created_at) ");
builder.push("(");
builder.push_bind(session.id);
builder.push(", ");
builder.push_bind(session.username);
builder.push(", ");
builder.push_bind(session.created_at);
builder.push(")");
```

`QueryBuilder` handles placeholder syntax differences automatically.

---

## 3. Schema Differences Across Backends

### Auto-increment PKs

| Backend | Syntax |
|---------|--------|
| PostgreSQL | `id SERIAL PRIMARY KEY` or `id GENERATED ALWAYS AS IDENTITY` |
| MySQL | `id INT AUTO_INCREMENT PRIMARY KEY` |
| SQLite | `id INTEGER PRIMARY KEY AUTOINCREMENT` |

**Portable approach:** Use `id INTEGER PRIMARY KEY` — in PostgreSQL this creates a `BIGINT` (not auto-increment). Better: use a **separate migration per backend** or use a `BIGSERIAL`/`BIGINT` that works across all:
```sql
-- PostgreSQL
id BIGSERIAL PRIMARY KEY

-- MySQL
id BIGINT AUTO_INCREMENT PRIMARY KEY

-- SQLite
id INTEGER PRIMARY KEY AUTOINCREMENT
```

### UPSERT

| Backend | Syntax |
|---------|--------|
| PostgreSQL | `ON CONFLICT (col) DO UPDATE SET ...` |
| MySQL | `ON DUPLICATE KEY UPDATE col = ...` |
| SQLite | `ON CONFLICT (col) DO UPDATE SET ...` (SQLite 3.24+) |

**Not portable.** Must use backend-specific queries or `sqlx::QueryBuilder` with conditional clauses.

### Text Types

| Backend | Syntax |
|---------|--------|
| PostgreSQL | `TEXT` or `VARCHAR(n)` |
| MySQL | `TEXT` or `VARCHAR(n)` |
| SQLite | `TEXT` (all text stored as TEXT internally) |

**Portable:** Use `TEXT` — works across all three.

### BLOB Types

| Backend | Syntax |
|---------|--------|
| PostgreSQL | `BYTEA` |
| MySQL | `BLOB`, `LONGBLOB`, etc. |
| SQLite | `BLOB` |

**Portable:** Use `BYTEA` (PostgreSQL) or `BLOB` (MySQL/SQLite). Not directly compatible. For portable DDL:
- PostgreSQL: `BYTEA`
- MySQL: `LONGBLOB`
- SQLite: `BLOB`

Or store as base64 `TEXT` if cross-compatibility matters more than storage efficiency.

### JSON Columns

| Backend | Syntax |
|---------|--------|
| PostgreSQL | `JSONB` (binary, indexable) |
| MySQL | `JSON` |
| SQLite | `TEXT` (no native JSON type) |

**Portable:** Store JSON as `TEXT` across all backends, or use `JSONB`/`JSON` with a migration per backend. For querying JSON, PostgreSQL has `->>`, `@>`, MySQL has `JSON_EXTRACT()`, SQLite has `json_extract()`.

### Timestamp Functions

| Backend | Current timestamp |
|---------|------------------|
| PostgreSQL | `NOW()` or `CURRENT_TIMESTAMP` |
| MySQL | `NOW()` or `CURRENT_TIMESTAMP` |
| SQLite | `datetime('now')` or `CURRENT_TIMESTAMP` |

**Portable:** `CURRENT_TIMESTAMP` works across all three as a column default.

### Portable DDL Template

```sql
-- This works across PostgreSQL, MySQL, and SQLite:
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,          -- UUID stored as text
    username TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
);
```

**Key insight:** Using `TEXT` for PKs (UUIDs), `TEXT` for timestamps, and `TEXT` for enums gives maximum portability. The trade-off is losing database-level type checking and auto-increment.

---

## 4. Migration Strategy

### sqlx-migrate

SQLx's built-in `migrate!()` macro embeds migrations at compile time. From docs:

```rust
// Embeds ./migrations directory into the binary
static MIGRATOR: sqlx::migrator::Migrator = sqlx::migrate!("./migrations");

// Run at startup
MIGRATOR.run(&pool).await?;
```

### Can you have per-backend migrations?

**Not natively.** SQLx's `migrate!()` macro takes a single directory and runs all `.sql` files in it. There is no built-in mechanism for per-backend migration directories.

**Workarounds:**

1. **Conditional SQL in a single migration** — Use backend-specific SQL with comments or runtime checks:
   ```sql
   -- PostgreSQL
   CREATE TABLE IF NOT EXISTS sessions (
       id BIGSERIAL PRIMARY KEY,
       ...
   );
   ```
   Problem: PostgreSQL's `BIGSERIAL` will fail on MySQL.

2. **Per-backend migration directories with runtime selection:**
   ```rust
   static PG_MIGRATOR: sqlx::migrator::Migrator = sqlx::migrate!("./migrations/postgres");
   static MYSQL_MIGRATOR: sqlx::migrator::Migrator = sqlx::migrate!("./migrations/mysql");
   static SQLITE_MIGRATOR: sqlx::migrator::Migrator = sqlx::migrate!("./migrations/sqlite");

   match &pool {
       DbPool::Postgres(pg) => PG_MIGRATOR.run(pg).await?,
       DbPool::MySQL(mysql) => MYSQL_MIGRATOR.run(mysql).await?,
       DbPool::SQLite(sqlite) => SQLITE_MIGRATOR.run(sqlite).await?,
   }
   ```

3. **Programmatic migrations using `Migrator::with_migrations()`:**
   ```rust
   use sqlx::migrate::Migration;
   use sqlx::migrator::Migrator;
   use std::borrow::Cow;

   let migrations = vec![
       Migration::new(1, "init".into(), Cow::Borrowed("CREATE TABLE ..."), false),
   ];
   let migrator = Migrator::with_migrations(migrations);
   ```

4. **Use a portable DDL subset** — Write SQL that works across all backends (see Section 3 above). This is the simplest approach for new projects.

**Recommendation:** Use approach #2 (per-backend migration directories) for maximum flexibility. It adds some directory structure overhead but gives full control over backend-specific DDL.

### Alternative: refinery or sea-orm-migration

- `refinery` — Supports per-backend migrations with compiled SQL files, but is older and less maintained
- `sea-orm-migration` — Built on SQLx, supports per-backend migrations, but adds ORM overhead

**Recommendation:** Stick with SQLx's `migrate!()` macro and per-backend directories. It's the most straightforward approach.

---

## 5. Compile-Time Checking with Multiple Backends

### How `query!()` works

The `query!()` macro connects to the database specified by `DATABASE_URL` at compile time and validates the SQL against the actual schema. It **does not work** with the `Any` driver.

### Feature flags

```toml
[dependencies]
sqlx = { version = "0.8", features = [
    "runtime-tokio",
    "tls-rustls",
    "postgres",    # for PgPool, query! with Postgres
    "mysql",       # for MySqlPool, query! with MySQL
    "sqlite",      # for SqlitePool, query! with SQLite
    "any",         # for AnyPool (no compile-time checking)
    "migrate",
    "macros",
] }
```

### Multi-backend compile-time checking strategy

**Option A: Single DATABASE_URL for CI, accept trade-offs**
- Set `DATABASE_URL` to one backend (e.g., PostgreSQL) during development
- Use `sqlx::query()` (runtime-checked) for backend-specific queries
- Use `sqlx::query!()` only for queries that work across all backends

**Option B: Compile-time check per backend with conditional compilation**
```rust
#[cfg(feature = "pg")]
pub async fn insert_session(pool: &PgPool, session: &Session) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO sessions (id, username, created_at) VALUES ($1, $2, $3)",
        session.id,
        session.username,
        session.created_at,
    )
    .execute(pool)
    .await?;
    Ok(())
}
```

**Option C: Offline mode with per-backend `.sqlx` caches**
- Run `cargo sqlx prepare` against each backend
- Store `.sqlx/` directories per backend (e.g., `.sqlx-pg/`, `.sqlx-mysql/`)
- Use `SQLX_OFFLINE_DIR` environment variable to select which cache to use

**Recommendation:** Use Option A for simplicity. Write most queries using `sqlx::query()` (runtime-checked) and reserve `query!()` for the common subset. Use `FromRow` derives for type-safe row mapping.

---

## 6. Connection Pooling

### sqlx's built-in pool (`sqlx::Pool`)

From docs.rs/sqlx:

```rust
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(5)
    .connect("postgres://localhost/mydb")
    .await?;
```

Features:
- Built-in, zero extra dependencies
- Configurable `max_connections`, `min_connections`, `connect_timeout`, `idle_timeout`
- Automatic connection health checking
- Works with all backends (PgPool, MySqlPool, SqlitePool)

### deadpool

```toml
deadpool-postgres = { version = "0.12", features = ["sqlx"] }
```

Features:
- Generic pool that works with any `Manager` trait
- More configuration options (recycling strategies, timeouts)
- Status reporting
- Extra dependency

### bb8

```toml
bb8 = "0.8"
bb8-postgres = "0.8"
```

Features:
- Generic connection pool
- More mature than deadpool
- Customizable recycling
- Extra dependency

### Recommendation

**Use sqlx's built-in pool.** Reasons:
- Zero extra dependencies
- Sufficient for most use cases
- First-party support, maintained alongside SQLx
- `deadpool` and `bb8` add complexity without proportional benefit for this use case

For the enum-based `DbPool`, each variant holds its own typed pool:

```rust
pub enum DbPool {
    Postgres(PgPool),      // sqlx::PgPool
    MySQL(MySqlPool),      // sqlx::MySqlPool
    SQLite(SqlitePool),    // sqlx::SqlitePool
}
```

---

## 7. Real-World Examples

### Projects supporting MySQL + PostgreSQL + SQLite simultaneously

1. **SeaORM** (`sea-ql/sea-orm`) — The most prominent example. An ORM built on top of SQLx that supports all three backends. Uses feature flags to select backends at compile time.

2. **sql-web** (`YinMo19/sql-web`) — A web-based database browser supporting SQLite, MySQL, and PostgreSQL. Uses SQLx with the `Any` driver for runtime backend selection.

3. **sqlx-ts** (`JasonShin/sqlx-ts`) — A TypeScript tool for compile-time SQL validation that supports multiple backends.

4. **ormlite** (`kurtbuilds/ormlite`) — An ORM built on SQLx supporting multiple backends.

5. **summer-rs** (`summer-rs/summer-rs`) — A Spring Boot-inspired framework for Rust that supports multiple database backends.

### Pattern observed across projects

Most multi-backend projects use one of two patterns:

1. **Feature flags for compile-time selection** (SeaORM pattern):
   ```toml
   [features]
   default = ["sqlite"]
   sqlite = ["sqlx/sqlite"]
   mysql = ["sqlx/mysql"]
   postgres = ["sqlx/postgres"]
   ```

2. **Enum dispatch for runtime selection** (sql-web pattern):
   - Connect based on URL scheme
   - Match on pool type for backend-specific queries
   - Use `sqlx::query()` (not `query!()`) for runtime flexibility

---

## 8. Implementation Plan for persea

### Cargo.toml

```toml
[dependencies]
sqlx = { version = "0.8", features = [
    "runtime-tokio",
    "tls-rustls",
    "postgres",
    "mysql",
    "sqlite",
    "any",
    "migrate",
    "macros",
    "uuid",
    "chrono",
    "json",
] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
thiserror = "1"
```

### Module structure

```
src/
  db/
    mod.rs          # DbPool enum, DbKind, connect()
    postgres.rs     # PostgreSQL-specific queries
    mysql.rs        # MySQL-specific queries
    sqlite.rs       # SQLite-specific queries
    common.rs       # Shared query logic
    migrations/
      postgres/     # PostgreSQL-specific DDL
      mysql/        # MySQL-specific DDL
      sqlite/       # SQLite-specific DDL
```

### Migration directories

```
migrations/
  postgres/
    20240101000000_init.sql    # PostgreSQL-specific DDL
  mysql/
    20240101000000_init.sql    # MySQL-specific DDL
  sqlite/
    20240101000000_init.sql    # SQLite-specific DDL
```

### Key decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| ORM vs raw SQL | Raw SQL (SQLx) | Current codebase uses rusqlite; smallest migration path |
| Runtime switching | Enum-based `DbPool` | Full control, no `Any` limitations |
| Compile-time checking | `query!()` for common queries, `query()` for backend-specific | Balance safety and flexibility |
| Connection pooling | sqlx built-in pool | Zero extra deps, sufficient |
| Migration strategy | Per-backend directories | Maximum flexibility |
| Placeholder syntax | `?` for MySQL/SQLite, `$N` for PostgreSQL | Must use backend-specific SQL strings |
| Portable DDL | `TEXT` for PKs, timestamps, enums | Maximizes shared migration code |

### Query strategy

1. **Common queries** (SELECT, basic INSERT/UPDATE) — Write once with `?` placeholders for MySQL/SQLite, `$N` for PostgreSQL. Use `db_dispatch!` macro.

2. **UPSERT queries** — Backend-specific SQL:
   ```rust
   match pool {
       DbPool::Postgres(pg) => sqlx::query("INSERT ... ON CONFLICT ... DO UPDATE ..."),
       DbPool::MySQL(mysql) => sqlx::query("INSERT ... ON DUPLICATE KEY UPDATE ..."),
       DbPool::SQLite(sqlite) => sqlx::query("INSERT ... ON CONFLICT ... DO UPDATE ..."),
   }
   ```

3. **Schema DDL** — Per-backend migration directories.

4. **Type mapping** — Use `TEXT` for UUIDs, timestamps, and enums across all backends. Use `FromRow` for deserialization.

---

## Sources

- SQLx docs.rs: https://docs.rs/sqlx/latest/sqlx/
- SQLx GitHub: https://github.com/launchbadge/sqlx
- SQLx `Any` module: https://docs.rs/sqlx/latest/sqlx/any/
- SQLx migrations: https://docs.rs/sqlx/latest/sqlx/macro.migrate.html
- SeaORM: https://github.com/sea-ql/sea-orm
- sql-web: https://github.com/YinMo19/sql-web
- SQLx compile-time checking: https://mo8it.com/blog/sqlx-interacting-with-databases-in-rust
- SQLx migration issue #1698: https://github.com/launchbadge/sqlx/issues/1698
