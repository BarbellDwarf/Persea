# Multi-Database Backend Support for persea

> **Design record.** This is a historical design document: the research that decided how persea would support MySQL and PostgreSQL in addition to SQLite. It is not a user guide: see the [Deployment Guide](../deployment-guide.md#database-backends) for configuring `db_url`.

## What this document is

persea was built on a single-file SQLite database, which is fine for one server but a poor fit for shared, multi-instance deployments. This document compared the options for supporting MySQL and PostgreSQL alongside SQLite: SQLx, SeaORM, and Diesel, and decided what to build and how.

**What was decided:**

- **Use SQLx** (not SeaORM, not Diesel): raw SQL keeps the code style consistent with the existing codebase, it is async-native (persea already runs on tokio), it ships connection pooling and migrations built in, and its `Any` driver can select the backend at runtime from the connection URL.
- **Enum dispatch, not trait objects**: a `DbPool` enum with one variant per backend (`Postgres`, `MySQL`, `SQLite`). The compiler forces every operation to handle every backend: no dynamic dispatch overhead, no missing arms.
- **Per-backend migration directories**: one schema per backend under `migrations/{mysql,postgres,sqlite}/`, matching Apache Guacamole's own pattern (it keeps separate schema scripts per backend too).
- **Portable SQL where possible, backend-specific where not**: most queries are portable; the divergences (auto-increment, upsert syntax, timestamp functions, case-sensitive `LIKE`) are handled per backend.

**What shipped and the current status:** the `DbPool` enum, per-backend migrations, and startup pool initialisation all shipped. Today the SQLx pool carries the **high-availability subsystem**, the shared session registry and the cross-instance WebSocket tickets (see [High Availability](../high-availability.md)), which is why a shared `db_url` backend is required for HA. The rest of the runtime data (users, connections, auth sessions, audit log, session history) still routes through the original rusqlite admin database, so setting `db_url` does **not** yet migrate that data to MySQL/PostgreSQL. The `[storage] backend` key (`"db"` default or `"vault"`) selects where connection credentials live; DB-stored credentials are AES-256-GCM encrypted.

---

**Date**: 2026-08-01
**Status**: **Partially shipped.** Multi-backend database support via SQLx is implemented: the SQLx pool and per-backend DDL (`migrations/{mysql,postgres,sqlite}/`) ship, and the HA session registry and cross-instance WebSocket tickets run on the pool. The remaining runtime data (session history, audit, address book) still routes through the rusqlite admin DB (`src/db.rs`). This document is kept as a historical record of the original design research.

## Current State

persea uses `rusqlite` with `Arc<Mutex<Connection>>` (synchronous, single-threaded). All SQL is SQLite-specific: `INTEGER PRIMARY KEY AUTOINCREMENT`, `datetime('now')`, `?1` positional params, `ON CONFLICT DO UPDATE`, `TEXT` columns. No async runtime for DB.

**Goal**: Support SQLite (dev/single-node) + MySQL/PostgreSQL (enterprise). SQL must be portable or backend-specific with minimal code duplication.

---

## 1. SQLx: Multi-DB Support

### Feature Flags

```toml
[dependencies]
sqlx = { version = "0.8", features = [
    "runtime-tokio",
    "tls-rustls",
    "sqlite",       # dev/local
    "mysql",        # enterprise option 1
    "postgres",     # enterprise option 2
    "any",          # runtime backend switching
    "macros",       # query! compile-time checking
    "migrate",      # embedded migrations
    "chrono",
    "json",
    "uuid",
] }
```

### Compile-Time Checking for Multi-DB

**The `query!` macro requires a live database at compile time.** This means:
- `cargo sqlx prepare` creates `.sqlx/` metadata files (committed to git)
- CI/CD validates queries without a live DB using cached metadata
- For multi-DB, you'd need **separate `.sqlx` caches** per backend, or use `query_unchecked!` for cross-DB queries

**Cross-DB query strategy**: Write queries using portable SQL (ANSI SQL where possible), use `query_unchecked!` or `query_as!` with runtime validation. For backend-specific syntax, use `sqlx::query()` (runtime, no compile-time check).

### The `Any` Driver

SQLx provides `sqlx::any::AnyPool` / `AnyConnection` which selects the driver at runtime from the URL scheme:

```rust
// Same code, different URL = different backend
let pool = AnyPool::connect("sqlite://file.db").await?;
let pool = AnyPool::connect("postgres://localhost/persea").await?;
let pool = AnyPool::connect("mysql://localhost/persea").await?;
```

**Trade-offs of `Any`:**
- Lose compile-time query checking (can't use `query!`)
- Lose backend-specific type optimizations
- Runtime dispatch overhead (minimal for most apps)
- Good for: startup/config-driven backend selection, testing against SQLite in dev

### Portable SQL Patterns

| Feature | SQLite | MySQL | PostgreSQL |
|---------|--------|-------|------------|
| Auto-increment PK | `INTEGER PRIMARY KEY AUTOINCREMENT` | `INT AUTO_INCREMENT PRIMARY KEY` | `SERIAL PRIMARY KEY` or `GENERATED ALWAYS AS IDENTITY` |
| Current timestamp | `datetime('now')` | `NOW()` or `CURRENT_TIMESTAMP` | `NOW()` or `CURRENT_TIMESTAMP` |
| Boolean type | `INTEGER` (0/1) | `TINYINT(1)` | `BOOLEAN` |
| String concatenation | `\|\|` | `CONCAT()` | `\|\|` |
| UPSERT | `ON CONFLICT DO UPDATE` | `ON DUPLICATE KEY UPDATE` | `ON CONFLICT DO UPDATE` |
| LIMIT/OFFSET | `LIMIT ? OFFSET ?` | `LIMIT ? OFFSET ?` | `LIMIT ? OFFSET ?` |
| Text type | `TEXT` | `VARCHAR(65535)` or `TEXT` | `TEXT` |
| Binary type | `BLOB` | `VARBINARY(255)` | `BYTEA` |
| JSON type | `TEXT` (no native) | `JSON` | `JSONB` |
| `LIKE` case | Case-insensitive default | Case-insensitive default | Case-sensitive default |
| `ILIKE` | N/A (use `LIKE`) | N/A | `ILIKE` |

**Recommendation**: Use `CASE WHEN` or backend-specific patterns for the 5-10 divergent SQL idioms. Most SELECT/INSERT/UPDATE/DELETE is portable.

### Connection Pooling

SQLx's built-in pool (`sqlx::Pool`) handles all three backends:

```rust
use sqlx::postgres::PgPoolOptions;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::sqlite::SqlitePoolOptions;

// All return Pool<Backend>, same API
let pool = PgPoolOptions::new()
    .max_connections(20)
    .connect("postgres://...").await?;
```

For production, also consider:
- **`deadpool`**: More advanced pool features (health checks, timeouts)
- **`bb8`**: Battle-tested, tokio-native
- SQLx's built-in pool is sufficient for most cases

---

## 2. SeaORM: Multi-DB Support

### How It Works

SeaORM is built **on top of SQLx**. Entity definitions are backend-agnostic:

```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub email: String,
    pub name: String,
}
```

**Key advantage**: Business logic is compiled once (not trait-based). Backend differences are handled via `match` statements in the SeaQuery backend. You compile once for Postgres, MySQL, or SQLite; no monomorphization per backend.

### Production Readiness

- **Version 2.0** released January 2026
- Used by RisingWave (production distributed streaming)
- Zed Editor uses SeaORM for collab API (SQLite dev, Postgres prod)
- Active maintainer team, good documentation

### Comparison to SQLx

| Aspect | SQLx | SeaORM |
|--------|------|--------|
| Abstraction level | Raw SQL | Entity/ActiveModel ORM |
| Compile-time checking | `query!` macro (needs DB) | N/A (uses SeaQuery builder) |
| Cross-DB | Manual SQL differences | Auto-generated by SeaQuery |
| Multi-DB effort | Write SQL per backend | Write entities once, backend handled |
| Performance | Faster (direct SQL) | Slight overhead (SeaQuery builder) |
| Learning curve | SQL + macros | Entity model + ActiveModel |
| Migration tool | `sqlx-cli` (SQL files) | `sea-orm-cli` (Rust or SQL) |

### Migration Support

`sea-orm-migration` supports all three backends with Rust code:

```rust
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct CreateUsers;

impl MigrationTrait for CreateUsers {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).integer().not_null().auto_increment().primary_key())
                    .col(ColumnDef::new(Users::Email).string().not_null().unique_key())
                    .to_owned(),
            )
            .await
    }
}
```

SeaORM generates the correct DDL for each backend automatically.

---

## 3. Diesel: Multi-DB Support

### How It Handles Multiple Backends

Diesel uses feature flags + monomorphization:

```toml
[dependencies]
diesel = { version = "2.3", features = ["sqlite", "mysql", "postgres"] }
```

Queries are written in Diesel's DSL, which compiles to backend-specific SQL:

```rust
use diesel::prelude::*;

#[derive(Queryable, Selectable)]
#[diesel(table_name = users)]
struct User {
    id: i32,
    email: String,
}
```

### Compile-Time Implications

- `#[derive(MultiConnection)]` (new in Diesel 2.1+) lets you write queries generic over multiple backends
- Code is monomorphized per backend: each backend gets its own compiled version
- Requires a running database at compile time (similar to SQLx's `query!`)
- **Slower compile times** than SQLx due to generic expansion

### Verdict for persea

**Not recommended** for this use case. Diesel is excellent for single-backend projects with stable schemas, but:
- Requires Diesel's DSL (no raw SQL with compile-time checking)
- Async support requires separate `diesel-async` crate
- Multi-DB requires more boilerplate than SeaORM
- The DSL learning curve is steep for a team used to raw SQL

---

## 4. Apache Guacamole's DB Schema: Dialect Handling

Guacamole supports **MySQL/MariaDB, PostgreSQL, and SQL Server** via separate schema scripts per backend. Key differences:

### Identity / Auto-Increment

| Backend | Syntax |
|---------|--------|
| MySQL | `INT NOT NULL AUTO_INCREMENT` |
| PostgreSQL | `SERIAL` or `GENERATED ALWAYS AS IDENTITY` |
| SQL Server | `INT IDENTITY(1,1)` |

Guacamole maintains **separate DDL files** for each backend, not a single portable schema.

### Text / Binary Types

| Feature | MySQL | PostgreSQL | SQL Server |
|---------|-------|------------|------------|
| Long text | `LONGTEXT` | `TEXT` | `NVARCHAR(MAX)` |
| Binary | `VARBINARY(32)` | `BYTEA` | `VARBINARY(32)` |
| JSON | `TEXT` (JSON stored as text) | `JSONB` | `NVARCHAR(MAX)` |

### Timestamp Handling

- MySQL: `TIMESTAMP` with `DEFAULT CURRENT_TIMESTAMP`
- PostgreSQL: `TIMESTAMP` with `DEFAULT CURRENT_TIMESTAMP`
- SQL Server: `DATETIME2` with `DEFAULT GETDATE()`

### LIKE Behavior

- MySQL: Case-insensitive by default (utf8_general_ci collation)
- PostgreSQL: Case-sensitive by default (use `ILIKE` for case-insensitive)
- Guacamole uses `ILIKE` in PostgreSQL queries where case-insensitivity matters

---

## 5. Multi-DB Migration Patterns

### Option A: SQLx Migrations (Recommended)

Use `sqlx-cli` with per-backend migration directories:

```
migrations/
  postgres/
    001-create-schema.sql
  mysql/
    001-create-schema.sql
  sqlite/
    001-create-schema.sql
```

At startup, select the right directory based on config:

```rust
let migrations_dir = match db_backend {
    "postgres" => "./migrations/postgres",
    "mysql" => "./migrations/mysql",
    "sqlite" => "./migrations/sqlite",
};
sqlx::migrate!(migrations_dir).run(&pool).await?;
```

### Option B: SeaORM Migrations

Write migrations once in Rust code, SeaORM generates correct DDL per backend. Better for keeping a single source of truth.

### Option C: Refinery

Supports `postgres`, `mysql`, `rusqlite`, and `tiberius` (SQL Server). Uses SQL files. Can also work with SQLx via `Config`. Less popular but more mature for multi-DB.

### Recommendation

**SQLx migrations with per-backend directories**: simplest approach, matches Guacamole's own pattern, keeps SQL visible and auditable.

---

## 6. Connection Management

### Current persea Pattern

```rust
pub type Db = Arc<Mutex<Connection>>;  // rusqlite, synchronous
```

### Recommended Pattern with SQLx

```rust
// Generic pool type, same API for all backends
pub type DbPool = sqlx::Pool<sqlx::Any>;

// Or use concrete types for compile-time checking:
pub enum DbPool {
    Postgres(sqlx::PgPool),
    MySQL(sqlx::MySqlPool),
    SQLite(sqlx::SqlitePool),
}

impl DbPool {
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        // Parse URL scheme to select backend
        if url.starts_with("postgres") {
            Ok(Self::Postgres(sqlx::PgPool::connect(url).await?))
        } else if url.starts_with("mysql") {
            Ok(Self::MySQL(sqlx::MySqlPool::connect(url).await?))
        } else {
            Ok(Self::SQLite(sqlx::SqlitePool::connect(url).await?))
        }
    }
}
```

### Pool Configuration

```rust
// Production defaults
let pool = PgPoolOptions::new()
    .max_connections(20)        // tune for workload
    .min_connections(2)
    .acquire_timeout(Duration::from_secs(5))
    .idle_timeout(Duration::from_secs(600))
    .max_lifetime(Duration::from_secs(1800))
    .connect(url).await?;
```

**For SQLite**: Use `SqlitePoolOptions` with `journal_mode(WAL)` and `busy_timeout(5000)`.

---

## 7. Practical Patterns: Real Rust Projects

### Pattern: Enum Dispatch (Recommended for persea)

Rust forum consensus: for a **closed set of backends** (SQLite + MySQL + PostgreSQL), use an **enum** rather than trait objects:

```rust
pub enum Database {
    Postgres { pool: sqlx::PgPool },
    MySQL { pool: sqlx::MySqlPool },
    SQLite { pool: sqlx::SqlitePool },
}

impl Database {
    pub async fn get_user(&self, email: &str) -> Result<User, Error> {
        match self {
            Self::Postgres { pool } => query_postgres_user(pool, email).await,
            Self::MySQL { pool } => query_mysql_user(pool, email).await,
            Self::SQLite { pool } => query_sqlite_user(pool, email).await,
        }
    }
}
```

**Why enum over trait objects:**
- No `Box<dyn>` overhead
- Exhaustive match ensures all backends handle every operation
- Compiler catches missing match arms
- Better cache locality

**If you need extensibility** (e.g., future SQL Server support by downstream forks), use a trait + enum hybrid:

```rust
#[async_trait]
pub trait DatabaseBackend: Send + Sync {
    async fn get_user(&self, email: &str) -> Result<User, Error>;
    // ... other operations
}

pub enum Database {
    Postgres(PgBackend),
    MySQL(MySqlBackend),
    SQLite(SqliteBackend),
}

impl DatabaseBackend for Database {
    async fn get_user(&self, email: &str) -> Result<User, Error> {
        match self {
            Self::Postgres(b) => b.get_user(email).await,
            Self::MySQL(b) => b.get_user(email).await,
            Self::SQLite(b) => b.get_user(email).await,
        }
    }
}
```

### Pattern: Feature-Flag Conditional Compilation

For compile-time backend selection (binary ships with one backend):

```rust
#[cfg(feature = "backend-postgres")]
mod postgres_impl;

#[cfg(feature = "backend-mysql")]
mod mysql_impl;

#[cfg(feature = "backend-sqlite")]
mod sqlite_impl;
```

**Not recommended** for persea; runtime selection via config is better for enterprise flexibility.

### Pattern: Separate Modules Per Backend

```
src/
  db/
    mod.rs          # trait definitions, shared types
    postgres.rs     # Postgres implementation
    mysql.rs        # MySQL implementation
    sqlite.rs       # SQLite implementation (current rusqlite code)
    queries/
      postgres/     # .sql files or inline SQL
      mysql/
      sqlite/
```

This is the cleanest structure for maintaining backend-specific SQL.

---

## 8. MySQL/PostgreSQL Schema Specifics for Auth Tables

### User Tables

| Aspect | SQLite (current) | MySQL | PostgreSQL |
|--------|-----------------|-------|------------|
| PK | `INTEGER PRIMARY KEY AUTOINCREMENT` | `INT NOT NULL AUTO_INCREMENT PRIMARY KEY` | `SERIAL PRIMARY KEY` or `GENERATED ALWAYS AS IDENTITY PRIMARY KEY` |
| Email | `TEXT NOT NULL UNIQUE` | `VARCHAR(255) NOT NULL UNIQUE` | `TEXT NOT NULL UNIQUE` |
| Role | `TEXT NOT NULL DEFAULT 'viewer'` | `VARCHAR(32) NOT NULL DEFAULT 'viewer'` | `TEXT NOT NULL DEFAULT 'viewer'` |
| Boolean (disabled) | `INTEGER NOT NULL DEFAULT 0` | `TINYINT(1) NOT NULL DEFAULT 0` | `BOOLEAN NOT NULL DEFAULT FALSE` |
| Timestamp | `TEXT` (ISO string) | `TIMESTAMP NULL` | `TIMESTAMP NULL` |
| Groups | `TEXT` (comma-separated) | `TEXT` or `VARCHAR(65535)` | `TEXT` |

### Password Hash / API Key Storage

| Backend | Column Type | Notes |
|---------|-------------|-------|
| SQLite | `TEXT` | Hex-encoded SHA-256 |
| MySQL | `VARCHAR(255)` | Hex-encoded, supports up to 255 chars |
| PostgreSQL | `TEXT` | Hex-encoded, unlimited length |

**All backends**: Store hex-encoded hashes as TEXT/VARCHAR. No BLOB/BYTEA needed for hex strings.

### JSON Columns for Metadata

- **SQLite**: Store as `TEXT`, parse in application layer
- **MySQL**: Use `JSON` type (MySQL 5.7+), supports JSON path queries
- **PostgreSQL**: Use `JSONB` type, supports GIN indexing

**Recommendation**: Store metadata as `TEXT`/`VARCHAR` with JSON serialization in the app layer. This is portable and matches Guacamole's approach.

### Timestamp Handling

| Backend | Current Timestamp | Storage |
|---------|------------------|---------|
| SQLite | `datetime('now')` | TEXT (ISO 8601 string) |
| MySQL | `NOW()` or `CURRENT_TIMESTAMP` | TIMESTAMP/DATETIME |
| PostgreSQL | `NOW()` or `CURRENT_TIMESTAMP` | TIMESTAMP |

**Portable approach**: Store timestamps as TEXT (ISO 8601) in all backends. This matches the current SQLite schema and is simplest for serialization. Use `NOW()` in SQL for "current time".

### Full-Text Search (Audit Logs)

- **SQLite**: `LIKE '%term%'` or FTS5 extension
- **MySQL**: `FULLTEXT` index + `MATCH ... AGAINST`
- **PostgreSQL**: `GIN` index + `tsvector`/`plainto_tsquery`

**Recommendation**: For the audit log query patterns in persea (filter by user_email, action, date range), standard `LIKE` / indexed columns are sufficient. Full-text search is overkill for this scale.

---

## Concrete Recommendations for persea

### 1. Library Choice: SQLx

**SQLx** (not SeaORM, not Diesel) because:
- Raw SQL = full control, matches current code style
- Async-native (tokio already in use)
- Built-in pool + migrations
- `Any` driver for runtime backend selection
- Smallest dependency tree of the three

### 2. Architecture

```
src/
  db/
    mod.rs              # DbPool enum, shared types (User, AdminInfo, etc.)
    pool.rs             # Pool creation, config parsing
    sqlite.rs           # SQLite-specific implementations (migrate current code)
    postgres.rs         # PostgreSQL-specific SQL
    mysql.rs            # MySQL-specific SQL
    migrations/
      sqlite/
        001-init.sql
      postgres/
        001-init.sql
      mysql/
        001-init.sql
```

### 3. Migration Strategy

1. **Keep current SQLite schema as-is** (it works, don't break dev)
2. **Create equivalent MySQL/PostgreSQL migration files** using the correct DDL per backend
3. **Embed migrations in binary** via `sqlx::migrate!()`
4. **Select migration directory at startup** based on `DATABASE_URL` scheme

### 4. SQL Portability Approach

For each query in `db.rs`:
- **80% will be portable**: standard SELECT/INSERT/UPDATE/DELETE with `?` params
- **UPSERT differences**: write per-backend or use `sqlx::query()` with runtime dispatch
- **Auto-increment last_insert_id**: `last_insert_rowid()` (SQLite) vs `LAST_INSERT_ID()` (MySQL) vs `RETURNING id` (PostgreSQL)
- **datetime functions**: `datetime('now')` (SQLite) vs `NOW()` (MySQL/Postgres)

### 5. Config

Add to `config.toml`:

```toml
[database]
url = "sqlite:///opt/persea/data/persea.db"     # dev default
# url = "postgres://user:pass@localhost:5432/persea"  # enterprise
# url = "mysql://user:pass@localhost:3306/persea"     # enterprise
max_connections = 10
```

### 6. Build Features

```toml
[features]
default = ["sqlite"]
backend-sqlite = ["sqlx/sqlite"]
backend-postgres = ["sqlx/postgres"]
backend-mysql = ["sqlx/mysql"]
```

Ship default binary with SQLite. Enterprise builds enable `backend-postgres` or `backend-mysql`.

### 7. Migration Path

1. Add `sqlx` dependency alongside `rusqlite` (temporary)
2. Create `src/db/` module structure
3. Port SQLite code to `sqlx::SqlitePool` (async, matches new pattern)
4. Write MySQL/PostgreSQL migrations and query implementations
5. Remove `rusqlite` dependency
6. All code goes through `DbPool` enum

---

## Key Risks

1. **Compile-time checking breaks with `Any`**: use `query_unchecked!` or runtime `query()` for portable queries
2. **SQLite quirks**: WAL mode, busy timeouts, single-writer semantics differ from MySQL/Postgres
3. **Testing**: need CI instances for MySQL + PostgreSQL (GitHub Actions provides both)
4. **Schema drift**: per-backend migrations must be kept in sync manually
5. **UPSERT syntax**: most complex divergence; consider app-level "insert or update" logic

---

## Sources

- SQLx docs: https://docs.rs/sqlx/latest/sqlx
- SQLx GitHub: https://github.com/transact-rs/sqlx
- SeaORM docs: https://www.sea-ql.org/SeaORM/
- SeaORM vs Diesel: https://www.sea-ql.org/SeaORM/docs/internal-design/diesel
- Diesel comparison: https://diesel.rs/compare/compare_diesel
- Guacamole DB auth docs: https://guacamole.apache.org/doc/1.6.0/gug/jdbc-auth.html
- Refinery: https://github.com/rust-db/refinery
- Rust ORMs comparison (2026): https://www.rustfinity.com/blog/rust-orms
