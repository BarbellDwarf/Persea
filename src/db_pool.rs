//! Multi-database backend support via SQLx.
//!
//! Provides `DbPool` — an enum-based pool that supports PostgreSQL, MySQL,
//! and SQLite at runtime. Use this alongside the existing rusqlite `Db` type
//! during migration.

use sqlx::{MySqlPool, PgPool, SqlitePool};
use std::fmt;

/// Supported database backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DbKind {
    Postgres,
    MySQL,
    SQLite,
}

impl fmt::Display for DbKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbKind::Postgres => write!(f, "postgresql"),
            DbKind::MySQL => write!(f, "mysql"),
            DbKind::SQLite => write!(f, "sqlite"),
        }
    }
}

/// A database pool that supports multiple backends at runtime.
///
/// The active backend is determined by the connection URL scheme:
/// - `postgres://` / `postgresql://` → PostgreSQL
/// - `mysql://` → MySQL
/// - `sqlite://` → SQLite
#[derive(Clone)]
pub enum DbPool {
    Postgres(PgPool),
    MySQL(MySqlPool),
    SQLite(SqlitePool),
    /// Placeholder for when no SQLx pool is configured (existing rusqlite-only mode).
    None,
}

impl DbPool {
    /// Return which backend this pool is connected to.
    pub fn kind(&self) -> Option<DbKind> {
        match self {
            DbPool::Postgres(_) => Some(DbKind::Postgres),
            DbPool::MySQL(_) => Some(DbKind::MySQL),
            DbPool::SQLite(_) => Some(DbKind::SQLite),
            DbPool::None => None,
        }
    }

    /// Connect to a database based on the URL scheme.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        if url.starts_with("postgres") {
            let pool = PgPool::connect(url).await?;
            Ok(DbPool::Postgres(pool))
        } else if url.starts_with("mysql") {
            let pool = MySqlPool::connect(url).await?;
            Ok(DbPool::MySQL(pool))
        } else if url.starts_with("sqlite") {
            let pool = SqlitePool::connect(url).await?;
            Ok(DbPool::SQLite(pool))
        } else {
            Err(sqlx::Error::Configuration(
                format!("Unsupported database URL scheme: {}", url).into(),
            ))
        }
    }

    /// Run embedded migrations for the active backend.
    pub async fn run_migrations(&self) -> Result<(), sqlx::migrate::MigrateError> {
        match self {
            DbPool::Postgres(pg) => {
                sqlx::migrate!("./migrations/postgres").run(pg).await?;
            }
            DbPool::MySQL(mysql) => {
                sqlx::migrate!("./migrations/mysql").run(mysql).await?;
            }
            DbPool::SQLite(sqlite) => {
                sqlx::migrate!("./migrations/sqlite").run(sqlite).await?;
            }
            DbPool::None => {}
        }
        Ok(())
    }
}

impl fmt::Debug for DbPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DbPool::Postgres(_) => write!(f, "DbPool::Postgres"),
            DbPool::MySQL(_) => write!(f, "DbPool::MySQL"),
            DbPool::SQLite(_) => write!(f, "DbPool::SQLite"),
            DbPool::None => write!(f, "DbPool::None"),
        }
    }
}

/// Macro to reduce match boilerplate when dispatching queries across backends.
///
/// # Example
/// ```ignore
/// db_dispatch!(pool, |conn| {
///     sqlx::query("INSERT INTO users (id, name) VALUES (?, ?)")
///         .bind(&user.id)
///         .bind(&user.name)
///         .execute(conn)
///         .await?;
/// });
/// ```
#[macro_export]
macro_rules! db_dispatch {
    ($pool:expr, |$conn:ident| $body:expr) => {
        match $pool {
            $crate::db_pool::DbPool::Postgres($conn) => $body,
            $crate::db_pool::DbPool::MySQL($conn) => $body,
            $crate::db_pool::DbPool::SQLite($conn) => $body,
            $crate::db_pool::DbPool::None => panic!("No database pool configured"),
        }
    };
}

/// Macro for backend-specific SQL with different placeholder syntax.
///
/// PostgreSQL uses `$1, $2, $3` while MySQL and SQLite use `?`.
///
/// # Example
/// ```ignore
/// let sql = db_sql!(
///     pool,
///     pg: "INSERT INTO users (id, name) VALUES ($1, $2)",
///     mysql: "INSERT INTO users (id, name) VALUES (?, ?)",
///     sqlite: "INSERT INTO users (id, name) VALUES (?, ?)"
/// );
/// ```
#[macro_export]
macro_rules! db_sql {
    ($pool:expr, pg: $pg:expr, mysql: $mysql:expr, sqlite: $sqlite:expr) => {
        match $pool {
            $crate::db_pool::DbPool::Postgres(_) => $pg,
            $crate::db_pool::DbPool::MySQL(_) => $mysql,
            $crate::db_pool::DbPool::SQLite(_) => $sqlite,
            $crate::db_pool::DbPool::None => panic!("No database pool configured"),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_db_kind_display() {
        assert_eq!(DbKind::Postgres.to_string(), "postgresql");
        assert_eq!(DbKind::MySQL.to_string(), "mysql");
        assert_eq!(DbKind::SQLite.to_string(), "sqlite");
    }

    #[test]
    fn test_db_pool_none_kind() {
        let pool = DbPool::None;
        assert_eq!(pool.kind(), None);
    }
}
