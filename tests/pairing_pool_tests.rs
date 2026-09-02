//! Pairing insert routing through the db worker runtime (persea#319).
//!
//! `insert_pairing` used to await the SQLx pool query directly on the axum
//! runtime, which risks the sqlx cross-runtime acquire race (lost readiness
//! wakeup, observed as a full 30s `acquire_timeout` stall). The insert now
//! goes through `db::insert_active_pairing`, which dispatches on the
//! dedicated persea-db-worker thread and reports `Ok(false)` when no pool
//! store is active so the caller falls back to the legacy SQLite path.
//!
//! The worker routing itself has no deterministic seam (a direct await also
//! succeeds on a fast machine, and `pool_call` is synchronous from the
//! caller's side), so the assertions pin the observable contract instead:
//! the fallback sentinel before a pool is installed, a successful insert
//! via the pool store once installed, and the row landing in the pool
//! store's database.
//!
//! This lives in its own test binary because the pool store is a
//! process-global `OnceLock`: installing it here must not flip the
//! pairing flow tests (which exercise the SQLite fallback) onto the pool
//! path, and the warm-up test binary already consumes its own install.

use persea::db;
use persea::db_pool::DbPool;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_insert_uses_pool_store_when_active_and_reports_fallback_when_not() {
    // No pool store installed yet: the wrapper must hand back the fallback
    // sentinel instead of erroring or touching any database.
    let sentinel = db::insert_active_pairing(
        "pairing-route-sentinel",
        "sentinel-box",
        "2030-01-01 00:00:00",
    );
    assert!(
        matches!(sentinel, Ok(false)),
        "expected the no-pool fallback sentinel, got {sentinel:?}"
    );

    // Mirror main.rs: connect + run migrations on the test's main runtime,
    // THEN install the pool as the active store (spawns the db worker).
    let dir = std::env::temp_dir().join(format!("persea-319-pairing-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sqlite_path = dir.join("pairing.db");
    let pool = DbPool::connect(&format!("sqlite://{}?mode=rwc", sqlite_path.display()))
        .await
        .unwrap();
    pool.run_migrations().await.unwrap();
    db::set_active_pool(pool).unwrap();

    // Pool store active: the insert must succeed through the worker.
    let inserted =
        db::insert_active_pairing("pairing-route-hash", "route-box", "2030-01-01 00:00:00");
    assert!(
        matches!(inserted, Ok(true)),
        "pool-store insert failed: {inserted:?}"
    );

    // The row landed in the pool store's database (read back with rusqlite
    // through the same file the SQLx SQLite pool owns).
    let conn = rusqlite::Connection::open(&sqlite_path).unwrap();
    let (hostname, expires_at): (String, String) = conn
        .query_row(
            "SELECT hostname, expires_at FROM desktop_pairings WHERE code_hash = ?1",
            rusqlite::params!["pairing-route-hash"],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(hostname, "route-box");
    assert_eq!(expires_at, "2030-01-01 00:00:00");

    let _ = std::fs::remove_dir_all(&dir);
}
