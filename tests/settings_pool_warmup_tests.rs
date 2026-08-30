//! Pool warm-up regression test (persea#289).
//!
//! The settings-epoch work made worker-runtime pool acquires routine at
//! boot (the epoch point read in `init_settings_cache`) and on every
//! authenticated request. On CI, the first serving-era acquire — the deep
//! health check's `ping_active_pool()` — lost the sqlx cross-runtime
//! acquire race against the connection `run_migrations` left pooled from
//! the boot runtime, burning exactly the 30s `acquire_timeout` and
//! reporting db_pool "down" (backend_tests.rs:356, run 33318449395).
//!
//! `set_active_pool` now warms the pool on the worker runtime at install:
//! it evicts the boot runtime's connection and establishes a fresh one
//! whose entire lifecycle happens on the worker runtime, so serving-era
//! acquires never touch cross-runtime state.
//!
//! This test mirrors the boot sequence (connect + migrate on the test's
//! main runtime, then install) and asserts the deep health check succeeds
//! and stays far below the 30s acquire timeout. The CI race cannot be
//! reproduced deterministically on fast machines (it never lost locally),
//! so the latency bound is the guardrail: any reintroduction of a cold
//! first touch turns this test red on CI hardware.

use std::time::{Duration, Instant};

use persea::db;
use persea::db_pool::DbPool;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn deep_health_ping_after_install_is_fast_and_worker_proven() {
    let dir = std::env::temp_dir().join(format!("persea-289-warm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Mirror main.rs: connect + run migrations on the main runtime, THEN
    // install the pool as the active store.
    let sqlite_path = dir.join("shared.db");
    let pool = DbPool::connect(&format!("sqlite://{}?mode=rwc", sqlite_path.display()))
        .await
        .unwrap();
    pool.run_migrations().await.unwrap();
    db::set_active_pool(pool).unwrap();

    // The boot-time first touch (settings-epoch point read, persea#289)
    // and the deep health check path (4cac536) — in the order a real boot
    // issues them.
    let dummy = db::init_db(&dir.join("admin.db")).unwrap();
    let t0 = Instant::now();
    let d = dummy.clone();
    let epoch = tokio::task::spawn_blocking(move || db::settings_epoch(&d))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(epoch, 0, "a fresh database reads as epoch 0");

    let t1 = Instant::now();
    db::ping_active_pool()
        .unwrap_or_else(|e| panic!("deep health ping failed after warm install: {e}"));
    let first_ping = t1.elapsed();

    let t2 = Instant::now();
    db::ping_active_pool().unwrap_or_else(|e| panic!("steady-state deep health ping failed: {e}"));
    let second_ping = t2.elapsed();

    // The regression burned exactly the 30s sqlx acquire_timeout. The warm
    // path is single-digit milliseconds; 5s leaves room for a slow CI box
    // while still being far below any acquire-timeout stall.
    let bound = Duration::from_secs(5);
    assert!(
        first_ping < bound,
        "first deep ping took {first_ping:?} — cold-touch race is back"
    );
    assert!(
        second_ping < bound,
        "steady-state deep ping took {second_ping:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
