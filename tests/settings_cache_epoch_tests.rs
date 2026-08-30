//! HA settings-flag cache coherence test (persea#289).
//!
//! In HA deployments instances share the `system_settings` table but
//! cache the auth flags per process. The shared `settings_epoch` row,
//! bumped by the settings PUT in the same commit as the flag writes, is
//! what makes a peer's toggle visible within one request: the cached
//! read validates its epoch with a single primary-key point read and
//! reloads the flags when it differs.
//!
//! This test installs a real SQLx SQLite pool (the HA detection is "a
//! shared pool is installed", process-global like in production), runs
//! the embedded migrations (which seed the epoch row via
//! `018_settings_epoch.sql`), and simulates a peer instance's PUTs with
//! `settings_put_pool` — the exact commit path `put_settings` uses on
//! the pool side.

use persea::auth::{
    cached_api_keys_enabled, cached_compliance_mode_enabled, init_settings_cache,
    set_settings_cache_epoch, update_settings_cache,
};
use persea::db::{self};
use persea::db_pool::DbPool;

#[tokio::test]
async fn ha_epoch_mismatch_reloads_flags_within_one_read() {
    let dir = std::env::temp_dir().join(format!("persea-289-ha-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Shared backend: real pool + embedded migrations (seeds the epoch row).
    let sqlite_path = dir.join("shared.db");
    let pool = DbPool::connect(&format!("sqlite://{}?mode=rwc", sqlite_path.display()))
        .await
        .unwrap();
    pool.run_migrations().await.unwrap();
    db::set_active_pool(pool).unwrap();
    let pool = db::active_pool().unwrap();

    // The rusqlite handle is a formality in pool mode: store calls route
    // to the shared pool, exactly like in a real HA instance.
    let dummy = db::init_db(&dir.join("admin.db")).unwrap();

    // Migration 018 seeded the shared epoch at 0 on a fresh database.
    let epoch = {
        let d = dummy.clone();
        tokio::task::spawn_blocking(move || db::settings_epoch(&d).unwrap())
            .await
            .unwrap()
    };
    assert_eq!(epoch, 0, "migration 018 must seed settings_epoch = 0");

    // Instance B boots: cache loads flags + epoch from the shared DB.
    init_settings_cache(&dummy);
    assert!(cached_api_keys_enabled(&dummy).await);
    assert!(!cached_compliance_mode_enabled(&dummy).await);

    // Instance A PUTs enable_api_keys=false: flag row + epoch bump in ONE
    // commit (settings_put_pool is the pool side of put_settings).
    let epoch = db::settings_put_pool(
        pool,
        vec![("enable_api_keys".to_string(), "false".to_string())],
    )
    .await
    .unwrap();
    assert_eq!(epoch, 1, "the PUT must bump the epoch");
    let epoch_in_db = {
        let d = dummy.clone();
        tokio::task::spawn_blocking(move || db::settings_epoch(&d).unwrap())
            .await
            .unwrap()
    };
    assert_eq!(epoch_in_db, 1, "the epoch row must read back bumped");

    // Instance B's next cached read detects the mismatch and reloads:
    // the toggle is visible within one request.
    assert!(
        !cached_api_keys_enabled(&dummy).await,
        "the peer toggle must be visible on the next cached read"
    );
    assert!(!cached_compliance_mode_enabled(&dummy).await);

    // Second remote PUT: compliance on, epoch 2.
    let epoch = db::settings_put_pool(
        pool,
        vec![("compliance_mode".to_string(), "true".to_string())],
    )
    .await
    .unwrap();
    assert_eq!(epoch, 2);
    assert!(
        cached_compliance_mode_enabled(&dummy).await,
        "the second peer toggle must be visible within one request"
    );
    assert!(!cached_api_keys_enabled(&dummy).await);

    // Local PUT coherence: the handler bumps + updates the cache (flags
    // via update_settings_cache, epoch via set_settings_cache_epoch) so
    // its own next read passes the freshness check without a reload.
    let epoch = db::settings_put_pool(
        pool,
        vec![("enable_api_keys".to_string(), "true".to_string())],
    )
    .await
    .unwrap();
    assert_eq!(epoch, 3);
    update_settings_cache("enable_api_keys", "true");
    set_settings_cache_epoch(epoch);
    assert!(cached_api_keys_enabled(&dummy).await);

    let _ = std::fs::remove_dir_all(&dir);
}
