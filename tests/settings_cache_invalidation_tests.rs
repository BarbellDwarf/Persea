//! Single-instance settings-flag cache invalidation test (persea#289).
//!
//! The auth middleware caches `enable_api_keys` and `compliance_mode`
//! per process (persea#276). In single-instance mode (no shared SQLx
//! pool) the cache is the only view: the settings PUT handler updates it
//! directly after its commit, so `update_settings_cache` must flip the
//! cached readers instantly and with zero `system_settings` reads.
//!
//! The zero-read property is proven by dropping the `system_settings`
//! table after the cached write: any full-table read would recreate the
//! table (empty) and fall back to the legacy defaults (api keys enabled,
//! compliance off), failing the asserts.

use persea::auth::{
    cached_api_keys_enabled, cached_compliance_mode_enabled, init_settings_cache,
    update_settings_cache,
};
use persea::db;

#[tokio::test]
async fn single_instance_flag_cache_updates_instantly_without_db_reads() {
    let db = db::init_db(std::path::Path::new(":memory:")).unwrap();

    // Fresh DB, no system_settings table yet: defaults, epoch 0.
    init_settings_cache(&db);
    assert!(
        cached_api_keys_enabled(&db).await,
        "unset enable_api_keys defaults to enabled"
    );
    assert!(
        !cached_compliance_mode_enabled(&db).await,
        "unset compliance_mode defaults to off"
    );

    // The PUT handler's invalidation: cached readers flip immediately.
    update_settings_cache("enable_api_keys", "false");
    update_settings_cache("compliance_mode", "true");
    assert!(!cached_api_keys_enabled(&db).await);
    assert!(cached_compliance_mode_enabled(&db).await);

    // ...with zero DB reads: remove the backing table entirely. A reader
    // that still queried it would fall back to the defaults and flip the
    // values back (enabled / off), failing these asserts.
    db.lock()
        .unwrap()
        .execute_batch("DROP TABLE IF EXISTS system_settings")
        .unwrap();
    assert!(
        !cached_api_keys_enabled(&db).await,
        "cached enable_api_keys must survive with no DB behind it"
    );
    assert!(
        cached_compliance_mode_enabled(&db).await,
        "cached compliance_mode must survive with no DB behind it"
    );
}
