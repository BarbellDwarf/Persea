//! Apply DB-persisted settings (admin settings page) to the running config.
//!
//! The settings API (`src/api/settings.rs`) stores admin-chosen values in the
//! `system_settings` table. This module reads them at startup and overlays
//! them onto the config-file values. Keys without a config equivalent (for
//! example `session_idle_timeout_secs`, which has no `Config` field) are
//! stored and returned by the API but have no runtime effect; keep this list
//! in sync with `src/api/settings.rs`.

use crate::db::Db;

/// All keys the admin settings page can save, with their types.
pub const SETTINGS_KEYS: &[&str] = &[
    "listen_addr",
    "guacd_addr",
    "tls_cert_path",
    "tls_key_path",
    "session_max_duration_secs",
    "max_concurrent_sessions",
    "session_history_retention_days",
    "enable_vdi",
    "vault_enabled",
    "db_only_mode",
];

/// Read the `system_settings` table as a map of key → string value.
pub fn load_db_settings(db: &Db) -> rusqlite::Result<Vec<(String, String)>> {
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS system_settings (
            key        TEXT PRIMARY KEY,
            value      TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )?;
    let mut stmt = conn.prepare("SELECT key, value FROM system_settings")?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    Ok(rows)
}

/// Overlay DB settings onto a config in place. Unknown keys and values that
/// fail to parse are skipped (the API validates on write, so this is a
/// defensive second gate).
pub fn apply_db_settings(config: &mut crate::config::Config, settings: &[(String, String)]) {
    for (key, value) in settings {
        match key.as_str() {
            "listen_addr" if !value.is_empty() => config.listen_addr = value.clone(),
            "guacd_addr" if !value.is_empty() => config.guacd_addr = value.clone(),
            "tls_cert_path" if !value.is_empty() => {
                let tls = config.tls.get_or_insert_with(|| crate::config::TlsConfig {
                    cert_path: None,
                    key_path: None,
                    guacd_cert_path: None,
                    secure_cookies: true,
                });
                tls.cert_path = Some(std::path::PathBuf::from(value));
            }
            "tls_key_path" if !value.is_empty() => {
                let tls = config.tls.get_or_insert_with(|| crate::config::TlsConfig {
                    cert_path: None,
                    key_path: None,
                    guacd_cert_path: None,
                    secure_cookies: true,
                });
                tls.key_path = Some(std::path::PathBuf::from(value));
            }
            "session_max_duration_secs" => {
                if let Ok(v) = value.parse::<u64>() {
                    config.session_max_duration_secs = v;
                }
            }
            "max_concurrent_sessions" => {
                if let Ok(v) = value.parse::<usize>() {
                    config.max_sessions = v;
                }
            }
            "session_history_retention_days" => {
                if let Ok(v) = value.parse::<u32>() {
                    config.session_history_retention_days = v;
                }
            }
            "enable_vdi" => match value.as_str() {
                "true" => {
                    if config.vdi.is_none() {
                        config.vdi = serde_json::from_str::<crate::config::VdiConfig>(
                            r#"{"enabled": true}"#,
                        )
                        .ok();
                    } else if let Some(ref mut vdi) = config.vdi {
                        vdi.enabled = true;
                    }
                }
                _ => {
                    if let Some(ref mut vdi) = config.vdi {
                        vdi.enabled = false;
                    }
                }
            },
            "vault_enabled" => {
                // DB-first storage (ticket 026): flipping Vault on routes
                // credential storage to Vault. Requires a [vault] section —
                // without one there is nowhere to store them.
                if value == "true" {
                    if config.vault.is_some() {
                        let storage =
                            config
                                .storage
                                .get_or_insert_with(|| crate::config::StorageConfig {
                                    backend: "db".into(),
                                    encryption_key: None,
                                });
                        storage.backend = "vault".into();
                    } else {
                        tracing::warn!(
                            "vault_enabled saved but no [vault] section — credentials stay in the DB"
                        );
                    }
                }
            }
            "db_only_mode" => {
                if value == "true" {
                    let storage =
                        config
                            .storage
                            .get_or_insert_with(|| crate::config::StorageConfig {
                                backend: "db".into(),
                                encryption_key: None,
                            });
                    storage.backend = "db".into();
                }
            }
            // No Config equivalent: session_idle_timeout_secs,
            // enable_browser_sessions, enable_proxmox, vault_enabled.
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn applies_scalar_overrides() {
        let mut config = Config::default();
        let settings = vec![
            ("listen_addr".to_string(), "0.0.0.0:9999".to_string()),
            ("session_max_duration_secs".to_string(), "12345".to_string()),
            ("max_concurrent_sessions".to_string(), "42".to_string()),
            (
                "session_history_retention_days".to_string(),
                "7".to_string(),
            ),
        ];
        apply_db_settings(&mut config, &settings);
        assert_eq!(config.listen_addr, "0.0.0.0:9999");
        assert_eq!(config.session_max_duration_secs, 12345);
        assert_eq!(config.max_sessions, 42);
        assert_eq!(config.session_history_retention_days, 7);
    }

    #[test]
    fn toggles_existing_feature_configs() {
        let mut config = Config::default();
        config.vdi = serde_json::from_str::<crate::config::VdiConfig>(r#"{"enabled": false}"#).ok();
        let settings = vec![("enable_vdi".to_string(), "true".to_string())];
        apply_db_settings(&mut config, &settings);
        assert!(config.vdi.unwrap().enabled);
    }

    #[test]
    fn ignores_unknown_and_invalid_values() {
        let mut config = Config::default();
        let original = config.listen_addr.clone();
        let settings = vec![
            ("nonsense_key".to_string(), "x".to_string()),
            ("listen_addr".to_string(), String::new()),
            (
                "session_max_duration_secs".to_string(),
                "not-a-number".to_string(),
            ),
        ];
        apply_db_settings(&mut config, &settings);
        assert_eq!(config.listen_addr, original);
        assert_eq!(config.session_max_duration_secs, 28800);
    }
}
