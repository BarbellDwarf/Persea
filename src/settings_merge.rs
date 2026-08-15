//! Apply DB-persisted settings (admin settings page) to the running config.
//!
//! The settings API (`src/api/settings.rs`) stores admin-chosen values in the
//! `system_settings` table. This module reads them at startup and overlays
//! them onto the config-file values. Keys without a config equivalent (for
//! example `session_idle_timeout_secs`, which has no `Config` field) are
//! stored and returned by the API but have no startup-config effect; the
//! `enable_*` lockdown toggles are enforced at the point of use (session
//! creation, auth middleware) via `toggle_enabled`/`read_toggle`. Keep this
//! list in sync with `src/api/settings.rs`.

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
    "site_title",
    "logo_url",
    "primary_color",
];

/// Read the `system_settings` table as a map of key → string value.
pub fn load_db_settings(db: &Db) -> rusqlite::Result<Vec<(String, String)>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::settings_load_all_pool(pool)
        });
    }
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

/// Effective `enable_*` lockdown toggle: the DB-persisted value when present,
/// otherwise `default`. Only the literal strings "true"/"false" are honoured;
/// anything else (or absent) falls back to `default`. The settings API only
/// writes these two forms, so the fallback is purely defensive.
pub fn toggle_enabled(settings: &[(String, String)], key: &str, default: bool) -> bool {
    match settings
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
    {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}

/// Read a single `enable_*` toggle straight from the DB. Unset, unreadable,
/// or a missing table → `default`. All toggles default to enabled so existing
/// deployments behave exactly as before an admin flips a switch.
pub fn read_toggle(db: &Db, key: &str, default: bool) -> bool {
    match load_db_settings(db) {
        Ok(settings) => toggle_enabled(&settings, key, default),
        Err(_) => default,
    }
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
                // A TLS section synthesized from DB settings must not flip
                // secure_cookies on: the listener may be plain HTTP (e.g.
                // stale cert paths behind a reverse proxy) and Secure cookies
                // over HTTP break login.
                let tls = config.tls.get_or_insert(crate::config::TlsConfig {
                    cert_path: None,
                    key_path: None,
                    guacd_cert_path: None,
                    secure_cookies: false,
                });
                tls.cert_path = Some(std::path::PathBuf::from(value));
            }
            "tls_key_path" if !value.is_empty() => {
                let tls = config.tls.get_or_insert(crate::config::TlsConfig {
                    cert_path: None,
                    key_path: None,
                    guacd_cert_path: None,
                    secure_cookies: false,
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
                // DB-first storage: flipping Vault on routes
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
            // Branding: overlaid onto the runtime config at
            // startup so the SiteTitle extension, ThemeData (logo + resolved
            // colors served via /api/auth/status) and the login page all pick
            // the saved values up. Takes effect on the next server start.
            "site_title" if !value.is_empty() => config.site_title = value.clone(),
            // logo_url has no is_empty guard: saving "" is how an admin clears
            // a previously-uploaded logo (Some("") renders the placeholder).
            "logo_url" => {
                let theme = config
                    .theme
                    .get_or_insert_with(crate::config::ThemeConfig::default);
                theme.logo_url = Some(value.clone());
            }
            "primary_color" if !value.is_empty() => {
                let theme = config
                    .theme
                    .get_or_insert_with(crate::config::ThemeConfig::default);
                theme.primary_color = Some(value.clone());
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

    #[test]
    fn toggle_enabled_defaults_when_unset() {
        assert!(toggle_enabled(&[], "enable_rdp", true));
        assert!(!toggle_enabled(&[], "enable_rdp", false));
    }

    #[test]
    fn synthesized_tls_defaults_secure_cookies_off() {
        let mut config = Config::default();
        assert!(config.tls.is_none());
        let settings = vec![("tls_cert_path".to_string(), "/tls/cert.pem".to_string())];
        apply_db_settings(&mut config, &settings);
        let tls = config.tls.unwrap();
        assert_eq!(
            tls.cert_path,
            Some(std::path::PathBuf::from("/tls/cert.pem"))
        );
        assert!(
            !tls.secure_cookies,
            "synthesized TLS must not flip Secure cookies on for a plain-HTTP listener"
        );
    }

    #[test]
    fn applies_branding_overrides() {
        let mut config = Config::default();
        assert_eq!(config.site_title, "Persea");
        assert!(config.theme.is_none());
        let settings = vec![
            ("site_title".to_string(), "My Gateway".to_string()),
            ("logo_url".to_string(), "/uploads/logo/logo.png".to_string()),
            ("primary_color".to_string(), "#ff0000".to_string()),
        ];
        apply_db_settings(&mut config, &settings);
        assert_eq!(config.site_title, "My Gateway");
        let theme = config.theme.unwrap();
        assert_eq!(theme.logo_url.as_deref(), Some("/uploads/logo/logo.png"));
        assert_eq!(theme.primary_color.as_deref(), Some("#ff0000"));
    }

    #[test]
    fn branding_empty_values_fall_back_to_config() {
        let mut config = Config::default();
        config.theme = Some(crate::config::ThemeConfig {
            logo_url: Some("/keep.png".into()),
            primary_color: Some("#00ff00".into()),
            ..Default::default()
        });
        let settings = vec![
            ("site_title".to_string(), String::new()),
            ("primary_color".to_string(), String::new()),
        ];
        apply_db_settings(&mut config, &settings);
        assert_eq!(config.site_title, "Persea");
        let theme = config.theme.unwrap();
        assert_eq!(theme.primary_color.as_deref(), Some("#00ff00"));
    }

    #[test]
    fn logo_url_empty_clears_the_logo() {
        let mut config = Config::default();
        config.theme = Some(crate::config::ThemeConfig {
            logo_url: Some("/keep.png".into()),
            ..Default::default()
        });
        let settings = vec![("logo_url".to_string(), String::new())];
        apply_db_settings(&mut config, &settings);
        assert_eq!(config.theme.unwrap().logo_url, Some(String::new()));
    }

    #[test]
    fn toggle_enabled_honours_stored_true_false() {
        let settings = vec![
            ("enable_rdp".to_string(), "true".to_string()),
            ("enable_spice".to_string(), "false".to_string()),
        ];
        assert!(toggle_enabled(&settings, "enable_rdp", true));
        assert!(!toggle_enabled(&settings, "enable_spice", true));
        assert!(toggle_enabled(&settings, "enable_rdp", false));
    }

    #[test]
    fn toggle_enabled_falls_back_on_unexpected_value() {
        let settings = vec![("enable_rdp".to_string(), "yes".to_string())];
        assert!(toggle_enabled(&settings, "enable_rdp", true));
        assert!(!toggle_enabled(&settings, "enable_rdp", false));
    }
}
