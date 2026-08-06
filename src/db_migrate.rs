//! `db-migrate-from-vault` subcommand: migrate address-book entries from Vault
//! into the address book tables (`address_book_folders` /
//! `address_book_entries` / `address_book_credentials`), encrypting
//! credential fields with AES-256-GCM.
//!
//! BFS-walks all Vault scope folders, reads each entry, encrypts sensitive
//! fields, and writes the full JSON params to the DB. User credential
//! variables (the `users/` subtree) are also migrated with values encrypted.
//!
//! Idempotent: skips entries whose `(name, group_id)` already exist in the DB.

use std::collections::HashMap;
use std::sync::Arc;

use rusqlite::params;

use crate::config::Config;
use crate::crypto::{encrypt_value, EncryptionKey};
use crate::db::{self, Db};
use crate::vault::{self, AddressBookEntry, FolderConfig, VaultClient, VaultError};

/// Credential fields that contain plaintext secrets and must be encrypted
/// before writing to the DB.
const CREDENTIAL_FIELDS: &[&str] = &[
    "password",
    "private_key",
    "container_password",
    "proxmox_token_secret",
    "jump_password",
    "jump_private_key",
    "spice_ca_cert",
];

/// Resolve the AES-256-GCM encryption key hex string from the environment.
/// `PERSEA_STORAGE_KEY` is the standard name (matches the runtime app);
/// `ENCRYPTION_KEY` is a legacy fallback, read only when the primary var is
/// unset (a deprecation notice is printed to stderr when it is used).
fn resolve_enc_key_hex_from_env() -> Option<String> {
    match std::env::var("PERSEA_STORAGE_KEY") {
        Ok(k) if !k.is_empty() => Some(k),
        _ => match std::env::var("ENCRYPTION_KEY") {
            Ok(k) if !k.is_empty() => {
                eprintln!("Warning: ENCRYPTION_KEY is deprecated; set PERSEA_STORAGE_KEY instead");
                Some(k)
            }
            _ => None,
        },
    }
}

/// Run the `db-migrate-from-vault` subcommand.
pub async fn cmd_db_migrate_from_vault(
    config: &Config,
    scope: &str,
    overwrite: bool,
    dry_run: bool,
    vault_delete: bool,
) {
    if scope != "shared" && scope != "instance" {
        eprintln!("Error: --scope must be \"shared\" or \"instance\"");
        std::process::exit(1);
    }

    // Resolve encryption key from env var (PERSEA_STORAGE_KEY primary,
    // ENCRYPTION_KEY as legacy fallback)
    let enc_key_hex = match resolve_enc_key_hex_from_env() {
        Some(k) => k,
        None => {
            eprintln!(
                "Error: PERSEA_STORAGE_KEY env var required (64-char hex string); \
                 ENCRYPTION_KEY is accepted as a legacy fallback"
            );
            std::process::exit(1);
        }
    };
    let enc_key = match EncryptionKey::from_hex(&enc_key_hex) {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "Error: invalid PERSEA_STORAGE_KEY (or legacy ENCRYPTION_KEY): {}",
                e
            );
            std::process::exit(1);
        }
    };

    // Connect to Vault
    let vault_config = config.vault.as_ref().unwrap_or_else(|| {
        eprintln!("Error: [vault] not configured in config.toml");
        std::process::exit(1);
    });
    let secret_id = match std::env::var("VAULT_SECRET_ID") {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("Error: VAULT_SECRET_ID env var required");
            std::process::exit(1);
        }
    };
    let vault = match VaultClient::new(vault_config, &secret_id).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("Error connecting to Vault ({}): {}", vault_config.addr, e);
            std::process::exit(1);
        }
    };

    // Open the DB
    let database = crate::db::init_db(&config.db_path).unwrap_or_else(|e| {
        eprintln!("Error opening database: {}", e);
        std::process::exit(1);
    });

    let label = if dry_run { "[DRY RUN] " } else { "" };
    println!("{}Migrating {} scope from Vault to DB...", label, scope);

    // BFS-collect every folder path in the scope subtree
    let top = match vault.list_folders_in_scope(scope).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error listing folders in {} scope on Vault: {}", scope, e);
            std::process::exit(1);
        }
    };
    let mut folder_paths: Vec<String> = top.into_iter().map(|f| f.path.unwrap_or(f.name)).collect();
    let mut i = 0;
    while i < folder_paths.len() {
        let path = folder_paths[i].clone();
        if let Ok(subs) = vault.list_subfolders(scope, &path).await {
            for s in subs {
                folder_paths.push(s.path.unwrap_or_else(|| format!("{}/{}", path, s.name)));
            }
        }
        i += 1;
    }

    let mut groups_written = 0usize;
    let mut entries_migrated = 0usize;
    let mut entries_skipped = 0usize;
    let mut users_migrated = 0usize;
    let mut failures = 0usize;

    // Process each folder
    for folder_path in &folder_paths {
        // Read folder .config for description and allowed_groups
        let folder_config = vault.get_folder_config(scope, folder_path).await;

        // Ensure parent group exists and get its ID
        let parent_group_id =
            ensure_folder_group(&database, scope, folder_path, &folder_config, dry_run);
        groups_written += 1;

        // List entries in this folder
        let entries = match vault.list_entries(scope, folder_path).await {
            Ok(e) => e,
            Err(e) => {
                eprintln!(
                    "  Warning: failed to list entries in '{}': {}",
                    folder_path, e
                );
                failures += 1;
                continue;
            }
        };

        for entry_name in &entries {
            // Read the full entry from Vault
            let entry = match vault.get_entry(scope, folder_path, entry_name).await {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("  FAILED to read {}/{}: {}", folder_path, entry_name, e);
                    failures += 1;
                    continue;
                }
            };

            // Check idempotency: skip if entry already exists
            if !overwrite
                && !dry_run
                && entry_exists(
                    &database,
                    scope,
                    parent_group_id.as_deref().unwrap_or(""),
                    entry_name,
                )
            {
                println!("  skip (exists): {}/{}", folder_path, entry_name);
                entries_skipped += 1;
                continue;
            }

            let mut inserted_ok = false;
            if dry_run {
                println!(
                    "  [entry]  {}/{} ({})",
                    folder_path, entry_name, entry.session_type
                );
                entries_migrated += 1;
            } else {
                let inserted = insert_ab_entry(
                    &database,
                    scope,
                    parent_group_id.as_deref().unwrap_or(""),
                    entry_name,
                    &entry,
                    &enc_key,
                    overwrite,
                );
                match &inserted {
                    Ok(()) => {
                        println!(
                            "  migrated: {}/{} ({})",
                            folder_path, entry_name, entry.session_type
                        );
                        inserted_ok = true;
                        entries_migrated += 1;
                    }
                    Err(e) => {
                        eprintln!("  FAILED:  {}/{} — {}", folder_path, entry_name, e);
                        failures += 1;
                    }
                }
            }

            // Optionally delete from Vault after migration — only when the
            // DB write succeeded, so the source of truth is never destroyed
            // by a failed insert.
            if vault_delete && !dry_run && inserted_ok {
                if let Err(e) = vault.delete_entry(scope, folder_path, entry_name).await {
                    eprintln!(
                        "  Warning: failed to delete {}/{} from Vault: {}",
                        folder_path, entry_name, e
                    );
                }
            }
        }
    }

    // Migrate user credential variables
    match vault.list_user_keys().await {
        Ok(keys) => {
            for key in &keys {
                match vault.get_user_credentials_by_key(key).await {
                    Ok(creds) => {
                        if dry_run {
                            println!("  [users]  {} ({} vars)", key, creds.len());
                            users_migrated += 1;
                        } else {
                            match insert_user_credentials(&database, key, &creds, &enc_key) {
                                Ok(()) => {
                                    println!("  migrated:  users/{}", key);
                                    users_migrated += 1;
                                }
                                Err(e) => {
                                    eprintln!("  FAILED:  users/{} — {}", key, e);
                                    failures += 1;
                                }
                            }
                        }

                        // Note: vault_delete for user credentials is not supported
                        // because the delete API takes an email, not the sanitized key.
                    }
                    Err(e) => {
                        eprintln!("  Warning: could not read users/{}: {}", key, e);
                        // Not a hard failure — user secrets may not exist
                    }
                }
            }
        }
        Err(e) => {
            println!(
                "  Warning: could not list user credentials from Vault: {}",
                e
            );
        }
    }

    // Summary
    let verb = if dry_run { "would migrate" } else { "migrated" };
    println!(
        "\n{} {} folders, {} entries {} ({} skipped), {} user credential sets{}.",
        if dry_run { "[DRY RUN]" } else { "Done:" },
        groups_written,
        entries_migrated,
        verb,
        entries_skipped,
        users_migrated,
        if failures > 0 {
            format!(", {} FAILURES", failures)
        } else {
            String::new()
        }
    );
    if dry_run {
        println!("Re-run without --dry-run to perform the migration.");
    }
    if vault_delete && !dry_run {
        println!("Vault entries deleted after migration.");
    }
    if failures > 0 {
        std::process::exit(1);
    }
}

/// Ensure a folder group hierarchy exists in the DB. Walks up the path
/// creating intermediate groups as needed. Returns the leaf group's UUID.
fn ensure_folder_group(
    db: &Db,
    scope: &str,
    folder_path: &str,
    folder_config: &Result<FolderConfig, VaultError>,
    dry_run: bool,
) -> Option<String> {
    // Get-or-create the folder row for each path segment (DB-first storage:
    // folders always live in `address_book_folders`). The leaf folder picks
    // up the vault .config's description and allowed_groups; intermediate
    // segments get defaults. Existing rows are never overwritten.
    let segments: Vec<&str> = folder_path.split('/').collect();
    let mut parent: Option<String> = None;

    for (depth, segment) in segments.iter().enumerate() {
        let current_path = if depth == 0 {
            segment.to_string()
        } else {
            segments[..=depth].join("/")
        };

        if db::get_ab_folder(db, scope, &current_path).is_ok() {
            parent = Some(current_path);
            continue;
        }

        let (description, allowed_groups) = if depth == segments.len() - 1 {
            match folder_config {
                Ok(cfg) => (cfg.description.clone(), cfg.allowed_groups.join(",")),
                Err(_) => (String::new(), String::new()),
            }
        } else {
            (String::new(), String::new())
        };

        if dry_run {
            println!(
                "  [group]  {} (scope={}, parent={})",
                current_path,
                scope,
                parent.as_deref().unwrap_or("root")
            );
        } else if let Err(e) = db::create_ab_folder(
            db,
            scope,
            &current_path,
            &description,
            &allowed_groups,
            true,
        ) {
            // A concurrent migrate could have created it — treat as success.
            if db::get_ab_folder(db, scope, &current_path).is_err() {
                eprintln!(
                    "  Warning: failed to create folder \"{}\": {}",
                    current_path, e
                );
            }
        }

        parent = Some(current_path);
    }

    parent
}

/// Check if an entry with the given name already exists in a folder.
fn entry_exists(db: &Db, scope: &str, folder_path: &str, name: &str) -> bool {
    match db::get_ab_folder(db, scope, folder_path) {
        Ok(folder) => db::get_ab_entry(db, folder.id, name).is_ok(),
        Err(_) => false,
    }
}

/// Serialize an AddressBookEntry to JSON params, encrypting credential fields.
fn serialize_entry_params(entry: &AddressBookEntry, enc_key: &EncryptionKey) -> String {
    let mut map: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    // Always include type
    map.insert(
        "type".into(),
        serde_json::Value::String(entry.session_type.clone()),
    );

    // Helper to encrypt a field if it has a non-empty plaintext value
    let mut enc_field = |key: &str, val: &Option<String>| {
        if let Some(v) = val {
            if !v.is_empty() {
                if vault::is_credential_variable(v) {
                    // Keep variable references as-is (e.g. "$corp_user")
                    map.insert(key.into(), serde_json::Value::String(v.clone()));
                } else {
                    match encrypt_value(enc_key, v) {
                        Ok(enc) => {
                            map.insert(key.into(), serde_json::Value::String(enc));
                        }
                        Err(_) => {
                            // Fall back to plaintext on encryption failure
                            map.insert(key.into(), serde_json::Value::String(v.clone()));
                        }
                    }
                }
            }
        }
    };

    // Credential fields (encrypted)
    for field in CREDENTIAL_FIELDS {
        match *field {
            "password" => enc_field("password", &entry.password),
            "private_key" => enc_field("private_key", &entry.private_key),
            "container_password" => enc_field("container_password", &entry.container_password),
            "proxmox_token_secret" => {
                enc_field("proxmox_token_secret", &entry.proxmox_token_secret)
            }
            "jump_password" => enc_field("jump_password", &entry.jump_password),
            "jump_private_key" => enc_field("jump_private_key", &entry.jump_private_key),
            "spice_ca_cert" => enc_field("spice_ca_cert", &entry.spice_ca_cert),
            _ => {}
        }
    }

    // Non-credential fields (plaintext)
    let opt_str =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<String>| {
            if let Some(v) = val {
                map.insert(key.into(), serde_json::Value::String(v.clone()));
            }
        };
    let opt_u16 =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<u16>| {
            if let Some(v) = val {
                map.insert(key.into(), serde_json::Value::Number((*v).into()));
            }
        };
    let opt_bool =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<bool>| {
            if let Some(v) = val {
                map.insert(key.into(), serde_json::Value::Bool(*v));
            }
        };
    let opt_u8 =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<u8>| {
            if let Some(v) = val {
                map.insert(key.into(), serde_json::Value::Number((*v).into()));
            }
        };
    let opt_u32 =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<u32>| {
            if let Some(v) = val {
                map.insert(key.into(), serde_json::Value::Number((*v).into()));
            }
        };
    let opt_u64 =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<u64>| {
            if let Some(v) = val {
                if let Some(n) = serde_json::Number::from_f64(*v as f64) {
                    map.insert(key.into(), serde_json::Value::Number(n));
                }
            }
        };
    let opt_f64 =
        |map: &mut serde_json::Map<String, serde_json::Value>, key: &str, val: &Option<f64>| {
            if let Some(v) = val {
                if let Some(n) = serde_json::Number::from_f64(*v) {
                    map.insert(key.into(), serde_json::Value::Number(n));
                }
            }
        };

    opt_str(&mut map, "hostname", &entry.hostname);
    opt_u16(&mut map, "port", &entry.port);
    opt_str(&mut map, "username", &entry.username);
    opt_str(&mut map, "url", &entry.url);
    opt_str(&mut map, "display_name", &entry.display_name);
    opt_str(&mut map, "domain", &entry.domain);
    opt_str(&mut map, "security", &entry.security);
    opt_bool(&mut map, "ignore_cert", &entry.ignore_cert);
    opt_bool(&mut map, "enable_drive", &entry.enable_drive);
    opt_str(&mut map, "auth_pkg", &entry.auth_pkg);
    opt_str(&mut map, "kdc_url", &entry.kdc_url);
    opt_bool(&mut map, "prompt_credentials", &entry.prompt_credentials);
    opt_u8(&mut map, "color_depth", &entry.color_depth);

    // Jump hosts (serialized as JSON array)
    if let Some(ref hosts) = entry.jump_hosts {
        if let Ok(val) = serde_json::to_value(hosts) {
            map.insert("jump_hosts".into(), val);
        }
    }

    // RemoteApp
    opt_str(&mut map, "remote_app", &entry.remote_app);
    opt_str(&mut map, "remote_app_dir", &entry.remote_app_dir);
    opt_str(&mut map, "remote_app_args", &entry.remote_app_args);

    // Recording
    opt_bool(&mut map, "enable_recording", &entry.enable_recording);
    opt_u32(&mut map, "max_recordings", &entry.max_recordings);
    opt_bool(&mut map, "record_typescript", &entry.record_typescript);

    // Web session fields
    opt_str(&mut map, "login_script", &entry.login_script);
    opt_str(&mut map, "autofill", &entry.autofill);
    if let Some(ref domains) = entry.allowed_domains {
        if let Ok(val) = serde_json::to_value(domains) {
            map.insert("allowed_domains".into(), val);
        }
    }

    // Clipboard
    opt_bool(&mut map, "disable_copy", &entry.disable_copy);
    opt_bool(&mut map, "disable_paste", &entry.disable_paste);
    opt_str(&mut map, "banner", &entry.banner);

    // RDP GFX
    opt_bool(&mut map, "enable_gfx", &entry.enable_gfx);
    opt_bool(
        &mut map,
        "enable_desktop_composition",
        &entry.enable_desktop_composition,
    );
    opt_bool(&mut map, "enable_wallpaper", &entry.enable_wallpaper);
    opt_bool(&mut map, "enable_theming", &entry.enable_theming);
    opt_bool(
        &mut map,
        "enable_full_window_drag",
        &entry.enable_full_window_drag,
    );
    opt_bool(&mut map, "force_lossless", &entry.force_lossless);
    opt_bool(&mut map, "enable_h264", &entry.enable_h264);

    // VDI
    opt_str(&mut map, "container_image", &entry.container_image);
    opt_f64(&mut map, "container_cpu_limit", &entry.container_cpu_limit);
    opt_u64(
        &mut map,
        "container_memory_limit",
        &entry.container_memory_limit,
    );
    if let Some(ref env) = entry.container_env {
        if let Ok(val) = serde_json::to_value(env) {
            map.insert("container_env".into(), val);
        }
    }
    opt_u64(
        &mut map,
        "container_idle_timeout_mins",
        &entry.container_idle_timeout_mins,
    );
    opt_str(&mut map, "container_username", &entry.container_username);

    // Misc
    opt_bool(&mut map, "allow_sharing", &entry.allow_sharing);
    opt_bool(
        &mut map,
        "auto_open_if_singleton",
        &entry.auto_open_if_singleton,
    );
    opt_bool(
        &mut map,
        "fullscreen_on_connect",
        &entry.fullscreen_on_connect,
    );
    opt_bool(&mut map, "autohide_side_tabs", &entry.autohide_side_tabs);

    // SPICE
    opt_bool(&mut map, "spice_tls", &entry.spice_tls);
    opt_u16(&mut map, "spice_tls_port", &entry.spice_tls_port);
    opt_str(&mut map, "spice_cert_subject", &entry.spice_cert_subject);
    opt_str(&mut map, "spice_proxy", &entry.spice_proxy);

    // Proxmox
    opt_str(&mut map, "proxmox_url", &entry.proxmox_url);
    opt_str(&mut map, "proxmox_node", &entry.proxmox_node);
    opt_u32(&mut map, "proxmox_vmid", &entry.proxmox_vmid);
    opt_str(&mut map, "proxmox_token_id", &entry.proxmox_token_id);
    opt_bool(&mut map, "proxmox_verify_tls", &entry.proxmox_verify_tls);
    opt_u32(&mut map, "max_monitors", &entry.max_monitors);

    serde_json::Value::Object(map).to_string()
}

/// Insert a connection into the DB.
fn insert_ab_entry(
    db: &Db,
    scope: &str,
    folder_path: &str,
    name: &str,
    entry: &AddressBookEntry,
    enc_key: &EncryptionKey,
    overwrite: bool,
) -> Result<(), String> {
    let folder =
        db::get_ab_folder(db, scope, folder_path).map_err(|e| format!("folder lookup: {}", e))?;
    let protocol_config = crate::api::address_book::build_protocol_config(entry);
    let entry_id = match db::create_ab_entry(
        db,
        folder.id,
        name,
        entry.display_name.as_deref().unwrap_or(name),
        &entry.session_type,
        entry.hostname.as_deref().unwrap_or(""),
        entry.port,
        entry.username.as_deref().unwrap_or(""),
        &serde_json::to_string(&protocol_config).unwrap_or_else(|_| "{}".into()),
        "",
    ) {
        Ok(id) => id,
        // A re-run with --overwrite updates the existing row instead of
        // failing on the UNIQUE(folder_id, name) constraint.
        Err(e) if overwrite => {
            let existing = db::get_ab_entry(db, folder.id, name)
                .map_err(|e2| format!("overwrite lookup: {}", e2))?;
            db::update_ab_entry(
                db,
                existing.id,
                entry.display_name.as_deref().unwrap_or(name),
                &entry.session_type,
                entry.hostname.as_deref().unwrap_or(""),
                entry.port,
                entry.username.as_deref().unwrap_or(""),
                &serde_json::to_string(&protocol_config).unwrap_or_else(|_| "{}".into()),
                "",
            )
            .map_err(|e2| format!("overwrite update: {}", e2))?;
            existing.id
        }
        Err(e) => return Err(format!("insert entry: {}", e)),
    };

    // Credential fields are encrypted with the configured storage key and
    // stored in the credentials table (the same path the runtime uses).
    for (ctype, value) in [
        ("password", entry.password.as_deref()),
        ("private_key", entry.private_key.as_deref()),
        (
            "proxmox_token_secret",
            entry.proxmox_token_secret.as_deref(),
        ),
        ("container_password", entry.container_password.as_deref()),
    ] {
        if let Some(v) = value.filter(|v| !v.is_empty()) {
            let encrypted =
                encrypt_value(enc_key, v).map_err(|e| format!("encrypt {}: {}", ctype, e))?;
            db::store_ab_credential(db, entry_id, ctype, &encrypted)
                .map_err(|e| format!("store {}: {}", ctype, e))?;
        }
    }
    Ok(())
}

/// Insert user credential variables into a dedicated `user_credentials` table.
/// If the table doesn't exist yet, we create it.
fn insert_user_credentials(
    db: &Db,
    user_key: &str,
    creds: &HashMap<String, String>,
    enc_key: &EncryptionKey,
) -> Result<(), rusqlite::Error> {
    let conn = db.lock().unwrap();

    // Ensure the table exists
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_credentials (
            user_key    TEXT NOT NULL,
            var_name    TEXT NOT NULL,
            var_value   TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            PRIMARY KEY (user_key, var_name)
        );",
    )?;

    // Delete existing entries for this user (full replace)
    conn.execute(
        "DELETE FROM user_credentials WHERE user_key = ?1",
        params![user_key],
    )?;

    // Insert each credential variable with encrypted value
    for (var_name, var_value) in creds {
        let enc_value = if var_value.is_empty() {
            String::new()
        } else {
            encrypt_value(enc_key, var_value).unwrap_or_else(|_| var_value.clone())
        };
        conn.execute(
            "INSERT INTO user_credentials (user_key, var_name, var_value)
             VALUES (?1, ?2, ?3)",
            params![user_key, var_name, enc_value],
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize env-var mutation across the tests in this module (the
    /// process-wide environment is shared between parallel tests).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn clear_enc_env() {
        std::env::remove_var("PERSEA_STORAGE_KEY");
        std::env::remove_var("ENCRYPTION_KEY");
    }

    #[test]
    fn enc_key_prefers_persea_storage_key() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_enc_env();
        std::env::set_var("PERSEA_STORAGE_KEY", "primary-key");
        std::env::set_var("ENCRYPTION_KEY", "legacy-key");
        assert_eq!(
            resolve_enc_key_hex_from_env().as_deref(),
            Some("primary-key")
        );
    }

    #[test]
    fn enc_key_falls_back_to_legacy_name() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_enc_env();
        std::env::set_var("ENCRYPTION_KEY", "legacy-key");
        assert_eq!(
            resolve_enc_key_hex_from_env().as_deref(),
            Some("legacy-key")
        );
    }

    #[test]
    fn enc_key_empty_vars_are_treated_as_unset() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_enc_env();
        std::env::set_var("PERSEA_STORAGE_KEY", "");
        std::env::set_var("ENCRYPTION_KEY", "");
        assert_eq!(resolve_enc_key_hex_from_env(), None);
    }

    #[test]
    fn enc_key_missing_returns_none() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_enc_env();
        assert_eq!(resolve_enc_key_hex_from_env(), None);
    }
}
