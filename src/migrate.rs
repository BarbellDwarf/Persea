//! `vault-migrate` subcommand: copy an address-book scope subtree between
//! configured Vault backends, for the multi-Vault DR split.
//!
//! The scope→path layout is identical in every backend, so migration is a
//! server-to-server copy (same scope/folder/entry identity), not a path
//! rewrite: reading `scope=shared, folder=Foo, entry=Bar` from the source and
//! writing it back with the same coordinates maps `<src_base>/shared/Foo/Bar`
//! to `<dst_base>/shared/Foo/Bar`, each client applying its own mount /
//! base_path / instance_name. Entries AND the `.config` sentinel at every
//! folder level are copied (the latter carries allowed_groups /
//! inherit_from_parent — dropping it would silently lose a folder's ACL).

use std::sync::Arc;

use crate::config::Config;
use crate::vault::{VaultClient, VaultError};

/// Run the `vault-migrate` subcommand.
#[allow(clippy::too_many_arguments)]
pub async fn cmd_vault_migrate(
    config: &Config,
    scope: &str,
    from: &str,
    to: &str,
    include_users: bool,
    overwrite: bool,
    dry_run: bool,
) {
    if scope != "shared" && scope != "instance" {
        eprintln!("Error: --scope must be \"shared\" or \"instance\"");
        std::process::exit(1);
    }
    if from == to {
        eprintln!("Error: --from and --to must name different backends");
        std::process::exit(1);
    }

    let src = connect_named(config, from).await;
    let dst = connect_named(config, to).await;

    if dry_run {
        println!(
            "[DRY RUN] Copy {} scope: {} -> {} (nothing will be written)\n",
            scope, from, to
        );
    } else {
        println!("Copying {} scope: {} -> {}\n", scope, from, to);
    }

    // BFS-collect every folder path in the scope subtree (top-level first, so
    // ancestors are written before descendants).
    let top = match src.list_folders_in_scope(scope).await {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "Error listing folders in {} scope on '{}': {}",
                scope, from, e
            );
            std::process::exit(1);
        }
    };
    let mut folder_paths: Vec<String> = top.into_iter().map(|f| f.path.unwrap_or(f.name)).collect();
    let mut i = 0;
    while i < folder_paths.len() {
        let path = folder_paths[i].clone();
        if let Ok(subs) = src.list_subfolders(scope, &path).await {
            for s in subs {
                folder_paths.push(s.path.unwrap_or_else(|| format!("{}/{}", path, s.name)));
            }
        }
        i += 1;
    }

    let mut folders_done = 0usize;
    let mut entries_copied = 0usize;
    let mut entries_skipped = 0usize;
    let mut failures = 0usize;

    for path in &folder_paths {
        folders_done += 1;

        // Copy the folder's .config sentinel (if any).
        match src.get_folder_config(scope, path).await {
            Ok(cfg) => {
                if dry_run {
                    println!("  [config] {}", path);
                } else if let Err(e) = dst.put_folder_config(scope, path, &cfg).await {
                    eprintln!("  Warning: write .config for '{}' failed: {}", path, e);
                    failures += 1;
                }
            }
            Err(VaultError::NotFound) => {}
            Err(e) => eprintln!("  Warning: read .config for '{}' failed: {}", path, e),
        }

        // Copy entries.
        let entries = src.list_entries(scope, path).await.unwrap_or_default();
        for name in &entries {
            // Skip existing unless --overwrite (the existence probe is only
            // meaningful for a real write).
            if !overwrite && !dry_run {
                match dst.get_entry(scope, path, name).await {
                    Ok(_) => {
                        println!("  skip (exists): {}/{}", path, name);
                        entries_skipped += 1;
                        continue;
                    }
                    Err(VaultError::NotFound) => {}
                    Err(_) => {} // fall through and try the copy
                }
            }

            match src.get_entry(scope, path, name).await {
                Ok(entry) => {
                    if dry_run {
                        println!("  [entry]  {}/{}", path, name);
                        entries_copied += 1;
                    } else {
                        match dst.put_entry(scope, path, name, &entry).await {
                            Ok(()) => {
                                println!("  copied:  {}/{}", path, name);
                                entries_copied += 1;
                            }
                            Err(e) => {
                                eprintln!("  FAILED:  {}/{} — {}", path, name, e);
                                failures += 1;
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("  FAILED to read {}/{}: {}", path, name, e);
                    failures += 1;
                }
            }
        }
    }

    // Optionally copy every per-user credential secret (users/*).
    let mut users_copied = 0usize;
    if include_users {
        match src.list_user_keys().await {
            Ok(keys) => {
                for key in &keys {
                    match src.get_user_credentials_by_key(key).await {
                        Ok(creds) => {
                            if dry_run {
                                println!("  [users]  {} ({} vars)", key, creds.len());
                                users_copied += 1;
                            } else {
                                match dst.put_user_credentials_by_key(key, &creds).await {
                                    Ok(()) => {
                                        println!("  copied:  users/{}", key);
                                        users_copied += 1;
                                    }
                                    Err(e) => {
                                        eprintln!("  FAILED:  users/{} — {}", key, e);
                                        failures += 1;
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("  FAILED to read users/{}: {}", key, e),
                    }
                }
            }
            Err(e) => eprintln!("Warning: could not list users on '{}': {}", from, e),
        }
    }

    let verb = if dry_run { "would copy" } else { "copied" };
    println!(
        "\n{} {} folders, {} entries {} ({} skipped){}{}.",
        if dry_run { "[DRY RUN]" } else { "Done:" },
        folders_done,
        entries_copied,
        verb,
        entries_skipped,
        if include_users {
            format!(", {} user credential secrets", users_copied)
        } else {
            String::new()
        },
        if failures > 0 {
            format!(", {} FAILURES", failures)
        } else {
            String::new()
        }
    );
    if dry_run {
        println!("Re-run without --dry-run to perform the copy.");
    }
    if failures > 0 {
        std::process::exit(1);
    }
}

/// Resolve a named backend (`vault` / `vault_shared` / `vault_local`) from
/// config, read its secret ID from the matching env var, and connect. Exits
/// the process with a clear message on any misconfiguration.
async fn connect_named(config: &Config, name: &str) -> Arc<VaultClient> {
    let (vault_config, env_var) = match name {
        "vault" => (config.vault.as_ref(), "VAULT_SECRET_ID"),
        "vault_shared" => (config.vault_shared.as_ref(), "VAULT_SHARED_SECRET_ID"),
        "vault_local" => (config.vault_local.as_ref(), "VAULT_LOCAL_SECRET_ID"),
        _ => {
            eprintln!(
                "Error: unknown backend '{}' (use vault, vault_shared, or vault_local)",
                name
            );
            std::process::exit(1);
        }
    };

    let vault_config = match vault_config {
        Some(vc) => vc,
        None => {
            eprintln!("Error: backend '{}' is not configured in config.toml", name);
            std::process::exit(1);
        }
    };

    let secret_id = match std::env::var(env_var) {
        Ok(s) if !s.is_empty() => s,
        _ => {
            eprintln!("Error: {} env var required for backend '{}'", env_var, name);
            std::process::exit(1);
        }
    };

    match VaultClient::new(vault_config, &secret_id).await {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!(
                "Error connecting to backend '{}' ({}): {}",
                name, vault_config.addr, e
            );
            std::process::exit(1);
        }
    }
}
