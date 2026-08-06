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

use std::future::Future;
use std::sync::Arc;

use crate::config::Config;
use crate::vault::{FolderInfo, VaultClient, VaultError};

/// Run the `vault-migrate` subcommand.
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
    let folder_paths = collect_folder_paths(
        top,
        &mut ClientSubfolders {
            client: &src,
            scope,
        },
    )
    .await;

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

/// Resolves the children of a folder path, for the BFS walk.
trait SubfolderLister {
    fn list_subfolders(
        &mut self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<FolderInfo>, VaultError>> + Send;
}

/// BFS-collect every folder path in the scope subtree, top-level folders
/// first so ancestors always precede descendants.
///
/// `list_subfolders` resolves the children of a path; a failed listing is
/// tolerated and contributes nothing, matching the error-tolerant walk in
/// `cmd_vault_migrate`.
async fn collect_folder_paths(
    top: Vec<FolderInfo>,
    lister: &mut impl SubfolderLister,
) -> Vec<String> {
    let mut folder_paths: Vec<String> = top.into_iter().map(|f| f.path.unwrap_or(f.name)).collect();
    let mut i = 0;
    while i < folder_paths.len() {
        let path = folder_paths[i].clone();
        if let Ok(subs) = lister.list_subfolders(&path).await {
            for s in subs {
                folder_paths.push(s.path.unwrap_or_else(|| format!("{}/{}", path, s.name)));
            }
        }
        i += 1;
    }
    folder_paths
}

/// Adapts a live `VaultClient` + scope for the BFS walk.
struct ClientSubfolders<'a> {
    client: &'a VaultClient,
    scope: &'a str,
}

impl SubfolderLister for ClientSubfolders<'_> {
    fn list_subfolders(
        &mut self,
        path: &str,
    ) -> impl Future<Output = Result<Vec<FolderInfo>, VaultError>> + Send {
        self.client.list_subfolders(self.scope, path)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn folder(name: &str) -> FolderInfo {
        FolderInfo {
            name: name.to_string(),
            description: String::new(),
            scope: "shared".to_string(),
            path: None,
            has_children: None,
        }
    }

    fn folder_with_path(name: &str, path: &str) -> FolderInfo {
        let mut f = folder(name);
        f.path = Some(path.to_string());
        f
    }

    /// Drives the BFS walk from an in-memory subfolder map. Paths absent from
    /// `subfolders` have no children; paths listed in `errors` fail to list
    /// (exercising the walk's error tolerance).
    struct MapLister<'a> {
        subfolders: &'a HashMap<String, Vec<FolderInfo>>,
        errors: &'a [&'a str],
    }

    impl SubfolderLister for MapLister<'_> {
        fn list_subfolders(
            &mut self,
            path: &str,
        ) -> impl Future<Output = Result<Vec<FolderInfo>, VaultError>> + Send {
            std::future::ready(if self.errors.contains(&path) {
                Err(VaultError::NotFound)
            } else {
                Ok(self.subfolders.get(path).cloned().unwrap_or_default())
            })
        }
    }

    async fn run_walk(
        top: Vec<FolderInfo>,
        subfolders: &HashMap<String, Vec<FolderInfo>>,
        errors: &[&str],
    ) -> Vec<String> {
        collect_folder_paths(top, &mut MapLister { subfolders, errors }).await
    }

    #[tokio::test]
    async fn top_level_folders_fall_back_to_name_when_path_missing() {
        let subs = HashMap::new();
        let paths = run_walk(
            vec![
                folder("Clients"),
                folder_with_path("Acme", "Customers/Acme"),
            ],
            &subs,
            &[],
        )
        .await;
        assert_eq!(paths, vec!["Clients", "Customers/Acme"]);
    }

    #[tokio::test]
    async fn nested_subfolders_join_parent_path_when_path_missing() {
        let mut subs = HashMap::new();
        subs.insert(
            "Clients".to_string(),
            vec![folder_with_path("Acme", "Clients/Acme"), folder("Dept")],
        );
        subs.insert(
            "Clients/Acme".to_string(),
            vec![folder_with_path("Prod", "Clients/Acme/Prod")],
        );
        let paths = run_walk(vec![folder_with_path("Clients", "Clients")], &subs, &[]).await;
        assert_eq!(
            paths,
            vec![
                "Clients",
                "Clients/Acme",
                "Clients/Dept",
                "Clients/Acme/Prod"
            ]
        );
    }

    #[tokio::test]
    async fn walk_is_breadth_first_ancestors_before_descendants() {
        let mut subs = HashMap::new();
        subs.insert("A".to_string(), vec![folder("A1"), folder("A2")]);
        subs.insert("B".to_string(), vec![folder("B1")]);
        subs.insert("A/A1".to_string(), vec![folder("A1a")]);
        let paths = run_walk(vec![folder("A"), folder("B")], &subs, &[]).await;
        assert_eq!(paths, vec!["A", "B", "A/A1", "A/A2", "B/B1", "A/A1/A1a"]);
    }

    #[tokio::test]
    async fn listing_errors_are_tolerated() {
        let mut subs = HashMap::new();
        subs.insert("B".to_string(), vec![folder("B1")]);
        let paths = run_walk(vec![folder("A"), folder("B")], &subs, &["A"]).await;
        assert_eq!(paths, vec!["A", "B", "B/B1"]);
    }

    #[tokio::test]
    async fn empty_scope_produces_no_paths() {
        let paths = run_walk(Vec::new(), &HashMap::new(), &[]).await;
        assert!(paths.is_empty());
    }
}
