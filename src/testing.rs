//! Test utilities and mock traits for unit testing.
//!
//! Mock data containers for Vault, Docker, and guacd so tests can run
//! without real services. No complex logic — just inspectable state.

use async_trait::async_trait;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

// ── Vault mock ──

/// In-memory Vault store implementing [`crate::vault::VaultBackend`].
///
/// Tests populate `entries` before the SUT runs (via `with_entry` or by
/// writing the map directly), then inspect them after to verify writes.
#[derive(Debug, Clone, Default)]
pub struct MockVault {
    /// `path → JSON string`. Keys mirror real Vault KV v2 paths
    /// (e.g. `shared/folder/entry`, `shared/folder/.config`).
    /// `Arc<Mutex<…>>` so the async [`crate::vault::VaultBackend`] impl
    /// (which only receives `&self`) can mutate through inspection handles.
    pub entries: Arc<Mutex<HashMap<String, String>>>,
}

impl MockVault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_entry(self, path: &str, value: &str) -> Self {
        self.entries
            .lock()
            .unwrap()
            .insert(path.to_string(), value.to_string());
        self
    }

    /// Simulate `get_entry` — deserialize stored JSON into `AddressBookEntry`.
    pub fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<crate::vault::AddressBookEntry, crate::vault::VaultError> {
        let key = format!("{}/{}/{}", scope, folder, entry);
        let raw = self
            .entries
            .lock()
            .unwrap()
            .get(&key)
            .ok_or(crate::vault::VaultError::NotFound)?
            .clone();
        serde_json::from_str(&raw).map_err(|e| crate::vault::VaultError::Parse(e.to_string()))
    }

    /// Simulate `put_entry`.
    pub fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &crate::vault::AddressBookEntry,
    ) -> Result<(), crate::vault::VaultError> {
        let key = format!("{}/{}/{}", scope, folder, entry);
        let json = serde_json::to_string(data)
            .map_err(|e| crate::vault::VaultError::Parse(e.to_string()))?;
        self.entries.lock().unwrap().insert(key, json);
        Ok(())
    }

    /// Simulate `delete_entry`.
    pub fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), crate::vault::VaultError> {
        let key = format!("{}/{}/{}", scope, folder, entry);
        self.entries
            .lock()
            .unwrap()
            .remove(&key)
            .ok_or(crate::vault::VaultError::NotFound)?;
        Ok(())
    }

    /// Simulate `get_folder_config`.
    pub fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<crate::vault::FolderConfig, crate::vault::VaultError> {
        let key = format!("{}/{}/.config", scope, folder);
        let raw = self
            .entries
            .lock()
            .unwrap()
            .get(&key)
            .ok_or(crate::vault::VaultError::NotFound)?
            .clone();
        serde_json::from_str(&raw).map_err(|e| crate::vault::VaultError::Parse(e.to_string()))
    }

    /// Simulate `put_folder_config`.
    pub fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &crate::vault::FolderConfig,
    ) -> Result<(), crate::vault::VaultError> {
        let key = format!("{}/{}/.config", scope, folder);
        let json = serde_json::to_string(config)
            .map_err(|e| crate::vault::VaultError::Parse(e.to_string()))?;
        self.entries.lock().unwrap().insert(key, json);
        Ok(())
    }

    /// Simulate `list_entries` — returns entry names in a folder.
    pub fn list_entries(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Vec<String>, crate::vault::VaultError> {
        let prefix = format!("{}/{}/", scope, folder);
        let entries = self.entries.lock().unwrap();
        let mut names: Vec<String> = entries
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&prefix).and_then(|rest| {
                    if rest.contains('/') || rest == ".config" {
                        None
                    } else {
                        Some(rest.to_string())
                    }
                })
            })
            .collect();
        names.sort();
        Ok(names)
    }

    /// Simulate `list_children` — immediate children at a folder path.
    /// Subfolder names end with `/`.
    pub fn list_children(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Vec<String>, crate::vault::VaultError> {
        let prefix = format!("{}/{}/", scope, folder);
        let entries = self.entries.lock().unwrap();
        let mut names: Vec<String> = entries
            .keys()
            .filter_map(|k| {
                k.strip_prefix(&prefix).map(|rest| {
                    if rest.contains('/') {
                        format!("{}/", rest.split('/').next().unwrap_or(""))
                    } else {
                        rest.to_string()
                    }
                })
            })
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Simulate `read_kv_field`.
    pub fn read_kv_field(
        &self,
        kv_path: &str,
        field: &str,
    ) -> Result<String, crate::vault::VaultError> {
        let raw = self
            .entries
            .lock()
            .unwrap()
            .get(kv_path)
            .ok_or(crate::vault::VaultError::NotFound)?
            .clone();
        let json: serde_json::Value = serde_json::from_str(&raw)
            .map_err(|e| crate::vault::VaultError::Parse(e.to_string()))?;
        json.get(field)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| crate::vault::VaultError::Parse(format!("field '{}' not found", field)))
    }
}

#[async_trait]
impl crate::vault::VaultBackend for MockVault {
    async fn list_folders_in_scope(
        &self,
        scope: &str,
    ) -> Result<Vec<crate::vault::FolderInfo>, crate::vault::VaultError> {
        let keys: Vec<String> = self.entries.lock().unwrap().keys().cloned().collect();
        let prefix = format!("{}/", scope);
        let mut names: Vec<String> = keys
            .iter()
            .filter_map(|k| k.strip_prefix(&prefix))
            .map(|rest| rest.split('/').next().unwrap_or("").to_string())
            .filter(|n| !n.is_empty() && n != ".config")
            .collect();
        names.sort();
        names.dedup();

        let mut folders = Vec::new();
        for name in names {
            let mut info = crate::vault::FolderInfo {
                name: name.clone(),
                description: String::new(),
                scope: scope.to_string(),
                path: Some(name.clone()),
                has_children: None,
            };
            if let Ok(config) = self.get_folder_config(scope, &name) {
                info.description = config.description;
            }
            if let Ok(children) = self.list_children(scope, &name) {
                info.has_children = Some(children.iter().any(|c| c.ends_with('/')));
            }
            folders.push(info);
        }
        Ok(folders)
    }

    async fn list_subfolders(
        &self,
        scope: &str,
        parent_path: &str,
    ) -> Result<Vec<crate::vault::FolderInfo>, crate::vault::VaultError> {
        let children = self.list_children(scope, parent_path)?;
        let mut folders = Vec::new();
        for key in &children {
            if let Some(name) = key.strip_suffix('/') {
                let full_path = format!("{}/{}", parent_path, name);
                let mut info = crate::vault::FolderInfo {
                    name: name.to_string(),
                    description: String::new(),
                    scope: scope.to_string(),
                    path: Some(full_path.clone()),
                    has_children: None,
                };
                if let Ok(config) = self.get_folder_config(scope, &full_path) {
                    info.description = config.description;
                }
                if let Ok(grandchildren) = self.list_children(scope, &full_path) {
                    info.has_children = Some(grandchildren.iter().any(|c| c.ends_with('/')));
                }
                folders.push(info);
            }
        }
        Ok(folders)
    }

    async fn list_entries(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<Vec<String>, crate::vault::VaultError> {
        self.list_entries(scope, folder)
    }

    async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<crate::vault::AddressBookEntry, crate::vault::VaultError> {
        self.get_entry(scope, folder, entry)
    }

    async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &crate::vault::AddressBookEntry,
    ) -> Result<(), crate::vault::VaultError> {
        self.put_entry(scope, folder, entry, data)
    }

    async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), crate::vault::VaultError> {
        self.delete_entry(scope, folder, entry)
    }

    async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<crate::vault::FolderConfig, crate::vault::VaultError> {
        self.get_folder_config(scope, folder)
    }

    async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &crate::vault::FolderConfig,
    ) -> Result<(), crate::vault::VaultError> {
        self.put_folder_config(scope, folder, config)
    }

    async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), crate::vault::VaultError> {
        let prefix = format!("{}/{}/", scope, folder);
        let mut entries = self.entries.lock().unwrap();
        let doomed: Vec<String> = entries
            .keys()
            .filter(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        let mut entry_count = 0usize;
        let mut subfolders: Vec<String> = Vec::new();
        for key in &doomed {
            let rest = key.strip_prefix(&prefix).unwrap_or("");
            if rest.contains('/') {
                let sub = rest.split('/').next().unwrap_or("").to_string();
                if !sub.is_empty() && !subfolders.contains(&sub) {
                    subfolders.push(sub);
                }
            } else if rest != ".config" {
                entry_count += 1;
            }
            entries.remove(key);
        }
        Ok((subfolders.len(), entry_count))
    }

    async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        user_groups: &[String],
    ) -> Result<bool, crate::vault::VaultError> {
        let mut current = folder.to_string();
        loop {
            let config = match self.get_folder_config(scope, &current) {
                Ok(c) => c,
                Err(crate::vault::VaultError::NotFound) => return Ok(false),
                Err(e) => return Err(e),
            };
            if config
                .allowed_groups
                .iter()
                .any(|g| user_groups.iter().any(|ug| ug == g))
            {
                return Ok(true);
            }
            if !config.inherit_from_parent {
                return Ok(false);
            }
            // Walk to parent segment; stop at the top-level folder.
            match current.rsplit_once('/') {
                Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
                _ => return Ok(false),
            }
        }
    }

    async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<HashMap<String, String>, crate::vault::VaultError> {
        let key = format!("users/{}", email);
        match self.entries.lock().unwrap().get(&key).cloned() {
            Some(raw) => serde_json::from_str(&raw)
                .map_err(|e| crate::vault::VaultError::Parse(e.to_string())),
            None => Ok(HashMap::new()),
        }
    }

    async fn put_user_credentials(
        &self,
        email: &str,
        creds: &HashMap<String, String>,
    ) -> Result<(), crate::vault::VaultError> {
        let key = format!("users/{}", email);
        let json = serde_json::to_string(creds)
            .map_err(|e| crate::vault::VaultError::Parse(e.to_string()))?;
        self.entries.lock().unwrap().insert(key, json);
        Ok(())
    }

    async fn read_kv_field(
        &self,
        kv_path: &str,
        field: &str,
    ) -> Result<String, crate::vault::VaultError> {
        self.read_kv_field(kv_path, field)
    }
}

// ── Docker mock ──

/// Snapshot of a mock container.
#[derive(Debug, Clone)]
pub struct MockContainer {
    pub name: String,
    pub image: String,
    pub running: bool,
}

/// In-memory Docker daemon simulation.
#[derive(Debug, Clone, Default)]
pub struct MockDocker {
    pub containers: HashMap<String, MockContainer>,
}

impl MockDocker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_container(mut self, name: &str, image: &str, running: bool) -> Self {
        self.containers.insert(
            name.to_string(),
            MockContainer {
                name: name.to_string(),
                image: image.to_string(),
                running,
            },
        );
        self
    }
}

/// Mock implementation of the `VdiDriver` trait.
pub struct MockVdiDriver {
    pub docker: Mutex<MockDocker>,
    /// Next container ID to assign (incremented on each start).
    pub next_id: Mutex<u32>,
}

impl MockVdiDriver {
    pub fn new(docker: MockDocker) -> Self {
        Self {
            docker: Mutex::new(docker),
            next_id: Mutex::new(1),
        }
    }
}

impl crate::vdi::VdiDriver for MockVdiDriver {
    fn start_or_reuse<'a>(
        &'a self,
        spec: &'a crate::vdi::ContainerSpec,
    ) -> Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<crate::vdi::ContainerInfo, crate::vdi::VdiError>,
                > + Send
                + 'a,
        >,
    > {
        let mut docker = self.docker.lock().unwrap();
        let mut id_guard = self.next_id.lock().unwrap();

        let name = format!("mock-{}", spec.username);

        // Reuse if already running
        if let Some(c) = docker.containers.get(&name) {
            if c.running {
                let cid = c.name.clone();
                return Box::pin(async move {
                    Ok(crate::vdi::ContainerInfo {
                        container_id: cid,
                        container_name: name,
                        rdp_host: "127.0.0.1".into(),
                        rdp_port: 3389,
                        reused: true,
                    })
                });
            }
        }

        let id = *id_guard;
        *id_guard += 1;
        let container_id = format!("mock-{:08x}", id);

        docker.containers.insert(
            name.clone(),
            MockContainer {
                name: name.clone(),
                image: spec.image.clone(),
                running: true,
            },
        );

        let cid = container_id.clone();
        let cname = name.clone();
        Box::pin(async move {
            Ok(crate::vdi::ContainerInfo {
                container_id: cid,
                container_name: cname,
                rdp_host: "127.0.0.1".into(),
                rdp_port: 3389,
                reused: false,
            })
        })
    }

    fn stop_container<'a>(
        &'a self,
        container_id: &'a str,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), crate::vdi::VdiError>> + Send + 'a>>
    {
        let mut docker = self.docker.lock().unwrap();
        // Find and remove by container_id or name
        let to_remove: Vec<String> = docker
            .containers
            .iter()
            .filter(|(_, c)| c.name == container_id || c.name.contains(container_id))
            .map(|(k, _)| k.clone())
            .collect();
        for k in to_remove {
            docker.containers.remove(&k);
        }
        Box::pin(async { Ok(()) })
    }

    fn health_check(
        &self,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<(), crate::vdi::VdiError>> + Send + '_>>
    {
        Box::pin(async { Ok(()) })
    }

    fn list_managed_containers(
        &self,
    ) -> Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<String>, crate::vdi::VdiError>> + Send + '_,
        >,
    > {
        let docker = self.docker.lock().unwrap();
        let ids: Vec<String> = docker.containers.keys().cloned().collect();
        Box::pin(async { Ok(ids) })
    }

    fn list_managed_containers_detail(
        &self,
    ) -> Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<Vec<crate::vdi::ManagedContainer>, crate::vdi::VdiError>,
                > + Send
                + '_,
        >,
    > {
        let docker = self.docker.lock().unwrap();
        let list: Vec<crate::vdi::ManagedContainer> = docker
            .containers
            .values()
            .map(|c| crate::vdi::ManagedContainer {
                container_id: c.name.clone(),
                container_name: c.name.clone(),
                username: String::new(),
                image: c.image.clone(),
                entry_key: None,
                thumbnail_url: None,
                has_active_session: c.running,
                idle_timeout_mins: None,
            })
            .collect();
        Box::pin(async { Ok(list) })
    }
}

// ── Guacd mock ──

/// A mock guacd connection that captures outbound instructions
/// and allows injecting inbound ones.
pub struct MockGuacdConnection {
    /// Instructions the SUT sent (captured by the mock transport).
    pub sent: Arc<Mutex<Vec<crate::protocol::Instruction>>>,
}

impl MockGuacdConnection {
    pub fn new() -> Self {
        Self {
            sent: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Drain captured instructions.
    pub fn drain_sent(&self) -> Vec<crate::protocol::Instruction> {
        std::mem::take(&mut self.sent.lock().unwrap())
    }
}

impl Default for MockGuacdConnection {
    fn default() -> Self {
        Self::new()
    }
}
