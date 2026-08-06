use super::{AppState, StorageKey, VaultBackends, VaultState};
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::rbac;
use crate::session::{
    CreateSessionRequest, ProxmoxParams, RdpParams, SessionType, SpiceParams, SshParams, VdiParams,
    VncParams, WebParams,
};
use crate::vault::{AddressBookEntry, FolderConfig, VaultError};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use std::net::SocketAddr;

/// Check if the DB storage backend is available (address book tables exist).
fn is_db_storage_available(db: &Db) -> bool {
    db::list_ab_folders(db, None).is_ok()
}

/// Resolve the credential encryption key: the startup-resolved `StorageKey`
/// extension (config `[storage].encryption_key`, falling back to the
/// `PERSEA_STORAGE_KEY` env var) takes precedence; the env var is re-checked
/// for callers that run without the extension (e.g. handler tests).
fn resolve_encryption_key(storage_key: Option<&StorageKey>) -> String {
    storage_key
        .and_then(|k| k.0.clone())
        .or_else(|| {
            std::env::var("PERSEA_STORAGE_KEY")
                .ok()
                .filter(|k| !k.is_empty())
        })
        .unwrap_or_default()
}

/// Check if a folder's allowed_groups grant access to the given user groups.
fn folder_allowed_for_user(
    db: &Db,
    scope: &str,
    folder_name: &str,
    user_groups: &[String],
) -> bool {
    if user_groups.is_empty() {
        return false;
    }
    match db::get_ab_folder(db, scope, folder_name) {
        Ok(folder) => {
            if folder.description.is_empty() {
                // No description means no group restrictions set
                return true;
            }
            // Check if any entry in this folder has allowed_groups matching
            match db::list_ab_entries(db, folder.id) {
                Ok(entries) => {
                    for entry in &entries {
                        if entry.allowed_groups.is_empty() {
                            return true;
                        }
                        for group in entry.allowed_groups.split(',') {
                            let g = group.trim();
                            if !g.is_empty() && user_groups.iter().any(|ug| ug == g) {
                                return true;
                            }
                        }
                    }
                    false
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

/// Get folder ID by scope and name from DB.
fn get_folder_id(db: &Db, scope: &str, name: &str) -> Result<i64, AppError> {
    let folder = db::get_ab_folder(db, scope, name)
        .map_err(|e| AppError::Internal(format!("folder not found: {}", e)))?;
    Ok(folder.id)
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub dpi: Option<u32>,
    #[serde(default)]
    pub banner: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Deserialize)]
pub struct ProbeHostKeyRequest {
    pub hostname: String,
    pub port: Option<u16>,
}

#[derive(Deserialize)]
pub struct CreateFolderRequest {
    pub name: String,
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub inherit_from_parent: bool,
}

#[derive(Deserialize)]
pub struct UpdateFolderRequest {
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub inherit_from_parent: bool,
}

#[derive(Deserialize)]
pub struct CreateEntryRequest {
    pub name: String,
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

#[derive(Deserialize)]
pub struct QuickConnectQuery {
    pub protocol: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub url: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    pub scope: Option<String>,
    pub folder: Option<String>,
    pub entry: Option<String>,
}

fn default_scope() -> String {
    "shared".into()
}

pub(crate) fn audit_client_ip(
    headers: &axum::http::HeaderMap,
    addr: &SocketAddr,
    trusted: Option<&Extension<TrustedProxies>>,
) -> String {
    let proxies = trusted.map(|Extension(t)| t.0.as_slice()).unwrap_or(&[]);
    client_ip(headers, addr.ip(), proxies).to_string()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_ab_event(
    database: &Db,
    email: &str,
    action: &str,
    scope: &str,
    folder_path: &str,
    entry_name: Option<&str>,
    ip: &str,
    details: Option<&str>,
) {
    let database = database.clone();
    let email = email.to_string();
    let action = action.to_string();
    let scope = scope.to_string();
    let folder_path = folder_path.to_string();
    let entry_name = entry_name.map(str::to_string);
    let ip = ip.to_string();
    let details = details.map(str::to_string);
    if let Err(e) = tokio::task::spawn_blocking(move || {
        let _ = db::log_addressbook_event(
            &database,
            &email,
            &action,
            &scope,
            &folder_path,
            entry_name.as_deref(),
            Some(&ip),
            details.as_deref(),
        );
    })
    .await
    {
        tracing::error!(error = %e, "audit task failed");
    }
}

pub(crate) async fn check_folder_access(
    vault: &VaultBackends,
    scope: &str,
    folder: &str,
    identity: &AuthIdentity,
) -> Result<(), AppError> {
    if identity.has_role("admin") {
        return Ok(());
    }

    let user_groups = identity.groups();
    match vault
        .resolve_folder_access(scope, folder, user_groups)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(AppError::Forbidden("no access to this folder".into())),
        Err(VaultError::NotFound) => Err(AppError::Vault("folder not found".into())),
        Err(e) => Err(AppError::Vault(e.to_string())),
    }
}

pub(crate) fn folder_or_descendant_accessible<'a>(
    vault: &'a VaultBackends,
    scope: &'a str,
    path: &'a str,
    user_groups: &'a [String],
) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
    Box::pin(async move {
        if vault
            .resolve_folder_access(scope, path, user_groups)
            .await
            .unwrap_or(false)
        {
            return true;
        }
        if let Ok(subs) = vault.list_subfolders(scope, path).await {
            for sub in subs {
                let child = sub.path.unwrap_or(sub.name);
                if folder_or_descendant_accessible(vault, scope, &child, user_groups).await {
                    return true;
                }
            }
        }
        false
    })
}

pub async fn ab_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    // Try Vault first if connected, otherwise use DB backend
    if vault.any_connected().await {
        let folders = vault
            .list_all_folders()
            .await
            .map_err(|e| AppError::Vault(e.to_string()))?
            .0;

        let user_groups = id.groups();
        let mut visible = Vec::new();
        for folder in folders {
            if id.has_role("admin")
                || vault
                    .resolve_folder_access(&folder.scope, &folder.name, user_groups)
                    .await
                    .unwrap_or(false)
            {
                visible.push(folder);
            }
        }

        return Ok(Json(json!(visible)));
    }

    // DB backend fallback
    if is_db_storage_available(&database) {
        let db_folders =
            db::list_ab_folders(&database, None).map_err(|e| AppError::Internal(e.to_string()))?;
        let user_groups = id.groups();
        let mut visible = Vec::new();
        for folder in db_folders {
            if id.has_role("admin")
                || folder_allowed_for_user(&database, &folder.scope, &folder.name, user_groups)
            {
                visible.push(serde_json::json!({
                    "name": folder.name,
                    "scope": folder.scope,
                    "description": folder.description,
                    "path": folder.name,
                    "has_children": None::<bool>,
                }));
            }
        }
        return Ok(Json(json!(visible)));
    }

    Err(AppError::Vault(
        "address book unavailable: no storage backend configured".into(),
    ))
}

pub async fn ab_list_subfolders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    check_folder_access(&vault, &scope, &folder, id).await?;

    match vault.list_subfolders(&scope, &folder).await {
        Ok(subfolders) => {
            if id.has_role("admin") {
                return Ok(Json(json!(subfolders)));
            }
            let user_groups = id.groups();
            let mut visible = Vec::with_capacity(subfolders.len());
            for sf in subfolders {
                let path = sf.path.clone().unwrap_or_else(|| sf.name.clone());
                if folder_or_descendant_accessible(&vault, &scope, &path, user_groups).await {
                    visible.push(sf);
                }
            }
            Ok(Json(json!(visible)))
        }
        Err(crate::vault::VaultError::NotFound) => Ok(Json(json!([]))),
        Err(e) => Err(AppError::Vault(e.to_string())),
    }
}

pub async fn ab_list_all(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    let (folders, unavailable_scopes) = vault
        .list_all_folders()
        .await
        .map_err(|e| AppError::Vault(e.to_string()))?;

    let mut result = Vec::new();
    let user_groups = id.groups();
    for folder in folders {
        if !id.has_role("admin")
            && !vault
                .resolve_folder_access(&folder.scope, &folder.name, user_groups)
                .await
                .unwrap_or(false)
        {
            continue;
        }

        let config = vault
            .get_folder_config(&folder.scope, &folder.name)
            .await
            .ok();

        let entry_names = vault
            .list_entries(&folder.scope, &folder.name)
            .await
            .unwrap_or_default();
        let mut entries = Vec::new();
        for name in &entry_names {
            if let Ok(entry) = vault.get_entry(&folder.scope, &folder.name, name).await {
                entries.push(crate::vault::EntryInfo::from((name.as_str(), &entry)));
            }
        }

        result.push(json!({
            "name": folder.name,
            "scope": folder.scope,
            "path": folder.path,
            "has_children": folder.has_children,
            "description": folder.description,
            "allowed_groups": config.as_ref().map(|c| &c.allowed_groups),
            "entries": entries,
        }));
    }

    Ok(Json(
        json!({"folders": result, "unavailable_scopes": unavailable_scopes}),
    ))
}

pub async fn ab_search_index(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    let user_groups = id.groups();
    let is_admin = id.has_role("admin");

    let top = vault
        .list_all_folders()
        .await
        .map_err(|e| AppError::Vault(e.to_string()))?
        .0;

    let mut queue: Vec<(String, String)> = top
        .into_iter()
        .map(|f| (f.scope, f.path.unwrap_or(f.name)))
        .collect();
    let mut emitted = Vec::new();

    while let Some((scope, path)) = queue.pop() {
        if let Ok(subs) = vault.list_subfolders(&scope, &path).await {
            for s in subs {
                let child_path = s.path.unwrap_or_else(|| s.name.clone());
                queue.push((scope.clone(), child_path));
            }
        }

        let allowed = is_admin
            || vault
                .resolve_folder_access(&scope, &path, user_groups)
                .await
                .unwrap_or(false);
        if !allowed {
            continue;
        }

        let names = match vault.list_entries(&scope, &path).await {
            Ok(n) => n,
            Err(_) => continue,
        };
        for name in &names {
            if let Ok(entry) = vault.get_entry(&scope, &path, name).await {
                emitted.push(json!({
                    "scope": scope,
                    "folder_path": path,
                    "entry": crate::vault::EntryInfo::from((name.as_str(), &entry)),
                }));
            }
        }
    }

    Ok(Json(json!({"entries": emitted})))
}

pub async fn ab_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    // Try Vault first if connected
    if vault.any_connected().await {
        check_folder_access(&vault, &scope, &folder, id).await?;

        let entry_names = match vault.list_entries(&scope, &folder).await {
            Ok(e) => e,
            Err(VaultError::NotFound) => Vec::new(),
            Err(e) => return Err(AppError::Vault(e.to_string())),
        };

        let mut entries = Vec::new();
        for name in &entry_names {
            if let Ok(entry) = vault.get_entry(&scope, &folder, name).await {
                entries.push(crate::vault::EntryInfo::from((name.as_str(), &entry)));
            }
        }

        return Ok(Json(json!(entries)));
    }

    // DB backend
    if is_db_storage_available(&database) {
        let folder = db::get_ab_folder(&database, &scope, &folder)
            .map_err(|e| AppError::Internal(format!("folder not found: {}", e)))?;

        let db_entries = db::list_ab_entries(&database, folder.id)
            .map_err(|e| AppError::Internal(e.to_string()))?;

        let mut entries = Vec::new();
        for entry in &db_entries {
            // Reconstruct an AddressBookEntry from DB fields for EntryInfo conversion
            let _protocol_config: serde_json::Value = serde_json::from_str(&entry.protocol_config)
                .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

            let ab_entry = AddressBookEntry {
                session_type: entry.protocol.clone(),
                hostname: Some(entry.hostname.clone()),
                port: entry.port,
                username: if entry.username.is_empty() {
                    None
                } else {
                    Some(entry.username.clone())
                },
                display_name: if entry.display_name.is_empty() {
                    None
                } else {
                    Some(entry.display_name.clone())
                },
                ..Default::default()
            };

            entries.push(crate::vault::EntryInfo::from((
                entry.name.as_str(),
                &ab_entry,
            )));
        }

        return Ok(Json(json!(entries)));
    }

    Err(AppError::Vault("address book unavailable".into()))
}

pub async fn ssh_probe_host_key(
    identity: Option<Extension<AuthIdentity>>,
    axum::Json(body): axum::Json<ProbeHostKeyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return Err(AppError::Forbidden(
                "requires poweruser or admin role".into(),
            ));
        }
    }

    let port = body.port.unwrap_or(22);
    let host_key = crate::tunnel::probe_host_key(&body.hostname, port).await?;
    let fingerprint =
        crate::tunnel::fingerprint_openssh_key(&host_key).unwrap_or_else(|_| "unknown".into());
    let algorithm = host_key
        .split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string();
    Ok(Json(json!({
        "host_key": host_key,
        "fingerprint": fingerprint,
        "algorithm": algorithm,
    })))
}

#[allow(clippy::too_many_arguments)]
pub async fn ab_connect_entry(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    storage_key: Option<Extension<StorageKey>>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    check_folder_access(&vault, &scope, &folder, &id).await?;

    // RBAC connection permission check (skip for admin role)
    if !id.has_role("admin") {
        if let Some(db_ref) = manager.db() {
            let db_rbac = db_ref.clone();
            let email = id.display_name().to_string();
            let conn_id = format!("{}/{}/{}", scope, folder, entry);
            let has_perm = tokio::task::spawn_blocking(move || {
                // Look up user by email to get numeric ID
                let user = db::get_user_by_email(&db_rbac, &email).ok();
                match user {
                    Some(u) => rbac::check_connection_permission(
                        &db_rbac,
                        u.id,
                        &conn_id,
                        rbac::ObjectPermission::Connect,
                    )
                    .unwrap_or(false),
                    // Unknown user — deny
                    None => false,
                }
            })
            .await
            .unwrap_or(false);
            if !has_perm {
                return Err(AppError::Forbidden(
                    "No permission to connect to this resource".into(),
                ));
            }
        }
    }

    let ab_entry = if vault.any_connected().await {
        match vault.get_entry(&scope, &folder, &entry).await {
            Ok(e) => e,
            Err(VaultError::NotFound) => return Err(AppError::Vault("entry not found".into())),
            Err(e) => return Err(AppError::Vault(e.to_string())),
        }
    } else if is_db_storage_available(&database) {
        // Read entry from DB
        let folder_rec = db::get_ab_folder(&database, &scope, &folder)
            .map_err(|e| AppError::Internal(format!("folder not found: {}", e)))?;
        let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
            .map_err(|e| AppError::Internal(format!("entry not found: {}", e)))?;

        // Read credentials from DB
        let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
        let creds = db::list_ab_credentials(&database, entry_rec.id).unwrap_or_default();

        let mut password = None;
        let mut private_key = None;
        let mut proxmox_token_secret = None;
        let mut container_password = None;

        for cred in &creds {
            let decrypted = if !encryption_key.is_empty() {
                crate::crypto::decrypt_value(
                    &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                        .unwrap_or_else(|_| panic!("invalid encryption key")),
                    &cred.credential_data,
                )
                .unwrap_or(cred.credential_data.clone())
            } else {
                cred.credential_data.clone()
            };

            match cred.credential_type.as_str() {
                "password" => password = Some(decrypted),
                "private_key" => private_key = Some(decrypted),
                "proxmox_token_secret" => proxmox_token_secret = Some(decrypted),
                "container_password" => container_password = Some(decrypted),
                _ => {}
            }
        }

        // Parse protocol_config JSON
        let protocol_config: serde_json::Value = serde_json::from_str(&entry_rec.protocol_config)
            .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

        AddressBookEntry {
            session_type: entry_rec.protocol,
            hostname: Some(entry_rec.hostname),
            port: entry_rec.port,
            username: if entry_rec.username.is_empty() {
                None
            } else {
                Some(entry_rec.username)
            },
            password,
            private_key,
            display_name: if entry_rec.display_name.is_empty() {
                None
            } else {
                Some(entry_rec.display_name)
            },
            domain: protocol_config
                .get("domain")
                .and_then(|v| v.as_str())
                .map(String::from),
            security: protocol_config
                .get("security")
                .and_then(|v| v.as_str())
                .map(String::from),
            ignore_cert: protocol_config.get("ignore_cert").and_then(|v| v.as_bool()),
            url: protocol_config
                .get("url")
                .and_then(|v| v.as_str())
                .map(String::from),
            enable_drive: protocol_config
                .get("enable_drive")
                .and_then(|v| v.as_bool()),
            auth_pkg: protocol_config
                .get("auth_pkg")
                .and_then(|v| v.as_str())
                .map(String::from),
            kdc_url: protocol_config
                .get("kdc_url")
                .and_then(|v| v.as_str())
                .map(String::from),
            color_depth: protocol_config
                .get("color_depth")
                .and_then(|v| v.as_u64())
                .map(|v| v as u8),
            enable_recording: protocol_config
                .get("enable_recording")
                .and_then(|v| v.as_bool()),
            record_typescript: protocol_config
                .get("record_typescript")
                .and_then(|v| v.as_bool()),
            remote_app: protocol_config
                .get("remote_app")
                .and_then(|v| v.as_str())
                .map(String::from),
            remote_app_dir: protocol_config
                .get("remote_app_dir")
                .and_then(|v| v.as_str())
                .map(String::from),
            remote_app_args: protocol_config
                .get("remote_app_args")
                .and_then(|v| v.as_str())
                .map(String::from),
            enable_gfx: protocol_config.get("enable_gfx").and_then(|v| v.as_bool()),
            enable_desktop_composition: protocol_config
                .get("enable_desktop_composition")
                .and_then(|v| v.as_bool()),
            enable_wallpaper: protocol_config
                .get("enable_wallpaper")
                .and_then(|v| v.as_bool()),
            enable_theming: protocol_config
                .get("enable_theming")
                .and_then(|v| v.as_bool()),
            enable_full_window_drag: protocol_config
                .get("enable_full_window_drag")
                .and_then(|v| v.as_bool()),
            force_lossless: protocol_config
                .get("force_lossless")
                .and_then(|v| v.as_bool()),
            enable_h264: protocol_config.get("enable_h264").and_then(|v| v.as_bool()),
            banner: protocol_config
                .get("banner")
                .and_then(|v| v.as_str())
                .map(String::from),
            prompt_credentials: protocol_config
                .get("prompt_credentials")
                .and_then(|v| v.as_bool()),
            allow_sharing: protocol_config
                .get("allow_sharing")
                .and_then(|v| v.as_bool()),
            auto_open_if_singleton: protocol_config
                .get("auto_open_if_singleton")
                .and_then(|v| v.as_bool()),
            fullscreen_on_connect: protocol_config
                .get("fullscreen_on_connect")
                .and_then(|v| v.as_bool()),
            autohide_side_tabs: protocol_config
                .get("autohide_side_tabs")
                .and_then(|v| v.as_bool()),
            spice_tls: protocol_config.get("spice_tls").and_then(|v| v.as_bool()),
            spice_tls_port: protocol_config
                .get("spice_tls_port")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16),
            spice_ca_cert: protocol_config
                .get("spice_ca_cert")
                .and_then(|v| v.as_str())
                .map(String::from),
            spice_cert_subject: protocol_config
                .get("spice_cert_subject")
                .and_then(|v| v.as_str())
                .map(String::from),
            spice_proxy: protocol_config
                .get("spice_proxy")
                .and_then(|v| v.as_str())
                .map(String::from),
            proxmox_url: protocol_config
                .get("proxmox_url")
                .and_then(|v| v.as_str())
                .map(String::from),
            proxmox_node: protocol_config
                .get("proxmox_node")
                .and_then(|v| v.as_str())
                .map(String::from),
            proxmox_vmid: protocol_config
                .get("proxmox_vmid")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            proxmox_token_id: protocol_config
                .get("proxmox_token_id")
                .and_then(|v| v.as_str())
                .map(String::from),
            proxmox_token_secret,
            proxmox_verify_tls: protocol_config
                .get("proxmox_verify_tls")
                .and_then(|v| v.as_bool()),
            container_image: protocol_config
                .get("container_image")
                .and_then(|v| v.as_str())
                .map(String::from),
            container_cpu_limit: protocol_config
                .get("container_cpu_limit")
                .and_then(|v| v.as_f64()),
            container_memory_limit: protocol_config
                .get("container_memory_limit")
                .and_then(|v| v.as_u64()),
            container_env: None,
            container_idle_timeout_mins: protocol_config
                .get("container_idle_timeout_mins")
                .and_then(|v| v.as_u64()),
            container_username: protocol_config
                .get("container_username")
                .and_then(|v| v.as_str())
                .map(String::from),
            container_password,
            max_monitors: protocol_config
                .get("max_monitors")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            max_recordings: protocol_config
                .get("max_recordings")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            login_script: protocol_config
                .get("login_script")
                .and_then(|v| v.as_str())
                .map(String::from),
            autofill: protocol_config
                .get("autofill")
                .and_then(|v| v.as_str())
                .map(String::from),
            allowed_domains: protocol_config
                .get("allowed_domains")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
            disable_copy: protocol_config
                .get("disable_copy")
                .and_then(|v| v.as_bool()),
            disable_paste: protocol_config
                .get("disable_paste")
                .and_then(|v| v.as_bool()),
            ..Default::default()
        }
    } else {
        return Err(AppError::Vault("address book unavailable".into()));
    };

    let ab_entry = if !crate::vault::entry_credential_variables(&ab_entry).is_empty() {
        let user_email = match &id {
            AuthIdentity::User { email, .. } => Some(email.clone()),
            _ => None,
        };
        if let Some(email) = user_email {
            match vault.get_user_credentials(&email).await {
                Ok(user_creds) => {
                    match crate::vault::resolve_credential_variables(&ab_entry, &user_creds) {
                        Ok(resolved) => resolved,
                        Err(missing) => {
                            return Err(AppError::Internal(format!(
                                "missing credential variables: {}",
                                missing.join(", ")
                            )))
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read user credentials from Vault: {}", e);
                    ab_entry
                }
            }
        } else {
            ab_entry
        }
    } else {
        ab_entry
    };

    let session_type = match ab_entry.session_type.as_str() {
        "ssh" => SessionType::Ssh,
        "rdp" => SessionType::Rdp,
        "vnc" => SessionType::Vnc,
        "spice" => SessionType::Spice,
        "proxmox" => SessionType::Proxmox,
        "web" => SessionType::Web,
        "vdi" => SessionType::Vdi,
        other => {
            return Err(AppError::Internal(format!(
                "unknown session type: {}",
                other
            )))
        }
    };

    let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
    let create_req = CreateSessionRequest {
        session_type,
        hostname: ab_entry.hostname,
        port: ab_entry.port,
        username: req.username.or(ab_entry.username),
        password: req.password.or(ab_entry.password),
        ignore_cert: ab_entry.ignore_cert,
        max_monitors: ab_entry.max_monitors,
        jump_hosts: ab_entry.jump_hosts,
        jump_host: None,
        jump_port: None,
        jump_username: None,
        jump_password: None,
        jump_private_key: None,
        width: req.width,
        height: req.height,
        dpi: req.dpi,
        banner: req.banner.or(ab_entry.banner),
        enable_drive: ab_entry.enable_drive,
        disable_copy: ab_entry.disable_copy,
        disable_paste: ab_entry.disable_paste,
        enable_recording: ab_entry.enable_recording,
        address_book_entry: Some(ab_entry_key),
        address_book_folder: Some(folder.to_string()),
        entry_display_name: ab_entry.display_name.clone(),
        max_recordings: ab_entry.max_recordings,
        allow_sharing: ab_entry.allow_sharing,
        fullscreen_on_connect: ab_entry.fullscreen_on_connect,
        autohide_side_tabs: ab_entry.autohide_side_tabs,
        ssh: Some(SshParams {
            private_key: ab_entry.private_key,
            generate_keypair: None,
            record_typescript: ab_entry.record_typescript,
        }),
        rdp: Some(RdpParams {
            domain: req.domain.or(ab_entry.domain),
            security: ab_entry.security,
            auth_pkg: ab_entry.auth_pkg,
            kdc_url: ab_entry.kdc_url,
            kerberos_cache: None,
            remote_app: ab_entry.remote_app,
            remote_app_dir: ab_entry.remote_app_dir,
            remote_app_args: ab_entry.remote_app_args,
            enable_gfx: ab_entry.enable_gfx,
            enable_desktop_composition: ab_entry.enable_desktop_composition,
            enable_wallpaper: ab_entry.enable_wallpaper,
            enable_theming: ab_entry.enable_theming,
            enable_full_window_drag: ab_entry.enable_full_window_drag,
            force_lossless: ab_entry.force_lossless,
            enable_h264: ab_entry.enable_h264,
        }),
        vnc: Some(VncParams {
            color_depth: ab_entry.color_depth,
        }),
        web: Some(WebParams {
            url: ab_entry.url,
            login_script: ab_entry.login_script,
            autofill: ab_entry.autofill,
            allowed_domains: ab_entry.allowed_domains,
        }),
        vdi: Some(VdiParams {
            container_image: ab_entry.container_image,
            container_cpu_limit: ab_entry.container_cpu_limit,
            container_memory_limit: ab_entry.container_memory_limit,
            container_env: ab_entry.container_env,
            container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
            container_username: ab_entry.container_username,
            container_password: ab_entry.container_password,
        }),
        spice: Some(SpiceParams {
            spice_tls: ab_entry.spice_tls,
            spice_tls_port: ab_entry.spice_tls_port,
            spice_ca_cert: ab_entry.spice_ca_cert,
            spice_cert_subject: ab_entry.spice_cert_subject,
            spice_proxy: ab_entry.spice_proxy,
        }),
        proxmox: Some(ProxmoxParams {
            proxmox_url: ab_entry.proxmox_url,
            proxmox_node: ab_entry.proxmox_node,
            proxmox_vmid: ab_entry.proxmox_vmid,
            proxmox_token_id: ab_entry.proxmox_token_id,
            proxmox_token_secret: ab_entry.proxmox_token_secret,
            proxmox_verify_tls: ab_entry.proxmox_verify_tls,
        }),
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip_addr = client_ip(&headers, addr.ip(), &proxies);
    let admin_name = id.display_name().to_string();

    tracing::info!(
        user = %admin_name,
        client_ip = %client_ip_addr,
        folder = %folder,
        entry = %entry,
        scope = %scope,
        "Address book connect requested"
    );

    match manager.create_session(create_req, admin_name.clone()).await {
        Ok(info) => {
            tracing::info!(
                user = %admin_name,
                session_id = %info.session_id,
                "Address book session created"
            );
            Ok(Json(json!(info)))
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!(user = %admin_name, error = %msg, "Address book session creation failed");
            Err(AppError::Session(msg))
        }
    }
}

pub async fn ab_create_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Json(req): Json<CreateFolderRequest>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let allowed_count = req.allowed_groups.len();
    let inherit = req.inherit_from_parent;
    let folder_name = req.name.clone();
    let folder_scope = req.scope.clone();
    let folder_desc = req.description.clone();

    // Try Vault first if connected
    if vault.any_connected().await {
        let config = FolderConfig {
            allowed_groups: req.allowed_groups,
            description: req.description,
            inherit_from_parent: req.inherit_from_parent,
        };

        match vault
            .put_folder_config(&folder_scope, &folder_name, &config)
            .await
        {
            Ok(()) => {
                let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
                let details = json!({
                    "allowed_groups_count": allowed_count,
                    "inherit_from_parent": inherit,
                })
                .to_string();
                log_ab_event(
                    &database,
                    &admin_email,
                    "create_folder",
                    &folder_scope,
                    &folder_name,
                    None,
                    &ip,
                    Some(&details),
                )
                .await;
                return Ok(StatusCode::CREATED);
            }
            Err(e) => {
                tracing::error!(error = %e, scope = %folder_scope, folder = %folder_name, "Failed to create folder in Vault");
                // Fall through to DB
            }
        }
    }

    // DB backend
    match db::create_ab_folder(&database, &folder_scope, &folder_name, &folder_desc) {
        Ok(_id) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            let details = json!({
                "allowed_groups_count": allowed_count,
                "inherit_from_parent": inherit,
                "backend": "db",
            })
            .to_string();
            log_ab_event(
                &database,
                &admin_email,
                "create_folder",
                &folder_scope,
                &folder_name,
                None,
                &ip,
                Some(&details),
            )
            .await;
            Ok(StatusCode::CREATED)
        }
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint") {
                Err(AppError::Conflict("folder already exists".into()))
            } else {
                tracing::error!(error = %e, scope = %folder_scope, folder = %folder_name, "Failed to create folder in DB");
                Err(AppError::Internal(e.to_string()))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn ab_update_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<UpdateFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let allowed_count = req.allowed_groups.len();
    let inherit = req.inherit_from_parent;
    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        description: req.description,
        inherit_from_parent: req.inherit_from_parent,
    };

    vault.put_folder_config(&scope, &folder, &config).await?;
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "allowed_groups_count": allowed_count,
        "inherit_from_parent": inherit,
    })
    .to_string();
    log_ab_event(
        &database,
        &admin_email,
        "update_folder",
        &scope,
        &folder,
        None,
        &ip,
        Some(&details),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn ab_get_folder_config(
    identity: Option<Extension<AuthIdentity>>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    match vault.get_folder_config(&scope, &folder).await {
        Ok(cfg) => Ok(Json(json!({
            "allowed_groups": cfg.allowed_groups,
            "description": cfg.description,
            "inherit_from_parent": cfg.inherit_from_parent,
        }))),
        Err(crate::vault::VaultError::NotFound) => Ok(Json(json!({
            "allowed_groups": Vec::<String>::new(),
            "description": "",
            "inherit_from_parent": false,
        }))),
        Err(e) => Err(AppError::Vault(e.to_string())),
    }
}

pub async fn ab_delete_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let (subfolders, entries) = vault.delete_folder(&scope, &folder).await?;
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "subfolders_deleted": subfolders,
        "entries_deleted": entries,
    })
    .to_string();
    log_ab_event(
        &database,
        &admin_email,
        "delete_folder",
        &scope,
        &folder,
        None,
        &ip,
        Some(&details),
    )
    .await;
    Ok(Json(json!({
        "ok": true,
        "subfolders_deleted": subfolders,
        "entries_deleted": entries,
    })))
}

#[allow(clippy::too_many_arguments)]
pub async fn ab_create_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    storage_key: Option<Extension<StorageKey>>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<CreateEntryRequest>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let session_type = req.entry.session_type.clone();

    // Try Vault first if connected
    if vault.any_connected().await {
        match vault
            .put_entry(&scope, &folder, &req.name, &req.entry)
            .await
        {
            Ok(()) => {
                let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
                let details = json!({ "type": session_type }).to_string();
                log_ab_event(
                    &database,
                    &admin_email,
                    "create_entry",
                    &scope,
                    &folder,
                    Some(&req.name),
                    &ip,
                    Some(&details),
                )
                .await;
                return Ok(StatusCode::CREATED);
            }
            Err(e) => {
                tracing::error!(error = %e, scope = %scope, folder = %folder, entry = %req.name, "Failed to create entry in Vault");
                // Fall through to DB
            }
        }
    }

    // DB backend
    let folder_id = get_folder_id(&database, &scope, &folder)?;

    // Build protocol_config JSON from entry fields
    let mut config = serde_json::Map::new();
    if let Some(ref v) = req.entry.domain {
        config.insert("domain".into(), json!(v));
    }
    if let Some(ref v) = req.entry.security {
        config.insert("security".into(), json!(v));
    }
    if let Some(v) = req.entry.ignore_cert {
        config.insert("ignore_cert".into(), json!(v));
    }
    if let Some(ref v) = req.entry.url {
        config.insert("url".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_drive {
        config.insert("enable_drive".into(), json!(v));
    }
    if let Some(ref v) = req.entry.auth_pkg {
        config.insert("auth_pkg".into(), json!(v));
    }
    if let Some(ref v) = req.entry.kdc_url {
        config.insert("kdc_url".into(), json!(v));
    }
    if let Some(v) = req.entry.color_depth {
        config.insert("color_depth".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_recording {
        config.insert("enable_recording".into(), json!(v));
    }
    if let Some(v) = req.entry.record_typescript {
        config.insert("record_typescript".into(), json!(v));
    }
    if let Some(ref v) = req.entry.remote_app {
        config.insert("remote_app".into(), json!(v));
    }
    if let Some(ref v) = req.entry.remote_app_dir {
        config.insert("remote_app_dir".into(), json!(v));
    }
    if let Some(ref v) = req.entry.remote_app_args {
        config.insert("remote_app_args".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_gfx {
        config.insert("enable_gfx".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_desktop_composition {
        config.insert("enable_desktop_composition".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_wallpaper {
        config.insert("enable_wallpaper".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_theming {
        config.insert("enable_theming".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_full_window_drag {
        config.insert("enable_full_window_drag".into(), json!(v));
    }
    if let Some(v) = req.entry.force_lossless {
        config.insert("force_lossless".into(), json!(v));
    }
    if let Some(v) = req.entry.enable_h264 {
        config.insert("enable_h264".into(), json!(v));
    }
    if let Some(ref v) = req.entry.banner {
        config.insert("banner".into(), json!(v));
    }
    if let Some(v) = req.entry.prompt_credentials {
        config.insert("prompt_credentials".into(), json!(v));
    }
    if let Some(v) = req.entry.allow_sharing {
        config.insert("allow_sharing".into(), json!(v));
    }
    if let Some(v) = req.entry.auto_open_if_singleton {
        config.insert("auto_open_if_singleton".into(), json!(v));
    }
    if let Some(v) = req.entry.fullscreen_on_connect {
        config.insert("fullscreen_on_connect".into(), json!(v));
    }
    if let Some(v) = req.entry.autohide_side_tabs {
        config.insert("autohide_side_tabs".into(), json!(v));
    }
    if let Some(v) = req.entry.spice_tls {
        config.insert("spice_tls".into(), json!(v));
    }
    if let Some(v) = req.entry.spice_tls_port {
        config.insert("spice_tls_port".into(), json!(v));
    }
    if let Some(ref v) = req.entry.spice_ca_cert {
        config.insert("spice_ca_cert".into(), json!(v));
    }
    if let Some(ref v) = req.entry.spice_cert_subject {
        config.insert("spice_cert_subject".into(), json!(v));
    }
    if let Some(ref v) = req.entry.spice_proxy {
        config.insert("spice_proxy".into(), json!(v));
    }
    if let Some(ref v) = req.entry.proxmox_url {
        config.insert("proxmox_url".into(), json!(v));
    }
    if let Some(ref v) = req.entry.proxmox_node {
        config.insert("proxmox_node".into(), json!(v));
    }
    if let Some(v) = req.entry.proxmox_vmid {
        config.insert("proxmox_vmid".into(), json!(v));
    }
    if let Some(ref v) = req.entry.proxmox_token_id {
        config.insert("proxmox_token_id".into(), json!(v));
    }
    if let Some(v) = req.entry.proxmox_verify_tls {
        config.insert("proxmox_verify_tls".into(), json!(v));
    }
    if let Some(ref v) = req.entry.container_image {
        config.insert("container_image".into(), json!(v));
    }
    if let Some(v) = req.entry.container_cpu_limit {
        config.insert("container_cpu_limit".into(), json!(v));
    }
    if let Some(v) = req.entry.container_memory_limit {
        config.insert("container_memory_limit".into(), json!(v));
    }
    if let Some(v) = req.entry.container_idle_timeout_mins {
        config.insert("container_idle_timeout_mins".into(), json!(v));
    }
    if let Some(ref v) = req.entry.container_username {
        config.insert("container_username".into(), json!(v));
    }
    if let Some(v) = req.entry.max_monitors {
        config.insert("max_monitors".into(), json!(v));
    }
    if let Some(v) = req.entry.max_recordings {
        config.insert("max_recordings".into(), json!(v));
    }
    if let Some(ref v) = req.entry.login_script {
        config.insert("login_script".into(), json!(v));
    }
    if let Some(ref v) = req.entry.autofill {
        config.insert("autofill".into(), json!(v));
    }
    if let Some(ref v) = req.entry.allowed_domains {
        config.insert("allowed_domains".into(), json!(v));
    }
    if let Some(v) = req.entry.disable_copy {
        config.insert("disable_copy".into(), json!(v));
    }
    if let Some(v) = req.entry.disable_paste {
        config.insert("disable_paste".into(), json!(v));
    }

    let entry_id = db::create_ab_entry(
        &database,
        folder_id,
        &req.name,
        req.entry.display_name.as_deref().unwrap_or(""),
        &req.entry.session_type,
        req.entry.hostname.as_deref().unwrap_or(""),
        req.entry.port,
        req.entry.username.as_deref().unwrap_or(""),
        &serde_json::to_string(&config).unwrap_or_else(|_| "{}".into()),
        "",
    )?;

    // Store credentials if present
    let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
    if !encryption_key.is_empty() {
        if let Some(ref password) = req.entry.password {
            let encrypted = crate::crypto::encrypt_value(
                &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                password,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            db::store_ab_credential(&database, entry_id, "password", &encrypted)?;
        }
        if let Some(ref private_key) = req.entry.private_key {
            let encrypted = crate::crypto::encrypt_value(
                &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                private_key,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            db::store_ab_credential(&database, entry_id, "private_key", &encrypted)?;
        }
        if let Some(ref secret) = req.entry.proxmox_token_secret {
            let encrypted = crate::crypto::encrypt_value(
                &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                secret,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            db::store_ab_credential(&database, entry_id, "proxmox_token_secret", &encrypted)?;
        }
        if let Some(ref pw) = req.entry.container_password {
            let encrypted = crate::crypto::encrypt_value(
                &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                    .map_err(|e| AppError::Internal(e.to_string()))?,
                pw,
            )
            .map_err(|e| AppError::Internal(e.to_string()))?;
            db::store_ab_credential(&database, entry_id, "container_password", &encrypted)?;
        }
    }

    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({ "type": session_type, "backend": "db" }).to_string();
    log_ab_event(
        &database,
        &admin_email,
        "create_entry",
        &scope,
        &folder,
        Some(&req.name),
        &ip,
        Some(&details),
    )
    .await;
    Ok(StatusCode::CREATED)
}

#[allow(clippy::too_many_arguments)]
pub async fn ab_update_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(data): Json<AddressBookEntry>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    let merged = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(existing) => {
            let merged_jump_hosts = if let Some(ref new_hops) = data.jump_hosts {
                let old_hops = existing.jump_hosts.as_deref().unwrap_or(&[]);
                let merged: Vec<_> = new_hops
                    .iter()
                    .enumerate()
                    .map(|(i, hop)| {
                        let old = old_hops.get(i);
                        crate::tunnel::JumpHost {
                            hostname: hop.hostname.clone(),
                            port: hop.port,
                            username: hop.username.clone(),
                            password: hop
                                .password
                                .clone()
                                .or_else(|| old.and_then(|o| o.password.clone())),
                            private_key: hop
                                .private_key
                                .clone()
                                .or_else(|| old.and_then(|o| o.private_key.clone())),
                            host_key: hop
                                .host_key
                                .clone()
                                .or_else(|| old.and_then(|o| o.host_key.clone())),
                        }
                    })
                    .collect();
                Some(merged)
            } else {
                data.jump_hosts.clone()
            };

            AddressBookEntry {
                password: data.password.or(existing.password),
                private_key: data.private_key.or(existing.private_key),
                container_password: data.container_password.or(existing.container_password),
                proxmox_token_secret: data.proxmox_token_secret.or(existing.proxmox_token_secret),
                jump_hosts: merged_jump_hosts,
                jump_password: None,
                jump_private_key: None,
                ..data
            }
        }
        Err(_) => data,
    };

    let session_type = merged.session_type.clone();
    vault.put_entry(&scope, &folder, &entry, &merged).await?;
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({ "type": session_type }).to_string();
    log_ab_event(
        &database,
        &admin_email,
        "update_entry",
        &scope,
        &folder,
        Some(&entry),
        &ip,
        Some(&details),
    )
    .await;
    Ok(Json(json!({"ok": true})))
}

pub async fn ab_delete_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    match vault.delete_entry(&scope, &folder, &entry).await {
        Ok(()) => {
            let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
            log_ab_event(
                &database,
                &admin_email,
                "delete_entry",
                &scope,
                &folder,
                Some(&entry),
                &ip,
                None,
            )
            .await;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(VaultError::NotFound) => Err(AppError::Session("entry not found".into())),
        Err(e) => {
            tracing::error!(error = %e, scope = %scope, folder = %folder, entry = %entry, "Failed to delete entry");
            Err(AppError::Vault(e.to_string()))
        }
    }
}

pub(crate) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

fn quick_connect_credential_form(
    scope: &str,
    folder: &str,
    entry: &str,
    session_type: &str,
    username: Option<&str>,
    domain: Option<&str>,
    display_name: Option<&str>,
) -> Response {
    let title = display_name.unwrap_or(entry);
    let user_val = html_escape(username.unwrap_or(""));
    let domain_val = html_escape(domain.unwrap_or(""));
    let domain_display = if session_type == "rdp" {
        "block"
    } else {
        "none"
    };
    let html = format!(
        r##"<!DOCTYPE html>
<html><head><title>Connect — {title}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#1a1a2e;color:#e0e0e0;margin:0;
  display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#16213e;border-radius:12px;padding:32px;width:100%;max-width:400px;
  box-shadow:0 4px 24px rgba(0,0,0,.4)}}
h2{{margin:0 0 4px;color:#fff;font-size:1.3em}}
.sub{{color:#8899aa;font-size:.85em;margin-bottom:20px}}
label{{display:block;color:#aab;font-size:.85em;margin-bottom:4px;margin-top:14px}}
input{{width:100%;padding:10px 12px;border:1px solid #2a3a5e;border-radius:6px;
  background:#0f1629;color:#e0e0e0;font-size:1em}}
input:focus{{outline:none;border-color:#4a6fa5}}
.domain-row{{display:{domain_display}}}
button{{width:100%;margin-top:20px;padding:12px;border:none;border-radius:6px;
  background:#4a6fa5;color:#fff;font-size:1em;cursor:pointer;font-weight:600}}
button:hover{{background:#5a8fbf}}
button:disabled{{opacity:.6;cursor:wait}}
.error{{color:#f66;font-size:.85em;margin-top:12px;display:none}}
</style></head>
<body>
<div class="card">
<h2>{title}</h2>
<div class="sub">{session_type_upper} connection</div>
<form id="cred-form" autocomplete="on"
  data-scope="{scope}" data-folder="{folder}" data-entry="{entry}">
<label for="username">Username</label>
<input id="username" name="username" type="text" value="{user_val}" autocomplete="username" autofocus>
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password">
<div class="domain-row">
<label for="domain">Domain</label>
<input id="domain" name="domain" type="text" value="{domain_val}">
</div>
<button type="submit" id="btn">Connect</button>
<div class="error" id="err"></div>
</form>
</div>
<script>
document.getElementById('cred-form').addEventListener('submit', async function(e) {{
  e.preventDefault();
  const form = e.target;
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  btn.disabled = true;
  btn.textContent = 'Connecting…';
  err.style.display = 'none';
  const apiPath = '/api/addressbook/folders/'
    + encodeURIComponent(form.dataset.scope) + '/'
    + encodeURIComponent(form.dataset.folder) + '/entries/'
    + encodeURIComponent(form.dataset.entry) + '/connect';
  const body = {{
    username: document.getElementById('username').value || undefined,
    password: document.getElementById('password').value || undefined,
    domain: document.getElementById('domain').value || undefined,
    width: window.innerWidth,
    height: window.innerHeight,
    dpi: Math.round(window.devicePixelRatio * 96) || 96,
  }};
  try {{
    const headers = {{'Content-Type': 'application/json'}};
    const apiKey = sessionStorage.getItem('api_key');
    if (apiKey) headers['X-API-Key'] = apiKey;
    const resp = await fetch(apiPath, {{
      method: 'POST',
      headers: headers,
      credentials: 'same-origin',
      body: JSON.stringify(body),
    }});
    if (resp.ok) {{
      const data = await resp.json();
      window.location.href = '/client/' + data.session_id;
    }} else {{
      const data = await resp.json().catch(() => ({{}}));
      throw new Error(data.error || ('HTTP ' + resp.status));
    }}
  }} catch (ex) {{
    err.textContent = ex.message;
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Connect';
  }}
}});
</script>
</body></html>"##,
        title = html_escape(title),
        session_type_upper = session_type.to_uppercase(),
        domain_display = domain_display,
        scope = html_escape(scope),
        folder = html_escape(folder),
        entry = html_escape(entry),
        user_val = user_val,
        domain_val = domain_val,
    );
    (StatusCode::OK, axum::response::Html(html)).into_response()
}

fn quick_connect_error(status: StatusCode, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html><head><title>Connection Error</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:80px auto;padding:0 20px}}
h1{{color:#c00}}a{{color:#06c}}</style></head>
<body><h1>Connection Error</h1><p>{}</p>
<p><a href="/">Return to home page</a></p></body></html>"#,
        html_escape(message)
    );
    (status, axum::response::Html(html)).into_response()
}

#[allow(clippy::too_many_arguments)]
pub async fn quick_connect(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(vault): Extension<VaultState>,
    Extension(oidc_enabled): Extension<super::OidcEnabled>,
    request: axum::extract::Request,
) -> Response {
    let query_string = request.uri().query().unwrap_or("");

    let query: QuickConnectQuery = match serde_urlencoded::from_str(query_string) {
        Ok(q) => q,
        Err(e) => {
            return quick_connect_error(
                StatusCode::BAD_REQUEST,
                &format!("Invalid query parameters: {}", e),
            );
        }
    };

    let id = match identity {
        Some(Extension(ref id)) => id.clone(),
        None => {
            if oidc_enabled.0 {
                let next = format!("/api/connect?{}", query_string);
                let encoded = urlencoding::encode(&next);
                return Redirect::temporary(&format!("/auth/login?next={}", encoded))
                    .into_response();
            }
            return quick_connect_error(
                StatusCode::UNAUTHORIZED,
                "Authentication required. Sign in via SSO or provide an API key.",
            );
        }
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);
    let admin_name = id.display_name().to_string();

    if let (Some(scope), Some(folder), Some(entry)) = (
        query.scope.as_ref(),
        query.folder.as_ref(),
        query.entry.as_ref(),
    ) {
        if !id.has_role("operator") {
            return quick_connect_error(
                StatusCode::FORBIDDEN,
                "Operator role or higher required for address book connections.",
            );
        }

        if !vault.any_connected().await {
            return quick_connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Address book is temporarily unavailable (Vault offline).",
            );
        }

        if check_folder_access(&vault, scope, folder, &id)
            .await
            .is_err()
        {
            return quick_connect_error(StatusCode::FORBIDDEN, "No access to this folder.");
        }

        let ab_entry = match vault.get_entry(scope, folder, entry).await {
            Ok(e) => e,
            Err(VaultError::NotFound) => {
                return quick_connect_error(
                    StatusCode::NOT_FOUND,
                    &format!("Entry '{}' not found in {}/{}.", entry, scope, folder),
                );
            }
            Err(e) => {
                return quick_connect_error(
                    StatusCode::BAD_GATEWAY,
                    &format!("Failed to read address book entry: {}", e),
                );
            }
        };

        let ab_entry = if !crate::vault::entry_credential_variables(&ab_entry).is_empty() {
            let user_email = match &id {
                AuthIdentity::User { email, .. } => Some(email.clone()),
                _ => None,
            };
            if let Some(email) = user_email {
                match vault.get_user_credentials(&email).await {
                    Ok(user_creds) => {
                        match crate::vault::resolve_credential_variables(&ab_entry, &user_creds) {
                            Ok(resolved) => resolved,
                            Err(missing) => {
                                return quick_connect_error(
                                    StatusCode::PRECONDITION_FAILED,
                                    &format!(
                                        "Missing credential variables: {}. Set them in My Credentials.",
                                        missing.join(", ")
                                    ),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to read user credentials from Vault: {}", e);
                        ab_entry
                    }
                }
            } else {
                ab_entry
            }
        } else {
            ab_entry
        };

        let needs_prompt = ab_entry.session_type != "web"
            && (ab_entry.prompt_credentials == Some(true)
                || (ab_entry.password.as_ref().is_none_or(|p| p.is_empty())
                    && ab_entry.private_key.as_ref().is_none_or(|k| k.is_empty())));

        if needs_prompt {
            return quick_connect_credential_form(
                scope,
                folder,
                entry,
                &ab_entry.session_type,
                ab_entry.username.as_deref(),
                ab_entry.domain.as_deref(),
                ab_entry.display_name.as_deref(),
            );
        }

        let session_type = match ab_entry.session_type.as_str() {
            "ssh" => SessionType::Ssh,
            "rdp" => SessionType::Rdp,
            "vnc" => SessionType::Vnc,
            "web" => SessionType::Web,
            other => {
                return quick_connect_error(
                    StatusCode::BAD_REQUEST,
                    &format!("Unknown session type: {}", other),
                );
            }
        };

        let ab_entry_key = format!("{}/{}/{}", scope, folder, entry);
        let create_req = CreateSessionRequest {
            session_type,
            hostname: ab_entry.hostname,
            port: ab_entry.port,
            username: ab_entry.username,
            password: ab_entry.password,
            ignore_cert: ab_entry.ignore_cert,
            max_monitors: ab_entry.max_monitors,
            jump_hosts: ab_entry.jump_hosts,
            jump_host: None,
            jump_port: None,
            jump_username: None,
            jump_password: None,
            jump_private_key: None,
            width: query.width,
            height: query.height,
            dpi: query.dpi,
            banner: ab_entry.banner,
            enable_drive: ab_entry.enable_drive,
            disable_copy: ab_entry.disable_copy,
            disable_paste: ab_entry.disable_paste,
            enable_recording: ab_entry.enable_recording,
            address_book_entry: Some(ab_entry_key),
            address_book_folder: Some(folder.to_string()),
            entry_display_name: ab_entry.display_name.clone(),
            max_recordings: ab_entry.max_recordings,
            allow_sharing: ab_entry.allow_sharing,
            fullscreen_on_connect: ab_entry.fullscreen_on_connect,
            autohide_side_tabs: ab_entry.autohide_side_tabs,
            ssh: Some(SshParams {
                private_key: ab_entry.private_key,
                generate_keypair: None,
                record_typescript: ab_entry.record_typescript,
            }),
            rdp: Some(RdpParams {
                domain: ab_entry.domain,
                security: ab_entry.security,
                auth_pkg: ab_entry.auth_pkg,
                kdc_url: ab_entry.kdc_url,
                kerberos_cache: None,
                remote_app: ab_entry.remote_app,
                remote_app_dir: ab_entry.remote_app_dir,
                remote_app_args: ab_entry.remote_app_args,
                enable_gfx: ab_entry.enable_gfx,
                enable_desktop_composition: ab_entry.enable_desktop_composition,
                enable_wallpaper: ab_entry.enable_wallpaper,
                enable_theming: ab_entry.enable_theming,
                enable_full_window_drag: ab_entry.enable_full_window_drag,
                force_lossless: ab_entry.force_lossless,
                enable_h264: ab_entry.enable_h264,
            }),
            vnc: Some(VncParams {
                color_depth: ab_entry.color_depth,
            }),
            web: Some(WebParams {
                url: ab_entry.url,
                login_script: ab_entry.login_script,
                autofill: ab_entry.autofill,
                allowed_domains: ab_entry.allowed_domains,
            }),
            vdi: Some(VdiParams {
                container_image: ab_entry.container_image,
                container_cpu_limit: ab_entry.container_cpu_limit,
                container_memory_limit: ab_entry.container_memory_limit,
                container_env: ab_entry.container_env,
                container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
                container_username: ab_entry.container_username,
                container_password: ab_entry.container_password,
            }),
            spice: Some(SpiceParams {
                spice_tls: ab_entry.spice_tls,
                spice_tls_port: ab_entry.spice_tls_port,
                spice_ca_cert: ab_entry.spice_ca_cert,
                spice_cert_subject: ab_entry.spice_cert_subject,
                spice_proxy: ab_entry.spice_proxy,
            }),
            proxmox: Some(ProxmoxParams::default()),
        };

        tracing::info!(
            user = %admin_name,
            client_ip = %client_ip,
            scope = %scope,
            folder = %folder,
            entry = %entry,
            "Quick connect (address book)"
        );

        return match manager.create_session(create_req, admin_name).await {
            Ok(info) => {
                Redirect::temporary(&format!("/client/{}", info.session_id)).into_response()
            }
            Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
        };
    }

    if !id.has_role("poweruser") {
        return quick_connect_error(
            StatusCode::FORBIDDEN,
            "Poweruser role or higher required for ad-hoc connections.",
        );
    }

    let session_type = match query.protocol.as_deref() {
        Some("rdp") => SessionType::Rdp,
        Some("vnc") => SessionType::Vnc,
        Some("web") => SessionType::Web,
        Some("ssh") | None => SessionType::Ssh,
        Some(other) => {
            return quick_connect_error(
                StatusCode::BAD_REQUEST,
                &format!("Unknown protocol '{}'. Use ssh, rdp, vnc, or web.", other),
            );
        }
    };

    tracing::info!(
        user = %admin_name,
        client_ip = %client_ip,
        protocol = query.protocol.as_deref().unwrap_or("ssh"),
        hostname = query.hostname.as_deref().unwrap_or("?"),
        "Quick connect (ad-hoc)"
    );

    let create_req = CreateSessionRequest {
        session_type,
        hostname: query.hostname,
        port: query.port,
        username: query.username,
        width: query.width,
        height: query.height,
        dpi: query.dpi,
        web: Some(WebParams {
            url: query.url,
            ..Default::default()
        }),
        ..Default::default()
    };

    match manager.create_session(create_req, admin_name).await {
        Ok(info) => Redirect::temporary(&format!("/client/{}", info.session_id)).into_response(),
        Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}
