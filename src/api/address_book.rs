use super::{AppState, StorageBackend, StorageKey, VaultBackends, VaultState};
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::rbac;
use crate::session::{
    CreateSessionRequest, ProxmoxParams, RdpParams, SessionType, SpiceParams, SshParams, VdiParams,
    VncParams, WebParams,
};
use crate::vault::{AddressBookEntry, VaultError};
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
pub(crate) fn resolve_encryption_key(storage_key: Option<&StorageKey>) -> String {
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
/// Groups of a folder row, as a cleaned list.
fn folder_groups(folder: &db::AbFolder) -> Vec<String> {
    folder
        .allowed_groups
        .split(',')
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect()
}

pub(crate) fn folder_allowed_for_user(
    db: &Db,
    scope: &str,
    folder_name: &str,
    user_groups: &[String],
) -> bool {
    if user_groups.is_empty() {
        return false;
    }
    // Walk up the slash-path hierarchy: a folder without its own ACL
    // inherits from its nearest ancestor that has one (`inherit_from_parent`
    // is the default for migrated/imported trees, so the subtree must not
    // silently open up). A folder WITH an ACL is evaluated directly.
    let mut current = folder_name.to_string();
    loop {
        let folder = match db::get_ab_folder(db, scope, &current) {
            Ok(f) => f,
            // Missing folder mid-walk (deleted concurrently) — deny.
            Err(_) => return false,
        };
        let groups = folder_groups(&folder);
        if !groups.is_empty() {
            return groups.iter().any(|g| user_groups.iter().any(|ug| ug == g));
        }
        if current == folder_name || folder.inherit_from_parent {
            // The folder itself defines no ACL: fall back to entry-level
            // groups (legacy/import data stored allowed_groups per entry).
            if current == folder_name {
                match db::list_ab_entries(db, folder.id) {
                    Ok(entries) => {
                        if entries.iter().all(|entry| {
                            let groups: Vec<String> = entry
                                .allowed_groups
                                .split(',')
                                .map(|g| g.trim().to_string())
                                .filter(|g| !g.is_empty())
                                .collect();
                            if groups.is_empty() {
                                true
                            } else {
                                groups.iter().any(|g| user_groups.iter().any(|ug| ug == g))
                            }
                        }) {
                            return true;
                        }
                    }
                    Err(_) => return false,
                }
            }
            // If the target folder has no ACL and no entry grants access,
            // continue up the tree only when inheritance is enabled.
            if !folder.inherit_from_parent {
                return false;
            }
        }
        match current.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
            _ => return false,
        }
    }
}

/// Get folder ID by scope and name from DB.
fn get_folder_id(db: &Db, scope: &str, name: &str) -> Result<i64, AppError> {
    let folder = db::get_ab_folder(db, scope, name)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    Ok(folder.id)
}

/// Whether address book credentials live in Vault: config `[storage].backend`
/// is `"vault"` AND at least one Vault backend is currently connected. Folder
/// and entry metadata always live in the DB regardless.
pub(crate) async fn vault_credentials_enabled(
    backend: Option<&StorageBackend>,
    vault: &VaultState,
) -> bool {
    backend.map(|b| b.0 == "vault").unwrap_or(false) && vault.any_connected().await
}

/// Reconstruct an `AddressBookEntry` (metadata only, no credentials) from a
/// DB row. Credential fields are left `None`; callers overlay them from the
/// vault copy (vault mode) or the decrypted credential rows (db mode).
fn ab_entry_from_db(row: &db::AbEntry) -> AddressBookEntry {
    let protocol_config: serde_json::Value = serde_json::from_str(&row.protocol_config)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    AddressBookEntry {
        session_type: row.protocol.clone(),
        hostname: Some(row.hostname.clone()),
        port: row.port,
        username: if row.username.is_empty() {
            None
        } else {
            Some(row.username.clone())
        },
        password: None,
        private_key: None,
        display_name: if row.display_name.is_empty() {
            None
        } else {
            Some(row.display_name.clone())
        },
        jump_hosts: protocol_config
            .get("jump_hosts")
            .and_then(|v| serde_json::from_value::<Vec<crate::tunnel::JumpHost>>(v.clone()).ok()),
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
        proxmox_token_secret: None,
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
        container_password: None,
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
}

/// Build the public `EntryInfo` for a DB entry, with `has_credentials`
/// reflecting whether credential rows exist (values stay encrypted).
fn entry_info_from_db_row(database: &Db, row: &db::AbEntry) -> crate::vault::EntryInfo {
    let ab_entry = ab_entry_from_db(row);
    let mut info = crate::vault::EntryInfo::from((row.name.as_str(), &ab_entry));
    info.has_credentials = db::list_ab_credentials(database, row.id)
        .map(|creds| {
            creds
                .iter()
                .any(|c| c.credential_type == "password" || c.credential_type == "private_key")
        })
        .unwrap_or(false);
    info.allowed_groups = row.allowed_groups.clone();
    info
}

/// Serialize the non-credential entry fields into the `protocol_config` JSON
/// column. Credential fields are stored separately (DB credentials table in
/// db mode, vault copy in vault mode).
pub(crate) fn build_protocol_config(
    entry: &AddressBookEntry,
) -> serde_json::Map<String, serde_json::Value> {
    let mut config = serde_json::Map::new();
    // Jump hosts are part of the routing config: persist them so the DB row
    // round-trips them (they were silently dropped before).
    if let Some(ref hops) = entry.jump_hosts {
        config.insert("jump_hosts".into(), json!(hops));
    }
    if let Some(ref v) = entry.domain {
        config.insert("domain".into(), json!(v));
    }
    if let Some(ref v) = entry.security {
        config.insert("security".into(), json!(v));
    }
    if let Some(v) = entry.ignore_cert {
        config.insert("ignore_cert".into(), json!(v));
    }
    if let Some(ref v) = entry.url {
        config.insert("url".into(), json!(v));
    }
    if let Some(v) = entry.enable_drive {
        config.insert("enable_drive".into(), json!(v));
    }
    if let Some(ref v) = entry.auth_pkg {
        config.insert("auth_pkg".into(), json!(v));
    }
    if let Some(ref v) = entry.kdc_url {
        config.insert("kdc_url".into(), json!(v));
    }
    if let Some(v) = entry.color_depth {
        config.insert("color_depth".into(), json!(v));
    }
    if let Some(v) = entry.enable_recording {
        config.insert("enable_recording".into(), json!(v));
    }
    if let Some(v) = entry.record_typescript {
        config.insert("record_typescript".into(), json!(v));
    }
    if let Some(ref v) = entry.remote_app {
        config.insert("remote_app".into(), json!(v));
    }
    if let Some(ref v) = entry.remote_app_dir {
        config.insert("remote_app_dir".into(), json!(v));
    }
    if let Some(ref v) = entry.remote_app_args {
        config.insert("remote_app_args".into(), json!(v));
    }
    if let Some(v) = entry.enable_gfx {
        config.insert("enable_gfx".into(), json!(v));
    }
    if let Some(v) = entry.enable_desktop_composition {
        config.insert("enable_desktop_composition".into(), json!(v));
    }
    if let Some(v) = entry.enable_wallpaper {
        config.insert("enable_wallpaper".into(), json!(v));
    }
    if let Some(v) = entry.enable_theming {
        config.insert("enable_theming".into(), json!(v));
    }
    if let Some(v) = entry.enable_full_window_drag {
        config.insert("enable_full_window_drag".into(), json!(v));
    }
    if let Some(v) = entry.force_lossless {
        config.insert("force_lossless".into(), json!(v));
    }
    if let Some(v) = entry.enable_h264 {
        config.insert("enable_h264".into(), json!(v));
    }
    if let Some(ref v) = entry.banner {
        config.insert("banner".into(), json!(v));
    }
    if let Some(v) = entry.prompt_credentials {
        config.insert("prompt_credentials".into(), json!(v));
    }
    if let Some(v) = entry.allow_sharing {
        config.insert("allow_sharing".into(), json!(v));
    }
    if let Some(v) = entry.auto_open_if_singleton {
        config.insert("auto_open_if_singleton".into(), json!(v));
    }
    if let Some(v) = entry.fullscreen_on_connect {
        config.insert("fullscreen_on_connect".into(), json!(v));
    }
    if let Some(v) = entry.autohide_side_tabs {
        config.insert("autohide_side_tabs".into(), json!(v));
    }
    if let Some(v) = entry.spice_tls {
        config.insert("spice_tls".into(), json!(v));
    }
    if let Some(v) = entry.spice_tls_port {
        config.insert("spice_tls_port".into(), json!(v));
    }
    if let Some(ref v) = entry.spice_ca_cert {
        config.insert("spice_ca_cert".into(), json!(v));
    }
    if let Some(ref v) = entry.spice_cert_subject {
        config.insert("spice_cert_subject".into(), json!(v));
    }
    if let Some(ref v) = entry.spice_proxy {
        config.insert("spice_proxy".into(), json!(v));
    }
    if let Some(ref v) = entry.proxmox_url {
        config.insert("proxmox_url".into(), json!(v));
    }
    if let Some(ref v) = entry.proxmox_node {
        config.insert("proxmox_node".into(), json!(v));
    }
    if let Some(v) = entry.proxmox_vmid {
        config.insert("proxmox_vmid".into(), json!(v));
    }
    if let Some(ref v) = entry.proxmox_token_id {
        config.insert("proxmox_token_id".into(), json!(v));
    }
    if let Some(v) = entry.proxmox_verify_tls {
        config.insert("proxmox_verify_tls".into(), json!(v));
    }
    if let Some(ref v) = entry.container_image {
        config.insert("container_image".into(), json!(v));
    }
    if let Some(v) = entry.container_cpu_limit {
        config.insert("container_cpu_limit".into(), json!(v));
    }
    if let Some(v) = entry.container_memory_limit {
        config.insert("container_memory_limit".into(), json!(v));
    }
    if let Some(v) = entry.container_idle_timeout_mins {
        config.insert("container_idle_timeout_mins".into(), json!(v));
    }
    if let Some(ref v) = entry.container_username {
        config.insert("container_username".into(), json!(v));
    }
    if let Some(v) = entry.max_monitors {
        config.insert("max_monitors".into(), json!(v));
    }
    if let Some(v) = entry.max_recordings {
        config.insert("max_recordings".into(), json!(v));
    }
    if let Some(ref v) = entry.login_script {
        config.insert("login_script".into(), json!(v));
    }
    if let Some(ref v) = entry.autofill {
        config.insert("autofill".into(), json!(v));
    }
    if let Some(ref v) = entry.allowed_domains {
        config.insert("allowed_domains".into(), json!(v));
    }
    if let Some(v) = entry.disable_copy {
        config.insert("disable_copy".into(), json!(v));
    }
    if let Some(v) = entry.disable_paste {
        config.insert("disable_paste".into(), json!(v));
    }
    config
}

/// Upsert an encrypted credential, or delete the stored one when `value` is
/// an explicit empty string (clear semantics). `None` callers should not use
/// this helper — omitted fields keep their stored value.
fn upsert_or_clear_credential(
    database: &Db,
    entry_id: i64,
    credential_type: &str,
    value: &str,
    encryption_key: &str,
) -> Result<(), AppError> {
    if value.is_empty() {
        db::delete_ab_credential(database, entry_id, credential_type)
            .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(());
    }
    let encrypted = crate::crypto::encrypt_value(
        &crate::crypto::EncryptionKey::from_hex(encryption_key)
            .map_err(|e| AppError::Internal(e.to_string()))?,
        value,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;
    db::store_ab_credential(database, entry_id, credential_type, &encrypted)
        .map_err(|e| AppError::Internal(e.to_string()))
}

/// Whether any credential field is present in a create/update payload.
fn has_credential_fields(entry: &AddressBookEntry) -> bool {
    entry.password.is_some()
        || entry.private_key.is_some()
        || entry.proxmox_token_secret.is_some()
        || entry.container_password.is_some()
}

/// Overlay decrypted DB credential rows onto an entry (db mode).
fn apply_db_credentials(
    database: &Db,
    entry_id: i64,
    storage_key: Option<&StorageKey>,
    ab_entry: &mut AddressBookEntry,
) -> Result<(), AppError> {
    let encryption_key = resolve_encryption_key(storage_key);
    let creds = db::list_ab_credentials(database, entry_id).unwrap_or_default();
    for cred in &creds {
        let decrypted = if !encryption_key.is_empty() {
            let key = crate::crypto::EncryptionKey::from_hex(&encryption_key)
                .map_err(|e| AppError::Internal(format!("invalid encryption key: {e}")))?;
            crate::crypto::decrypt_value(&key, &cred.credential_data).map_err(|e| {
                tracing::error!(entry_id, "failed to decrypt credential: {e}");
                AppError::Internal("failed to decrypt credential — wrong key?".into())
            })?
        } else {
            return Err(AppError::Internal(
                "Encryption key required but not configured. Set [storage].encryption_key.".into(),
            ));
        };
        match cred.credential_type.as_str() {
            "password" => ab_entry.password = Some(decrypted),
            "private_key" => ab_entry.private_key = Some(decrypted),
            "proxmox_token_secret" => ab_entry.proxmox_token_secret = Some(decrypted),
            "container_password" => ab_entry.container_password = Some(decrypted),
            _ => {}
        }
    }
    Ok(())
}

/// Overlay the credential fields from a vault copy onto a DB entry (vault
/// mode). The vault copy's metadata is ignored — only the credential fields
/// are read back.
fn apply_vault_credentials(vault_entry: &AddressBookEntry, ab_entry: &mut AddressBookEntry) {
    ab_entry.password = vault_entry.password.clone();
    ab_entry.private_key = vault_entry.private_key.clone();
    ab_entry.proxmox_token_secret = vault_entry.proxmox_token_secret.clone();
    ab_entry.container_password = vault_entry.container_password.clone();
    // Routing config (jump hosts) also lives on the vault copy.
    ab_entry.jump_hosts = vault_entry.jump_hosts.clone();
}

/// DB-side folder access check (metadata always lives in the DB now).
/// Admins bypass; everyone else needs a folder the DB grants access to.
fn check_folder_access_db(
    db: &Db,
    scope: &str,
    folder: &str,
    identity: &AuthIdentity,
) -> Result<(), AppError> {
    if identity.has_role("admin") {
        return Ok(());
    }
    if folder_allowed_for_user(db, scope, folder, identity.groups()) {
        Ok(())
    } else {
        Err(AppError::Forbidden("no access to this folder".into()))
    }
}

/// Entry-level ACL: an entry with `allowed_groups` set is only usable by
/// members of one of those groups, even inside an accessible folder.
fn check_entry_access_db(
    db: &Db,
    folder_id: i64,
    entry_name: &str,
    identity: &AuthIdentity,
) -> Result<(), AppError> {
    if identity.has_role("admin") {
        return Ok(());
    }
    let entry = db::get_ab_entry(db, folder_id, entry_name)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;
    let groups: Vec<String> = entry
        .allowed_groups
        .split(',')
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    if groups.is_empty()
        || groups
            .iter()
            .any(|g| identity.groups().iter().any(|ug| ug == g))
    {
        Ok(())
    } else {
        Err(AppError::Forbidden("no access to this entry".into()))
    }
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
    /// Comma-separated group names allowed to use this entry. Flattened
    /// siblings of `entry` are ignored by serde when absent.
    #[serde(default)]
    pub allowed_groups: Option<Vec<String>>,
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

/// Update payload: the flattened `AddressBookEntry` plus optional
/// `allowed_groups` (serde keeps the wire format backward-compatible).
#[derive(Deserialize, Clone)]
pub struct UpdateEntryRequest {
    #[serde(default)]
    pub allowed_groups: Option<Vec<String>>,
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

/// DB-based descendant walk: true if the folder itself grants access, or any
/// DB folder with a slash-path under it does (mirrors the vault subtree walk).
fn folder_or_descendant_accessible_db(
    db: &Db,
    scope: &str,
    path: &str,
    user_groups: &[String],
) -> bool {
    if folder_allowed_for_user(db, scope, path, user_groups) {
        return true;
    }
    if let Ok(folders) = db::list_ab_folders(db, Some(scope)) {
        let prefix = format!("{}/", path);
        for folder in folders {
            if folder.name.starts_with(&prefix)
                && folder_or_descendant_accessible_db(db, scope, &folder.name, user_groups)
            {
                return true;
            }
        }
    }
    false
}

pub async fn ab_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let db_folders =
        db::list_ab_folders(&database, None).map_err(|e| AppError::Internal(e.to_string()))?;
    let user_groups = id.groups();
    let mut visible = Vec::new();
    for folder in &db_folders {
        if id.has_role("admin")
            || folder_allowed_for_user(&database, &folder.scope, &folder.name, user_groups)
        {
            visible.push(serde_json::json!({
                "name": folder.name,
                "scope": folder.scope,
                "description": folder.description,
                "path": folder.name,
                "has_children": db_folders
                    .iter()
                    .any(|g| g.name.starts_with(&format!("{}/", folder.name))),
            }));
        }
    }
    Ok(Json(json!(visible)))
}

pub async fn ab_list_subfolders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    check_folder_access_db(&database, &scope, &folder, id)?;

    // DB folders are flat rows; hierarchy is expressed through slash-paths
    // (`Clients/Acme` is a subfolder of `Clients`), mirroring the vault path
    // layout. Only immediate children are returned.
    let folders = db::list_ab_folders(&database, Some(&scope))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let prefix = format!("{}/", folder);

    let mut subfolders: Vec<crate::vault::FolderInfo> = folders
        .iter()
        .filter(|f| {
            f.name
                .strip_prefix(&prefix)
                .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
        })
        .map(|f| crate::vault::FolderInfo {
            name: f.name[prefix.len()..].to_string(),
            description: f.description.clone(),
            scope: f.scope.clone(),
            path: Some(f.name.clone()),
            has_children: Some(
                folders
                    .iter()
                    .any(|g| g.name.starts_with(&format!("{}/", f.name))),
            ),
        })
        .collect();

    if !id.has_role("admin") {
        let user_groups = id.groups();
        subfolders.retain(|sf| {
            let path = sf.path.clone().unwrap_or_else(|| sf.name.clone());
            folder_or_descendant_accessible_db(&database, &scope, &path, user_groups)
        });
    }

    Ok(Json(json!(subfolders)))
}

pub async fn ab_list_all(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let db_folders =
        db::list_ab_folders(&database, None).map_err(|e| AppError::Internal(e.to_string()))?;
    let user_groups = id.groups();

    let mut result = Vec::new();
    for folder in &db_folders {
        if !id.has_role("admin")
            && !folder_allowed_for_user(&database, &folder.scope, &folder.name, user_groups)
        {
            continue;
        }

        let has_children = db_folders
            .iter()
            .any(|f| f.scope == folder.scope && f.name.starts_with(&format!("{}/", folder.name)));

        let mut entries = Vec::new();
        if let Ok(db_entries) = db::list_ab_entries(&database, folder.id) {
            for entry in &db_entries {
                entries.push(entry_info_from_db_row(&database, entry));
            }
        }

        result.push(json!({
            "name": folder.name,
            "scope": folder.scope,
            "path": folder.name,
            "has_children": has_children,
            "description": folder.description,
            "allowed_groups": serde_json::Value::Null,
            "entries": entries,
        }));
    }

    Ok(Json(
        json!({"folders": result, "unavailable_scopes": Vec::<String>::new()}),
    ))
}

pub async fn ab_search_index(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let user_groups = id.groups();
    let is_admin = id.has_role("admin");

    let all_folders =
        db::list_ab_folders(&database, None).map_err(|e| AppError::Internal(e.to_string()))?;

    // BFS over the slash-path folder tree (top-level = no `/` in the name).
    let mut queue: Vec<(String, String)> = all_folders
        .iter()
        .filter(|f| !f.name.contains('/'))
        .map(|f| (f.scope.clone(), f.name.clone()))
        .collect();
    let mut emitted = Vec::new();

    while let Some((scope, path)) = queue.pop() {
        for child in all_folders.iter().filter(|f| {
            f.scope == scope
                && f.name
                    .strip_prefix(&format!("{}/", path))
                    .is_some_and(|rest| !rest.contains('/'))
        }) {
            queue.push((scope.clone(), child.name.clone()));
        }

        if !is_admin && !folder_allowed_for_user(&database, &scope, &path, user_groups) {
            continue;
        }

        let folder_rec = match db::get_ab_folder(&database, &scope, &path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let db_entries = match db::list_ab_entries(&database, folder_rec.id) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in &db_entries {
            emitted.push(json!({
                "scope": scope,
                "folder_path": path,
                "entry": entry_info_from_db_row(&database, entry),
            }));
        }
    }

    Ok(Json(json!({"entries": emitted})))
}

pub async fn ab_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault("address book unavailable".into()));
    }

    check_folder_access_db(&database, &scope, &folder, id)?;

    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;

    let db_entries = db::list_ab_entries(&database, folder_rec.id)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let mut entries = Vec::new();
    for entry in &db_entries {
        entries.push(entry_info_from_db_row(&database, entry));
    }

    Ok(Json(json!(entries)))
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
    backend: Option<Extension<StorageBackend>>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault("address book unavailable".into()));
    }

    check_folder_access_db(&database, &scope, &folder, &id)?;

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
                    "No permission to connect to this entry. Ask an administrator to grant your group Connect access to it.".into(),
                ));
            }
        }
    }

    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;

    check_entry_access_db(&database, folder_rec.id, &entry, &id)?;

    // Metadata always comes from the DB.
    let mut ab_entry = ab_entry_from_db(&entry_rec);

    if vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await {
        // Credentials live in Vault: read only the credential fields back
        // from the vault copy; its metadata is ignored.
        match vault.get_entry(&scope, &folder, &entry).await {
            Ok(vault_entry) => apply_vault_credentials(&vault_entry, &mut ab_entry),
            // The DB entry exists but has no vault copy yet (e.g. the
            // backend was switched to vault after DB-mode use, or the copy
            // was never written). Fall back to the DB credential rows so the
            // entry stays reachable; a genuinely missing entry was caught by
            // the DB lookup above.
            Err(VaultError::NotFound) => apply_db_credentials(
                &database,
                entry_rec.id,
                storage_key.as_ref().map(|Extension(k)| k),
                &mut ab_entry,
            )?,
            Err(e) => return Err(AppError::Vault(e.to_string())),
        }
    } else {
        // Credentials live in the DB: decrypt the stored credential rows.
        apply_db_credentials(
            &database,
            entry_rec.id,
            storage_key.as_ref().map(|Extension(k)| k),
            &mut ab_entry,
        )?;
    }

    // Per-user preset fallback: entries without their own password use the
    // user's preset credentials (set on the profile page). This covers
    // rotating-password setups where shared entry credentials are left blank.
    if ab_entry.password.as_deref().map_or(true, |p| p.is_empty()) {
        let user_email = match &id {
            AuthIdentity::User { email, .. } => Some(email.clone()),
            _ => None,
        };
        if let Some(email) = user_email {
            if let Ok(user) = db::get_user_by_email(&database, &email) {
                if let Ok(Some((preset_username, preset_password_enc))) =
                    db::get_user_preset_credentials(&database, user.id)
                {
                    if !preset_password_enc.is_empty() {
                        let key_hex = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
                        if !key_hex.is_empty() {
                            if let Ok(key) = crate::crypto::EncryptionKey::from_hex(&key_hex) {
                                if let Ok(pw) =
                                    crate::crypto::decrypt_value(&key, &preset_password_enc)
                                {
                                    if ab_entry.username.as_deref().map_or(true, |u| u.is_empty())
                                        && !preset_username.is_empty()
                                    {
                                        ab_entry.username = Some(preset_username);
                                    }
                                    ab_entry.password = Some(pw);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Login credential pass-through: with [auth] pass_login_credentials the
    // user's login password (LDAP/database/etc.) is reused for entries that
    // carry no credentials. Applies only when the entry and the preset are
    // both empty, and only within the login TTL.
    if ab_entry.password.as_deref().map_or(true, |p| p.is_empty())
        && manager
            .config()
            .auth
            .as_ref()
            .map(|a| a.pass_login_credentials)
            .unwrap_or(false)
    {
        let user_email = match &id {
            AuthIdentity::User { email, .. } => Some(email.clone()),
            _ => None,
        };
        if let Some(email) = user_email {
            if let Ok(user) = db::get_user_by_email(&database, &email) {
                if let Ok(Some((login_username, login_password_enc, expires_at))) =
                    db::get_login_credentials(&database, user.id)
                {
                    let now = chrono::Utc::now().to_rfc3339();
                    if expires_at > now && !login_password_enc.is_empty() {
                        let key_hex = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
                        if !key_hex.is_empty() {
                            if let Ok(key) = crate::crypto::EncryptionKey::from_hex(&key_hex) {
                                if let Ok(pw) =
                                    crate::crypto::decrypt_value(&key, &login_password_enc)
                                {
                                    if ab_entry.username.as_deref().map_or(true, |u| u.is_empty())
                                        && !login_username.is_empty()
                                    {
                                        ab_entry.username = Some(login_username);
                                    }
                                    ab_entry.password = Some(pw);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

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
    Json(req): Json<CreateFolderRequest>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let allowed_count = req.allowed_groups.len();
    let inherit = req.inherit_from_parent;
    let folder_name = req.name.clone();
    let folder_scope = req.scope.clone();

    // Folders always live in the DB; allowed_groups / inherit_from_parent
    // are persisted on the folder row and also recorded in the audit event.
    match db::create_ab_folder(
        &database,
        &folder_scope,
        &folder_name,
        &req.description,
        &req.allowed_groups.join(","),
        req.inherit_from_parent,
    ) {
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
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<UpdateFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    // Folders always live in the DB; description and ACLs are persisted on
    // the folder row.
    let changed = db::update_ab_folder(
        &database,
        &scope,
        &folder,
        &req.description,
        &req.allowed_groups.join(","),
        req.inherit_from_parent,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;
    if !changed {
        return Err(AppError::Internal("folder not found".into()));
    }

    let allowed_count = req.allowed_groups.len();
    let inherit = req.inherit_from_parent;
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
    Extension(database): Extension<Db>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    // Folders always live in the DB; ACLs come from the folder row.
    match db::get_ab_folder(&database, &scope, &folder) {
        Ok(folder_rec) => Ok(Json(json!({
            "allowed_groups": folder_rec
                .allowed_groups
                .split(',')
                .map(|g| g.trim().to_string())
                .filter(|g| !g.is_empty())
                .collect::<Vec<String>>(),
            "description": folder_rec.description,
            "inherit_from_parent": folder_rec.inherit_from_parent,
        }))),
        Err(e) => Err(AppError::NotFound(format!("folder not found: {}", e))),
    }
}

pub async fn ab_delete_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    backend: Option<Extension<StorageBackend>>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    // The folder itself must exist.
    db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;

    let folders = db::list_ab_folders(&database, Some(&scope))
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let prefix = format!("{}/", folder);
    let sub_paths: Vec<String> = folders
        .iter()
        .filter(|f| f.name.starts_with(&prefix))
        .map(|f| f.name.clone())
        .collect();

    // Count entries across the subtree, then delete every folder row (their
    // entries/credentials cascade via the FK).
    let mut entry_count = 0usize;
    for path in sub_paths.iter().chain(std::iter::once(&folder)) {
        if let Ok(f) = db::get_ab_folder(&database, &scope, path) {
            entry_count += db::list_ab_entries(&database, f.id)
                .map(|e| e.len())
                .unwrap_or(0);
        }
    }
    for path in &sub_paths {
        db::delete_ab_folder(&database, &scope, path)
            .map_err(|e| AppError::Internal(e.to_string()))?;
    }
    db::delete_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let subfolder_count = sub_paths.len();

    // DB subtree is gone — only now remove the vault credential copies
    // (best-effort: a vault failure must not undo the DB delete).
    if vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await {
        if let Err(e) = vault.delete_folder(&scope, &folder).await {
            tracing::warn!(
                "folder deleted from DB but vault cleanup failed for '{}': {}",
                folder,
                e
            );
        }
    }
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "subfolders_deleted": subfolder_count,
        "entries_deleted": entry_count,
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
        "subfolders_deleted": subfolder_count,
        "entries_deleted": entry_count,
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
    backend: Option<Extension<StorageBackend>>,
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<CreateEntryRequest>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let session_type = req.entry.session_type.clone();
    let vault_mode =
        vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await;

    // Metadata always lives in the DB.
    let folder_id = get_folder_id(&database, &scope, &folder)?;

    // No encryption key in db mode means credentials would be silently
    // dropped — fail loudly instead of pretending the password was saved.
    // Checked BEFORE the row is inserted so a rejected create leaves no
    // orphan entry behind.
    if !vault_mode
        && resolve_encryption_key(storage_key.as_ref().map(|k| &k.0)).is_empty()
        && has_credential_fields(&req.entry)
    {
        return Err(AppError::Validation(
            "no [storage].encryption_key / PERSEA_STORAGE_KEY configured —              credentials cannot be stored; set a key first"
                .into(),
        ));
    }

    let config = build_protocol_config(&req.entry);
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
        &req.allowed_groups
            .as_ref()
            .map(|g| g.join(","))
            .unwrap_or_default(),
    )
    .map_err(|e| {
        use rusqlite::ErrorCode;
        if matches!(
            e,
            rusqlite::Error::SqliteFailure(ref f, _)
                if f.code == ErrorCode::ConstraintViolation
        ) {
            AppError::Conflict("an entry with this name already exists".into())
        } else {
            AppError::Internal(e.to_string())
        }
    })?;

    if vault_mode {
        // Credentials live in Vault: write the full entry (its metadata is
        // ignored on read — only the credential fields are used).
        if let Err(e) = vault
            .put_entry(&scope, &folder, &req.name, &req.entry)
            .await
        {
            // Roll back the DB row so the entry doesn't linger credential-less.
            let _ = db::delete_ab_entry(&database, entry_id);
            return Err(AppError::Vault(e.to_string()));
        }
    } else {
        // Credentials live in the DB: encrypt and store the provided fields.
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
    }

    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let details = json!({
        "type": session_type,
        "backend": if vault_mode { "vault" } else { "db" },
    })
    .to_string();
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
    storage_key: Option<Extension<StorageKey>>,
    backend: Option<Extension<StorageBackend>>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(data): Json<UpdateEntryRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let vault_mode =
        vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await;

    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;

    // Same guard as create: db mode without a key cannot store credentials.
    if !vault_mode
        && resolve_encryption_key(storage_key.as_ref().map(|k| &k.0)).is_empty()
        && has_credential_fields(&data.entry)
    {
        return Err(AppError::Validation(
            "no [storage].encryption_key / PERSEA_STORAGE_KEY configured —              credentials cannot be stored; set a key first"
                .into(),
        ));
    }

    if vault_mode {
        // Credentials live in Vault: merge the credential fields with the
        // existing vault copy (keeps credentials when the payload omits
        // them), then rewrite the copy.
        let payload = data.clone();
        let merged = match vault.get_entry(&scope, &folder, &entry).await {
            Ok(existing) => {
                let merged_jump_hosts = if let Some(ref new_hops) = payload.entry.jump_hosts {
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
                    payload.entry.jump_hosts.clone()
                };

                AddressBookEntry {
                    password: payload.entry.password.or(existing.password),
                    private_key: payload.entry.private_key.or(existing.private_key),
                    container_password: payload
                        .entry
                        .container_password
                        .or(existing.container_password),
                    proxmox_token_secret: payload
                        .entry
                        .proxmox_token_secret
                        .or(existing.proxmox_token_secret),
                    jump_hosts: merged_jump_hosts,
                    jump_password: None,
                    jump_private_key: None,
                    ..payload.entry
                }
            }
            // A missing vault copy (e.g. after a db→vault backend switch)
            // behaves like an empty copy: write the payload as-is. Any OTHER
            // read failure must not proceed — the put below would overwrite
            // the stored credentials with `None`s.
            Err(VaultError::NotFound) => payload.entry,
            Err(e) => return Err(AppError::Vault(e.to_string())),
        };
        // Preserve metadata the modal doesn't edit (same merge contract as
        // the DB path): fields omitted from the payload keep their vault
        // values.
        let merged = {
            let existing = vault.get_entry(&scope, &folder, &entry).await.ok();
            let mut full = merged.clone();
            if let Some(existing) = existing {
                if full.domain.is_none() {
                    full.domain = existing.domain.clone();
                }
                if full.jump_hosts.is_none() {
                    full.jump_hosts = existing.jump_hosts.clone();
                }
                if full.display_name.is_none() {
                    full.display_name = existing.display_name.clone();
                }
            }
            full
        };
        vault.put_entry(&scope, &folder, &entry, &merged).await?;
    } else {
        // Credentials live in the DB: upsert the credential fields present
        // in the payload (fields omitted keep their stored value).
        let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
        if !encryption_key.is_empty() {
            // A field sent as an explicit empty string clears the stored
            // credential; `None` keeps it.
            if let Some(ref password) = data.entry.password {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "password",
                    password,
                    &encryption_key,
                )?;
            }
            if let Some(ref private_key) = data.entry.private_key {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "private_key",
                    private_key,
                    &encryption_key,
                )?;
            }
            if let Some(ref secret) = data.entry.proxmox_token_secret {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "proxmox_token_secret",
                    secret,
                    &encryption_key,
                )?;
            }
            if let Some(ref pw) = data.entry.container_password {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "container_password",
                    pw,
                    &encryption_key,
                )?;
            }
        }
    }

    // Metadata always lives in the DB. The edit modal sends only a subset
    // of fields — MERGE over the stored protocol_config so untouched fields
    // (security, jump_hosts, recording, login_script, proxmox_* …) survive
    // the edit. `allowed_groups` omitted by the client keeps the stored
    // value (same keep-on-blank contract as credentials).
    let mut merged_config: serde_json::Map<String, serde_json::Value> = {
        let existing_config: serde_json::Value = serde_json::from_str(&entry_rec.protocol_config)
            .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
        existing_config.as_object().cloned().unwrap_or_default()
    };
    let payload_config = build_protocol_config(&data.entry);
    for (k, v) in payload_config {
        merged_config.insert(k, v);
    }
    let allowed_groups = data
        .allowed_groups
        .as_ref()
        .map(|g| g.join(","))
        .unwrap_or_else(|| entry_rec.allowed_groups.clone());
    db::update_ab_entry(
        &database,
        entry_rec.id,
        data.entry.display_name.as_deref().unwrap_or(""),
        &data.entry.session_type,
        data.entry.hostname.as_deref().unwrap_or(""),
        data.entry.port,
        data.entry.username.as_deref().unwrap_or(""),
        &serde_json::to_string(&merged_config).unwrap_or_else(|_| "{}".into()),
        &allowed_groups,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let session_type = data.entry.session_type.clone();
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let credential_rotated = data.entry.password.is_some();
    let details =
        json!({ "type": session_type, "credential_rotated": credential_rotated }).to_string();
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
    if credential_rotated {
        log_ab_event(
            &database,
            &admin_email,
            "credential_rotated",
            &scope,
            &folder,
            Some(&entry),
            &ip,
            Some(&json!({ "timestamp": chrono::Utc::now().to_rfc3339() }).to_string()),
        )
        .await;
    }
    Ok(Json(json!({"ok": true})))
}

pub async fn ab_delete_entry(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    backend: Option<Extension<StorageBackend>>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
) -> Result<StatusCode, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    // Vault mode: remove the credential copy first — if that fails, nothing
    // is deleted and the error propagates.
    if vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await {
        match vault.delete_entry(&scope, &folder, &entry).await {
            Ok(()) => {}
            Err(VaultError::NotFound) => return Err(AppError::Session("entry not found".into())),
            Err(e) => {
                tracing::error!(error = %e, scope = %scope, folder = %folder, entry = %entry, "Failed to delete entry");
                return Err(AppError::Vault(e.to_string()));
            }
        }
    }

    // Metadata always lives in the DB.
    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;
    db::delete_ab_entry(&database, entry_rec.id).map_err(|e| AppError::Internal(e.to_string()))?;

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
        session_type_upper = html_escape(&session_type.to_uppercase()),
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
    Extension(database): Extension<Db>,
    storage_key: Option<Extension<StorageKey>>,
    backend: Option<Extension<StorageBackend>>,
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

        if !is_db_storage_available(&database) {
            return quick_connect_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Address book is temporarily unavailable.",
            );
        }

        if check_folder_access_db(&database, scope, folder, &id).is_err() {
            return quick_connect_error(StatusCode::FORBIDDEN, "No access to this folder.");
        }

        // Metadata always comes from the DB.
        let folder_rec = match db::get_ab_folder(&database, scope, folder) {
            Ok(f) => f,
            Err(_) => {
                return quick_connect_error(
                    StatusCode::NOT_FOUND,
                    &format!("Folder '{}' not found in {}.", folder, scope),
                );
            }
        };
        let entry_rec = match db::get_ab_entry(&database, folder_rec.id, entry) {
            Ok(e) => e,
            Err(_) => {
                return quick_connect_error(
                    StatusCode::NOT_FOUND,
                    &format!("Entry '{}' not found in {}/{}.", entry, scope, folder),
                );
            }
        };
        let mut ab_entry = ab_entry_from_db(&entry_rec);

        if vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await {
            // Credentials live in Vault: read only the credential fields
            // back from the vault copy; its metadata is ignored.
            match vault.get_entry(scope, folder, entry).await {
                Ok(vault_entry) => apply_vault_credentials(&vault_entry, &mut ab_entry),
                // No vault copy (db→vault switch, or the copy was never
                // written): fall back to the DB credential rows, exactly
                // like ab_connect_entry, so the entry stays reachable.
                Err(VaultError::NotFound) => {
                    if let Err(e) = apply_db_credentials(
                        &database,
                        entry_rec.id,
                        storage_key.as_ref().map(|Extension(k)| k),
                        &mut ab_entry,
                    ) {
                        return quick_connect_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &format!("Failed to read stored credentials: {}", e),
                        );
                    }
                }
                Err(e) => {
                    return quick_connect_error(
                        StatusCode::BAD_GATEWAY,
                        &format!("Failed to read address book entry: {}", e),
                    );
                }
            }
        } else {
            // Credentials live in the DB: decrypt the stored rows.
            if let Err(e) = apply_db_credentials(
                &database,
                entry_rec.id,
                storage_key.as_ref().map(|Extension(k)| k),
                &mut ab_entry,
            ) {
                return e.into_response();
            }
        }

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
