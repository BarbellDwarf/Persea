//! Address book API: folder and entry management, connection start, SSH
//! host-key probing, quick connect, and per-user personal folders.
//!
//! Handlers enforce role gates (operator or higher for reads and connects,
//! admin for writes) plus folder and entry ACLs, and report failures as
//! `AppError` (403 for denied access, 404 for missing folders or entries).
//!
//! Personal folders (`pf_*`) are owner-only: every authenticated user gets
//! their own private folder tree referencing shared address book entries.
//! There is no admin bypass, and a request for another user's folder is
//! indistinguishable from a missing one (404).
use super::{AppState, StorageBackend, StorageKey, VaultState};
use crate::auth::{client_ip, extract_cookie, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::rbac;
use crate::session::{
    CreateSessionRequest, ProxmoxParams, RdpParams, SessionType, SpiceParams, SshParams, VdiParams,
    VncParams, WebParams,
};
use crate::slugify::slugify;
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

/// Session credential forwarding (persea#245): with
/// `[auth] forward_session_credentials`, try the credentials retained at
/// login for the request's own auth session against an entry that still
/// carries no password (after the entry, preset, and login pass-through
/// fallbacks missed). Gated on the per-instance setting (default off),
/// the owning session (the request's `persea_session` cookie must key a
/// retained entry for the same user), and the entry's continued lack of
/// a password. The stored ciphertext is decrypted with the storage key,
/// exactly like the preset and login pass-through fallbacks.
///
/// Returns true when the session credentials were applied. Callers keep
/// that as the marker that this attempt's credentials came from the
/// session, so the attempt path can classify auth failures and decide
/// whether to prompt instead of erroring. Fail-closed: any missing,
/// expired, or user-mismatched entry is simply skipped, as are API-key /
/// token identities, which have no session.
pub(crate) fn apply_session_credentials(
    manager: &AppState,
    database: &Db,
    headers: &axum::http::HeaderMap,
    storage_key: Option<&StorageKey>,
    identity: &AuthIdentity,
    ab_entry: &mut AddressBookEntry,
) -> bool {
    // Gate 1: the per-instance setting (default off).
    if !manager
        .config()
        .auth
        .as_ref()
        .map(|a| a.forward_session_credentials)
        .unwrap_or(false)
    {
        return false;
    }
    // Only credential-less entries: the chain stays entry → preset →
    // login pass-through → session → prompt.
    if !ab_entry.password.as_deref().is_none_or(|p| p.is_empty()) {
        return false;
    }
    // Gate 2: owning session only. The request must present the auth
    // session cookie that retained the credential, and the retained
    // entry must belong to the authenticated user.
    let Some(session_token) = extract_cookie(headers, "persea_session") else {
        return false;
    };
    let AuthIdentity::User { email, .. } = identity else {
        return false; // API key / user-token identities have no session
    };
    let Ok(user) = db::get_user_by_email(database, email) else {
        return false;
    };
    let Some(retained) = manager.session_credentials(&session_token, user.id) else {
        return false;
    };
    // Decrypt with the storage key, like the preset/login fallbacks.
    let key_hex = resolve_encryption_key(storage_key);
    if key_hex.is_empty() {
        return false;
    }
    let Ok(key) = crate::crypto::EncryptionKey::from_hex(&key_hex) else {
        return false;
    };
    let Ok(password) = crate::crypto::decrypt_value(&key, &retained.password_enc) else {
        return false;
    };
    if ab_entry.username.as_deref().is_none_or(|u| u.is_empty()) && !retained.username.is_empty() {
        ab_entry.username = Some(retained.username);
    }
    ab_entry.password = Some(password);
    true
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
    // Own ACL first; a folder without one walks up the slash-path hierarchy
    // while inheritance is enabled (`inherit_from_parent` defaults to true
    // in the API and the schema, so a subtree must not silently open up). A
    // folder whose chain has no ACL is unrestricted — in particular, users
    // without groups (e.g. DB accounts) can see it. The entry-level
    // fallback (legacy/import data stored allowed_groups per entry) runs
    // only after the ancestor walk finds no ACL, so a child folder under a
    // restricted parent stays restricted.
    let mut current = folder_name.to_string();
    loop {
        let folder = match db::get_ab_folder(db, scope, &current) {
            Ok(f) => f,
            // Missing folder mid-walk (deleted concurrently) — deny.
            Err(_) => return false,
        };
        let groups = folder_groups(&folder);
        if !groups.is_empty() {
            // The folder (or an inheriting ancestor) defines an ACL:
            // group-less users are denied, everyone else needs membership.
            if user_groups.is_empty() {
                return false;
            }
            return groups.iter().any(|g| user_groups.iter().any(|ug| ug == g));
        }
        // No ACL here. Inheritance disabled ends the walk: the folder below
        // is unrestricted, so higher ancestors cannot restrict it either.
        if !folder.inherit_from_parent {
            break;
        }
        match current.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => current = parent.to_string(),
            _ => break,
        }
    }
    // No ACL on the folder or any inheriting ancestor: fall back to the
    // entry-level groups. The folder is unrestricted when every entry is
    // ungrouped or matches one of the user's groups.
    match db::get_ab_folder(db, scope, folder_name) {
        Ok(folder) => match db::list_ab_entries(db, folder.id) {
            Ok(entries) => entries.iter().all(|entry| {
                let groups: Vec<String> = entry
                    .allowed_groups
                    .split(',')
                    .map(|g| g.trim().to_string())
                    .filter(|g| !g.is_empty())
                    .collect();
                groups.is_empty() || groups.iter().any(|g| user_groups.iter().any(|ug| ug == g))
            }),
            Err(_) => false,
        },
        Err(_) => false,
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
        description: protocol_config
            .get("description")
            .and_then(|v| v.as_str())
            .map(String::from),
        custom_fields: protocol_config.get("custom_fields").and_then(|v| {
            serde_json::from_value::<std::collections::HashMap<String, String>>(v.clone()).ok()
        }),
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
        auto_size: protocol_config.get("auto_size").and_then(|v| v.as_bool()),
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
    info.created_at = Some(row.created_at.clone());
    info.updated_at = Some(row.updated_at.clone());
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

/// Inject the per-entry PowerShell binary (stored in the `protocol_config`
/// JSON column) into a serialized `EntryInfo` object so the edit modal can
/// prefill the field. `EntryInfo` has no field for it — it is
/// PowerShell-only metadata that lives in the protocol_config JSON.
fn inject_powershell_binary(row: &db::AbEntry, mut value: serde_json::Value) -> serde_json::Value {
    if let Some(obj) = value.as_object_mut() {
        let config: serde_json::Value =
            serde_json::from_str(&row.protocol_config).unwrap_or(serde_json::Value::Null);
        if let Some(bin) = config.get("powershell_binary").and_then(|b| b.as_str()) {
            obj.insert("powershell_binary".into(), json!(bin));
        }
    }
    value
}

/// Serialize the non-credential entry fields into the `protocol_config` JSON
/// column. Credential fields are stored separately (DB credentials table in
/// db mode, vault copy in vault mode).
pub(crate) fn build_protocol_config(
    entry: &AddressBookEntry,
) -> serde_json::Map<String, serde_json::Value> {
    let mut config = serde_json::Map::new();
    // Description is non-credential metadata persisted alongside the other
    // per-protocol fields (no schema/migration needed).
    if let Some(ref v) = entry.description {
        config.insert("description".into(), json!(v));
    }
    // Custom field values (admin-defined fields, feature off by default).
    if let Some(ref fields) = entry.custom_fields {
        config.insert("custom_fields".into(), json!(fields));
    }
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
    if let Some(v) = entry.auto_size {
        config.insert("auto_size".into(), json!(v));
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

/// Whether the PowerShell (SSH) entry type is enabled. Unset toggles
/// default to enabled, matching the runtime gate in session/create.rs
/// (`settings_merge::toggle_enabled(..., true)`).
fn powershell_ssh_enabled(database: &Db) -> bool {
    crate::settings_merge::load_db_settings(database)
        .map(|s| crate::settings_merge::toggle_enabled(&s, "enable_powershell_ssh", true))
        .unwrap_or(true)
}

/// Whether a DB error is a unique-constraint violation. SQLite reports
/// "UNIQUE constraint failed", Postgres/MySQL "duplicate key value
/// violates unique constraint": match case-insensitively so duplicates
/// map to 409 on every backend.
fn is_unique_violation(e: &rusqlite::Error) -> bool {
    let msg = e.to_string().to_lowercase();
    msg.contains("unique constraint") || msg.contains("duplicate key")
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
/// Admins bypass; custom-role holders with global `read` see every folder;
/// everyone else needs a folder the DB grants access to.
fn check_folder_access_db(
    db: &Db,
    scope: &str,
    folder: &str,
    identity: &AuthIdentity,
) -> Result<(), AppError> {
    if identity.has_role("admin") {
        return Ok(());
    }
    if rbac::identity_has_object_permission(
        db,
        identity,
        "connection_group",
        folder,
        rbac::ObjectPermission::Read,
    ) {
        return Ok(());
    }
    if folder_allowed_for_user(db, scope, folder, identity.groups()) {
        Ok(())
    } else {
        Err(AppError::Forbidden("no access to this folder".into()))
    }
}

/// Whether an entry's `allowed_groups` match one of the user's groups.
/// An empty ACL is open to everyone.
fn entry_groups_match(entry: &db::AbEntry, user_groups: &[String]) -> bool {
    let groups: Vec<String> = entry
        .allowed_groups
        .split(',')
        .map(|g| g.trim().to_string())
        .filter(|g| !g.is_empty())
        .collect();
    groups.is_empty() || groups.iter().any(|g| user_groups.iter().any(|ug| ug == g))
}

/// Entry-level ACL: an entry with `allowed_groups` set is only usable by
/// members of one of those groups, even inside an accessible folder.
/// Custom-role holders with global `read` bypass it (the bundle is global —
/// no per-entry object id is resolvable at this layer).
fn check_entry_access_db(
    db: &Db,
    folder_id: i64,
    entry_name: &str,
    identity: &AuthIdentity,
) -> Result<(), AppError> {
    if identity.has_role("admin") {
        return Ok(());
    }
    if rbac::identity_has_custom_permission(db, identity, "read") {
        return Ok(());
    }
    let entry = db::get_ab_entry(db, folder_id, entry_name)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;
    if entry_groups_match(&entry, identity.groups()) {
        Ok(())
    } else {
        Err(AppError::Forbidden("no access to this entry".into()))
    }
}

/// Body for `POST .../entries/{entry}/connect`: overrides applied on
/// top of the stored entry before the session starts.
#[derive(Deserialize)]
pub struct ConnectRequest {
    /// Display width override.
    #[serde(default)]
    pub width: Option<u32>,
    /// Display height override.
    #[serde(default)]
    pub height: Option<u32>,
    /// Display DPI override.
    #[serde(default)]
    pub dpi: Option<u32>,
    /// Banner text shown in the client.
    #[serde(default)]
    pub banner: Option<String>,
    /// Login username override; the stored one wins when absent.
    #[serde(default)]
    pub username: Option<String>,
    /// Login password override; the stored one wins when absent.
    #[serde(default)]
    pub password: Option<String>,
    /// RDP domain override.
    #[serde(default)]
    pub domain: Option<String>,
    /// Connection reason (V09): why this session was started. Stored in
    /// session history; required when `[session] reason_required` is on.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Body for `POST /api/ssh/probe-host-key`.
#[derive(Deserialize)]
pub struct ProbeHostKeyRequest {
    /// Host to probe.
    pub hostname: String,
    /// SSH port; defaults to 22.
    pub port: Option<u16>,
}

/// Body for `POST /api/addressbook/folders`.
#[derive(Deserialize)]
pub struct CreateFolderRequest {
    /// Folder name; slash-separated paths nest folders.
    pub name: String,
    /// Group names allowed to see the folder.
    pub allowed_groups: Vec<String>,
    /// Free-text description.
    #[serde(default)]
    pub description: String,
    /// Address-book scope: `shared` (default) or `instance`.
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Inherit the nearest ancestor ACL when the folder has none.
    /// Defaults to true: a child folder without an ACL must not open up
    /// a restricted parent.
    #[serde(default = "default_inherit")]
    pub inherit_from_parent: bool,
}

/// Body for `PUT /api/addressbook/folders/{scope}/{folder}`.
#[derive(Deserialize)]
pub struct UpdateFolderRequest {
    /// Full replacement ACL; groups absent from this list lose access.
    pub allowed_groups: Vec<String>,
    /// Free-text description.
    #[serde(default)]
    pub description: String,
    /// Inherit the nearest ancestor ACL when the folder has none.
    /// Defaults to true, matching the create default.
    #[serde(default = "default_inherit")]
    pub inherit_from_parent: bool,
}

/// Body for `POST /api/addressbook/folders/{scope}/{folder}/entries`.
#[derive(Deserialize)]
pub struct CreateEntryRequest {
    /// Friendly name; the stored slug identifier is `slugify(name)`.
    pub name: String,
    /// Comma-separated group names allowed to use this entry. Flattened
    /// siblings of `entry` are ignored by serde when absent.
    #[serde(default)]
    pub allowed_groups: Option<Vec<String>>,
    /// PowerShell binary to launch for PowerShell (SSH) entries (default
    /// `pwsh.exe`). Stored in `protocol_config.powershell_binary`; kept as a
    /// sibling of the flattened `entry` because `AddressBookEntry` has no
    /// field for it.
    #[serde(default)]
    pub powershell_binary: Option<String>,
    /// Flattened connection fields (protocol, hostname, port,
    /// credentials) from the `AddressBookEntry` shape.
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

/// Update payload: the flattened `AddressBookEntry` plus optional
/// `allowed_groups` (serde keeps the wire format backward-compatible).
#[derive(Deserialize, Clone)]
pub struct UpdateEntryRequest {
    /// Full replacement ACL; absent means keep the stored list.
    #[serde(default)]
    pub allowed_groups: Option<Vec<String>>,
    /// Friendly name: updates `display_name` ONLY — the stored slug
    /// identifier is immutable (it is the URL path, Vault key, RBAC id and
    /// audit subject).
    #[serde(default)]
    pub name: Option<String>,
    /// PowerShell binary for PowerShell (SSH) entries; stored in
    /// `protocol_config.powershell_binary` (see `CreateEntryRequest`).
    #[serde(default)]
    pub powershell_binary: Option<String>,
    /// Flattened connection fields from the `AddressBookEntry` shape.
    #[serde(flatten)]
    pub entry: AddressBookEntry,
}

/// Query parameters for `GET /api/connect`.
#[derive(Deserialize)]
pub struct QuickConnectQuery {
    /// Ad-hoc session protocol (ssh, rdp, vnc, spice, web).
    pub protocol: Option<String>,
    /// Ad-hoc target host.
    pub hostname: Option<String>,
    /// Ad-hoc target port.
    pub port: Option<u16>,
    /// Ad-hoc login username.
    pub username: Option<String>,
    /// Web-session URL.
    pub url: Option<String>,
    /// Display width.
    pub width: Option<u32>,
    /// Display height.
    pub height: Option<u32>,
    /// Display DPI.
    pub dpi: Option<u32>,
    /// Address book scope, when connecting to a stored entry.
    pub scope: Option<String>,
    /// Address book folder path, when connecting to a stored entry.
    pub folder: Option<String>,
    /// Address book entry slug, when connecting to a stored entry.
    pub entry: Option<String>,
}

fn default_scope() -> String {
    "shared".into()
}

/// Serde default for `inherit_from_parent`: new folders inherit the nearest
/// ancestor ACL, so an API-created child cannot silently open up a
/// restricted parent.
fn default_inherit() -> bool {
    true
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

/// `GET /api/addressbook/folders`: list the top-level folders the
/// caller can see. Requires operator or higher (or a custom role with
/// the `read` permission). Admins see everything; others see folders
/// matching their groups or an RBAC Read grant.
pub async fn ab_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") =>
        {
            id
        }
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
            || rbac::identity_has_object_permission(
                &database,
                id,
                "connection_group",
                &folder.name,
                rbac::ObjectPermission::Read,
            )
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

/// `GET /api/addressbook/folders/{scope}/{folder}/subfolders`: list
/// the immediate children of `folder`. Requires operator or higher;
/// `AppError::Forbidden` when the folder's ACL denies access.
pub async fn ab_list_subfolders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") =>
        {
            id
        }
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
                || rbac::identity_has_object_permission(
                    &database,
                    id,
                    "connection_group",
                    &path,
                    rbac::ObjectPermission::Read,
                )
        });
    }

    Ok(Json(json!(subfolders)))
}

/// `GET /api/addressbook`: the whole visible tree, folders with
/// their entries, for the connections page. Requires operator or
/// higher; inaccessible folders are skipped, not rejected, and entries
/// whose `allowed_groups` exclude the caller are skipped as well.
pub async fn ab_list_all(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") =>
        {
            id
        }
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
            && !rbac::identity_has_object_permission(
                &database,
                id,
                "connection_group",
                &folder.name,
                rbac::ObjectPermission::Read,
            )
        {
            continue;
        }

        let has_children = db_folders
            .iter()
            .any(|f| f.scope == folder.scope && f.name.starts_with(&format!("{}/", folder.name)));

        let mut entries = Vec::new();
        if let Ok(db_entries) = db::list_ab_entries(&database, folder.id) {
            for entry in &db_entries {
                // Entry ACLs gate metadata listing the same way they gate
                // connect (admin and global `read` bypass).
                if !id.has_role("admin")
                    && !rbac::identity_has_custom_permission(&database, id, "read")
                    && !entry_groups_match(entry, user_groups)
                {
                    continue;
                }
                entries.push(inject_powershell_binary(
                    entry,
                    json!(entry_info_from_db_row(&database, entry)),
                ));
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

/// `GET /api/addressbook/search-index`: every visible entry with its
/// scope and folder path, for client-side search. Requires operator or
/// higher; entries whose `allowed_groups` exclude the caller are skipped.
pub async fn ab_search_index(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") =>
        {
            id
        }
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

        if !is_admin
            && !folder_allowed_for_user(&database, &scope, &path, user_groups)
            && !rbac::identity_has_object_permission(
                &database,
                id,
                "connection_group",
                &path,
                rbac::ObjectPermission::Read,
            )
        {
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
            // Entry ACLs gate metadata listing the same way they gate
            // connect (admin and global `read` bypass).
            if !is_admin
                && !rbac::identity_has_custom_permission(&database, id, "read")
                && !entry_groups_match(entry, user_groups)
            {
                continue;
            }
            emitted.push(json!({
                "scope": scope,
                "folder_path": path,
                "entry": inject_powershell_binary(
                    entry,
                    json!(entry_info_from_db_row(&database, entry)),
                ),
            }));
        }
    }

    Ok(Json(json!({"entries": emitted})))
}

/// `GET /api/addressbook/folders/{scope}/{folder}/entries`: list the
/// entries in one folder. Requires operator or higher plus folder and
/// entry access; entries whose `allowed_groups` exclude the caller are
/// skipped, not rejected. `AppError::NotFound` for a missing folder.
pub async fn ab_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") =>
        {
            id
        }
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

    let user_groups = id.groups();
    let mut entries = Vec::new();
    for entry in &db_entries {
        // Entry ACLs gate metadata listing the same way they gate connect:
        // an entry restricted to other groups is invisible here.
        if !id.has_role("admin")
            && !rbac::identity_has_custom_permission(&database, id, "read")
            && !entry_groups_match(entry, user_groups)
        {
            continue;
        }
        entries.push(inject_powershell_binary(
            entry,
            json!(entry_info_from_db_row(&database, entry)),
        ));
    }

    Ok(Json(json!(entries)))
}

/// GET /api/addressbook/custom-fields — the admin-defined custom field
/// definitions for connection entries. Operator+ (NOT admin-only): the
/// connections page needs them for every user who can create or edit
/// entries. Returns `[]` when the feature is off (nothing configured).
pub async fn ab_get_custom_fields(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    match identity.as_ref() {
        Some(Extension(id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "read") => {}
        _ => return Err(AppError::Forbidden("operator role required".into())),
    }
    let db_clone = database.clone();
    let stored = tokio::task::spawn_blocking(move || super::settings::read_all_settings(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    Ok(Json(super::settings::custom_fields_value(&stored)))
}

/// Request body for `PUT /api/addressbook/defaults/apply`.
#[derive(Debug, Deserialize)]
pub struct ApplyDefaultsRequest {
    /// Protocols whose entries get the current global defaults written into
    /// their `protocol_config`: `"rdp"` and/or `"ssh"`. Missing or empty
    /// applies both. Anything else is rejected.
    #[serde(default)]
    pub protocols: Option<Vec<String>>,
}

/// `PUT /api/addressbook/defaults/apply`: apply the current global
/// per-protocol defaults to every saved entry. RDP entries get the
/// auto-size, security, and auth-package defaults
/// (`default_rdp_auto_size` / `default_rdp_security` /
/// `default_rdp_auth_pkg`); SSH (and PowerShell) entries get the auto-size
/// default (`default_ssh_auto_size`). Admin-only, idempotent (a second run
/// changes nothing and counts 0), audited on the admin hash chain. Returns
/// the number of entries updated, the protocols touched, and the defaults
/// that were applied.
pub async fn ab_apply_defaults(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Json(req): Json<ApplyDefaultsRequest>,
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

    // Resolve the requested protocol scope. Missing or empty means both;
    // an unknown protocol is rejected rather than silently ignored.
    let mut want_rdp = false;
    let mut want_ssh = false;
    let mut matched_any = false;
    if let Some(protocols) = req.protocols {
        for p in protocols {
            match p.as_str() {
                "rdp" => want_rdp = true,
                "ssh" => want_ssh = true,
                other => {
                    return Err(AppError::Validation(format!(
                        "unsupported protocol '{other}': expected \"rdp\" or \"ssh\""
                    )))
                }
            }
            matched_any = true;
        }
    }
    if !matched_any {
        want_rdp = true;
        want_ssh = true;
    }

    // The current global defaults drive the bulk write. Only keys with a
    // STORED default are written: an unset security or auth-package key
    // means "no global default", so per-entry values are left untouched
    // (matching the create-path precedence where the entry wins).
    let db_clone = database.clone();
    let settings =
        tokio::task::spawn_blocking(move || crate::settings_merge::load_db_settings(&db_clone))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .unwrap_or_default();
    let rdp_auto_size =
        crate::settings_merge::toggle_enabled(&settings, "default_rdp_auto_size", true);
    let ssh_auto_size =
        crate::settings_merge::toggle_enabled(&settings, "default_ssh_auto_size", true);
    let rdp_security = settings
        .iter()
        .find(|(k, _)| k == "default_rdp_security")
        .map(|(_, v)| v.as_str())
        .filter(|v| matches!(*v, "any" | "rdp" | "tls" | "nla"))
        .map(str::to_string);
    // An empty stored auth package means "no global default": entries keep
    // their per-entry value (or none), so the create path falls back to
    // the `[rdp]` config value, then NTLM.
    let rdp_auth_pkg = settings
        .iter()
        .find(|(k, _)| k == "default_rdp_auth_pkg")
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty() && matches!(*v, "ntlm" | "kerberos" | "negotiate"))
        .map(str::to_string);

    // PowerShell entries are SSH sessions (session creation maps them to
    // SessionType::Ssh), so the SSH default applies to them too.
    let mut protocols: Vec<String> = Vec::new();
    if want_rdp {
        protocols.push("rdp".into());
    }
    if want_ssh {
        protocols.push("ssh".into());
        protocols.push("powershell".into());
    }

    let db_clone = database.clone();
    let protocols_owned = protocols.clone();
    let entries = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = protocols_owned.iter().map(|s| s.as_str()).collect();
        db::list_ab_entries_by_protocols(&db_clone, &refs)
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;

    // Write the defaults where the stored value differs. RDP entries get
    // auto_size + security + auth_pkg; SSH/PowerShell entries get
    // auto_size only. The update runs in one spawn_blocking so the loop
    // holds the lock once.
    let db_clone = database.clone();
    let rdp_security_for_write = rdp_security.clone();
    let rdp_auth_pkg_for_write = rdp_auth_pkg.clone();
    let applied = tokio::task::spawn_blocking(move || {
        let mut applied = 0u64;
        let mut failures = 0u64;
        for entry in &entries {
            // A non-object protocol_config (valid JSON that is not a map)
            // is left untouched rather than replaced: only object configs
            // are updated.
            let mut config: Option<serde_json::Map<String, serde_json::Value>> =
                serde_json::from_str(&entry.protocol_config)
                    .ok()
                    .and_then(|v: serde_json::Value| v.as_object().cloned());
            let Some(config) = config.as_mut() else {
                failures += 1;
                continue;
            };
            let mut changed = false;
            if entry.protocol == "rdp" {
                let current = config.get("auto_size").and_then(|v| v.as_bool());
                if current != Some(rdp_auto_size) {
                    config.insert("auto_size".into(), json!(rdp_auto_size));
                    changed = true;
                }
                if let Some(security) = &rdp_security_for_write {
                    let current = config.get("security").and_then(|v| v.as_str());
                    if current != Some(security.as_str()) {
                        config.insert("security".into(), json!(security));
                        changed = true;
                    }
                }
                if let Some(pkg) = &rdp_auth_pkg_for_write {
                    let current = config.get("auth_pkg").and_then(|v| v.as_str());
                    if current != Some(pkg.as_str()) {
                        config.insert("auth_pkg".into(), json!(pkg));
                        changed = true;
                    }
                }
            } else {
                let current = config.get("auto_size").and_then(|v| v.as_bool());
                if current != Some(ssh_auto_size) {
                    config.insert("auto_size".into(), json!(ssh_auto_size));
                    changed = true;
                }
            }
            if !changed {
                continue;
            }
            let serialized = serde_json::to_string(&config).unwrap_or_else(|_| "{}".into());
            match db::set_ab_entry_protocol_config(&db_clone, entry.id, &serialized) {
                Ok(true) => applied += 1,
                Ok(false) => {}
                Err(e) => {
                    tracing::error!(error = %e, entry = entry.name, "bulk defaults write failed");
                    failures += 1;
                }
            }
        }
        Ok::<(u64, u64), rusqlite::Error>((applied, failures))
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?
    .map_err(|e| AppError::Internal(e.to_string()))?;
    let (applied, failures) = applied;

    // Audit the admin mutation on the hash chain (same pattern as the other
    // admin mutations in users.rs / groups.rs).
    {
        let db_audit = database.clone();
        let admin_name = admin_email.clone();
        let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
        let details = json!({
            "action": "apply_defaults",
            "protocols": protocols.clone(),
            "applied": applied,
            "failures": failures,
            "auto_size": {"rdp": rdp_auto_size, "ssh": ssh_auto_size},
            "security": {"rdp": rdp_security},
            "auth_pkg": {"rdp": rdp_auth_pkg},
        });
        if let Err(e) = tokio::task::spawn_blocking(move || {
            let _ = crate::audit::log_event(
                &db_audit,
                &mut crate::audit::EventBuilder::new("admin.config.change", "success")
                    .user_id(&admin_name)
                    .source_ip(&ip)
                    .details(details)
                    .build(),
            );
        })
        .await
        {
            tracing::error!(error = %e, "audit task failed");
        }
    }

    Ok(Json(json!({
        "applied": applied,
        "failures": failures,
        "protocols": protocols,
        "auto_size": {"rdp": rdp_auto_size, "ssh": ssh_auto_size},
        "security": {"rdp": rdp_security},
        "auth_pkg": {"rdp": rdp_auth_pkg},
    })))
}

/// `POST /api/ssh/probe-host-key`: fetch an SSH host key from a
/// host and return it with its fingerprint and algorithm. Requires
/// poweruser or higher; `AppError::Forbidden` for lower roles.
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
/// `POST /api/addressbook/folders/{scope}/{folder}/entries/{entry}/connect`:
/// start a session from a stored entry, resolving credentials from the
/// DB or Vault and applying the request's overrides. Requires operator
/// or higher, plus folder and entry ACLs and the RBAC Connect grant.
/// Returns the session info, or `AppError::Session` when guacd rejects
/// the connection.
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
        Some(Extension(ref id))
            if id.has_role("operator")
                || rbac::identity_has_custom_permission(&database, id, "connect") =>
        {
            id.clone()
        }
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault("address book unavailable".into()));
    }

    // Custom role holders with global `connect` can connect everywhere —
    // folder ACLs, the per-connection RBAC grant check and the entry ACL
    // all resolve to yes for them (the bundle is global). Everyone else
    // keeps the exact previous flow: folder ACL → per-connection RBAC
    // grant → entry ACL.
    if !rbac::identity_has_custom_permission(&database, &id, "connect") {
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
        check_entry_access_db(&database, folder_rec.id, &entry, &id)?;
    }

    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;

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
    if ab_entry.password.as_deref().is_none_or(|p| p.is_empty()) {
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
                                    if ab_entry.username.as_deref().is_none_or(|u| u.is_empty())
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
    if ab_entry.password.as_deref().is_none_or(|p| p.is_empty())
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
                                    if ab_entry.username.as_deref().is_none_or(|u| u.is_empty())
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

    // Session credential forwarding (persea#245): with
    // [auth] forward_session_credentials, the login password retained for
    // the owning auth session is tried before the prompt. The marker is
    // kept so the attempt path can classify failures (S6) and decide
    // whether to prompt instead of erroring.
    let used_session_credentials = apply_session_credentials(
        &manager,
        &database,
        &headers,
        storage_key.as_ref().map(|Extension(k)| k),
        &id,
        &mut ab_entry,
    );
    if used_session_credentials {
        tracing::debug!(
            user = %id.display_name(),
            scope = %scope,
            folder = %folder,
            entry = %entry,
            "Connect uses session-forwarded credentials"
        );
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
        "powershell" => SessionType::Ssh,
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
        auto_size: ab_entry.auto_size,
        banner: req.banner.or(ab_entry.banner),
        reason: req.reason,
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

    match manager
        .create_session(
            create_req,
            admin_name.clone(),
            Some(client_ip_addr.to_string()),
        )
        .await
    {
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

/// `POST /api/addressbook/folders`: create a folder with its ACL.
/// Admin only, or a custom role with `create_connection_group`.
/// Returns 201 on success, `AppError::Conflict` for a duplicate name.
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
        Some(Extension(id))
            if rbac::identity_has_system_permission(
                &database,
                id,
                rbac::SystemPermission::CreateConnectionGroup,
            ) =>
        {
            id.display_name().to_string()
        }
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
            if is_unique_violation(&e) {
                Err(AppError::Conflict("folder already exists".into()))
            } else {
                tracing::error!(error = %e, scope = %folder_scope, folder = %folder_name, "Failed to create folder in DB");
                Err(AppError::Internal(e.to_string()))
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
/// `PUT /api/addressbook/folders/{scope}/{folder}`: replace a
/// folder's description and ACL. Admin only; `AppError::Internal`
/// when the folder is missing.
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

/// `GET /api/addressbook/folders/{scope}/{folder}/config`: a
/// folder's ACL config for the management UI. Admin only;
/// `AppError::NotFound` when the folder is missing.
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

/// `DELETE /api/addressbook/folders/{scope}/{folder}`: delete a
/// folder, its subfolders, and its entries. Admin only, or a custom
/// role with the Delete object permission on the folder. Returns the
/// number of subfolders and entries removed.
#[allow(clippy::too_many_arguments)]
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
        Some(Extension(id))
            if rbac::identity_has_object_permission(
                &database,
                id,
                "connection_group",
                &folder,
                rbac::ObjectPermission::Delete,
            ) =>
        {
            id.display_name().to_string()
        }
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
/// `POST /api/addressbook/folders/{scope}/{folder}/entries`: create
/// an entry; the slug identifier is `slugify(name)`. Admin only, or a
/// custom role with `create_connection`. Returns 201, or
/// `AppError::Validation` for unusable names and
/// `AppError::Conflict` for duplicate slugs.
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
        Some(Extension(id))
            if rbac::identity_has_system_permission(
                &database,
                id,
                rbac::SystemPermission::CreateConnection,
            ) =>
        {
            id.display_name().to_string()
        }
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let session_type = req.entry.session_type.clone();
    if session_type == "powershell" && !powershell_ssh_enabled(&database) {
        return Err(AppError::Validation(
            "PowerShell (SSH) entries are disabled by an administrator".into(),
        ));
    }
    let vault_mode =
        vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await;

    // ONE friendly name in, two things out: the slug becomes the stored
    // identifier (URL path / Vault key / RBAC id / audit subject), and the
    // friendly text becomes `display_name` (an explicit display_name from
    // API clients, e.g. CSV import, is honored).
    let friendly_name = req.name.trim().to_string();
    let slug = slugify(&friendly_name);
    if friendly_name.is_empty() {
        return Err(AppError::Validation("entry name must not be empty".into()));
    }
    if slug.is_empty() {
        return Err(AppError::Validation(format!(
            "'{}' contains no usable characters — use at least one letter, digit, dot, underscore or dash",
            friendly_name
        )));
    }
    if slug.len() > 64 {
        return Err(AppError::Validation(format!(
            "'{}' is too long — the connection identifier may be at most 64 characters (got {})",
            friendly_name,
            slug.len()
        )));
    }
    let display_name = req
        .entry
        .display_name
        .clone()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| friendly_name.clone());

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

    let mut entry = req.entry.clone();
    entry.display_name = Some(display_name.clone());
    let mut config = build_protocol_config(&entry);
    if let Some(bin) = req
        .powershell_binary
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
    {
        config.insert("powershell_binary".into(), json!(bin));
    }
    let entry_id = db::create_ab_entry(
        &database,
        folder_id,
        &slug,
        &display_name,
        &entry.session_type,
        entry.hostname.as_deref().unwrap_or(""),
        entry.port,
        entry.username.as_deref().unwrap_or(""),
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
            AppError::Conflict(format!(
                "a connection '{slug}' already exists in this folder"
            ))
        } else {
            AppError::Internal(e.to_string())
        }
    })?;

    if vault_mode {
        // Credentials live in Vault: write the full entry keyed by the slug
        // identifier. The friendly display name and custom field values
        // round-trip through the vault copy.
        if let Err(e) = vault.put_entry(&scope, &folder, &slug, &entry).await {
            // Roll back the DB row so the entry doesn't linger credential-less.
            let _ = db::delete_ab_entry(&database, entry_id);
            return Err(AppError::Vault(e.to_string()));
        }
    } else {
        // Credentials live in the DB: encrypt and store the provided fields.
        let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));
        if !encryption_key.is_empty() {
            if let Some(ref password) = entry.password {
                let encrypted = crate::crypto::encrypt_value(
                    &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                        .map_err(|e| AppError::Internal(e.to_string()))?,
                    password,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                db::store_ab_credential(&database, entry_id, "password", &encrypted)?;
            }
            if let Some(ref private_key) = entry.private_key {
                let encrypted = crate::crypto::encrypt_value(
                    &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                        .map_err(|e| AppError::Internal(e.to_string()))?,
                    private_key,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                db::store_ab_credential(&database, entry_id, "private_key", &encrypted)?;
            }
            if let Some(ref secret) = entry.proxmox_token_secret {
                let encrypted = crate::crypto::encrypt_value(
                    &crate::crypto::EncryptionKey::from_hex(&encryption_key)
                        .map_err(|e| AppError::Internal(e.to_string()))?,
                    secret,
                )
                .map_err(|e| AppError::Internal(e.to_string()))?;
                db::store_ab_credential(&database, entry_id, "proxmox_token_secret", &encrypted)?;
            }
            if let Some(ref pw) = entry.container_password {
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
        Some(&slug),
        &ip,
        Some(&details),
    )
    .await;
    Ok(StatusCode::CREATED)
}

#[allow(clippy::too_many_arguments)]
/// `PUT /api/addressbook/folders/{scope}/{folder}/entries/{entry}`:
/// update an entry's fields, credentials, and ACL. Admin only, or a
/// custom role with the Update object permission on the entry.
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
        Some(Extension(id))
            if rbac::identity_has_object_permission(
                &database,
                id,
                "connection",
                &format!("{}/{}/{}", scope, folder, entry),
                rbac::ObjectPermission::Update,
            ) =>
        {
            id.display_name().to_string()
        }
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let vault_mode =
        vault_credentials_enabled(backend.as_ref().map(|Extension(b)| b), &vault).await;

    // A friendly `name` in the update payload updates display_name ONLY —
    // the slug identifier is immutable (URL path / Vault key / RBAC id /
    // audit subject all key off it). The trimmed friendly text is used for
    // the vault copy merge and the DB row alike.
    let mut payload = data.clone();
    if let Some(name) = data.name.as_ref().filter(|n| !n.trim().is_empty()) {
        payload.entry.display_name = Some(name.trim().to_string());
    }

    if payload.entry.session_type == "powershell" && !powershell_ssh_enabled(&database) {
        return Err(AppError::Validation(
            "PowerShell (SSH) entries are disabled by an administrator".into(),
        ));
    }

    let folder_rec = db::get_ab_folder(&database, &scope, &folder)
        .map_err(|e| AppError::NotFound(format!("folder not found: {}", e)))?;
    let entry_rec = db::get_ab_entry(&database, folder_rec.id, &entry)
        .map_err(|e| AppError::NotFound(format!("entry not found: {}", e)))?;

    // Same guard as create: db mode without a key cannot store credentials.
    if !vault_mode
        && resolve_encryption_key(storage_key.as_ref().map(|k| &k.0)).is_empty()
        && has_credential_fields(&payload.entry)
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
                    password: payload.entry.password.clone().or(existing.password),
                    private_key: payload.entry.private_key.clone().or(existing.private_key),
                    container_password: payload
                        .entry
                        .container_password
                        .clone()
                        .or(existing.container_password),
                    proxmox_token_secret: payload
                        .entry
                        .proxmox_token_secret
                        .clone()
                        .or(existing.proxmox_token_secret),
                    jump_hosts: merged_jump_hosts,
                    jump_password: None,
                    jump_private_key: None,
                    ..payload.entry.clone()
                }
            }
            // A missing vault copy (e.g. after a db→vault backend switch)
            // behaves like an empty copy: write the payload as-is. Any OTHER
            // read failure must not proceed — the put below would overwrite
            // the stored credentials with `None`s.
            Err(VaultError::NotFound) => payload.entry.clone(),
            Err(e) => return Err(AppError::Vault(e.to_string())),
        };
        // Preserve metadata the modal doesn't edit (same merge contract as
        // the DB path): fields omitted from the payload keep their vault
        // values. Custom field values merge per key so edits that omit or
        // partially update the map keep the rest.
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
                match (&full.custom_fields, &existing.custom_fields) {
                    (Some(new_fields), Some(old_fields)) => {
                        let mut merged_fields = old_fields.clone();
                        for (k, v) in new_fields {
                            merged_fields.insert(k.clone(), v.clone());
                        }
                        full.custom_fields = Some(merged_fields);
                    }
                    (None, Some(old_fields)) => full.custom_fields = Some(old_fields.clone()),
                    _ => {}
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
            if let Some(ref password) = payload.entry.password {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "password",
                    password,
                    &encryption_key,
                )?;
            }
            if let Some(ref private_key) = payload.entry.private_key {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "private_key",
                    private_key,
                    &encryption_key,
                )?;
            }
            if let Some(ref secret) = payload.entry.proxmox_token_secret {
                upsert_or_clear_credential(
                    &database,
                    entry_rec.id,
                    "proxmox_token_secret",
                    secret,
                    &encryption_key,
                )?;
            }
            if let Some(ref pw) = payload.entry.container_password {
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
    let payload_config = build_protocol_config(&payload.entry);
    for (k, v) in payload_config {
        if k == "custom_fields" {
            // Per-key merge: custom field values set by earlier edits
            // survive a partial update of the map.
            let stored_map = merged_config
                .get("custom_fields")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            let new_map = v.as_object().cloned().unwrap_or_default();
            let mut out = stored_map;
            for (fk, fv) in new_map {
                out.insert(fk, fv);
            }
            merged_config.insert("custom_fields".into(), serde_json::Value::Object(out));
        } else {
            merged_config.insert(k, v);
        }
    }
    if let Some(bin) = payload
        .powershell_binary
        .as_deref()
        .map(str::trim)
        .filter(|b| !b.is_empty())
    {
        merged_config.insert("powershell_binary".into(), json!(bin));
    }
    let allowed_groups = payload
        .allowed_groups
        .as_ref()
        .map(|g| g.join(","))
        .unwrap_or_else(|| entry_rec.allowed_groups.clone());
    db::update_ab_entry(
        &database,
        entry_rec.id,
        payload.entry.display_name.as_deref().unwrap_or(""),
        &payload.entry.session_type,
        payload.entry.hostname.as_deref().unwrap_or(""),
        payload.entry.port,
        payload.entry.username.as_deref().unwrap_or(""),
        &serde_json::to_string(&merged_config).unwrap_or_else(|_| "{}".into()),
        &allowed_groups,
    )
    .map_err(|e| AppError::Internal(e.to_string()))?;

    let session_type = payload.entry.session_type.clone();
    let ip = audit_client_ip(&headers, &addr, trusted.as_ref());
    let credential_rotated = payload.entry.password.is_some();
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

/// `DELETE /api/addressbook/folders/{scope}/{folder}/entries/{entry}`:
/// delete an entry and its stored credentials. Admin only, or a
/// custom role with the Delete object permission on the entry.
#[allow(clippy::too_many_arguments)]
/// Returns 204 on success.
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
        Some(Extension(id))
            if rbac::identity_has_object_permission(
                &database,
                id,
                "connection",
                &format!("{}/{}/{}", scope, folder, entry),
                rbac::ObjectPermission::Delete,
            ) =>
        {
            id.display_name().to_string()
        }
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
/// `GET /api/connect`: quick-connect entry point that redirects to
/// the client page. Accepts either address book coordinates (`scope`,
/// `folder`, `entry`) or an ad-hoc spec (`protocol`, `hostname`, ...).
/// Unauthenticated callers are redirected to the login page when OIDC
/// is enabled; otherwise they get an HTML error page.
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
        let has_global_connect = rbac::identity_has_custom_permission(&database, &id, "connect");
        if !id.has_role("operator") && !has_global_connect {
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

        // Same gate as ab_connect_entry: folder ACL, then RBAC Connect,
        // then entry ACL. Custom-role holders with global `connect` bypass
        // it (the bundle is global, exactly like ab_connect_entry).
        if !has_global_connect {
            if check_folder_access_db(&database, scope, folder, &id).is_err() {
                return quick_connect_error(StatusCode::FORBIDDEN, "No access to this folder.");
            }

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
                        return quick_connect_error(
                            StatusCode::FORBIDDEN,
                            "No permission to connect to this entry. Ask an administrator to grant your group Connect access to it.",
                        );
                    }
                }
            }
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

        // Entry ACL: a restricted entry stays restricted even inside an
        // accessible folder (same gate as ab_connect_entry).
        if !has_global_connect {
            if let Err(e) = check_entry_access_db(&database, folder_rec.id, entry, &id) {
                return quick_connect_error(StatusCode::FORBIDDEN, &e.to_string());
            }
        }
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

        // Session credential forwarding (persea#245): with
        // [auth] forward_session_credentials, the login password retained
        // for the owning auth session is tried before the prompt. The
        // marker is kept so the attempt path can classify failures (S6)
        // and decide whether to prompt instead of erroring.
        let used_session_credentials = apply_session_credentials(
            &manager,
            &database,
            &headers,
            storage_key.as_ref().map(|Extension(k)| k),
            &id,
            &mut ab_entry,
        );
        if used_session_credentials {
            tracing::debug!(
                user = %admin_name,
                scope = %scope,
                folder = %folder,
                entry = %entry,
                "Quick connect uses session-forwarded credentials"
            );
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
            "powershell" => SessionType::Ssh,
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
            auto_size: None,
            banner: ab_entry.banner,
            reason: None,
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

        return match manager
            .create_session(create_req, admin_name, Some(client_ip.to_string()))
            .await
        {
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

    match manager
        .create_session(create_req, admin_name, Some(client_ip.to_string()))
        .await
    {
        Ok(info) => Redirect::temporary(&format!("/client/{}", info.session_id)).into_response(),
        Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}

// ── Personal folders (persea#138 / persea#166) ─────────────────────────
//
// Every authenticated user owns a private folder tree. Folders nest via
// slash paths and reference shared address book entries without copying
// them. All endpoints are owner-only: the authenticated user's own folders
// only, no admin bypass, and foreign or missing folders are both 404 so
// nothing can be enumerated.

/// Body for `POST /api/personal/folders`.
#[derive(Deserialize)]
pub struct CreatePersonalFolderRequest {
    /// Folder name; slash-separated paths nest folders.
    pub name: String,
    /// Free-text description.
    #[serde(default)]
    pub description: String,
}

/// Body for `PUT /api/personal/folders/{id}`.
#[derive(Deserialize)]
pub struct RenamePersonalFolderRequest {
    /// New folder name; slash-separated paths nest folders.
    pub name: String,
}

/// Body for `POST /api/personal/folders/{id}/entries`: the shared address
/// book key of the entry to reference.
#[derive(Deserialize)]
pub struct AddPersonalFolderEntryRequest {
    /// Address book scope of the shared entry (`shared` or `instance`).
    pub scope: String,
    /// Address book folder path holding the entry.
    pub folder: String,
    /// Entry name inside that folder.
    pub entry: String,
}

/// Resolve the authenticated caller to (user id, identity). Personal
/// folders are per-user, so an API key identity (which has no user row) or
/// a missing identity is rejected with 403: fail closed, no admin bypass.
fn personal_caller<'a>(
    database: &Db,
    identity: Option<&'a Extension<AuthIdentity>>,
) -> Result<(i64, &'a AuthIdentity), AppError> {
    match identity {
        Some(ext) => match &ext.0 {
            AuthIdentity::User { email, .. } => {
                let user = db::get_user_by_email(database, email).map_err(|_| {
                    AppError::Forbidden("authenticated user session required".into())
                })?;
                Ok((user.id, &ext.0))
            }
            AuthIdentity::ApiKey(_) => Err(AppError::Forbidden("user session required".into())),
        },
        None => Err(AppError::Forbidden("user session required".into())),
    }
}

/// Validate a personal folder slash-path name: non-empty, no leading or
/// trailing slash, no empty path segments (rejects `//` and whitespace-only
/// segments). The stored name is the trimmed input.
fn validate_personal_folder_name(name: &str) -> Result<String, AppError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(AppError::Validation("folder name must not be empty".into()));
    }
    if trimmed.starts_with('/') || trimmed.ends_with('/') {
        return Err(AppError::Validation(
            "folder name must not start or end with a slash".into(),
        ));
    }
    if trimmed.split('/').any(|seg| seg.trim().is_empty()) {
        return Err(AppError::Validation(
            "folder name must not contain empty path segments".into(),
        ));
    }
    Ok(trimmed.to_string())
}

/// Fail-closed owner check: 404 when the folder does not exist or belongs
/// to another user, so foreign folders are indistinguishable from missing
/// ones (no enumeration).
fn require_owned_personal_folder(
    database: &Db,
    user_id: i64,
    folder_id: i64,
) -> Result<(), AppError> {
    let owned = db::list_user_folders(database, user_id)
        .map_err(|e| AppError::Internal(e.to_string()))?
        .iter()
        .any(|f| f.id == folder_id);
    if owned {
        Ok(())
    } else {
        Err(AppError::NotFound("folder not found".into()))
    }
}

/// Resolve a shared entry reference (scope, folder, entry) to its DB id.
/// The folder and entry must exist and the caller must be able to read
/// them; missing and unreadable both map to 404 so the API never reveals
/// which shared entries exist to callers without access.
fn resolve_readable_shared_entry(
    database: &Db,
    scope: &str,
    folder: &str,
    entry: &str,
    identity: &AuthIdentity,
) -> Result<i64, AppError> {
    let folder_rec = db::get_ab_folder(database, scope, folder)
        .map_err(|_| AppError::NotFound("folder not found".into()))?;
    let entry_rec = db::get_ab_entry(database, folder_rec.id, entry)
        .map_err(|_| AppError::NotFound("entry not found".into()))?;
    if identity.has_role("admin")
        || rbac::identity_has_custom_permission(database, identity, "read")
    {
        return Ok(entry_rec.id);
    }
    check_folder_access_db(database, scope, folder, identity)
        .map_err(|_| AppError::NotFound("folder not found".into()))?;
    check_entry_access_db(database, folder_rec.id, entry, identity)
        .map_err(|_| AppError::NotFound("entry not found".into()))?;
    Ok(entry_rec.id)
}

/// `GET /api/personal/folders`: list the caller's personal folders, flat
/// with slash paths (`Work/Acme` nests under `Work`). Any authenticated
/// user; no admin gate. API key identities are rejected (no user row).
pub async fn pf_list_folders(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, _) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let folders =
        db::list_user_folders(&database, user_id).map_err(|e| AppError::Internal(e.to_string()))?;
    let mut result = Vec::new();
    for folder in &folders {
        result.push(json!({
            "id": folder.id,
            "name": folder.name,
            "path": folder.name,
            "description": folder.description,
            "created_at": folder.created_at,
            "has_children": folders
                .iter()
                .any(|g| g.name.starts_with(&format!("{}/", folder.name))),
        }));
    }
    Ok(Json(json!(result)))
}

/// `POST /api/personal/folders`: create a personal folder. The name is a
/// slash path (`Work/Acme` nests under `Work`), validated non-empty with
/// no leading/trailing slash and no empty segments; duplicate names per
/// user conflict with 409.
pub async fn pf_create_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Json(req): Json<CreatePersonalFolderRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let (user_id, _) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let name = validate_personal_folder_name(&req.name)?;
    match db::create_user_folder(&database, user_id, &name, &req.description) {
        Ok(id) => Ok((StatusCode::CREATED, Json(json!({"id": id, "name": name})))),
        Err(e) if is_unique_violation(&e) => Err(AppError::Conflict(
            "a folder with this name already exists".into(),
        )),
        Err(e) => {
            tracing::error!(
                error = %e,
                folder = %name,
                "Failed to create personal folder"
            );
            Err(AppError::Internal(e.to_string()))
        }
    }
}

/// `PUT /api/personal/folders/{id}`: rename one of the caller's folders.
/// The new name follows the same validation as create and must stay unique
/// per user; foreign folders return 404.
pub async fn pf_rename_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(folder_id): Path<i64>,
    Json(req): Json<RenamePersonalFolderRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, _) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let name = validate_personal_folder_name(&req.name)?;
    match db::rename_user_folder(&database, user_id, folder_id, &name) {
        Ok(true) => Ok(Json(json!({"id": folder_id, "name": name}))),
        Ok(false) => Err(AppError::NotFound("folder not found".into())),
        Err(e) if is_unique_violation(&e) => Err(AppError::Conflict(
            "a folder with this name already exists".into(),
        )),
        Err(e) => {
            tracing::error!(
                error = %e,
                folder = folder_id,
                "Failed to rename personal folder"
            );
            Err(AppError::Internal(e.to_string()))
        }
    }
}

/// `DELETE /api/personal/folders/{id}`: delete one of the caller's
/// folders. Removes only the folder's entry references; shared address
/// book entries are never touched. Foreign folders return 404.
pub async fn pf_delete_folder(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(folder_id): Path<i64>,
) -> Result<StatusCode, AppError> {
    let (user_id, _) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    match db::delete_user_folder(&database, user_id, folder_id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(AppError::NotFound("folder not found".into())),
        Err(e) => {
            tracing::error!(
                error = %e,
                folder = folder_id,
                "Failed to delete personal folder"
            );
            Err(AppError::Internal(e.to_string()))
        }
    }
}

/// `POST /api/personal/folders/{id}/entries`: reference a shared address
/// book entry from one of the caller's folders. The body carries the
/// shared entry key (scope/folder/entry); the entry must exist and be
/// readable by the caller, else 404 (no enumeration). Duplicate references
/// conflict with 409.
pub async fn pf_add_folder_entry(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(folder_id): Path<i64>,
    Json(req): Json<AddPersonalFolderEntryRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), AppError> {
    let (user_id, id) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    let entry_id =
        resolve_readable_shared_entry(&database, &req.scope, &req.folder, &req.entry, id)?;
    match db::add_user_folder_entry(&database, user_id, folder_id, entry_id) {
        Ok(reference_id) => Ok((
            StatusCode::CREATED,
            Json(json!({"id": reference_id, "entry_id": entry_id})),
        )),
        // The schema layer fails this way when the folder is missing or
        // owned by someone else: 404, same as a missing folder.
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(AppError::NotFound("folder not found".into()))
        }
        Err(e) if is_unique_violation(&e) => Err(AppError::Conflict(
            "this entry is already in the folder".into(),
        )),
        Err(e) => {
            tracing::error!(
                error = %e,
                folder = folder_id,
                "Failed to add entry reference to personal folder"
            );
            Err(AppError::Internal(e.to_string()))
        }
    }
}

/// `DELETE /api/personal/folders/{id}/entries/{entry_id}`: remove an
/// entry reference from one of the caller's folders. `entry_id` is the
/// shared entry id used when the reference was added. Foreign folders and
/// unknown references return 404.
pub async fn pf_remove_entry(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path((folder_id, entry_id)): Path<(i64, i64)>,
) -> Result<StatusCode, AppError> {
    let (user_id, _) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    match db::remove_user_folder_entry(&database, user_id, folder_id, entry_id) {
        Ok(true) => Ok(StatusCode::NO_CONTENT),
        Ok(false) => Err(AppError::NotFound("folder entry not found".into())),
        Err(e) => {
            tracing::error!(
                error = %e,
                folder = folder_id,
                "Failed to remove entry reference from personal folder"
            );
            Err(AppError::Internal(e.to_string()))
        }
    }
}

/// `GET /api/personal/folders/{id}/entries`: list the shared entries
/// referenced from one of the caller's folders, resolved to their real
/// rows with the same serialization as the address-book entry lists.
///
/// Reference integrity: deleting a shared entry removes its references
/// (the schema cascades them away), and the join here additionally skips
/// any reference whose entry no longer resolves, so a deleted entry simply
/// stops appearing. Entry ACLs gate the listing the same way they gate the
/// shared entry lists: entries restricted away are skipped, not rejected.
pub async fn pf_list_entries(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Path(folder_id): Path<i64>,
) -> Result<Json<serde_json::Value>, AppError> {
    let (user_id, id) = personal_caller(&database, identity.as_ref())?;

    if !is_db_storage_available(&database) {
        return Err(AppError::Vault(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    require_owned_personal_folder(&database, user_id, folder_id)?;

    let db_entries = db::list_user_folder_entries(&database, user_id, folder_id)
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let user_groups = id.groups();
    let mut visible = Vec::new();
    for entry in &db_entries {
        // The containing folder's ACL gates the reference the same way it
        // gates the shared tree: a tightened folder hides its entries
        // everywhere, including personal references. A vanished folder
        // also hides the reference.
        let folder_path = match db::get_ab_folder_by_id(&database, entry.folder_id) {
            Ok(folder) => folder.name,
            Err(_) => continue,
        };
        if check_folder_access_db(&database, "shared", &folder_path, id).is_err() {
            continue;
        }
        if !id.has_role("admin")
            && !rbac::identity_has_custom_permission(&database, id, "read")
            && !entry_groups_match(entry, user_groups)
        {
            continue;
        }
        // The shared location rides along so the client can connect to the
        // real entry without a client-side location map.
        let mut value = json!(entry_info_from_db_row(&database, entry));
        if let Some(obj) = value.as_object_mut() {
            obj.insert("shared_scope".into(), json!("shared"));
            obj.insert("shared_folder".into(), json!(folder_path));
        }
        visible.push(inject_powershell_binary(entry, value));
    }
    Ok(Json(json!(visible)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        CredentialDefaultScope, DriveConfigured, OidcEnabled, SiteTitle, StorageBackend,
        VaultBackends, VaultCell, VaultConfigured, VaultState,
    };
    use axum::body::Body;
    use axum::http::{HeaderMap, Request};
    use serde_json::{json, Value};
    use std::sync::Arc;
    use tower::ServiceExt;

    fn test_db() -> Db {
        db::init_db(std::path::Path::new(":memory:")).expect("Failed to create test DB")
    }

    fn test_addr() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    fn insert_test_admin(db: &Db, name: &str) -> String {
        let key = format!("test-key-{}", name);
        let key_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(key.as_bytes());
            hex::encode(hasher.finalize())
        };
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO admins (name, api_key_hash) VALUES (?1, ?2)",
            rusqlite::params![name, key_hash],
        )
        .unwrap();
        key
    }

    fn insert_test_user(db: &Db, email: &str, name: &str, role: &str) {
        let conn = db.lock().unwrap();
        let _ = conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT", []);
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN auth_source TEXT DEFAULT 'database'",
            [],
        );
        let _ = conn.execute(
            "ALTER TABLE users ADD COLUMN oidc_groups TEXT DEFAULT ''",
            [],
        );
        conn.execute(
            "INSERT INTO users (email, name, role, disabled, created_at) VALUES (?1, ?2, ?3, 0, datetime('now'))",
            rusqlite::params![email, name, role],
        )
        .unwrap();
    }

    fn test_vault_state() -> VaultState {
        let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(None));
        Arc::new(VaultBackends {
            default: cell.clone(),
            shared: cell.clone(),
            local: cell,
        })
    }

    fn mock_vault_state(mock: Arc<crate::testing::MockVault>) -> VaultState {
        let cell: VaultCell = Arc::new(tokio::sync::RwLock::new(Some(mock)));
        Arc::new(VaultBackends {
            default: cell.clone(),
            shared: cell.clone(),
            local: cell,
        })
    }

    /// Minimal router for the entry create/update/list + custom-fields
    /// handlers plus the personal folders API, mirroring the route shapes
    /// in `src/main.rs`.
    fn build_router(db: Db, vault: VaultState, backend: Option<&str>) -> axum::Router {
        use axum::routing::{delete, get, post, put};
        let api_routes = axum::Router::new()
            .route(
                "/api/addressbook/custom-fields",
                get(super::ab_get_custom_fields),
            )
            .route(
                "/api/addressbook/defaults/apply",
                put(super::ab_apply_defaults),
            )
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries",
                get(super::ab_list_entries),
            )
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries",
                post(super::ab_create_entry),
            )
            .route(
                "/api/addressbook/folders/{scope}/{folder}/entries/{entry}",
                put(super::ab_update_entry),
            )
            .route("/api/personal/folders", get(super::pf_list_folders))
            .route("/api/personal/folders", post(super::pf_create_folder))
            .route("/api/personal/folders/{id}", put(super::pf_rename_folder))
            .route(
                "/api/personal/folders/{id}",
                delete(super::pf_delete_folder),
            )
            .route(
                "/api/personal/folders/{id}/entries",
                get(super::pf_list_entries),
            )
            .route(
                "/api/personal/folders/{id}/entries",
                post(super::pf_add_folder_entry),
            )
            .route(
                "/api/personal/folders/{id}/entries/{entry_id}",
                delete(super::pf_remove_entry),
            )
            .with_state(());
        let mut api_routes = api_routes
            .layer(axum::middleware::from_fn(crate::auth::require_auth))
            .layer(Extension(db))
            .layer(Extension(vault))
            .layer(Extension(VaultConfigured(false)))
            .layer(Extension(OidcEnabled(false)))
            .layer(Extension(DriveConfigured(false)))
            .layer(Extension(CredentialDefaultScope("local".into())))
            .layer(Extension(SiteTitle("Test".into())));
        if let Some(b) = backend {
            api_routes = api_routes.layer(Extension(StorageBackend(b.into())));
        }
        api_routes
    }

    fn auth_req(method: &str, uri: &str, key: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", key))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        req
    }

    fn json_req(method: &str, uri: &str, key: &str, body: Value) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", key))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        req
    }

    fn session_req(method: &str, uri: &str, session: &str) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", format!("persea_session={}", session))
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        req
    }

    async fn body_json(response: axum::response::Response) -> Value {
        serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn test_create_entry_slugifies_friendly_name() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "Slugs", "", "", false).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/Slugs/entries",
                &key,
                json!({"name": "Web Server 01", "type": "ssh", "hostname": "10.0.0.1"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let folder = db::get_ab_folder(&db, "shared", "Slugs").unwrap();
        let entries = db::list_ab_entries(&db, folder.id).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name, "web-server-01",
            "stored identifier must be the slug"
        );
        assert_eq!(
            entries[0].display_name, "Web Server 01",
            "friendly name becomes display_name"
        );

        // List API surfaces the slug identifier + friendly display name.
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/Slugs/entries",
                &key,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body[0]["name"], "web-server-01");
        assert_eq!(body[0]["display_name"], "Web Server 01");
    }

    #[tokio::test]
    async fn test_create_entry_explicit_display_name_honored() {
        // CSV import compat: an explicit display_name wins over the
        // friendly name.
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "Exp", "", "", false).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/Exp/entries",
                &key,
                json!({"name": "DB Server 01", "display_name": "Imported Label", "type": "ssh", "hostname": "10.0.0.2"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let folder = db::get_ab_folder(&db, "shared", "Exp").unwrap();
        let entries = db::list_ab_entries(&db, folder.id).unwrap();
        assert_eq!(entries[0].name, "db-server-01");
        assert_eq!(entries[0].display_name, "Imported Label");
    }

    #[tokio::test]
    async fn test_create_entry_duplicate_slug_conflict_names_identifier() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "Dups", "", "", false).unwrap();
        let first = build_router(db.clone(), test_vault_state(), None);
        let response = first
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/Dups/entries",
                &key,
                json!({"name": "Web Server 01", "type": "ssh", "hostname": "10.0.0.1"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let second = build_router(db.clone(), test_vault_state(), None);
        let response = second
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/Dups/entries",
                &key,
                json!({"name": "web server 01", "type": "ssh", "hostname": "10.0.0.2"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let body = body_json(response).await;
        let err = body["error"].as_str().unwrap_or("");
        assert!(
            err.contains("web-server-01"),
            "409 must name the derived slug, got: {err}"
        );
    }

    #[tokio::test]
    async fn test_create_entry_rejects_unusable_name() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "Bad", "", "", false).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/Bad/entries",
                &key,
                json!({"name": "!!!", "type": "ssh", "hostname": "10.0.0.1"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = body_json(response).await;
        assert!(
            body["error"]
                .as_str()
                .unwrap_or("")
                .contains("no usable characters"),
            "got: {}",
            body
        );
    }

    #[tokio::test]
    async fn test_custom_fields_round_trip_db_mode_and_edit_merge() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "CF", "", "", false).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/CF/entries",
                &key,
                json!({
                    "name": "Prod Web",
                    "type": "ssh",
                    "hostname": "10.0.0.3",
                    "custom_fields": {"Environment": "Production", "Owner": "alice"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // List API returns the values.
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/CF/entries",
                &key,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(body[0]["custom_fields"]["Environment"], "Production");

        // Edit with a friendly name but NO custom_fields: values survive and
        // display_name changes while the slug stays.
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/folders/shared/CF/entries/prod-web",
                &key,
                json!({"name": "Prod Web Renamed", "type": "ssh", "hostname": "10.0.0.4"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/CF/entries",
                &key,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(
            body[0]["custom_fields"]["Environment"], "Production",
            "values must survive an edit that omits them"
        );
        assert_eq!(
            body[0]["display_name"], "Prod Web Renamed",
            "friendly name in update changes display_name"
        );
        assert_eq!(body[0]["name"], "prod-web", "slug identifier is immutable");

        // Partial map edit merges per key.
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/folders/shared/CF/entries/prod-web",
                &key,
                json!({"type": "ssh", "hostname": "10.0.0.4", "custom_fields": {"Owner": "bob"}}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/CF/entries",
                &key,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        let cf = &body[0]["custom_fields"];
        assert_eq!(cf["Environment"], "Production");
        assert_eq!(cf["Owner"], "bob");
    }

    #[tokio::test]
    async fn test_custom_fields_round_trip_vault_mode() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "CFV", "", "", false).unwrap();
        let mock = Arc::new(crate::testing::MockVault::new());
        let app = build_router(db.clone(), mock_vault_state(mock.clone()), Some("vault"));
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/CFV/entries",
                &key,
                json!({
                    "name": "Prod Web",
                    "type": "ssh",
                    "hostname": "10.0.0.3",
                    "password": "secret",
                    "custom_fields": {"Environment": "Production"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // The vault copy is keyed by the SLUG and round-trips custom fields
        // + the friendly display name.
        let vault_entry = mock
            .get_entry("shared", "CFV", "prod-web")
            .expect("vault copy must be keyed by the slug");
        assert_eq!(
            vault_entry
                .custom_fields
                .as_ref()
                .and_then(|f| f.get("Environment"))
                .map(String::as_str),
            Some("Production"),
            "vault copy must carry custom field values"
        );
        assert_eq!(vault_entry.password.as_deref(), Some("secret"));
        assert_eq!(vault_entry.display_name.as_deref(), Some("Prod Web"));

        // List API returns the values from the DB row.
        let app = build_router(db.clone(), mock_vault_state(mock.clone()), Some("vault"));
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/CFV/entries",
                &key,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(body[0]["custom_fields"]["Environment"], "Production");
        assert_eq!(body[0]["name"], "prod-web");
        assert_eq!(body[0]["display_name"], "Prod Web");
    }

    #[tokio::test]
    async fn test_custom_fields_vault_mode_edit_merge() {
        let db = test_db();
        let key = insert_test_admin(&db, "admin");
        db::create_ab_folder(&db, "shared", "CFVM", "", "", false).unwrap();
        let mock = Arc::new(crate::testing::MockVault::new());
        let app = build_router(db.clone(), mock_vault_state(mock.clone()), Some("vault"));
        let response = app
            .oneshot(json_req(
                "POST",
                "/api/addressbook/folders/shared/CFVM/entries",
                &key,
                json!({
                    "name": "Prod Web",
                    "type": "ssh",
                    "hostname": "10.0.0.3",
                    "password": "secret",
                    "custom_fields": {"Environment": "Production"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Edit: partial custom_fields map + friendly name, password omitted.
        let app = build_router(db.clone(), mock_vault_state(mock.clone()), Some("vault"));
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/folders/shared/CFVM/entries/prod-web",
                &key,
                json!({
                    "name": "Prod Web Renamed",
                    "type": "ssh",
                    "hostname": "10.0.0.4",
                    "custom_fields": {"Owner": "bob"}
                }),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let vault_entry = mock
            .get_entry("shared", "CFVM", "prod-web")
            .expect("vault copy must still exist");
        assert_eq!(
            vault_entry.password.as_deref(),
            Some("secret"),
            "credentials must survive an edit that omits them"
        );
        assert_eq!(
            vault_entry
                .custom_fields
                .as_ref()
                .and_then(|f| f.get("Environment"))
                .map(String::as_str),
            Some("Production"),
            "existing custom field values must survive a partial map edit"
        );
        assert_eq!(
            vault_entry
                .custom_fields
                .as_ref()
                .and_then(|f| f.get("Owner"))
                .map(String::as_str),
            Some("bob")
        );
        assert_eq!(
            vault_entry.display_name.as_deref(),
            Some("Prod Web Renamed"),
            "friendly name in update changes the vault copy display_name"
        );

        // The DB row agrees with the vault copy.
        let folder = db::get_ab_folder(&db, "shared", "CFVM").unwrap();
        let entries = db::list_ab_entries(&db, folder.id).unwrap();
        assert_eq!(entries[0].name, "prod-web");
        assert_eq!(entries[0].display_name, "Prod Web Renamed");
        let config: Value = serde_json::from_str(&entries[0].protocol_config).unwrap();
        assert_eq!(config["custom_fields"]["Environment"], "Production");
        assert_eq!(config["custom_fields"]["Owner"], "bob");
    }

    #[tokio::test]
    async fn test_custom_fields_endpoint_gates_and_values() {
        let db = test_db();
        // Seed definitions directly (PUT /api/system/settings is covered by
        // the settings unit tests).
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES ('custom_fields', ?1) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![r#"[{"name":"Environment","type":"select","options":["Test","Pilot","Production"]},{"name":"Owner","type":"text"}]"#],
            )
            .unwrap();
        }

        // Operator session can read the definitions.
        insert_test_user(&db, "op@test.com", "Op", "operator");
        let user = db::get_user_by_email(&db, "op@test.com").unwrap();
        let session = db::create_auth_session(&db, user.id, 3600).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/addressbook/custom-fields",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body[0]["name"], "Environment");
        assert_eq!(body[0]["type"], "select");
        assert_eq!(body[0]["options"][2], "Production");
        assert_eq!(body[1]["name"], "Owner");
        assert_eq!(body[1]["type"], "text");

        // Viewer is denied; unauthenticated is denied.
        insert_test_user(&db, "view@test.com", "View", "viewer");
        let user = db::get_user_by_email(&db, "view@test.com").unwrap();
        let view_session = db::create_auth_session(&db, user.id, 3600).unwrap();
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/addressbook/custom-fields",
                &view_session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Admin API key works too.
        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req("GET", "/api/addressbook/custom-fields", &key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        // Empty by default: a fresh DB returns [].
        let db2 = test_db();
        insert_test_user(&db2, "op2@test.com", "Op2", "operator");
        let user = db::get_user_by_email(&db2, "op2@test.com").unwrap();
        let session = db::create_auth_session(&db2, user.id, 3600).unwrap();
        let app = build_router(db2.clone(), test_vault_state(), None);
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/addressbook/custom-fields",
                &session,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(body, json!([]), "feature is off by default");
    }

    // ── Bulk auto-size defaults apply (persea#142) ────────────────────────

    #[tokio::test]
    async fn test_apply_auto_size_defaults_updates_entries_and_is_idempotent() {
        let db = test_db();
        let folder = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "win1",
            "Win 1",
            "rdp",
            "10.0.0.5",
            Some(3389),
            "user",
            r#"{"security":"nla"}"#,
            "",
        )
        .unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "ssh1",
            "Ssh 1",
            "ssh",
            "10.0.0.7",
            Some(22),
            "user",
            "{}",
            "",
        )
        .unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "web1",
            "Web 1",
            "web",
            "10.0.0.6",
            Some(80),
            "user",
            "{}",
            "",
        )
        .unwrap();

        // Defaults are unset, so the fallback (true) applies to rdp + ssh
        // entries; the web entry must be untouched.
        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["applied"], json!(2));
        let protocols = body["protocols"].as_array().unwrap();
        assert!(protocols.contains(&json!("rdp")), "got: {protocols:?}");
        assert!(protocols.contains(&json!("ssh")), "got: {protocols:?}");
        assert_eq!(body["auto_size"]["rdp"], json!(true));
        assert_eq!(body["auto_size"]["ssh"], json!(true));

        let entries = db::list_ab_entries(&db, folder).unwrap();
        for e in &entries {
            let cfg: Value = serde_json::from_str(&e.protocol_config).unwrap();
            match e.protocol.as_str() {
                "rdp" | "ssh" => {
                    assert_eq!(cfg["auto_size"], json!(true), "entry {}", e.name);
                }
                "web" => {
                    assert!(cfg.get("auto_size").is_none(), "web entry must not change");
                }
                _ => panic!("unexpected protocol {}", e.protocol),
            }
        }

        // Idempotent: a second apply changes nothing and counts 0.
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["applied"], json!(0), "second apply must be a no-op");
    }

    #[tokio::test]
    async fn test_apply_auto_size_defaults_scope_and_stored_default() {
        let db = test_db();
        let folder = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "win1",
            "Win 1",
            "rdp",
            "10.0.0.5",
            Some(3389),
            "user",
            r#"{"auto_size":true}"#,
            "",
        )
        .unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "ssh1",
            "Ssh 1",
            "ssh",
            "10.0.0.7",
            Some(22),
            "user",
            "{}",
            "",
        )
        .unwrap();
        // Global defaults: both protocols stored as off.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES ('default_rdp_auto_size', 'false') ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES ('default_ssh_auto_size', 'false') ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                [],
            )
            .unwrap();
        }

        // ssh scope only: the rdp entry keeps its stored true; the ssh
        // entry takes the stored false default.
        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({"protocols": ["ssh"]}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["applied"], json!(1));

        let entries = db::list_ab_entries(&db, folder).unwrap();
        for e in &entries {
            let cfg: Value = serde_json::from_str(&e.protocol_config).unwrap();
            match e.protocol.as_str() {
                "rdp" => assert_eq!(
                    cfg["auto_size"],
                    json!(true),
                    "rdp scope must not touch rdp entries"
                ),
                "ssh" => assert_eq!(
                    cfg["auto_size"],
                    json!(false),
                    "ssh entries get the stored ssh default"
                ),
                _ => panic!("unexpected protocol {}", e.protocol),
            }
        }
    }

    #[tokio::test]
    async fn test_apply_defaults_writes_security_and_auth_pkg_to_rdp_only() {
        let db = test_db();
        let folder = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "win1",
            "Win 1",
            "rdp",
            "10.0.0.5",
            Some(3389),
            "user",
            r#"{"auto_size":false,"security":"rdp","auth_pkg":"ntlm"}"#,
            "",
        )
        .unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "ssh1",
            "Ssh 1",
            "ssh",
            "10.0.0.7",
            Some(22),
            "user",
            r#"{}"#,
            "",
        )
        .unwrap();
        // Stored global defaults: security nla, auth package kerberos,
        // auto-size off for both protocols.
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
                [],
            )
            .unwrap();
            for (key, value) in [
                ("default_rdp_auto_size", "false"),
                ("default_ssh_auto_size", "false"),
                ("default_rdp_security", "nla"),
                ("default_rdp_auth_pkg", "kerberos"),
            ] {
                conn.execute(
                    "INSERT INTO system_settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    rusqlite::params![key, value],
                )
                .unwrap();
            }
        }

        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["applied"], json!(2));
        assert_eq!(body["security"]["rdp"], json!("nla"));
        assert_eq!(body["auth_pkg"]["rdp"], json!("kerberos"));

        let entries = db::list_ab_entries(&db, folder).unwrap();
        for e in &entries {
            let cfg: Value = serde_json::from_str(&e.protocol_config).unwrap();
            match e.protocol.as_str() {
                "rdp" => {
                    assert_eq!(cfg["auto_size"], json!(false), "entry {}", e.name);
                    assert_eq!(cfg["security"], json!("nla"), "entry {}", e.name);
                    assert_eq!(cfg["auth_pkg"], json!("kerberos"), "entry {}", e.name);
                }
                "ssh" => {
                    assert_eq!(cfg["auto_size"], json!(false), "entry {}", e.name);
                    assert!(
                        cfg.get("security").is_none(),
                        "ssh entries must not get the RDP security default"
                    );
                    assert!(
                        cfg.get("auth_pkg").is_none(),
                        "ssh entries must not get the RDP auth package default"
                    );
                }
                _ => panic!("unexpected protocol {}", e.protocol),
            }
        }
    }

    #[tokio::test]
    async fn test_apply_defaults_unset_keys_leave_entry_values_untouched() {
        let db = test_db();
        let folder = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "win1",
            "Win 1",
            "rdp",
            "10.0.0.5",
            Some(3389),
            "user",
            r#"{"auth_pkg":"kerberos","security":"nla"}"#,
            "",
        )
        .unwrap();
        // No stored defaults at all: only auto-size falls back to true; the
        // unset security and auth-package keys must leave the per-entry
        // values untouched (matching the create-path precedence).
        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({"protocols": ["rdp"]}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["applied"], json!(1));

        let entries = db::list_ab_entries(&db, folder).unwrap();
        let cfg: Value = serde_json::from_str(&entries[0].protocol_config).unwrap();
        assert_eq!(
            cfg["auth_pkg"],
            json!("kerberos"),
            "per-entry auth package kept"
        );
        assert_eq!(cfg["security"], json!("nla"), "per-entry security kept");
        assert_eq!(cfg["auto_size"], json!(true));
    }

    #[tokio::test]
    async fn test_apply_auto_size_defaults_admin_gated_and_validates_protocols() {
        let db = test_db();
        let folder = db::create_ab_folder(&db, "shared", "IT", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            folder,
            "win1",
            "Win 1",
            "rdp",
            "10.0.0.5",
            Some(3389),
            "user",
            "{}",
            "",
        )
        .unwrap();

        // An authenticated operator is denied.
        insert_test_user(&db, "op@test.com", "Op", "operator");
        let user = db::get_user_by_email(&db, "op@test.com").unwrap();
        let session = db::create_auth_session(&db, user.id, 3600).unwrap();
        let mut req = Request::builder()
            .method("PUT")
            .uri("/api/addressbook/defaults/apply")
            .header("cookie", format!("persea_session={session}"))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // An unknown protocol is rejected up front.
        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(json_req(
                "PUT",
                "/api/addressbook/defaults/apply",
                &key,
                json!({"protocols": ["vnc"]}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Nothing was written by either failed attempt.
        let entries = db::list_ab_entries(&db, folder).unwrap();
        let cfg: Value = serde_json::from_str(&entries[0].protocol_config).unwrap();
        assert!(cfg.get("auto_size").is_none());
    }

    // ── Address book ACL hardening (persea#33) ─────────────────────────────

    fn insert_user_with_groups(db: &Db, email: &str, role: &str, groups: &[&str]) -> String {
        let groups: Vec<String> = groups.iter().map(|g| g.to_string()).collect();
        let user = db::upsert_user(db, email, email, None, role, &groups).unwrap();
        db::create_auth_session(db, user.id, 3600).unwrap()
    }

    fn build_quick_connect_router(db: Db, vault: VaultState) -> axum::Router {
        use axum::routing::get;
        let manager: AppState = Arc::new(crate::session::SessionManager::new_with_db(
            crate::config::Config::default(),
            None,
            db.clone(),
        ));
        axum::Router::new()
            .route("/api/connect", get(super::quick_connect))
            .with_state(manager)
            .layer(axum::middleware::from_fn(crate::auth::optional_auth))
            .layer(Extension(vault))
            .layer(Extension(OidcEnabled(false)))
            .layer(Extension(db))
    }

    #[test]
    fn folder_allowed_db_user_sees_unrestricted_folder() {
        let db = test_db();
        db::create_ab_folder(&db, "shared", "Public", "", "", false).unwrap();
        let groups: Vec<String> = Vec::new();
        assert!(
            folder_allowed_for_user(&db, "shared", "Public", &groups),
            "a folder without an ACL must be visible to users without groups"
        );
    }

    #[test]
    fn folder_allowed_restricted_parent_stays_restricted() {
        let db = test_db();
        db::create_ab_folder(&db, "shared", "Clients", "", "ops", false).unwrap();
        db::create_ab_folder(&db, "shared", "Clients/Acme", "", "", true).unwrap();
        let folder = db::get_ab_folder(&db, "shared", "Clients/Acme").unwrap();
        db::create_ab_entry(
            &db,
            folder.id,
            "web1",
            "Web 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap();

        let ops: Vec<String> = vec!["ops".to_string()];
        let other: Vec<String> = vec!["other".to_string()];
        assert!(
            !folder_allowed_for_user(&db, "shared", "Clients/Acme", &other),
            "a child folder under a restricted parent must not open up via ungrouped entries"
        );
        assert!(folder_allowed_for_user(&db, "shared", "Clients/Acme", &ops));
    }

    #[test]
    fn folder_allowed_inheritance_matrix() {
        let db = test_db();
        // Restricted chain: parent, child and grandchild all inherit.
        db::create_ab_folder(&db, "shared", "Clients", "", "ops", false).unwrap();
        db::create_ab_folder(&db, "shared", "Clients/Acme", "", "", true).unwrap();
        db::create_ab_folder(&db, "shared", "Clients/Acme/Prod", "", "", true).unwrap();
        // Open chain: no ACL anywhere, so the subtree stays unrestricted.
        db::create_ab_folder(&db, "shared", "Public", "", "", false).unwrap();
        db::create_ab_folder(&db, "shared", "Public/Open", "", "", false).unwrap();

        let ops: Vec<String> = vec!["ops".to_string()];
        let other: Vec<String> = vec!["other".to_string()];
        let none: Vec<String> = Vec::new();

        assert!(folder_allowed_for_user(&db, "shared", "Clients", &ops));
        assert!(!folder_allowed_for_user(&db, "shared", "Clients", &other));
        assert!(!folder_allowed_for_user(&db, "shared", "Clients", &none));
        assert!(folder_allowed_for_user(&db, "shared", "Clients/Acme", &ops));
        assert!(!folder_allowed_for_user(
            &db,
            "shared",
            "Clients/Acme",
            &other
        ));
        assert!(!folder_allowed_for_user(
            &db,
            "shared",
            "Clients/Acme",
            &none
        ));
        assert!(folder_allowed_for_user(
            &db,
            "shared",
            "Clients/Acme/Prod",
            &ops
        ));
        assert!(!folder_allowed_for_user(
            &db,
            "shared",
            "Clients/Acme/Prod",
            &other
        ));
        assert!(!folder_allowed_for_user(
            &db,
            "shared",
            "Clients/Acme/Prod",
            &none
        ));

        assert!(folder_allowed_for_user(&db, "shared", "Public", &none));
        assert!(folder_allowed_for_user(&db, "shared", "Public/Open", &none));
    }

    #[test]
    fn folder_requests_default_inherit_to_true() {
        let create: CreateFolderRequest =
            serde_json::from_str(r#"{"name": "Clients/Acme", "allowed_groups": []}"#).unwrap();
        assert!(
            create.inherit_from_parent,
            "API-created folders must inherit the nearest ancestor ACL by default"
        );
        let update: UpdateFolderRequest =
            serde_json::from_str(r#"{"allowed_groups": []}"#).unwrap();
        assert!(update.inherit_from_parent);
    }

    #[tokio::test]
    async fn ab_list_entries_gates_metadata_by_entry_acl() {
        let db = test_db();
        // Folder ACL admits both test groups; the entry ACL does the gating.
        db::create_ab_folder(&db, "shared", "Clients", "", "ops,other", false).unwrap();
        let folder = db::get_ab_folder(&db, "shared", "Clients").unwrap();
        db::create_ab_entry(
            &db,
            folder.id,
            "open1",
            "Open 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap();
        db::create_ab_entry(
            &db,
            folder.id,
            "restricted1",
            "Restricted 1",
            "ssh",
            "10.0.0.2",
            Some(22),
            "root",
            "{}",
            "ops",
        )
        .unwrap();

        // A user outside the entry's group sees only the open entry.
        let session = insert_user_with_groups(&db, "alice@test.com", "operator", &["other"]);
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/addressbook/folders/shared/Clients/entries",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec!["open1"],
            "entries restricted to other groups must not be listed"
        );

        // A member of the entry's group sees it; an admin sees everything.
        let session = insert_user_with_groups(&db, "bob@test.com", "operator", &["ops"]);
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/addressbook/folders/shared/Clients/entries",
                &session,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["open1", "restricted1"]);

        let key = insert_test_admin(&db, "admin");
        let app = build_router(db.clone(), test_vault_state(), None);
        let response = app
            .oneshot(auth_req(
                "GET",
                "/api/addressbook/folders/shared/Clients/entries",
                &key,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(body.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn quick_connect_denied_for_entry_restricted_groups() {
        let db = test_db();
        db::create_ab_folder(&db, "shared", "Clients", "", "team", false).unwrap();
        let folder = db::get_ab_folder(&db, "shared", "Clients").unwrap();
        db::create_ab_entry(
            &db,
            folder.id,
            "web1",
            "Web 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "ops",
        )
        .unwrap();

        let session = insert_user_with_groups(&db, "alice@test.com", "operator", &["team"]);
        let user = db::get_user_by_email(&db, "alice@test.com").unwrap();
        rbac::grant_connection_permission(
            &db,
            &format!("u:{}", user.id),
            "shared/Clients/web1",
            rbac::ObjectPermission::Connect,
        )
        .unwrap();

        let app = build_quick_connect_router(db.clone(), test_vault_state());
        let response = app
            .oneshot(session_req(
                "GET",
                "/api/connect?scope=shared&folder=Clients&entry=web1",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "quick connect must enforce the entry ACL even when the folder and the RBAC Connect grant allow it"
        );
    }

    #[tokio::test]
    async fn quick_connect_requires_rbac_connect_grant() {
        let db = test_db();
        db::create_ab_folder(&db, "shared", "Clients", "", "", false).unwrap();
        let folder = db::get_ab_folder(&db, "shared", "Clients").unwrap();
        db::create_ab_entry(
            &db,
            folder.id,
            "web1",
            "Web 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap();

        let session = insert_user_with_groups(&db, "bob@test.com", "operator", &[]);
        let user = db::get_user_by_email(&db, "bob@test.com").unwrap();

        let app = build_quick_connect_router(db.clone(), test_vault_state());
        let denied = app
            .clone()
            .oneshot(session_req(
                "GET",
                "/api/connect?scope=shared&folder=Clients&entry=web1",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(
            denied.status(),
            StatusCode::FORBIDDEN,
            "quick connect without an RBAC Connect grant must be denied"
        );

        rbac::grant_connection_permission(
            &db,
            &format!("u:{}", user.id),
            "shared/Clients/web1",
            rbac::ObjectPermission::Connect,
        )
        .unwrap();
        let allowed = app
            .oneshot(session_req(
                "GET",
                "/api/connect?scope=shared&folder=Clients&entry=web1",
                &session,
            ))
            .await
            .unwrap();
        assert_eq!(
            allowed.status(),
            StatusCode::OK,
            "with the Connect grant the credential prompt is served"
        );
    }

    // ── Personal folders API (persea#138 / persea#166) ──────────────────

    fn make_session(db: &Db, email: &str, role: &str) -> String {
        insert_test_user(db, email, email, role);
        let user = db::get_user_by_email(db, email).unwrap();
        db::create_auth_session(db, user.id, 3600).unwrap()
    }

    fn session_json_req(method: &str, uri: &str, session: &str, body: Value) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("cookie", format!("persea_session={}", session))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(test_addr()));
        req
    }

    /// Reusable shared folder plus a fresh entry; returns the entry id.
    fn make_shared_entry(db: &Db, name: &str) -> i64 {
        let folder_id = match db::get_ab_folder(db, "shared", "Shared") {
            Ok(f) => f.id,
            Err(_) => db::create_ab_folder(db, "shared", "Shared", "", "", false).unwrap(),
        };
        db::create_ab_entry(
            db,
            folder_id,
            name,
            "",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap()
    }

    /// Create a personal folder via the API; returns its id.
    async fn make_personal_folder(app: &axum::Router, session: &str, name: &str) -> i64 {
        let response = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                "/api/personal/folders",
                session,
                json!({"name": name}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        body_json(response).await["id"].as_i64().unwrap()
    }

    #[tokio::test]
    async fn test_personal_folders_create_list_and_validate() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);

        let a = make_personal_folder(&app, &alice, "Work").await;
        let b = make_personal_folder(&app, &alice, "Work/Acme").await;
        let c = make_personal_folder(&app, &alice, "Personal").await;
        assert!(a > 0 && b > 0 && c > 0);

        // Flat list with slash paths, ordered by name.
        let response = app
            .clone()
            .oneshot(session_req("GET", "/api/personal/folders", &alice))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["Personal", "Work", "Work/Acme"]);
        assert_eq!(body[1]["path"], "Work");
        assert_eq!(body[1]["has_children"], json!(true));
        assert_eq!(body[2]["has_children"], json!(false));
        assert_eq!(body[0]["description"], "");

        // Name validation: empty, slashes at either end, empty segments.
        for bad in ["", "   ", "/x", "x/", "/x/", "a//b", "a/ /b"] {
            let response = app
                .clone()
                .oneshot(session_json_req(
                    "POST",
                    "/api/personal/folders",
                    &alice,
                    json!({"name": bad}),
                ))
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "name {:?} must be rejected",
                bad
            );
        }

        // Duplicate name per user conflicts.
        let response = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                "/api/personal/folders",
                &alice,
                json!({"name": "Work"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // Another user may reuse the same name.
        let bob = make_session(&db, "bob@test.com", "viewer");
        let response = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                "/api/personal/folders",
                &bob,
                json!({"name": "Work"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_personal_folders_owner_isolation() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let bob = make_session(&db, "bob@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);

        let alice_folder = make_personal_folder(&app, &alice, "Work").await;
        let entry = make_shared_entry(&db, "srv1");

        // Bob sees only his own (empty) list.
        let response = app
            .clone()
            .oneshot(session_req("GET", "/api/personal/folders", &bob))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(body_json(response).await, json!([]));

        // Every operation on Alice's folder is a 404 for Bob.
        let uri = format!("/api/personal/folders/{}", alice_folder);
        let rename = app
            .clone()
            .oneshot(session_json_req(
                "PUT",
                &uri,
                &bob,
                json!({"name": "Hijacked"}),
            ))
            .await
            .unwrap();
        assert_eq!(rename.status(), StatusCode::NOT_FOUND);
        let delete = app
            .clone()
            .oneshot(session_req("DELETE", &uri, &bob))
            .await
            .unwrap();
        assert_eq!(delete.status(), StatusCode::NOT_FOUND);

        let list_entries = app
            .clone()
            .oneshot(session_req("GET", &format!("{}/entries", uri), &bob))
            .await
            .unwrap();
        assert_eq!(list_entries.status(), StatusCode::NOT_FOUND);
        let add_entry = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                &format!("{}/entries", uri),
                &bob,
                json!({"scope": "shared", "folder": "Shared", "entry": "srv1"}),
            ))
            .await
            .unwrap();
        assert_eq!(add_entry.status(), StatusCode::NOT_FOUND);
        let remove_entry = app
            .clone()
            .oneshot(session_req(
                "DELETE",
                &format!("{}/entries/{}", uri, entry),
                &bob,
            ))
            .await
            .unwrap();
        assert_eq!(remove_entry.status(), StatusCode::NOT_FOUND);

        // Alice's folder is untouched.
        let response = app
            .clone()
            .oneshot(session_req("GET", "/api/personal/folders", &alice))
            .await
            .unwrap();
        let body = body_json(response).await;
        assert_eq!(body.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_personal_folders_api_key_and_anonymous_denied() {
        let db = test_db();
        let app = build_router(db.clone(), test_vault_state(), None);

        // API key identities have no user row: fail closed with 403.
        let key = insert_test_admin(&db, "admin");
        let response = app
            .clone()
            .oneshot(auth_req("GET", "/api/personal/folders", &key))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(json_req(
                "POST",
                "/api/personal/folders",
                &key,
                json!({"name": "Work"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // No session cookie at all.
        let response = app
            .clone()
            .oneshot(session_req("GET", "/api/personal/folders", "nope"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_personal_folders_rename() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);
        let folder = make_personal_folder(&app, &alice, "Work").await;

        // Rename into a deeper slash path.
        let response = app
            .clone()
            .oneshot(session_json_req(
                "PUT",
                &format!("/api/personal/folders/{}", folder),
                &alice,
                json!({"name": "Career/Lead"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["name"], "Career/Lead");

        // Invalid names are rejected on rename too.
        let response = app
            .clone()
            .oneshot(session_json_req(
                "PUT",
                &format!("/api/personal/folders/{}", folder),
                &alice,
                json!({"name": "/bad"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Renaming onto an existing per-user name conflicts.
        make_personal_folder(&app, &alice, "Work").await;
        let response = app
            .clone()
            .oneshot(session_json_req(
                "PUT",
                &format!("/api/personal/folders/{}", folder),
                &alice,
                json!({"name": "Work"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // A missing folder is a 404, not a 500.
        let response = app
            .clone()
            .oneshot(session_json_req(
                "PUT",
                "/api/personal/folders/999999",
                &alice,
                json!({"name": "Nope"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_personal_folders_entries_add_list_remove() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);
        let folder = make_personal_folder(&app, &alice, "Work").await;
        let entry_a = make_shared_entry(&db, "srv-a");
        let entry_b = make_shared_entry(&db, "srv-b");

        let add = |uri: String, entry: String| {
            let app = app.clone();
            let session = alice.clone();
            async move {
                app.oneshot(session_json_req(
                    "POST",
                    &uri,
                    &session,
                    json!({"scope": "shared", "folder": "Shared", "entry": entry}),
                ))
                .await
                .unwrap()
            }
        };

        let response = add(
            format!("/api/personal/folders/{}/entries", folder),
            "srv-a".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let body = body_json(response).await;
        assert_eq!(body["entry_id"], json!(entry_a));

        // Duplicate references conflict.
        let response = add(
            format!("/api/personal/folders/{}/entries", folder),
            "srv-a".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CONFLICT);

        // A missing shared entry is a 404.
        let response = add(
            format!("/api/personal/folders/{}/entries", folder),
            "nope".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // An entry the caller cannot read is a 404 (no enumeration). The
        // restricted entry lives in its own folder so the open folder's
        // entry fallback stays open.
        db::create_ab_folder(&db, "shared", "Restricted", "", "", false).unwrap();
        db::create_ab_entry(
            &db,
            db::get_ab_folder(&db, "shared", "Restricted").unwrap().id,
            "secret",
            "",
            "ssh",
            "10.0.0.9",
            Some(22),
            "root",
            "{}",
            "admins",
        )
        .unwrap();
        let response = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
                json!({"scope": "shared", "folder": "Restricted", "entry": "secret"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        // The referenced entries resolve to their real rows with the same
        // serialization as the address-book entry lists.
        let response = add(
            format!("/api/personal/folders/{}/entries", folder),
            "srv-b".to_string(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        let response = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["srv-a", "srv-b"]);
        assert_eq!(body[0]["session_type"], "ssh");
        assert_eq!(body[0]["hostname"], "10.0.0.1");
        assert_eq!(body[0]["port"], json!(22));
        assert!(body[0].get("password").is_none(), "no credentials leak");

        // Remove one reference, then the other; a second remove is 404.
        let response = app
            .clone()
            .oneshot(session_req(
                "DELETE",
                &format!("/api/personal/folders/{}/entries/{}", folder, entry_a),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let response = app
            .clone()
            .oneshot(session_req(
                "DELETE",
                &format!("/api/personal/folders/{}/entries/{}", folder, entry_a),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["srv-b"]);
        let _ = entry_b;
    }

    #[tokio::test]
    async fn test_personal_folders_cascade_and_reference_integrity() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);
        let folder = make_personal_folder(&app, &alice, "Work").await;
        let entry_a = make_shared_entry(&db, "srv-a");
        let entry_b = make_shared_entry(&db, "srv-b");
        for (_, entry_name) in [(entry_a, "srv-a"), (entry_b, "srv-b")] {
            let response = app
                .clone()
                .oneshot(session_json_req(
                    "POST",
                    &format!("/api/personal/folders/{}/entries", folder),
                    &alice,
                    json!({"scope": "shared", "folder": "Shared", "entry": entry_name}),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
        }

        // Deleting the shared entry removes its references: the folder
        // survives and the read path skips the gone entry.
        assert!(db::delete_ab_entry(&db, entry_a).unwrap());
        let response = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        let names: Vec<&str> = body
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["srv-b"], "deleted entry is skipped");

        // The shared entry itself is really gone; the folder survives.
        let shared_folder = db::get_ab_folder(&db, "shared", "Shared").unwrap();
        let remaining: Vec<String> = db::list_ab_entries(&db, shared_folder.id)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(remaining, vec!["srv-b".to_string()]);

        // Deleting the personal folder cascades to references only: the
        // shared folder and its remaining entry survive.
        let response = app
            .clone()
            .oneshot(session_req(
                "DELETE",
                &format!("/api/personal/folders/{}", folder),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // The folder is gone, so its entry listing is a 404.
        let response = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let remaining: Vec<String> = db::list_ab_entries(&db, shared_folder.id)
            .unwrap()
            .into_iter()
            .map(|e| e.name)
            .collect();
        assert_eq!(remaining, vec!["srv-b".to_string()]);
        let folders = db::list_user_folders(
            &db,
            db::get_user_by_email(&db, "alice@test.com").unwrap().id,
        )
        .unwrap();
        assert!(folders.is_empty(), "personal folders are gone");
    }
    #[tokio::test]
    async fn test_personal_folders_folder_acl_gates_references() {
        let db = test_db();
        let alice = make_session(&db, "alice@test.com", "viewer");
        let app = build_router(db.clone(), test_vault_state(), None);
        let folder = make_personal_folder(&app, &alice, "Work").await;
        let entry_id = make_shared_entry(&db, "srv-a");
        let response = app
            .clone()
            .oneshot(session_json_req(
                "POST",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
                json!({"scope": "shared", "folder": "Shared", "entry": "srv-a"}),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Visible while the folder is open.
        let list = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        assert_eq!(body_json(list).await.as_array().unwrap().len(), 1);

        // Tighten the folder ACL to a group Alice is not in: the reference
        // must disappear from the personal view (same rule as the shared
        // tree) while the reference row survives.
        let shared_folder = db::get_ab_folder(&db, "shared", "Shared").unwrap();
        db::update_ab_folder(&db, "shared", "Shared", "", "admins", false).unwrap();
        let list = app
            .clone()
            .oneshot(session_req(
                "GET",
                &format!("/api/personal/folders/{}/entries", folder),
                &alice,
            ))
            .await
            .unwrap();
        let body = body_json(list).await;
        assert_eq!(
            body.as_array().unwrap().len(),
            0,
            "a tightened folder hides its references"
        );
        // The reference row itself still exists (folder + entry intact).
        let alice_user = db::get_user_by_email(&db, "alice@test.com").unwrap();
        let refs = db::list_user_folder_entries(&db, alice_user.id, folder).unwrap();
        assert_eq!(refs.len(), 1);
        let _ = entry_id;
    }

    // ── Session credential forwarding (persea#245) ──────────────────────────

    /// Manager whose `[auth] forward_session_credentials` gate is ON and
    /// whose recording dir lives in the system temp dir.
    fn session_credentials_manager(gate_on: bool) -> AppState {
        let mut config = crate::config::Config::default();
        config.recording = Some(crate::config::RecordingConfig {
            path: std::env::temp_dir().join(format!("persea-ab-{}", uuid::Uuid::new_v4())),
            ..Default::default()
        });
        config.auth = Some(crate::config::AuthConfig {
            forward_session_credentials: gate_on,
            ..Default::default()
        });
        Arc::new(crate::session::SessionManager::new(config, None))
    }

    const TEST_ENC_KEY: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn session_headers(token: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(t) = token {
            headers.insert("cookie", format!("persea_session={}", t).parse().unwrap());
        }
        headers
    }

    fn user_identity(email: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: email.to_string(),
            name: email.to_string(),
            role: "operator".into(),
            groups: vec![],
        }
    }

    fn user_id_of(db: &Db, email: &str) -> i64 {
        db::get_user_by_email(db, email).unwrap().id
    }

    fn retained_enc(password: &str) -> String {
        crate::crypto::encrypt_value(
            &crate::crypto::EncryptionKey::from_hex(TEST_ENC_KEY).unwrap(),
            password,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn session_credentials_gate_off_are_never_applied() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let manager = session_credentials_manager(false); // gate OFF
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        let applied = apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        );
        assert!(!applied, "gate off: nothing is forwarded");
        assert!(ab_entry.password.is_none());
    }

    #[tokio::test]
    async fn session_credentials_require_the_owning_session_cookie() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let uid = user_id_of(&db, "alice@test.com");
        let manager = session_credentials_manager(true);
        manager.store_session_credentials(
            "session-token",
            uid,
            "alice",
            retained_enc("DCPScret-p@ss"),
            3600,
        );

        // No cookie at all: nothing applied.
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(None),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        ));
        assert!(ab_entry.password.is_none());
    }

    #[tokio::test]
    async fn session_credentials_are_owned_by_their_session_and_user() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let uid = user_id_of(&db, "alice@test.com");
        let manager = session_credentials_manager(true);
        manager.store_session_credentials(
            "session-token",
            uid,
            "alice",
            retained_enc("p@ssword-1"),
            3600,
        );

        // A different session token: fail closed.
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("other-session")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        ));

        // The same cookie under a different user's identity: fail closed.
        insert_test_user(&db, "mallory@test.com", "Mallory", "viewer");
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("mallory@test.com"),
            &mut ab_entry,
        ));
        assert!(ab_entry.password.is_none());
    }

    #[tokio::test]
    async fn session_credentials_expired_or_mismatched_never_apply() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let uid = user_id_of(&db, "alice@test.com");
        let manager = session_credentials_manager(true);

        // The retained entry belongs to a different user.
        manager.store_session_credentials(
            "session-token",
            uid + 1,
            "alice",
            retained_enc("p@ssword-1"),
            3600,
        );
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        ));

        // A zero-TTL entry is already expired: fail closed.
        manager.store_session_credentials(
            "expired-token",
            uid,
            "alice",
            retained_enc("p@ssword-expired"),
            0,
        );
        let mut ab = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("expired-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab,
        ));
        assert!(ab.password.is_none());
    }

    #[tokio::test]
    async fn session_credentials_apply_after_entry_and_preset_miss() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let uid = user_id_of(&db, "alice@test.com");
        let manager = session_credentials_manager(true);
        manager.store_session_credentials(
            "session-token",
            uid,
            "alice",
            retained_enc("p@ssword-session"),
            3600,
        );

        // Credential-less entry: the session credentials fill username +
        // password with the decrypted value.
        let mut ab_entry = crate::vault::AddressBookEntry {
            session_type: "ssh".into(),
            hostname: Some("target.example.com".into()),
            ..Default::default()
        };
        let applied = apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        );
        assert!(applied, "credential-less entry takes the session credentials");
        assert_eq!(ab_entry.username.as_deref(), Some("alice"));
        assert_eq!(ab_entry.password.as_deref(), Some("p@ssword-session"));

        // An entry that already resolved a password (entry or preset
        // credentials) is left untouched: the chain keeps entry → preset →
        // session ordering.
        let mut ab_entry = crate::vault::AddressBookEntry {
            session_type: "ssh".into(),
            password: Some("preset-p@ss".into()),
            ..Default::default()
        };
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &user_identity("alice@test.com"),
            &mut ab_entry,
        ));
        assert_eq!(ab_entry.password.as_deref(), Some("preset-p@ss"));
    }

    #[tokio::test]
    async fn session_credentials_skip_api_key_identities() {
        let db = test_db();
        insert_test_user(&db, "alice@test.com", "Alice", "operator");
        let uid = user_id_of(&db, "alice@test.com");
        let manager = session_credentials_manager(true);
        manager.store_session_credentials(
            "session-token",
            uid,
            "alice",
            retained_enc("p@ssword-key"),
            3600,
        );
        // API key identities have no session: fail closed.
        let mut ab_entry = crate::vault::AddressBookEntry::default();
        assert!(!apply_session_credentials(
            &manager,
            &db,
            &session_headers(Some("session-token")),
            Some(&StorageKey(Some(TEST_ENC_KEY.into()))),
            &AuthIdentity::ApiKey("admin".into()),
            &mut ab_entry,
        ));
        assert!(ab_entry.password.is_none());
    }
}
