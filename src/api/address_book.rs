use super::{AppState, VaultBackends, VaultState};
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::session::{CreateSessionRequest, SessionType};
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
    let _ = tokio::task::spawn_blocking(move || {
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
    .await;
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
        Err(VaultError::NotFound) => {
            Err(AppError::Vault("folder not found".into()))
        }
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
    Extension(vault): Extension<VaultState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    let folders = vault.list_all_folders().await.map_err(|e| {
        AppError::Vault(e.to_string())
    })?.0;

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

    Ok(Json(json!(visible)))
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

    let (folders, unavailable_scopes) = vault.list_all_folders().await.map_err(|e| {
        AppError::Vault(e.to_string())
    })?;

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

    Ok(Json(json!({"folders": result, "unavailable_scopes": unavailable_scopes})))
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

    let top = vault.list_all_folders().await.map_err(|e| {
        AppError::Vault(e.to_string())
    })?.0;

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
    Extension(vault): Extension<VaultState>,
    Path((scope, folder)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id,
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

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
    Extension(vault): Extension<VaultState>,
    Path((scope, folder, entry)): Path<(String, String, String)>,
    Json(req): Json<ConnectRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => return Err(AppError::Forbidden("operator role required".into())),
    };

    check_folder_access(&vault, &scope, &folder, &id).await?;

    let ab_entry = match vault.get_entry(&scope, &folder, &entry).await {
        Ok(e) => e,
        Err(VaultError::NotFound) => {
            return Err(AppError::Vault("entry not found".into()))
        }
        Err(e) => return Err(AppError::Vault(e.to_string())),
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
        private_key: ab_entry.private_key,
        generate_keypair: None,
        url: ab_entry.url,
        domain: req.domain.or(ab_entry.domain),
        security: ab_entry.security,
        ignore_cert: ab_entry.ignore_cert,
        auth_pkg: ab_entry.auth_pkg,
        kdc_url: ab_entry.kdc_url,
        kerberos_cache: None,
        color_depth: ab_entry.color_depth,
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
        remote_app: ab_entry.remote_app,
        remote_app_dir: ab_entry.remote_app_dir,
        remote_app_args: ab_entry.remote_app_args,
        enable_recording: ab_entry.enable_recording,
        record_typescript: ab_entry.record_typescript,
        address_book_entry: Some(ab_entry_key),
        address_book_folder: Some(folder.to_string()),
        entry_display_name: ab_entry.display_name.clone(),
        max_recordings: ab_entry.max_recordings,
        login_script: ab_entry.login_script,
        autofill: ab_entry.autofill,
        allowed_domains: ab_entry.allowed_domains,
        disable_copy: ab_entry.disable_copy,
        disable_paste: ab_entry.disable_paste,
        enable_gfx: ab_entry.enable_gfx,
        enable_desktop_composition: ab_entry.enable_desktop_composition,
        enable_wallpaper: ab_entry.enable_wallpaper,
        enable_theming: ab_entry.enable_theming,
        enable_full_window_drag: ab_entry.enable_full_window_drag,
        force_lossless: ab_entry.force_lossless,
        enable_h264: ab_entry.enable_h264,
        container_image: ab_entry.container_image,
        container_cpu_limit: ab_entry.container_cpu_limit,
        container_memory_limit: ab_entry.container_memory_limit,
        container_env: ab_entry.container_env,
        container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
        container_username: ab_entry.container_username,
        container_password: ab_entry.container_password,
        allow_sharing: ab_entry.allow_sharing,
        fullscreen_on_connect: ab_entry.fullscreen_on_connect,
        autohide_side_tabs: ab_entry.autohide_side_tabs,
        spice_tls: ab_entry.spice_tls,
        spice_tls_port: ab_entry.spice_tls_port,
        spice_ca_cert: ab_entry.spice_ca_cert,
        spice_cert_subject: ab_entry.spice_cert_subject,
        spice_proxy: ab_entry.spice_proxy,
        proxmox_url: ab_entry.proxmox_url,
        proxmox_node: ab_entry.proxmox_node,
        proxmox_vmid: ab_entry.proxmox_vmid,
        proxmox_token_id: ab_entry.proxmox_token_id,
        proxmox_token_secret: ab_entry.proxmox_token_secret,
        proxmox_verify_tls: ab_entry.proxmox_verify_tls,
        max_monitors: ab_entry.max_monitors,
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

#[allow(clippy::too_many_arguments)]
pub async fn ab_create_folder(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    Extension(vault): Extension<VaultState>,
    Json(req): Json<CreateFolderRequest>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    let allowed_count = req.allowed_groups.len();
    let inherit = req.inherit_from_parent;
    let config = FolderConfig {
        allowed_groups: req.allowed_groups,
        description: req.description,
        inherit_from_parent: req.inherit_from_parent,
    };

    match vault
        .put_folder_config(&req.scope, &req.name, &config)
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
                &req.scope,
                &req.name,
                None,
                &ip,
                Some(&details),
            )
            .await;
            (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
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
    Path((scope, folder)): Path<(String, String)>,
    Json(req): Json<CreateEntryRequest>,
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
    };

    let session_type = req.entry.session_type.clone();
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
            (StatusCode::CREATED, Json(json!({"ok": true}))).into_response()
        }
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
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
) -> impl IntoResponse {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => {
            return (
                StatusCode::FORBIDDEN,
                Json(json!({"error": "admin role required"})),
            )
                .into_response()
        }
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
            StatusCode::NO_CONTENT.into_response()
        }
        Err(VaultError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "entry not found"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
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
            private_key: ab_entry.private_key,
            generate_keypair: None,
            url: ab_entry.url,
            domain: ab_entry.domain,
            security: ab_entry.security,
            ignore_cert: ab_entry.ignore_cert,
            auth_pkg: ab_entry.auth_pkg,
            kdc_url: ab_entry.kdc_url,
            kerberos_cache: None,
            color_depth: ab_entry.color_depth,
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
            remote_app: ab_entry.remote_app,
            remote_app_dir: ab_entry.remote_app_dir,
            remote_app_args: ab_entry.remote_app_args,
            enable_recording: ab_entry.enable_recording,
            record_typescript: ab_entry.record_typescript,
            address_book_entry: Some(ab_entry_key),
            address_book_folder: Some(folder.to_string()),
            entry_display_name: ab_entry.display_name.clone(),
            max_recordings: ab_entry.max_recordings,
            login_script: ab_entry.login_script,
            autofill: ab_entry.autofill,
            allowed_domains: ab_entry.allowed_domains,
            disable_copy: ab_entry.disable_copy,
            disable_paste: ab_entry.disable_paste,
            enable_gfx: ab_entry.enable_gfx,
            enable_desktop_composition: ab_entry.enable_desktop_composition,
            enable_wallpaper: ab_entry.enable_wallpaper,
            enable_theming: ab_entry.enable_theming,
            enable_full_window_drag: ab_entry.enable_full_window_drag,
            force_lossless: ab_entry.force_lossless,
            enable_h264: ab_entry.enable_h264,
            container_image: ab_entry.container_image,
            container_cpu_limit: ab_entry.container_cpu_limit,
            container_memory_limit: ab_entry.container_memory_limit,
            container_env: ab_entry.container_env,
            container_idle_timeout_mins: ab_entry.container_idle_timeout_mins,
            container_username: ab_entry.container_username,
            container_password: ab_entry.container_password,
            allow_sharing: ab_entry.allow_sharing,
            fullscreen_on_connect: ab_entry.fullscreen_on_connect,
            autohide_side_tabs: ab_entry.autohide_side_tabs,
            spice_tls: ab_entry.spice_tls,
            spice_tls_port: ab_entry.spice_tls_port,
            spice_ca_cert: ab_entry.spice_ca_cert,
            spice_cert_subject: ab_entry.spice_cert_subject,
            spice_proxy: ab_entry.spice_proxy,
            proxmox_url: None,
            proxmox_node: None,
            proxmox_vmid: None,
            proxmox_token_id: None,
            proxmox_token_secret: None,
            proxmox_verify_tls: None,
            max_monitors: None,
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
        password: None,
        private_key: None,
        generate_keypair: None,
        url: query.url,
        domain: None,
        security: None,
        ignore_cert: None,
        auth_pkg: None,
        kdc_url: None,
        kerberos_cache: None,
        color_depth: None,
        jump_hosts: None,
        jump_host: None,
        jump_port: None,
        jump_username: None,
        jump_password: None,
        jump_private_key: None,
        width: query.width,
        height: query.height,
        dpi: query.dpi,
        banner: None,
        enable_drive: None,
        remote_app: None,
        remote_app_dir: None,
        remote_app_args: None,
        enable_recording: None,
        record_typescript: None,
        address_book_entry: None,
        address_book_folder: None,
        entry_display_name: None,
        max_recordings: None,
        login_script: None,
        autofill: None,
        allowed_domains: None,
        disable_copy: None,
        disable_paste: None,
        enable_gfx: None,
        enable_desktop_composition: None,
        enable_wallpaper: None,
        enable_theming: None,
        enable_full_window_drag: None,
        force_lossless: None,
        enable_h264: None,
        container_image: None,
        container_cpu_limit: None,
        container_memory_limit: None,
        container_env: None,
        container_idle_timeout_mins: None,
        container_username: None,
        container_password: None,
        allow_sharing: None,
        fullscreen_on_connect: None,
        autohide_side_tabs: None,
        spice_tls: None,
        spice_tls_port: None,
        spice_ca_cert: None,
        spice_cert_subject: None,
        spice_proxy: None,
        proxmox_url: None,
        proxmox_node: None,
        proxmox_vmid: None,
        proxmox_token_id: None,
        proxmox_token_secret: None,
        proxmox_verify_tls: None,
        max_monitors: None,
    };

    match manager.create_session(create_req, admin_name).await {
        Ok(info) => Redirect::temporary(&format!("/client/{}", info.session_id)).into_response(),
        Err(e) => quick_connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}
