//! vSphere inventory and session-start endpoints.
//!
//! Connects to vCenter, caches the VM inventory, and routes VM sessions to
//! RDP or SSH depending on the detected guest OS. Returns a
//! `{"configured": false, "vms": []}` shape when vSphere is not configured
//! so the connections page can hide the section.
use crate::api::AppState;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::db::Db;
use crate::error::AppError;
use crate::session::{CreateSessionRequest, RdpParams, SessionType, SshParams, VncParams};
use crate::vsphere::{self, VsphereClient, VsphereConfig};
use axum::extract::{ConnectInfo, Extension, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Json;
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Shared vSphere client state, wrapped in Arc<Mutex<>> for handler access.
pub type VsphereState = Option<Arc<Mutex<VsphereClient>>>;

/// Connect to vCenter and store the client in shared state.
pub async fn connect_vsphere(config: &VsphereConfig) -> VsphereState {
    match vsphere::connect(config).await {
        Ok(client) => Some(Arc::new(Mutex::new(client))),
        Err(e) => {
            tracing::error!(error = %e, "vSphere connection failed");
            None
        }
    }
}

/// GET /api/vsphere/vms
///
/// List VMs from vCenter. Returns the cached inventory or fetches fresh data.
/// When vSphere is not configured this returns HTTP 200 with
/// `{"configured": false, "vms": []}` so the connections page can hide the
/// section without triggering error-level logs on every load. The
/// `enable_vmware` admin toggle (system_settings) reports the same
/// not-configured shape even when `[vsphere]` config exists.
pub async fn list_vms(
    identity: Option<Extension<AuthIdentity>>,
    Extension(db): Extension<Db>,
    Extension(client): Extension<VsphereState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Forbidden("login required".into()))?;
    if !id.has_role("operator") {
        return Err(AppError::Forbidden("operator role required".into()));
    }

    if !crate::settings_merge::read_toggle(&db, "enable_vmware", true) {
        return Ok(Json(json!({"configured": false, "vms": []})));
    }

    let Some(client) = client else {
        return Ok(Json(json!({"configured": false, "vms": []})));
    };

    let mut client = client.lock().await;
    let vms = vsphere::list_vms(&mut client).await?;

    // Enrich each VM with the Guacamole protocol + default port detected from
    // its guest OS identifier, so the UI never re-derives the mapping.
    let enriched: Vec<serde_json::Value> = vms
        .iter()
        .map(|vm| {
            let (protocol, port) = vsphere::detect_protocol(&vm.guest_os);
            let mut obj = serde_json::to_value(vm).unwrap_or_else(|_| json!({}));
            obj["protocol"] = json!(protocol);
            obj["port"] = json!(port);
            obj
        })
        .collect();

    Ok(Json(json!({"configured": true, "vms": enriched})))
}

/// POST /api/vsphere/vms/{vm_id}/power
///
/// Perform a power action on a VM. Body: `{ "action": "on|off|suspend|reset" }`
pub async fn power_action(
    identity: Option<Extension<AuthIdentity>>,
    Extension(client): Extension<VsphereState>,
    axum::extract::Path(vm_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or_else(|| AppError::Forbidden("login required".into()))?;
    if !id.has_role("operator") {
        return Err(AppError::Forbidden("operator role required".into()));
    }

    if vm_id.len() > 128
        || !vm_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(AppError::Validation("invalid vm_id".into()));
    }

    let Some(client) = client else {
        return Err(AppError::Vsphere(
            "vSphere not configured or unavailable".into(),
        ));
    };

    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("missing 'action' field".into()))?;

    let mut client = client.lock().await;
    vsphere::power_action(&mut client, &vm_id, action).await?;
    Ok(Json(json!({ "ok": true })))
}

/// Render an HTML error page for a failed vSphere connect (mirrors the
/// address-book quick-connect error page).
fn connect_error(status: StatusCode, message: &str) -> Response {
    let html = format!(
        r#"<!DOCTYPE html>
<html><head><title>Connection Error</title>
<style>body{{font-family:system-ui,sans-serif;max-width:600px;margin:80px auto;padding:0 20px}}
h1{{color:#c00}}a{{color:#06c}}</style></head>
<body><h1>Connection Error</h1><p>{}</p>
<p><a href="/connections.html">Return to connections</a></p></body></html>"#,
        crate::api::address_book::html_escape(message)
    );
    (status, axum::response::Html(html)).into_response()
}

/// GET /api/vsphere/vms/{vm_id}/connect
///
/// Create a session to a vSphere VM and redirect to its client page. The
/// protocol (RDP/SSH/VNC) is detected from the guest OS identifier via
/// `detect_protocol()`. Guest credentials come from the matching
/// `[vsphere.vm_credentials]` override, falling back to the global vSphere
/// username and password env var. Mirrors the `/api/connect` GET pattern.
#[allow(clippy::too_many_arguments)]
pub async fn connect_vm(
    State(manager): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(client): Extension<VsphereState>,
    Path(vm_id): Path<String>,
) -> Response {
    let id = match identity {
        Some(Extension(ref id)) if id.has_role("operator") => id.clone(),
        _ => {
            return connect_error(
                StatusCode::FORBIDDEN,
                "Operator role or higher required to connect to vSphere VMs.",
            );
        }
    };

    let Some(client) = client else {
        return connect_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "vSphere not configured or unavailable.",
        );
    };

    let mut client = client.lock().await;

    // Force a fresh inventory fetch if the cache is empty, then find the VM.
    let vms = match vsphere::list_vms(&mut client).await {
        Ok(vms) => vms,
        Err(e) => {
            return connect_error(StatusCode::BAD_GATEWAY, &e.to_string());
        }
    };
    let Some(vm) = vms.iter().find(|v| v.vm_id == vm_id) else {
        return connect_error(StatusCode::NOT_FOUND, "VM not found in vCenter inventory.");
    };

    if vm.power_state != crate::vsphere::PowerState::PoweredOn {
        return connect_error(
            StatusCode::CONFLICT,
            &format!("VM '{}' is not powered on.", vm.name),
        );
    }
    let Some(ip) = vm.ip_address.as_deref() else {
        return connect_error(
            StatusCode::CONFLICT,
            &format!(
                "VM '{}' has no guest IP — is VMware Tools running?",
                vm.name
            ),
        );
    };

    // Resolve guest credentials: per-VM override (by name or ID) wins,
    // otherwise the global vSphere username + password env var.
    let (username, password) = client
        .config
        .vm_credentials
        .get(&vm.name)
        .or_else(|| client.config.vm_credentials.get(&vm.vm_id))
        .map(|c| (c.username.clone(), std::env::var(&c.password_env).ok()))
        .unwrap_or_else(|| {
            (
                client.config.username.clone(),
                std::env::var(&client.config.password_env).ok(),
            )
        });

    let (protocol, port) = crate::vsphere::detect_protocol(&vm.guest_os);
    let session_type = match protocol.as_str() {
        "rdp" => SessionType::Rdp,
        "ssh" => SessionType::Ssh,
        _ => SessionType::Vnc,
    };

    let proxies = trusted.map(|Extension(t)| t.0).unwrap_or_default();
    let client_ip = client_ip(&headers, addr.ip(), &proxies);
    let user_name = id.display_name().to_string();

    tracing::info!(
        user = %user_name,
        client_ip = %client_ip,
        vm = %vm.name,
        vm_id = %vm_id,
        protocol = %protocol,
        ip = %ip,
        "vSphere VM connect requested"
    );

    let create_req = CreateSessionRequest {
        session_type,
        hostname: Some(ip.to_string()),
        port: Some(port),
        username: Some(username),
        password,
        address_book_entry: Some(format!("vsphere/{}", vm.name)),
        entry_display_name: Some(vm.name.clone()),
        ssh: Some(SshParams::default()),
        rdp: Some(RdpParams::default()),
        vnc: Some(VncParams::default()),
        ..Default::default()
    };

    match manager
        .create_session(create_req, user_name, Some(client_ip.to_string()))
        .await
    {
        Ok(info) => {
            tracing::info!(session_id = %info.session_id, vm = %vm.name, "vSphere session created");
            Redirect::temporary(&format!("/client/{}", info.session_id)).into_response()
        }
        Err(e) => connect_error(StatusCode::BAD_GATEWAY, &e.to_string()),
    }
}
