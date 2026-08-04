use crate::error::AppError;
use crate::vsphere::{self, VsphereClient, VsphereConfig};
use axum::extract::State;
use axum::Json;
use serde_json::json;
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
pub async fn list_vms(
    State(client): State<VsphereState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(client) = client else {
        return Err(AppError::Vsphere("vSphere not configured or unavailable".into()));
    };

    let mut client = client.lock().await;
    let vms = vsphere::list_vms(&mut client).await?;
    Ok(Json(json!(vms)))
}

/// POST /api/vsphere/vms/{vm_id}/power
///
/// Perform a power action on a VM. Body: `{ "action": "on|off|suspend|reset" }`
pub async fn power_action(
    State(client): State<VsphereState>,
    axum::extract::Path(vm_id): axum::extract::Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Some(client) = client else {
        return Err(AppError::Vsphere("vSphere not configured or unavailable".into()));
    };

    let action = body
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Validation("missing 'action' field".into()))?;

    let mut client = client.lock().await;
    vsphere::power_action(&mut client, &vm_id, action).await?;
    Ok(Json(json!({ "ok": true })))
}
