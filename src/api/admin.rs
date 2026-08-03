use super::{AppState, DriveConfigured, OidcEnabled, SiteTitle, ThemeData, VaultConfigured};
use crate::auth::{AuthIdentity, WsTicketStore};
use crate::db::Db;
use crate::error::AppError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::State, Extension, Json};
use serde_json::json;

pub async fn health(
    State(state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Shallow check (no auth)
    let Some(Extension(identity)) = identity else {
        return Ok(Json(json!({"status": "ok"})));
    };

    // Deep check (authenticated with operator+ role)
    if !identity.has_role("operator") {
        return Ok(Json(json!({"status": "ok"})));
    }

    let mut components = std::collections::HashMap::new();

    // Check guacd
    components.insert(
        "guacd".to_string(),
        match tokio::net::TcpStream::connect(&state.config().guacd_addr).await {
            Ok(_) => "ok".to_string(),
            Err(e) => {
                tracing::warn!(error = %e, "health: guacd unreachable");
                "unreachable".to_string()
            }
        },
    );

    // Check database
    if let Some(db) = state.db() {
        components.insert(
            "database".to_string(),
            match db.lock().unwrap().execute("SELECT 1", []) {
                Ok(_) => "ok".to_string(),
                Err(e) => {
                    tracing::warn!(error = %e, "health: database error");
                    "error".to_string()
                }
            },
        );
    }

    let status = if components.values().all(|v| v == "ok") {
        "ok"
    } else {
        "degraded"
    };

    Ok(Json(json!({
        "status": status,
        "components": components,
    })))
}

pub async fn create_ws_ticket(
    Extension(ticket_store): Extension<WsTicketStore>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Extension(identity) = identity.ok_or_else(|| AppError::Auth("unauthorized".into()))?;
    let ticket = ticket_store.create(identity).await;
    Ok(Json(json!({"ticket": ticket})))
}

pub async fn system_status(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    Extension(vault_configured): Extension<VaultConfigured>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let version = env!("CARGO_PKG_VERSION");

    let rec_path = manager.recording_path().to_path_buf();
    let (rec_disk_pct, rec_count, rec_size_mb) = tokio::task::spawn_blocking(move || {
        let pct = crate::recording::disk_usage_percent(&rec_path).unwrap_or(0.0);
        let mut count = 0u32;
        let mut total_bytes = 0u64;
        if let Ok(entries) = std::fs::read_dir(&rec_path) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|e| e.to_str()) == Some("guac") {
                    count += 1;
                    total_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        (pct, count, total_bytes as f64 / 1024.0 / 1024.0)
    })
    .await
    .unwrap_or((0.0, 0, 0.0));

    let sessions = manager.list_sessions().await;
    let active_sessions = sessions
        .iter()
        .filter(|s| s.status == crate::session::SessionStatus::Active)
        .count();
    let pending_sessions = sessions
        .iter()
        .filter(|s| s.status == crate::session::SessionStatus::Pending)
        .count();

    let vault_ok = if vault_configured.0 {
        manager.config().vault.is_some()
    } else {
        false
    };

    let user_count = {
        let conn = database.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
    };

    let history_total = {
        let conn = database.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM session_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_or(0)
    };

    let oidc_configured = manager.config().oidc.is_some();
    let drive_configured = manager.config().drive.is_some();
    let tls_configured = manager.config().tls.is_some();

    Ok(Json(json!({
        "version": version,
        "sessions": {
            "active": active_sessions,
            "pending": pending_sessions,
            "total_current": sessions.len(),
        },
        "recordings": {
            "count": rec_count,
            "size_mb": (rec_size_mb * 10.0).round() / 10.0,
            "disk_usage_pct": (rec_disk_pct * 10.0).round() / 10.0,
        },
        "vault": {
            "configured": vault_configured.0,
            "connected": vault_ok,
        },
        "users": {
            "count": user_count,
        },
        "history": {
            "total_sessions": history_total,
        },
        "features": {
            "oidc": oidc_configured,
            "drive": drive_configured,
            "tls": tls_configured,
        },
    })))
}

pub async fn auth_status(
    Extension(oidc_enabled): Extension<OidcEnabled>,
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    Extension(drive_configured): Extension<DriveConfigured>,
) -> Result<Json<serde_json::Value>, AppError> {
    let mut resp = json!({
        "oidc_enabled": oidc_enabled.0,
        "site_title": site_title.0,
        "drive_configured": drive_configured.0,
    });
    resp["theme"] = json!({
        "admin_preset": theme.admin_preset,
        "admin_colors": theme.admin_colors,
        "presets": theme.presets,
    });
    if let Some(ref url) = theme.logo_url {
        resp["theme"]["logo_url"] = json!(url);
    }
    Ok(Json(resp))
}

include!(concat!(env!("OUT_DIR"), "/docs-rendered.rs"));

pub async fn get_docs() -> Result<Json<serde_json::Value>, AppError> {
    let sections: Vec<serde_json::Value> = DOCS
        .iter()
        .map(|(slug, title, html)| json!({ "slug": slug, "title": title, "html": html }))
        .collect();
    Ok(Json(json!(sections)))
}

pub async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        crate::metrics::render_prometheus(),
    )
}
