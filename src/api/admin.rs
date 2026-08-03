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

    let mut checks = std::collections::HashMap::new();

    // Check guacd
    let guacd_start = std::time::Instant::now();
    let guacd_status = match tokio::net::TcpStream::connect(&state.config().guacd_addr).await {
        Ok(stream) => {
            drop(stream);
            "up"
        }
        Err(e) => {
            tracing::warn!(error = %e, "health: guacd unreachable");
            "down"
        }
    };
    checks.insert(
        "guacd".to_string(),
        json!({
            "status": guacd_status,
            "latency_ms": guacd_start.elapsed().as_millis(),
        }),
    );

    // Check database
    let db_start = std::time::Instant::now();
    let db_status = if let Some(db) = state.db() {
        match db.lock().unwrap().execute("SELECT 1", []) {
            Ok(_) => "up",
            Err(e) => {
                tracing::warn!(error = %e, "health: database error");
                "down"
            }
        }
    } else {
        "unavailable"
    };
    checks.insert(
        "database".to_string(),
        json!({
            "status": db_status,
            "latency_ms": db_start.elapsed().as_millis(),
        }),
    );

    // Check vault (if configured)
    if let Some(vault_config) = &state.config().vault {
        let vault_start = std::time::Instant::now();
        let vault_url = format!("{}/v1/sys/health", vault_config.addr);
        let skip_verify = vault_config.tls_skip_verify;
        let vault_status = match reqwest::Client::builder()
            .danger_accept_invalid_certs(skip_verify)
            .build()
        {
            Ok(client) => match client.get(&vault_url).send().await {
                Ok(resp) => {
                    let status_code = resp.status().as_u16();
                    if status_code == 200 || status_code == 429 {
                        "up"
                    } else {
                        tracing::warn!(status = status_code, "health: vault unhealthy");
                        "down"
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "health: vault unreachable");
                    "down"
                }
            },
            Err(e) => {
                tracing::warn!(error = %e, "health: vault client build failed");
                "down"
            }
        };
        checks.insert(
            "vault".to_string(),
            json!({
                "status": vault_status,
                "latency_ms": vault_start.elapsed().as_millis(),
            }),
        );
    }

    // Check disk usage
    let rec_path = state.recording_path().to_path_buf();
    let max_disk = state.config().recording.as_ref().map(|r| r.max_disk_percent).unwrap_or(80);
    let disk_usage = tokio::task::spawn_blocking(move || {
        crate::recording::disk_usage_percent(&rec_path).unwrap_or(0.0)
    })
    .await
    .unwrap_or(0.0);
    let disk_status = if max_disk > 0 && disk_usage >= max_disk as f64 {
        "warning"
    } else {
        "ok"
    };
    checks.insert(
        "disk".to_string(),
        json!({
            "status": disk_status,
            "usage_percent": (disk_usage * 10.0).round() / 10.0,
        }),
    );

    // Count active sessions
    let sessions = state.list_sessions().await;
    let active_sessions = sessions
        .iter()
        .filter(|s| s.status == crate::session::SessionStatus::Active)
        .count();

    let status = if checks.values().all(|c| c["status"] == "up" || c["status"] == "ok") {
        "healthy"
    } else {
        "degraded"
    };

    Ok(Json(json!({
        "status": status,
        "checks": checks,
        "uptime_seconds": crate::metrics::uptime_seconds(),
        "active_sessions": active_sessions,
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
