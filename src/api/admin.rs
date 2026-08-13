//! Health, system status, docs, metrics, and audit endpoints.
//!
//! `GET /api/health` is public and answers with per-backend checks
//! (guacd, database, db pool, vault, disk). The remaining handlers require
//! operator or higher, with the status and audit views reserved for admins.
use super::{AppState, DriveConfigured, OidcEnabled, SiteTitle, ThemeData, VaultConfigured};
use crate::auth::{AuthIdentity, WsTicketStore};
use crate::db::Db;
use crate::error::AppError;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{extract::State, Extension, Json};
use serde_json::json;

/// `GET /api/health`: liveness and dependency checks.
///
/// Without authentication this is a shallow `{"status": "ok"}`. With
/// operator or higher it probes guacd, the rusqlite DB, the SQLx pool,
/// Vault (when configured), and disk usage, and reports an overall
/// `healthy` or `degraded` verdict.
pub async fn health(
    State(state): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    db_pool: Extension<crate::db_pool::DbPool>,
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
        // rusqlite's `execute()` rejects statements that return rows (a
        // hard error, not just a lint) — `query_row` is the correct call
        // for a SELECT. This is a bug fix: this path always reported
        // "down" for a perfectly healthy connection, it just had never
        // been reachable before now (optional_auth API-key auth and this
        // route's Db extension were both broken until this same change).
        match db.lock().unwrap().query_row("SELECT 1", [], |_| Ok(())) {
            Ok(()) => "up",
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

    // Check the SQLx multi-backend pool (Postgres/MySQL/SQLite via `db_url`)
    // — distinct from the rusqlite admin DB checked above. Actually issues a
    // query rather than just confirming the pool object exists, so a
    // backend-specific regression (e.g. a bad query for one SQL dialect)
    // shows up here instead of only at first real use.
    let db_pool_start = std::time::Instant::now();
    let db_pool_status = match db_pool.0.kind() {
        None => "unavailable",
        Some(kind) => match crate::db::ping_active_pool() {
            Ok(()) => "up",
            Err(e) => {
                tracing::warn!(error = %e, backend = %kind, "health: db_pool error");
                "down"
            }
        },
    };
    checks.insert(
        "db_pool".to_string(),
        json!({
            "status": db_pool_status,
            "backend": db_pool.0.kind().map(|k| k.to_string()),
            "latency_ms": db_pool_start.elapsed().as_millis(),
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
    let max_disk = state
        .config()
        .recording
        .as_ref()
        .map(|r| r.max_disk_percent)
        .unwrap_or(80);
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

    let status = if checks.values().all(|c| {
        matches!(
            c["status"].as_str(),
            Some("up") | Some("ok") | Some("unavailable")
        )
    }) {
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

/// `POST /api/ws-ticket`: mint a short-lived WebSocket ticket for
/// the session stream. Any authenticated identity may call it; returns
/// `AppError::Auth` when the identity is missing.
pub async fn create_ws_ticket(
    Extension(ticket_store): Extension<WsTicketStore>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let Extension(identity) = identity.ok_or_else(|| AppError::Auth("unauthorized".into()))?;
    let ticket = ticket_store.create(identity).await;
    Ok(Json(json!({"ticket": ticket})))
}

/// `GET /api/system/status`: version, session counts, recording
/// stats, Vault and feature flags, and HA instance info. Admin only;
/// `AppError::Forbidden` for lower roles.
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
        let db_clone = database.clone();
        tokio::task::spawn_blocking(move || crate::db::count_users(&db_clone))
            .await
            .unwrap_or(Ok(0))
            .unwrap_or(0)
    };

    let history_total = {
        let db_clone = database.clone();
        tokio::task::spawn_blocking(move || crate::db::count_session_history(&db_clone))
            .await
            .unwrap_or(Ok(0))
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
        "instance": {
            "instance_id": manager.instance_id(),
            "ha_enabled": manager.ha_enabled(),
        },
    })))
}

/// Compiled-in server capabilities, probed anonymously via
/// `GET /api/auth/status`. These reflect whether the binary actually
/// contains the feature; the v1.2.0 ticket dispatcher flips them as the
/// tickets land (S02 → session_events, S03 → drive_upload, S04 →
/// desktop_pairing, S07 → desktop_bridge).
/// S03 landed: the drive upload endpoint is compiled in.
pub const COMPILED_DRIVE_UPLOAD: bool = true;
/// S02 landed: the SSE session-event feed is compiled in.
pub const COMPILED_SESSION_EVENTS: bool = true;
/// S04 landed: the device-pairing flow is compiled in.
pub const COMPILED_DESKTOP_PAIRING: bool = true;
/// S07 landed: the Tauri IPC bridge + CSP schemes are compiled in.
pub const COMPILED_DESKTOP_BRIDGE: bool = true;

/// `system_settings` keys backing the admin-gated desktop capabilities
/// (S09 "Desktop" settings section, all default ON).
const SETTING_DESKTOP_KIOSK: &str = "desktop_kiosk";
const SETTING_DESKTOP_TRANSFERS: &str = "desktop_transfers";
const SETTING_DESKTOP_PAIRING: &str = "desktop_pairing";

/// `GET /api/auth/status`: login-page configuration for anonymous
/// callers: OIDC availability, site title, drive flag, the resolved
/// theme data, the server version, the desktop-shell capability
/// probe, and the cached server update-check result (S16).
pub async fn auth_status(
    Extension(oidc_enabled): Extension<OidcEnabled>,
    Extension(site_title): Extension<SiteTitle>,
    Extension(theme): Extension<ThemeData>,
    Extension(drive_configured): Extension<DriveConfigured>,
    database: Option<Extension<Db>>,
    update_state: Option<Extension<crate::updates::UpdateState>>,
) -> Result<Json<serde_json::Value>, AppError> {
    let settings = load_capability_settings(database).await;
    let kiosk_allowed =
        crate::settings_merge::toggle_enabled(&settings, SETTING_DESKTOP_KIOSK, true);
    let desktop_transfers =
        crate::settings_merge::toggle_enabled(&settings, SETTING_DESKTOP_TRANSFERS, true);
    let desktop_pairing = COMPILED_DESKTOP_PAIRING
        && crate::settings_merge::toggle_enabled(&settings, SETTING_DESKTOP_PAIRING, true);

    let mut resp = json!({
        "oidc_enabled": oidc_enabled.0,
        "site_title": site_title.0,
        "drive_configured": drive_configured.0,
        "version": env!("CARGO_PKG_VERSION"),
        "capabilities": {
            "drive_api": true,
            "drive_upload": COMPILED_DRIVE_UPLOAD,
            "session_events": COMPILED_SESSION_EVENTS,
            "desktop_pairing": desktop_pairing,
            "desktop_bridge": COMPILED_DESKTOP_BRIDGE,
            "kiosk_allowed": kiosk_allowed,
            "desktop_transfers": desktop_transfers,
        },
    });
    resp["theme"] = json!({
        "admin_preset": theme.admin_preset,
        "admin_colors": theme.admin_colors,
        "presets": theme.presets,
    });
    if let Some(ref url) = theme.logo_url {
        resp["theme"]["logo_url"] = json!(url);
    }
    // S16: cached server update check. Null/false when the checker is
    // disabled, never ran, or every attempt failed so far.
    let (latest_version, update_available) = match update_state {
        Some(state) => {
            let info = state.info.read().unwrap();
            let latest = info.latest_version.clone();
            let available = latest
                .as_deref()
                .map(|v| crate::updates::version_newer(v, env!("CARGO_PKG_VERSION")))
                .unwrap_or(false);
            (latest, available)
        }
        None => (None, false),
    };
    resp["latest_version"] = json!(latest_version);
    resp["update_available"] = json!(update_available);
    Ok(Json(resp))
}

/// Read the `system_settings` rows for the anonymous capability probe.
/// Resolves through the SQLx pool when one is active, otherwise through
/// the legacy `Db` handle when one is layered (tests), and falls back to
/// an empty list so every admin-gated capability defaults to ON when
/// neither store is reachable.
async fn load_capability_settings(database: Option<Extension<Db>>) -> Vec<(String, String)> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::settings_load_all_pool(pool)
        })
        .unwrap_or_default();
    }
    match database {
        Some(Extension(db)) => {
            let db_clone = db.clone();
            tokio::task::spawn_blocking(move || crate::settings_merge::load_db_settings(&db_clone))
                .await
                .unwrap_or(Ok(Vec::new()))
                .unwrap_or_else(|e| {
                    tracing::warn!("failed to load capability settings: {e}");
                    Vec::new()
                })
        }
        None => Vec::new(),
    }
}

include!(concat!(env!("OUT_DIR"), "/docs-rendered.rs"));

/// `GET /api/docs`: the rendered documentation sections (slug,
/// title, HTML) baked in at build time.
pub async fn get_docs() -> Result<Json<serde_json::Value>, AppError> {
    let sections: Vec<serde_json::Value> = DOCS
        .iter()
        .map(|(slug, title, html)| json!({ "slug": slug, "title": title, "html": html }))
        .collect();
    Ok(Json(json!(sections)))
}

/// `GET /api/metrics`: Prometheus text exposition format. Public;
/// no authentication required.
pub async fn metrics() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        crate::metrics::render_prometheus(),
    )
}

/// HTMX fragment: table rows for audit events.
pub async fn audit_events(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50);
    let offset = params
        .get("offset")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    let filters = crate::audit::AuditFilters {
        user_id: params.get("user").cloned().filter(|s| !s.is_empty()),
        event_type: params.get("event_type").cloned().filter(|s| !s.is_empty()),
        outcome: params.get("outcome").cloned().filter(|s| !s.is_empty()),
        from: params.get("from").cloned().filter(|s| !s.is_empty()),
        to: params.get("to").cloned().filter(|s| !s.is_empty()),
    };

    let total = crate::audit::count_events(&database, &filters).unwrap_or(0);
    let events = crate::audit::list_events(&database, limit, offset, &filters).unwrap_or_default();

    let mut html = String::new();
    for event in &events {
        let short_hash = if event.event_hash.len() >= 8 {
            &event.event_hash[..8]
        } else {
            &event.event_hash
        };
        let short_hash_display = format!("{short_hash}…");
        let details = if event.details.is_null() {
            "-".to_string()
        } else if let Some(obj) = event.details.as_object() {
            obj.iter()
                .map(|(k, v)| format!("{}: {}", k, v))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            event.details.to_string()
        };
        let outcome_class = match event.outcome.as_str() {
            "failure" | "error" => "bg-red-900/50 text-red-300 border-red-800",
            _ => "bg-emerald-900/50 text-emerald-300 border-emerald-800",
        };
        let escaped_details = html_escape(&details);
        let escaped_hash = html_escape(&event.event_hash);
        html.push_str(&format!(
            r#"<tr class="hover:bg-[var(--bg-hover)]/50">
<td class="px-4 py-3 text-sm text-[var(--text-muted)] whitespace-nowrap">{}</td>
<td class="px-4 py-3 text-sm text-[var(--text-primary)]">{}</td>
<td class="px-4 py-3 text-sm text-[var(--text-muted)]">{}</td>
<td class="px-4 py-3 text-sm text-[var(--text-muted)]">{}</td>
<td class="px-4 py-3"><span class="inline-block px-2 py-0.5 text-xs rounded border {}">{}</span></td>
<td class="px-4 py-3 text-sm text-[var(--text-muted)] max-w-xs truncate" title="{}">{}</td>
<td class="px-4 py-3 text-sm text-[var(--text-muted)] font-mono text-right" title="{}">{}</td>
</tr>"#,
            event.timestamp.to_rfc3339(),
            event.event_type,
            event.user_id.as_deref().unwrap_or("-"),
            event.source_ip.as_deref().unwrap_or("-"),
            outcome_class,
            event.outcome,
            escaped_details,
            escaped_details,
            escaped_hash,
            short_hash_display,
        ));
    }

    // Append pagination info as hx-headers so the client can update pagination controls
    let total_pages = total.div_ceil(limit);
    let current_page = offset / limit + 1;
    html.push_str(&format!(
        r#"<tr id="audit-pagination-data" data-total="{}" data-pages="{}" data-current="{}" data-limit="{}" style="display:none"></tr>"#,
        total, total_pages, current_page, limit,
    ));

    Ok((
        [
            // After-Swap (not plain HX-Trigger, which fires as soon as the
            // response arrives — before the new rows, including the
            // pagination-data row below, actually land in the DOM).
            ("HX-Trigger-After-Swap", "auditEventsLoaded"),
            ("Content-Type", "text/html; charset=utf-8"),
        ],
        html,
    ))
}

/// JSON: hash chain verification result.
pub async fn audit_verify(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let verification =
        tokio::task::spawn_blocking(move || crate::audit::verify_chain(&database, None, None))
            .await
            .map_err(|e| AppError::Internal(format!("task join error: {}", e)))?
            .map_err(|e| AppError::Internal(format!("verify error: {}", e)))?;

    let status_str = match verification.status {
        crate::audit::ChainStatus::Verified => "verified",
        crate::audit::ChainStatus::Broken => "broken",
    };

    Ok(Json(json!({
        "status": status_str,
        "events_scanned": verification.events_scanned,
        "errors": verification.errors.iter().map(|e| json!({
            "event_id": e.event_id,
            "message": e.message,
        })).collect::<Vec<_>>(),
    })))
}

/// CSV download: audit event export with filters.
pub async fn audit_export(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<impl IntoResponse, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let filters = crate::audit::AuditFilters {
        user_id: params.get("user").cloned().filter(|s| !s.is_empty()),
        event_type: params.get("event_type").cloned().filter(|s| !s.is_empty()),
        outcome: params.get("outcome").cloned().filter(|s| !s.is_empty()),
        from: params.get("from").cloned().filter(|s| !s.is_empty()),
        to: params.get("to").cloned().filter(|s| !s.is_empty()),
    };

    let format = params.get("format").map(|s| s.as_str()).unwrap_or("csv");

    if format == "json" {
        let events = tokio::task::spawn_blocking(move || {
            crate::audit::list_events(&database, 100_000, 0, &filters)
        })
        .await
        .map_err(|e| AppError::Internal(format!("task join error: {}", e)))?
        .map_err(|e| AppError::Internal(format!("export error: {}", e)))?;

        let json_data = serde_json::to_string_pretty(&events)
            .map_err(|e| AppError::Internal(format!("JSON serialization error: {}", e)))?;

        return Ok((
            [
                ("Content-Type", "application/json; charset=utf-8"),
                (
                    "Content-Disposition",
                    "attachment; filename=\"audit-export.json\"",
                ),
            ],
            json_data,
        ));
    }

    let csv_data =
        tokio::task::spawn_blocking(move || crate::audit::export_events_csv(&database, &filters))
            .await
            .map_err(|e| AppError::Internal(format!("task join error: {}", e)))?
            .map_err(|e| AppError::Internal(format!("export error: {}", e)))?;

    Ok((
        [
            ("Content-Type", "text/csv; charset=utf-8"),
            (
                "Content-Disposition",
                "attachment; filename=\"audit-export.csv\"",
            ),
        ],
        csv_data,
    ))
}

/// Escape HTML special characters to prevent XSS.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
