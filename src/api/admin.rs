//! Health, system status, docs, metrics, and audit endpoints.
//!
//! `GET /api/health` is public and answers with per-backend checks
//! (guacd, database, db pool, vault, disk). The remaining handlers require
//! operator or higher, with the status and audit views reserved for admins.
use super::{AppState, DriveConfigured, OidcEnabled, SiteTitle, ThemeData, VaultConfigured};
use crate::auth::{AuthIdentity, WsTicketStore};
use crate::db::Db;
use crate::error::AppError;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Serialize;
use serde_json::json;
use x509_parser::prelude::{FromDer, X509Certificate};

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

/// `system_settings` key backing the compliance-mode gate (S3, persea#228):
/// closes the direct API surface (admin API keys + self-service user
/// tokens) while interactive sessions and scoped desktop tokens keep
/// authenticating. Default OFF, read by the auth middleware per request.
const SETTING_COMPLIANCE_MODE: &str = "compliance_mode";

/// `GET /api/auth/status`: login-page configuration for anonymous
/// callers: OIDC availability, site title, drive flag, the resolved
/// theme data, the server version, the desktop-shell capability
/// probe, the compliance-mode flag (S3, persea#228), and the cached
/// server update-check result (S16). Answers without authentication so
/// the desktop app can detect the mode and switch to the login-prompt
/// flow.
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
    let compliance_mode =
        crate::settings_merge::toggle_enabled(&settings, SETTING_COMPLIANCE_MODE, false);

    let mut resp = json!({
        "oidc_enabled": oidc_enabled.0,
        "site_title": site_title.0,
        "drive_configured": drive_configured.0,
        "compliance_mode": compliance_mode,
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
/// title, HTML) baked in at build time. Admin only: the docs describe
/// internal endpoints and configuration; anonymous callers get 403.
pub async fn get_docs(
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let sections: Vec<serde_json::Value> = DOCS
        .iter()
        .map(|(slug, title, html, _)| json!({ "slug": slug, "title": title, "html": html }))
        .collect();
    Ok(Json(json!(sections)))
}

/// `GET /api/metrics`: Prometheus text exposition format. Admin only —
/// the endpoint exposes session counts, uptime, and request metrics that
/// are useful to attackers; scrapers authenticate with an admin API key.
pub async fn metrics(
    identity: Option<Extension<AuthIdentity>>,
) -> Result<impl IntoResponse, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    Ok((
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4")],
        crate::metrics::render_prometheus(),
    ))
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
        // Every interpolated value is escaped: `user_id` is attacker-
        // controlled (session rows store the caller's display name) and
        // this fragment is swapped into the admin page via innerHTML.
        let escaped_timestamp = html_escape(&event.timestamp.to_rfc3339());
        let escaped_type = html_escape(&event.event_type);
        let escaped_user = html_escape(event.user_id.as_deref().unwrap_or("-"));
        let escaped_ip = html_escape(event.source_ip.as_deref().unwrap_or("-"));
        let escaped_outcome = html_escape(&event.outcome);
        let escaped_details = html_escape(&details);
        let escaped_hash = html_escape(&event.event_hash);
        let escaped_short_hash = html_escape(&short_hash_display);
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
            escaped_timestamp,
            escaped_type,
            escaped_user,
            escaped_ip,
            outcome_class,
            escaped_outcome,
            escaped_details,
            escaped_details,
            escaped_hash,
            escaped_short_hash,
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

// ── TLS certificate metadata (Security page) ───────────────────────────────

/// Parsed metadata for the server's TLS certificate, exposed to the
/// Security page's TLS Certificates tab.
#[derive(Serialize)]
struct CertMetadata {
    /// Certificate subject, e.g. "CN=persea.example.com".
    subject: String,
    /// Certificate issuer, e.g. "CN=persea.example.com".
    issuer: String,
    /// Validity start as an RFC 3339 timestamp.
    not_before: String,
    /// Expiry as an RFC 3339 timestamp.
    not_after: String,
    /// Whole days until expiry (negative once expired).
    expires_in_days: i64,
    /// "valid", "expiring_soon" (within 30 days), or "expired".
    status: &'static str,
}

/// Expiry status: "expired" past the not-after instant, "expiring_soon"
/// within the 30-day warning window, "valid" otherwise.
fn cert_status(not_after_ts: i64, now_ts: i64) -> &'static str {
    let days = (not_after_ts - now_ts).div_euclid(86_400);
    if days < 0 {
        "expired"
    } else if days <= 30 {
        "expiring_soon"
    } else {
        "valid"
    }
}

/// Format a Unix timestamp as an RFC 3339 string (falls back to the raw
/// seconds when the timestamp is out of chrono's representable range).
fn fmt_timestamp(ts: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}

/// Read a PEM certificate file and extract subject, issuer, and validity
/// metadata. `rustls_pemfile` pulls the first CERTIFICATE block; the DER it
/// yields is parsed with the pure-Rust x509-parser crate.
fn parse_cert_metadata(cert_path: &std::path::Path) -> Result<CertMetadata, String> {
    let pem = std::fs::read(cert_path).map_err(|e| format!("failed to read certificate: {e}"))?;
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("failed to parse certificate PEM: {e}"))?;
    let der = certs
        .first()
        .ok_or_else(|| "no certificate found in PEM file".to_string())?;
    let (_, cert) = X509Certificate::from_der(der.as_ref())
        .map_err(|e| format!("failed to parse certificate: {e}"))?;
    let not_before_ts = cert.validity().not_before.timestamp();
    let not_after_ts = cert.validity().not_after.timestamp();
    let now_ts = chrono::Utc::now().timestamp();
    Ok(CertMetadata {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        not_before: fmt_timestamp(not_before_ts),
        not_after: fmt_timestamp(not_after_ts),
        expires_in_days: (not_after_ts - now_ts).div_euclid(86_400),
        status: cert_status(not_after_ts, now_ts),
    })
}

/// `GET /api/admin/tls-cert-info?cert_path=...&key_path=...` — TLS
/// certificate metadata for the Security page's TLS Certificates tab.
///
/// Admin only. The caller passes the configured paths (fetched from
/// `GET /api/system/settings`); the endpoint reports whether each file
/// exists and, when the cert file is readable, its parsed subject, issuer,
/// validity window, and a 30-day expiry warning state. Unparseable or
/// missing files are reported in-band (`cert` null + `cert_error`), never
/// as a 500, so the tab can render a clear status.
pub async fn tls_cert_info(
    Extension(database): Extension<Db>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    // Resolve the paths server-side from the stored settings: the client
    // never supplies file paths (no arbitrary-file oracle).
    let db = database.clone();
    let settings =
        tokio::task::spawn_blocking(move || crate::settings_merge::load_db_settings(&db))
            .await
            .map_err(|e| AppError::Internal(e.to_string()))?
            .unwrap_or_default();
    let get = |key: &str| {
        settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let cert_path = get("tls_cert_path");
    let key_path = get("tls_key_path");
    let cert_exists = !cert_path.is_empty() && std::path::Path::new(&cert_path).is_file();
    let key_exists = !key_path.is_empty() && std::path::Path::new(&key_path).is_file();
    let (cert, cert_error) = if cert_exists {
        match parse_cert_metadata(std::path::Path::new(&cert_path)) {
            Ok(meta) => (json!(meta), None),
            Err(e) => (serde_json::Value::Null, Some(e)),
        }
    } else {
        (serde_json::Value::Null, None)
    };
    Ok(Json(json!({
        "tls_cert_path": cert_path,
        "tls_key_path": key_path,
        "cert_exists": cert_exists,
        "key_exists": key_exists,
        "cert": cert,
        "cert_error": cert_error,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::EventBuilder;
    use crate::db::{self, Db};
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn test_db() -> Db {
        db::init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn identity(email: &str, name: &str, role: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: email.into(),
            name: name.into(),
            role: role.into(),
            groups: vec![],
        }
    }

    fn router(db: Db, id: Option<AuthIdentity>) -> Router {
        let r = Router::new()
            .route("/api/audit/events", get(audit_events))
            .layer(Extension(db));
        match id {
            Some(id) => r.layer(Extension(id)),
            None => r,
        }
    }

    fn req_get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn log(
        db: &Db,
        event_type: &str,
        outcome: &str,
        user_id: Option<&str>,
        ip: Option<&str>,
        details: serde_json::Value,
    ) {
        let mut b = EventBuilder::new(event_type, outcome);
        if let Some(u) = user_id {
            b = b.user_id(u);
        }
        if let Some(i) = ip {
            b = b.source_ip(i);
        }
        let mut event = b.details(details).build();
        crate::audit::log_event(db, &mut event).unwrap();
    }

    #[tokio::test]
    async fn audit_fragment_escapes_user_controlled_fields() {
        let db = test_db();
        log(
            &db,
            "session_start",
            "success",
            Some("<img src=x onerror=alert(1)>"),
            Some("<script>alert(1)</script>"),
            serde_json::json!({"host": "<b>bold</b>"}),
        );
        let router = router(db, Some(identity("admin@example.com", "Admin", "admin")));
        let resp = router.oneshot(req_get("/api/audit/events")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(
            html.contains("&lt;img src=x onerror=alert(1)&gt;"),
            "user_id must be escaped: {html}"
        );
        assert!(!html.contains("<img src=x"), "raw user_id leaked: {html}");
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
            "source_ip must be escaped: {html}"
        );
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw ip leaked: {html}"
        );
        assert!(
            html.contains("&lt;b&gt;bold&lt;/b&gt;"),
            "details must be escaped: {html}"
        );
        assert!(!html.contains("<b>bold</b>"), "raw details leaked: {html}");
    }

    #[tokio::test]
    async fn audit_fragment_escapes_event_type_and_outcome() {
        let db = test_db();
        log(
            &db,
            "login\" onmouseover=\"x",
            "failure'><script>alert(1)</script>",
            None,
            None,
            serde_json::Value::Null,
        );
        let router = router(db, Some(identity("admin@example.com", "Admin", "admin")));
        let resp = router.oneshot(req_get("/api/audit/events")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(
            html.contains("login&quot; onmouseover=&quot;x"),
            "event_type must be escaped: {html}"
        );
        assert!(
            html.contains("failure'&gt;&lt;script&gt;alert(1)&lt;/script&gt;"),
            "outcome must be escaped: {html}"
        );
        assert!(
            !html.contains("><script>"),
            "raw outcome tag leaked: {html}"
        );
    }

    #[tokio::test]
    async fn audit_fragment_requires_admin() {
        let db = test_db();
        let router = router(db, Some(identity("viewer@example.com", "Viewer", "viewer")));
        let resp = router.oneshot(req_get("/api/audit/events")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // ── Operational endpoint gating (metrics, docs) ─────────────────────

    fn ops_router(db: Db, id: Option<AuthIdentity>) -> Router {
        let r = Router::new()
            .route("/metrics", get(metrics))
            .route("/api/docs", get(get_docs));
        match id {
            Some(id) => r.layer(Extension(id)),
            None => r,
        }
    }

    #[tokio::test]
    async fn metrics_requires_admin() {
        let db = test_db();
        // Anonymous → 403.
        let resp = ops_router(db.clone(), None)
            .oneshot(req_get("/metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Viewer → 403.
        let resp = ops_router(db.clone(), Some(identity("v@example.com", "V", "viewer")))
            .oneshot(req_get("/metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // Admin → 200 with the Prometheus content type.
        let resp = ops_router(db, Some(identity("a@example.com", "A", "admin")))
            .oneshot(req_get("/metrics"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()["content-type"], "text/plain; version=0.0.4");
    }

    #[tokio::test]
    async fn docs_requires_admin() {
        let db = test_db();
        let resp = ops_router(db.clone(), None)
            .oneshot(req_get("/api/docs"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = ops_router(db.clone(), Some(identity("v@example.com", "V", "viewer")))
            .oneshot(req_get("/api/docs"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let resp = ops_router(db, Some(identity("a@example.com", "A", "admin")))
            .oneshot(req_get("/api/docs"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── TLS certificate info endpoint (Security page TLS tab) ─────────────

    fn tls_router(db: Db, id: Option<AuthIdentity>) -> Router {
        let r = Router::new()
            .route("/api/admin/tls-cert-info", get(tls_cert_info))
            .layer(Extension(db));
        match id {
            Some(id) => r.layer(Extension(id)),
            None => r,
        }
    }

    /// Seed the tls_cert_path/tls_key_path settings the endpoint resolves.
    fn seed_tls_settings(db: &Db, cert_path: &str, key_path: &str) {
        let conn = db.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS system_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)",
            [],
        )
        .unwrap();
        for (key, value) in [("tls_cert_path", cert_path), ("tls_key_path", key_path)] {
            conn.execute(
                "INSERT INTO system_settings (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                rusqlite::params![key, value],
            )
            .unwrap();
        }
    }

    /// Generate a self-signed cert fixture (rcgen) with a far-future expiry
    /// and write it to `dir`; returns the cert path.
    fn write_fixture_cert(dir: &std::path::Path) -> std::path::PathBuf {
        let mut params = rcgen::CertificateParams::new(vec!["persea.example.com".to_string()])
            .expect("fixture cert params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "persea.example.com");
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2099, 1, 1);
        let key = rcgen::KeyPair::generate().expect("fixture key");
        let cert = params.self_signed(&key).expect("fixture cert");
        let path = dir.join("cert.pem");
        std::fs::write(&path, cert.pem()).expect("fixture cert write");
        path
    }

    #[tokio::test]
    async fn tls_cert_info_parses_fixture_cert() {
        let dir = std::env::temp_dir().join(format!("persea-tls-fixture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = write_fixture_cert(&dir);
        let db = test_db();
        seed_tls_settings(&db, &cert_path.to_string_lossy(), "/nonexistent/key.pem");
        let router = tls_router(db, Some(identity("admin@example.com", "Admin", "admin")));
        let resp = router
            .oneshot(req_get("/api/admin/tls-cert-info"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body["cert_exists"], json!(true));
        assert_eq!(body["key_exists"], json!(false));
        assert_eq!(body["cert"]["status"], json!("valid"));
        assert!(
            body["cert"]["expires_in_days"].as_i64().unwrap() > 1000,
            "2099 fixture must be far in the future"
        );
        let subject = body["cert"]["subject"].as_str().unwrap();
        let issuer = body["cert"]["issuer"].as_str().unwrap();
        assert!(
            subject.contains("persea.example.com"),
            "subject must carry the fixture CN: {subject}"
        );
        assert!(
            issuer.contains("persea.example.com"),
            "issuer must carry the fixture CN: {issuer}"
        );
        assert_eq!(subject, issuer, "self-signed cert subject == issuer");
        assert!(
            body["cert"]["not_after"]
                .as_str()
                .unwrap()
                .starts_with("2099"),
            "not_after must reflect the fixture expiry: {}",
            body["cert"]["not_after"]
        );
        assert!(
            body["cert"]["not_before"]
                .as_str()
                .unwrap()
                .starts_with("2026"),
            "not_before must reflect the fixture start: {}",
            body["cert"]["not_before"]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tls_cert_info_missing_files_report_false_existence() {
        let db = test_db();
        seed_tls_settings(&db, "/nonexistent/cert.pem", "/nonexistent/key.pem");
        let router = tls_router(db, Some(identity("admin@example.com", "Admin", "admin")));
        let resp = router
            .oneshot(req_get("/api/admin/tls-cert-info"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body["cert_exists"], json!(false));
        assert_eq!(body["key_exists"], json!(false));
        assert!(body["cert"].is_null());
        assert!(body["cert_error"].is_null());
    }

    #[tokio::test]
    async fn tls_cert_info_unparseable_pem_reports_error_in_band() {
        let dir = std::env::temp_dir().join(format!("persea-cert-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bad = dir.join("bad.pem");
        std::fs::write(&bad, "not a pem").unwrap();
        let db = test_db();
        seed_tls_settings(&db, &bad.to_string_lossy(), "");
        let router = tls_router(db, Some(identity("admin@example.com", "Admin", "admin")));
        let resp = router
            .oneshot(req_get("/api/admin/tls-cert-info"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_str(&body_string(resp).await).unwrap();
        assert_eq!(body["cert_exists"], json!(true));
        assert!(body["cert"].is_null());
        assert!(
            body["cert_error"].as_str().is_some(),
            "a parse failure must carry an error message"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn tls_cert_info_requires_admin() {
        let cases: [Option<AuthIdentity>; 2] = [
            None,
            Some(identity("viewer@example.com", "Viewer", "viewer")),
        ];
        for id in cases {
            let router = tls_router(test_db(), id);
            let resp = router
                .oneshot(req_get("/api/admin/tls-cert-info"))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
    }

    #[test]
    fn cert_status_thresholds() {
        let now = 1_800_000_000i64;
        let day = 86_400i64;
        assert_eq!(cert_status(now + 31 * day, now), "valid");
        assert_eq!(cert_status(now + 30 * day, now), "expiring_soon");
        assert_eq!(cert_status(now, now), "expiring_soon");
        assert_eq!(cert_status(now - 1, now), "expired");
        assert_eq!(cert_status(now - 365 * day, now), "expired");
    }

    // ── Compliance probe (GET /api/auth/status, persea#228) ──────────────

    fn status_router(db: Option<Db>) -> Router {
        let r = Router::new()
            .route("/api/auth/status", get(auth_status))
            .layer(Extension(crate::api::OidcEnabled(false)))
            .layer(Extension(crate::api::SiteTitle("Persea".into())))
            .layer(Extension(crate::api::DriveConfigured(false)))
            .layer(Extension(crate::api::ThemeData {
                admin_preset: "dark".into(),
                admin_colors: crate::config::builtin_presets()
                    .first()
                    .map(|(_, c)| c.clone())
                    .expect("builtin presets exist"),
                logo_url: None,
                presets: std::collections::HashMap::new(),
            }));
        match db {
            Some(db) => r.layer(Extension(db)),
            None => r,
        }
    }

    /// Store a compliance setting row exactly as the settings API would.
    fn set_system_setting(db: &Db, key: &str, value: &str) {
        let conn = db.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS system_settings (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL DEFAULT '',
                updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO system_settings (key, value, updated_at)
             VALUES (?1, ?2, CURRENT_TIMESTAMP)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
            rusqlite::params![key, value],
        )
        .unwrap();
    }

    async fn get_status_json(router: &Router) -> serde_json::Value {
        let resp = router
            .clone()
            .oneshot(req_get("/api/auth/status"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        serde_json::from_str(&body_string(resp).await).unwrap()
    }

    #[tokio::test]
    async fn auth_status_advertises_compliance_mode() {
        // Unset toggle → off (existing deployments unaffected).
        let body = get_status_json(&status_router(Some(test_db()))).await;
        assert_eq!(body["compliance_mode"], json!(false));

        // Stored "true" → advertised, so the desktop app can switch to the
        // login-prompt flow.
        let db = test_db();
        set_system_setting(&db, SETTING_COMPLIANCE_MODE, "true");
        let body = get_status_json(&status_router(Some(db))).await;
        assert_eq!(body["compliance_mode"], json!(true));

        // Flipped back to "false" → advertised off.
        let db = test_db();
        set_system_setting(&db, SETTING_COMPLIANCE_MODE, "false");
        let body = get_status_json(&status_router(Some(db))).await;
        assert_eq!(body["compliance_mode"], json!(false));
    }

    #[tokio::test]
    async fn auth_status_answers_without_auth_or_db() {
        // The probe is anonymous by design and must keep answering without
        // a DB handle, advertising the default (off) mode.
        let body = get_status_json(&status_router(None)).await;
        assert_eq!(body["compliance_mode"], json!(false));
        assert!(body["version"].as_str().is_some());
        assert!(body["capabilities"]["desktop_bridge"].as_bool().is_some());
    }
}
