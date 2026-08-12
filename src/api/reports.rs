//! Session reports and recording endpoints.
//!
//! Covers session history queries (JSON and CSV), top-connection and
//! top-user rankings, activity by hour, and the recording list, playback,
//! and deletion handlers. All require at least poweruser; deleting a
//! recording requires admin.
use super::AppState;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio_util::io::ReaderStream;

/// Maximum number of rows returned by CSV export queries.
#[allow(dead_code)]
const MAX_CSV_EXPORT_ROWS: u32 = 100_000;

/// Query parameters for the session-report endpoints.
#[derive(Deserialize)]
pub struct ReportQuery {
    /// Filter by the user who created the session.
    pub user: Option<String>,
    /// Filter by the address book entry slug.
    pub entry: Option<String>,
    /// Filter by session type (ssh, rdp, vnc, ...).
    #[serde(rename = "type")]
    pub session_type: Option<String>,
    /// Start of the time window (RFC 3339).
    pub from: Option<String>,
    /// End of the time window (RFC 3339).
    pub to: Option<String>,
    /// Row limit; clamped per endpoint.
    pub limit: Option<u32>,
    /// Pagination offset.
    pub offset: Option<u32>,
}

/// Query parameters for `GET /api/recordings`.
#[derive(Deserialize)]
pub struct RecordingQuery {
    /// Case-insensitive substring filter across entry display name, user, and folder.
    pub q: Option<String>,
}

/// `GET /api/recordings`: list recording files with metadata from
/// their sidecar files, newest first. Requires poweruser or admin.
/// Returns `AppError::Forbidden` for lower roles.
pub async fn list_recordings(
    State(manager): State<AppState>,
    Query(query): Query<RecordingQuery>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return Err(AppError::Forbidden(
                "requires poweruser or admin role".into(),
            ));
        }
    }
    let recording_path = manager.recording_path().to_path_buf();
    let q = query
        .q
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_lowercase);

    let recordings = tokio::task::spawn_blocking(move || {
        let mut recordings = Vec::new();
        let entries = match std::fs::read_dir(&recording_path) {
            Ok(e) => e,
            Err(_) => return recordings,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            // Accept both plain `.guac` recordings and encrypted-at-rest
            // `.guac.enc` recordings (extension `enc`, stem ending `.guac`).
            let ext = path.extension().and_then(|e| e.to_str());
            let is_guac = ext == Some("guac");
            let is_enc = ext == Some("enc")
                && path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s.ends_with(".guac"));
            if !is_guac && !is_enc {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_default();
            let mut rec = json!({
                "name": name,
                "size_bytes": meta.len(),
                "modified": modified,
            });
            if let Some(sidecar) = crate::recording::read_meta(&path) {
                if let Some(ref e) = sidecar.address_book_entry {
                    rec["address_book_entry"] = json!(e);
                }
                rec["created_at"] = json!(sidecar.created_at);
                if let Some(ref u) = sidecar.user {
                    rec["user"] = json!(u);
                }
                if let Some(ref f) = sidecar.folder {
                    rec["folder"] = json!(f);
                }
                if let Some(ref d) = sidecar.entry_display_name {
                    rec["entry_display_name"] = json!(d);
                }
                if let Some(ref t) = sidecar.session_type {
                    rec["session_type"] = json!(t);
                }
                if let Ok(created) = chrono::DateTime::parse_from_rfc3339(&sidecar.created_at) {
                    rec["display_date"] = json!(created
                        .with_timezone(&chrono::Local)
                        .format("%Y-%m-%d %H:%M")
                        .to_string());
                    if let Ok(modified) = meta.modified() {
                        let mod_dt: chrono::DateTime<chrono::Utc> = modified.into();
                        let dur = (mod_dt - created.with_timezone(&chrono::Utc)).num_seconds();
                        if dur >= 0 {
                            rec["duration_secs"] = json!(dur);
                        }
                    }
                }
            }
            if let Some(ref ql) = q {
                let haystack = [
                    rec["entry_display_name"].as_str().unwrap_or(""),
                    rec["user"].as_str().unwrap_or(""),
                    rec["folder"].as_str().unwrap_or(""),
                ]
                .join(" ")
                .to_lowercase();
                if !haystack.contains(ql.as_str()) {
                    continue;
                }
            }
            recordings.push(rec);
        }
        recordings.sort_by(|a, b| {
            let ma = a["modified"].as_str().unwrap_or("");
            let mb = b["modified"].as_str().unwrap_or("");
            mb.cmp(ma)
        });
        recordings
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!(recordings)))
}

/// `GET /api/recordings/typescripts`: list typescript files when
/// `recording.typescript_path` is configured. Requires poweruser or
/// admin. Returns `AppError::Forbidden` for lower roles.
pub async fn list_typescripts(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return Err(AppError::Forbidden(
                "requires poweruser or admin role".into(),
            ));
        }
    }

    let ts_path = match manager
        .config()
        .recording
        .as_ref()
        .and_then(|r| r.typescript_path.clone())
    {
        Some(p) => p,
        None => return Ok(Json(json!({"path": null, "items": []}))),
    };
    let ts_path_str = ts_path.display().to_string();

    let items = tokio::task::spawn_blocking(move || {
        let mut items = Vec::new();
        let entries = match std::fs::read_dir(&ts_path) {
            Ok(e) => e,
            Err(_) => return items,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if name.ends_with(".timing") {
                continue;
            }
            let meta = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let dt: chrono::DateTime<chrono::Utc> = t.into();
                    dt.to_rfc3339()
                })
                .unwrap_or_default();
            items.push(json!({
                "name": name,
                "size_bytes": meta.len(),
                "modified": modified,
            }));
        }
        items.sort_by(|a, b| {
            let ma = a["modified"].as_str().unwrap_or("");
            let mb = b["modified"].as_str().unwrap_or("");
            mb.cmp(ma)
        });
        items
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(json!({"path": ts_path_str, "items": items})))
}

/// `GET /api/reports/sessions`: session history with filters and
/// pagination. Requires poweruser or admin. `AppError::Forbidden` for
/// lower roles; `AppError::Internal` on database errors.
pub async fn report_sessions(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let (rows, total) = db::query_session_history(
        &database,
        q.user.as_deref(),
        q.entry.as_deref(),
        q.session_type.as_deref(),
        q.from.as_deref(),
        q.to.as_deref(),
        limit,
        offset,
    )?;
    Ok(Json(
        json!({"sessions": rows, "total": total, "limit": limit, "offset": offset}),
    ))
}

/// `GET /api/reports/sessions.csv`: the same session history as a
/// downloadable CSV attachment. Requires poweruser or admin.
pub async fn report_sessions_csv(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<axum::response::Response, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let mut csv_buf = Vec::new();
    db::stream_session_history_csv(
        &database,
        &mut csv_buf,
        q.user.as_deref(),
        q.entry.as_deref(),
        q.session_type.as_deref(),
        q.from.as_deref(),
        q.to.as_deref(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to query session history for CSV export");
        AppError::Internal("failed to query session history".into())
    })?;

    let mut csv = String::from("Session ID,Type,Hostname,Username,User,Entry,Folder,Started,Ended,Duration (secs),Status,Recording\n");
    csv.push_str(&String::from_utf8_lossy(&csv_buf));
    Ok(axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/csv; charset=utf-8")
        .header(
            "Content-Disposition",
            "attachment; filename=\"session-history.csv\"",
        )
        .body(Body::from(csv))
        .unwrap()
        .into_response())
}

/// `GET /api/reports/top-connections`: most-used address book entries
/// in the window. Requires poweruser or admin.
pub async fn report_top_connections(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let limit = q.limit.unwrap_or(20).min(100);
    let rows = db::top_connections(&database, limit)?;
    Ok(Json(json!(rows)))
}

/// `GET /api/reports/top-users`: most active users in the window.
/// Requires poweruser or admin.
pub async fn report_top_users(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let limit = q.limit.unwrap_or(20).min(100);
    let rows = db::top_users(&database, limit)?;
    Ok(Json(json!(rows)))
}

/// `GET /api/reports/summary`: aggregate counts for the reports page.
/// Requires poweruser or admin.
pub async fn report_summary(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let summary = db::session_summary(&database)?;
    Ok(Json(summary))
}

/// Query parameters for `GET /api/reports/activity`.
#[derive(Deserialize)]
pub struct ActivityQuery {
    /// Window size in hours; clamped to 1..=168.
    pub hours: Option<i32>,
}

/// `GET /api/reports/activity`: session starts per hour over the
/// window. Requires poweruser or admin.
pub async fn report_activity(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !identity
        .as_ref()
        .map(|Extension(id)| id.has_role("poweruser"))
        .unwrap_or(false)
    {
        return Err(AppError::Forbidden("poweruser role required".into()));
    }
    let hours = q.hours.unwrap_or(24).clamp(1, 168);
    let rows = db::session_activity_by_hour(&database, hours)?;
    Ok(Json(json!(rows)))
}

pub(crate) fn is_safe_recording_name(name: &str, recording_dir: &std::path::Path) -> bool {
    if name.is_empty()
        || name == ".guac"
        || name == ".guac.enc"
        || (!name.ends_with(".guac") && !name.ends_with(".guac.enc"))
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        return false;
    }
    // The named file may be the plaintext or the encrypted variant; accept
    // the sibling when the literal name is the other variant.
    let resolve = |n: &str| {
        let full = recording_dir.join(n);
        match (full.canonicalize(), recording_dir.canonicalize()) {
            (Ok(resolved), Ok(base)) => resolved.starts_with(&base),
            _ => false,
        }
    };
    if resolve(name) {
        return true;
    }
    if name.ends_with(".guac") {
        resolve(&format!("{name}.enc"))
    } else if let Some(plain) = name.strip_suffix(".enc") {
        resolve(plain)
    } else {
        false
    }
}

/// `GET /api/recordings/{name}`: stream a recording for playback.
/// Requires poweruser or admin. Encrypted recordings are decrypted
/// on the fly with the storage key. Returns `AppError::Internal` for
/// unsafe names, and `AppError::Session` when the recording is missing.
pub async fn serve_recording(
    State(manager): State<AppState>,
    Path(name): Path<String>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<axum::response::Response, AppError> {
    match &identity {
        Some(Extension(id)) if id.has_role("poweruser") => {}
        _ => {
            return Err(AppError::Forbidden(
                "requires poweruser or admin role".into(),
            ));
        }
    }
    if !is_safe_recording_name(&name, manager.recording_path()) {
        return Err(AppError::Internal("invalid recording name".into()));
    }

    // `.guac.enc` requests decrypt the named file directly; `.guac` requests
    // transparently fall back to the encrypted sibling when present.
    let is_enc = name.ends_with(".guac.enc");
    let plain_name = if is_enc {
        // Strip only the `.enc` suffix so `foo.guac.enc` maps to `foo.guac`
        // (Path::with_extension would produce `foo.guac.guac`).
        name.strip_suffix(".enc").unwrap_or(&name).to_string()
    } else {
        name.clone()
    };
    let plain_path = manager.recording_path().join(&plain_name);
    let enc_path = plain_path.with_extension("guac.enc");

    // Prefer the encrypted file when it exists.
    if enc_path.exists() {
        let enc_key = manager.config().storage_encryption_key().ok_or_else(|| {
            AppError::Internal("recording is encrypted but no encryption key is configured".into())
        })?;
        let plaintext = tokio::task::spawn_blocking(move || {
            crate::recording::decrypt_recording(&plain_path, &enc_key)
        })
        .await
        .map_err(|e| AppError::Internal(format!("join error: {e}")))?
        .map_err(|e| {
            tracing::warn!(name = %name, error = %e, "Failed to decrypt recording");
            AppError::Internal("failed to decrypt recording".into())
        })?;

        return Ok(axum::response::Response::builder()
            .header("content-type", "application/octet-stream")
            .header(
                "content-disposition",
                format!("inline; filename=\"{}\"", name),
            )
            .body(Body::from(plaintext))
            .unwrap()
            .into_response());
    }

    // Legacy unencrypted recording.
    let file = tokio::fs::File::open(&plain_path).await.map_err(|e| {
        tracing::warn!(name = %name, error = %e, "Recording not found");
        AppError::Session("recording not found".into())
    })?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream);

    Ok(axum::response::Response::builder()
        .header("content-type", "application/octet-stream")
        .header(
            "content-disposition",
            format!("inline; filename=\"{}\"", name),
        )
        .body(body)
        .unwrap()
        .into_response())
}

/// `DELETE /api/recordings/{name}`: remove a recording and its
/// sidecar, both the plaintext and encrypted variants. Admin only;
/// `AppError::Forbidden` for lower roles, `AppError::Session` when the
/// recording does not exist.
pub async fn delete_recording(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    let id = identity
        .as_ref()
        .map(|Extension(id)| id)
        .ok_or(AppError::Forbidden("authentication required".into()))?;
    if !id.has_role("admin") {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    if !is_safe_recording_name(&name, manager.recording_path()) {
        return Err(AppError::Internal("invalid recording name".into()));
    }

    let is_enc = name.ends_with(".guac.enc");
    let plain_name = if is_enc {
        name.strip_suffix(".enc").unwrap_or(&name).to_string()
    } else {
        name.clone()
    };
    let plain_path = manager.recording_path().join(&plain_name);
    let enc_path = plain_path.with_extension("guac.enc");

    // Remove whichever of the plaintext/encrypted variants exist.
    let mut removed = false;
    for p in [&plain_path, &enc_path] {
        match tokio::fs::remove_file(p).await {
            Ok(_) => removed = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(name = %name, error = %e, "Failed to delete recording");
            }
        }
    }
    if !removed {
        return Err(AppError::Session("recording not found".into()));
    }
    // Also remove the sidecar `.meta` file (best effort).
    let _ = tokio::fs::remove_file(plain_path.with_extension("meta")).await;
    Ok(StatusCode::NO_CONTENT)
}
