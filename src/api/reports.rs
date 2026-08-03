use super::AppState;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use serde::Deserialize;
use serde_json::json;
use tokio_util::io::ReaderStream;

/// Maximum number of rows returned by CSV export queries.
const MAX_CSV_EXPORT_ROWS: u32 = 100_000;

#[derive(Deserialize)]
pub struct ReportQuery {
    pub user: Option<String>,
    pub entry: Option<String>,
    #[serde(rename = "type")]
    pub session_type: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

pub async fn list_recordings(
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
    let recording_path = manager.recording_path().to_path_buf();

    let recordings = tokio::task::spawn_blocking(move || {
        let mut recordings = Vec::new();
        let entries = match std::fs::read_dir(&recording_path) {
            Ok(e) => e,
            Err(_) => return recordings,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("guac") {
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
    Ok(Json(json!({"sessions": rows, "total": total, "limit": limit, "offset": offset})))
}

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

pub(crate) fn is_safe_recording_name(name: &str, recording_dir: &std::path::Path) -> bool {
    if name.is_empty()
        || name == ".guac"
        || !name.ends_with(".guac")
        || name.contains('/')
        || name.contains('\\')
        || name.contains("..")
        || name.contains('\0')
    {
        return false;
    }
    let full = recording_dir.join(name);
    match (full.canonicalize(), recording_dir.canonicalize()) {
        (Ok(resolved), Ok(base)) => resolved.starts_with(&base),
        _ => false,
    }
}

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

    let path = manager.recording_path().join(&name);

    let file = tokio::fs::File::open(&path).await.map_err(|e| {
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

pub async fn delete_recording(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
    Path(name): Path<String>,
) -> Result<StatusCode, AppError> {
    if let Some(Extension(ref id)) = identity {
        if !id.has_role("admin") {
            return Err(AppError::Forbidden(
                "insufficient permissions — admin role required".into(),
            ));
        }
    }

    if !is_safe_recording_name(&name, manager.recording_path()) {
        return Err(AppError::Internal("invalid recording name".into()));
    }

    let path = manager.recording_path().join(&name);

    tokio::fs::remove_file(&path).await.map_err(|e| {
        tracing::warn!(name = %name, error = %e, "Recording not found");
        AppError::Session("recording not found".into())
    })?;
    Ok(StatusCode::NO_CONTENT)
}
