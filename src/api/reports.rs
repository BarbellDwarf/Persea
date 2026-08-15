//! Session reports and recording endpoints.
//!
//! Covers session history queries (JSON and CSV), top-connection and
//! top-user rankings, activity by hour, and the recording list, playback,
//! and deletion handlers. Session-history and recording endpoints accept
//! poweruser and above, but only admins see other users' data: a poweruser
//! is scoped to their own sessions and recordings (user decision
//! 2026-08-14). The cross-user aggregates (top connections, top users,
//! summary, activity, typescripts) are admin-only; deleting a recording
//! requires admin.
use super::AppState;
use crate::auth::AuthIdentity;
use crate::db::{self, Db};
use crate::error::AppError;
use aes::cipher::{Block, BlockCipherEncrypt, Key, KeyInit};
use aes::Aes256;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Extension, Json,
};
use bytes::Bytes;
use futures_util::Stream;
use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Seek, SeekFrom};
use tokio_util::io::ReaderStream;

/// Maximum number of rows returned by CSV export queries.
const MAX_CSV_EXPORT_ROWS: u32 = 100_000;

/// Whether the caller is an admin. Cross-user report and recording views
/// are admin-only; powerusers see their own sessions and recordings.
fn is_admin(identity: &Option<Extension<AuthIdentity>>) -> bool {
    identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
}

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
/// their sidecar files, newest first. Requires poweruser or admin;
/// powerusers see only their own recordings (sidecar `user` must match
/// their display name; recordings without a sidecar are admin-only).
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
    let admin = is_admin(&identity);
    let own_name = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string());
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
        if !admin {
            // Scoped to the caller's own recordings; a recording without a
            // matching sidecar owner is invisible to powerusers.
            recordings.retain(|rec| rec["user"].as_str() == own_name.as_deref());
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
/// `recording.typescript_path` is configured. Admin only: typescript
/// filenames carry no per-user metadata, so there is no way to scope a
/// listing to the caller. Returns `AppError::Forbidden` for lower roles.
pub async fn list_typescripts(
    State(manager): State<AppState>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Json<serde_json::Value>, AppError> {
    match &identity {
        Some(Extension(id)) if id.has_role("admin") => {}
        _ => {
            return Err(AppError::Forbidden("admin role required".into()));
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
/// pagination. Requires poweruser or admin. Powerusers see only their
/// own sessions (exact `created_by` match); admins see everyone and may
/// filter by user. `AppError::Forbidden` for lower roles;
/// `AppError::Internal` on database errors.
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
    let admin = is_admin(&identity);
    let own_name = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string());
    let user_filter = if admin {
        q.user.as_deref()
    } else {
        own_name.as_deref()
    };
    let limit = q.limit.unwrap_or(100).min(1000);
    let offset = q.offset.unwrap_or(0);
    let (mut rows, total) = db::query_session_history(
        &database,
        user_filter,
        q.entry.as_deref(),
        q.session_type.as_deref(),
        q.from.as_deref(),
        q.to.as_deref(),
        limit,
        offset,
    )?;
    if !admin {
        // Exact ownership: the shared query's user filter is a substring
        // LIKE, so rows are re-filtered to the caller's exact display
        // name. `total` stays the LIKE count, which can over-count when
        // one user's name is a substring of another's; the rows are exact.
        rows.retain(|row| row["created_by"].as_str() == own_name.as_deref());
    }
    Ok(Json(
        json!({"sessions": rows, "total": total, "limit": limit, "offset": offset}),
    ))
}

/// `GET /api/reports/sessions/csv`: the same session history as a
/// downloadable CSV attachment. Requires poweruser or admin; powerusers
/// export only their own sessions.
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
    let admin = is_admin(&identity);
    let own_name = identity
        .as_ref()
        .map(|Extension(id)| id.display_name().to_string());
    if !admin {
        // Scoped export: query the caller's own history and write the CSV
        // here, so no other user's sessions can leak through the shared
        // query's substring match.
        let (rows, _total) = db::query_session_history(
            &database,
            own_name.as_deref(),
            q.entry.as_deref(),
            q.session_type.as_deref(),
            q.from.as_deref(),
            q.to.as_deref(),
            MAX_CSV_EXPORT_ROWS,
            0,
        )
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to query session history for scoped CSV export");
            AppError::Internal("failed to query session history".into())
        })?;
        let mut csv =
            String::from("Session ID,Type,Hostname,Username,User,Source IP,Entry,Folder,Started,Ended,Duration (secs),Status,Recording\n");
        for row in rows {
            if row["created_by"].as_str() != own_name.as_deref() {
                continue;
            }
            write_session_row_csv(&mut csv, &row);
        }
        return Ok(csv_response(csv));
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

    let mut csv = String::from("Session ID,Type,Hostname,Username,User,Source IP,Entry,Folder,Started,Ended,Duration (secs),Status,Recording\n");
    csv.push_str(&String::from_utf8_lossy(&csv_buf));
    Ok(csv_response(csv))
}

/// Build a downloadable CSV response with the standard attachment name.
fn csv_response(csv: String) -> axum::response::Response {
    axum::response::Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/csv; charset=utf-8")
        .header(
            "Content-Disposition",
            "attachment; filename=\"session-history.csv\"",
        )
        .body(Body::from(csv))
        .unwrap()
        .into_response()
}

/// Write one session-history row as a CSV line, mirroring the column
/// layout and escaping of `db::stream_session_history_csv` (the admin
/// export). Used by the scoped, non-admin export so ownership filtering
/// happens before any other user's data is serialized.
fn write_session_row_csv(out: &mut String, row: &serde_json::Value) {
    let session_id = row["session_id"].as_str().unwrap_or("");
    let hostname = row["hostname"].as_str().unwrap_or("");
    let created_by = row["created_by"].as_str().unwrap_or("");
    let entry = row["entry_display_name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or_else(|| row["address_book_entry"].as_str())
        .unwrap_or("");
    let folder = row["address_book_folder"].as_str().unwrap_or("");
    let started_at = row["started_at"].as_str().unwrap_or("");
    let ended_at = row["ended_at"].as_str().unwrap_or("");
    let duration_secs = row["duration_secs"].as_i64();
    let status = row["status"].as_str().unwrap_or("");
    // Mirrors db.rs's recording_display_name: entry falls back from the
    // display name to the hostname to the session id; user to "unknown".
    let recording = {
        let entry_name = if entry.is_empty() {
            if hostname.is_empty() {
                session_id
            } else {
                hostname
            }
        } else {
            entry
        };
        let user = if created_by.is_empty() {
            "unknown"
        } else {
            created_by
        };
        match local_display_datetime(started_at) {
            Some(d) => format!("{d} — {entry_name} — {user}"),
            None => format!("{entry_name} — {user}"),
        }
    };
    let fields = [
        session_id,
        row["session_type"].as_str().unwrap_or(""),
        hostname,
        row["username"].as_str().unwrap_or(""),
        created_by,
        row["source_ip"].as_str().unwrap_or(""),
        entry,
        folder,
        started_at,
        ended_at,
    ];
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        db::csv_escape_field(out, field).expect("writing to a String cannot fail");
    }
    out.push(',');
    if let Some(d) = duration_secs {
        out.push_str(&d.to_string());
    }
    out.push(',');
    db::csv_escape_field(out, status).expect("writing to a String cannot fail");
    out.push(',');
    db::csv_escape_field(out, &recording).expect("writing to a String cannot fail");
    out.push('\n');
}

/// Format a `YYYY-MM-DD HH:MM:SS` UTC timestamp as server-local
/// `YYYY-MM-DD HH:MM`; mirrors the private helper in db.rs.
fn local_display_datetime(started_at: &str) -> Option<String> {
    let naive = chrono::NaiveDateTime::parse_from_str(started_at, "%Y-%m-%d %H:%M:%S").ok()?;
    Some(
        chrono::Utc
            .from_utc_datetime(&naive)
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M")
            .to_string(),
    )
}

/// `GET /api/reports/top-connections`: most-used address book entries
/// in the window. Admin only: the ranking spans all users.
pub async fn report_top_connections(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let limit = q.limit.unwrap_or(20).min(100);
    let rows = db::top_connections(&database, limit)?;
    Ok(Json(json!(rows)))
}

/// `GET /api/reports/top-users`: most active users in the window.
/// Admin only: the ranking spans all users.
pub async fn report_top_users(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let limit = q.limit.unwrap_or(20).min(100);
    let rows = db::top_users(&database, limit)?;
    Ok(Json(json!(rows)))
}

/// `GET /api/reports/summary`: aggregate counts for the reports page.
/// Admin only: the aggregates span all users.
pub async fn report_summary(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
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
/// window. Admin only: the histogram spans all users.
pub async fn report_activity(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    axum::extract::Query(q): axum::extract::Query<ActivityQuery>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let hours = q.hours.unwrap_or(24).clamp(1, 168);
    let rows = db::session_activity_by_hour(&database, hours)?;
    Ok(Json(json!(rows)))
}

/// AES-GCM parameters for the on-disk recording format.
const GCM_NONCE_LEN: usize = 12;
const GCM_TAG_LEN: usize = 16;
const GCM_BLOCK: usize = 16;

/// Encrypted recordings at or below this size are decrypted whole (the
/// tag is then verified before the first byte is served, so a tampered
/// file fails closed). Larger recordings stream through the bounded-
/// memory decryptor.
const STREAM_DECRYPT_THRESHOLD: u64 = 32 * 1024 * 1024;

/// Stream a `.guac.enc` recording as decrypted plaintext chunks.
///
/// The on-disk format is `nonce(12) || ciphertext || tag(16)` produced by
/// `crypto::encrypt_bytes`, a single AES-256-GCM message. AES-GCM
/// authenticates the whole message with one trailing tag, so a stream can
/// only verify the tag at the end: chunks are emitted as they decrypt and
/// a tag mismatch aborts the stream (the client sees a truncated
/// download). Files at or below [`STREAM_DECRYPT_THRESHOLD`] are
/// decrypted whole instead, which verifies before serving.
///
/// The keystream is AES-256 over the GCM counter blocks (J0 = nonce ||
/// 0x00000001; the first data block uses counter value 2, matching
/// `crypto::encrypt_bytes`), and the tag is GHASH over the zero-padded
/// ciphertext plus the length block, XORed with E_K(J0). GHASH uses the
/// constant-time carryless multiplication from BearSSL's
/// `ghash_ctmul64.c`, the same algorithm RustCrypto's polyval crate
/// applies to GHASH.
fn decrypt_recording_stream<F>(
    enc_path: &std::path::Path,
    key_hex: &str,
    mut emit: F,
) -> Result<(), String>
where
    F: FnMut(&[u8]) -> Result<(), String>,
{
    let key_bytes: [u8; 32] = hex::decode(key_hex)
        .map_err(|e| format!("invalid encryption key: {e}"))?
        .try_into()
        .map_err(|_| "encryption key must be 32 bytes".to_string())?;
    let aes = Aes256::new(&Key::<Aes256>::from(key_bytes));

    let mut file = std::fs::File::open(enc_path).map_err(|e| e.to_string())?;
    let file_len = file.metadata().map_err(|e| e.to_string())?.len();
    if file_len < (GCM_NONCE_LEN + GCM_TAG_LEN) as u64 {
        return Err("recording too short to be a valid encrypted file".into());
    }
    let ct_len = file_len - (GCM_NONCE_LEN + GCM_TAG_LEN) as u64;
    if ct_len / GCM_BLOCK as u64 + 2 > u32::MAX as u64 {
        return Err("recording exceeds the AES-GCM size limit".into());
    }

    let mut nonce = [0u8; GCM_NONCE_LEN];
    file.read_exact(&mut nonce).map_err(|e| e.to_string())?;

    let mut stored_tag = [0u8; GCM_TAG_LEN];
    file.seek(SeekFrom::End(-(GCM_TAG_LEN as i64)))
        .map_err(|e| e.to_string())?;
    file.read_exact(&mut stored_tag)
        .map_err(|e| e.to_string())?;
    file.seek(SeekFrom::Start(GCM_NONCE_LEN as u64))
        .map_err(|e| e.to_string())?;

    // GHASH key: H = E_K(0^128), then its bit-reversed (POLYVAL) form.
    let mut zero_block = [0u8; GCM_BLOCK];
    let mut h_block: Block<Aes256> = zero_block.into();
    aes.encrypt_block(&mut h_block);
    let mut ghash = Ghash::new(h_block.into());

    // Tag mask: E_K(J0), J0 = nonce || 0x00000001.
    let mut j0 = [0u8; GCM_BLOCK];
    j0[..GCM_NONCE_LEN].copy_from_slice(&nonce);
    j0[GCM_BLOCK - 1] = 1;
    let mut j0_block: Block<Aes256> = j0.into();
    aes.encrypt_block(&mut j0_block);
    let tag_mask: [u8; GCM_BLOCK] = j0_block.into();

    let mut counter: u32 = 2;
    let mut buf = vec![0u8; 64 * 1024];
    let mut out = vec![0u8; 64 * 1024];
    let mut out_len = 0usize;
    let mut pending = [0u8; GCM_BLOCK];
    let mut pending_len = 0usize;
    let mut remaining = ct_len;

    while remaining > 0 {
        let want = buf.len().min(remaining as usize);
        let n = file.read(&mut buf[..want]).map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("unexpected end of recording".into());
        }
        remaining -= n as u64;
        let mut pos = 0usize;
        while pos < n {
            let take = (n - pos).min(GCM_BLOCK - pending_len);
            pending[pending_len..pending_len + take].copy_from_slice(&buf[pos..pos + take]);
            pending_len += take;
            pos += take;
            if pending_len == GCM_BLOCK {
                // Authenticate the block...
                ghash.update_block(&pending);
                // ...then decrypt it: keystream = E_K(nonce || counter).
                let mut ctr_block = [0u8; GCM_BLOCK];
                ctr_block[..GCM_NONCE_LEN].copy_from_slice(&nonce);
                ctr_block[GCM_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
                let mut block: Block<Aes256> = ctr_block.into();
                aes.encrypt_block(&mut block);
                let keystream: [u8; GCM_BLOCK] = block.into();
                for (dst, ks) in pending.iter_mut().zip(keystream.iter()) {
                    *dst ^= ks;
                }
                out[out_len..out_len + GCM_BLOCK].copy_from_slice(&pending);
                out_len += GCM_BLOCK;
                pending_len = 0;
                counter += 1;
                if out_len == out.len() {
                    emit(&out)?;
                    out_len = 0;
                }
            }
        }
    }
    if out_len > 0 {
        emit(&out[..out_len])?;
    }

    // Final partial block: zero-padded for GHASH, keystream truncated.
    if pending_len > 0 {
        let mut padded = [0u8; GCM_BLOCK];
        padded[..pending_len].copy_from_slice(&pending[..pending_len]);
        ghash.update_block(&padded);
        let mut ctr_block = [0u8; GCM_BLOCK];
        ctr_block[..GCM_NONCE_LEN].copy_from_slice(&nonce);
        ctr_block[GCM_NONCE_LEN..].copy_from_slice(&counter.to_be_bytes());
        let mut block: Block<Aes256> = ctr_block.into();
        aes.encrypt_block(&mut block);
        let keystream: [u8; GCM_BLOCK] = block.into();
        for i in 0..pending_len {
            pending[i] ^= keystream[i];
        }
        emit(&pending[..pending_len])?;
    }

    // GHASH length block: AAD length (0) || ciphertext length, in bits.
    let mut len_block = [0u8; GCM_BLOCK];
    len_block[8..].copy_from_slice(&(ct_len * 8).to_be_bytes());
    ghash.update_block(&len_block);

    let mut expected = ghash.finalize();
    for (e, m) in expected.iter_mut().zip(tag_mask.iter()) {
        *e ^= *m;
    }
    use subtle::ConstantTimeEq;
    if !bool::from(expected.ct_eq(&stored_tag)) {
        return Err("recording failed authentication (tag mismatch)".into());
    }
    Ok(())
}

/// Response-body stream yielding decrypted recording chunks produced by
/// the blocking worker in [`serve_recording`].
struct RecordingDecryptStream {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, String>>,
}

impl Stream for RecordingDecryptStream {
    type Item = Result<Bytes, String>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// GHASH, the AES-GCM authentication hash, over GF(2^128) with the
/// reduction polynomial x^128 + x^7 + x^2 + x + 1.
///
/// Operates in the bit-reversed POLYVAL representation exactly like
/// RustCrypto's ghash crate: input blocks are byte-reversed before the
/// multiply, the key is `reverse(H)·x` (RFC 8452 mulX_POLYVAL), and the
/// final tag is byte-reversed again.
struct Ghash {
    /// Key as two little-endian u64 words.
    h: (u64, u64),
    /// Running accumulator, same word layout.
    y: (u64, u64),
}

impl Ghash {
    fn new(h: [u8; 16]) -> Self {
        let mut h_rev = h;
        h_rev.reverse();
        let h_polyval = mulx(u128::from_le_bytes(h_rev));
        Self {
            h: (h_polyval as u64, (h_polyval >> 64) as u64),
            y: (0, 0),
        }
    }

    /// Absorb one 16-byte block (zero-padded if partial).
    fn update_block(&mut self, block: &[u8; 16]) {
        let mut x = *block;
        x.reverse();
        let x = u128::from_le_bytes(x);
        self.y = polyval_mul(
            (self.y.0 ^ x as u64, self.y.1 ^ (x >> 64) as u64),
            self.h,
        );
    }

    /// Final GHASH tag bytes.
    fn finalize(self) -> [u8; 16] {
        let mut out = (self.y.0 as u128 | (self.y.1 as u128) << 64).to_le_bytes();
        out.reverse();
        out
    }
}

/// `mulX_POLYVAL` (RFC 8452 Appendix A): multiply by x in the POLYVAL
/// field, converting the GHASH key to its bit-reversed representation.
fn mulx(v: u128) -> u128 {
    let v_hi = v >> 127;
    let mut r = v << 1;
    r ^= v_hi ^ (v_hi << 127) ^ (v_hi << 126) ^ (v_hi << 121);
    r
}

/// Carryless 64x64 multiplication using the "holes" trick (BearSSL
/// ghash_ctmul64.c, as shipped in RustCrypto's polyval); constant-time.
fn bmul64(x: u64, y: u64) -> u64 {
    let m0: u64 = 0x1111_1111_1111_1111;
    let m1 = m0 << 1;
    let m2 = m1 << 1;
    let m3 = m2 << 1;
    let x0 = x & m0;
    let x1 = x & m1;
    let x2 = x & m2;
    let x3 = x & m3;
    let y0 = y & m0;
    let y1 = y & m1;
    let y2 = y & m2;
    let y3 = y & m3;
    // z_i is the XOR of the four "hole-aligned" products that land in
    // word i; the masks keep carries inside their holes.
    let z0 = x0.wrapping_mul(y0)
        ^ x1.wrapping_mul(y3)
        ^ x2.wrapping_mul(y2)
        ^ x3.wrapping_mul(y1);
    let z1 = x0.wrapping_mul(y1)
        ^ x1.wrapping_mul(y0)
        ^ x2.wrapping_mul(y3)
        ^ x3.wrapping_mul(y2);
    let z2 = x0.wrapping_mul(y2)
        ^ x1.wrapping_mul(y1)
        ^ x2.wrapping_mul(y0)
        ^ x3.wrapping_mul(y3);
    let z3 = x0.wrapping_mul(y3)
        ^ x1.wrapping_mul(y2)
        ^ x2.wrapping_mul(y1)
        ^ x3.wrapping_mul(y0);
    (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3)
}

/// POLYVAL field multiplication: Karatsuba over the 64-bit halves with
/// the bit-reversal trick, then Montgomery reduction against
/// x^128 + x^127 + x^126 + x^121 + 1 (polyval 0.7's soft backend, itself
/// BearSSL's ghash_ctmul64.c).
fn polyval_mul(a: (u64, u64), b: (u64, u64)) -> (u64, u64) {
    let (a0, a1) = a;
    let (b0, b1) = b;
    let a0r = a0.reverse_bits();
    let a1r = a1.reverse_bits();
    let a2 = a0 ^ a1;
    let a2r = a0r ^ a1r;
    let b0r = b0.reverse_bits();
    let b1r = b1.reverse_bits();
    let b2 = b0 ^ b1;
    let b2r = b0r ^ b1r;

    let z0 = bmul64(a0, b0);
    let z1 = bmul64(a1, b1);
    let mut z2 = bmul64(a2, b2);
    let mut z0h = bmul64(a0r, b0r);
    let mut z1h = bmul64(a1r, b1r);
    let mut z2h = bmul64(a2r, b2r);

    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = z0h.reverse_bits() >> 1;
    z1h = z1h.reverse_bits() >> 1;
    z2h = z2h.reverse_bits() >> 1;

    let v0 = z0;
    let mut v1 = z0h ^ z2;
    let mut v2 = z1 ^ z2h;
    let mut v3 = z1h;

    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    (v2, v3)
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
/// Requires poweruser or admin; powerusers can only play their own
/// recordings (sidecar owner must match their display name). Encrypted
/// recordings are decrypted on the fly with the storage key; files above
/// [`STREAM_DECRYPT_THRESHOLD`] stream through a bounded-memory
/// decryptor instead of loading whole into RAM. Returns
/// `AppError::Internal` for unsafe names, `AppError::Forbidden` for
/// recordings owned by someone else, and `AppError::Session` when the
/// recording is missing.
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

    if !is_admin(&identity) {
        // Ownership gate for powerusers: the sidecar records who created
        // the session. Recordings without a matching sidecar owner are
        // not playable (fail closed).
        let owner = identity
            .as_ref()
            .map(|Extension(id)| id.display_name().to_string());
        let meta = crate::recording::read_meta(&plain_path);
        if meta.as_ref().and_then(|m| m.user.as_deref()) != owner.as_deref() {
            return Err(AppError::Forbidden(
                "recording belongs to another user".into(),
            ));
        }
    }

    // Prefer the encrypted file when it exists.
    if enc_path.exists() {
        let enc_key = manager.config().storage_encryption_key().ok_or_else(|| {
            AppError::Internal("recording is encrypted but no encryption key is configured".into())
        })?;
        let enc_size = tokio::fs::metadata(&enc_path)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        if enc_size > STREAM_DECRYPT_THRESHOLD {
            // Multi-hundred-MB recordings must not be decrypted into a
            // single heap buffer (OOM). Stream instead: a worker decrypts
            // 64 KiB chunks into a bounded channel while the response
            // body drains it.
            let (tx, rx) = tokio::sync::mpsc::channel(8);
            let log_name = name.clone();
            tokio::task::spawn_blocking(move || {
                let result = decrypt_recording_stream(&enc_path, &enc_key, |chunk| {
                    tx.blocking_send(Ok(Bytes::copy_from_slice(chunk)))
                        .map_err(|_| "recording stream receiver dropped".to_string())
                });
                if let Err(e) = result {
                    tracing::warn!(
                        name = %log_name,
                        error = %e,
                        "Streaming recording decrypt failed"
                    );
                    let _ = tx.blocking_send(Err(e));
                }
            });
            return Ok(axum::response::Response::builder()
                .header("content-type", "application/octet-stream")
                .header(
                    "content-disposition",
                    format!("inline; filename=\"{}\"", name),
                )
                .body(Body::from_stream(RecordingDecryptStream { rx }))
                .unwrap()
                .into_response());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, StorageConfig};
    use crate::crypto;
    use crate::db::init_db;
    use crate::recording::{write_meta, RecordingMeta};
    use crate::session::SessionManager;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
    use axum::Router;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tower::ServiceExt;

    const TEST_KEY_HEX: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn test_key() -> crypto::EncryptionKey {
        crypto::EncryptionKey::from_hex(TEST_KEY_HEX).unwrap()
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("persea-reptest-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn random_bytes(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        rand::fill(&mut buf[..]);
        buf
    }

    fn identity(email: &str, name: &str, role: &str) -> AuthIdentity {
        AuthIdentity::User {
            email: email.into(),
            name: name.into(),
            role: role.into(),
            groups: vec![],
        }
    }

    fn admin() -> AuthIdentity {
        identity("admin@example.com", "Admin", "admin")
    }

    fn poweruser() -> AuthIdentity {
        identity("alice@example.com", "Alice", "poweruser")
    }

    fn test_db() -> Db {
        init_db(std::path::Path::new(":memory:")).unwrap()
    }

    fn decrypt_to_vec(path: &std::path::Path, key_hex: &str) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        decrypt_recording_stream(path, key_hex, |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    // ── Streaming decrypt ──

    #[test]
    fn stream_decrypt_matches_whole_buffer_decrypt() {
        for size in [
            0usize, 1, 15, 16, 17, 31, 1000, 4096, 65535, 65536, 65537, 200_000, 1 << 20,
        ] {
            let plaintext = random_bytes(size);
            let encrypted = crypto::encrypt_bytes(&test_key(), &plaintext).unwrap();
            let dir = temp_dir("stream-match");
            let path = dir.join("s.guac.enc");
            std::fs::write(&path, &encrypted).unwrap();
            let got = decrypt_to_vec(&path, TEST_KEY_HEX).unwrap();
            assert_eq!(got, plaintext, "size {size}");
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[test]
    fn stream_decrypt_rejects_wrong_key() {
        let plaintext = random_bytes(4096);
        let encrypted = crypto::encrypt_bytes(&test_key(), &plaintext).unwrap();
        let dir = temp_dir("stream-wrong-key");
        let path = dir.join("s.guac.enc");
        std::fs::write(&path, &encrypted).unwrap();
        let wrong_key = "02".repeat(32);
        let err = decrypt_to_vec(&path, &wrong_key).unwrap_err();
        assert!(err.contains("tag mismatch"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stream_decrypt_rejects_tampered_ciphertext() {
        let plaintext = random_bytes(1 << 20);
        let mut encrypted = crypto::encrypt_bytes(&test_key(), &plaintext).unwrap();
        // Flip one bit in the middle of the ciphertext body.
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0x01;
        let dir = temp_dir("stream-tamper");
        let path = dir.join("s.guac.enc");
        std::fs::write(&path, &encrypted).unwrap();
        let err = decrypt_to_vec(&path, TEST_KEY_HEX).unwrap_err();
        assert!(err.contains("tag mismatch"), "unexpected error: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stream_decrypt_rejects_truncated_and_empty_files() {
        let dir = temp_dir("stream-truncated");
        let empty = dir.join("empty.guac.enc");
        std::fs::write(&empty, b"").unwrap();
        assert!(decrypt_to_vec(&empty, TEST_KEY_HEX).is_err());

        let short = dir.join("short.guac.enc");
        std::fs::write(&short, vec![0u8; 20]).unwrap();
        assert!(decrypt_to_vec(&short, TEST_KEY_HEX).is_err());

        let plaintext = random_bytes(5000);
        let mut encrypted = crypto::encrypt_bytes(&test_key(), &plaintext).unwrap();
        encrypted.truncate(encrypted.len() - 5);
        let cut = dir.join("cut.guac.enc");
        std::fs::write(&cut, &encrypted).unwrap();
        let err = decrypt_to_vec(&cut, TEST_KEY_HEX).unwrap_err();
        assert!(
            err.contains("unexpected end of recording"),
            "unexpected error: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn stream_decrypt_rejects_invalid_key_hex() {
        let dir = temp_dir("stream-bad-hex");
        let path = dir.join("s.guac.enc");
        std::fs::write(&path, vec![0u8; 64]).unwrap();
        assert!(decrypt_to_vec(&path, "not-hex").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── Endpoint scoping (poweruser sees own sessions/recordings) ──

    fn recordings_router(
        dir: &std::path::Path,
        with_key: bool,
        id: Option<AuthIdentity>,
    ) -> Router {
        let mut config = Config::default();
        config.recording_path = Some(dir.to_path_buf());
        if with_key {
            config.storage = Some(StorageConfig {
                encryption_key: Some(TEST_KEY_HEX.to_string()),
                ..Default::default()
            });
        }
        let manager = Arc::new(SessionManager::new(config, None));
        let router = Router::new()
            .route("/api/recordings", get(list_recordings))
            .route(
                "/api/recordings/{name}",
                get(serve_recording),
            );
        match id {
            Some(id) => router.layer(Extension(id)).with_state(manager),
            None => router.with_state(manager),
        }
    }

    fn meta(user: &str) -> RecordingMeta {
        RecordingMeta {
            address_book_entry: Some("shared/folder/server1".into()),
            created_at: "2025-01-15T10:30:00Z".into(),
            user: Some(user.into()),
            folder: Some("shared/folder".into()),
            entry_display_name: Some("Production Server".into()),
            session_type: Some("rdp".into()),
        }
    }

    async fn body_bytes(resp: axum::response::Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&body_bytes(resp).await).unwrap()
    }

    fn req_get(path: &str) -> Request<Body> {
        Request::builder().uri(path).body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn list_recordings_poweruser_sees_only_own() {
        let dir = temp_dir("list-scope");
        std::fs::write(dir.join("mine.guac"), b"mine").unwrap();
        write_meta(&dir.join("mine.guac"), &meta("Alice")).unwrap();
        std::fs::write(dir.join("theirs.guac"), b"theirs").unwrap();
        write_meta(&dir.join("theirs.guac"), &meta("Bob")).unwrap();
        // No sidecar at all: not attributable, invisible to powerusers.
        std::fs::write(dir.join("orphan.guac"), b"orphan").unwrap();

        let router = recordings_router(&dir, false, Some(poweruser()));
        let resp = router.oneshot(req_get("/api/recordings")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let items = body_json(resp).await;
        let names: Vec<&str> = items
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["mine.guac"], "poweruser listing: {names:?}");

        let router = recordings_router(&dir, false, Some(admin()));
        let resp = router.oneshot(req_get("/api/recordings")).await.unwrap();
        let items = body_json(resp).await;
        let names: Vec<&str> = items
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap())
            .collect();
        assert_eq!(names.len(), 3, "admin sees everything: {names:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn serve_recording_poweruser_cannot_play_other_users_recording() {
        let dir = temp_dir("serve-scope");
        std::fs::write(dir.join("mine.guac"), b"4.3\nsize 1,1\n").unwrap();
        write_meta(&dir.join("mine.guac"), &meta("Alice")).unwrap();
        std::fs::write(dir.join("theirs.guac"), b"4.3\nsize 2,2\n").unwrap();
        write_meta(&dir.join("theirs.guac"), &meta("Bob")).unwrap();

        let router = recordings_router(&dir, false, Some(poweruser()));
        let resp = router
            .oneshot(req_get("/api/recordings/mine.guac"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_bytes(resp).await,
            b"4.3\nsize 1,1\n",
            "poweruser plays own recording"
        );

        let resp = router
            .oneshot(req_get("/api/recordings/theirs.guac"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "poweruser must not play another user's recording"
        );

        // Admin plays anything.
        let router = recordings_router(&dir, false, Some(admin()));
        let resp = router
            .oneshot(req_get("/api/recordings/theirs.guac"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn serve_encrypted_recording_streams_large_files() {
        let dir = temp_dir("serve-stream");
        // Just above the whole-buffer threshold: forces the streaming path.
        let plaintext = random_bytes((STREAM_DECRYPT_THRESHOLD + 1) as usize);
        let src = dir.join("big.guac");
        std::fs::write(&src, &plaintext).unwrap();
        write_meta(&src, &meta("Alice")).unwrap();
        crate::recording::encrypt_recording_file(&src, TEST_KEY_HEX).unwrap();

        let router = recordings_router(&dir, true, Some(poweruser()));
        let resp = router
            .oneshot(req_get("/api/recordings/big.guac"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let got = body_bytes(resp).await;
        assert_eq!(got.len(), plaintext.len());
        assert_eq!(got, plaintext);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn reports_router(db: Db, id: AuthIdentity) -> Router {
        Router::new()
            .route("/api/reports/sessions", get(report_sessions))
            .route("/api/reports/sessions/csv", get(report_sessions_csv))
            .route("/api/reports/top-connections", get(report_top_connections))
            .route("/api/reports/top-users", get(report_top_users))
            .route("/api/reports/summary", get(report_summary))
            .route("/api/reports/activity", get(report_activity))
            .layer(Extension(id))
            .layer(Extension(db))
    }

    fn seed_history(db: &Db) {
        db::insert_session_history(
            db,
            "sess-alice",
            "ssh",
            "alice-host",
            None,
            "alice",
            "Alice",
            Some("shared/a"),
            Some("shared"),
            Some("A Entry"),
            Some("10.0.0.1"),
        )
        .unwrap();
        db::insert_session_history(
            db,
            "sess-bob",
            "rdp",
            "bob-host",
            None,
            "bob",
            "Bob",
            Some("shared/b"),
            Some("shared"),
            Some("B Entry"),
            Some("10.0.0.2"),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn report_sessions_poweruser_sees_only_own_sessions() {
        let db = test_db();
        seed_history(&db);
        let router = reports_router(db.clone(), poweruser());
        let resp = router
            .oneshot(req_get("/api/reports/sessions"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let sessions = json["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1, "poweruser sees own sessions only");
        assert_eq!(sessions[0]["created_by"], "Alice");

        // A requested user filter must not widen the poweruser's scope.
        let router = reports_router(db.clone(), poweruser());
        let resp = router
            .oneshot(req_get("/api/reports/sessions?user=Bob"))
            .await
            .unwrap();
        let json = body_json(resp).await;
        let sessions = json["sessions"].as_array().unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0]["created_by"], "Alice");

        let router = reports_router(db.clone(), admin());
        let resp = router
            .oneshot(req_get("/api/reports/sessions"))
            .await
            .unwrap();
        let json = body_json(resp).await;
        assert_eq!(json["sessions"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn report_sessions_csv_poweruser_exports_only_own_sessions() {
        let db = test_db();
        seed_history(&db);
        let router = reports_router(db.clone(), poweruser());
        let resp = router
            .oneshot(req_get("/api/reports/sessions/csv"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let csv = String::from_utf8(body_bytes(resp).await).unwrap();
        assert!(csv.contains("sess-alice"), "own session exported: {csv}");
        assert!(
            !csv.contains("sess-bob"),
            "other user's session must not be exported: {csv}"
        );
    }

    #[tokio::test]
    async fn report_aggregates_require_admin() {
        let db = test_db();
        seed_history(&db);
        let router = reports_router(db.clone(), poweruser());
        for path in [
            "/api/reports/top-connections",
            "/api/reports/top-users",
            "/api/reports/summary",
            "/api/reports/activity",
        ] {
            let resp = router.clone().oneshot(req_get(path)).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "poweruser must be denied {path}"
            );
        }
        let router = reports_router(db.clone(), admin());
        for path in [
            "/api/reports/top-connections",
            "/api/reports/top-users",
            "/api/reports/summary",
            "/api/reports/activity",
        ] {
            let resp = router.clone().oneshot(req_get(path)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "admin allowed {path}");
        }
    }

    #[tokio::test]
    async fn reports_require_poweruser_role() {
        let db = test_db();
        let viewer = identity("viewer@example.com", "Viewer", "viewer");
        let router = reports_router(db, viewer);
        for path in [
            "/api/reports/sessions",
            "/api/reports/sessions/csv",
            "/api/reports/top-connections",
            "/api/reports/top-users",
            "/api/reports/summary",
            "/api/reports/activity",
        ] {
            let resp = router.clone().oneshot(req_get(path)).await.unwrap();
            assert_eq!(resp.status(), StatusCode::FORBIDDEN, "viewer denied {path}");
        }
    }
}
