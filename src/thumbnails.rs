//! Background cleanup of orphaned session thumbnails.
//!
//! Session thumbnails are written to `<recording>/thumbnails/<session-id>.jpg`
//! by `PUT /api/sessions/{id}/thumbnail`, but nothing removed them once the
//! session left the registry. This module runs a periodic pass that deletes
//! JPEGs whose session id has no row in the `session_history` table. Thumbnails
//! for sessions still in history (any status, including completed and expired)
//! are kept, matching the web UI's recording and thumbnail expectations. VDI
//! container thumbnails (`vdi-<name>.jpg`) and any other file in the directory
//! are never touched.

use crate::api::AppState;
use crate::db;
use crate::session::SessionManager;
use std::collections::HashSet;
use std::io;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Seconds between cleanup passes (30 minutes).
pub const CLEANUP_INTERVAL_SECS: u64 = 30 * 60;

/// Outcome of a cleanup pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupResult {
    /// Number of orphaned thumbnail files removed.
    pub deleted: usize,
    /// Number of orphaned thumbnail files that could not be removed.
    pub failed: usize,
}

/// Why a cleanup pass could not run. The pass is skipped (never fatal).
#[derive(Debug, thiserror::Error)]
pub enum ThumbnailCleanupError {
    /// The session history could not be queried (temporarily unavailable).
    #[error("session history unavailable: {0}")]
    Database(String),
    /// The thumbnails directory could not be scanned.
    #[error("cannot scan thumbnails dir: {0}")]
    Scan(String),
}

/// Start the periodic orphaned-thumbnail cleanup loop. Runs every
/// [`CLEANUP_INTERVAL_SECS`], skipping the first tick so startup is not
/// delayed. Each pass is logged at info level with the number of files
/// deleted; a failed pass (DB unreachable, directory unreadable) is logged as
/// a warning and the loop continues.
pub fn spawn_thumbnail_cleanup(state: AppState) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;
            let manager = state.clone();
            let result = tokio::task::spawn_blocking(move || cleanup_pass(&manager)).await;
            match result {
                Ok(Ok(outcome)) => {
                    if outcome.failed > 0 {
                        tracing::info!(
                            deleted = outcome.deleted,
                            failed = outcome.failed,
                            "Thumbnail cleanup pass complete"
                        );
                    } else {
                        tracing::info!(
                            deleted = outcome.deleted,
                            "Thumbnail cleanup pass complete"
                        );
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "Thumbnail cleanup pass skipped");
                }
                Err(error) => {
                    tracing::warn!(error = %error, "Thumbnail cleanup task failed");
                }
            }
        }
    })
}

/// Run a single cleanup pass: scan `<recording>/thumbnails`, delete every
/// `<uuid>.jpg` whose session id has no row in `session_history`, and return
/// the number of files deleted (and deletion failures).
///
/// A missing thumbnails directory is an empty pass. Session history query
/// failures abort the pass with [`ThumbnailCleanupError::Database`] so the
/// caller can skip it; nothing is deleted when the DB is unreachable.
pub fn cleanup_pass(manager: &SessionManager) -> Result<CleanupResult, ThumbnailCleanupError> {
    let dir = manager.thumbnails_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(CleanupResult {
                deleted: 0,
                failed: 0,
            });
        }
        Err(error) => {
            return Err(ThumbnailCleanupError::Scan(error.to_string()));
        }
    };

    let session_ids = session_ids_in_history(manager)?;

    let mut deleted = 0;
    let mut failed = 0;
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(stem) = file_name.strip_suffix(".jpg") else {
            continue;
        };
        let Ok(session_id) = Uuid::parse_str(stem) else {
            // Not a session thumbnail (e.g. `vdi-<container>.jpg`).
            continue;
        };
        if session_ids.contains(&session_id) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => deleted += 1,
            Err(_) => failed += 1,
        }
    }
    Ok(CleanupResult { deleted, failed })
}

/// Session ids present in `session_history`, across all database backends.
///
/// Reuses `db::query_session_history` (the same backend-routed access the
/// reports API uses) so a configured SQLx pool is consulted when present and
/// the legacy rusqlite handle otherwise. Rows whose session id is not a valid
/// UUID cannot match a thumbnail file and are skipped.
fn session_ids_in_history(
    manager: &SessionManager,
) -> Result<HashSet<Uuid>, ThumbnailCleanupError> {
    let db = manager.db().ok_or_else(|| {
        ThumbnailCleanupError::Database("no database handle configured".to_string())
    })?;
    let (rows, _total) = db::query_session_history(db, None, None, None, None, None, u32::MAX, 0)
        .map_err(|e| ThumbnailCleanupError::Database(e.to_string()))?;
    let mut ids = HashSet::new();
    for row in rows {
        if let Some(session_id) = row.get("session_id").and_then(serde_json::Value::as_str) {
            if let Ok(id) = Uuid::parse_str(session_id) {
                ids.insert(id);
            }
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_thirty_minutes() {
        assert_eq!(CLEANUP_INTERVAL_SECS, 1800);
    }
}
