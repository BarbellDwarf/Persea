//! Integration tests for the orphaned session thumbnail cleanup task
//! (`src/thumbnails.rs`): orphaned files are deleted, files for sessions
//! still in history (any status) are kept, and a pass with no reachable
//! database is skipped without touching anything.
use persea::db::{self, Db};
use persea::session::SessionManager;
use persea::thumbnails::{cleanup_pass, CleanupResult, ThumbnailCleanupError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("persea-thumb-test-{tag}-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn thumbnails_dir(recording_dir: &Path) -> PathBuf {
    recording_dir.join("thumbnails")
}

fn write_thumbnail(recording_dir: &Path, session_id: Uuid) -> PathBuf {
    let path = thumbnails_dir(recording_dir).join(format!("{session_id}.jpg"));
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"jpeg").unwrap();
    path
}

fn manager_with_db(recording_dir: &Path, db: Db) -> Arc<SessionManager> {
    let mut config = persea::config::Config::default();
    config.recording_path = Some(recording_dir.to_path_buf());
    Arc::new(SessionManager::new_with_db(config, None, db))
}

fn manager_without_db(recording_dir: &Path) -> Arc<SessionManager> {
    let mut config = persea::config::Config::default();
    config.recording_path = Some(recording_dir.to_path_buf());
    Arc::new(SessionManager::new(config, None))
}

#[test]
fn orphaned_thumbnail_is_deleted_live_one_kept() {
    let dir = temp_dir("orphan");
    let db = db::init_db(Path::new(":memory:")).unwrap();
    let live = Uuid::new_v4();
    let orphan = Uuid::new_v4();
    db::insert_session_history(
        &db,
        &live.to_string(),
        "ssh",
        "server1",
        Some(22),
        "root",
        "alice",
        None,
        None,
        None,
        None,
    )
    .unwrap();

    let live_path = write_thumbnail(&dir, live);
    let orphan_path = write_thumbnail(&dir, orphan);

    let manager = manager_with_db(&dir, db);
    let result = cleanup_pass(&manager).unwrap();

    assert_eq!(
        result,
        CleanupResult {
            deleted: 1,
            failed: 0
        }
    );
    assert!(!orphan_path.exists(), "orphaned thumbnail must be deleted");
    assert!(
        live_path.exists(),
        "thumbnail for session in history must be kept"
    );
}

#[test]
fn completed_session_thumbnail_is_kept() {
    let dir = temp_dir("completed");
    let db = db::init_db(Path::new(":memory:")).unwrap();
    let ended = Uuid::new_v4();
    db::insert_session_history(
        &db,
        &ended.to_string(),
        "rdp",
        "server2",
        None,
        "",
        "bob",
        None,
        None,
        None,
        None,
    )
    .unwrap();
    db::end_session_history(&db, &ended.to_string(), "completed", 3600, None).unwrap();

    let ended_path = write_thumbnail(&dir, ended);
    let manager = manager_with_db(&dir, db);
    let result = cleanup_pass(&manager).unwrap();

    assert_eq!(result.deleted, 0);
    assert!(
        ended_path.exists(),
        "thumbnail for a completed session in history is not an orphan"
    );
}

#[test]
fn vdi_and_non_session_files_are_never_touched() {
    let dir = temp_dir("vdi");
    let db = db::init_db(Path::new(":memory:")).unwrap();
    let vdi_thumb = thumbnails_dir(&dir).join("vdi-some-container.jpg");
    let stray = thumbnails_dir(&dir).join("notes.txt");
    let not_a_uuid = thumbnails_dir(&dir).join("not-a-session.jpg");
    std::fs::create_dir_all(&dir.join("thumbnails")).unwrap();
    std::fs::write(&vdi_thumb, b"jpeg").unwrap();
    std::fs::write(&stray, b"not a thumbnail").unwrap();
    std::fs::write(&not_a_uuid, b"jpeg").unwrap();

    let manager = manager_with_db(&dir, db);
    let result = cleanup_pass(&manager).unwrap();

    assert_eq!(result.deleted, 0);
    assert!(vdi_thumb.exists(), "VDI container thumbnails must survive");
    assert!(stray.exists(), "non-thumbnail files must survive");
    assert!(not_a_uuid.exists(), "non-UUID .jpg files must survive");
}

#[test]
fn missing_thumbnails_dir_is_an_empty_pass() {
    let dir = temp_dir("missing-dir");
    let db = db::init_db(Path::new(":memory:")).unwrap();
    let manager = manager_with_db(&dir, db);
    let result = cleanup_pass(&manager).unwrap();
    assert_eq!(result.deleted, 0);
}

#[test]
fn db_down_skips_pass_and_keeps_files() {
    let dir = temp_dir("db-down");
    let orphan = Uuid::new_v4();
    let orphan_path = write_thumbnail(&dir, orphan);

    let manager = manager_without_db(&dir);
    let error = cleanup_pass(&manager).unwrap_err();

    assert!(
        matches!(error, ThumbnailCleanupError::Database(_)),
        "expected Database error, got {error:?}"
    );
    assert!(
        orphan_path.exists(),
        "a skipped pass must not delete anything"
    );
}
