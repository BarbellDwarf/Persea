//! Recording rotation and disk-space management.
//!
//! Provides functions to:
//! - Check disk usage percentage via `statvfs`
//! - List `.guac` recordings sorted by age (oldest first)
//! - Read/write sidecar `.meta` JSON files for per-entry tracking
//! - Rotate recordings globally (by count and disk usage)
//! - Rotate recordings per address-book entry

use crate::config::RecordingConfig;
use crate::crypto;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Sidecar metadata written alongside each `.guac` recording file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMeta {
    /// Address book entry key (e.g. "shared/folder/entry").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_book_entry: Option<String>,
    /// ISO 8601 timestamp when the recording was created.
    pub created_at: String,
    /// User who created the session (email).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Address book folder name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Display name of the address book entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_display_name: Option<String>,
    /// Session type (ssh, rdp, vnc, web).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_type: Option<String>,
}

/// Get the disk usage percentage for the filesystem containing `path`.
/// Returns 0.0–100.0, or an error if the syscall fails.
pub fn disk_usage_percent(path: &Path) -> std::io::Result<f64> {
    use std::ffi::CString;

    let c_path = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    // SAFETY: statvfs(2) reads filesystem metadata for the given path.
    // The path is a valid C string (CString), and stat is stack-allocated
    // and zeroed before the call. The function returns 0 on success or
    // sets errno on failure — we check the return value and propagate errors.
    unsafe {
        let mut stat: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut stat) != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let total = stat.f_blocks as f64;
        if total == 0.0 {
            return Ok(0.0);
        }
        let free = stat.f_bfree as f64;
        let used = total - free;
        Ok((used / total) * 100.0)
    }
}

/// List all `.guac` (and `.guac.enc`) recordings in `dir`, sorted oldest-first.
/// Returns `(path, modified_time, size_bytes)`.
pub fn list_recordings_by_age(dir: &Path) -> Vec<(PathBuf, SystemTime, u64)> {
    let mut recordings = Vec::new();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return recordings,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let is_guac = path.extension().and_then(|e| e.to_str()) == Some("guac");
        let is_enc = path.extension().and_then(|e| e.to_str()) == Some("enc")
            && path
                .file_stem()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.ends_with(".guac"));
        if !is_guac && !is_enc {
            continue;
        }
        if let Ok(meta) = std::fs::metadata(&path) {
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            recordings.push((path, modified, meta.len()));
        }
    }

    recordings.sort_by_key(|(_, time, _)| *time);
    recordings
}

/// Read the sidecar `.meta` JSON for a `.guac` or `.guac.enc` file.
pub fn read_meta(guac_path: &Path) -> Option<RecordingMeta> {
    // For `.guac.enc`, the stem is `foo.guac`; the meta lives alongside `foo.meta`.
    let meta_path = if guac_path.extension().and_then(|e| e.to_str()) == Some("enc") {
        let stem = guac_path.file_stem().and_then(|s| s.to_str())?;
        // stem is "<session>.guac" → strip the ".guac" suffix to get the base name
        let base = stem.strip_suffix(".guac").unwrap_or(stem);
        guac_path.with_file_name(format!("{base}.meta"))
    } else {
        guac_path.with_extension("meta")
    };
    let data = std::fs::read_to_string(&meta_path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Write a sidecar `.meta` JSON alongside a `.guac` file.
pub fn write_meta(guac_path: &Path, meta: &RecordingMeta) -> std::io::Result<()> {
    let meta_path = guac_path.with_extension("meta");
    let json = serde_json::to_string(meta).map_err(std::io::Error::other)?;
    std::fs::write(&meta_path, json)?;

    // Restrictive permissions on meta file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&meta_path, std::fs::Permissions::from_mode(0o640));
    }

    Ok(())
}

/// Delete a recording and its sidecar `.meta` file.
/// Handles both `.guac` and `.guac.enc` variants.
fn delete_recording(path: &Path) {
    if let Err(e) = std::fs::remove_file(path) {
        tracing::warn!("Failed to delete recording {}: {}", path.display(), e);
    } else {
        tracing::info!("Rotated recording: {}", path.display());
    }
    // Also remove sidecar meta (stem may contain ".guac" or ".guac.enc")
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let meta_path = if stem.ends_with(".guac") {
        // .guac.enc → meta is <stem-without-guac>.meta
        path.with_file_name(format!("{}.meta", stem))
    } else {
        path.with_extension("meta")
    };
    let _ = std::fs::remove_file(&meta_path);
    // If we deleted a .guac.enc, also remove the stale .guac (and vice versa).
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext == "enc" {
        let plaintext = path.with_extension("guac");
        let _ = std::fs::remove_file(&plaintext);
    } else if ext == "guac" {
        let encrypted = path.with_extension("guac.enc");
        let _ = std::fs::remove_file(&encrypted);
    }
}

/// Run global rotation based on `RecordingConfig`.
/// Deletes oldest recordings when:
/// 1. Total count exceeds `max_recordings` (if > 0)
/// 2. Disk usage exceeds `max_disk_percent` (if > 0)
///
/// Returns the number of recordings deleted.
pub fn rotate(config: &RecordingConfig) -> usize {
    let mut deleted = 0;
    let dir = &config.path;

    // Phase 1: enforce max_recordings count
    if config.max_recordings > 0 {
        let recordings = list_recordings_by_age(dir);
        let over = recordings
            .len()
            .saturating_sub(config.max_recordings as usize);
        for (path, _, _) in recordings.iter().take(over) {
            delete_recording(path);
            deleted += 1;
        }
    }

    // Phase 2: enforce max_disk_percent
    if config.max_disk_percent > 0 {
        let threshold = config.max_disk_percent as f64;
        loop {
            let usage = match disk_usage_percent(dir) {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!("Failed to check disk usage: {}", e);
                    break;
                }
            };
            if usage <= threshold {
                break;
            }
            // Find the oldest recording and delete it
            let recordings = list_recordings_by_age(dir);
            if let Some((path, _, _)) = recordings.first() {
                delete_recording(path);
                deleted += 1;
            } else {
                break; // no more recordings to delete
            }
        }
    }

    if deleted > 0 {
        tracing::info!("Recording rotation: deleted {} files", deleted);
    }
    deleted
}

/// Rotate recordings for a specific address book entry.
/// Deletes oldest recordings whose `.meta` matches `entry_key`
/// until the count is at most `max`.
///
/// Returns the number of recordings deleted.
pub fn rotate_per_entry(recording_dir: &Path, entry_key: &str, max: u32) -> usize {
    if max == 0 {
        return 0; // unlimited
    }

    let recordings = list_recordings_by_age(recording_dir);

    // Filter to recordings matching this entry
    let mut matching: Vec<&PathBuf> = Vec::new();
    for (path, _, _) in &recordings {
        if let Some(meta) = read_meta(path) {
            if meta.address_book_entry.as_deref() == Some(entry_key) {
                matching.push(path);
            }
        }
    }

    // Already sorted oldest-first
    let over = matching.len().saturating_sub(max as usize);
    let mut deleted = 0;
    for path in matching.iter().take(over) {
        delete_recording(path);
        deleted += 1;
    }

    if deleted > 0 {
        tracing::info!(
            "Per-entry rotation for '{}': deleted {} files ({} remaining)",
            entry_key,
            deleted,
            matching.len() - deleted
        );
    }
    deleted
}

/// Whether recordings should be encrypted at rest.
///
/// Returns `true` when `encrypt_at_rest` is explicitly `Some(true)`, or when
/// it is `None` (auto) and an encryption key is configured.
pub fn should_encrypt_at_rest(config: &RecordingConfig, encryption_key_hex: Option<&str>) -> bool {
    match config.encrypt_at_rest {
        Some(v) => v,
        None => encryption_key_hex.is_some_and(|k| !k.is_empty()),
    }
}

/// Encrypt a `.guac` file in place: reads the plaintext, writes `<path>.enc`,
/// then removes the original plaintext file.
pub fn encrypt_recording_file(
    guac_path: &Path,
    encryption_key_hex: &str,
) -> Result<(), std::io::Error> {
    let key = crypto::EncryptionKey::from_hex(encryption_key_hex)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

    let plaintext = std::fs::read(guac_path)?;
    let encrypted = crypto::encrypt_bytes(&key, &plaintext)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    let enc_path = guac_path.with_extension("guac.enc");
    std::fs::write(&enc_path, &encrypted)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o640));
    }

    std::fs::remove_file(guac_path)?;
    Ok(())
}

/// Decrypt a `.guac.enc` file into an in-memory buffer.
///
/// If `guac_path` has no `.enc` counterpart, falls back to reading the
/// plaintext `.guac` file directly (for unencrypted recordings).
pub fn decrypt_recording(
    guac_path: &Path,
    encryption_key_hex: &str,
) -> Result<Vec<u8>, std::io::Error> {
    let enc_path = guac_path.with_extension("guac.enc");
    if enc_path.exists() {
        let key = crypto::EncryptionKey::from_hex(encryption_key_hex)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let encrypted = std::fs::read(&enc_path)?;
        crypto::decrypt_bytes(&key, &encrypted)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    } else {
        // Legacy unencrypted recording
        std::fs::read(guac_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("persea_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn recording_meta_serde_roundtrip() {
        let meta = RecordingMeta {
            address_book_entry: Some("shared/folder/server1".into()),
            created_at: "2025-01-15T10:30:00Z".into(),
            user: Some("admin@example.com".into()),
            folder: Some("shared/folder".into()),
            entry_display_name: Some("Production Server".into()),
            session_type: Some("rdp".into()),
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: RecordingMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.address_book_entry.as_deref(),
            Some("shared/folder/server1")
        );
        assert_eq!(deserialized.created_at, "2025-01-15T10:30:00Z");
        assert_eq!(deserialized.user.as_deref(), Some("admin@example.com"));
        assert_eq!(deserialized.session_type.as_deref(), Some("rdp"));
    }

    #[test]
    fn recording_meta_optional_fields_skipped() {
        let meta = RecordingMeta {
            address_book_entry: None,
            created_at: "2025-01-01T00:00:00Z".into(),
            user: None,
            folder: None,
            entry_display_name: None,
            session_type: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        assert!(!json.contains("address_book_entry"));
        assert!(!json.contains("user"));
        assert!(!json.contains("folder"));
        assert!(!json.contains("entry_display_name"));
        assert!(!json.contains("session_type"));
        assert!(json.contains("created_at"));
    }

    #[test]
    fn recording_meta_minimal_json() {
        let json = r#"{"created_at":"2025-01-01T00:00:00Z"}"#;
        let meta: RecordingMeta = serde_json::from_str(json).unwrap();
        assert_eq!(meta.created_at, "2025-01-01T00:00:00Z");
        assert!(meta.address_book_entry.is_none());
        assert!(meta.user.is_none());
    }

    #[test]
    fn disk_usage_percent_returns_value() {
        let usage = disk_usage_percent(Path::new("/"));
        assert!(usage.is_ok());
        let pct = usage.unwrap();
        assert!((0.0..=100.0).contains(&pct));
    }

    #[test]
    fn disk_usage_percent_invalid_path() {
        let result = disk_usage_percent(Path::new("/nonexistent_path_12345"));
        assert!(result.is_err());
    }

    #[test]
    fn list_recordings_by_age_empty_dir() {
        let dir = temp_dir();
        let result = list_recordings_by_age(&dir);
        assert!(result.is_empty());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_recordings_by_age_nonexistent_dir() {
        let result = list_recordings_by_age(Path::new("/nonexistent_dir_12345"));
        assert!(result.is_empty());
    }

    #[test]
    fn list_recordings_by_age_filters_non_guac() {
        let dir = temp_dir();
        fs::write(dir.join("test.txt"), "not a recording").unwrap();
        fs::write(dir.join("session.guac"), "fake guac").unwrap();
        fs::write(dir.join("another.log"), "log file").unwrap();

        let result = list_recordings_by_age(&dir);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0.file_name().unwrap(), "session.guac");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn list_recordings_by_age_sorted_oldest_first() {
        let dir = temp_dir();
        // Create files with different names (OS will set mtime to creation time)
        fs::write(dir.join("c.guac"), "c").unwrap();
        fs::write(dir.join("a.guac"), "a").unwrap();
        fs::write(dir.join("b.guac"), "b").unwrap();

        let result = list_recordings_by_age(&dir);
        assert_eq!(result.len(), 3);
        // All should be .guac files
        for (path, _, _) in &result {
            assert_eq!(path.extension().unwrap(), "guac");
        }
        // Should be sorted by modification time
        for i in 1..result.len() {
            assert!(result[i - 1].1 <= result[i].1);
        }
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_and_read_meta() {
        let dir = temp_dir();
        let guac_path = dir.join("test.guac");
        fs::write(&guac_path, "fake data").unwrap();

        let meta = RecordingMeta {
            address_book_entry: Some("entry/key".into()),
            created_at: "2025-06-01T12:00:00Z".into(),
            user: Some("test@example.com".into()),
            folder: None,
            entry_display_name: None,
            session_type: Some("ssh".into()),
        };

        write_meta(&guac_path, &meta).unwrap();

        let read = read_meta(&guac_path);
        assert!(read.is_some());
        let read = read.unwrap();
        assert_eq!(read.address_book_entry.as_deref(), Some("entry/key"));
        assert_eq!(read.created_at, "2025-06-01T12:00:00Z");
        assert_eq!(read.user.as_deref(), Some("test@example.com"));
        assert_eq!(read.session_type.as_deref(), Some("ssh"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn read_meta_missing_file() {
        let result = read_meta(Path::new("/nonexistent/file.guac"));
        assert!(result.is_none());
    }

    #[test]
    fn read_meta_invalid_json() {
        let dir = temp_dir();
        let guac_path = dir.join("bad.guac");
        fs::write(&guac_path, "").unwrap();
        let meta_path = guac_path.with_extension("meta");
        fs::write(&meta_path, "not valid json {{{").unwrap();

        let result = read_meta(&guac_path);
        assert!(result.is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_zero_max_recordings_is_noop() {
        let dir = temp_dir();
        fs::write(dir.join("test.guac"), "data").unwrap();

        let config = RecordingConfig {
            path: dir.clone(),
            max_recordings: 0,
            max_disk_percent: 0,
            ..Default::default()
        };
        let deleted = rotate(&config);
        assert_eq!(deleted, 0);
        assert!(dir.join("test.guac").exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_enforces_max_recordings() {
        let dir = temp_dir();
        for i in 0..5 {
            fs::write(dir.join(format!("{}.guac", i)), "data").unwrap();
        }

        let config = RecordingConfig {
            path: dir.clone(),
            max_recordings: 3,
            max_disk_percent: 0,
            ..Default::default()
        };
        let deleted = rotate(&config);
        assert_eq!(deleted, 2);
        let remaining = list_recordings_by_age(&dir);
        assert_eq!(remaining.len(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_no_op_when_under_limit() {
        let dir = temp_dir();
        for i in 0..3 {
            fs::write(dir.join(format!("{}.guac", i)), "data").unwrap();
        }

        let config = RecordingConfig {
            path: dir.clone(),
            max_recordings: 5,
            max_disk_percent: 0,
            ..Default::default()
        };
        let deleted = rotate(&config);
        assert_eq!(deleted, 0);
        assert_eq!(list_recordings_by_age(&dir).len(), 3);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_per_entry_zero_max_is_noop() {
        let dir = temp_dir();
        fs::write(dir.join("test.guac"), "data").unwrap();

        let deleted = rotate_per_entry(&dir, "entry/key", 0);
        assert_eq!(deleted, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_per_entry_no_matching_metas() {
        let dir = temp_dir();
        fs::write(dir.join("test.guac"), "data").unwrap();
        // No .meta file, so nothing matches
        let deleted = rotate_per_entry(&dir, "entry/key", 1);
        assert_eq!(deleted, 0);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_per_entry_matches_and_deletes_oldest() {
        let dir = temp_dir();
        // Create 3 recordings all for the same entry
        for i in 0..3 {
            let guac_path = dir.join(format!("{}.guac", i));
            fs::write(&guac_path, "data").unwrap();
            let meta = RecordingMeta {
                address_book_entry: Some("target/entry".into()),
                created_at: format!("2025-01-0{}T00:00:00Z", i + 1),
                user: None,
                folder: None,
                entry_display_name: None,
                session_type: None,
            };
            write_meta(&guac_path, &meta).unwrap();
        }

        let deleted = rotate_per_entry(&dir, "target/entry", 2);
        assert_eq!(deleted, 1);
        // Two should remain
        let remaining: Vec<_> = list_recordings_by_age(&dir)
            .into_iter()
            .filter(|(p, _, _)| {
                read_meta(p)
                    .map(|m| m.address_book_entry.as_deref() == Some("target/entry"))
                    .unwrap_or(false)
            })
            .collect();
        assert_eq!(remaining.len(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rotate_per_entry_ignores_other_entries() {
        let dir = temp_dir();
        // Create recordings for different entries
        for (i, entry) in ["other/entry", "target/entry", "other/entry"]
            .iter()
            .enumerate()
        {
            let guac_path = dir.join(format!("{}.guac", i));
            fs::write(&guac_path, "data").unwrap();
            let meta = RecordingMeta {
                address_book_entry: Some(entry.to_string()),
                created_at: format!("2025-01-0{}T00:00:00Z", i + 1),
                user: None,
                folder: None,
                entry_display_name: None,
                session_type: None,
            };
            write_meta(&guac_path, &meta).unwrap();
        }

        let deleted = rotate_per_entry(&dir, "target/entry", 1);
        assert_eq!(deleted, 0); // only 1 match, at limit
        fs::remove_dir_all(&dir).ok();
    }
}
