//! Regression tests for first-run storage key generation (persea#97): a
//! fresh store with no configured key gets one generated and persisted;
//! stores that already hold encrypted credentials refuse to start.
//!
//! Mirrors the harness in tests/api_handler_tests.rs: in-memory SQLite via
//! `db::init_db(":memory:")`.

use persea::config::{
    ensure_db_storage_key, generate_encryption_key, persist_storage_encryption_key, Config,
    StorageKeyGuard,
};
use persea::db::{self, Db};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static DIR_SEQ: AtomicU64 = AtomicU64::new(0);

fn test_db() -> Db {
    db::init_db(Path::new(":memory:")).unwrap()
}

fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

/// Scratch directory, unique per call so parallel tests never collide.
fn scratch_dir(tag: &str) -> std::path::PathBuf {
    let n = DIR_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("persea-storage-key-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// CI sets PERSEA_STORAGE_KEY; pin the env to "unset" for the duration so
/// results are deterministic. Every test in this binary calls this first
/// and none of them set the variable, so parallel tests cannot race.
fn without_env_key() {
    std::env::remove_var("PERSEA_STORAGE_KEY");
}

fn insert_credential(db: &Db) {
    let folder_id = db::create_ab_folder(db, "shared", "servers", "", "", false).unwrap();
    let entry_id = db::create_ab_entry(
        db,
        folder_id,
        "host-a",
        "",
        "ssh",
        "host-a",
        Some(22),
        "root",
        "{}",
        "",
    )
    .unwrap();
    db::store_ab_credential(db, entry_id, "password", "enc:v1:AAAA").unwrap();
}

#[test]
fn fresh_store_generates_and_persists_key() {
    without_env_key();
    let dir = scratch_dir("fresh");
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, "listen_addr = \"127.0.0.1:8089\"\n").unwrap();

    let db = test_db();
    let mut config = Config::default();
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::Ready);

    let key = config.storage_encryption_key().expect("key installed on config");
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));

    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(file.contains("[storage]"));
    assert!(file.contains(&format!("encryption_key = \"{}\"", key)));

    // A restart picks the persisted key back up.
    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(reloaded.storage_encryption_key().as_deref(), Some(key.as_str()));
}

#[test]
fn existing_storage_section_is_filled_in() {
    without_env_key();
    let dir = scratch_dir("fill");
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        "listen_addr = \"127.0.0.1:8089\"\n\n[storage]\nbackend = \"db\"\n\n[recording]\npath = \"./recordings\"\n",
    )
    .unwrap();

    let db = test_db();
    let mut config = Config::default();
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::Ready);

    let key = config.storage_encryption_key().unwrap();
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    // A duplicate [storage] header would be invalid TOML.
    assert_eq!(file.matches("[storage]").count(), 1);
    // Existing keys in the section survive.
    assert!(file.contains("backend = \"db\""));
    assert!(file.contains(&format!("encryption_key = \"{}\"", key)));
    // The key lands inside [storage], not before the next section.
    let storage_idx = file.find("[storage]").unwrap();
    let recording_idx = file.find("[recording]").unwrap();
    let key_idx = file.find(&format!("encryption_key = \"{}\"", key)).unwrap();
    assert!(key_idx > storage_idx && key_idx < recording_idx);

    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(
        reloaded.storage_encryption_key().as_deref(),
        Some(key.as_str())
    );
    assert_eq!(
        reloaded.storage.as_ref().map(|s| s.backend.as_str()),
        Some("db")
    );
}

#[test]
fn store_with_credentials_refuses() {
    without_env_key();
    let dir = scratch_dir("creds");
    let cfg_path = dir.join("config.toml");
    let original = "listen_addr = \"127.0.0.1:8089\"\n";
    std::fs::write(&cfg_path, original).unwrap();

    let db = test_db();
    insert_credential(&db);

    let mut config = Config::default();
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::RefuseExistingCredentials);
    // No key generated, config file untouched.
    assert!(config.storage_encryption_key().is_none());
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
}

#[test]
fn unwritable_config_refuses() {
    without_env_key();
    let dir = scratch_dir("unwritable");
    // A path inside a directory that does not exist cannot be written.
    let missing = dir.join("no-such-dir").join("config.toml");

    let db = test_db();
    let mut config = Config::default();
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&missing));
    assert!(matches!(outcome, StorageKeyGuard::RefuseUnwritable { .. }));
    assert!(config.storage_encryption_key().is_none());
}

#[test]
fn configured_key_is_left_alone() {
    without_env_key();
    let dir = scratch_dir("existing");
    let cfg_path = dir.join("config.toml");
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let original = format!("[storage]\nbackend = \"db\"\nencryption_key = \"{}\"\n", key);
    std::fs::write(&cfg_path, &original).unwrap();

    let db = test_db();
    let mut config = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(config.storage_encryption_key().as_deref(), Some(key));
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::Ready);
    assert_eq!(config.storage_encryption_key().as_deref(), Some(key));
    // File untouched.
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
}

#[test]
fn empty_key_in_file_is_replaced() {
    without_env_key();
    let dir = scratch_dir("empty-key");
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, "[storage]\nbackend = \"db\"\nencryption_key = \"\"\n").unwrap();

    let mut config = Config::load(Some(path_str(&cfg_path)));
    // An empty string key counts as "no key".
    assert!(config.storage_encryption_key().is_none());

    let db = test_db();
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::Ready);

    let key = config.storage_encryption_key().unwrap();
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    // The empty entry is replaced, not duplicated (a duplicate key in one
    // section is a TOML error).
    assert_eq!(file.matches("encryption_key").count(), 1);
    assert!(file.contains(&format!("encryption_key = \"{}\"", key)));

    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(
        reloaded.storage_encryption_key().as_deref(),
        Some(key.as_str())
    );
}

#[test]
fn vault_backend_skips_generation() {
    without_env_key();
    let dir = scratch_dir("vault");
    let cfg_path = dir.join("config.toml");
    let original = "[storage]\nbackend = \"vault\"\n";
    std::fs::write(&cfg_path, original).unwrap();

    // Even a store holding encrypted credentials does not block the vault
    // backend: credentials live in Vault, not the DB.
    let db = test_db();
    insert_credential(&db);

    let mut config = Config::load(Some(path_str(&cfg_path)));
    let outcome = ensure_db_storage_key(&mut config, &db, &path_str(&cfg_path));
    assert_eq!(outcome, StorageKeyGuard::Ready);
    assert!(config.storage_encryption_key().is_none());
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
}

#[test]
fn generated_key_is_random_64_hex() {
    let a = generate_encryption_key();
    let b = generate_encryption_key();
    assert_eq!(a.len(), 64);
    assert_eq!(b.len(), 64);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(a, b);
}

#[test]
fn persist_creates_file_and_section_when_absent() {
    let dir = scratch_dir("persist");
    let cfg_path = dir.join("config.toml");
    let key = generate_encryption_key();
    persist_storage_encryption_key(&path_str(&cfg_path), &key).unwrap();
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert_eq!(file, format!("[storage]\nencryption_key = \"{}\"\n", key));
}
