//! Regression tests for first-run storage key generation (persea#97): a
//! fresh store with no configured key gets one generated and persisted;
//! stores that already hold encrypted credentials refuse to start.
//!
//! Mirrors the harness in tests/api_handler_tests.rs: in-memory SQLite via
//! `db::init_db(":memory:")`.

use persea::config::{
    ensure_db_storage_key, ensure_storage_encryption_key, generate_encryption_key,
    persist_storage_encryption_key, read_storage_encryption_key, storage_section_for, Config,
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
    let dir = std::env::temp_dir().join(format!(
        "persea-storage-key-{tag}-{}-{n}",
        std::process::id()
    ));
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

    let key = config
        .storage_encryption_key()
        .expect("key installed on config");
    assert_eq!(key.len(), 64);
    assert!(key.chars().all(|c| c.is_ascii_hexdigit()));

    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert!(file.contains("[storage]"));
    assert!(file.contains(&format!("encryption_key = \"{}\"", key)));

    // A restart picks the persisted key back up.
    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(
        reloaded.storage_encryption_key().as_deref(),
        Some(key.as_str())
    );
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
    let original = format!(
        "[storage]\nbackend = \"db\"\nencryption_key = \"{}\"\n",
        key
    );
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
    std::fs::write(
        &cfg_path,
        "[storage]\nbackend = \"db\"\nencryption_key = \"\"\n",
    )
    .unwrap();

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

// ── persea#271: one storage-key bootstrap for Rust and shell ───────────────

/// persea#271: an indented `encryption_key` inside `[storage]` is valid
/// TOML. The old shell bootstraps grepped column 0 only, saw no key, and
/// injected a second one — a hard TOML parse error that crash-looped the
/// container on first boot. The single implementation must see the key and
/// leave the file untouched byte-for-byte.
#[test]
fn indented_key_is_seen_and_preserved_exactly_once() {
    without_env_key();
    let dir = scratch_dir("indented");
    let cfg_path = dir.join("config.toml");
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let original = format!(
        "listen_addr = \"127.0.0.1:8089\"\n\n[storage]\n  backend = \"db\"\n  encryption_key = \"{}\"\n",
        key
    );
    std::fs::write(&cfg_path, &original).unwrap();

    // One run: the key is reported, the file is untouched, and exactly one
    // encryption_key line remains.
    let ensured = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    assert_eq!(ensured, key);
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert_eq!(file.matches("encryption_key").count(), 1);

    // A second run is idempotent.
    let again = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    assert_eq!(again, key);
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);

    // The config loads and the key is picked up: the old crash-loop ended
    // in a hard TOML parse error, which this must not reproduce.
    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(reloaded.storage_encryption_key().as_deref(), Some(key));
}

/// A pre-existing key is preserved byte-for-byte: the file is not rewritten
/// at all when it already holds a usable key.
#[test]
fn ensure_preserves_existing_key_byte_for_byte() {
    without_env_key();
    let dir = scratch_dir("preserve");
    let cfg_path = dir.join("config.toml");
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let original = format!("[storage]\nencryption_key = \"{}\"\n", key);
    std::fs::write(&cfg_path, &original).unwrap();

    let ensured = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    assert_eq!(ensured, key);
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
    assert_eq!(
        read_storage_encryption_key(path_str(&cfg_path)).as_deref(),
        Some(key)
    );
}

/// The file ends up owner-only (0600) after a write, both when the ensure
/// pass creates it and when it rewrites an existing world-readable one.
#[cfg(unix)]
#[test]
fn written_config_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    without_env_key();

    let dir = scratch_dir("mode-fresh");
    let cfg_path = dir.join("config.toml");
    ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);

    let dir = scratch_dir("mode-rewrite");
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, "listen_addr = \"127.0.0.1:8089\"\n").unwrap();
    std::fs::set_permissions(&cfg_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

/// A config left with duplicate `encryption_key` entries (the damage the
/// old column-0 grep bootstraps caused) is repaired to exactly one line and
/// valid TOML again.
#[test]
fn duplicate_keys_left_by_old_installers_are_repaired() {
    without_env_key();
    let dir = scratch_dir("dedupe");
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        "[storage]\nbackend = \"db\"\nencryption_key = \"a\"\n  encryption_key = \"b\"\n",
    )
    .unwrap();

    let ensured = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert_eq!(file.matches("encryption_key").count(), 1);
    assert!(file.contains(&format!("encryption_key = \"{}\"", ensured)));
    assert!(file.contains("backend = \"db\""));

    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(
        reloaded.storage_encryption_key().as_deref(),
        Some(ensured.as_str())
    );
}

/// An empty `encryption_key` counts as no key: it is replaced with a
/// generated one instead of duplicated.
#[test]
fn empty_key_is_replaced_with_a_generated_one() {
    without_env_key();
    let dir = scratch_dir("ensure-empty");
    let cfg_path = dir.join("config.toml");
    std::fs::write(
        &cfg_path,
        "[storage]\nbackend = \"db\"\nencryption_key = \"\"\n",
    )
    .unwrap();

    let ensured = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap();
    assert_eq!(ensured.len(), 64);
    let file = std::fs::read_to_string(&cfg_path).unwrap();
    assert_eq!(file.matches("encryption_key").count(), 1);
    let reloaded = Config::load(Some(path_str(&cfg_path)));
    assert_eq!(
        reloaded.storage_encryption_key().as_deref(),
        Some(ensured.as_str())
    );
}

/// `storage` defined as an inline table cannot be edited by the line-based
/// writer: the ensure pass fails closed instead of appending a second
/// definition of the table.
#[test]
fn inline_storage_table_fails_closed_without_corruption() {
    without_env_key();
    let dir = scratch_dir("inline");
    let cfg_path = dir.join("config.toml");
    let original = "storage = { backend = \"db\" }\nlisten_addr = \"127.0.0.1:8089\"\n";
    std::fs::write(&cfg_path, &original).unwrap();

    let err = ensure_storage_encryption_key(path_str(&cfg_path)).unwrap_err();
    assert!(err.to_string().contains("inline"));
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), original);
}

/// The setup wizard's generated section preserves an existing section
/// verbatim — including an indented key and other storage settings — so an
/// admin-set key survives the wizard's full-file rewrite.
#[test]
fn storage_section_preserves_existing_section() {
    let dir = scratch_dir("section");
    let cfg_path = dir.join("config.toml");
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    std::fs::write(
        &cfg_path,
        format!(
            "listen_addr = \"127.0.0.1:8089\"\n\n[storage]\n  backend = \"db\"\n  encryption_key = \"{}\"\n\n[recording]\npath = \"./recordings\"\n",
            key
        ),
    )
    .unwrap();

    let section = storage_section_for(path_str(&cfg_path));
    assert!(section.contains(&format!("encryption_key = \"{}\"", key)));
    assert!(section.contains("backend = \"db\""));
    assert_eq!(section.matches("encryption_key").count(), 1);
    assert!(!section.contains("[recording]"));
}

/// Without a `[storage]` section the wizard's section is generated fresh
/// with a new key.
#[test]
fn storage_section_generated_when_absent() {
    let dir = scratch_dir("section-none");
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, "listen_addr = \"127.0.0.1:8089\"\n").unwrap();

    let section = storage_section_for(path_str(&cfg_path));
    assert!(section.starts_with("[storage]\n"));
    assert_eq!(section.matches("encryption_key").count(), 1);
    let line = section.lines().nth(1).unwrap().trim();
    let key = line
        .strip_prefix("encryption_key = \"")
        .unwrap()
        .strip_suffix('"')
        .unwrap();
    assert_eq!(key.len(), 64);
}

/// The `ensure-storage-key` CLI subcommand runs before any config load or
/// database open (the Docker entrypoint calls it ahead of the first-run
/// admin bootstrap) and never prints the key.
#[test]
fn cli_subcommand_ensures_key_without_touching_the_db() {
    without_env_key();
    let dir = scratch_dir("cli");
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, "listen_addr = \"127.0.0.1:8089\"\n").unwrap();

    let out = std::process::Command::new(env!("CARGO_BIN_EXE_persea"))
        .args(["--config", path_str(&cfg_path), "ensure-storage-key"])
        .env_remove("RUSTGUAC_CONFIG")
        .env_remove("PERSEA_STORAGE_KEY")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let key = read_storage_encryption_key(path_str(&cfg_path)).expect("subcommand persisted a key");
    assert_eq!(key.len(), 64);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stdout.contains(&key), "key leaked to stdout");
    assert!(!stderr.contains(&key), "key leaked to stderr");

    // Idempotent re-run: preserved, file unchanged.
    let before = std::fs::read_to_string(&cfg_path).unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_persea"))
        .args(["--config", path_str(&cfg_path), "ensure-storage-key"])
        .env_remove("RUSTGUAC_CONFIG")
        .env_remove("PERSEA_STORAGE_KEY")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("preserved"));
    assert_eq!(std::fs::read_to_string(&cfg_path).unwrap(), before);
}
