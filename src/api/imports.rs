//! Address book CSV import endpoints.
//!
//! `POST /api/addressbook/import` ingests connection rows into the DB-backed
//! address book (folder hierarchy auto-created) in one of three modes:
//! `create` (legacy — existing entries skipped), `upsert` (default — create
//! missing, update changed, skip completely-identical rows), or `update`
//! (only existing rows; missing rows become errors). The stored identifier
//! of each row is `slugify(name)`; the friendly `name` text becomes the
//! entry's `display_name`. `GET /api/addressbook/import-template` serves a
//! downloadable CSV template (optional settings columns plus custom-field
//! columns when any are configured).

use super::address_book::log_ab_event;
use super::StorageKey;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::csv_import::{self, validate_row};
use crate::db::{self, Db};
use crate::error::AppError;
use crate::slugify::slugify;
use axum::extract::{ConnectInfo, Query};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;

/// Resolve the credential encryption key: the startup-resolved `StorageKey`
/// extension takes precedence; the `PERSEA_STORAGE_KEY` env var is re-checked
/// for callers that run without the extension (e.g. handler tests).
/// Mirrors the private helper in `src/api/address_book.rs`.
fn resolve_encryption_key(storage_key: Option<&StorageKey>) -> String {
    storage_key
        .and_then(|k| k.0.clone())
        .or_else(|| {
            std::env::var("PERSEA_STORAGE_KEY")
                .ok()
                .filter(|k| !k.is_empty())
        })
        .unwrap_or_default()
}

/// Check if the DB storage backend is available (address book tables exist).
fn is_db_storage_available(db: &Db) -> bool {
    db::list_ab_folders(db, None).is_ok()
}

fn default_scope() -> String {
    "shared".into()
}

fn default_mode() -> String {
    "upsert".into()
}

/// Deserialize custom field values from either a JSON map
/// (`{"Environment": "prod"}`) or a sequence of `[name, value]` pairs — the
/// wire shape the connections-page CSV importer sends (it mirrors the
/// trailing CSV columns one-to-one).
fn deserialize_custom_fields<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct CustomFieldsVisitor;

    impl<'de> Visitor<'de> for CustomFieldsVisitor {
        type Value = HashMap<String, String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter
                .write_str("a map of field names to values, or a sequence of [name, value] pairs")
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((key, value)) = map.next_entry::<String, String>()? {
                out.insert(key, value);
            }
            Ok(out)
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = HashMap::new();
            while let Some((key, value)) = seq.next_element::<(String, String)>()? {
                out.insert(key, value);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(CustomFieldsVisitor)
}

/// One connection row from the import request body.
#[derive(Debug, Clone, Deserialize)]
/// One connection row from the import request body.
///
/// Passwords are stored encrypted when a storage key is configured;
/// without one they are dropped and counted in the response.
pub struct ImportRow {
    /// Friendly name; the stored identifier is `slugify(name)`.
    pub name: String,
    /// Connection protocol: ssh, rdp, vnc, spice, web, vdi, proxmox.
    pub protocol: String,
    /// Target host; required unless the protocol is `web`.
    #[serde(default)]
    pub hostname: String,
    /// Target port; defaults per protocol when absent.
    #[serde(default)]
    pub port: Option<u16>,
    /// Login username.
    #[serde(default)]
    pub username: String,
    /// Login password. Empty cells request no credential change on
    /// existing entries.
    #[serde(default)]
    pub password: String,
    /// Destination folder path; missing levels are created.
    #[serde(default)]
    pub folder: String,
    /// Optional explicit display name (JSON API compat). CSV imports always
    /// leave this empty — the `name` column IS the friendly name.
    #[serde(default)]
    pub display_name: String,
    /// Group names allowed to use the entry.
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    /// Free-text description stored in `protocol_config`.
    #[serde(default)]
    pub description: String,
    /// NTLM/Kerberos domain; `protocol_config.domain`. `None` = not set
    /// (keeps the stored value on update).
    #[serde(default)]
    pub domain: Option<String>,
    /// RDP security mode (`nla`, `any`, ...); `protocol_config.security`.
    #[serde(default)]
    pub security: Option<String>,
    /// Skip TLS certificate verification; `protocol_config.ignore_cert`.
    #[serde(default)]
    pub ignore_cert: Option<bool>,
    /// RDP color depth in bits; `protocol_config.color_depth`.
    #[serde(default)]
    pub color_depth: Option<u8>,
    /// RemoteApp program path; `protocol_config.remote_app`.
    #[serde(default)]
    pub remote_app: Option<String>,
    /// RDP GFX pipeline; `protocol_config.enable_gfx`.
    #[serde(default)]
    pub enable_gfx: Option<bool>,
    /// RDP drive redirection; `protocol_config.enable_drive`.
    #[serde(default)]
    pub enable_drive: Option<bool>,
    /// Disable clipboard copy; `protocol_config.disable_copy`.
    #[serde(default)]
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste; `protocol_config.disable_paste`.
    #[serde(default)]
    pub disable_paste: Option<bool>,
    /// RDP auth package (`ntlm`, `kerberos`); `protocol_config.auth_pkg`.
    #[serde(default)]
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL; `protocol_config.kdc_url`.
    #[serde(default)]
    pub kdc_url: Option<String>,
    /// Prompt for credentials on connect; `protocol_config.prompt_credentials`.
    #[serde(default)]
    pub prompt_credentials: Option<bool>,
    /// SSH private key material, stored as a credential like `password`
    /// (encrypted when a storage key exists; dropped + counted when not).
    /// `None`/empty = not set (keeps the stored value on update).
    #[serde(default)]
    pub private_key: Option<String>,
    /// Custom field values (field name → value), same shape as the
    /// connections API's per-entry `protocol_config.custom_fields`. Accepts
    /// a map or `[[name, value], ...]` pairs (the CSV-import UI shape).
    #[serde(default, deserialize_with = "deserialize_custom_fields")]
    pub custom_fields: HashMap<String, String>,
}

/// Normalize an entry identifier for near-duplicate detection: lowercase,
/// alphanumerics only. Applied to the slugified names, so "web-server-01",
/// "Web Server 01" and "webserver01" all collapse to the same key.
fn fuzzy_key(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

#[derive(Debug, Deserialize)]
/// Body of `POST /api/addressbook/import` (JSON path).
///
/// Raw `text/csv` bodies are also accepted; for those the scope always
/// defaults to `shared` and the mode travels in the query string.
pub struct ImportRequest {
    /// Address-book scope to import into (`shared` default, `instance`).
    #[serde(default = "default_scope")]
    pub scope: String,
    /// Import mode: `create` (legacy — skip existing), `upsert` (default —
    /// create missing, update changed, skip identical), `update` (only
    /// existing rows; missing rows become errors).
    /// Import mode override; falls back to the `?mode=` query param.
    #[serde(default)]
    pub mode: Option<String>,
    /// Connection rows to import.
    pub rows: Vec<ImportRow>,
}

/// `?mode=` query parameter. Raw-CSV bodies have no JSON envelope, so the
/// mode travels in the query string for that path.
#[derive(Debug, Deserialize)]
pub struct ModeQuery {
    /// Import mode for raw-CSV bodies: create, upsert (default), update.
    #[serde(default = "default_mode")]
    pub mode: String,
}

/// Extract the configured custom field NAMES from the stored settings map.
fn custom_field_names(stored: &HashMap<String, String>) -> Vec<String> {
    super::settings::custom_fields_value(stored)
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|f| f.get("name").and_then(|n| n.as_str()))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Normalize a custom-field value map for storage and comparison: empty
/// values are dropped, values trimmed.
fn normalized_custom_fields(custom_fields: &HashMap<String, String>) -> HashMap<String, String> {
    custom_fields
        .iter()
        .filter(|(_, v)| !v.trim().is_empty())
        .map(|(k, v)| (k.clone(), v.trim().to_string()))
        .collect()
}

/// The optional-settings entries of a row: only keys with a set (non-blank)
/// value are included, in the `protocol_config` key space.
fn row_settings_map(row: &ImportRow) -> serde_json::Map<String, serde_json::Value> {
    let mut settings = serde_json::Map::new();
    for (key, value) in [
        ("domain", opt_setting_str(row.domain.as_deref())),
        ("security", opt_setting_str(row.security.as_deref())),
        ("remote_app", opt_setting_str(row.remote_app.as_deref())),
        ("auth_pkg", opt_setting_str(row.auth_pkg.as_deref())),
        ("kdc_url", opt_setting_str(row.kdc_url.as_deref())),
        ("ignore_cert", opt_setting_bool(row.ignore_cert)),
        ("enable_gfx", opt_setting_bool(row.enable_gfx)),
        ("enable_drive", opt_setting_bool(row.enable_drive)),
        ("disable_copy", opt_setting_bool(row.disable_copy)),
        ("disable_paste", opt_setting_bool(row.disable_paste)),
        (
            "prompt_credentials",
            opt_setting_bool(row.prompt_credentials),
        ),
        ("color_depth", row.color_depth.map(|v| json!(v))),
    ] {
        if let Some(value) = value {
            settings.insert(key.into(), value);
        }
    }
    settings
}

/// `Some` when the optional string setting is set and non-blank.
fn opt_setting_str(value: Option<&str>) -> Option<serde_json::Value> {
    value
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| json!(v))
}

/// `Some` when the optional bool setting is present.
fn opt_setting_bool(value: Option<bool>) -> Option<serde_json::Value> {
    value.map(|v| json!(v))
}

/// Apply a row's metadata onto a `protocol_config` map: `description` and
/// custom fields replace the stored entries (existing behavior), optional
/// settings only overwrite keys the row sets (blank = keep stored).
fn apply_row_metadata(
    cfg: &mut serde_json::Map<String, serde_json::Value>,
    description: &str,
    custom_fields: &HashMap<String, String>,
    row: &ImportRow,
) {
    cfg.remove("description");
    cfg.remove("custom_fields");
    if !description.is_empty() {
        cfg.insert("description".into(), json!(description));
    }
    let fields = normalized_custom_fields(custom_fields);
    if !fields.is_empty() {
        cfg.insert("custom_fields".into(), json!(fields));
    }
    for (key, value) in row_settings_map(row) {
        cfg.insert(key, value);
    }
}

/// Build the `protocol_config` JSON for a new row: non-credential metadata
/// (description + custom field values + optional settings), same shape as
/// the connections API.
fn row_protocol_config(
    description: &str,
    custom_fields: &HashMap<String, String>,
    row: &ImportRow,
) -> String {
    let mut meta = serde_json::Map::new();
    apply_row_metadata(&mut meta, description, custom_fields, row);
    serde_json::to_string(&meta).unwrap_or_else(|_| "{}".into())
}

/// The stored display name for a row: an explicit override (JSON API) wins,
/// otherwise the friendly name from the `name` column.
fn effective_display_name(friendly_name: &str, display_name_override: &str) -> String {
    if display_name_override.trim().is_empty() {
        friendly_name.to_string()
    } else {
        display_name_override.trim().to_string()
    }
}

/// Encrypt + store a row's credential (password or private key) for an
/// entry. An empty value is a no-op (`true`) — callers keep the existing
/// credential, never wipe it. Without an encryption key the value is dropped
/// and counted. Returns `false` when a credential error was pushed to
/// `errors`.
#[allow(clippy::too_many_arguments)]
fn store_row_credential(
    database: &Db,
    entry_id: i64,
    credential_type: &str,
    value: &str,
    encryption_key: &str,
    row_index: usize,
    credentials_dropped: &mut usize,
    errors: &mut Vec<serde_json::Value>,
) -> bool {
    if value.is_empty() {
        return true;
    }
    if encryption_key.is_empty() {
        *credentials_dropped += 1;
        return true;
    }
    let key = match crate::crypto::EncryptionKey::from_hex(encryption_key) {
        Ok(k) => k,
        Err(e) => {
            errors.push(json!({"row": row_index, "error": format!("failed to parse encryption key: {}", e)}));
            return false;
        }
    };
    let encrypted = match crate::crypto::encrypt_value(&key, value) {
        Ok(e) => e,
        Err(e) => {
            errors.push(json!({"row": row_index, "error": format!(
                "failed to encrypt {}: {}",
                credential_type, e
            )}));
            return false;
        }
    };
    if let Err(e) = db::store_ab_credential(database, entry_id, credential_type, &encrypted) {
        errors.push(json!({"row": row_index, "error": format!(
            "failed to store {}: {}",
            credential_type, e
        )}));
        return false;
    }
    true
}

/// Outcome of inserting a new entry row.
#[derive(Debug, PartialEq, Eq)]
enum InsertOutcome {
    /// Row written — count as imported.
    Inserted,
    /// A concurrent writer beat us to the slug — count as skipped.
    SkippedRace,
    /// Validation/DB error pushed to `errors` — count nothing.
    Failed,
}

/// Insert a new entry for an import row. On credential failure the
/// just-created entry is rolled back so a corrected re-import is possible
/// (an orphan row would otherwise be skipped as a duplicate forever).
#[allow(clippy::too_many_arguments)]
fn insert_new_row(
    database: &Db,
    folder_id: i64,
    slug: &str,
    friendly_name: &str,
    display_name_override: &str,
    row: &ImportRow,
    protocol: &str,
    hostname: &str,
    encryption_key: &str,
    row_index: usize,
    passwords_dropped: &mut usize,
    errors: &mut Vec<serde_json::Value>,
) -> InsertOutcome {
    let display_name = effective_display_name(friendly_name, display_name_override);
    let username = row.username.trim().to_string();
    let description = row.description.trim().to_string();
    let allowed_groups = row
        .allowed_groups
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    let protocol_config = row_protocol_config(&description, &row.custom_fields, row);

    let entry_id = match db::create_ab_entry(
        database,
        folder_id,
        slug,
        &display_name,
        protocol,
        hostname,
        row.port,
        &username,
        &protocol_config,
        &allowed_groups,
    ) {
        Ok(id) => id,
        Err(e) => {
            if e.to_string().contains("UNIQUE constraint") {
                return InsertOutcome::SkippedRace;
            }
            errors.push(json!({"row": row_index, "error": e.to_string()}));
            return InsertOutcome::Failed;
        }
    };
    let credentials_ok = store_row_credential(
        database,
        entry_id,
        "password",
        &row.password,
        encryption_key,
        row_index,
        passwords_dropped,
        errors,
    ) && store_row_credential(
        database,
        entry_id,
        "private_key",
        row.private_key.as_deref().unwrap_or(""),
        encryption_key,
        row_index,
        passwords_dropped,
        errors,
    );
    if !credentials_ok {
        let _ = db::delete_ab_entry(database, entry_id);
        return InsertOutcome::Failed;
    }
    InsertOutcome::Inserted
}

/// Apply an import row to an existing entry (metadata always; password only
/// when non-empty — empty keeps the existing credential). Returns `false`
/// when an error was pushed to `errors`.
#[allow(clippy::too_many_arguments)]
fn update_existing_row(
    database: &Db,
    entry: &db::AbEntry,
    row: &ImportRow,
    friendly_name: &str,
    display_name_override: &str,
    protocol: &str,
    hostname: &str,
    encryption_key: &str,
    row_index: usize,
    passwords_dropped: &mut usize,
    errors: &mut Vec<serde_json::Value>,
) -> bool {
    let display_name = effective_display_name(friendly_name, display_name_override);
    let username = row.username.trim().to_string();
    let description = row.description.trim().to_string();
    let allowed_groups = row
        .allowed_groups
        .iter()
        .map(|g| g.trim())
        .filter(|g| !g.is_empty())
        .collect::<Vec<_>>()
        .join(",");
    // Merge onto the stored config: description/custom fields are replaced,
    // optional settings only overwrite keys the row sets (blank = keep).
    let mut cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config)
        .unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new()));
    if !cfg.is_object() {
        cfg = serde_json::Value::Object(serde_json::Map::new());
    }
    apply_row_metadata(
        cfg.as_object_mut()
            .expect("config normalized to an object above"),
        &description,
        &row.custom_fields,
        row,
    );
    let protocol_config = cfg.to_string();

    if let Err(e) = db::update_ab_entry(
        database,
        entry.id,
        &display_name,
        protocol,
        hostname,
        row.port,
        &username,
        &protocol_config,
        &allowed_groups,
    ) {
        errors.push(json!({"row": row_index, "error": e.to_string()}));
        return false;
    }
    if !store_row_credential(
        database,
        entry.id,
        "password",
        &row.password,
        encryption_key,
        row_index,
        passwords_dropped,
        errors,
    ) {
        return false;
    }
    store_row_credential(
        database,
        entry.id,
        "private_key",
        row.private_key.as_deref().unwrap_or(""),
        encryption_key,
        row_index,
        passwords_dropped,
        errors,
    )
}

/// "Completely identical": every importable field of the row matches the
/// stored entry — protocol, hostname, port, username, description,
/// allowed_groups, custom fields, and the stored credential plaintext
/// (compared post-decrypt). An empty password cell requests no change, so it
/// always matches whatever is stored.
#[allow(clippy::too_many_arguments)]
fn row_matches_entry(
    database: &Db,
    entry: &db::AbEntry,
    row: &ImportRow,
    protocol: &str,
    hostname: &str,
    encryption_key: &str,
) -> bool {
    if entry.protocol != protocol
        || entry.hostname != hostname
        || entry.port != row.port
        || entry.username != row.username.trim()
        || entry.allowed_groups
            != row
                .allowed_groups
                .iter()
                .map(|g| g.trim())
                .filter(|g| !g.is_empty())
                .collect::<Vec<_>>()
                .join(",")
    {
        return false;
    }

    let cfg: serde_json::Value = serde_json::from_str(&entry.protocol_config).unwrap_or_default();
    if cfg
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        != row.description.trim()
    {
        return false;
    }
    let stored_fields: HashMap<String, String> = cfg
        .get("custom_fields")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    if stored_fields != normalized_custom_fields(&row.custom_fields) {
        return false;
    }
    // Optional settings: every key the row sets must match the stored
    // config; keys the row leaves blank impose no constraint.
    for (key, value) in row_settings_map(row) {
        if cfg.get(&key) != Some(&value) {
            return false;
        }
    }

    if !row.password.is_empty() {
        let Ok(cred) = db::get_ab_credential(database, entry.id, "password") else {
            return false;
        };
        if encryption_key.is_empty() {
            return false;
        }
        let Ok(key) = crate::crypto::EncryptionKey::from_hex(encryption_key) else {
            return false;
        };
        match crate::crypto::decrypt_value(&key, &cred.credential_data) {
            Ok(plain) if plain == row.password => {}
            _ => return false,
        }
    }
    match row.private_key.as_deref().filter(|k| !k.is_empty()) {
        None => true,
        Some(private_key) => {
            let Ok(cred) = db::get_ab_credential(database, entry.id, "private_key") else {
                return false;
            };
            if encryption_key.is_empty() {
                return false;
            }
            let Ok(key) = crate::crypto::EncryptionKey::from_hex(encryption_key) else {
                return false;
            };
            match crate::crypto::decrypt_value(&key, &cred.credential_data) {
                Ok(plain) => plain == private_key,
                Err(_) => false,
            }
        }
    }
}

/// Ensure a folder path hierarchy exists under `scope`, creating each missing
/// level, and return the leaf folder ID. An empty path resolves to (and if
/// needed creates) the scope-root folder named `""`.
fn ensure_folder(db: &Db, scope: &str, path: &str) -> Result<i64, AppError> {
    let mut current = String::new();
    let mut leaf_id: Option<i64> = None;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
        // Segment sanity (T09 audit): `..`/`.` segments would land in the
        // DB as-is (URL path segments, RBAC connection ids, Vault keys) and
        // control characters are never legitimate folder names. Vault mode
        // already rejects these at entry-write time; this keeps DB mode
        // consistent instead of silently storing traversal-shaped names.
        if segment == "." || segment == ".." {
            return Err(AppError::Validation(format!(
                "invalid folder path '{path}': '.' and '..' segments are not allowed"
            )));
        }
        if segment.chars().any(|c| c.is_control()) {
            return Err(AppError::Validation(format!(
                "invalid folder path '{path}': control characters are not allowed"
            )));
        }
        if !current.is_empty() {
            current.push('/');
        }
        current.push_str(segment);
        leaf_id = Some(get_or_create_folder(db, scope, &current)?);
    }
    match leaf_id {
        Some(id) => Ok(id),
        None => get_or_create_folder(db, scope, ""),
    }
}

/// Look up a folder by (scope, name), creating it when missing.
fn get_or_create_folder(db: &Db, scope: &str, name: &str) -> Result<i64, AppError> {
    match db::get_ab_folder(db, scope, name) {
        Ok(folder) => Ok(folder.id),
        Err(e) if is_no_rows(&e) => db::create_ab_folder(db, scope, name, "", "", false)
            .map_err(|e| AppError::Internal(format!("failed to create folder: {}", e))),
        Err(e) => Err(AppError::Internal(format!("folder lookup failed: {}", e))),
    }
}

/// True when the rusqlite error means "no matching row".
fn is_no_rows(e: &rusqlite::Error) -> bool {
    let msg = e.to_string();
    msg.contains("Query returned no rows") || msg.contains("QueryReturnedNoRows")
}

/// Import address book connections from a JSON or raw-CSV body.
///
/// Admin only. Each row is validated (`name` required and slugifiable,
/// `protocol` in {ssh, rdp, vnc, spice, web, vdi, proxmox}, `hostname`
/// required unless the protocol is `web`). The stored identifier is
/// `slugify(name)`; the friendly `name` becomes `display_name`.
///
/// Mode (JSON `mode` field, or `?mode=` query param for raw CSV bodies;
/// default `upsert`):
/// - `create`: legacy behavior — existing entries skipped, near-duplicates
///   reported.
/// - `upsert`: missing → create; existing but identical (all importable
///   fields incl. decrypted password) → unchanged; existing and different →
///   update (password only when non-empty).
/// - `update`: only existing rows are touched; missing rows become errors.
///
/// Passwords are stored encrypted when a storage key is available; without
/// one they are dropped and counted. The response reports `imported`,
/// `updated`, `unchanged`, `skipped`, `passwords_dropped` and `errors`.
#[allow(clippy::too_many_arguments)]
pub async fn import_csv(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    storage_key: Option<Extension<StorageKey>>,
    headers_2: axum::http::HeaderMap,
    Query(query): Query<ModeQuery>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    let admin_email = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("admin") => id.display_name().to_string(),
        _ => return Err(AppError::Forbidden("admin role required".into())),
    };

    if !is_db_storage_available(&database) {
        return Err(AppError::Internal(
            "address book unavailable: no storage backend configured".into(),
        ));
    }

    // Accept either the JSON contract (`{"scope": ..., "mode": ..., "rows": [...]}`)
    // or a raw `text/csv` body (single source of truth: the CSV parser in
    // src/csv_import.rs is the same code the template generator uses).
    let mut csv_parser_report: Option<Vec<csv_import::CsvError>> = None;
    let mut csv_parser_skipped = 0usize;
    let req: ImportRequest = if headers_2
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.split(';')
                .next()
                .map(|m| m.trim().eq_ignore_ascii_case("text/csv"))
                .unwrap_or(false)
        })
        .unwrap_or(false)
    {
        // Trailing header columns must match the configured custom field
        // names exactly — the definitions come from the settings store.
        let stored = super::settings::read_all_settings(&database)?;
        let custom_defs = custom_field_names(&stored);
        let csv_text = String::from_utf8_lossy(&body).to_string();
        let parsed = csv_import::parse_rows(&csv_text, &custom_defs)
            .map_err(|e| AppError::Validation(e.message))?;
        // Parser-level row errors (invalid ports, malformed rows) must not
        // vanish — they are surfaced alongside handler-level errors below.
        csv_parser_report = Some(parsed.errors);
        csv_parser_skipped = parsed.skipped.len();
        ImportRequest {
            scope: String::new(),
            mode: None,
            rows: parsed
                .rows
                .into_iter()
                .map(|r| ImportRow {
                    name: r.name,
                    protocol: r.protocol,
                    hostname: r.hostname,
                    port: r.port,
                    username: r.username,
                    password: r.password,
                    folder: r.folder,
                    display_name: String::new(),
                    allowed_groups: r.allowed_groups,
                    description: r.description,
                    domain: r.settings.domain,
                    security: r.settings.security,
                    ignore_cert: r.settings.ignore_cert,
                    color_depth: r.settings.color_depth,
                    remote_app: r.settings.remote_app,
                    enable_gfx: r.settings.enable_gfx,
                    enable_drive: r.settings.enable_drive,
                    disable_copy: r.settings.disable_copy,
                    disable_paste: r.settings.disable_paste,
                    auth_pkg: r.settings.auth_pkg,
                    kdc_url: r.settings.kdc_url,
                    prompt_credentials: r.settings.prompt_credentials,
                    private_key: r.private_key,
                    custom_fields: r.custom_fields.into_iter().collect(),
                })
                .collect(),
        }
    } else {
        serde_json::from_slice::<ImportRequest>(&body)
            .map_err(|e| AppError::Validation(format!("invalid JSON body: {}", e)))?
    };

    let scope = if req.scope.trim().is_empty() {
        default_scope()
    } else {
        req.scope.trim().to_string()
    };
    let mode = req.mode.clone().unwrap_or(query.mode);
    let mode = mode.trim().to_ascii_lowercase();
    if !matches!(mode.as_str(), "create" | "upsert" | "update") {
        return Err(AppError::Validation(format!(
            "invalid mode '{}' (must be one of: create, upsert, update)",
            mode
        )));
    }
    let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));

    let mut imported = 0usize;
    let mut updated = 0usize;
    let mut unchanged = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<serde_json::Value> = Vec::new();
    let mut passwords_dropped = 0usize;
    if let Some(report) = csv_parser_report {
        for e in report {
            errors.push(json!({"row": e.row, "error": e.message}));
        }
    }
    skipped += csv_parser_skipped;

    for (idx, row) in req.rows.iter().enumerate() {
        let row_index = idx + 1;
        let friendly_name = row.name.trim().to_string();
        let protocol = row.protocol.trim().to_ascii_lowercase();
        let hostname = row.hostname.trim().to_string();
        let folder = csv_import::normalize_folder(&row.folder);
        let slug = slugify(&friendly_name);

        if let Err(msg) = validate_row(&friendly_name, &protocol, &hostname, row.port) {
            errors.push(json!({"row": row_index, "error": msg}));
            continue;
        }
        if slug.is_empty() {
            errors.push(json!({"row": row_index, "error": format!(
                "'{}' contains no usable characters for the entry identifier — use at least one letter, digit, dot, underscore or dash",
                friendly_name
            )}));
            continue;
        }
        if slug.len() > 64 {
            errors.push(json!({"row": row_index, "error": format!(
                "'{}' is too long — the connection identifier may be at most 64 characters (got {})",
                friendly_name,
                slug.len()
            )}));
            continue;
        }

        let folder_id = match ensure_folder(&database, &scope, &folder) {
            Ok(id) => id,
            Err(e) => {
                errors.push(json!({"row": row_index, "error": e.to_string()}));
                continue;
            }
        };

        let existing = db::get_ab_entry(&database, folder_id, &slug);
        let exists = existing.is_ok();

        // Near-duplicate reporting guards row CREATION only (create + upsert):
        // a row whose slug is fuzzy-equal to an existing entry's slug is
        // almost certainly a typo — surface it instead of importing a twin.
        if !exists && mode != "update" {
            if let Ok(entries) = db::list_ab_entries(&database, folder_id) {
                if let Some(hit) = entries
                    .iter()
                    .find(|e| fuzzy_key(&e.name) == fuzzy_key(&slug))
                {
                    errors.push(json!({
                        "row": row_index,
                        "error": format!(
                            "'{}' is a near-duplicate of existing entry '{}' (skipped)",
                            friendly_name, hit.name
                        ),
                    }));
                    skipped += 1;
                    continue;
                }
            }
        }

        if mode == "update" {
            let entry = match existing {
                Ok(e) => e,
                Err(_) => {
                    errors.push(json!({"row": row_index, "error": format!(
                        "no existing entry '{}' to update — use mode 'upsert' to create missing rows",
                        slug
                    )}));
                    continue;
                }
            };
            if update_existing_row(
                &database,
                &entry,
                row,
                &friendly_name,
                &row.display_name,
                &protocol,
                &hostname,
                &encryption_key,
                row_index,
                &mut passwords_dropped,
                &mut errors,
            ) {
                updated += 1;
            }
            continue;
        }

        if exists {
            if mode == "create" {
                // Legacy create-mode behavior: existing entries are skipped.
                skipped += 1;
                continue;
            }
            // upsert: skip rows that are completely identical, update the rest.
            let entry = existing.unwrap();
            if row_matches_entry(
                &database,
                &entry,
                row,
                &protocol,
                &hostname,
                &encryption_key,
            ) {
                unchanged += 1;
                continue;
            }
            if update_existing_row(
                &database,
                &entry,
                row,
                &friendly_name,
                &row.display_name,
                &protocol,
                &hostname,
                &encryption_key,
                row_index,
                &mut passwords_dropped,
                &mut errors,
            ) {
                updated += 1;
            }
            continue;
        }

        // Missing → create (both create and upsert modes).
        match insert_new_row(
            &database,
            folder_id,
            &slug,
            &friendly_name,
            &row.display_name,
            row,
            &protocol,
            &hostname,
            &encryption_key,
            row_index,
            &mut passwords_dropped,
            &mut errors,
        ) {
            InsertOutcome::Inserted => imported += 1,
            InsertOutcome::SkippedRace => skipped += 1,
            InsertOutcome::Failed => {}
        }
    }

    let proxies = trusted
        .as_ref()
        .map(|Extension(t)| t.0.as_slice())
        .unwrap_or(&[]);
    let ip = client_ip(&headers, addr.ip(), proxies).to_string();
    let details = json!({
        "imported": imported,
        "updated": updated,
        "unchanged": unchanged,
        "skipped": skipped,
        "errors": errors.len(),
        "passwords_dropped": passwords_dropped,
    })
    .to_string();
    log_ab_event(
        &database,
        &admin_email,
        "import_csv",
        &scope,
        "",
        None,
        &ip,
        Some(&details),
    )
    .await;

    Ok(Json(json!({
        "imported": imported,
        "updated": updated,
        "unchanged": unchanged,
        "skipped": skipped,
        "passwords_dropped": passwords_dropped,
        "errors": errors,
    })))
}

/// Serve a CSV template (header + two example rows) for download.
///
/// Any authenticated user with at least the operator role may download.
/// The template carries the optional settings columns plus any configured
/// custom-field columns so it stays in sync with the importer.
pub async fn import_template(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
) -> Result<Response, AppError> {
    let allowed = matches!(identity.as_ref(), Some(Extension(id)) if id.has_role("operator"));
    if !allowed {
        return Err(AppError::Forbidden("operator role required".into()));
    }

    let stored = super::settings::read_all_settings(&database)?;
    let template = csv_import::render_template(&custom_field_names(&stored));

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"persea-connections-template.csv\"",
        )
        .body(axum::body::Body::from(template))
        .map_err(|e| AppError::Internal(e.to_string()))
}
