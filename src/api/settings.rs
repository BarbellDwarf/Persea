//! Admin system settings API.
//!
//! Settings are persisted as strings in the `system_settings` key/value
//! table and returned as typed JSON. Config-file values are not available
//! to handlers, so `GET /api/system/settings` returns whatever is stored in
//! the DB, falling back to sensible defaults that mirror the hardcoded
//! values in `templates/pages/admin/settings.html` and the documented
//! defaults in `src/config.rs`. The per-protocol session defaults
//! (`default_rdp_*`, `default_ssh_*`, `default_vnc_*`) mirror
//! `config::PROTOCOL_DEFAULT_KEYS`; the session creation path applies them
//! at create time.

use crate::api::SettingsBaseline;
use crate::auth::AuthIdentity;
use crate::db::Db;
use crate::error::AppError;
use axum::extract::Multipart;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use rusqlite::params;
use serde_json::{json, Value};
use std::net::SocketAddr;

/// The full ordered set of keys this API manages. Order matters: it
/// determines the JSON key order in GET/PUT responses.
const SETTING_KEYS: &[&str] = &[
    "listen_addr",
    "guacd_addr",
    "tls_cert_path",
    "tls_key_path",
    "session_max_duration_secs",
    "session_idle_timeout_secs",
    "max_concurrent_sessions",
    "session_history_retention_days",
    "enable_rdp",
    "enable_ssh_tunnels",
    "enable_api_keys",
    "compliance_mode",
    "enable_recordings",
    "enable_web_sessions",
    "enable_spice",
    "enable_proxmox",
    "enable_vmware",
    "enable_vdi",
    "enable_powershell_ssh",
    "enable_file_transfer",
    "desktop_kiosk",
    "desktop_transfers",
    "desktop_pairing",
    "vault_enabled",
    "db_only_mode",
    "site_title",
    "logo_url",
    "primary_color",
    "custom_fields",
    // Per-protocol session defaults (admin Settings → Session →
    // Session defaults). Their unset values mirror the canonical table in
    // `config::PROTOCOL_DEFAULT_KEYS`.
    "default_rdp_width",
    "default_rdp_height",
    "default_rdp_dpi",
    "default_rdp_security",
    "default_rdp_auth_pkg",
    "default_rdp_h264",
    "default_rdp_gfx",
    "default_rdp_drive",
    "default_rdp_auto_size",
    "default_ssh_width",
    "default_ssh_height",
    "default_ssh_auto_size",
    "default_vnc_color_depth",
    "default_vnc_disable_copy",
    "default_vnc_disable_paste",
];

/// Numeric per-protocol defaults with their upper bound. Values must be
/// positive; the session creation path clamps display dimensions to its
/// own safe ranges, so the API only rejects nonsense here.
const PROTOCOL_NUM_KEYS: &[(&str, u64)] = &[
    ("default_rdp_width", 8192),
    ("default_rdp_height", 8192),
    ("default_rdp_dpi", 384),
    ("default_ssh_width", 8192),
    ("default_ssh_height", 8192),
    ("default_vnc_color_depth", 32),
];

/// RDP security modes accepted as a global default. "any" matches the
/// pass-through behaviour of the create path (guacd receives no security
/// arg and falls back to its own default).
const RDP_SECURITY_KEYS: &[&str] = &["default_rdp_security"];
const RDP_SECURITY_VALUES: &[&str] = &["any", "rdp", "tls", "nla"];

/// RDP NLA auth packages accepted as a global default. The empty string
/// means "no global default": the create path falls back to the `[rdp]`
/// config value, then NTLM.
const RDP_AUTH_PKG_KEYS: &[&str] = &["default_rdp_auth_pkg"];
const RDP_AUTH_PKG_VALUES: &[&str] = &["", "ntlm", "kerberos", "negotiate"];

/// Keys whose stored value is a JSON document (serialized as a string in the
/// `system_settings` table).
const JSON_KEYS: &[&str] = &["custom_fields"];

const STRING_KEYS: &[&str] = &[
    "listen_addr",
    "guacd_addr",
    "tls_cert_path",
    "tls_key_path",
    "site_title",
    "logo_url",
    "primary_color",
];
const ADDR_KEYS: &[&str] = &["listen_addr", "guacd_addr"];
const DURATION_KEYS: &[&str] = &[
    "session_max_duration_secs",
    "session_idle_timeout_secs",
    "max_concurrent_sessions",
    "session_history_retention_days",
];
const BOOL_KEYS: &[&str] = &[
    "enable_rdp",
    "enable_ssh_tunnels",
    "enable_api_keys",
    "compliance_mode",
    "enable_recordings",
    "enable_web_sessions",
    "enable_spice",
    "enable_proxmox",
    "enable_vmware",
    "enable_vdi",
    "enable_powershell_ssh",
    "enable_file_transfer",
    "desktop_kiosk",
    "desktop_transfers",
    "desktop_pairing",
    "vault_enabled",
    "db_only_mode",
    "default_rdp_h264",
    "default_rdp_gfx",
    "default_rdp_drive",
    "default_rdp_auto_size",
    "default_ssh_auto_size",
    "default_vnc_disable_copy",
    "default_vnc_disable_paste",
];

/// Upper bounds for unbounded numeric settings (0 stays "unlimited" where
/// the runtime treats it that way).
const MAX_DURATION_SECS: u64 = 31_536_000; // 365 days
const MAX_RETENTION_DAYS: u32 = 3650;

/// Idempotent — the table is created by migration `003-system-settings.sql`
/// on the sqlx backends; the rusqlite backend creates it lazily here.
const CREATE_TABLE_SQL: &str = "CREATE TABLE IF NOT EXISTS system_settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
)";

/// Defaults when a key has not been stored yet. The first four mirror the
/// hardcoded values in `templates/pages/admin/settings.html`; the rest
/// mirror the documented defaults in `src/config.rs` (max_sessions: 500,
/// session_history_retention_days: 90). Every `enable_*` feature toggle
/// defaults to true: the runtime treats an unset toggle as enabled
/// (`settings_merge::toggle_enabled(..., true)`), so reporting anything
/// else here would make the admin page lie about the actual gate.
fn default_value(key: &str) -> Value {
    match key {
        "listen_addr" => json!("0.0.0.0:8089"),
        "guacd_addr" => json!("127.0.0.1:4822"),
        "tls_cert_path" => json!(""),
        "tls_key_path" => json!(""),
        "session_max_duration_secs" => json!(28800u64),
        "session_idle_timeout_secs" => json!(1800u64),
        "max_concurrent_sessions" => json!(500u64),
        "session_history_retention_days" => json!(90u64),
        "enable_rdp" => json!(true),
        "enable_ssh_tunnels" => json!(true),
        "enable_api_keys" => json!(true),
        // Compliance mode (persea#228): off by default so existing
        // deployments behave exactly as before. The auth middleware treats
        // an unset toggle as off (settings_merge::toggle_enabled(..., false)),
        // so the Settings API must report false too or the admin checkbox
        // lies about the gate.
        "compliance_mode" => json!(false),
        "enable_recordings" => json!(true),
        "enable_web_sessions" => json!(true),
        "enable_spice" => json!(true),
        "enable_proxmox" => json!(true),
        "enable_vmware" => json!(true),
        "enable_vdi" => json!(true),
        "enable_powershell_ssh" => json!(true),
        // Unset = enabled everywhere: the runtime gate at
        // session/create.rs defaults an absent enable_file_transfer toggle
        // to true (settings_merge::toggle_enabled), so the Settings API
        // must report true too or the admin checkbox lies about the gate.
        "enable_file_transfer" => json!(true),
        "enable_browser_sessions" => json!(true),
        // S09 "Desktop" section toggles. All default ON: the S05 capability
        // probe (auth_status) reads an unset desktop_* toggle as enabled
        // (settings_merge::toggle_enabled(..., true)), so the Settings API
        // must agree or the admin checkboxes lie about the gates.
        "desktop_kiosk" => json!(true),
        "desktop_transfers" => json!(true),
        "desktop_pairing" => json!(true),
        "vault_enabled" => json!(false),
        "db_only_mode" => json!(true),
        "site_title" => json!("persea"),
        "logo_url" => json!(""),
        "primary_color" => json!("#10b981"),
        // Custom field definitions: JSON array, empty by default so the
        // feature is OFF until an admin configures fields.
        "custom_fields" => json!([]),
        // Per-protocol session defaults. These mirror the canonical table
        // in `config::PROTOCOL_DEFAULT_KEYS` — the session creation path
        // and this API must agree (an integration test in
        // tests/protocol_defaults_tests.rs asserts GET matches the table).
        "default_rdp_width" => json!(1920u64),
        "default_rdp_height" => json!(1080u64),
        "default_rdp_dpi" => json!(96u64),
        "default_rdp_security" => json!("any"),
        "default_rdp_auth_pkg" => json!(""),
        "default_rdp_h264" => json!(true),
        "default_rdp_gfx" => json!(true),
        "default_rdp_drive" => json!(false),
        "default_rdp_auto_size" => json!(true),
        "default_ssh_width" => json!(1920u64),
        "default_ssh_height" => json!(1080u64),
        "default_ssh_auto_size" => json!(true),
        "default_vnc_color_depth" => json!(24u64),
        "default_vnc_disable_copy" => json!(false),
        "default_vnc_disable_paste" => json!(false),
        _ => json!(null),
    }
}

/// Parse a stored string back into its typed JSON form. Stored values are
/// written by `put_settings` and therefore always well-formed; anything
/// unexpected falls back to the default rather than erroring.
fn stored_to_value(key: &str, stored: &str) -> Value {
    if STRING_KEYS.contains(&key) {
        json!(stored)
    } else if DURATION_KEYS.contains(&key) {
        stored
            .parse::<u64>()
            .map(|n| json!(n))
            .unwrap_or_else(|_| default_value(key))
    } else if BOOL_KEYS.contains(&key) {
        match stored {
            "true" => json!(true),
            "false" => json!(false),
            _ => default_value(key),
        }
    } else if JSON_KEYS.contains(&key) {
        serde_json::from_str::<Value>(stored).unwrap_or_else(|_| default_value(key))
    } else if PROTOCOL_NUM_KEYS.iter().any(|(k, _)| *k == key) {
        stored
            .parse::<u64>()
            .map(|n| json!(n))
            .unwrap_or_else(|_| default_value(key))
    } else if RDP_SECURITY_KEYS.contains(&key) {
        // Only the accepted modes pass through; anything else (manual DB
        // edits) falls back so guacd never receives an unknown mode.
        if RDP_SECURITY_VALUES.contains(&stored) {
            json!(stored)
        } else {
            default_value(key)
        }
    } else if RDP_AUTH_PKG_KEYS.contains(&key) {
        // Only the accepted packages pass through (the empty string is a
        // valid "no global default" value); anything else falls back.
        if RDP_AUTH_PKG_VALUES.contains(&stored) {
            json!(stored)
        } else {
            default_value(key)
        }
    } else {
        default_value(key)
    }
}

/// Merge stored rows with defaults into the full effective settings object.
/// Merge the startup config baseline (from `SettingsBaseline`) with DB
/// overrides; DB values win.
fn effective_settings_with_baseline(
    baseline: &Value,
    stored: &std::collections::HashMap<String, String>,
) -> Value {
    let mut out = serde_json::Map::new();
    let base = baseline.as_object().cloned().unwrap_or_default();
    for key in SETTING_KEYS {
        let v = stored
            .get(*key)
            .map(|s| stored_to_value(key, s))
            .or_else(|| base.get(*key).cloned())
            .unwrap_or_else(|| default_value(key));
        out.insert((*key).to_string(), v);
    }
    Value::Object(out)
}

pub(crate) fn read_all_settings(
    database: &Db,
) -> Result<std::collections::HashMap<String, String>, AppError> {
    if crate::db::pool_active() {
        let rows = crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::settings_load_all_pool(pool)
        })
        .map_err(|e| AppError::Internal(e.to_string()))?;
        return Ok(rows.into_iter().collect());
    }
    let conn = database.lock().unwrap();
    conn.execute_batch(CREATE_TABLE_SQL)?;
    let mut stmt = conn.prepare("SELECT key, value FROM system_settings")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut stored = std::collections::HashMap::new();
    for row in rows {
        let (key, value) = row?;
        stored.insert(key, value);
    }
    Ok(stored)
}

fn is_admin(identity: &Option<Extension<AuthIdentity>>) -> bool {
    identity
        .as_ref()
        .map(|Extension(id)| id.has_role("admin"))
        .unwrap_or(false)
}

/// GET /api/system/settings — return effective settings (DB values with
/// defaults for unset keys). Admin-only.
pub async fn get_settings(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    baseline: Option<Extension<SettingsBaseline>>,
) -> Result<Json<Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let db_clone = database.clone();
    let stored = tokio::task::spawn_blocking(move || read_all_settings(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    // Report the effective values: config-file baseline overlaid with DB
    // overrides (DB wins). Without the extension (tests, direct routers)
    // fall back to defaults only.
    Ok(Json(effective_settings_with_baseline(
        &baseline.map(|b| b.0 .0).unwrap_or_else(|| json!({})),
        &stored,
    )))
}

fn parse_u64(value: &Value, key: &str) -> Result<u64, AppError> {
    let parsed = match value {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse::<u64>().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| AppError::Validation(format!("{key} must be a non-negative integer")))
}

fn parse_bool(value: &Value, key: &str) -> Result<bool, AppError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) if s == "true" => Ok(true),
        Value::String(s) if s == "false" => Ok(false),
        _ => Err(AppError::Validation(format!("{key} must be a boolean"))),
    }
}

/// Validate one submitted value and reduce it to its canonical string form.
fn canonicalize(key: &str, value: &Value) -> Result<String, AppError> {
    // JSON document keys must be handled BEFORE the array-last
    // simplification below: a `custom_fields` array must not be truncated
    // to its last element.
    if JSON_KEYS.contains(&key) {
        return canonicalize_custom_fields(key, value);
    }
    // The settings form historically submitted checkbox+hidden pairs with
    // duplicate names; htmx's json-enc collects duplicates as arrays. Take
    // the last entry so those payloads still validate.
    let value = match value {
        Value::Array(items) => items.last().unwrap_or(value),
        other => other,
    };
    if ADDR_KEYS.contains(&key) {
        let addr = value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{key} must be a string")))?;
        if key == "listen_addr" {
            addr.parse::<SocketAddr>().map_err(|_| {
                AppError::Validation(format!("{key} must be a valid host:port address"))
            })?;
        } else {
            // guacd_addr mirrors the config validation: IP:port OR
            // hostname:port, only the port is checked.
            match addr.rsplit(':').next() {
                Some(p) if p.parse::<u16>().is_ok() => {}
                _ => {
                    return Err(AppError::Validation(format!(
                        "{key} must end in a valid port (:1-65535)"
                    )));
                }
            }
        }
        Ok(addr.to_string())
    } else if STRING_KEYS.contains(&key) {
        Ok(value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{key} must be a string")))?
            .to_string())
    } else if DURATION_KEYS.contains(&key) {
        let n = parse_u64(value, key)?;
        if key == "session_max_duration_secs" && (n == 0 || n > MAX_DURATION_SECS) {
            return Err(AppError::Validation(format!(
                "{key} must be between 1 and {MAX_DURATION_SECS}"
            )));
        }
        if key == "session_history_retention_days" && n > MAX_RETENTION_DAYS as u64 {
            return Err(AppError::Validation(format!(
                "{key} must be at most {MAX_RETENTION_DAYS}"
            )));
        }
        Ok(n.to_string())
    } else if BOOL_KEYS.contains(&key) {
        Ok(parse_bool(value, key)?.to_string())
    } else if PROTOCOL_NUM_KEYS.iter().any(|(k, _)| *k == key) {
        let n = parse_u64(value, key)?;
        let max = PROTOCOL_NUM_KEYS
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, m)| *m)
            .expect("key matched PROTOCOL_NUM_KEYS");
        if n == 0 || n > max {
            return Err(AppError::Validation(format!(
                "{key} must be between 1 and {max}"
            )));
        }
        Ok(n.to_string())
    } else if RDP_SECURITY_KEYS.contains(&key) {
        let s = value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{key} must be a string")))?;
        if !RDP_SECURITY_VALUES.contains(&s) {
            return Err(AppError::Validation(format!(
                "{key} must be one of: {}",
                RDP_SECURITY_VALUES.join(", ")
            )));
        }
        Ok(s.to_string())
    } else if RDP_AUTH_PKG_KEYS.contains(&key) {
        let s = value
            .as_str()
            .ok_or_else(|| AppError::Validation(format!("{key} must be a string")))?;
        if !RDP_AUTH_PKG_VALUES.contains(&s) {
            return Err(AppError::Validation(format!(
                "{key} must be one of: {}",
                RDP_AUTH_PKG_VALUES
                    .iter()
                    .map(|v| if v.is_empty() { "empty" } else { *v })
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        Ok(s.to_string())
    } else {
        // A key in SETTING_KEYS without a type handler is a programming
        // error — fail loudly instead of silently persisting "".
        Err(AppError::Validation(format!(
            "internal error: no validator for settings key '{key}'"
        )))
    }
}

/// Validate the `custom_fields` definitions array and reduce it to its
/// canonical JSON string. Accepted either as a JSON array (JSON API
/// clients) or as a JSON-encoded string (form submission via htmx
/// json-enc, which sends every form value as a string).
///
/// Each definition is `{name, type: "text"|"select", options?, required?}`.
/// Names are trimmed and must be unique; `select` fields must have at least
/// one option; `required` must be a boolean when present. Unknown keys are
/// dropped, and only non-default keys are emitted.
fn canonicalize_custom_fields(key: &str, value: &Value) -> Result<String, AppError> {
    let parsed = match value {
        Value::String(s) => serde_json::from_str::<Value>(s).ok(),
        other => Some(other.clone()),
    };
    let arr = parsed
        .as_ref()
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::Validation(format!("{key} must be a JSON array")))?;
    let mut seen = std::collections::HashSet::new();
    let mut fields: Vec<Value> = Vec::new();
    for (i, field) in arr.iter().enumerate() {
        let obj = field
            .as_object()
            .ok_or_else(|| AppError::Validation(format!("{key}[{i}] must be an object")))?;
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                AppError::Validation(format!("{key}[{i}]: name must be a non-empty string"))
            })?;
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err(AppError::Validation(format!(
                "{key}: duplicate field name '{name}'"
            )));
        }
        let field_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("text");
        if field_type != "text" && field_type != "select" {
            return Err(AppError::Validation(format!(
                "{key}[{i}] '{name}': type must be \"text\" or \"select\""
            )));
        }
        let mut options: Vec<String> = Vec::new();
        if let Some(opts) = obj.get("options") {
            let opts = opts.as_array().ok_or_else(|| {
                AppError::Validation(format!(
                    "{key}[{i}] '{name}': options must be an array of strings"
                ))
            })?;
            for opt in opts {
                let s = opt.as_str().ok_or_else(|| {
                    AppError::Validation(format!("{key}[{i}] '{name}': options must be strings"))
                })?;
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() && !options.contains(&trimmed) {
                    options.push(trimmed);
                }
            }
        }
        if field_type == "select" && options.is_empty() {
            return Err(AppError::Validation(format!(
                "{key}[{i}] '{name}': select fields need at least one option"
            )));
        }
        let required = match obj.get("required") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(AppError::Validation(format!(
                    "{key}[{i}] '{name}': required must be a boolean"
                )))
            }
        };
        let mut canon = serde_json::Map::new();
        canon.insert("name".into(), json!(name));
        canon.insert("type".into(), json!(field_type));
        if field_type == "select" {
            canon.insert("options".into(), json!(options));
        }
        if required {
            canon.insert("required".into(), json!(true));
        }
        fields.push(Value::Object(canon));
    }
    serde_json::to_string(&fields).map_err(|e| AppError::Internal(e.to_string()))
}

/// Extract the `custom_fields` definitions array from stored settings,
/// defaulting to `[]` when unset or unparseable. Consumed by
/// `GET /api/addressbook/custom-fields` so the connections page can render
/// the per-entry value inputs.
pub(crate) fn custom_fields_value(stored: &std::collections::HashMap<String, String>) -> Value {
    stored
        .get("custom_fields")
        .map(|s| stored_to_value("custom_fields", s))
        .unwrap_or_else(|| default_value("custom_fields"))
}

/// PUT /api/system/settings — validate and persist settings. Admin-only.
/// Accepts a JSON object; unknown keys are ignored. Returns the full
/// effective settings (same shape as GET).
pub async fn put_settings(
    identity: Option<Extension<AuthIdentity>>,
    Extension(database): Extension<Db>,
    baseline: Option<Extension<SettingsBaseline>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    let obj = body
        .as_object()
        .ok_or_else(|| AppError::Validation("request body must be a JSON object".into()))?;

    // Validate everything up front so a bad value persists nothing.
    let mut entries: Vec<(String, String)> = Vec::new();
    for (key, value) in obj {
        if !SETTING_KEYS.contains(&key.as_str()) {
            continue;
        }
        let canonical = canonicalize(key, value)?;
        entries.push((key.clone(), canonical));
    }

    let db_clone = database.clone();
    let entries_clone = entries.clone();
    tokio::task::spawn_blocking(move || {
        if crate::db::pool_active() {
            return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| crate::db::settings_put_pool(pool, entries_clone));
        }
        let conn = db_clone.lock().unwrap();
        conn.execute_batch(CREATE_TABLE_SQL)?;
        for (key, value) in &entries_clone {
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at)
                 VALUES (?1, ?2, CURRENT_TIMESTAMP)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP",
                params![key, value],
            )?;
        }
        Ok::<_, rusqlite::Error>(())
    })
    .await
    .map_err(|e| AppError::Internal(e.to_string()))??;

    // Invalidate the cached settings flags for any flag-shaped keys that
    // were just written, so subsequent API-key requests see the new values
    // without a restart (persea#276).
    for (key, value) in &entries {
        crate::auth::update_settings_cache(key, value);
    }

    let db_clone = database.clone();
    let stored = tokio::task::spawn_blocking(move || read_all_settings(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    // Same merge as GET so PUT and GET always agree on effective values.
    Ok(Json(effective_settings_with_baseline(
        &baseline.map(|b| b.0 .0).unwrap_or_else(|| json!({})),
        &stored,
    )))
}

/// POST /api/admin/upload-logo — accept multipart image upload, save to
/// <static_path>/uploads/logo/, return the URL path. Admin-only.
pub async fn upload_logo(
    State(state): State<crate::api::AppState>,
    identity: Option<Extension<AuthIdentity>>,
    mut multipart: Multipart,
) -> Result<Response, AppError> {
    if !is_admin(&identity) {
        return Err(AppError::Forbidden("admin role required".into()));
    }

    let allowed_exts = ["png", "svg", "jpg", "jpeg", "ico"];
    let max_size: usize = 2 * 1024 * 1024; // 2 MB

    let mut file_data: Vec<u8> = Vec::new();
    let mut filename: Option<String> = None;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("multipart error: {e}")))?
    {
        let name = field.name().unwrap_or_default().to_string();
        if name == "file" {
            let fname = field
                .file_name()
                .map(|f| f.to_string())
                .ok_or_else(|| AppError::Validation("missing filename".into()))?;
            filename = Some(fname);
            while let Some(chunk) = field
                .chunk()
                .await
                .map_err(|e| AppError::Validation(format!("upload read error: {e}")))?
            {
                file_data.extend_from_slice(&chunk);
                if file_data.len() > max_size {
                    return Err(AppError::Validation("file exceeds 2 MB limit".into()));
                }
            }
        }
    }

    let fname = filename.ok_or_else(|| AppError::Validation("no file provided".into()))?;
    let ext = fname.rsplit('.').next().unwrap_or("").to_lowercase();
    if !allowed_exts.contains(&ext.as_str()) {
        return Err(AppError::Validation(format!(
            "unsupported file type '.{ext}'; allowed: {}",
            allowed_exts.join(", ")
        )));
    }

    // Build a deterministic name: logo.<ext>. Write under the configured
    // static_path so the file lands exactly where ServeDir serves it from
    // (the old CWD-relative "static" diverged when static_path was
    // customized).
    let out_name = format!("logo.{ext}");
    let uploads_dir = state.config().static_path.join("uploads").join("logo");
    std::fs::create_dir_all(&uploads_dir)
        .map_err(|e| AppError::Internal(format!("failed to create upload dir: {e}")))?;
    let out_path = uploads_dir.join(&out_name);
    std::fs::write(&out_path, &file_data)
        .map_err(|e| AppError::Internal(format!("failed to write logo: {e}")))?;

    let url = format!("/uploads/logo/{out_name}");
    Ok((StatusCode::OK, Json(json!({ "url": url }))).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn custom_fields_default_is_empty_array() {
        assert_eq!(default_value("custom_fields"), json!([]));
    }

    #[test]
    fn enable_powershell_ssh_default_matches_runtime_gate() {
        // The runtime treats an unset enable_powershell_ssh toggle as
        // enabled (settings_merge::toggle_enabled(..., true) at
        // session/create.rs), so the Settings API default must agree or the
        // admin Settings page would show "Off" for a feature that is on.
        assert_eq!(default_value("enable_powershell_ssh"), json!(true));
        assert!(crate::settings_merge::toggle_enabled(
            &[],
            "enable_powershell_ssh",
            true
        ));
        // An explicitly stored "false" still wins on both sides.
        let stored = vec![("enable_powershell_ssh".to_string(), "false".to_string())];
        assert_eq!(
            stored_to_value("enable_powershell_ssh", "false"),
            json!(false)
        );
        assert!(!crate::settings_merge::toggle_enabled(
            &stored,
            "enable_powershell_ssh",
            true
        ));
    }

    #[test]
    fn compliance_mode_default_matches_runtime_gate() {
        // The auth middleware treats an unset compliance_mode toggle as off
        // (settings_merge::toggle_enabled(..., false)), so the Settings API
        // default must agree or the admin Settings page would show "On" for
        // a mode that is not enforced.
        assert_eq!(default_value("compliance_mode"), json!(false));
        assert!(!crate::settings_merge::toggle_enabled(
            &[],
            "compliance_mode",
            false
        ));
        // An explicitly stored "true" still wins on both sides.
        let stored = vec![("compliance_mode".to_string(), "true".to_string())];
        assert_eq!(stored_to_value("compliance_mode", "true"), json!(true));
        assert!(crate::settings_merge::toggle_enabled(
            &stored,
            "compliance_mode",
            false
        ));
    }

    #[test]
    fn enable_file_transfer_default_matches_runtime_gate() {
        // The runtime treats an unset enable_file_transfer toggle as
        // enabled (settings_merge::toggle_enabled(..., true) at
        // session/create.rs), so the Settings API default must agree or the
        // admin Settings page would show "Off" for a feature that is on.
        assert_eq!(default_value("enable_file_transfer"), json!(true));
        assert!(crate::settings_merge::toggle_enabled(
            &[],
            "enable_file_transfer",
            true
        ));
        // An explicitly stored "false" still wins on both sides.
        let stored = vec![("enable_file_transfer".to_string(), "false".to_string())];
        assert_eq!(
            stored_to_value("enable_file_transfer", "false"),
            json!(false)
        );
        assert!(!crate::settings_merge::toggle_enabled(
            &stored,
            "enable_file_transfer",
            true
        ));
    }

    #[test]
    fn custom_fields_stored_to_value_round_trips() {
        let stored =
            r#"[{"name":"Environment","type":"select","options":["prod","dev"],"required":true}]"#;
        let v = stored_to_value("custom_fields", stored);
        assert_eq!(v[0]["name"], "Environment");
        assert_eq!(v[0]["type"], "select");
        assert_eq!(v[0]["options"][1], "dev");
        assert_eq!(v[0]["required"], json!(true));
        // Garbage falls back to the default.
        assert_eq!(stored_to_value("custom_fields", "not json"), json!([]));
    }

    #[test]
    fn custom_fields_canonicalize_accepts_array_and_string_forms() {
        let arr = json!([{
            "name": "Environment",
            "type": "select",
            "options": ["Test", "Pilot", "Production"],
            "required": true,
        }]);
        let as_array = canonicalize("custom_fields", &arr).unwrap();
        let as_string = canonicalize("custom_fields", &json!(as_array.clone())).unwrap();
        assert_eq!(
            as_array, as_string,
            "array and JSON-string forms must agree"
        );
        let v: Value = serde_json::from_str(&as_array).unwrap();
        assert_eq!(v[0]["name"], "Environment");
        assert_eq!(v[0]["type"], "select");
        assert_eq!(v[0]["options"][2], "Production");
        assert_eq!(v[0]["required"], json!(true));
    }

    #[test]
    fn custom_fields_rejects_bad_type() {
        let err =
            canonicalize("custom_fields", &json!([{"name": "Env", "type": "radio"}])).unwrap_err();
        assert!(err.to_string().contains("text"), "got: {}", err);
        assert!(err.to_string().contains("select"), "got: {}", err);
    }

    #[test]
    fn custom_fields_rejects_duplicate_names() {
        let err = canonicalize(
            "custom_fields",
            &json!([
                {"name": "Environment", "type": "text"},
                {"name": "Environment", "type": "text"},
            ]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("duplicate"), "got: {}", err);
        assert!(err.to_string().contains("Environment"), "got: {}", err);
    }

    #[test]
    fn custom_fields_requires_options_for_select() {
        let err =
            canonicalize("custom_fields", &json!([{"name": "Env", "type": "select"}])).unwrap_err();
        assert!(err.to_string().contains("option"), "got: {}", err);
    }

    #[test]
    fn custom_fields_rejects_non_bool_required() {
        let err = canonicalize(
            "custom_fields",
            &json!([{"name": "Env", "type": "text", "required": "yes"}]),
        )
        .unwrap_err();
        assert!(err.to_string().contains("boolean"), "got: {}", err);
    }

    #[test]
    fn custom_fields_text_fields_drop_options_and_default_required() {
        let out = canonicalize(
            "custom_fields",
            &json!([{"name": "Owner", "type": "text", "options": ["x"], "required": false}]),
        )
        .unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v[0].get("options").is_none(), "text fields keep no options");
        assert!(
            v[0].get("required").is_none(),
            "default required is omitted"
        );
        assert_eq!(v[0]["name"], "Owner");
    }

    #[test]
    fn custom_fields_accepts_text_default_type() {
        let out = canonicalize("custom_fields", &json!([{"name": "Owner"}])).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["type"], "text");
    }

    // ── Per-protocol session defaults ──

    #[test]
    fn protocol_default_values_are_typed() {
        assert_eq!(default_value("default_rdp_width"), json!(1920u64));
        assert_eq!(default_value("default_rdp_height"), json!(1080u64));
        assert_eq!(default_value("default_rdp_dpi"), json!(96u64));
        assert_eq!(default_value("default_rdp_security"), json!("any"));
        assert_eq!(default_value("default_rdp_auth_pkg"), json!(""));
        assert_eq!(default_value("default_rdp_h264"), json!(true));
        assert_eq!(default_value("default_rdp_gfx"), json!(true));
        assert_eq!(default_value("default_rdp_drive"), json!(false));
        assert_eq!(default_value("default_rdp_auto_size"), json!(true));
        assert_eq!(default_value("default_ssh_width"), json!(1920u64));
        assert_eq!(default_value("default_ssh_height"), json!(1080u64));
        assert_eq!(default_value("default_ssh_auto_size"), json!(true));
        assert_eq!(default_value("default_vnc_color_depth"), json!(24u64));
        assert_eq!(default_value("default_vnc_disable_copy"), json!(false));
        assert_eq!(default_value("default_vnc_disable_paste"), json!(false));
    }

    #[test]
    fn protocol_defaults_stored_to_value_round_trips() {
        assert_eq!(stored_to_value("default_rdp_width", "1280"), json!(1280u64));
        assert_eq!(stored_to_value("default_rdp_h264", "false"), json!(false));
        assert_eq!(stored_to_value("default_rdp_security", "nla"), json!("nla"));
        assert_eq!(
            stored_to_value("default_rdp_auth_pkg", "kerberos"),
            json!("kerberos")
        );
        assert_eq!(
            stored_to_value("default_rdp_auth_pkg", ""),
            json!(""),
            "the empty package is a valid stored value (no global default)"
        );
        assert_eq!(
            stored_to_value("default_rdp_auto_size", "false"),
            json!(false)
        );
        assert_eq!(
            stored_to_value("default_ssh_auto_size", "true"),
            json!(true)
        );
        assert_eq!(
            stored_to_value("default_vnc_color_depth", "16"),
            json!(16u64)
        );
        // Garbage falls back to the code default.
        assert_eq!(stored_to_value("default_rdp_width", "wide"), json!(1920u64));
        assert_eq!(stored_to_value("default_rdp_h264", "maybe"), json!(true));
        // Unknown security modes fall back too (guacd must never receive
        // one from a manual DB edit).
        assert_eq!(stored_to_value("default_rdp_security", "psk"), json!("any"));
        // Unknown auth packages fall back to the empty default.
        assert_eq!(stored_to_value("default_rdp_auth_pkg", "pam"), json!(""));
    }

    #[test]
    fn protocol_defaults_canonicalize_validates() {
        assert_eq!(
            canonicalize("default_rdp_width", &json!(1280)).unwrap(),
            "1280"
        );
        assert_eq!(
            canonicalize("default_rdp_security", &json!("nla")).unwrap(),
            "nla"
        );
        assert_eq!(
            canonicalize("default_rdp_auth_pkg", &json!("kerberos")).unwrap(),
            "kerberos"
        );
        assert_eq!(
            canonicalize("default_rdp_auth_pkg", &json!("")).unwrap(),
            "",
            "the empty package is accepted (no global default)"
        );
        assert_eq!(
            canonicalize("default_rdp_auth_pkg", &json!("negotiate")).unwrap(),
            "negotiate"
        );
        assert_eq!(
            canonicalize("default_vnc_disable_copy", &json!(false)).unwrap(),
            "false"
        );
        assert_eq!(
            canonicalize("default_rdp_auto_size", &json!(false)).unwrap(),
            "false"
        );
        assert_eq!(
            canonicalize("default_ssh_auto_size", &json!(true)).unwrap(),
            "true"
        );
        assert!(canonicalize("default_rdp_auto_size", &json!("maybe")).is_err());
        // Zero and oversized values are rejected.
        assert!(canonicalize("default_rdp_width", &json!(0)).is_err());
        assert!(canonicalize("default_rdp_width", &json!(9000)).is_err());
        assert!(canonicalize("default_rdp_dpi", &json!(400)).is_err());
        assert!(canonicalize("default_vnc_color_depth", &json!(64)).is_err());
        // Unknown security modes are rejected.
        let err = canonicalize("default_rdp_security", &json!("tls-psk")).unwrap_err();
        assert!(err.to_string().contains("any"), "got: {err}");
        assert!(err.to_string().contains("nla"), "got: {err}");
        // Unknown auth packages are rejected.
        let err = canonicalize("default_rdp_auth_pkg", &json!("pam")).unwrap_err();
        assert!(err.to_string().contains("ntlm"), "got: {err}");
        assert!(err.to_string().contains("kerberos"), "got: {err}");
    }
}
