//! Admin system settings API.
//!
//! Settings are persisted as strings in the `system_settings` key/value
//! table and returned as typed JSON. Config-file values are not available
//! to handlers, so `GET /api/system/settings` returns whatever is stored in
//! the DB, falling back to sensible defaults that mirror the hardcoded
//! values in `templates/pages/admin/settings.html` and the documented
//! defaults in `src/config.rs`.

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
    "enable_recordings",
    "enable_web_sessions",
    "enable_spice",
    "enable_proxmox",
    "enable_vmware",
    "enable_vdi",
    "enable_file_transfer",
    "vault_enabled",
    "db_only_mode",
    "site_title",
    "logo_url",
    "primary_color",
    "custom_fields",
];

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
    "enable_recordings",
    "enable_web_sessions",
    "enable_spice",
    "enable_proxmox",
    "enable_vmware",
    "enable_vdi",
    "enable_file_transfer",
    "vault_enabled",
    "db_only_mode",
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
/// session_history_retention_days: 90, all feature toggles default off).
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
        "enable_recordings" => json!(true),
        "enable_web_sessions" => json!(true),
        "enable_spice" => json!(true),
        "enable_proxmox" => json!(true),
        "enable_vmware" => json!(true),
        "enable_vdi" => json!(true),
        "enable_file_transfer" => json!(false),
        "enable_browser_sessions" => json!(true),
        "vault_enabled" => json!(false),
        "db_only_mode" => json!(true),
        "site_title" => json!("persea"),
        "logo_url" => json!(""),
        "primary_color" => json!("#10b981"),
        // Custom field definitions: JSON array, empty by default so the
        // feature is OFF until an admin configures fields.
        "custom_fields" => json!([]),
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
    } else {
        default_value(key)
    }
}

/// Merge stored rows with defaults into the full effective settings object.
/// Merge the startup config baseline (from `SettingsBaseline`) with DB
/// overrides; DB values win.
fn effective_settings_with_baseline(
    baseline: Value,
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

fn effective_settings(stored: &std::collections::HashMap<String, String>) -> Value {
    let mut out = serde_json::Map::new();
    for key in SETTING_KEYS {
        let v = stored
            .get(*key)
            .map(|s| stored_to_value(key, s))
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
        baseline.map(|b| b.0 .0).unwrap_or_else(|| json!({})),
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
        if key == "session_max_duration_secs" {
            if n == 0 || n > MAX_DURATION_SECS {
                return Err(AppError::Validation(format!(
                    "{key} must be between 1 and {MAX_DURATION_SECS}"
                )));
            }
        }
        if key == "session_history_retention_days" && n > MAX_RETENTION_DAYS as u64 {
            return Err(AppError::Validation(format!(
                "{key} must be at most {MAX_RETENTION_DAYS}"
            )));
        }
        Ok(n.to_string())
    } else if BOOL_KEYS.contains(&key) {
        Ok(parse_bool(value, key)?.to_string())
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
        let obj = field.as_object().ok_or_else(|| {
            AppError::Validation(format!("{key}[{i}] must be an object"))
        })?;
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
        let field_type = obj
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("text");
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
                    AppError::Validation(format!(
                        "{key}[{i}] '{name}': options must be strings"
                    ))
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
    tokio::task::spawn_blocking(move || {
        if crate::db::pool_active() {
            return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| crate::db::settings_put_pool(pool, entries));
        }
        let conn = db_clone.lock().unwrap();
        conn.execute_batch(CREATE_TABLE_SQL)?;
        for (key, value) in &entries {
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

    let db_clone = database.clone();
    let stored = tokio::task::spawn_blocking(move || read_all_settings(&db_clone))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
    // Same merge as GET so PUT and GET always agree on effective values.
    Ok(Json(effective_settings_with_baseline(
        baseline.map(|b| b.0 .0).unwrap_or_else(|| json!({})),
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
    fn custom_fields_stored_to_value_round_trips() {
        let stored = r#"[{"name":"Environment","type":"select","options":["prod","dev"],"required":true}]"#;
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
        assert_eq!(as_array, as_string, "array and JSON-string forms must agree");
        let v: Value = serde_json::from_str(&as_array).unwrap();
        assert_eq!(v[0]["name"], "Environment");
        assert_eq!(v[0]["type"], "select");
        assert_eq!(v[0]["options"][2], "Production");
        assert_eq!(v[0]["required"], json!(true));
    }

    #[test]
    fn custom_fields_rejects_bad_type() {
        let err = canonicalize(
            "custom_fields",
            &json!([{"name": "Env", "type": "radio"}]),
        )
        .unwrap_err();
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
        let err = canonicalize(
            "custom_fields",
            &json!([{"name": "Env", "type": "select"}]),
        )
        .unwrap_err();
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
        assert!(v[0].get("required").is_none(), "default required is omitted");
        assert_eq!(v[0]["name"], "Owner");
    }

    #[test]
    fn custom_fields_accepts_text_default_type() {
        let out = canonicalize("custom_fields", &json!([{"name": "Owner"}])).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v[0]["type"], "text");
    }
}
