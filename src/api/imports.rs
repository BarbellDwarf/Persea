//! Address book CSV import endpoints.
//!
//! `POST /api/addressbook/import` ingests connection rows into the DB-backed
//! address book (folder hierarchy auto-created, duplicates skipped by
//! `(folder, name)`), and `GET /api/addressbook/import-template` serves a
//! downloadable CSV template.

use super::address_book::log_ab_event;
use super::StorageKey;
use crate::auth::{client_ip, AuthIdentity, TrustedProxies};
use crate::csv_import::{self, validate_row};
use crate::db::{self, Db};
use crate::error::AppError;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use serde::Deserialize;
use serde_json::json;
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

/// One connection row from the import request body.
#[derive(Debug, Clone, Deserialize)]
pub struct ImportRow {
    pub name: String,
    pub protocol: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub folder: String,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub allowed_groups: Vec<String>,
    #[serde(default)]
    pub description: String,
}

/// Normalize an entry name for near-duplicate detection: lowercase,
/// alphanumerics only. "web-server-01", "Web Server 01" and "webserver01"
/// all collapse to the same key.
fn fuzzy_key(name: &str) -> String {
    name.to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct ImportRequest {
    #[serde(default = "default_scope")]
    pub scope: String,
    pub rows: Vec<ImportRow>,
}

/// Ensure a folder path hierarchy exists under `scope`, creating each missing
/// level, and return the leaf folder ID. An empty path resolves to (and if
/// needed creates) the scope-root folder named `""`.
fn ensure_folder(db: &Db, scope: &str, path: &str) -> Result<i64, AppError> {
    let mut current = String::new();
    let mut leaf_id: Option<i64> = None;
    for segment in path.split('/').filter(|s| !s.is_empty()) {
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

/// Import address book connections from a JSON body.
///
/// Admin only. Each row is validated (`name` required, `protocol` in
/// {ssh, rdp, vnc, spice, web, vdi, proxmox}, `hostname` required unless the
/// protocol is `web`); valid rows are inserted under the (auto-created)
/// folder hierarchy; rows whose `(folder, name)` already exists are skipped.
/// Passwords are stored encrypted when a storage key is available.
#[allow(clippy::too_many_arguments)]
pub async fn import_csv(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    identity: Option<Extension<AuthIdentity>>,
    trusted: Option<Extension<TrustedProxies>>,
    Extension(database): Extension<Db>,
    storage_key: Option<Extension<StorageKey>>,
    headers_2: axum::http::HeaderMap,
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

    // Accept either the JSON contract (`{"scope": ..., "rows": [...]}`) or
    // a raw `text/csv` body (single source of truth: the CSV parser in
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
        let csv_text = String::from_utf8_lossy(&body).to_string();
        let parsed =
            csv_import::parse_rows(&csv_text).map_err(|e| AppError::Validation(e.message))?;
        // Parser-level row errors (invalid ports, malformed rows) must not
        // vanish — they are surfaced alongside handler-level errors below.
        csv_parser_report = Some(parsed.errors);
        csv_parser_skipped = parsed.skipped.len();
        ImportRequest {
            scope: String::new(),
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
                    display_name: r.display_name,
                    allowed_groups: r.allowed_groups,
                    description: r.description,
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
    let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));

    let mut imported = 0usize;
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
        let name = row.name.trim().to_string();
        let protocol = row.protocol.trim().to_ascii_lowercase();
        let hostname = row.hostname.trim().to_string();
        let folder = csv_import::normalize_folder(&row.folder);

        if let Err(msg) = validate_row(&name, &protocol, &hostname, row.port) {
            errors.push(json!({"row": row_index, "error": msg}));
            continue;
        }

        let folder_id = match ensure_folder(&database, &scope, &folder) {
            Ok(id) => id,
            Err(e) => {
                errors.push(json!({"row": row_index, "error": e.to_string()}));
                continue;
            }
        };

        // Exact duplicates are skipped silently; near-duplicates (same
        // normalized name) are reported so the admin can decide.
        if db::get_ab_entry(&database, folder_id, &name).is_ok() {
            skipped += 1;
            continue;
        }
        let fuzzy = fuzzy_key(&name);
        if let Ok(existing) = db::list_ab_entries(&database, folder_id) {
            if let Some(hit) = existing.iter().find(|e| fuzzy_key(&e.name) == fuzzy) {
                errors.push(json!({
                    "row": row_index,
                    "error": format!(
                        "'{}' is a near-duplicate of existing entry '{}' (skipped)",
                        name, hit.name
                    ),
                }));
                skipped += 1;
                continue;
            }
        }

        let display_name = row.display_name.trim().to_string();
        let username = row.username.trim().to_string();
        let description = row.description.trim().to_string();
        let allowed_groups = row
            .allowed_groups
            .iter()
            .map(|g| g.trim())
            .filter(|g| !g.is_empty())
            .collect::<Vec<_>>()
            .join(",");

        // Description is non-credential metadata: persist it in the
        // protocol_config JSON column so it round-trips the API.
        let mut entry_meta = serde_json::Map::new();
        if !description.is_empty() {
            entry_meta.insert("description".into(), json!(description));
        }
        let protocol_config = serde_json::to_string(&entry_meta).unwrap_or_else(|_| "{}".into());

        let entry_id = match db::create_ab_entry(
            &database,
            folder_id,
            &name,
            &display_name,
            &protocol,
            &hostname,
            row.port,
            &username,
            &protocol_config,
            &allowed_groups,
        ) {
            Ok(id) => id,
            Err(e) => {
                if e.to_string().contains("UNIQUE constraint") {
                    skipped += 1;
                } else {
                    errors.push(json!({"row": row_index, "error": e.to_string()}));
                }
                continue;
            }
        };
        // Store the password encrypted when a storage key is available.
        // Without a key the entry is imported but its password is dropped
        // and counted — the admin must not be left thinking it was stored.
        // On any credential failure the just-created entry is rolled back so
        // a corrected re-import is possible (an orphan row would otherwise
        // be skipped as a duplicate forever).
        let mut cred_failed = false;
        if !row.password.is_empty() {
            if encryption_key.is_empty() {
                passwords_dropped += 1;
            } else {
                let mut key: Option<crate::crypto::EncryptionKey> = None;
                if let Err(e) = crate::crypto::EncryptionKey::from_hex(&encryption_key) {
                    errors.push(json!({"row": row_index, "error": format!("failed to parse encryption key: {}", e)}));
                    cred_failed = true;
                } else {
                    key = Some(crate::crypto::EncryptionKey::from_hex(&encryption_key).unwrap());
                }
                if !cred_failed {
                    let stored = match crate::crypto::encrypt_value(
                        key.as_ref().unwrap(),
                        &row.password,
                    ) {
                        Ok(encrypted) => {
                            db::store_ab_credential(&database, entry_id, "password", &encrypted)
                        }
                        Err(e) => {
                            errors.push(json!({"row": row_index, "error": format!("failed to encrypt password: {}", e)}));
                            cred_failed = true;
                            Ok(())
                        }
                    };
                    if let Err(e) = stored {
                        errors.push(json!({"row": row_index, "error": format!("failed to store password: {}", e)}));
                        cred_failed = true;
                    }
                }
            }
        }
        if cred_failed {
            let _ = db::delete_ab_entry(&database, entry_id);
            continue;
        }
        imported += 1;
    }

    let proxies = trusted
        .as_ref()
        .map(|Extension(t)| t.0.as_slice())
        .unwrap_or(&[]);
    let ip = client_ip(&headers, addr.ip(), proxies).to_string();
    let details = json!({
        "imported": imported,
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
        "skipped": skipped,
        "passwords_dropped": passwords_dropped,
        "errors": errors,
    })))
}

/// Serve a CSV template (header + one example row) for download.
///
/// Any authenticated user with at least the operator role may download.
pub async fn import_template(
    identity: Option<Extension<AuthIdentity>>,
) -> Result<Response, AppError> {
    let allowed = match identity.as_ref() {
        Some(Extension(id)) if id.has_role("operator") => true,
        _ => false,
    };
    if !allowed {
        return Err(AppError::Forbidden("operator role required".into()));
    }

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/csv")
        .header(
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"persea-connections-template.csv\"",
        )
        .body(axum::body::Body::from(csv_import::render_template()))
        .map_err(|e| AppError::Internal(e.to_string()))
}
