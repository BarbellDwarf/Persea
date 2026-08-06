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
        Err(e) if is_no_rows(&e) => db::create_ab_folder(db, scope, name, "")
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
    Json(req): Json<ImportRequest>,
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

    let scope = if req.scope.trim().is_empty() {
        default_scope()
    } else {
        req.scope.trim().to_string()
    };
    let encryption_key = resolve_encryption_key(storage_key.as_ref().map(|k| &k.0));

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors: Vec<serde_json::Value> = Vec::new();

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

        // Skip duplicates by (folder, name).
        if db::get_ab_entry(&database, folder_id, &name).is_ok() {
            skipped += 1;
            continue;
        }

        let display_name = row.display_name.trim().to_string();
        let username = row.username.trim().to_string();
        let allowed_groups = row
            .allowed_groups
            .iter()
            .map(|g| g.trim())
            .filter(|g| !g.is_empty())
            .collect::<Vec<_>>()
            .join(",");

        let entry_id = match db::create_ab_entry(
            &database,
            folder_id,
            &name,
            &display_name,
            &protocol,
            &hostname,
            row.port,
            &username,
            "{}",
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
        imported += 1;

        // Store the password encrypted when a storage key is available
        // (exactly like ab_create_entry: without a key it is not stored).
        if !encryption_key.is_empty() && !row.password.is_empty() {
            let key = match crate::crypto::EncryptionKey::from_hex(&encryption_key) {
                Ok(k) => k,
                Err(e) => {
                    errors.push(json!({"row": row_index, "error": format!("failed to encrypt password: {}", e)}));
                    continue;
                }
            };
            match crate::crypto::encrypt_value(&key, &row.password) {
                Ok(encrypted) => {
                    if let Err(e) =
                        db::store_ab_credential(&database, entry_id, "password", &encrypted)
                    {
                        errors.push(json!({"row": row_index, "error": format!("failed to store password: {}", e)}));
                    }
                }
                Err(e) => {
                    errors.push(json!({"row": row_index, "error": format!("failed to encrypt password: {}", e)}));
                }
            }
        }
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
