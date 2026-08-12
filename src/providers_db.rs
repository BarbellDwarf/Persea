//! DB-backed auth provider configuration store.
//!
//! Admin-configured auth providers (oidc, ldap, saml, radius, database, totp)
//! live in the `auth_providers` table and are merged into the auth chain at
//! startup alongside config-file providers. This module owns the DB side
//! only: schema bootstrap, CRUD, ordering (position), enable/disable, and
//! per-type config validation. The merge itself is wired by the orchestrator
//! in `main.rs` — `load_providers` returns every DB provider in chain order
//! (`position`, then `id`) as the input for that merge.
//!
//! Schema (see `migrations/*/004-auth-providers.sql`):
//!
//! ```text
//! auth_providers (
//!     id         INTEGER PRIMARY KEY AUTOINCREMENT,
//!     name       TEXT NOT NULL,
//!     type       TEXT NOT NULL,
//!     enabled    INTEGER NOT NULL DEFAULT 1,
//!     position   INTEGER NOT NULL DEFAULT 0,
//!     config     TEXT NOT NULL DEFAULT '{}',   -- JSON object
//!     created_at TEXT NOT NULL DEFAULT (datetime('now')),
//!     updated_at TEXT NOT NULL DEFAULT (datetime('now'))
//! )
//! ```
//!
//! `config` is a JSON object whose required keys depend on `type` (see
//! [`validate_config`]).

use crate::db::Db;
use rusqlite::{params, Connection, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Valid provider types. Must match the dropdown in `auth.html`.
pub const PROVIDER_TYPES: &[&str] = &["ldap", "saml", "radius", "database", "totp", "oidc"];

/// A row from the `auth_providers` table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbProvider {
    pub id: i64,
    pub name: String,
    /// Provider type, one of [`PROVIDER_TYPES`].
    #[serde(rename = "type")]
    pub provider_type: String,
    pub enabled: bool,
    /// Chain order; lower runs first.
    pub position: i64,
    /// Free-form JSON config object (may contain secrets).
    pub config: Value,
    pub created_at: String,
    pub updated_at: String,
}

/// Direction for [`move_provider`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveDirection {
    Up,
    Down,
}

/// Create the `auth_providers` table if it does not exist.
///
/// The app's schema migrations live in `src/db.rs` (manual rusqlite
/// `execute_batch` — the `migrations/*.sql` files are reference DDL, not
/// auto-applied). The orchestrator should call this from `init_db` (or from
/// startup) so the table exists before the chain merge; tests call it
/// directly.
pub fn migrate(db: &Db) -> rusqlite::Result<()> {
    if crate::db::pool_active() {
        // The SQLx migrations create auth_providers (migrations/*/004); the
        // pool schema is already in place — nothing to do here.
        return Ok(());
    }
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS auth_providers (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            type       TEXT NOT NULL,
            enabled    INTEGER NOT NULL DEFAULT 1,
            position   INTEGER NOT NULL DEFAULT 0,
            config     TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
        -- Provider names are unique so the auth-chain key `db-provider-{name}`
        -- cannot collide; the API maps the resulting conflict to 409.
        CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_name
            ON auth_providers(name);",
    )
}

/// Load all DB-configured providers in chain order (`position`, then `id`).
pub fn load_providers(db: &Db) -> rusqlite::Result<Vec<DbProvider>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_load_pool(pool)
        });
    }
    let conn = db.lock().unwrap();
    load_providers_on(&conn)
}

/// Load providers ordered by chain position from a given connection. Exposed
/// so transactional callers (move/insert) read the list inside their own
/// transaction instead of racing concurrent writes.
fn load_providers_on(conn: &Connection) -> rusqlite::Result<Vec<DbProvider>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, type, enabled, position, config, created_at, updated_at
         FROM auth_providers ORDER BY position, id",
    )?;
    let rows = stmt.query_map([], row_to_provider)?;
    rows.collect()
}

/// Fetch a single provider by id, or `None` if it does not exist.
pub fn get_provider(db: &Db, id: i64) -> rusqlite::Result<Option<DbProvider>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_get_pool(pool, id)
        });
    }
    let conn = db.lock().unwrap();
    query_provider(&conn, id)
}

/// Insert a new provider at the end of the chain. Returns the inserted row.
pub fn insert_provider(
    db: &Db,
    name: &str,
    provider_type: &str,
    config: &Value,
) -> rusqlite::Result<DbProvider> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = name.to_string();
        let __db_route_arg_1 = provider_type.to_string();
        let __db_route_arg_2 = config.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_insert_pool(
                pool,
                __db_route_arg_0,
                __db_route_arg_1,
                __db_route_arg_2,
            )
        });
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    let next_position: i64 = tx.query_row(
        "SELECT COALESCE(MAX(position), -1) + 1 FROM auth_providers",
        [],
        |row| row.get(0),
    )?;
    tx.execute(
        "INSERT INTO auth_providers (name, type, enabled, position, config)
         VALUES (?1, ?2, 1, ?3, ?4)",
        params![name, provider_type, next_position, config.to_string()],
    )?;
    let id = tx.last_insert_rowid();
    let provider = query_provider(&tx, id)?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    tx.commit()?;
    Ok(provider)
}

/// Replace a provider's config JSON. Returns `false` if the id is unknown.
pub fn update_config(db: &Db, id: i64, config: &Value) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = config.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_update_config_pool(pool, id, __db_route_arg_0)
        });
    }
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE auth_providers SET config = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![config.to_string(), id],
    )?;
    Ok(changed > 0)
}

/// Flip a provider's `enabled` flag. Returns `false` if the id is unknown.
pub fn set_enabled(db: &Db, id: i64, enabled: bool) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_set_enabled_pool(pool, id, enabled)
        });
    }
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE auth_providers SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![i32::from(enabled), id],
    )?;
    Ok(changed > 0)
}

/// Delete a provider. Returns `false` if the id is unknown.
pub fn delete_provider(db: &Db, id: i64) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_delete_pool(pool, id)
        });
    }
    let conn = db.lock().unwrap();
    let changed = conn.execute("DELETE FROM auth_providers WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

/// Swap a provider's position with its neighbour (`Up` = earlier in the
/// chain, `Down` = later). Moving the first provider up or the last one down
/// is a no-op that still returns the provider. Returns `None` if the id is
/// unknown.
pub fn move_provider(
    db: &Db,
    id: i64,
    direction: MoveDirection,
) -> rusqlite::Result<Option<DbProvider>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::providers_move_pool(pool, id, direction)
        });
    }
    let mut conn = db.lock().unwrap();
    let tx = conn.transaction()?;
    // Read the ordered list inside the transaction so a concurrent move
    // cannot produce duplicate positions.
    let providers = load_providers_on(&tx)?;
    let idx = match providers.iter().position(|p| p.id == id) {
        Some(i) => i,
        None => return Ok(None),
    };
    let neighbor_idx = match direction {
        MoveDirection::Up => {
            if idx == 0 {
                return Ok(Some(providers[idx].clone()));
            }
            idx - 1
        }
        MoveDirection::Down => {
            if idx + 1 >= providers.len() {
                return Ok(Some(providers[idx].clone()));
            }
            idx + 1
        }
    };
    // Swap positions; target takes the neighbour's, neighbour takes the target's.
    tx.execute(
        "UPDATE auth_providers SET position = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![providers[neighbor_idx].position, id],
    )?;
    tx.execute(
        "UPDATE auth_providers SET position = ?1, updated_at = datetime('now') WHERE id = ?2",
        params![providers[idx].position, providers[neighbor_idx].id],
    )?;
    tx.commit()?;
    query_provider(&conn, id)
}

/// Validate a config JSON object against the required fields for a provider
/// type. Returns `Ok(())` or a human-readable validation error.
///
/// * `oidc` — requires `issuer_url`, `client_id`, `client_secret`,
///   `redirect_uri`; `groups_claim` is optional.
/// * `ldap` — requires `url`, `bind_dn`, `search_base`.
/// * `saml` — requires `idp_metadata_url`, `entity_id`, `acs_url`.
/// * `radius` — requires `hostname`, `auth_port`, `secret`.
/// * `database` / `totp` — no required fields.
pub fn validate_config(provider_type: &str, config: &Value) -> Result<(), String> {
    let required: &[&str] = match provider_type {
        "oidc" => &["issuer_url", "client_id", "client_secret", "redirect_uri"],
        "ldap" => &["url", "bind_dn", "search_base"],
        "saml" => &["idp_metadata_url", "entity_id", "acs_url"],
        "radius" => &["hostname", "auth_port", "secret"],
        "database" | "totp" => &[],
        other => return Err(format!("unknown provider type: {other}")),
    };
    for key in required {
        if !field_present(config.get(*key)) {
            return Err(format!("provider type '{provider_type}' requires '{key}'"));
        }
    }
    Ok(())
}

/// A required field counts as present when it is a non-empty string or any
/// number (ports, timeouts are sent as numbers by the UI).
fn field_present(v: Option<&Value>) -> bool {
    match v {
        Some(Value::String(s)) => !s.trim().is_empty(),
        Some(Value::Number(_)) => true,
        _ => false,
    }
}

fn query_provider(conn: &Connection, id: i64) -> rusqlite::Result<Option<DbProvider>> {
    conn.query_row(
        "SELECT id, name, type, enabled, position, config, created_at, updated_at
         FROM auth_providers WHERE id = ?1",
        params![id],
        row_to_provider,
    )
    .map(Some)
    .or_else(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => Ok(None),
        other => Err(other),
    })
}

fn row_to_provider(row: &Row) -> rusqlite::Result<DbProvider> {
    let config_raw: String = row.get(5)?;
    let config: Value = serde_json::from_str(&config_raw).unwrap_or_else(|_| json!({}));
    Ok(DbProvider {
        id: row.get(0)?,
        name: row.get(1)?,
        provider_type: row.get(2)?,
        enabled: row.get::<_, i32>(3)? != 0,
        position: row.get(4)?,
        config,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::init_db;

    fn test_db() -> Db {
        let db = init_db(std::path::Path::new(":memory:")).expect("test db");
        migrate(&db).expect("migrate");
        db
    }

    fn oidc_config() -> Value {
        json!({
            "issuer_url": "https://auth.example.com",
            "client_id": "persea",
            "client_secret": "s3cret",
            "redirect_uri": "https://persea.example.com/auth/callback",
            "groups_claim": "groups"
        })
    }

    #[test]
    fn insert_appends_at_end_of_chain() {
        let db = test_db();
        let first = insert_provider(&db, "Google", "oidc", &oidc_config()).unwrap();
        let second = insert_provider(&db, "Keycloak", "oidc", &oidc_config()).unwrap();
        assert_eq!(first.position, 0);
        assert_eq!(second.position, 1);
        let all = load_providers(&db).unwrap();
        assert_eq!(
            all.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            vec!["Google", "Keycloak"]
        );
    }

    #[test]
    fn insert_config_round_trips() {
        let db = test_db();
        let p = insert_provider(&db, "Google", "oidc", &oidc_config()).unwrap();
        assert_eq!(p.config["client_secret"], "s3cret");
        assert_eq!(p.config["groups_claim"], "groups");
    }

    #[test]
    fn set_enabled_flips_flag() {
        let db = test_db();
        let p = insert_provider(&db, "Google", "oidc", &oidc_config()).unwrap();
        assert!(p.enabled);
        assert!(set_enabled(&db, p.id, false).unwrap());
        assert!(!get_provider(&db, p.id).unwrap().unwrap().enabled);
        assert!(set_enabled(&db, p.id, true).unwrap());
        assert!(get_provider(&db, p.id).unwrap().unwrap().enabled);
    }

    #[test]
    fn set_enabled_unknown_id_returns_false() {
        let db = test_db();
        assert!(!set_enabled(&db, 999, false).unwrap());
    }

    #[test]
    fn move_provider_up_and_down() {
        let db = test_db();
        let a = insert_provider(&db, "A", "oidc", &oidc_config()).unwrap();
        let b = insert_provider(
            &db,
            "B",
            "ldap",
            &json!({"url": "ldap://x", "bind_dn": "cn=x", "search_base": "ou=x"}),
        )
        .unwrap();
        let c = insert_provider(&db, "C", "database", &json!({})).unwrap();

        let moved = move_provider(&db, b.id, MoveDirection::Up)
            .unwrap()
            .unwrap();
        assert_eq!(moved.position, 0);
        let order: Vec<String> = load_providers(&db)
            .unwrap()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(order, vec!["B", "A", "C"]);

        let moved = move_provider(&db, b.id, MoveDirection::Down)
            .unwrap()
            .unwrap();
        assert_eq!(moved.position, 1);
        let order: Vec<String> = load_providers(&db)
            .unwrap()
            .iter()
            .map(|p| p.name.clone())
            .collect();
        assert_eq!(order, vec!["A", "B", "C"]);

        // Edge: first up and last down are no-ops.
        let moved = move_provider(&db, a.id, MoveDirection::Up)
            .unwrap()
            .unwrap();
        assert_eq!(moved.position, 0);
        let moved = move_provider(&db, c.id, MoveDirection::Down)
            .unwrap()
            .unwrap();
        assert_eq!(moved.position, 2);
    }

    #[test]
    fn move_provider_unknown_id_returns_none() {
        let db = test_db();
        assert!(move_provider(&db, 999, MoveDirection::Up)
            .unwrap()
            .is_none());
    }

    #[test]
    fn delete_provider_removes_row() {
        let db = test_db();
        let p = insert_provider(&db, "X", "database", &json!({})).unwrap();
        assert!(delete_provider(&db, p.id).unwrap());
        assert!(get_provider(&db, p.id).unwrap().is_none());
        assert!(!delete_provider(&db, p.id).unwrap());
    }

    #[test]
    fn validate_config_accepts_oidc_with_required_fields() {
        assert!(validate_config("oidc", &oidc_config()).is_ok());
        // groups_claim is optional.
        let mut cfg = oidc_config();
        cfg.as_object_mut().unwrap().remove("groups_claim");
        assert!(validate_config("oidc", &cfg).is_ok());
    }

    #[test]
    fn validate_config_rejects_missing_oidc_fields() {
        let cfg = json!({"issuer_url": "https://auth.example.com"});
        let err = validate_config("oidc", &cfg).unwrap_err();
        assert!(err.contains("client_id"), "got: {err}");
    }

    #[test]
    fn validate_config_accepts_numeric_radius_port() {
        let cfg = json!({"hostname": "radius.example.com", "auth_port": 1812, "secret": "x"});
        assert!(validate_config("radius", &cfg).is_ok());
    }

    #[test]
    fn validate_config_accepts_empty_database_config() {
        assert!(validate_config("database", &json!({})).is_ok());
        assert!(validate_config("totp", &json!({})).is_ok());
    }

    #[test]
    fn validate_config_rejects_unknown_type() {
        assert!(validate_config("fido", &json!({})).is_err());
    }
}
