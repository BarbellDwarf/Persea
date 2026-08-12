//! Connection-level RBAC permissions.
//!
//! Provides group-based access control for connections:
//! - Connection groups (hierarchical, scoped)
//! - User ↔ group membership
//! - Per-connection permission grants (direct and inherited via groups)

use crate::db::Db;
use rusqlite::params;

// ── Permission enums ──

/// System-wide permissions (not tied to a specific object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemPermission {
    Administer,
    CreateSession,
    CreateConnection,
    CreateConnectionGroup,
    CreateUserGroup,
    Audit,
}

impl SystemPermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Administer => "administer",
            Self::CreateSession => "create_session",
            Self::CreateConnection => "create_connection",
            Self::CreateConnectionGroup => "create_connection_group",
            Self::CreateUserGroup => "create_user_group",
            Self::Audit => "audit",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "administer" => Some(Self::Administer),
            "create_session" => Some(Self::CreateSession),
            "create_connection" => Some(Self::CreateConnection),
            "create_connection_group" => Some(Self::CreateConnectionGroup),
            "create_user_group" => Some(Self::CreateUserGroup),
            "audit" => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Object-level permissions (applied to a specific connection or group).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectPermission {
    Read,
    Connect,
    Update,
    Delete,
    Administer,
}

impl ObjectPermission {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Connect => "connect",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Administer => "administer",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "read" => Some(Self::Read),
            "connect" => Some(Self::Connect),
            "update" => Some(Self::Update),
            "delete" => Some(Self::Delete),
            "administer" => Some(Self::Administer),
            _ => None,
        }
    }
}

/// Entity that can receive permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    User,
    Group,
}

// ── Structs ──

/// A connection group (hierarchical container for connections).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionGroup {
    pub id: String,
    pub name: String,
    pub parent_id: Option<String>,
    pub description: Option<String>,
    pub scope: String,
}

/// A permission entry listing who has what on a connection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PermissionEntry {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub permission: ObjectPermission,
}

// ── DB setup ──

/// Run RBAC migrations. Call from `init_db` or on startup.
pub fn migrate(db: &Db) -> rusqlite::Result<()> {
    let conn = db.lock().unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS rbac_groups (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            parent_id   TEXT REFERENCES rbac_groups(id),
            description TEXT,
            scope       TEXT NOT NULL DEFAULT 'shared',
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS rbac_user_groups (
            user_id     INTEGER NOT NULL REFERENCES users(id),
            group_id    TEXT NOT NULL REFERENCES rbac_groups(id) ON DELETE CASCADE,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (user_id, group_id)
        );

        CREATE TABLE IF NOT EXISTS rbac_permissions (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_id     TEXT NOT NULL,
            entity_type   TEXT NOT NULL CHECK(entity_type IN ('user', 'group')),
            object_type   TEXT NOT NULL CHECK(object_type IN ('connection', 'connection_group')),
            object_id     TEXT NOT NULL,
            permission    TEXT NOT NULL,
            created_at    TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(entity_id, entity_type, object_type, object_id, permission)
        );
        CREATE INDEX IF NOT EXISTS idx_rbac_perm_entity ON rbac_permissions(entity_id, entity_type);
        CREATE INDEX IF NOT EXISTS idx_rbac_perm_object ON rbac_permissions(object_type, object_id);
        ",
    )?;
    Ok(())
}

// ── Connection group CRUD ──

/// Create a connection group. Returns the new group UUID.
pub fn create_group(
    db: &Db,
    name: &str,
    parent_id: Option<&str>,
    description: Option<&str>,
) -> rusqlite::Result<String> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = name.to_string();
        let __db_route_arg_1 = parent_id.map(str::to_string);
        let __db_route_arg_2 = description.map(str::to_string);
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_create_group_pool(
                pool,
                __db_route_arg_0,
                __db_route_arg_1,
                __db_route_arg_2,
            )
        });
    }
    let id = uuid::Uuid::new_v4().to_string();
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO rbac_groups (id, name, parent_id, description) VALUES (?1, ?2, ?3, ?4)",
        params![id, name, parent_id, description],
    )?;
    Ok(id)
}

/// Delete a connection group by ID. Returns true if deleted.
/// Does not cascade — callers must re-parent or delete children first.
pub fn delete_group(db: &Db, group_id: &str) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = group_id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_delete_group_pool(pool, __db_route_arg_0)
        });
    }
    let conn = db.lock().unwrap();
    // Unparent children first
    conn.execute(
        "UPDATE rbac_groups SET parent_id = NULL WHERE parent_id = ?1",
        params![group_id],
    )?;
    let changed = conn.execute("DELETE FROM rbac_groups WHERE id = ?1", params![group_id])?;
    Ok(changed > 0)
}

/// List all connection groups.
pub fn list_groups(db: &Db) -> rusqlite::Result<Vec<ConnectionGroup>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_list_groups_pool(pool)
        });
    }
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id, name, parent_id, description, scope FROM rbac_groups ORDER BY name")?;
    let rows = stmt.query_map([], |row| {
        Ok(ConnectionGroup {
            id: row.get(0)?,
            name: row.get(1)?,
            parent_id: row.get(2)?,
            description: row.get(3)?,
            scope: row.get(4)?,
        })
    })?;
    rows.collect()
}

// ── User ↔ group membership ──

/// Add a user to a group. Idempotent (INSERT OR IGNORE).
pub fn add_user_to_group(db: &Db, user_id: i64, group_id: &str) -> rusqlite::Result<()> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = group_id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_add_user_to_group_pool(pool, user_id, __db_route_arg_0)
        });
    }
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT OR IGNORE INTO rbac_user_groups (user_id, group_id) VALUES (?1, ?2)",
        params![user_id, group_id],
    )?;
    Ok(())
}

/// Remove a user from a group.
pub fn remove_user_from_group(db: &Db, user_id: i64, group_id: &str) -> rusqlite::Result<()> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = group_id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_remove_user_from_group_pool(pool, user_id, __db_route_arg_0)
        });
    }
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM rbac_user_groups WHERE user_id = ?1 AND group_id = ?2",
        params![user_id, group_id],
    )?;
    Ok(())
}

// ── Permission grants ──

/// Grant a connection permission to a user or group. Idempotent.
pub fn grant_connection_permission(
    db: &Db,
    entity_id: &str,
    connection_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<()> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = entity_id.to_string();
        let __db_route_arg_1 = connection_id.to_string();
        let __db_route_arg_2 = permission.as_str().to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_grant_permission_pool(
                pool,
                __db_route_arg_0,
                "connection",
                __db_route_arg_1,
                __db_route_arg_2,
            )
        });
    }
    let conn = db.lock().unwrap();
    // Determine entity_type from prefix: "u:" = user, "g:" = group
    let (entity_type, bare_id) = parse_entity_ref(entity_id);
    conn.execute(
        "INSERT OR IGNORE INTO rbac_permissions (entity_id, entity_type, object_type, object_id, permission)
         VALUES (?1, ?2, 'connection', ?3, ?4)",
        params![bare_id, entity_type, connection_id, permission.as_str()],
    )?;
    Ok(())
}

/// Revoke a connection permission. Returns true if a row was removed.
pub fn revoke_connection_permission(
    db: &Db,
    entity_id: &str,
    connection_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = entity_id.to_string();
        let __db_route_arg_1 = connection_id.to_string();
        let __db_route_arg_2 = permission.as_str().to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_revoke_permission_pool(
                pool,
                __db_route_arg_0,
                "connection",
                __db_route_arg_1,
                __db_route_arg_2,
            )
        });
    }
    let conn = db.lock().unwrap();
    let (entity_type, bare_id) = parse_entity_ref(entity_id);
    let changed = conn.execute(
        "DELETE FROM rbac_permissions
         WHERE entity_id = ?1 AND entity_type = ?2 AND object_type = 'connection' AND object_id = ?3 AND permission = ?4",
        params![bare_id, entity_type, connection_id, permission.as_str()],
    )?;
    Ok(changed > 0)
}

/// Grant a connection-group-level permission. Idempotent.
pub fn grant_group_permission(
    db: &Db,
    entity_id: &str,
    group_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<()> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = entity_id.to_string();
        let __db_route_arg_1 = group_id.to_string();
        let __db_route_arg_2 = permission.as_str().to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_grant_permission_pool(
                pool,
                __db_route_arg_0,
                "connection_group",
                __db_route_arg_1,
                __db_route_arg_2,
            )
        });
    }
    let conn = db.lock().unwrap();
    let (entity_type, bare_id) = parse_entity_ref(entity_id);
    conn.execute(
        "INSERT OR IGNORE INTO rbac_permissions (entity_id, entity_type, object_type, object_id, permission)
         VALUES (?1, ?2, 'connection_group', ?3, ?4)",
        params![bare_id, entity_type, group_id, permission.as_str()],
    )?;
    Ok(())
}

/// Check if a user has a specific permission on a connection.
///
/// Resolution order (fail-closed):
/// 1. Direct user permission on the connection
/// 2. Group permission on the connection (user must be member of the group)
/// 3. Group permission on any ancestor connection group (recursive CTE walks `parent_id`)
/// 4. Denied if none match
pub fn check_connection_permission(
    db: &Db,
    user_id: i64,
    connection_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = connection_id.to_string();
        let __db_route_arg_1 = permission.as_str().to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_check_connection_permission_pool(
                pool,
                user_id,
                __db_route_arg_0,
                __db_route_arg_1,
            )
        });
    }
    let conn = db.lock().unwrap();

    // 1. Direct user permission on this connection
    let direct: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM rbac_permissions
            WHERE entity_id = ?1 AND entity_type = 'user'
              AND object_type = 'connection' AND object_id = ?2
              AND permission = ?3
        )",
        params![user_id, connection_id, permission.as_str()],
        |row| row.get(0),
    )?;
    if direct {
        return Ok(true);
    }

    // 2+3. Group permissions on the connection or ancestor groups via recursive CTE.
    // The CTE walks from the connection's group_id up through parent_id chain.
    // For each group in the chain, check if the user is a member and has the permission.
    // (SQLite requires the recursive term to reference the CTE via JOIN, not
    // via an IN-subquery — a subquery reference makes prepare fail with
    // "circular reference", which turned every check into a silent deny.)
    let inherited: bool = conn.query_row(
        "WITH RECURSIVE group_ancestors(group_id) AS (
            -- Base: groups granted directly on this connection
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection'
              AND object_id = ?2 AND permission = ?3
            UNION
            -- Walk ancestor groups via parent_id
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
            UNION
            -- Groups granted on connection-group objects that are in the chain
            SELECT DISTINCT p.entity_id
            FROM rbac_permissions p
            JOIN group_ancestors ga ON p.object_id = ga.group_id
            WHERE p.entity_type = 'group' AND p.object_type = 'connection_group'
              AND p.permission = ?3
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = ?1
        )",
        params![user_id, connection_id, permission.as_str()],
        |row| row.get(0),
    )?;
    Ok(inherited)
}

/// List all permissions for a connection.
pub fn list_connection_permissions(
    db: &Db,
    connection_id: &str,
) -> rusqlite::Result<Vec<PermissionEntry>> {
    if crate::db::pool_active() {
        let __db_route_arg_0 = connection_id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_list_connection_permissions_pool(pool, __db_route_arg_0)
        });
    }
    let conn = db.lock().unwrap();
    let mut stmt = conn.prepare(
        "SELECT entity_id, entity_type, permission
         FROM rbac_permissions
         WHERE object_type = 'connection' AND object_id = ?1
         ORDER BY entity_type, entity_id",
    )?;
    let rows = stmt.query_map(params![connection_id], |row| {
        let eid: String = row.get(0)?;
        let etype: String = row.get(1)?;
        let perm: String = row.get(2)?;
        Ok(PermissionEntry {
            entity_id: eid,
            entity_type: match etype.as_str() {
                "group" => EntityType::Group,
                _ => EntityType::User,
            },
            permission: ObjectPermission::parse(&perm).unwrap_or(ObjectPermission::Read),
        })
    })?;
    rows.collect()
}

// ── Helpers ──

/// Parse an entity reference like "u:123" or "g:abc-def" into (entity_type, bare_id).
fn parse_entity_ref(entity_id: &str) -> (&'static str, &str) {
    if let Some(rest) = entity_id.strip_prefix("u:") {
        ("user", rest)
    } else if let Some(rest) = entity_id.strip_prefix("g:") {
        ("group", rest)
    } else {
        // Default: treat as user
        ("user", entity_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_as_str_roundtrip() {
        for perm in [
            ObjectPermission::Read,
            ObjectPermission::Connect,
            ObjectPermission::Update,
            ObjectPermission::Delete,
            ObjectPermission::Administer,
        ] {
            assert_eq!(ObjectPermission::parse(perm.as_str()), Some(perm));
        }
    }

    #[test]
    fn test_system_permission_as_str_roundtrip() {
        for perm in [
            SystemPermission::Administer,
            SystemPermission::CreateSession,
            SystemPermission::CreateConnection,
            SystemPermission::CreateConnectionGroup,
            SystemPermission::CreateUserGroup,
            SystemPermission::Audit,
        ] {
            assert_eq!(SystemPermission::parse(perm.as_str()), Some(perm));
        }
    }

    #[test]
    fn test_parse_entity_ref() {
        assert_eq!(parse_entity_ref("u:42"), ("user", "42"));
        assert_eq!(parse_entity_ref("g:abc"), ("group", "abc"));
        assert_eq!(parse_entity_ref("bare"), ("user", "bare"));
    }
}
