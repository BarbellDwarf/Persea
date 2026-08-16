//! Connection-level RBAC permissions.
//!
//! Provides group-based access control for connections:
//! - Connection groups (hierarchical, scoped)
//! - User ↔ group membership
//! - Per-connection permission grants (direct and inherited via groups)

use crate::db::Db;
use rusqlite::params;
use rusqlite::OptionalExtension;

// ── Permission enums ──

/// System-wide permissions (not tied to a specific object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemPermission {
    /// Full system administration; bypasses the other checks.
    Administer,
    /// Create ad-hoc sessions outside the address book.
    CreateSession,
    /// Create and edit connections.
    CreateConnection,
    /// Create connection groups.
    CreateConnectionGroup,
    /// Create user groups.
    CreateUserGroup,
    /// View audit logs and reports.
    Audit,
}

impl SystemPermission {
    /// Snake-case string form used in storage and the API.
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

    /// Parse the snake-case string form; `None` for unknown names.
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
    /// See the connection's metadata.
    Read,
    /// Open a session to the connection.
    Connect,
    /// Modify the connection.
    Update,
    /// Delete the connection.
    Delete,
    /// Grant and revoke permissions on the connection.
    Administer,
}

impl ObjectPermission {
    /// Snake-case string form used in storage and the API.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Connect => "connect",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Administer => "administer",
        }
    }

    /// Parse the snake-case string form; `None` for unknown names.
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
    /// A direct grant to one user.
    User,
    /// A grant inherited by all group members.
    Group,
}

// ── Structs ──

/// A connection group (hierarchical container for connections).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnectionGroup {
    /// UUID of the group.
    pub id: String,
    /// Display name, unique among groups.
    pub name: String,
    /// Parent group ID; `None` for top-level groups.
    pub parent_id: Option<String>,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Group scope, e.g. shared or a per-user scope.
    pub scope: String,
}

/// A permission entry listing who has what on a connection.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PermissionEntry {
    /// ID of the user or group holding the grant.
    pub entity_id: String,
    /// Whether the holder is a user or a group.
    pub entity_type: EntityType,
    /// The granted permission.
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

        -- Custom roles (T05): named global permission bundles assignable to
        -- users via users.custom_role_id. Legacy SQLite runs without
        -- PRAGMA foreign_keys, so delete_custom_role clears the permission
        -- rows and the users references explicitly.
        CREATE TABLE IF NOT EXISTS custom_roles (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS custom_role_permissions (
            role_id     TEXT NOT NULL REFERENCES custom_roles(id) ON DELETE CASCADE,
            permission  TEXT NOT NULL,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            UNIQUE(role_id, permission)
        );
        CREATE INDEX IF NOT EXISTS idx_custom_role_perms_role ON custom_role_permissions(role_id);
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
/// 2. Direct user permission on the connection's address-book folder
/// 3. Group permission on the connection (user must be member of the group)
/// 4. Group permission on the connection's address-book folder
/// 5. Group permission on any ancestor connection group (recursive CTE walks `parent_id`)
/// 6. Folder grants cascade down the slash-path hierarchy: a grant on
///    "Clients" applies to entries in "Clients/Acme" (direct user and
///    group grants on every ancestor folder)
/// 7. Denied if none match
pub fn check_connection_permission(
    db: &Db,
    user_id: i64,
    connection_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<bool> {
    // Address-book connections are keyed "scope/folder/entry". Folder-level
    // grants (`connection_group` objects, keyed by the folder path) cascade
    // to the entries beneath the folder, so the folder path is resolved here
    // and seeded into the walk below. Non-address-book ids resolve to no
    // folder and keep the old behavior.
    let folder_path = ab_folder_path_for_connection(db, connection_id);
    if crate::db::pool_active() {
        let __db_route_arg_0 = connection_id.to_string();
        let __db_route_arg_1 = permission.as_str().to_string();
        let __db_route_arg_2 = folder_path;
        let __db_route_arg_3 = __db_route_arg_2
            .as_deref()
            .map(ab_folder_ancestors)
            .unwrap_or_default();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| async move {
            let on_connection = crate::db::rbac_check_connection_permission_pool(
                pool,
                user_id,
                __db_route_arg_0,
                __db_route_arg_1.clone(),
            )
            .await?;
            if on_connection {
                return Ok(true);
            }
            match __db_route_arg_2 {
                Some(folder) => {
                    if crate::db::rbac_check_group_object_permission_pool(
                        pool,
                        user_id,
                        folder,
                        __db_route_arg_1.clone(),
                    )
                    .await?
                    {
                        return Ok(true);
                    }
                    for ancestor in &__db_route_arg_3 {
                        if crate::db::rbac_check_group_object_permission_pool(
                            pool,
                            user_id,
                            ancestor.clone(),
                            __db_route_arg_1.clone(),
                        )
                        .await?
                        {
                            return Ok(true);
                        }
                    }
                    Ok(false)
                }
                None => Ok(false),
            }
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

    // 2. Direct user permission on the connection's address-book folder
    if let Some(folder) = folder_path.as_deref() {
        let direct_folder: bool = conn.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM rbac_permissions
                WHERE entity_id = ?1 AND entity_type = 'user'
                  AND object_type = 'connection_group' AND object_id = ?2
                  AND permission = ?3
            )",
            params![user_id, folder, permission.as_str()],
            |row| row.get(0),
        )?;
        if direct_folder {
            return Ok(true);
        }
    }

    // 3+4+5. Group permissions on the connection, its address-book folder,
    // or ancestor groups via recursive CTE. The CTE walks from the granted
    // groups up through parent_id chain; the user must be a member of one
    // of the groups in the chain. (SQLite requires the recursive term to
    // reference the CTE via JOIN, not via an IN-subquery — a subquery
    // reference makes prepare fail with "circular reference", which turned
    // every check into a silent deny.)
    let inherited: bool = conn.query_row(
        "WITH RECURSIVE group_ancestors(group_id) AS (
            -- Base: groups granted directly on this connection
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection'
              AND object_id = ?2 AND permission = ?3
            UNION
            -- Base: groups granted on the connection's address-book folder
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection_group'
              AND object_id = ?4 AND permission = ?3
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
        params![
            user_id,
            connection_id,
            permission.as_str(),
            folder_path.as_deref().unwrap_or("")
        ],
        |row| row.get(0),
    )?;
    drop(conn);
    if inherited {
        return Ok(true);
    }

    // 6. Folder grants cascade down the slash-path hierarchy: a Connect
    // grant on "Clients" applies to entries in "Clients/Acme". Each
    // ancestor folder runs the same direct-user + group-CTE walk.
    if let Some(folder) = folder_path.as_deref() {
        for ancestor in ab_folder_ancestors(folder) {
            if check_group_object_permission(db, user_id, &ancestor, permission)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Slash-path ancestors of a folder, deepest first, excluding the folder
/// itself: "Clients/Acme" → ["Clients"].
fn ab_folder_ancestors(folder: &str) -> Vec<String> {
    let mut ancestors = Vec::new();
    let mut current = folder;
    while let Some((parent, _)) = current.rsplit_once('/') {
        if parent.is_empty() {
            break;
        }
        ancestors.push(parent.to_string());
        current = parent;
    }
    ancestors
}

/// Address-book folder path for a connection id ("scope/folder/entry"),
/// resolved against the address book so only real folders seed the grant
/// walk. `None` for non-address-book connection ids.
fn ab_folder_path_for_connection(db: &Db, connection_id: &str) -> Option<String> {
    let mut parts: Vec<&str> = connection_id.split('/').collect();
    if parts.len() < 3 {
        return None;
    }
    let scope = parts[0];
    let entry = parts.pop().unwrap_or_default();
    if scope.is_empty() || entry.is_empty() {
        return None;
    }
    let folder = parts[1..].join("/");
    if folder.is_empty() {
        return None;
    }
    crate::db::get_ab_folder(db, scope, &folder)
        .ok()
        .map(|_| folder)
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

// ── Custom roles ──
//
// A custom role is a named bundle of GLOBAL permissions (the existing
// SystemPermission/ObjectPermission vocabulary) assignable to a user via
// `users.custom_role_id`. Custom roles are ADDITIVE on top of the fixed
// 4-tier role floor; admin always bypasses every check.

/// A named permission bundle assignable to a user.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CustomRole {
    /// UUID of the role.
    pub id: String,
    /// Display name, unique among roles.
    pub name: String,
    /// Optional description shown in the admin UI.
    pub description: Option<String>,
    /// Snake-case permission names in the bundle.
    pub permissions: Vec<String>,
    /// Creation timestamp.
    pub created_at: String,
}

fn custom_role_from_row(row: &rusqlite::Row) -> rusqlite::Result<CustomRole> {
    Ok(CustomRole {
        id: row.get(0)?,
        name: row.get(1)?,
        description: row.get(2)?,
        permissions: Vec::new(),
        created_at: row.get(3)?,
    })
}

/// List all custom roles with their permission bundles.
pub fn list_custom_roles(db: &Db) -> rusqlite::Result<Vec<CustomRole>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_list_custom_roles_pool(pool)
        });
    }
    let conn = db.lock().unwrap();
    let mut roles = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, name, description, created_at FROM custom_roles ORDER BY name")?;
        let rows = stmt.query_map([], custom_role_from_row)?;
        for row in rows {
            roles.push(row?);
        }
    }
    let mut stmt = conn
        .prepare("SELECT role_id, permission FROM custom_role_permissions ORDER BY permission")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (role_id, permission) = row?;
        if let Some(role) = roles.iter_mut().find(|r| r.id == role_id) {
            role.permissions.push(permission);
        }
    }
    Ok(roles)
}

/// Fetch one custom role by id (None when it does not exist).
pub fn get_custom_role(db: &Db, id: &str) -> rusqlite::Result<Option<CustomRole>> {
    if crate::db::pool_active() {
        let __id = id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_get_custom_role_pool(pool, __id)
        });
    }
    let conn = db.lock().unwrap();
    let mut role = conn
        .query_row(
            "SELECT id, name, description, created_at FROM custom_roles WHERE id = ?1",
            params![id],
            custom_role_from_row,
        )
        .optional()?;
    if let Some(role_ref) = role.as_mut() {
        load_role_permissions(&conn, role_ref)?;
    }
    Ok(role)
}

/// Fetch one custom role by name (None when it does not exist).
pub fn get_custom_role_by_name(db: &Db, name: &str) -> rusqlite::Result<Option<CustomRole>> {
    if crate::db::pool_active() {
        let __name = name.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_get_custom_role_by_name_pool(pool, __name)
        });
    }
    let conn = db.lock().unwrap();
    let mut role = conn
        .query_row(
            "SELECT id, name, description, created_at FROM custom_roles WHERE name = ?1",
            params![name],
            custom_role_from_row,
        )
        .optional()?;
    if let Some(role_ref) = role.as_mut() {
        load_role_permissions(&conn, role_ref)?;
    }
    Ok(role)
}

/// Create a custom role. Returns the new role id. Duplicate names surface
/// as a UNIQUE constraint error (mapped to 409 by the handlers).
pub fn create_custom_role(
    db: &Db,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
) -> rusqlite::Result<String> {
    if crate::db::pool_active() {
        let __name = name.to_string();
        let __desc = description.map(str::to_string);
        let __perms = permissions.to_vec();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_create_custom_role_pool(pool, __name, __desc, __perms)
        });
    }
    let id = uuid::Uuid::new_v4().to_string();
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO custom_roles (id, name, description) VALUES (?1, ?2, ?3)",
        params![id, name, description],
    )?;
    insert_role_permissions(&conn, &id, permissions)?;
    Ok(id)
}

/// Update a custom role's name/description and REPLACE its permission
/// bundle. Returns false when the role does not exist.
pub fn update_custom_role(
    db: &Db,
    id: &str,
    name: &str,
    description: Option<&str>,
    permissions: &[String],
) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __id = id.to_string();
        let __name = name.to_string();
        let __desc = description.map(str::to_string);
        let __perms = permissions.to_vec();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_update_custom_role_pool(pool, __id, __name, __desc, __perms)
        });
    }
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE custom_roles SET name = ?1, description = ?2 WHERE id = ?3",
        params![name, description, id],
    )?;
    if changed == 0 {
        return Ok(false);
    }
    conn.execute(
        "DELETE FROM custom_role_permissions WHERE role_id = ?1",
        params![id],
    )?;
    insert_role_permissions(&conn, id, permissions)?;
    Ok(true)
}

/// Delete a custom role: removes its permission rows, clears
/// `users.custom_role_id` references (set NULL) and deletes the role.
/// Returns false when the role does not exist.
pub fn delete_custom_role(db: &Db, id: &str) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __id = id.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_delete_custom_role_pool(pool, __id)
        });
    }
    let conn = db.lock().unwrap();
    conn.execute(
        "DELETE FROM custom_role_permissions WHERE role_id = ?1",
        params![id],
    )?;
    conn.execute(
        "UPDATE users SET custom_role_id = NULL WHERE custom_role_id = ?1",
        params![id],
    )?;
    let changed = conn.execute("DELETE FROM custom_roles WHERE id = ?1", params![id])?;
    Ok(changed > 0)
}

/// Assign (or clear, with `None`) a user's custom role by email. Returns
/// false when the user does not exist. The fixed 4-tier role is untouched —
/// custom roles are additive.
pub fn set_user_custom_role(db: &Db, email: &str, role_id: Option<&str>) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __email = email.to_string();
        let __role_id = role_id.map(str::to_string);
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_set_user_custom_role_pool(pool, __email, __role_id)
        });
    }
    let conn = db.lock().unwrap();
    let changed = conn.execute(
        "UPDATE users SET custom_role_id = ?1 WHERE email = ?2",
        params![role_id, email],
    )?;
    Ok(changed > 0)
}

/// Fetch the custom role assigned to a user (None when unassigned).
pub fn user_custom_role(db: &Db, user_id: i64) -> rusqlite::Result<Option<CustomRole>> {
    if crate::db::pool_active() {
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_user_custom_role_pool(pool, user_id)
        });
    }
    let conn = db.lock().unwrap();
    let mut role = conn
        .query_row(
            "SELECT cr.id, cr.name, cr.description, cr.created_at
             FROM custom_roles cr
             JOIN users u ON u.custom_role_id = cr.id
             WHERE u.id = ?1",
            params![user_id],
            custom_role_from_row,
        )
        .optional()?;
    if let Some(role_ref) = role.as_mut() {
        load_role_permissions(&conn, role_ref)?;
    }
    Ok(role)
}

/// True when the user's custom role bundle contains the permission
/// (global scope — no per-object grants involved).
pub fn user_has_custom_permission(
    db: &Db,
    user_id: i64,
    permission: &str,
) -> rusqlite::Result<bool> {
    if crate::db::pool_active() {
        let __permission = permission.to_string();
        return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
            crate::db::rbac_user_has_custom_permission_pool(pool, user_id, __permission)
        });
    }
    let conn = db.lock().unwrap();
    conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM custom_role_permissions crp
            JOIN users u ON u.custom_role_id = crp.role_id
            WHERE u.id = ?1 AND crp.permission = ?2
        )",
        params![user_id, permission],
        |row| row.get(0),
    )
}

/// Effective object-permission check: union of the custom role bundle
/// (global scope) and the existing `rbac_permissions` grants (direct user
/// grants + group-inherited CTE). Admin always allowed — callers branch on
/// `has_role("admin")` before calling this, so no grant keeps the current
/// behavior (403 / admin-only) for everyone else.
pub fn user_has_object_permission(
    db: &Db,
    user_id: i64,
    object_type: &str,
    object_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<bool> {
    if user_has_custom_permission(db, user_id, permission.as_str())? {
        return Ok(true);
    }
    match object_type {
        "connection" => check_connection_permission(db, user_id, object_id, permission),
        "connection_group" => {
            if crate::db::pool_active() {
                let __object_id = object_id.to_string();
                let __permission = permission.as_str().to_string();
                return crate::db::pool_call(move |pool: &'static crate::db_pool::DbPool| {
                    crate::db::rbac_check_group_object_permission_pool(
                        pool,
                        user_id,
                        __object_id,
                        __permission,
                    )
                });
            }
            check_group_object_permission(db, user_id, object_id, permission)
        }
        _ => Ok(false),
    }
}

/// System-permission check: only the custom role bundle can carry system
/// permissions (`rbac_permissions` has no system-permission rows).
pub fn user_has_system_permission(
    db: &Db,
    user_id: i64,
    permission: SystemPermission,
) -> rusqlite::Result<bool> {
    user_has_custom_permission(db, user_id, permission.as_str())
}

/// Identity-level system-permission check: admin short-circuits, otherwise
/// the user's custom role bundle decides (fail closed for unknown users).
pub fn identity_has_system_permission(
    db: &Db,
    identity: &crate::auth::AuthIdentity,
    permission: SystemPermission,
) -> bool {
    if identity.has_role("admin") {
        return true;
    }
    match identity_user_id(db, identity) {
        Some(user_id) => user_has_system_permission(db, user_id, permission).unwrap_or(false),
        None => false,
    }
}

/// Identity-level effective object-permission check (see
/// `user_has_object_permission`); admin short-circuits.
pub fn identity_has_object_permission(
    db: &Db,
    identity: &crate::auth::AuthIdentity,
    object_type: &str,
    object_id: &str,
    permission: ObjectPermission,
) -> bool {
    if identity.has_role("admin") {
        return true;
    }
    match identity_user_id(db, identity) {
        Some(user_id) => {
            user_has_object_permission(db, user_id, object_type, object_id, permission)
                .unwrap_or(false)
        }
        None => false,
    }
}

/// Identity-level custom-bundle check (admin short-circuits). Used where a
/// per-object grant cannot be resolved (e.g. entry-level ACLs keyed by
/// folder id + entry name instead of the full connection id).
pub fn identity_has_custom_permission(
    db: &Db,
    identity: &crate::auth::AuthIdentity,
    permission: &str,
) -> bool {
    if identity.has_role("admin") {
        return true;
    }
    match identity_user_id(db, identity) {
        Some(user_id) => user_has_custom_permission(db, user_id, permission).unwrap_or(false),
        None => false,
    }
}

/// Numeric DB id for a user identity (None for API keys / unknown users).
fn identity_user_id(db: &Db, identity: &crate::auth::AuthIdentity) -> Option<i64> {
    match identity {
        crate::auth::AuthIdentity::User { email, .. } => {
            crate::db::get_user_by_email(db, email).ok().map(|u| u.id)
        }
        crate::auth::AuthIdentity::ApiKey(_) => None,
    }
}

/// Insert a permission bundle, de-duplicated so the UNIQUE(role_id,
/// permission) constraint cannot fire on duplicate payload entries.
fn insert_role_permissions(
    conn: &rusqlite::Connection,
    role_id: &str,
    permissions: &[String],
) -> rusqlite::Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    let mut stmt =
        conn.prepare("INSERT INTO custom_role_permissions (role_id, permission) VALUES (?1, ?2)")?;
    for permission in permissions {
        if seen.contains(&permission.as_str()) {
            continue;
        }
        seen.push(permission.as_str());
        stmt.execute(params![role_id, permission])?;
    }
    Ok(())
}

fn load_role_permissions(
    conn: &rusqlite::Connection,
    role: &mut CustomRole,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(
        "SELECT permission FROM custom_role_permissions WHERE role_id = ?1 ORDER BY permission",
    )?;
    let rows = stmt.query_map(params![role.id], |row| row.get::<_, String>(0))?;
    for row in rows {
        role.permissions.push(row?);
    }
    Ok(())
}

/// Group-object permission check (folder-level grants): direct user grant
/// on the object, or a group the user belongs to granted on the object or
/// on an ancestor rbac group (recursive CTE over `parent_id`).
fn check_group_object_permission(
    db: &Db,
    user_id: i64,
    object_id: &str,
    permission: ObjectPermission,
) -> rusqlite::Result<bool> {
    let conn = db.lock().unwrap();

    let direct: bool = conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM rbac_permissions
            WHERE entity_id = ?1 AND entity_type = 'user'
              AND object_type = 'connection_group' AND object_id = ?2
              AND permission = ?3
        )",
        params![user_id, object_id, permission.as_str()],
        |row| row.get(0),
    )?;
    if direct {
        return Ok(true);
    }

    let inherited: bool = conn.query_row(
        "WITH RECURSIVE group_ancestors(group_id) AS (
            SELECT DISTINCT entity_id
            FROM rbac_permissions
            WHERE entity_type = 'group' AND object_type = 'connection_group'
              AND object_id = ?2 AND permission = ?3
            UNION
            SELECT g.parent_id
            FROM rbac_groups g
            JOIN group_ancestors ga ON g.id = ga.group_id
            WHERE g.parent_id IS NOT NULL
        )
        SELECT EXISTS(
            SELECT 1
            FROM rbac_user_groups ug
            INNER JOIN group_ancestors ga ON ug.group_id = ga.group_id
            WHERE ug.user_id = ?1
        )",
        params![user_id, object_id, permission.as_str()],
        |row| row.get(0),
    )?;
    Ok(inherited)
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

    #[test]
    fn folder_connect_grant_cascades_to_entries() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, role) VALUES ('member@test.com', 'Member', 'viewer')",
            [],
        )
        .unwrap();
        let member_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO users (email, name, role) VALUES ('outsider@test.com', 'Outsider', 'viewer')",
            [],
        )
        .unwrap();
        let outsider_id: i64 = conn.last_insert_rowid();
        drop(conn);

        // The folder must exist in the address book for the connection's
        // folder path to resolve.
        let folder_id =
            crate::db::create_ab_folder(&db, "shared", "Clients", "", "", false).unwrap();
        crate::db::create_ab_entry(
            &db,
            folder_id,
            "web1",
            "Web 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap();

        let group_id = create_group(&db, "devops", None, None).unwrap();
        add_user_to_group(&db, member_id, &group_id).unwrap();
        grant_group_permission(
            &db,
            &format!("g:{}", group_id),
            "Clients",
            ObjectPermission::Connect,
        )
        .unwrap();

        assert!(
            check_connection_permission(
                &db,
                member_id,
                "shared/Clients/web1",
                ObjectPermission::Connect
            )
            .unwrap(),
            "a Connect grant on the folder must cascade to entries beneath it"
        );
        assert!(
            !check_connection_permission(
                &db,
                outsider_id,
                "shared/Clients/web1",
                ObjectPermission::Connect
            )
            .unwrap(),
            "a user outside the granted group stays denied"
        );
    }

    #[test]
    fn folder_connect_grant_cascades_to_subfolder_entries() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, role) VALUES ('member@test.com', 'Member', 'viewer')",
            [],
        )
        .unwrap();
        let member_id: i64 = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO users (email, name, role) VALUES ('outsider@test.com', 'Outsider', 'viewer')",
            [],
        )
        .unwrap();
        let outsider_id: i64 = conn.last_insert_rowid();
        drop(conn);

        // The entry lives in a subfolder; the Connect grant sits on the
        // parent folder and must cascade down the slash-path hierarchy.
        crate::db::create_ab_folder(&db, "shared", "Clients", "", "", false).unwrap();
        crate::db::create_ab_folder(&db, "shared", "Clients/Acme", "", "", true).unwrap();
        let sub = crate::db::get_ab_folder(&db, "shared", "Clients/Acme").unwrap();
        crate::db::create_ab_entry(
            &db,
            sub.id,
            "web1",
            "Web 1",
            "ssh",
            "10.0.0.1",
            Some(22),
            "root",
            "{}",
            "",
        )
        .unwrap();

        let group_id = create_group(&db, "devops", None, None).unwrap();
        add_user_to_group(&db, member_id, &group_id).unwrap();
        grant_group_permission(
            &db,
            &format!("g:{}", group_id),
            "Clients",
            ObjectPermission::Connect,
        )
        .unwrap();

        assert!(
            check_connection_permission(
                &db,
                member_id,
                "shared/Clients/Acme/web1",
                ObjectPermission::Connect
            )
            .unwrap(),
            "a Connect grant on a parent folder must cascade to entries in subfolders"
        );
        assert!(
            !check_connection_permission(
                &db,
                outsider_id,
                "shared/Clients/Acme/web1",
                ObjectPermission::Connect
            )
            .unwrap(),
            "a user outside the granted group stays denied in subfolders"
        );
    }
}
