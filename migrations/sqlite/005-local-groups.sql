-- Local groups + provider-group mappings (ticket #029)
-- SQLite variant. Mirrors the CREATE TABLE statements applied at runtime in
-- src/db.rs::init_db (migration "ticket #029" block).

-- Admin-defined named groups that folders/connections can grant access to.
-- Folder `allowed_groups` reference a local group by *name* as a free-form
-- string, so renaming/deleting a local group never rewrites folder configs.
CREATE TABLE IF NOT EXISTS local_groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Links an auth-provider group name (OIDC/LDAP claim group, see
-- db::list_known_groups) to a local group. One provider group maps to at
-- most one local group (UNIQUE). SQLite runs without `PRAGMA foreign_keys`,
-- so db::delete_local_group removes mappings explicitly rather than relying
-- on the cascade.
CREATE TABLE IF NOT EXISTS group_mappings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id       INTEGER NOT NULL REFERENCES local_groups(id) ON DELETE CASCADE,
    provider_group TEXT NOT NULL UNIQUE,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);
