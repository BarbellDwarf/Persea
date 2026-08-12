-- Custom roles: named permission bundles assignable to users (T05).
--
-- A custom role bundles GLOBAL permissions that apply to every connection
-- and folder (no per-object grants). The permission vocabulary is the
-- existing enums: object perms (read, connect, update, delete, administer)
-- plus system perms (create_session, create_connection,
-- create_connection_group, audit). Users get at most one custom role,
-- stored on users.custom_role_id; it is ADDITIVE on top of the fixed
-- 4-tier role floor. Deleting a role cascades its permission rows and
-- clears the users.custom_role_id references (ON DELETE SET NULL).

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

ALTER TABLE users ADD COLUMN custom_role_id TEXT REFERENCES custom_roles(id) ON DELETE SET NULL;
