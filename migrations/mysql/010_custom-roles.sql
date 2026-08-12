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
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE TABLE IF NOT EXISTS custom_role_permissions (
    role_id     VARCHAR(64) NOT NULL,
    permission  VARCHAR(32) NOT NULL,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    PRIMARY KEY (role_id, permission),
    CONSTRAINT fk_custom_role_perms_role FOREIGN KEY (role_id) REFERENCES custom_roles(id) ON DELETE CASCADE
);

CREATE INDEX idx_custom_role_perms_role ON custom_role_permissions(role_id);

ALTER TABLE users ADD COLUMN custom_role_id VARCHAR(64) NULL;
ALTER TABLE users ADD CONSTRAINT fk_users_custom_role FOREIGN KEY (custom_role_id) REFERENCES custom_roles(id) ON DELETE SET NULL;
