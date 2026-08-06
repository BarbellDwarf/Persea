-- Local groups + provider-group mappings (ticket #029)
-- MySQL variant. Mirrors the SQLite schema created in src/db.rs::init_db.

-- Admin-defined named groups that folders/connections can grant access to.
-- Folder `allowed_groups` reference a local group by *name* as a free-form
-- string, so renaming/deleting a local group never rewrites folder configs.
CREATE TABLE IF NOT EXISTS local_groups (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Links an auth-provider group name (OIDC/LDAP claim group) to a local group.
-- One provider group maps to at most one local group (UNIQUE).
CREATE TABLE IF NOT EXISTS group_mappings (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    group_id       BIGINT NOT NULL,
    provider_group VARCHAR(255) NOT NULL UNIQUE,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_group_mappings_local_group FOREIGN KEY (group_id)
        REFERENCES local_groups(id) ON DELETE CASCADE
);
