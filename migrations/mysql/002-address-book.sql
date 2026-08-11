-- Address book tables for DB-backed storage — MySQL variant.
-- Mirrors src/db.rs::init_db (includes the folder-ACL columns added by
-- tickets 022/027 so all three backends stay in sync).

CREATE TABLE IF NOT EXISTS address_book_folders (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    scope       VARCHAR(64) NOT NULL DEFAULT 'shared',
    name        VARCHAR(512) NOT NULL,
    description TEXT,
    allowed_groups TEXT NOT NULL DEFAULT (''),
    inherit_from_parent TINYINT(1) NOT NULL DEFAULT 0,
    created_at  VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    updated_at  VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_ab_folder (scope, name)
);

CREATE TABLE IF NOT EXISTS address_book_entries (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    folder_id       BIGINT NOT NULL,
    name            VARCHAR(512) NOT NULL,
    display_name    VARCHAR(512) NOT NULL DEFAULT (''),
    protocol        VARCHAR(32) NOT NULL,
    hostname        VARCHAR(512) NOT NULL,
    port            BIGINT,
    username        VARCHAR(512) NOT NULL DEFAULT (''),
    protocol_config TEXT NOT NULL DEFAULT ('{}'),
    allowed_groups  TEXT NOT NULL DEFAULT (''),
    created_at      VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    updated_at      VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_ab_entry (folder_id, name),
    CONSTRAINT fk_ab_entries_folder FOREIGN KEY (folder_id) REFERENCES address_book_folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS address_book_credentials (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    entry_id        BIGINT NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_data TEXT NOT NULL,
    created_at      VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    updated_at      VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_ab_cred (entry_id, credential_type),
    CONSTRAINT fk_ab_creds_entry FOREIGN KEY (entry_id) REFERENCES address_book_entries(id) ON DELETE CASCADE
);

CREATE INDEX idx_ab_entries_folder ON address_book_entries(folder_id);
CREATE INDEX idx_ab_creds_entry ON address_book_credentials(entry_id);
