-- Address book tables for DB-backed storage (ticket #022)
-- MySQL variant

CREATE TABLE IF NOT EXISTS address_book_folders (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    scope       VARCHAR(32) NOT NULL DEFAULT 'shared',
    name        VARCHAR(255) NOT NULL,
    description TEXT DEFAULT '',
    allowed_groups      TEXT NOT NULL,
    inherit_from_parent TINYINT(1) NOT NULL DEFAULT 0,    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ab_folders (scope, name)
);

CREATE TABLE IF NOT EXISTS address_book_entries (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    folder_id       BIGINT NOT NULL,
    name            VARCHAR(255) NOT NULL,
    display_name    VARCHAR(255) DEFAULT '',
    protocol        VARCHAR(32) NOT NULL,
    hostname        VARCHAR(255) NOT NULL,
    port            INT,
    username        VARCHAR(255) DEFAULT '',
    protocol_config MEDIUMTEXT DEFAULT '{}',
    allowed_groups  TEXT DEFAULT '',
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ab_entries (folder_id, name),
    CONSTRAINT fk_ab_entries_folder FOREIGN KEY (folder_id) REFERENCES address_book_folders(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS address_book_credentials (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    entry_id        BIGINT NOT NULL,
    credential_type VARCHAR(64) NOT NULL,
    credential_data MEDIUMTEXT NOT NULL,
    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_ab_creds (entry_id, credential_type),
    CONSTRAINT fk_ab_creds_entry FOREIGN KEY (entry_id) REFERENCES address_book_entries(id) ON DELETE CASCADE
);

CREATE INDEX idx_ab_entries_folder ON address_book_entries(folder_id);
CREATE INDEX idx_ab_creds_entry ON address_book_credentials(entry_id);
