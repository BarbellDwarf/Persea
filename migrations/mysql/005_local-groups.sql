-- Local groups + provider-group mappings (ticket #029) — MySQL variant.
-- Mirrors src/db.rs::init_db. `auto_provisioned` (ticket F38) is folded in
-- here so the three backends stay in sync.

CREATE TABLE IF NOT EXISTS local_groups (
    id               BIGINT AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(255) NOT NULL UNIQUE,
    description      TEXT NOT NULL,
    auto_provisioned TINYINT(1) NOT NULL DEFAULT 0,
    created_at       VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE TABLE IF NOT EXISTS group_mappings (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    group_id       BIGINT NOT NULL,
    provider_group VARCHAR(512) NOT NULL UNIQUE,
    created_at     VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    CONSTRAINT fk_group_mappings_group FOREIGN KEY (group_id) REFERENCES local_groups(id) ON DELETE CASCADE
);
