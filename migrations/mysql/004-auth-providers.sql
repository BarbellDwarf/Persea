-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- MySQL variant. Mirrors src/providers_db.rs::migrate. `type` is backtick-quoted.

CREATE TABLE IF NOT EXISTS auth_providers (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    `type`     VARCHAR(32) NOT NULL,
    enabled    TINYINT(1) NOT NULL DEFAULT 1,
    position   BIGINT NOT NULL DEFAULT 0,
    config     TEXT NOT NULL,
    created_at VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    updated_at VARCHAR(32) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_auth_providers_name (name)
);
