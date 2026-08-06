-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- MySQL variant

CREATE TABLE IF NOT EXISTS auth_providers (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    name       VARCHAR(255) NOT NULL,
    type       VARCHAR(32) NOT NULL,
    enabled    TINYINT(1) NOT NULL DEFAULT 1,
    position   INT NOT NULL DEFAULT 0,
    config     MEDIUMTEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
