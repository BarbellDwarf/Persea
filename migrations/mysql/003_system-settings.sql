-- System settings key-value store (ticket #024) — MySQL variant.
-- `key` is a reserved word in MySQL and is backtick-quoted.

CREATE TABLE IF NOT EXISTS system_settings (
    `key`       VARCHAR(64) PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);
