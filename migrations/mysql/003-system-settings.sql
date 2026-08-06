-- System settings key-value store (ticket #024)
-- Admin-configurable server settings persisted in the database.
-- `key` is a reserved word in MySQL, hence backticks. TEXT columns cannot
-- have a DEFAULT clause in MySQL, so `value` has none — the application
-- always writes an explicit value.

CREATE TABLE IF NOT EXISTS system_settings (
    `key`       VARCHAR(255) PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  VARCHAR(32) NOT NULL DEFAULT (UTC_TIMESTAMP())
);
