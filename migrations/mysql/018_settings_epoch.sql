-- Monotonic settings epoch (persea#289) — MySQL variant.
-- `key` is a reserved word in MySQL and is backtick-quoted.
--
-- HA deployments share this table across instances. The admin settings
-- PUT bumps this row in the same commit as its flag writes; each instance
-- validates its cached auth flags (enable_api_keys, compliance_mode)
-- against it with one primary-key point read per request (src/auth.rs).
-- Seeded at 0 so pre-existing databases start coherent; INSERT IGNORE
-- keeps the migration idempotent.

INSERT IGNORE INTO system_settings (`key`, value) VALUES ('settings_epoch', '0');
