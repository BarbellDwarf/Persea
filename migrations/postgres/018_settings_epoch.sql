-- Monotonic settings epoch (persea#289) — PostgreSQL variant.
--
-- HA deployments share this table across instances. The admin settings
-- PUT bumps this row in the same commit as its flag writes; each instance
-- validates its cached auth flags (enable_api_keys, compliance_mode)
-- against it with one primary-key point read per request (src/auth.rs).
-- Seeded at 0 so pre-existing databases start coherent; ON CONFLICT
-- DO NOTHING keeps the migration idempotent.

INSERT INTO system_settings (key, value) VALUES ('settings_epoch', '0') ON CONFLICT (key) DO NOTHING;
