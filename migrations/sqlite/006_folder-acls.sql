-- Folder-level ACLs (wayfinder ticket 027) — SQLite backend.
--
-- The `allowed_groups` and `inherit_from_parent` columns are part of the
-- base `address_book_folders` DDL in 002-address-book.sql; this migration
-- exists to keep the per-backend file sets in sync and is a no-op.
SELECT 1;
