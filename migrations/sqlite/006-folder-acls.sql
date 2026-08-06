-- Folder-level ACLs (wayfinder ticket 027): allowed_groups + inherit flag on
-- address_book_folders. Delivered only here (NOT by editing 002) so sqlx
-- checksum validation on existing deployments stays intact. The rusqlite
-- backend creates the columns inline in src/db.rs init_db.
ALTER TABLE address_book_folders ADD COLUMN allowed_groups TEXT NOT NULL DEFAULT '';
ALTER TABLE address_book_folders ADD COLUMN inherit_from_parent INTEGER NOT NULL DEFAULT 0;
