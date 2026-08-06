-- Folder-level ACLs (wayfinder ticket 027).
ALTER TABLE address_book_folders ADD COLUMN IF NOT EXISTS allowed_groups TEXT NOT NULL DEFAULT '';
ALTER TABLE address_book_folders ADD COLUMN IF NOT EXISTS inherit_from_parent BOOLEAN NOT NULL DEFAULT FALSE;
