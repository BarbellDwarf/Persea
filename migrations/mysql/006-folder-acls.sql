-- Folder-level ACLs (wayfinder ticket 027).
ALTER TABLE address_book_folders ADD COLUMN allowed_groups TEXT NOT NULL AFTER description;
ALTER TABLE address_book_folders ADD COLUMN inherit_from_parent TINYINT(1) NOT NULL DEFAULT 0 AFTER allowed_groups;
