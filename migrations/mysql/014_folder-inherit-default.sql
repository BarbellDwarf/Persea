-- Folder ACL inheritance defaults to true (persea#108).
--
-- A child folder without its own ACL must not silently open up a
-- restricted parent: the ancestor walk in folder_allowed_for_user stops
-- at the first folder with inherit_from_parent = false, so the default
-- for new rows is flipped to true. 002_address-book.sql carries the new
-- default for fresh databases; this migration updates existing ones.
-- Existing rows keep their stored value (an explicit admin choice).

ALTER TABLE address_book_folders ALTER COLUMN inherit_from_parent SET DEFAULT 1;
