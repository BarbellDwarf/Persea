-- Personal folders (persea#165) — SQLite backend.
--
-- Users keep their own folder tree, expressed as slash paths exactly like
-- the shared tree (`Work/Acme` nests under `Work`), unique per user.
-- `user_folder_entries` stores *references* to shared address book entries:
-- deleting a personal folder or its owner removes only those references,
-- never the shared entries themselves (the entry FK cascade cleans
-- references when a shared entry is deleted, in the other direction).

CREATE TABLE IF NOT EXISTS user_folders (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS user_folder_entries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id   INTEGER NOT NULL REFERENCES user_folders(id) ON DELETE CASCADE,
    entry_id    INTEGER NOT NULL REFERENCES address_book_entries(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(user_id, folder_id, entry_id)
);

CREATE INDEX IF NOT EXISTS idx_ufe_folder ON user_folder_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_ufe_entry ON user_folder_entries(entry_id);
