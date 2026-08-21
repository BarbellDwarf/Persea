-- Personal folders (persea#165) — PostgreSQL variant.
--
-- Each user keeps their own private folder tree, nested like the shared
-- tree (`user_folder.name` values are slash paths), unique per user.
-- `user_folder_entries` stores *references* to shared address book entries:
-- deleting a personal folder or its owner removes only those references,
-- never the shared entries themselves (the entry FK cascade removes
-- references when a shared entry is deleted, in the other direction).

CREATE TABLE IF NOT EXISTS user_folders (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS user_folder_entries (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    folder_id   BIGINT NOT NULL REFERENCES user_folders(id) ON DELETE CASCADE,
    entry_id    BIGINT NOT NULL REFERENCES address_book_entries(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    UNIQUE(user_id, folder_id, entry_id)
);

CREATE INDEX IF NOT EXISTS idx_ufe_folder ON user_folder_entries(folder_id);
CREATE INDEX IF NOT EXISTS idx_ufe_entry ON user_folder_entries(entry_id);
