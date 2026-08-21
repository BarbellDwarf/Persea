-- Personal folders (persea#165) — MySQL variant.
--
-- Each user keeps their own private folder tree, nested like the shared
-- tree (`user_folder.name` values use slash paths), unique per user.
-- `user_folder_entries` stores *references* to shared address book entries:
-- deleting a personal folder or its user removes only those references,
-- never the shared entries themselves (the entry FK ON DELETE CASCADE
-- removes references when a shared entry is deleted, in the other
-- direction).

CREATE TABLE IF NOT EXISTS user_folders (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT NOT NULL,
    name        VARCHAR(512) NOT NULL,
    description TEXT,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_user_folder (user_id, name),
    CONSTRAINT fk_user_folders_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_folder_entries (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id     BIGINT NOT NULL,
    folder_id   BIGINT NOT NULL,
    entry_id    BIGINT NOT NULL,
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    UNIQUE KEY uq_ufe (user_id, folder_id, entry_id),
    CONSTRAINT fk_ufe_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_ufe_folder FOREIGN KEY (folder_id) REFERENCES user_folders(id) ON DELETE CASCADE,
    CONSTRAINT fk_ufe_entry FOREIGN KEY (entry_id) REFERENCES address_book_entries(id) ON DELETE CASCADE
);

CREATE INDEX idx_ufe_folder ON user_folder_entries(folder_id);
CREATE INDEX idx_ufe_entry ON user_folder_entries(entry_id);
