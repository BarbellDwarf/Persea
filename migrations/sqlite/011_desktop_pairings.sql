-- S04: device-code pairing for the desktop shell.
--
-- Pending pairing records for POST /api/desktop/pair. The 8-char code is
-- stored SHA-256-hashed (code_hash), never plaintext. user_id stays NULL
-- until a logged-in user confirms the code on the account page; the shell
-- polls status, which mints the user token once approved and stamps
-- consumed_at so the plaintext is handed out exactly once. Timestamps are
-- fixed-width 'YYYY-MM-DD HH:MM:SS' UTC strings (same convention as the
-- rest of the schema) so lexicographic comparison is time-ordered.

CREATE TABLE IF NOT EXISTS desktop_pairings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    code_hash   TEXT NOT NULL UNIQUE,
    user_id     INTEGER REFERENCES users(id),
    hostname    TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT NOT NULL,
    consumed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_desktop_pairings_expires ON desktop_pairings(expires_at);
CREATE INDEX IF NOT EXISTS idx_desktop_pairings_user ON desktop_pairings(user_id);
