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
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    code_hash   VARCHAR(128) NOT NULL,
    user_id     BIGINT NULL,
    hostname    VARCHAR(256) NOT NULL DEFAULT '',
    created_at  VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    expires_at  VARCHAR(64) NOT NULL,
    consumed_at VARCHAR(64) NULL,
    UNIQUE KEY uq_desktop_pairings_code (code_hash),
    CONSTRAINT fk_desktop_pairings_user FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX idx_desktop_pairings_expires ON desktop_pairings(expires_at);
CREATE INDEX idx_desktop_pairings_user ON desktop_pairings(user_id);
