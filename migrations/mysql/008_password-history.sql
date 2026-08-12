-- Password reuse history (R108): last N Argon2id hashes per user.
-- Mirrored in src/password.rs (legacy rusqlite lazy DDL).

CREATE TABLE IF NOT EXISTS password_history (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id       BIGINT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))
);

CREATE INDEX idx_password_history_user ON password_history(user_id);
