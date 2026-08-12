-- R110 enterprise HA: shared session registry + DB-backed WebSocket tickets.
--
-- session_registry mirrors live in-memory sessions so every instance sharing
-- the backend can see/join sessions owned by another instance. Rows are
-- written by the owning instance on create/status change and deleted when the
-- session leaves the local map. Timestamps are fixed-width 'YYYY-MM-DD
-- HH:MM:SS' UTC strings (same format as the other tables) so lexicographic
-- comparison is time-ordered on every backend.

CREATE TABLE IF NOT EXISTS session_registry (
    session_id        VARCHAR(64) PRIMARY KEY,
    owner_instance    VARCHAR(128) NOT NULL,
    owner_base_url    VARCHAR(512) NOT NULL DEFAULT '',
    session_type      VARCHAR(32) NOT NULL,
    status            VARCHAR(32) NOT NULL,
    hostname          TEXT NOT NULL,
    username          TEXT NOT NULL,
    created_by        TEXT NOT NULL,
    created_at        VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    last_active_at    VARCHAR(64) NOT NULL DEFAULT (DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s')),
    connection_id     VARCHAR(256) NOT NULL DEFAULT '',
    shadow_token_hash VARCHAR(128),
    shadow_issued_by  VARCHAR(256),
    shadow_expires_at VARCHAR(64)
);

CREATE INDEX idx_session_registry_owner ON session_registry(owner_instance);
CREATE INDEX idx_session_registry_status ON session_registry(status);

-- DB-backed WebSocket tickets: any instance can validate a ticket issued by
-- another. Only the SHA-256 hash of the ticket is stored (same convention as
-- auth_sessions); the raw ticket string is shown exactly once, in the URL.

CREATE TABLE IF NOT EXISTS ws_tickets (
    ticket_hash   VARCHAR(128) PRIMARY KEY,
    identity_json TEXT NOT NULL,
    session_id    VARCHAR(64),
    issued_by     VARCHAR(256) NOT NULL DEFAULT '',
    expires_at    VARCHAR(64) NOT NULL
);

CREATE INDEX idx_ws_tickets_expires ON ws_tickets(expires_at);
