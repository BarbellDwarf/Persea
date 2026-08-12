-- R110 enterprise HA: shared session registry + DB-backed WebSocket tickets.
--
-- session_registry mirrors live in-memory sessions so every instance sharing
-- the backend can see/join sessions owned by another instance. Rows are
-- written by the owning instance on create/status change and deleted when the
-- session leaves the local map. Timestamps are fixed-width 'YYYY-MM-DD
-- HH:MM:SS' UTC strings (same format the rest of the schema uses) so
-- lexicographic comparison is time-ordered on every backend.

CREATE TABLE IF NOT EXISTS session_registry (
    session_id        TEXT PRIMARY KEY,
    owner_instance    TEXT NOT NULL,
    owner_base_url    TEXT NOT NULL DEFAULT '',
    session_type      TEXT NOT NULL,
    status            TEXT NOT NULL,
    hostname          TEXT NOT NULL DEFAULT '',
    username          TEXT NOT NULL DEFAULT '',
    created_by        TEXT NOT NULL DEFAULT '',
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    last_active_at    TEXT NOT NULL DEFAULT (datetime('now')),
    connection_id     TEXT NOT NULL DEFAULT '',
    shadow_token_hash TEXT,
    shadow_issued_by  TEXT,
    shadow_expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_session_registry_owner ON session_registry(owner_instance);
CREATE INDEX IF NOT EXISTS idx_session_registry_status ON session_registry(status);

-- DB-backed WebSocket tickets: any instance can validate a ticket issued by
-- another. Only the SHA-256 hash of the ticket is stored (same convention as
-- auth_sessions); the raw ticket string is shown exactly once, in the URL.

CREATE TABLE IF NOT EXISTS ws_tickets (
    ticket_hash   TEXT PRIMARY KEY,
    identity_json TEXT NOT NULL,
    session_id    TEXT,
    issued_by     TEXT NOT NULL DEFAULT '',
    expires_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ws_tickets_expires ON ws_tickets(expires_at);
