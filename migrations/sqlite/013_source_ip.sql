-- Client source IP on the session history row.
--
-- Captured at session creation (the connecting client's IP, via the same
-- header/trusted-proxy logic used by the audit log) and stored alongside
-- the rest of the history metadata so reports and the recent-sessions
-- list can attribute connections by origin IP. NULL when unavailable.

ALTER TABLE session_history ADD COLUMN source_ip TEXT;
