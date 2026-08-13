-- V09: connection reason on the session history row.
--
-- Captured at session creation (dropdown + free text on the connections
-- connect flow and the sessions page ad-hoc form) and stored alongside the
-- rest of the history metadata so reports and the recent-sessions list can
-- show why a connection was made. NULL when no reason was given.

ALTER TABLE session_history ADD COLUMN reason TEXT NULL;
