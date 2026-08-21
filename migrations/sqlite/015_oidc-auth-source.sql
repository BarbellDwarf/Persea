-- Fix auth_source for pre-existing OIDC users (persea#153) — SQLite backend.
--
-- Before auth_source was written on OIDC upsert, OIDC logins inserted rows
-- without the column, leaving the schema default 'database'. Every row with
-- an oidc_subject authenticates via OIDC, so its source is corrected here.

UPDATE users SET auth_source = 'oidc'
WHERE oidc_subject IS NOT NULL AND auth_source = 'database';
