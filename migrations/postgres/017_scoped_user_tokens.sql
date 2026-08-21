-- Scoped user token for the desktop bridge (persea#227) — PostgreSQL variant.
--
-- user_api_tokens.token_type discriminates self-service/admin tokens
-- ('user') from desktop bridge tokens ('scoped'), so the bridge layers
-- (LDAP re-validation, compliance mode) can target the right rows.
-- auth_pending_mfa.desktop carries the desktop-login intent through the
-- TOTP gate so the MFA completion handler mints the scoped token after
-- the same gates a web login satisfies.

ALTER TABLE user_api_tokens ADD COLUMN token_type TEXT NOT NULL DEFAULT 'user';
ALTER TABLE auth_pending_mfa ADD COLUMN desktop BOOLEAN NOT NULL DEFAULT FALSE;
