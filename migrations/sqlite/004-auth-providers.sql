-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- Admin-configured providers (oidc, ldap, saml, radius, database, totp) are
-- stored here and merged into the auth chain at startup (see src/providers_db.rs).
-- `config` is a JSON object; required keys depend on `type`
-- (see providers_db::validate_config).

CREATE TABLE IF NOT EXISTS auth_providers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL DEFAULT 0,
    config     TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
