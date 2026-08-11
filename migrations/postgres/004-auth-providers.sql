-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- PostgreSQL variant. Mirrors src/providers_db.rs::migrate.

CREATE TABLE IF NOT EXISTS auth_providers (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    position   BIGINT NOT NULL DEFAULT 0,
    config     TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS'),
    updated_at TEXT NOT NULL DEFAULT to_char((now() at time zone 'utc'), 'YYYY-MM-DD HH24:MI:SS')
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_name ON auth_providers(name);
