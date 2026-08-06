-- Auth providers table for DB-backed auth chain configuration (ticket #025)
-- PostgreSQL variant

CREATE TABLE IF NOT EXISTS auth_providers (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    enabled    BOOLEAN NOT NULL DEFAULT TRUE,
    position   INTEGER NOT NULL DEFAULT 0,
    config     TEXT NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_providers_name ON auth_providers(name);
