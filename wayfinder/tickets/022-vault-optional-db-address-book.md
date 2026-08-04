# Ticket: Vault-Optional Address Book with DB Backend

**Type:** task + grilling
**Labels:** architecture, vault, database, wayfinder:task

## Current state

Vault is the **only** backend for the connections address book (folders, entries, credentials). Without Vault, the Connections page shows "Connections temporarily unavailable" and users can only run ad-hoc sessions.

The DB stores user accounts, tokens, audit logs, session history, group mappings, TOTP secrets, and RBAC permissions. But it does NOT store connection entries or credentials.

## Goal

Make Vault completely optional. The DB becomes the default address book backend. Vault becomes an optional credential store for organizations that want secrets management separate from the app database.

## Architecture

### Default mode (DB-backed address book)

```
persea
  |-- DB (SQLite/MySQL/PostgreSQL)
       |-- users, tokens, audit, sessions, RBAC
       |-- address_book_folders (NEW table)
       |-- address_book_entries (NEW table)
       |-- address_book_credentials (NEW table, encrypted)
```

All connection data lives in the DB. Credentials encrypted with AES-256-GCM using a config-provided key (`storage.encryption_key`).

### Vault mode (optional)

```
persea
  |-- DB (same as above for metadata)
  |-- Vault (optional, for credential storage only)
       |-- persea/address_book/{scope}/{folder}/{entry}/credentials
```

Folder/entry metadata stays in DB. Only the credential blob goes to Vault. This gives organizations secrets management, audit trails in Vault, and rotation capabilities.

## DB schema changes

### New tables

```sql
-- Connection folders
CREATE TABLE address_book_folders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL DEFAULT 'shared',
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(scope, name)
);

-- Connection entries
CREATE TABLE address_book_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    folder_id INTEGER NOT NULL REFERENCES address_book_folders(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    protocol TEXT NOT NULL,  -- ssh, rdp, vnc, spice, web, vdi
    hostname TEXT NOT NULL,
    port INTEGER,
    username TEXT DEFAULT '',
    -- Protocol-specific fields stored as JSON
    protocol_config TEXT DEFAULT '{}',  -- JSON blob for protocol-specific settings
    -- Access control
    allowed_groups TEXT DEFAULT '',  -- comma-separated OIDC groups
    -- Metadata
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(folder_id, name)
);

-- Credentials (encrypted at rest)
CREATE TABLE address_book_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entry_id INTEGER NOT NULL REFERENCES address_book_entries(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,  -- password, private_key, api_token
    credential_data TEXT NOT NULL,  -- AES-256-GCM encrypted
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(entry_id, credential_type)
);
```

### Migration path

1. Add new tables to migrations
2. If Vault is configured, migrate existing Vault entries to DB on startup
3. If Vault is not configured, DB is the only backend
4. Add `storage.backend` config option: `db` (default) or `vault`

## Config changes

```toml
# New section
[storage]
# Backend for connection credentials: "db" (default) or "vault"
backend = "db"

# Encryption key for DB-stored credentials (required when backend = "db")
# Generate with: openssl rand -hex 32
encryption_key = ""

# Vault config (optional, only used when backend = "vault")
[vault]
addr = "https://vault.example.com:8200"
mount = "secret"
base_path = "persea"
role_id = ""
```

## Code changes needed

### 1. New module: `src/storage.rs`
- `StorageBackend` trait with methods: `list_folders`, `list_entries`, `get_credential`, `put_credential`, etc.
- `DbBackend` implementation (encrypted with AES-256-GCM)
- `VaultBackend` implementation (wraps existing VaultClient)
- Factory function to create backend based on config

### 2. Migrate address book API (`src/api/address_book.rs`)
- Replace direct `VaultClient` calls with `StorageBackend` trait
- All folder/entry operations go through the trait
- Credential operations go through the trait (DB encrypts, Vault stores)

### 3. Add encryption module: `src/crypto.rs`
- AES-256-GCM encryption/decryption for credential data
- Key derivation from config encryption_key
- Nonce generation

### 4. Update config (`src/config.rs`)
- Add `storage` section with `backend` and `encryption_key`
- Deprecate direct `[vault]` for address book use
- Keep `[vault]` for credential-only mode

### 5. Migration logic
- On startup, if `storage.backend = "db"` and Vault has existing entries:
  - Prompt or auto-migrate entries from Vault to DB
  - Encrypt credentials with configured key
  - Keep Vault as read-only fallback during migration

### 6. Update connections page
- Show connections regardless of Vault status (DB is always available)
- Vault status shown as "credential store" not "connection store"
- Credential fields show "stored in Vault" or "stored locally" based on backend

## File locks

| Phase | Files | Risk |
|-------|-------|------|
| Schema + migration | `migrations/`, `src/db.rs` | Low |
| Crypto module | `src/crypto.rs` (new) | Low |
| Storage trait | `src/storage.rs` (new), `src/config.rs` | Low |
| API migration | `src/api/address_book.rs` | High - many functions |
| Connection page | `templates/pages/connections.html` | Medium |
| Tests | `tests/` | Low |

## Acceptance criteria

- [ ] DB-backed address book works without Vault configured
- [ ] Vault mode stores only credentials, metadata in DB
- [ ] Migration from Vault-only to DB-backed works
- [ ] Connections page shows entries regardless of Vault status
- [ ] Credentials encrypted at rest in DB mode
- [ ] Config option `storage.backend` controls behavior
- [ ] All existing tests pass
- [ ] New tests for DB backend, encryption, migration
- [ ] Documentation updated

## Dependencies

- AES-256-GCM encryption (new dependency: `aes-gcm` or similar)
- Existing VaultClient code (reuse for Vault mode)
- DB migration system (already in place)
