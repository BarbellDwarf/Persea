# 011 — Vault Optional: Research & Implementation Guidance

## 1. What Vault Currently Stores

### Address book (connections)
Every connection entry is a full `AddressBookEntry` struct (vault.rs:74–271) stored as JSON in Vault KV v2 at:
```
<mount>/data/<base_path>/shared/<folder>/<entry>        — shared scope
<mount>/data/<base_path>/instance/<name>/<folder>/<entry> — instance scope
```

Each folder also has a `.config` sentinel key (`FolderConfig`) at:
```
<mount>/data/<base_path>/<scope_prefix>/<folder>/.config
```

### Vault path layout
```
persea/                        # base_path (configurable)
├── shared/                      # shared scope
│   ├── Clients/                 # folder
│   │   ├── .config              # FolderConfig { allowed_groups, description, inherit_from_parent }
│   │   ├── Acme-Web             # entry (full AddressBookEntry JSON)
│   │   └── Acme-RDP             # entry
│   └── Dev/
│       └── .config
├── instance/<name>/             # instance scope (when instance_name set)
│   └── ...
├── users/                       # per-user credential variables
│   ├── alice_at_example.com     # { "corp_user": "alice", "corp_password": "s3cret" }
│   └── bob_at_example.com
```

### Credential-sensitive fields in AddressBookEntry
These are the "secret" fields that need protection at rest:
- `password` — RDP/SSH/VNC password
- `private_key` — SSH private key (PEM)
- `container_password` — VDI container password
- `proxmox_token_secret` — Proxmox API token secret
- `jump_password` — SSH tunnel jump password
- `jump_private_key` — SSH tunnel jump private key

Non-secret fields (hostname, port, session_type, display_name, etc.) are fine in plaintext.

### Per-user credential variables
Stored at `users/<sanitized_email>` as a flat `HashMap<String, String>`. These are referenced by `$variable` syntax in entry fields. Vault is the only store for these today.

## 2. DB Credential Encryption

### Recommendation: AES-256-GCM with config-sourced key

**Why not TDE (Transparent Data Encryption)?** SQLite doesn't support TDE natively. The bundled SQLite is file-based. TDE would require switching to a different DB or using SQLCipher (adds complexity, FIPS concerns, and doesn't help with partial encryption).

**Why not plaintext in DB?** The whole point of Vault was credential separation. If Vault is removed, encrypted-at-rest is the minimum bar.

### Implementation

Add `aes-gcm` (already in Cargo.lock as transitive dep) as a direct dependency:
```toml
aes-gcm = "0.10"
```

Add to `config.rs`:
```toml
[storage]
# AES-256-GCM key (32 bytes hex) for credential encryption at rest.
# Required when [vault] is NOT configured. Ignored when Vault is in use.
# Generate with: openssl rand -hex 32
encryption_key = "aabbccdd..."  # 64 hex chars = 32 bytes
```

Store encrypted credentials as `base64(nonce || ciphertext || tag)` in the DB column. Decrypt on read with the same key.

### Where the key lives
- **Option A (recommended):** In the config file (`config.toml`). Simple, works for single-server. The config file already contains sensitive values (OIDC client_secret, Vault role_id).
- **Option B:** Environment variable `RGUAC_STORAGE_KEY`. Overrides config. Good for containerized deployments where config is baked but secrets come from env.
- **Option C:** File path (`encryption_key_file = "/opt/persea/secrets/encryption.key"`). The file contains raw 32 bytes.

For the initial implementation, support Option A + B. Option C can come later.

### What gets encrypted
Only the credential-sensitive fields of `AddressBookEntry`. The rest stays plaintext in DB for queryability:
- `password` → encrypted
- `private_key` → encrypted
- `container_password` → encrypted
- `proxmox_token_secret` → encrypted
- `jump_password` → encrypted
- `jump_private_key` → encrypted

## 3. Migration Tool Design: `db-migrate-from-vault`

### New CLI subcommand

Add to `main.rs` Command enum:
```rust
/// Migrate address book and user credentials from Vault to the DB
DbMigrateFromVault {
    /// Dry run — show what would be migrated without writing
    #[arg(long)]
    dry_run: bool,
    /// Also delete migrated entries from Vault after successful DB write
    #[arg(long)]
    vault_delete: bool,
}
```

### Migration steps

1. **Connect to Vault** — reuse existing `connect_named()` from `migrate.rs`
2. **Create DB tables** — new migration in `db.rs`:
   ```sql
   CREATE TABLE IF NOT EXISTS address_book_folders (
       id            INTEGER PRIMARY KEY AUTOINCREMENT,
       scope         TEXT NOT NULL,          -- "shared" or "instance"
       path          TEXT NOT NULL,          -- full path e.g. "Clients/Acme"
       folder_name   TEXT NOT NULL,          -- last segment
       description   TEXT NOT NULL DEFAULT '',
       allowed_groups TEXT NOT NULL DEFAULT '[]',  -- JSON array
       inherit_from_parent INTEGER NOT NULL DEFAULT 0,
       created_at    TEXT NOT NULL DEFAULT (datetime('now')),
       UNIQUE(scope, path)
   );

   CREATE TABLE IF NOT EXISTS address_book_entries (
       id            INTEGER PRIMARY KEY AUTOINCREMENT,
       scope         TEXT NOT NULL,
       folder_path   TEXT NOT NULL,          -- FK to folder path
       entry_name    TEXT NOT NULL,
       entry_data    TEXT NOT NULL,          -- full AddressBookEntry JSON (credentials encrypted)
       has_credentials INTEGER NOT NULL DEFAULT 0, -- quick flag for UI
       created_at    TEXT NOT NULL DEFAULT (datetime('now')),
       updated_at    TEXT NOT NULL DEFAULT (datetime('now')),
       UNIQUE(scope, folder_path, entry_name)
   );

   CREATE TABLE IF NOT EXISTS user_credentials (
       id            INTEGER PRIMARY KEY AUTOINCREMENT,
       user_email    TEXT NOT NULL UNIQUE,
       credentials   TEXT NOT NULL,          -- JSON HashMap (values encrypted)
       created_at    TEXT NOT NULL DEFAULT (datetime('now')),
       updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
   );
   ```

3. **Iterate Vault scopes** — for each of `["shared", "instance"]`:
   - BFS list all folder paths
   - For each folder: write `.config` to `address_book_folders`
   - For each entry: read from Vault, encrypt credentials, write JSON to `address_book_entries`

4. **Migrate user credentials** — list `users/*` keys, read each, encrypt values, write to `user_credentials`

5. **Report** — print counts, any failures

6. **Optional vault_delete** — if `--vault-delete`, delete migrated entries from Vault (after confirming DB writes succeeded)

### Encryption during migration

The migration tool reads the encryption key from config. For each credential field:
```
plaintext → AES-256-GCM encrypt(key, nonce=rand_12_bytes, aad="field_name") → base64(nonce || ciphertext || tag)
```

Store as `enc:v1:<base64>` prefix to allow future key rotation (detect prefix to know if field is encrypted).

## 4. Per-Credential Scope

### Recommendation: All-or-nothing per deployment, NOT per-credential

**Why:** Per-credential scope (some creds in Vault, some in DB) creates a confusing split-brain:
- Which backend does `get_user_credentials()` hit?
- When migrating, do you partially migrate?
- UI needs to show "this credential is in Vault, that one in DB"

**Instead:** The decision is deployment-level:
- **Vault mode** (`[vault]` present): All credentials go through Vault. Address book entries can live in DB (for queryability) but credential fields are stored in/loaded from Vault. Per-user credential variables also live in Vault.
- **DB-only mode** (`[vault]` absent): Everything in DB, encrypted with AES-256-GCM.
- **Hybrid (transition):** During migration, Vault is read for existing creds. After migration completes, Vault can be removed from config.

### How this works in practice

In `VaultBackends`, add a `storage_backend` enum:
```rust
pub enum CredentialBackend {
    Vault,      // credentials live in Vault (current behavior)
    EncryptedDb, // credentials live in DB, AES-256-GCM encrypted
}
```

The `VaultBackends` struct gets a new field `credential_backend: CredentialBackend`. When `EncryptedDb`:
- Address book folder/entry CRUD hits DB directly
- Credential fields are encrypted on write, decrypted on read
- User credential variables hit `user_credentials` table

When `Vault`:
- Current behavior unchanged

### User credential variable scope (shared/local) becomes DB columns

With Vault, per-user credentials can be in `vault_shared` or `vault_local`. Without Vault, add a `scope` column to `user_credentials`:
```sql
CREATE TABLE IF NOT EXISTS user_credentials (
    ...
    scope TEXT NOT NULL DEFAULT 'local',  -- 'shared' or 'local'
    ...
    UNIQUE(user_email, scope)
);
```

## 5. Config Changes

### Minimal config for DB-only mode

```toml
listen_addr = "127.0.0.1:8089"
guacd_addr = "127.0.0.1:4822"

[storage]
encryption_key = "aabbccdd..."  # or use RGUAC_STORAGE_KEY env var

# No [vault] section at all
```

### With Vault (unchanged)

```toml
[vault]
addr = "https://vault.example.com:8200"
role_id = "..."
# VAULT_SECRET_ID env var
```

### Config changes in code

Add to `Config`:
```rust
pub storage: Option<StorageConfig>,
```

Add struct:
```rust
#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// AES-256-GCM encryption key (64 hex chars). Required when [vault] is absent.
    #[serde(default)]
    pub encryption_key: Option<String>,
    /// Path to file containing raw 32-byte encryption key (alternative to inline key).
    #[serde(default)]
    pub encryption_key_file: Option<PathBuf>,
}
```

Validation at startup:
- If `vault` is `None` AND `storage.encryption_key` is `None` → warn: "No [vault] and no encryption_key — credentials stored in plaintext. Set [storage] encryption_key or add [vault]."
- If `vault` is `Some` → `storage.encryption_key` is ignored (Vault handles encryption)

## 6. Multi-Backend Vault (Optional)

The existing `[vault_shared]` / `[vault_local]` pattern stays. When all three are absent, DB-only mode kicks in.

### Interaction matrix

| `[vault]` | `[vault_shared]` | `[vault_local]` | `[storage]` | Mode |
|-----------|------------------|-----------------|-------------|------|
| Yes | No | No | Any | Single Vault (current default) |
| Yes | Yes | Yes | Any | Multi-Vault DR (current feature) |
| No | No | No | Yes | DB-only with encryption |
| No | No | No | No | **WARN: plaintext creds** |

## 7. Implementation Sequence

### Phase 1: DB tables + encryption module
- Add `aes-gcm` dep
- New `src/crypto.rs`: `encrypt_field()`, `decrypt_field()`, `is_encrypted()`
- New DB tables in migration (`address_book_folders`, `address_book_entries`, `user_credentials`)
- Add `StorageConfig` to `config.rs`
- Startup validation

### Phase 2: API layer — dual-backend support
- `VaultBackends` gains `credential_backend` field
- When `EncryptedDb`: address book CRUD routes hit DB instead of Vault
- Credential fields encrypted/decrypted transparently
- User credential variables hit `user_credentials` table
- `VaultConfigured(false)` when no `[vault]`

### Phase 3: Migration tool
- `persea db-migrate-from-vault` subcommand
- Reads from Vault, writes to DB (encrypted)
- Reports counts, optional `--vault-delete`

### Phase 4: Cleanup
- Remove Vault-as-requirement from startup
- Update `connections.html` / admin UI to work without Vault
- Documentation

## 8. Key Files to Modify

| File | Change |
|------|--------|
| `Cargo.toml` | Add `aes-gcm` direct dep |
| `src/config.rs` | Add `StorageConfig`, make vault optional at validation level |
| `src/crypto.rs` | **NEW** — AES-256-GCM encrypt/decrypt helpers |
| `src/db.rs` | Add address book tables, user_credentials table, CRUD functions |
| `src/vault.rs` | No changes needed — stays as Vault client |
| `src/api/mod.rs` | `VaultBackends` gains `credential_backend`, DB fallback logic |
| `src/api/address_book.rs` | Route handlers check backend type, dispatch to DB or Vault |
| `src/api/users.rs` | Credential variable CRUD checks backend type |
| `src/main.rs` | Add `DbMigrateFromVault` subcommand, startup validation |
| `src/migrate.rs` | Add `cmd_db_migrate_from_vault()` |

## 9. Risks & Mitigations

- **Key management**: If the operator loses `encryption_key`, encrypted credentials are unrecoverable. Mitigation: document backup requirement, print warning at startup, consider key-file option.
- **Migration rollback**: If migration fails midway, DB has partial data. Mitigation: transactional DB writes, idempotent migration (skip already-migrated entries).
- **Vault still needed for LUKS**: `drive.luks_key_path` reads from Vault. DB-only mode can't support LUKS. Mitigation: warn at startup if drive is enabled but Vault is absent.
- **Concurrent access during migration**: Vault entries could change while migrating. Mitigation: migration is a one-shot CLI command, not run during production. Document: stop server, migrate, restart.
