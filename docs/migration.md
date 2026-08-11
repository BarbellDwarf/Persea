# Migrating from Apache Guacamole

> **Audience:** admins migrating from Apache Guacamole to persea, or moving persea connections between storage backends.
> **Next:** [Configuration](configuration.md) for the `[vault]`, `[storage]`, and `[vault_shared]`/`[vault_local]` sections these commands rely on.

persea can import connections from an Apache Guacamole MySQL/MariaDB database into its address book. Storage is DB-first: folders and entries are always written to the database, and credentials are encrypted (AES-256-GCM) into the DB unless `[storage].backend = "vault"` routes them to Vault/OpenBao instead.

## Prerequisites

- A MySQL/MariaDB dump of your Guacamole database
- DB mode (default): the storage encryption key, via `PERSEA_STORAGE_KEY` or `[storage].encryption_key` — a 64-character hex string (generate with `openssl rand -hex 32`). Without it, imported passwords and private keys are **not** stored; entries import credential-less. See [Configuration](configuration.md#storage-section).
- Vault storage mode only (`[storage].backend = "vault"`): a running Vault/OpenBao instance with `[vault]` configured in `config.toml`, and the `VAULT_SECRET_ID` environment variable set.

## Step 1: Export the Guacamole database

On the Guacamole database server, create a SQL dump:

```bash
mysqldump -u guacamole_user -p guacamole_db \
  guacamole_connection \
  guacamole_connection_parameter \
  guacamole_connection_group \
  > guacamole-dump.sql
```

Only these three tables are needed. Both the default multi-row dump format and `--skip-extended-insert` single-row dumps are supported; the dump needs `INSERT INTO` statements for those tables.

## Step 2: Preview the import

Use `--dry-run` to see what would be imported without writing anything:

```bash
persea --config /opt/persea/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --dry-run
```

Example output:

```
Found 42 connections (3 skipped, 39 to import)

[DRY RUN] Would import under folder "imported" (scope: shared):

  imported/Web-Server (ssh) → 10.0.0.1:22
  imported/Database-Primary (ssh) → 10.0.0.5:22
  imported/Production/DMZ-Firewall (ssh) → 10.0.2.1:22
  ...

Re-run without --dry-run to import.
```

Connections with unsupported protocols (e.g. telnet, kubernetes) are automatically skipped.

## Step 3: Import

DB mode (default):

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> \
persea --config /opt/persea/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --folder my-servers \
  --scope shared
```

Vault storage mode (`[storage].backend = "vault"`):

```bash
VAULT_SECRET_ID=your-secret-id \
persea --config /opt/persea/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --folder my-servers \
  --scope shared
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--file` | (required) | Path to the mysqldump SQL file |
| `--folder` | `imported` | Target folder in the address book |
| `--scope` | `shared` | `shared` (visible to all instances) or `instance` (this instance only) |
| `--allowed-groups` | (empty) | Comma-separated OIDC groups allowed to access the imported tree; applied to the root folder, subfolders inherit |
| `--dry-run` | off | Preview without writing anything |

## What gets imported

The importer maps Guacamole connection parameters to persea connections fields:

| Guacamole parameter | Connections field |
|--------------------|--------------------|
| `hostname` | `hostname` |
| `port` | `port` |
| `username` | `username` |
| `password` | `password` |
| `private-key` | `private_key` |
| `domain` | `domain` |
| `security` | `security` |
| `ignore-cert` | `ignore_cert` |
| `color-depth` | `color_depth` |
| `enable-drive` | `enable_drive` |
| `remote-app` | `remote_app` |
| `remote-app-dir` | `remote_app_dir` |
| `remote-app-args` | `remote_app_args` |

### Supported protocols

- **SSH** connections
- **RDP** connections (including RemoteApp)
- **VNC** connections

Unsupported protocols (telnet, kubernetes, etc.) are skipped with a warning.

### Connection groups

Guacamole's connection group hierarchy is preserved as folder structure. Each
group becomes a sanitized subfolder under the target folder, and its
connections land inside it. For example, a connection named "Firewall" in
group "Production > DMZ" is imported as `imported/Production/DMZ/Firewall`.
Connections without a parent group land at the root of the target folder.

### Name handling

- Spaces are replaced with hyphens
- Special characters are stripped
- Duplicate names get a `-2`, `-3` suffix
- Names are truncated to 64 characters
- The original connection name is preserved in the `display_name` field

## After import

Once imported, connections appear in the connections UI. You can:

- Edit entries to add features not available in Guacamole (login scripts, autofill, domain allowlists)
- Move entries between folders
- Set folder-level access controls via `allowed_groups`
- Enable per-entry clipboard restrictions (`disable_copy`/`disable_paste`)

## Notes

- The import is additive: existing entries in the target folder are left untouched. Re-running the import fails for names that already exist (duplicate names are deduplicated with `-2`, `-3` suffixes only within a single run) — delete or rename existing entries before re-importing. Use `db-migrate-from-vault`'s `--overwrite` for the Vault→DB path instead.
- Guacamole user/group permissions are not imported. Use persea's OIDC group mappings and folder `allowed_groups` instead.
- In DB mode, passwords and private keys are encrypted with AES-256-GCM into the database (`enc:v1:` values), never stored in plaintext; in Vault storage mode they go to Vault, encrypted at rest and never touching disk.

# Migrating from Vault to the database backend

If you want to stop using Vault and store connections in the database instead
(the `[storage]` backend, see [Configuration](configuration.md#storage-section)),
the `db-migrate-from-vault` subcommand copies address-book entries out of Vault
into the DB's `address_book_folders` / `address_book_entries` tables
(credentials into `address_book_credentials`). Credential fields are
encrypted with AES-256-GCM on the way in; non-credential fields are stored as
plain JSON params. Per-user credential variables (the `users/` subtree) are
migrated too, with values encrypted.

The command is idempotent: entries whose `(name, group_id)` already exist in
the DB are skipped unless `--overwrite` is given. It exits non-zero if any
entry failed to migrate.

## Step 1: Preview

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> VAULT_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  db-migrate-from-vault --scope shared --dry-run
```

The dry run prints every folder group, entry, and user credential set it would
migrate, plus a summary line.

## Step 2: Migrate

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> VAULT_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  db-migrate-from-vault --scope shared
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--scope` | (required) | `shared` or `instance` |
| `--overwrite` | off | Overwrite entries that already exist in the DB (default: skip existing) |
| `--dry-run` | off | Preview without writing to the DB |
| `--vault-delete` | off | Delete entries from Vault after a successful migration (not applicable to user credentials) |

## Requirements

- `[vault]` configured in `config.toml` (the source) and `VAULT_SECRET_ID` set
- `PERSEA_STORAGE_KEY` set to the 64-character hex key that will encrypt the
  DB credentials (`ENCRYPTION_KEY` is accepted as a legacy fallback name).
  This must be the same key persea runs with afterwards, or it will not be able
  to decrypt the credentials. Generate one with `openssl rand -hex 32`.

## What gets encrypted

`password`, `private_key`, `container_password`, and `proxmox_token_secret`
values are encrypted (`enc:v1:` prefix) into the `address_book_credentials`
table — the same set of fields the runtime API encrypts. Everything else,
including jump-host credentials and `spice_ca_cert`, is carried in the entry's
plain JSON params. Credential variable references (e.g. `$corp_password`, see
[Credential Variables](credential-variables.md)) are encrypted like any other
value; they are decrypted before variable resolution at connect time, so they
keep resolving after the migration.

## Cut over

Once the migration succeeds, run persea with the DB storage backend:

```toml
[storage]
backend = "db"
encryption_key = "<64-char-hex-key>"
```

(or `PERSEA_STORAGE_KEY` in the environment). With `backend = "db"`, connection
credentials come exclusively from the DB — Vault is not consulted for them.
Vault is still used for per-user credential variables (My Credentials) and the
LUKS drive key, so keep `[vault]` configured if you use either of those, and
remove it once you no longer do.

# Splitting to multiple Vaults (disaster recovery)

If you already run a single Vault serving both the `shared` and `instance`
scopes and want to move a scope onto a dedicated Vault (see
[Multiple Vault backends](configuration.md)), the `vault-migrate` subcommand
copies a scope's whole subtree between two configured backends. Because the
scope-to-path layout is identical in every backend, this is a same-identity
copy, not a rewrite: it moves the entries **and** each folder's access config
(`.config`), so `allowed_groups` and inheritance travel with them.

## Step 1: Preview

Configure the new backend block (e.g. `[vault_shared]`) and its
`VAULT_SHARED_SECRET_ID`, then dry-run the copy:

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared --dry-run
```

## Step 2: Copy

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--scope` | (required) | `shared` or `instance` |
| `--from` / `--to` | (required) | Backend names: `vault`, `vault_shared`, or `vault_local` |
| `--dry-run` | off | Preview without writing to the destination |
| `--overwrite` | off | Overwrite entries that already exist at the destination (default: skip existing) |
| `--users` | off | Also copy every per-user credential secret (`users/*`). This makes those credentials shared; normally you toggle per-credential in My Credentials instead. |

## Step 3: Cut over

Routing is deterministic and single-source: once `[vault_shared]` is configured,
the `shared` scope reads only from it, with no fall-back to `[vault]`. So the
order matters:

1. Copy the subtree first (Step 2).
2. Then add the `[vault_shared]` block and restart persea.

Doing it the other way round makes shared connections briefly disappear (the
data is safe in the old Vault, just not being read). Entries and folders are
single-source; only per-user credentials merge across backends, so those never
have a gap.
