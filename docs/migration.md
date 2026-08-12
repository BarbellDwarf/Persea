# Migration

This guide covers moving data into and around persea:

- importing connections from an existing Apache Guacamole installation,
- moving connection credentials out of Vault into the database,
- moving between database backends,
- splitting connections across multiple Vault servers.

Where credentials are stored is controlled by the `[storage]` section (see [Configuration](configuration.md)): with `backend = "db"` (the default) connection credentials are encrypted into the database; with `backend = "vault"` they are stored in Vault/OpenBao. Folders and entries are always stored in the database.

## Importing connections from Apache Guacamole

persea can import the address book from an Apache Guacamole MySQL/MariaDB database into its own Connections address book.

### Before you start

- A MySQL/MariaDB dump of your Guacamole database (see next step).
- The storage encryption key. In DB mode this is required: a 64-character hex string set via `PERSEA_STORAGE_KEY` or `[storage].encryption_key`, generated with `openssl rand -hex 32`. Without it, imported passwords and private keys are **not** stored; entries import with no credentials.
- If you store credentials in Vault instead (`backend = "vault"`): a working Vault/OpenBao with `[vault]` configured and `VAULT_SECRET_ID` set.

### Step 1: Export the Guacamole database

On the Guacamole database server, dump the three tables that hold connections:

```bash
mysqldump -u guacamole_user -p guacamole_db \
  guacamole_connection \
  guacamole_connection_parameter \
  guacamole_connection_group \
  > guacamole-dump.sql
```

Both the default dump format and `--skip-extended-insert` single-row dumps work, as long as the dump contains `INSERT INTO` statements for those tables.

### Step 2: Preview the import

Run with `--dry-run` first; it shows exactly what would be imported without writing anything:

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

Connections whose protocol persea doesn't support (telnet, kubernetes, and others) are skipped automatically with a warning.

### Step 3: Import

DB storage mode (default):

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> \
persea --config /opt/persea/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --folder my-servers \
  --scope shared
```

Vault storage mode:

```bash
VAULT_SECRET_ID=your-secret-id \
persea --config /opt/persea/config.toml \
  import-guacamole \
  --file guacamole-dump.sql \
  --folder my-servers \
  --scope shared
```

Options:

| Flag | Default | What it does |
|------|---------|--------------|
| `--file` | (required) | Path to the SQL dump file |
| `--folder` | `imported` | Folder in the address book to import under |
| `--scope` | `shared` | `shared` (visible on all instances) or `instance` (this instance only) |
| `--allowed-groups` | (empty) | Comma-separated OIDC groups allowed to access the imported tree; set on the root folder, subfolders inherit |
| `--dry-run` | off | Preview without writing anything |

### What gets imported

SSH, RDP (including RemoteApp), and VNC connections. The importer maps the Guacamole parameters it understands (hostname, port, username, password, private key, domain, security mode, certificate ignore, color depth, drive redirection, and the RemoteApp settings) onto the corresponding persea entry fields.

**Folders.** Guacamole's connection-group hierarchy becomes persea's folder structure, with each group a subfolder under the target folder and its connections inside it. A connection named "Firewall" in the group "Production > DMZ" imports as `imported/Production/DMZ/Firewall`. Connections without a parent group land directly in the target folder.

**Names.** Spaces become hyphens, special characters are stripped, names are truncated to 64 characters, and duplicates within a run get `-2`, `-3` suffixes. The original Guacamole name is kept in the entry's display name.

### After the import

The imported entries appear in the Connections page. You can then edit them to add things Guacamole didn't have: login scripts, autofill, domain allowlists, clipboard restrictions, and set folder-level access controls (`allowed_groups`).

Notes:

- The import is additive: existing entries are left alone. Re-running an import fails on names that already exist (deduplication suffixes only apply within a single run), so delete or rename existing entries before re-importing.
- Guacamole's user/group permissions are **not** imported. Set up persea's role mappings and folder access instead (see [Roles and Access Control](roles-and-access-control.md)).
- In DB mode, imported passwords and private keys are encrypted into the database and never stored in plaintext. In Vault mode they go to Vault.

## Moving connections from Vault into the database

If you currently store connection credentials in Vault and want to move them into the database (`backend = "db"`), the `db-migrate-from-vault` command copies the whole address book (folders, entries, and per-user credential variables) out of Vault and into the database, encrypting the credential fields (password, private key, container password, Proxmox token) with AES-256-GCM as it goes. Everything else, including jump-host credentials, is carried over as plain entry parameters.

The command is safe to re-run: entries that already exist in the database are skipped unless you pass `--overwrite`. It exits with a non-zero status if anything failed to migrate.

### Step 1: Preview

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> VAULT_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  db-migrate-from-vault --scope shared --dry-run
```

The dry run prints every folder, entry, and user credential set it would migrate, plus a summary.

### Step 2: Migrate

```bash
PERSEA_STORAGE_KEY=<64-char-hex-key> VAULT_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  db-migrate-from-vault --scope shared
```

Options:

| Flag | Default | What it does |
|------|---------|--------------|
| `--scope` | (required) | `shared` or `instance` |
| `--overwrite` | off | Overwrite entries that already exist in the database (default: skip) |
| `--dry-run` | off | Preview without writing |
| `--vault-delete` | off | Delete entries from Vault after a successful migration (user credentials are never deleted) |

### Requirements and cut-over

- `[vault]` must be configured in `config.toml` (it is the source) and `VAULT_SECRET_ID` set.
- `PERSEA_STORAGE_KEY` must be the same 64-character key persea will run with afterwards: it encrypts the database credentials, and a different key at runtime means the credentials cannot be decrypted (`ENCRYPTION_KEY` is accepted as a legacy name for the same variable).
- Credential-variable references (values like `$corp_password`: see [Credential Variables](credential-variables.md)) are encrypted like any other value but decrypted before use at connect time, so they keep working after the migration.

Once the migration succeeds, switch persea to the database backend:

```toml
[storage]
backend = "db"
encryption_key = "<64-char-hex-key>"
```

or set `PERSEA_STORAGE_KEY` in the environment. With `backend = "db"`, connection credentials come exclusively from the database, Vault is not consulted for them. Vault is still used for per-user credential variables (My Credentials) and the LUKS drive key, so keep `[vault]` configured if you use either of those, and remove it once you no longer do.

## Moving between database backends

persea can *store* its data in SQLite, PostgreSQL, or MySQL, but it does not ship a converter between them; a SQLite database cannot be handed to Postgres as-is, and there is no built-in export/import between backends. Two supported paths:

**Re-create on the new backend (recommended).** Point `db_url` at the new database in the config:

```toml
db_url = "postgres://user:password@dbhost:5432/persea"
```

Restart persea so it connects and creates the schema, then provision users again (the setup wizard or `create-user` creates the first admin on the new backend; other users and role mappings can be recreated via Admin → Users). Re-enter connection entries in the Connections UI. The old instance's session history, audit log, and recordings do not move: keep the old files if you need them for compliance.

**Manual export.** Dump the relevant tables from the old database and load them into the new one with schema adjustments:

```bash
sqlite3 persea.db .dump
```

persea does not ship a converter, so column names and formats must be adapted by hand, and the audit log's hash chain cannot be recomputed after a manual copy, so the copied audit history will not verify as untampered. This path is best avoided except for read-only historical data.

## Splitting connections across multiple Vault servers

If you run one Vault serving both the `shared` and `instance` scopes and want to move one scope onto its own Vault (a central fleet-wide Vault and a per-host local one, see [Multiple Vault backends](configuration.md)), the `vault-migrate` command copies a scope's entire subtree between two configured backends. Because the folder layout is identical in every backend, this is a straight copy: entries move **and** each folder's access config (`.config`, i.e. `allowed_groups` and inheritance) travels with them.

### Step 1: Preview

Add the new backend block to the config (e.g. `[vault_shared]`) with its own `VAULT_SHARED_SECRET_ID`, then dry-run:

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared --dry-run
```

### Step 2: Copy

```bash
VAULT_SECRET_ID=... VAULT_SHARED_SECRET_ID=... \
persea --config /opt/persea/config.toml \
  vault-migrate --scope shared --from vault --to vault_shared
```

Options:

| Flag | Default | What it does |
|------|---------|--------------|
| `--scope` | (required) | `shared` or `instance` |
| `--from` / `--to` | (required) | Backend names: `vault`, `vault_shared`, or `vault_local` |
| `--dry-run` | off | Preview without writing to the destination |
| `--overwrite` | off | Overwrite entries already present at the destination (default: skip) |
| `--users` | off | Also copy every per-user credential secret (`users/*`): this makes those credentials shared; normally you toggle that per credential in My Credentials instead |

### Step 3: Cut over

Routing is single-source: once `[vault_shared]` is configured, the `shared` scope reads only from it: there is no fallback to `[vault]`. So the order matters:

1. Copy the subtree first (Step 2).
2. Then add the `[vault_shared]` block and restart persea.

Doing it the other way round makes shared connections briefly disappear (the data is safe in the old Vault, just not being read). Entries and folders are single-source; only per-user credentials merge across backends, so those never have a gap.
