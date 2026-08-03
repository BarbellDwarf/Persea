# Ticket: Vault Optional + Credential Storage

wayfinder:research
Blocked by: 003 (Auth DB Schema), 001 (Multi-DB Backend)

## Question

How should persea make Vault optional while keeping it available for credential storage?

Currently Vault is the primary store for connections (address book) and credentials. The goal: DB becomes the primary store for connections/sessions/server info. Vault remains available for credential storage only (passwords, API keys, private keys).

Key decisions needed:

1. **DB as primary store** — Connections, connection groups, connection parameters, sharing profiles all move to DB tables.
2. **Vault as credential store** — Optional `[vault]` section. When configured, credentials (passwords, SSH keys, RDP passwords) stored in Vault. When not configured, credentials stored in DB (encrypted).
3. **Credential encryption in DB** — When Vault is not used, how to encrypt credentials at rest? AES-256-GCM with a key from config? Or leave it to DB-level encryption?
4. **Address book migration** — Existing Vault-stored connections need to move to DB. `persea db-migrate-from-vault` subcommand.
5. **Per-credential scope** — Can individual credentials be stored in Vault while others are in DB? Or is it all-or-nothing?
6. **Config structure** — `[vault]` section becomes optional. New `[storage]` section? Or just check if `[vault]` exists?
7. **Multi-backend Vault** — Keep existing `[vault_shared]`/`[vault_local]` for orgs that want Vault. But it's optional.

## Research needed

- Current Vault integration code (src/vault.rs) — what exactly is stored there
- How to encrypt credentials in DB (AES-256-GCM key management)
- Apache Guacamole's credential storage (DB-only, no Vault)
