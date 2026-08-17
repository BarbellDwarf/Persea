# persea v1.0.2

persea v1.0.2 is a small admin-CLI iteration.

## New

- **`persea set-password --email <email>`** — reset an existing user's password from the server box. Validates the password policy (minimum length, reuse history — identical to the change-password API), updates the hash, records the reuse-history entry, and clears the failed-login lockout. Pass `--password` for scripting, or let it prompt without echo. The password is never printed.
- **`persea unlock-user --email <email>`** — clear the failed-login lockout without changing the password (lockout-DoS recovery).

## Fixed

- **`persea create-user` no longer echoes the plaintext password** to stdout (audit round 4 finding).

## Examples

```
sudo -u persea /opt/persea/bin/persea --config /opt/persea/config.toml set-password --email admin@example.com
sudo -u persea /opt/persea/bin/persea --config /opt/persea/config.toml unlock-user --email admin@example.com
```

The CLI commands work against SQLite and the PostgreSQL/MySQL backends.
