# Docker Compose and nginx examples

Runnable examples for persea deployments.

| File | What it is |
|------|------------|
| `docker-compose.sqlite.yml` | Minimal single-service stack: persea with the bundled SQLite database |
| `docker-compose.postgres.yml` | persea with a PostgreSQL backend |
| `docker-compose.mysql.yml` | persea with a MySQL backend |
| `nginx.conf` | nginx reverse proxy: HTTP to HTTPS redirect, TLS termination, WebSocket support |

## One-liners

```bash
docker compose -f docs/examples/docker-compose.sqlite.yml up -d
docker compose -f docs/examples/docker-compose.postgres.yml up -d
docker compose -f docs/examples/docker-compose.mysql.yml up -d
```

Then open `https://your-server:8089` and complete the setup wizard.

## What to replace before starting

- `PERSEA_STORAGE_KEY` (all three files): generate your own with
  `openssl rand -hex 32`. The key encrypts connection credentials stored in
  the database, and it must never change after the first start, or existing
  credentials become undecryptable. The image's entrypoint can generate a
  key itself, but it writes it into the container's ephemeral config, so
  pinning it via the environment is what keeps it stable across recreates.
  The shipped value is a placeholder, not a key: persea refuses to start
  with it (it is not a 64-char hex string), so a forgotten replacement
  fails loudly in the container logs instead of silently running with a
  known key.
- `change-me` passwords (postgres and mysql files): the database password
  appears twice per file, in the database service environment and inside
  `PERSEA_DB_URL`; keep the two in sync.
- `example.com` in `nginx.conf`: replace with your real hostname.

## How the image behaves on first start

- Copies the default config, generates a self-signed TLS certificate into
  the `persea-tls` volume, and writes an admin API key to
  `/opt/persea/data/admin-key.txt`.
- Keep the `persea-tls` volume across container recreates: without it the
  certificate changes and browsers warn about the new fingerprint.
- The image ships its own healthcheck (`curl -skf
  https://localhost:8089/api/health`), so the compose files add none for
  the persea service. The database services get one, because persea must
  not start before the database is ready.

## Behind a reverse proxy

- `nginx.conf` terminates TLS and proxies to `127.0.0.1:8089`. The
  postgres and mysql files publish persea's port to the host loopback only;
  for direct access without a proxy, change `"127.0.0.1:8089:8089"` to
  `"8089:8089"`.
- With persea in Docker and nginx on the host, connections arrive from the
  Docker bridge gateway, not from 127.0.0.1: set `trusted_proxies` in
  persea's config to the bridge subnet (for example `["172.17.0.0/16"]`).
  `["127.0.0.1/32"]` is correct for a bare-metal persea.
- Let's Encrypt renewal with persea's SIGHUP TLS hot-reload: see
  [Reverse Proxy Configuration](../reverse-proxies.md).
