# Troubleshooting

> **Audience:** operators diagnosing persea, guacd, Vault, and database failures.
> **Next:** [Configuration](configuration.md) for the config keys referenced below.

## guacd

### guacd won't start
- Check `systemctl status persea-guacd`
- Check logs: `journalctl -u persea-guacd -n 50`
- Verify FreeRDP plugins: `ls /opt/persea/lib/freerdp3/`
- Common: missing `LD_LIBRARY_PATH` — the systemd service sets this automatically

### guacd connection refused / timeout
- Verify guacd is listening: `ss -tlnp | grep 4822`
- Check TLS certs exist: `ls /opt/persea/tls/`
- Verify config has `guacd_addr = "127.0.0.1:4822"` (default) and that the address matches where guacd actually listens
- persea times out after 10 seconds; the log says `Timeout connecting to guacd at <addr>` or `Failed to connect to guacd at <addr>` (`src/guacd.rs`). If guacd is up but persea still fails, check for a firewall or a namespace/container boundary between the two processes (e.g. persea in Docker, guacd on the host)
- Sessions fail at connect time with a 502 `BAD_GATEWAY` error response when guacd is unreachable — see [API error format](api.md#error-response-format)

### guacd TLS handshake errors
- When `[tls] guacd_cert_path` is set, persea connects to guacd over TLS. The log message is `TLS handshake with guacd failed: ...` (`src/guacd.rs`)
- The certificate must be trusted by the CA configured in `guacd_cert_path` (or the system roots)
- The TLS server name is taken from `guacd_addr`, so if you use an IP address the certificate needs an IP SAN for that IP; use a hostname in `guacd_addr` (e.g. `localhost:4822`) if your cert only has DNS SANs
- Make sure guacd itself was started with matching TLS flags: `guacd -b 127.0.0.1 -l 4822 -L info -f -C /opt/persea/tls/cert.pem -K /opt/persea/tls/key.pem`

## persea

### Server won't start
- Check `systemctl status persea`
- Verify config: `persea --config /opt/persea/config.toml serve`
- Port 8089 already in use is a frequent culprit; check `ss -tlnp | grep 8089`
- Config validation failures print `FATAL: config validation failed: <msg>` and exit before serving — fix the offending key (see [Configuration](configuration.md))
- Non-fatal config problems print `WARNING: ...` but the server still starts; read these on startup (e.g. the deprecated `recording_path`, below)

### CSRF 403 errors
- Symptom: POST/PUT/DELETE/PATCH requests return `403` with `{"error": "CSRF token missing or invalid"}` (`src/csrf.rs`)
- Cause: the `X-CSRF-Token` header must exactly match the `csrf_token` cookie. Every state-changing request needs both, including API calls from scripts and curl
- Fix: read the `csrf_token` cookie (it is deliberately **not** `HttpOnly`, so JavaScript can read it) and send it back as `X-CSRF-Token`. The built-in UI does this automatically (see [Security > CSRF protection](security.md#csrf-protection)). For a curl example:
  ```bash
  curl -c jar.txt https://console.example.com/api/health > /dev/null
  TOKEN=$(awk '$6 == "csrf_token" {print $7}' jar.txt)
  curl -b jar.txt -H "X-CSRF-Token: $TOKEN" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d '{"role":"poweruser"}' \
    https://console.example.com/api/users/alice@example.com/role
  ```
- If you are behind a reverse proxy that strips cookies or rewrites headers, verify the proxy forwards `Set-Cookie` and does not cache responses that set it

### WebSocket connection fails
- **Origin rejected** — the WebSocket endpoint validates the `Origin` header against the `Host` header and rejects mismatches (and missing Origins) with `403` and `{"error": "cross-origin WebSocket request rejected"}` or `{"error": "WebSocket upgrade requires Origin header"}` (`src/websocket.rs`). Fix: connect from the same origin as the site (use the hostname users actually browse, not `localhost`, and don't omit the `Origin` header in custom clients)
- **Rate limited** — WebSocket upgrades are always rate limited at 5/sec burst 50 per IP (unlike the API routes, which are only limited when `rate_limit = true`). Bursts of reconnects or many users behind one NAT can hit this; the upgrade fails with a 429. See [Security > Rate limiting](security.md#rate-limiting)
- **Shutdown** — during graceful shutdown new WebSockets are rejected with 503 `{"error": "server is shutting down"}`
- Check if `allowed_networks` includes your IP (target-side CIDR checks still apply to the session target)
- Check browser console for WebSocket errors

### Sessions fail to connect
- Verify guacd is running and reachable (see above)
- Check the [deep health endpoint](api.md#get-apihealth) as an operator — it reports guacd, database, Vault, and disk status in one call
- Check session timeout settings (`session_pending_timeout_secs`)
- Verify the target host is reachable from the server and allowed by the per-protocol CIDR allowlists (`ssh_allowed_networks`, `rdp_allowed_networks`, `vnc_allowed_networks`, `web_allowed_networks`)
- `User is not responding` in the session: the owner browser never attached to the WebSocket (see [Owner vs. join](api.md#owner-vs-join) — mint the ws-ticket and open the client promptly after creating the session)

## Database

### SQLite locked errors
- The admin database is a single SQLite file (`db_path`, default `./persea.db`) with one writer process. Writes are serialised in-process, so lock errors usually mean a **second process** is touching the file: another persea instance, a manual `sqlite3` session, a backup tool, or the file living on NFS/SMB where SQLite locking is unreliable
- Check for other holders: `lsof persea.db` or `fuser persea.db`
- Keep the DB file on local disk; if you need MySQL/PostgreSQL, set `db_url` (see [Multi-database backend](configuration.md#multi-database-backend))
- Ensure the `db_path` directory is writable by the `persea` user

### Missing or wrong PERSEA_STORAGE_KEY (DB credentials)
- Symptom: sessions started from connections entries fail authentication on the target — the password sent to guacd is the raw encrypted blob (`enc:v1:...`) instead of the plaintext
- Cause: with the DB storage backend, credentials are stored AES-256-GCM encrypted (see [Security > Multi-database encryption at rest](security.md#multi-database-encryption-at-rest)). persea reads the key from the `PERSEA_STORAGE_KEY` environment variable (`src/api/address_book.rs`); if it is unset, encrypted values are passed through untouched; if it is the wrong key, decryption fails the same way
- Fix: export `PERSEA_STORAGE_KEY=<64-char hex>` (generate with `openssl rand -hex 32`) in `/opt/persea/env` and restart. It must be the **same key that was used to encrypt the data** — entries created without a key configured cannot be decrypted afterwards. `[storage].encryption_key` is the config-file equivalent. A wrong-format key (not 64 hex chars) crashes the process with `panic: invalid encryption key` at connect time — always validate the key before restart

### Session history / reports missing
- History is retained for `session_history_retention_days` (default 90) and cleaned hourly; 0 keeps forever. Records older than the window are gone

## Vault / OpenBao

### "403 Forbidden" from Vault
- Check that the role_id and secret_id are correct
- Verify the policy is attached: `vault read auth/approle/role/persea`
- Check token hasn't expired: `vault token lookup`
- If using namespaces, ensure the policy was created inside the namespace

### "connection refused" when connecting to Vault
- Verify Vault is running: `vault status`
- Check Vault is unsealed: `vault status` shows `Sealed: false`
- Verify the address in config.toml matches Vault's listen address
- Check firewall rules if Vault is on a different host

### Vault unreachable → Connections page banner
- Symptom: the Connections page shows the amber **"Connections temporarily unavailable. Cannot reach the Vault server or database."** banner and auto-retries every 15 seconds; if Vault was never configured it instead shows the "no Vault" panel
- Cause: `vault.any_connected()` failed at startup or on renew. The API then falls back to the DB address-book tables when they exist; if neither backend is available, folder/entry reads return `502 BAD_GATEWAY` (`src/api/address_book.rs`)
- Fix: restore Vault reachability (or the DB). Check `VAULT_SECRET_ID` is set, the AppRole secret isn't revoked, and the health endpoint's `vault` check — see [Security > Deep health check](api.md#get-apihealth)
- If a dedicated `[vault_shared]` or `[vault_local]` backend is down, only its scope shows unavailable; other scopes keep working (see [Multiple Vault backends](configuration.md#multiple-vault-backends-disaster-recovery))

### VAULT_SECRET_ID not set
- The secret_id must be in the environment where persea runs
- For systemd: add to `/opt/persea/env` file (the shipped unit loads it via `EnvironmentFile=-/opt/persea/env`)
- For Docker: pass as `-e VAULT_SECRET_ID=...` or use Docker secrets
- Check: `systemctl show persea | grep Environment`

### Token renewal failures
- Check persea logs for "Vault: token renewal failed"
- If 403 on renewal, the token expired — persea will re-authenticate automatically
- If persistent, verify the AppRole secret_id hasn't been revoked

### Namespace mismatch
- The `namespace` field in config.toml must match the Vault namespace where AppRole is enabled
- CLI commands must target the namespace: `vault namespace exec -namespace=admin -- vault policy write ...`

### mTLS errors
- Verify CA cert is correct: `openssl s_client -connect vault:8200 -CAfile ca.pem`
- Check client cert hasn't expired: `openssl x509 -in client.pem -noout -dates`
- Ensure the cert's CN matches what Vault's cert auth backend expects

## Recording

### recording_path deprecation warning
- Symptom: on startup persea prints `WARNING: top-level 'recording_path' is deprecated in favour of [recording].path ...`
- Cause: the top-level `recording_path` key still exists but is deprecated; when both are set, `[recording].path` wins (see [Configuration > `[recording]`](configuration.md#recording-section))
- Fix: move the value into the `[recording]` section:
  ```toml
  [recording]
  path = "/opt/persea/recordings"
  ```

### Disk full / max_disk_percent
- Symptom: recordings fail to write, or the deep health check reports `disk.status = "warning"`
- Cause: the recording directory's disk usage crossed `recording.max_disk_percent` (default 80; `0` disables the check). Rotation deletes the oldest recordings when usage exceeds the threshold (`src/recording.rs`, run every `rotation_interval_secs`)
- Fix: free space on the volume, lower `max_disk_percent` to rotate sooner, or raise the global `max_recordings` cap if recordings are being deleted too aggressively
- `disk.usage_percent` is reported by the [deep health check](api.md#get-apihealth)

## Shutdown

### Graceful shutdown waits / hangs
- On SIGTERM/SIGINT persea stops accepting new connections, cancels sessions, and waits `shutdown_timeout_secs` (default 30) for active sessions to drain before exiting (`src/config.rs`, `src/main.rs`). The log shows `Graceful shutdown initiated — waiting for sessions to drain` and, on timeout, `Graceful shutdown timeout reached — exiting`
- If restarts feel slow, active sessions are being cancelled one by one — reduce `shutdown_timeout_secs`, or drain sessions before maintenance
- During the drain window new WebSocket connections are rejected with 503, and LUKS drives are unmounted as the last step of shutdown

## Web browser sessions

### Chromium won't start
- Verify `chromium` is installed: `which chromium`
- Check the `persea` user has a home directory: `ls -la /home/persea`
- The `--in-process-gpu` flag is often missing; check Chromium flags in config
- Check Xvnc: `ps aux | grep Xvnc`

### Black screen in browser session
- Chromium may have crashed — check logs
- Verify DISPLAY variable is set correctly
- Check available display numbers in config (`display_range_start/end`)

## VDI

### Container won't start
- Verify Docker is running: `docker ps`
- Check the `persea` user is in the `docker` group
- Verify the VDI image exists: `docker images | grep vdi`
- Check container logs: `docker logs persea-vdi-{username}`

## OIDC

### Login callback fails
- Verify `redirect_uri` matches your OIDC provider configuration
- Check `OIDC_CLIENT_SECRET` environment variable
- Verify issuer URL is reachable from the server
