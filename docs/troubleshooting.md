# Troubleshooting

This guide works through problems symptom by symptom: what you see, what is usually causing it, and how to fix it. If your symptom is not listed, the two tools below (logs and the health check) will usually point at the cause anyway.

## Where to look first

**The logs.** persea and guacd write their logs to standard output, which the service manager captures:

- Bare metal (Debian package / install script): `sudo journalctl -u persea -n 100 --no-pager` and `sudo journalctl -u persea-guacd -n 100 --no-pager`.
- Docker: `docker logs <container-name>`.

Useful lines to look for: `Timeout connecting to guacd at <addr>` / `Failed to connect to guacd at <addr>` (guacd unreachable), `TLS handshake with guacd failed` (guacd TLS problem), `Vault: authenticated via AppRole` / `Vault: token renewal failed`, `FATAL:` (config or database problem at startup, server exits), `WARNING:` (non-fatal config problems, server keeps running). The log verbosity is controlled by `RUST_LOG` (e.g. `RUST_LOG=debug` for more detail); guacd's verbosity is set with `-L` in its service config.

**The health check.** `GET /api/health` answers `{"status":"ok"}` to anyone, so it is a quick liveness probe:

```bash
curl -k https://localhost:8089/api/health
```

When you are logged in with the operator role or higher, the same endpoint returns the deep check: guacd up/down, database, Vault (configured/connected), and disk usage — one call that tells you most of what can be wrong.

## Can't reach the login page

**Symptom:** the browser shows a connection error, a timeout, or a certificate warning; the page never loads.

- **Cause: the server isn't running.** Fix: check the service — `sudo systemctl status persea` (bare metal) or `docker ps` (Docker). If it failed, read the log (see above). A `FATAL:` message at startup means the config or database failed validation; the server exits before serving anything. Fix the offending setting and start again.
- **Cause: a port or address problem.** persea listens where `listen_addr` says (default `127.0.0.1:8089`). If that is a loopback address and you're browsing from another machine, nothing answers — either the reverse proxy is supposed to be in front (check it is running) or the address must be changed. Also check nothing else is squatting on the port: `ss -tlnp | grep 8089`.
- **Cause: the browser can't trust the certificate.** Out of the box persea serves a self-signed certificate. Click through the warning once (or set up a proper certificate — see [TLS problems](#tls-problems) below).
- **Cause: a reverse proxy is misconfigured or down.** If there is a proxy in front, check the proxy itself and that it can reach persea on 8089.

## Login fails

**Symptom:** you enter credentials and land back on the login page, possibly with an error message.

- **Cause: wrong credentials.** The login page shows "invalid credentials" when the username/password doesn't match any account. Fix: check the account exists and the password is right; an admin can reset it. Each failed attempt is logged in the audit log and in the server log (`Password login failed: ...`).
- **Cause: the account is locked out.** After more than 5 failed attempts within 15 minutes (per account and source address), persea blocks further attempts and shows "Account temporarily locked due to too many failed attempts. Please try again later." Fix: wait for the window to pass, or have an admin check the audit log for the failed attempts.
- **Cause: the browser refuses the session cookie (self-signed certificates).** This one is silent: the login *succeeds* server-side but the browser never stores the `persea_session` cookie, so you end up back on the login page. Browsers block cookies marked `Secure` over a connection whose certificate is untrusted — even after you click through the warning. Fix: set `secure_cookies = false` under `[tls]` in `config.toml` (env: `PERSEA_TLS__SECURE_COOKIES=false`) and restart. `install.sh` and the Docker image add this automatically when they generate their own certificate; set it by hand if you generated or supplied the certificate yourself. See [TLS problems](#tls-problems).
- **Cause: sign-in through SSO (OIDC) fails.** The callback URL must match your identity provider's configuration exactly (`redirect_uri` in `[oidc]`), the `OIDC_CLIENT_SECRET` must be set in the environment, and the issuer URL must be reachable from the server. Also verify persea was restarted after the change.
- **Cause: rate limiting.** Login attempts are rate-limited per address (5/second burst 10). A script or a network of users behind one NAT can hit this; wait a moment and retry.

## Can't connect to a session

**Symptom:** you click Connect (or create an ad-hoc session) and the session fails to start, errors out, or hangs.

- **Cause: guacd is down or unreachable.** Everything flows through guacd; if it isn't running, sessions fail immediately (the API returns a 502 "bad gateway" error) and the server log says `Timeout connecting to guacd at <addr>` or `Failed to connect to guacd at <addr>`. Fix: `sudo systemctl status persea-guacd` (bare metal) or check the container (Docker); verify it is listening with `ss -tlnp | grep 4822`; verify `guacd_addr` in the config matches where guacd actually listens. If guacd is up but persea still can't reach it, suspect a firewall or a container/host boundary between the two processes. The deep health check reports guacd up/down directly.
- **Cause: the target machine is unreachable.** Fix: check the target from the server itself (`ping`, `nc -zv <host> <port>`). Remember guacd connects from the server — a host that works from your desk may not be reachable from the server's network.
- **Cause: the target is outside the allowed networks.** Every protocol has a CIDR allowlist (`ssh_allowed_networks`, `rdp_allowed_networks`, `vnc_allowed_networks`, `web_allowed_networks`). A session to a host outside the list is refused. Fix: add the target's network to the relevant list in `config.toml` and restart. (Defaults: SSH/RDP/VNC allow the private ranges plus localhost; web browser sessions allow loopback only.)
- **Cause: the protocol is disabled.** Admins can switch protocols off on the Admin → Settings page. A disabled protocol refuses new sessions with "X sessions are disabled by an administrator". Fix: re-enable it in Settings (takes effect immediately, no restart). VNC cannot be disabled.
- **Cause: credentials missing or wrong.** For entries from the address book: the stored credentials are encrypted with the storage key. If `PERSEA_STORAGE_KEY` is unset or changed, guacd receives the raw encrypted blob and authentication on the target fails. Fix: set the same key that was used when the credentials were stored (see [Database problems](#database-problems)). Otherwise, just re-enter the credentials on the entry.
- **Cause: session limits.** The server allows 500 concurrent sessions total, 50 per user, 10 extra viewers per session by default. Hitting a limit rejects the new session. Fix: end unused sessions, or raise the limits in config.
- **Cause: browser never attached.** A session that starts but then shows "User is not responding" means the browser never attached to the WebSocket (the owner must open the client promptly after the session is created). Fix: reconnect to the session from the Sessions page.
- **Cause: web browser sessions need Xvnc and Chromium.** If those binaries are missing, web sessions fail at start. Fix: install `tigervnc-standalone-server` and Chromium, and check `xvnc_path`/`chromium_path` in the config.

## Recordings not appearing

**Symptom:** sessions run, but the Recordings page is empty, or playback files are missing.

- **Cause: recording is disabled.** `[recording] enabled = false` turns recording off globally. Fix: set it to `true`.
- **Cause: the recording path differs from where files are actually written.** Recordings land in `[recording].path` (default `./recordings`, i.e. `/opt/persea/recordings` in standard installs). If the process can't write there (permissions, a read-only mount, a Docker volume not mounted), sessions may fail or files go elsewhere. Fix: check the directory exists and is writable by the persea user, and check the config path. There is also a legacy top-level `recording_path` key — if both are set, `[recording].path` wins, and the legacy key prints a deprecation warning at startup.
- **Cause: rotation deleted them.** When disk usage on the recording volume crosses `max_disk_percent` (default 80), the oldest recordings are deleted to make room, and a global cap on the number of recordings (`max_recordings`, default 1000 — the Debian package ships 0, meaning no cap) trims the oldest. Fix: free disk space, or adjust the two settings if recordings are being removed too aggressively.
- **Cause: recording failed mid-session.** Recordings are written by guacd as `.guac` files; a guacd crash or hard kill mid-session can leave a partial or missing file. Check the guacd log around the session time.
- **Cause (SSH text transcripts):** terminal text transcripts ("typescripts") are a separate, optional feature — guacd writes them only when `recording.typescript_path` is set, and the path is on the guacd side (guacd must be able to write there). Graphical `.guac` recordings are independent of this.

## Branding not applying

**Symptom:** the site name and logo shown in the browser don't match what you set.

- **Cause: the name/logo are set somewhere the page isn't reading.** The site name and logo are configured in two places: the config file (`site_title` in `config.toml`, `logo_url` under `[theme]`) and the Admin → Settings page (which stores them in the database). The settings page wins. Fix: set it where you expect it to take effect — for a permanent brand, use Admin → Settings so it survives config changes; the pages render the value that was in effect at start, so restart persea after changing `site_title` in the config file.
- **Cause: the logo URL doesn't load.** The logo is a URL the browser fetches — a filesystem path won't work, and a missing/renamed file shows nothing. Fix: put the logo where the web server serves it (for example under `/opt/persea/static/`) and use its URL path. The upload option on Admin → Settings handles this for you.
- **Cause: a cached page.** The browser may be showing a stale copy. Fix: hard-refresh (Ctrl/Cmd+Shift+R).

## TLS problems

- **Symptom: browsers show a certificate warning.** Out of the box persea uses a self-signed certificate. That is fine for testing; for production put a real certificate at the reverse proxy (see the [Deployment Guide](deployment-guide.md)) or replace `/opt/persea/tls/cert.pem` + `key.pem` with a certificate from your CA. Regenerate the self-signed one with `persea generate-cert --hostname your-host --out-dir /opt/persea/tls`.
- **Symptom: login is broken with a self-signed certificate (you log in and get bounced back).** That is the `secure_cookies` issue described under [Login fails](#login-fails) — set `secure_cookies = false` and restart.
- **Symptom: sessions fail with TLS handshake errors.** If `[tls] guacd_cert_path` is set, persea talks to guacd over TLS, and the certificate must be trusted by the CA the config points at (or the system roots). The TLS server name is taken from `guacd_addr`, so if that is an IP address the certificate needs an IP entry for it — use a hostname like `localhost:4822` if your certificate only covers names. Also confirm guacd itself was started with matching certificate flags (the `persea-guacd` service and the Docker entrypoint do this for you).
- **Symptom: you replaced the certificate and the old one still serves.** persea reloads the TLS certificate on SIGHUP — `sudo kill -HUP $(systemctl show -p MainPID --value persea)`. If the reload fails, the error is logged and the old certificate keeps serving.
- **Symptom: after renewing a Let's Encrypt certificate through the proxy, nothing changed.** The reverse proxy holds the certificate; persea's own self-signed cert is behind it. Restart the proxy after renewal so it picks up the new certificate.

## Setup wizard problems

- **Symptom: the wizard doesn't appear, or appears when it shouldn't.** The wizard is shown only while the database has **zero users** — it does not look at whether a config file exists. Fix: if it doesn't appear, a user already exists (create the admin from the CLI instead: `persea add-admin --name admin` for an API key, or `persea create-user --role admin` for a login account). If it appears and you've already set up, the database file persea is looking at may not be the one you set up (check `db_path`/`db_url`).
- **Symptom: "Database URL is required" or a URL mismatch error.** If the server was started with `db_url` in the config, the wizard cannot switch databases — it must match the running backend. Fix: change `db_url` in the config file and restart instead of using the wizard.
- **Symptom: setup completes but the config file wasn't written.** The wizard writes `/opt/persea/config.toml` (or the file given with `--config`). If the directory is not writable, it logs a warning and continues — the admin account exists but the settings are lost on restart. Fix: make the config directory writable by the persea user and re-run, or write the config by hand.
- **Symptom: the admin can't log in after setup.** See [Login fails](#login-fails) — with a self-signed certificate, check `secure_cookies` first.

## Other common problems

### CSRF 403 errors

- **Symptom:** POST/PUT/DELETE requests return `403` with `{"error": "CSRF token missing or invalid"}`.
- **Cause:** every state-changing request must send the `csrf_token` cookie value back in the `X-CSRF-Token` header. Scripts and curl calls need to do this explicitly; the built-in UI does it automatically.
- **Fix:** read the `csrf_token` cookie (it is deliberately readable by JavaScript) and echo it back as the header:
  ```bash
  curl -c jar.txt https://console.example.com/api/health > /dev/null
  TOKEN=$(awk '$6 == "csrf_token" {print $7}' jar.txt)
  curl -b jar.txt -H "X-CSRF-Token: $TOKEN" \
    -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d '{"role":"poweruser"}' \
    https://console.example.com/api/users/alice@example.com/role
  ```
- If a reverse proxy strips cookies or caches responses that set them, fix the proxy.

### WebSocket connection fails

- **Origin rejected** — the WebSocket endpoint checks that the `Origin` header matches the `Host`. Connect from the same hostname users actually browse (not `localhost`), and don't omit the `Origin` header in custom clients.
- **Rate limited** — WebSocket upgrades are always rate-limited (5/sec, burst 50 per address). Many users behind one NAT or a reconnect loop can hit this (HTTP 429). Wait and retry.
- **Shutting down** — during a graceful shutdown, new WebSockets get `503` "server is shutting down". Try again shortly.

### Database problems

- **"Database is locked" errors (SQLite).** The admin database is a single SQLite file with one writer. Lock errors mean a second process is touching it — another persea instance, a manual `sqlite3` session, a backup tool, or the file living on NFS/SMB (SQLite locking is unreliable there). Fix: find the other holder (`lsof persea.db` or `fuser persea.db`), keep the file on local disk, and ensure its directory is writable by the persea user. For shared filesystems use `db_url` with Postgres/MySQL.
- **Sessions fail authentication on the target with the raw encrypted blob.** Credentials stored by the database backend are AES-encrypted with the storage key. If `PERSEA_STORAGE_KEY` is unset, missing, or wrong, guacd receives the encrypted value instead of the real password. Fix: set the **same** key that encrypted the data (`PERSEA_STORAGE_KEY` in `/opt/persea/env`, or `[storage].encryption_key`), then restart. Entries created while no key was configured cannot be decrypted afterwards — re-enter those credentials. A wrong-format key (not 64 hex characters) crashes the process at connect time with `panic: invalid encryption key` — validate the key before restarting.
- **Session history missing.** History is kept for `session_history_retention_days` (default 90) and cleaned hourly; 0 keeps everything. Records older than the window are gone.

### Vault problems

- **"403 Forbidden" from Vault.** Check `role_id`/`secret_id` (AppRole), that the policy is attached (`vault read auth/approle/role/persea`), that the token hasn't expired, and — if namespaces are used — that policy and AppRole live in the same namespace as the `namespace` config field.
- **Connection refused to Vault.** Verify Vault is running and unsealed (`vault status`), that the address in config matches, and that the firewall allows it.
- **"Connections temporarily unavailable" banner.** The Connections page shows this when neither Vault nor the database can serve the address book; it retries every 15 seconds. Fix: restore Vault reachability (check `VAULT_SECRET_ID` is set and the AppRole secret isn't revoked — the deep health check reports Vault configured/connected). If only a dedicated `[vault_shared]`/`[vault_local]` backend is down, only its scope shows unavailable.
- **`VAULT_SECRET_ID` not set.** The secret must be in persea's environment: `/opt/persea/env` for systemd (check with `systemctl show persea | grep Environment`), `-e VAULT_SECRET_ID=...` for Docker.

### Web browser sessions

- **Chromium won't start.** Verify Chromium and Xvnc are installed and reachable as the config's `xvnc_path`/`chromium_path`, and that the `persea` user has a home directory (Chromium needs one). Check for running Xvnc processes: `ps aux | grep Xvnc`.
- **Black screen in a browser session.** Chromium may have crashed — check the logs around the session start. Also check the display-number range in config (`display_range_start`/`display_range_end`); a full range means no display is free.

### VDI containers

- **Container won't start.** Verify Docker is running, the `persea` user is in the `docker` group (restart the service after adding it), the image exists (`docker images`), and look at the container itself: `docker logs persea-vdi-<username>`.

### Graceful shutdown hangs

- On SIGTERM/SIGINT persea stops accepting new work and waits up to `shutdown_timeout_secs` (default 30) for active sessions to drain. If restarts feel slow, reduce the timeout or drain sessions before maintenance.
