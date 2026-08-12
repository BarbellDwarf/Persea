# Deployment Guide

This guide walks through standing up persea for real: the network layout, installation, first-run setup, sign-in, connections, recording, and the day-to-day operations (monitoring, backups, upgrades). If you only need to get a test instance running, the [Installation guide](installation.md) is enough; this one is about production.

## How a production setup fits together

A typical deployment has three layers:

```
Internet
   |
[reverse proxy] ── HTTPS with a real certificate, rate limiting, (optional) Knocknoc gating
   |
[persea] ── users, connections, sessions, recordings
   |
[guacd] ── protocol translation (SSH, RDP, VNC)
   |
[targets] ── SSH servers, RDP desktops, VNC hosts
```

For a small deployment (up to roughly 50 concurrent sessions) everything runs on one server. For larger ones, guacd is the part to scale separately: each RDP session costs about 150 MB of RAM there.

### Ports

| Port | Service | Exposure |
|------|---------|----------|
| 443 | reverse proxy (HTTPS) | Public |
| 8089 | persea (HTTPS) | Loopback only: the proxy is the only client |
| 4822 | guacd (TLS) | Loopback only |
| 6100–6199 | Xvnc displays for web browser sessions | Loopback only |

## Step 1: Install persea

**Debian 13 (recommended)**: install the `.deb` from the [releases page](https://github.com/BarbellDwarf/persea/releases):

```bash
curl -sL https://api.github.com/repos/BarbellDwarf/persea/releases/latest \
  | sed -n 's/.*"browser_download_url": "\([^"]*_amd64\.deb\)".*/\1/p' \
  | head -1 | xargs wget
sudo apt install ./persea_*.deb
sudo systemctl enable --now persea
```

**Any other distribution**: use the Docker image, which bundles guacd and FreeRDP so nothing can clash with the host:

```bash
docker pull ghcr.io/barbelldwarf/persea:latest
docker run -d -p 8089:8089 \
  -v persea-data:/opt/persea/data \
  -v persea-recordings:/opt/persea/recordings \
  -v persea-tls:/opt/persea/tls \
  -v "$PWD/config.toml:/opt/persea/config.toml" \
  ghcr.io/barbelldwarf/persea:latest
```

The three volumes are what keep your data across container upgrades. The `persea-tls` one matters more than it looks: without it, the container generates a fresh self-signed certificate every time it is recreated, and browsers warn again about a changed certificate. For production, mount your own certificate over `/opt/persea/tls/cert.pem` and `key.pem`.

## Step 2: First-run setup

### The setup wizard

Open the web interface in a browser (for the package and Docker installs above: `https://your-server:8089`). Until a user account exists, persea shows the setup wizard, which creates the first admin account and writes a starter config. What each field means is explained in the [Installation guide](installation.md#the-setup-wizard); the two decisions worth thinking about here are:

- **Database URL**: leave it empty to use the local SQLite file (`/opt/persea/data/persea.db`), which is fine for most deployments. Enter a `postgres://`, `mysql://`, or `sqlite://` URL to store everything in a managed database instead. persea connects, creates the tables, and creates the admin straight in that backend: there is no SQLite intermediate step. The URL is written into the config, so it applies to every later start.
- **guacd mode**: *Embedded* for guacd on the same machine (the normal setup), *External* if guacd runs on another host.

![Login page](assets/screenshots/login.png)

### Databases

persea stores its data in one of two ways:

| Mode | Config | What is stored there |
|------|--------|----------------------|
| SQLite file (default) | `db_path = "/opt/persea/data/persea.db"` | Everything: users, connections, session history, audit log, settings |
| Managed database | `db_url = "postgres://…"` / `mysql://…` / `sqlite://…` | Everything: the database is the store |

With `db_url` set, all data routes to that backend and the schema tables are created automatically at startup (the database user needs permission to create tables). Connection parameters such as TLS go in the URL itself:

```toml
db_url = "postgres://user:password@dbhost:5432/persea?sslmode=require"
db_url = "mysql://user:password@dbhost:3306/persea?ssl-mode=REQUIRED"
```

If the backend is unreachable or the tables cannot be created, persea refuses to start with a `FATAL:` message rather than quietly falling back to the SQLite file. The CLI commands (`create-user`, `add-admin`) and the setup wizard work against whichever backend is configured.

Multiple instances can share one database (users, connections, and audit are shared). Sharing live sessions across instances requires the HA feature: see [High Availability](high-availability.md).

Moving an existing SQLite installation to a managed database is covered in [Migration](migration.md).

### The configuration file

Everything persea does is controlled from `/opt/persea/config.toml` (bare metal) or the mounted `config.toml` (Docker). Edit it, then restart the service (`sudo systemctl restart persea`).

For a production deployment the key settings are:

```toml
listen_addr = "127.0.0.1:8089"      # loopback only, the reverse proxy handles public traffic
guacd_addr = "localhost:4822"

[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
guacd_cert_path = "/opt/persea/tls/cert.pem"   # TLS between persea and guacd

# Trust the reverse proxy's X-Forwarded-For header
trusted_proxies = ["127.0.0.1/32"]

# Which networks sessions may connect to (prevents sessions into unintended hosts)
ssh_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
rdp_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
vnc_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

A CIDR (for example `10.0.0.0/8`) describes a range of network addresses; the allowlists above mean "sessions may only connect to hosts inside these ranges". Every protocol has one, and the defaults already cover the private network ranges plus localhost. If a session to a legitimate target fails, check the relevant list first.

### Environment variables

Every setting can also be supplied as an environment variable: the `PERSEA_` prefix, nested keys separated by `__` (for example `PERSEA_LISTEN_ADDR`, `PERSEA_SESSION_MAX_DURATION_SECS`). Environment variables win over the config file, which wins over built-in defaults. On bare metal, put them in `/opt/persea/env` (the service reads it at start); in Docker, pass them with `-e`.

| Setting | Env var | Default | What it does |
|---------|---------|---------|--------------|
| listen_addr | `PERSEA_LISTEN_ADDR` | `127.0.0.1:8089` | Where the web server listens |
| guacd_addr | `PERSEA_GUACD_ADDR` | `127.0.0.1:4822` | Where guacd listens |
| static_path | `PERSEA_STATIC_PATH` | `./static` | Web UI files |
| db_path | `PERSEA_DB_PATH` | `./persea.db` | SQLite file (used when `db_url` is unset) |
| db_url | `PERSEA_DB_URL` | unset | Managed database backend (`postgres://`, `mysql://`, `sqlite://`) |
| site_title | `PERSEA_SITE_TITLE` | `Persea` | Name shown in the browser tab and header |
| session_pending_timeout_secs | `PERSEA_SESSION_PENDING_TIMEOUT_SECS` | `60` | How long a session waits for the browser to attach before expiring |
| session_max_duration_secs | `PERSEA_SESSION_MAX_DURATION_SECS` | `28800` | Hard cap on session length (8 h; 0 = no cap) |
| session_idle_timeout_secs | `PERSEA_SESSION_IDLE_TIMEOUT_SECS` | `1800` | Session killed after this much silence (30 min; 0 = off) |
| password.min_length | `PERSEA_PASSWORD__MIN_LENGTH` | `15` | Minimum password length |
| password.history | `PERSEA_PASSWORD__HISTORY` | `5` | How many previous passwords are remembered and rejected on reuse |
| session_history_retention_days | `PERSEA_SESSION_HISTORY_RETENTION_DAYS` | `90` | How long session history is kept (0 = forever) |
| max_sessions | `PERSEA_MAX_SESSIONS` | `500` | Concurrent session limit across all users (0 = unlimited) |
| max_sessions_per_user | `PERSEA_MAX_SESSIONS_PER_USER` | `50` | Concurrent sessions per user |
| max_viewers | `PERSEA_MAX_VIEWERS` | `10` | Extra viewers allowed per shared session |
| ssh/rdp/vnc_allowed_networks | `PERSEA_SSH_ALLOWED_NETWORKS` etc. | private ranges + loopback | Target address allowlists per protocol |
| web_allowed_networks | `PERSEA_WEB_ALLOWED_NETWORKS` | loopback only | Allowed URL hosts for web browser sessions |
| trusted_proxies | `PERSEA_TRUSTED_PROXIES` | empty | Proxy addresses whose `X-Forwarded-For` is trusted |
| rate_limit | `PERSEA_RATE_LIMIT` | `false` | Extra API rate limiting (usually handled by the proxy) |
| tls.secure_cookies | `PERSEA_TLS__SECURE_COOKIES` | `true` | Must be `false` when serving HTTPS with a self-signed certificate (see [Troubleshooting](troubleshooting.md)) |
| storage.encryption_key | `PERSEA_STORAGE__ENCRYPTION_KEY` | unset | Key that encrypts stored connection credentials (also settable as `PERSEA_STORAGE_KEY`) |

The full reference, including the `[auth]`, `[vault]`, `[oidc]`, `[recording]`, `[drive]`, `[vdi]`, and `[theme]` sections, is in the [Configuration guide](configuration.md).

### An admin API key for automation (optional)

The web UI logs in with the admin account from the wizard. Scripts and API access instead use an admin API key:

```bash
sudo -u persea /opt/persea/bin/persea --config /opt/persea/config.toml add-admin --name admin
```

The printed key (it starts with `rgu_`) is shown only once; save it. It grants full admin access with no MFA, so delete it once sign-in is set up ([Step 5](#step-5-sign-in)) unless you still need it.

## Step 3: Put a reverse proxy in front

persea serves HTTPS itself, but with a self-signed certificate. For production, terminate TLS at a reverse proxy with a real certificate, HAProxy here; nginx, Caddy, Apache, and Traefik examples are in [Reverse Proxies](reverse-proxies.md) (that page also covers a `%2F` path-encoding gotcha that affects nested folders on several proxies).

Install and configure HAProxy:

```bash
sudo apt install haproxy
```

Create `/etc/haproxy/haproxy.cfg`:

```
global
    log /dev/log local0
    maxconn 4096
    stats socket /run/haproxy/admin.sock mode 0660 level admin
    ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11

defaults
    log     global
    mode    http
    option  httplog
    timeout connect 5s
    timeout client  30s
    timeout server  30s
    timeout tunnel  8h              # long-lived WebSocket sessions
    timeout http-request 10s        # slowloris protection

frontend https
    bind *:443 ssl crt /etc/ssl/private/persea.pem alpn h2,http/1.1
    bind *:80
    http-request redirect scheme https unless { ssl_fc }
    http-request del-header X-Forwarded-For
    option forwardfor
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains"
    default_backend persea

backend persea
    option httpchk GET /api/health
    server persea 127.0.0.1:8089 ssl verify none check inter 30s
```

Point HAProxy at a certificate, e.g. from Let's Encrypt:

```bash
sudo certbot certonly --standalone -d console.example.com
sudo cat /etc/letsencrypt/live/console.example.com/{fullchain,privkey}.pem \
    > /etc/ssl/private/persea.pem
sudo systemctl restart haproxy
```

Because the proxy terminates TLS, persea itself can keep its self-signed certificate: the proxy accepts it (`ssl verify none`). Make sure `trusted_proxies` in persea's config includes the proxy's address so audit logs record the real visitor IP, not the proxy's.

## Step 4: Get your RDP targets ready

RDP into Windows works out of the box. The setup below is about making desktop sessions fast and smooth.

**Windows targets.** For video-heavy workloads, run the performance script on the Windows machine (as Administrator):

```powershell
.\contrib\setup-rdp-performance.ps1
# with GPU hardware encoding:
.\contrib\setup-rdp-performance.ps1 -EnableGPU
```

It enables AVC 4:4:4, 60 FPS, desktop composition, and GPU encoding. Windows only sends H.264 when a GPU (physical or virtual) is present; without one it falls back to RemoteFX/Planar, which guacd re-encodes as JPEG/WebP, still good quality, just not as low-latency.

**Linux targets (xrdp).** For the best video experience on Linux desktops, rebuild xrdp with x264 H.264 support. A script does the whole job (desktop environment, audio, xrdp rebuild, GFX configuration):

```bash
# Run on the RDP target machine, not the persea server:
wget -O setup-xrdp-gfx.sh https://raw.githubusercontent.com/BarbellDwarf/persea/main/contrib/setup-xrdp-gfx.sh
sudo bash setup-xrdp-gfx.sh --desktop mate
```

`--desktop` picks the desktop environment (`mate` is recommended, lightweight and Windows-like; other options: `xfce`, `kde`, `gnome`, `none`). The script runs `--diagnose` for post-setup troubleshooting. Then, on the connection entry in persea, tick **Enable Graphics Pipeline (GFX)** and **H.264 Passthrough**. Full details and manual tuning are in [RDP Video Performance](rdp-video-performance.md).

**What happens when a session ends.** Ending a session (tab close, the toolbar **Disconnect**/**Log Out** buttons, admin termination, or an idle/max-duration reap) actively closes the guacd connection, and each protocol reacts differently:

- **SSH**: the connection is torn down and the remote shell is terminated.
- **RDP**: the RDP connection is closed, but the Windows user session is **not** logged off. Windows leaves it in the **Disconnected** state: the user stays logged in, desktop apps keep running, and the session keeps consuming a Remote Desktop license. (guacd's RDP plugin has no logoff-on-disconnect.)
- **VNC / SPICE**: the connection closes; whether the remote desktop keeps running depends on the VNC/SPICE server. persea-managed sessions are always cleaned up: web browser sessions (Xvnc + Chromium) are killed by persea on session end, and VDI containers are stopped when the session ends.
- **Windows target:** to end disconnected Windows sessions automatically, set the Group Policy **Set time limit for disconnected sessions**, `Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Session Time Limits`, and set it low (e.g. 1–5 minutes). This is the supported way to end abandoned RDP sessions.

> **Future work:** true Windows logoff on disconnect would require a guacd fork change (RDP logoff-on-disconnect) or an out-of-band `shutdown /l` against the target: neither is implemented today.

## Step 5: Sign-in

### OIDC single sign-on (recommended)

With OIDC, users sign in through your existing identity provider (Authentik, Keycloak, Okta, Entra ID, Google; any provider that speaks OpenID Connect) instead of with a persea password. Add to `config.toml`:

```toml
[oidc]
issuer_url = "https://your-idp.example.com"
client_id = "persea"
redirect_uri = "https://console.example.com/auth/callback"
groups_claim = "groups"
```

Set the client secret in `/opt/persea/env` (or as the `OIDC_CLIENT_SECRET` environment variable) rather than in the config file:

```bash
echo 'OIDC_CLIENT_SECRET=your-secret-here' | sudo tee -a /opt/persea/env
sudo chmod 600 /opt/persea/env
sudo systemctl restart persea
```

persea must be restarted after the change. The login page then shows a sign-in button alongside the local form.

**Group-to-role mapping.** Roles are assigned per user, but you can map SSO groups to roles automatically: on the Admin → Users page or via the `POST /api/admin/group-mappings` API endpoint. Users arriving from a mapped group get that role on login. (New OIDC users default to *operator* unless a mapping applies, changeable with the `default_role` OIDC setting.)

![Admin users page](assets/screenshots/admin-users.png)

Provider-specific walkthroughs (Authentik, JumpCloud, Entra ID, …) are in [Integrations](integrations.md). SAML, LDAP, and RADIUS are available as alternatives under `[auth]`: see the [Configuration guide](configuration.md).

### Remove the bootstrap API key

Once sign-in works and you have an admin user, delete the automation key from [Step 2](#step-2-first-run-setup); it is full-admin and skips MFA:

```bash
sudo -u persea /opt/persea/bin/persea --config /opt/persea/config.toml list-admins
sudo -u persea /opt/persea/bin/persea --config /opt/persea/config.toml delete-admin --name admin
```

For programmatic API access later, create scoped [user API tokens](roles-and-access-control.md) instead.

## Step 6: Connections (database or Vault)

The Connections page is the address book: folders and connection entries (SSH, RDP, VNC, web sessions, VDI). Each entry stores the host, port, and credentials. Credentials never reach the browser; persea reads them server-side and hands them to guacd when the session starts.

By default everything, including credentials, is stored in the database, with credentials encrypted (AES-256-GCM) using the key from `[storage]` / `PERSEA_STORAGE_KEY`:

```toml
[storage]
backend = "db"        # "db" (default) or "vault"
encryption_key = "…"  # 64-char hex; generate with: openssl rand -hex 32
```

The database backend works out of the box and is the recommended default. The `encryption_key` is required when `backend = "db"` and must not change afterwards; changing it makes stored credentials undecryptable.

Alternatively, store credentials in HashiCorp Vault or OpenBao (`[storage] backend = "vault"`), for example to keep secrets in a central store. Setup: install Vault, enable KV v2, create a policy for `secret/data/persea/*`, enable AppRole auth, then:

```toml
[storage]
backend = "vault"

[vault]
addr = "http://127.0.0.1:8200"
role_id = "<your-role-id>"
```

```bash
echo 'VAULT_SECRET_ID=your-secret-id' | sudo tee -a /opt/persea/env
sudo systemctl restart persea
```

Check the persea logs for `Vault: authenticated via AppRole` to confirm. The full Vault walkthrough is in [Integrations](integrations.md). Moving an existing Vault-backed address book into the database is covered in [Migration](migration.md).

![Connections page](assets/screenshots/connections.png)

## Step 7 (optional): gate the login page with Knocknoc

[Knocknoc](https://knocknoc.io) removes the login page from the internet entirely. Instead of exposing persea's login to scanners and password-guessing bots, Knocknoc requires users to authenticate (SSO + MFA) at the network layer first; only then can their traffic reach persea.

Add to the HAProxy config (ACL #600 is managed by knocknoc-agent via the admin socket):

```
acl knoc_persea src -u 600
acl is_root path /

use_backend persea if is_root knoc_persea
use_backend denied   if is_root
use_backend persea
```

Only the front page is gated; API endpoints, OIDC callbacks, and session share links pass through to persea's own authentication.

## Step 8 (optional): file transfer

File transfer is off by default. To let RDP sessions mount a shared drive (and SSH sessions use browser-side SFTP):

```toml
[drive]
enabled = true
drive_path = "/opt/persea/drives"
drive_name = "Shared Drive"
```

For regulated environments, the same volume can be LUKS-encrypted with the key stored in Vault: `sudo /opt/persea/bin/drive-setup.sh` sets it up, details in [Integrations](integrations.md).

## Step 9 (optional): session recording

Recording is on by default: every session is saved to the recording directory as a `.guac` file and can be replayed in the browser from the Sessions/Recordings pages. Rotation prevents disk fill-up:

```toml
[recording]
enabled = true
path = "/opt/persea/recordings"
max_disk_percent = 80        # delete oldest recordings when disk usage exceeds 80%
max_recordings = 1000        # keep at most 1000 recordings (0 = unlimited)
rotation_interval_secs = 300 # check every 5 minutes
```

(There is a legacy top-level `recording_path` key; move its value into `[recording]` as above; the old key prints a deprecation warning at startup.)

![Sessions page with the live session list](assets/screenshots/sessions.png)

## Day-to-day operations

### Monitoring

- **Health check**: `GET /api/health` answers `{"status":"ok"}` to anyone. Logged-in users with the operator role or higher get the deep check: guacd reachability, database, Vault (configured/connected), and disk usage in one call. It is the first thing to ask when something seems wrong.
- **Metrics**: `GET /metrics` exports Prometheus metrics.
- **System status**: `GET /api/system/status` (admin only) reports version, uptime, and active session count.
- **Reports**: session history, top connections, and top users are on the Reports page (admin) and via the reports API.

![Admin settings page](assets/screenshots/admin-settings.png)

### License

persea's enterprise features (high availability, and anything beyond the basics) are available for a 30-day evaluation period after which a license key is needed. The current status is shown on Admin → License; paste a key there or set `license_key` in the config.

![Admin license page](assets/screenshots/admin-license.png)

### Backups

Back up these paths:

- `/opt/persea/config.toml`: configuration.
- `/opt/persea/data/persea.db`: users, API keys, session history, settings (and connections, when using the database storage backend).
- `/opt/persea/env`: secrets (Vault secret ID, OIDC client secret).
- `/opt/persea/recordings/`: session recordings, if you need them for compliance.
- If connections live in Vault (`backend = "vault"`), back up Vault separately.

In Docker, the named volumes hold all of the above.

### Upgrading

```bash
# Debian package
sudo apt install ./persea_new-version.deb
sudo systemctl restart persea
```

Config files are preserved across upgrades, and database tables migrate automatically at startup. In Docker, pull the new image and recreate the container with the same volumes.

### Security checklist

- [ ] The reverse proxy terminates TLS with a real certificate (not self-signed)
- [ ] persea listens on loopback only (`listen_addr = "127.0.0.1:8089"`)
- [ ] Network allowlists configured per protocol (sessions can't reach unintended hosts)
- [ ] Sign-in via OIDC/SAML/LDAP with group-to-role mappings
- [ ] Bootstrap API key deleted once sign-in works
- [ ] Knocknoc gating the login page (optional but strongly recommended)
- [ ] File-transfer storage encrypted if used in regulated environments
- [ ] Session recording enabled for audit compliance
- [ ] `/opt/persea/env` is `chmod 600`
- [ ] `trusted_proxies` matches the reverse proxy's address

## A note on the audit log

The audit log chains every event into the previous one with a hash, so any change to old entries is detectable. That makes it **tamper-evident, not tamper-proof**: someone with database write access could rewrite the chain from a point of tampering onward. There is no external signature or timestamp authority.

If the audit log matters for compliance, compensate with:

- **External anchoring**: periodically export the chain's head hash and sign it elsewhere.
- **SIEM streaming**: forward audit events to an external log collector in real time.
- **WORM storage**: write the log to write-once-read-many storage if available.
- **Database access controls**: restrict who can write to the persea database.
