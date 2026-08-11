# Deployment Guide

> **Audience:** operators standing up a production persea deployment (architecture, HAProxy, RDP targets, hardening).
> **Next:** [Installation](installation.md) for all install options; [Configuration](configuration.md) for the settings used below.

This guide covers network architecture, server preparation, RDP target setup, security hardening, and ongoing operations for a production persea deployment.

## Architecture Overview

A typical deployment has three layers:

```
Internet
   |
[HAProxy] ── TLS termination, rate limiting, Knocknoc ACL
   |
[persea] ── session management, WebSocket proxy, connections
   |
[guacd] ── protocol translation (SSH, RDP, VNC)
   |
[targets] ── SSH servers, RDP desktops, VNC hosts
```

**All components can run on a single server** for small deployments (up to ~50 concurrent sessions). For larger deployments, guacd is the bottleneck (~158 MB per RDP session) and can be scaled separately.

### Port allocation

| Port | Service | Exposure |
|------|---------|----------|
| 443 | HAProxy (HTTPS) | Public / Knocknoc-gated |
| 8089 | persea (HTTPS) | Loopback only (behind HAProxy) |
| 4822 | guacd (TLS) | Loopback only |
| 6000-6099 | Xvnc displays | Loopback only (web sessions) |

## Step 1: Install persea

### Debian 13 (recommended)

```bash
# Download the latest .deb from GitHub releases
# Asset name includes the version: persea_<version>+g<hash>_amd64.deb
wget https://github.com/BarbellDwarf/persea/releases/latest
sudo apt install ./persea_*.deb
```

This installs persea + guacd to `/opt/persea` with systemd services.

### Docker (recommended for non-Debian-13 hosts)

```bash
docker pull ghcr.io/barbelldwarf/persea:latest
docker run -d \
  -p 443:8089 \
  -v persea-data:/opt/persea/data \
  -v persea-recordings:/opt/persea/recordings \
  -v persea-tls:/opt/persea/tls \
  -v ./config.toml:/opt/persea/config.toml \
  ghcr.io/barbelldwarf/persea:latest
```

The Docker image bundles guacd + FreeRDP + dependencies, so it runs cleanly on Ubuntu, RHEL, Rocky, Arch, and other distros where the bare-metal `.deb` would hit a FreeRDP ABI mismatch. See [installation.md](installation.md#other-linux-distributions) for the full story on non-Debian-13 targets.

> **Persistent state:** the three named volumes (`persea-data`, `persea-recordings`, `persea-tls`) keep the SQLite database, recordings, and the TLS certificate across container recreations/upgrades. The `persea-tls` volume is important — without it, the entrypoint generates a fresh self-signed certificate on every container recreate, changing the cert fingerprint and re-triggering browser warnings. For production, mount your own certificate over `/opt/persea/tls/cert.pem` + `key.pem`; when persea generates a self-signed cert itself, it automatically adds `secure_cookies = false` to the config so browsers accept the session cookie over the untrusted connection.

See [installation.md](installation.md) for all install options.

## Environment Variables

All config options can be set via environment variables with the `PERSEA_` prefix.
Nested table keys use `__` as the separator (double underscore).

Examples:
- `PERSEA_LISTEN_ADDR`
- `PERSEA_DB_PATH`
- `PERSEA_SESSION_MAX_DURATION_SECS`
- `PERSEA_STORAGE_KEY` (special: storage encryption key)

| Config Key | Env Var | Default | Description |
|------------|---------|---------|-------------|
| listen_addr | PERSEA_LISTEN_ADDR | 127.0.0.1:8089 | Listen address |
| guacd_addr | PERSEA_GUACD_ADDR | 127.0.0.1:4822 | guacd daemon address |
| static_path | PERSEA_STATIC_PATH | ./static | Static files directory |
| db_path | PERSEA_DB_PATH | ./persea.db | SQLite database path |
| site_title | PERSEA_SITE_TITLE | Persea | Browser tab title |
| session_pending_timeout_secs | PERSEA_SESSION_PENDING_TIMEOUT_SECS | 60 | Pending session timeout |
| session_max_duration_secs | PERSEA_SESSION_MAX_DURATION_SECS | 28800 | Max session duration (8h) |
| auth_session_ttl_secs | PERSEA_AUTH_SESSION_TTL_SECS | 86400 | OIDC session TTL (24h) |
| session_history_retention_days | PERSEA_SESSION_HISTORY_RETENTION_DAYS | 90 | History retention days |
| xvnc_path | PERSEA_XVNC_PATH | Xvnc | Xvnc binary path |
| chromium_path | PERSEA_CHROMIUM_PATH | chromium | Chromium binary path |
| display_range_start | PERSEA_DISPLAY_RANGE_START | 100 | X display range start |
| display_range_end | PERSEA_DISPLAY_RANGE_END | 199 | X display range end |
| cdp_port_range_start | PERSEA_CDP_PORT_RANGE_START | 9200 | CDP port range start |
| cdp_port_range_end | PERSEA_CDP_PORT_RANGE_END | 9299 | CDP port range end |
| login_script_timeout_secs | PERSEA_LOGIN_SCRIPT_TIMEOUT_SECS | 120 | Login script timeout |
| login_scripts_dir | PERSEA_LOGIN_SCRIPTS_DIR | /opt/persea/scripts | Login scripts directory |
| ssh_scrollback | PERSEA_SSH_SCROLLBACK | 10000 | SSH terminal scrollback |
| ssh_tmux_detach | PERSEA_SSH_TMUX_DETACH | false | SSH tmux detach mode |
| max_sessions | PERSEA_MAX_SESSIONS | 500 | Max concurrent sessions |
| max_sessions_per_user | PERSEA_MAX_SESSIONS_PER_USER | 50 | Max sessions per user |
| max_viewers | PERSEA_MAX_VIEWERS | 10 | Max viewers per session |
| session_cleanup_delay_secs | PERSEA_SESSION_CLEANUP_DELAY_SECS | 300 | Session cleanup delay |
| shutdown_timeout_secs | PERSEA_SHUTDOWN_TIMEOUT_SECS | 30 | Graceful shutdown timeout |
| rate_limit | PERSEA_RATE_LIMIT | false | Enable rate limiting |
| user_credentials_default_scope | PERSEA_USER_CREDENTIALS_DEFAULT_SCOPE | local | Credential default scope |
| ssh_allowed_networks | PERSEA_SSH_ALLOWED_NETWORKS | ["10.0.0.0/8", ...] | SSH allowed networks |
| rdp_allowed_networks | PERSEA_RDP_ALLOWED_NETWORKS | ["10.0.0.0/8", ...] | RDP allowed networks |
| vnc_allowed_networks | PERSEA_VNC_ALLOWED_NETWORKS | ["10.0.0.0/8", ...] | VNC allowed networks |
| web_allowed_networks | PERSEA_WEB_ALLOWED_NETWORKS | ["127.0.0.0/8", ...] | Web allowed networks |
| trusted_proxies | PERSEA_TRUSTED_PROXIES | [] | Trusted proxy CIDRs |
| tls.secure_cookies | PERSEA_TLS__SECURE_COOKIES | true | Set `false` when serving HTTPS with a self-signed/untrusted cert — browsers block `Secure` cookies over untrusted connections, breaking logins. Auto-set by `install.sh` and the Docker entrypoint when they generate their own cert |
| storage.encryption_key | PERSEA_STORAGE__ENCRYPTION_KEY | (none) | Storage encryption key |

**Precedence:** Environment variables override config file values, which override built-in defaults.

**Note:** Some settings (like `OIDC_CLIENT_SECRET`, `VAULT_SECRET_ID`, `PERSEA_STORAGE_KEY`) are already read via dedicated environment variable handling and continue to work as before.

## Step 2: Initial Configuration

### Create an admin API key

```bash
/opt/persea/bin/persea --config /opt/persea/config.toml add-admin --name admin
```

Save the printed key (`rgu_...`), it is shown only once. Use it for initial setup, then **delete it once OIDC is configured** (see Step 5).

### Edit config.toml

```bash
sudo nano /opt/persea/config.toml
```

Key settings for a production deployment:

```toml
listen_addr = "127.0.0.1:8089"      # Loopback only — HAProxy handles public TLS
guacd_addr = "localhost:4822"

[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
guacd_cert_path = "/opt/persea/tls/cert.pem"

# Trust HAProxy's X-Forwarded-For header
trusted_proxies = ["127.0.0.1/32"]

# Network allowlists — restrict what targets guacd can connect to.
# Prevents SSRF via crafted session requests.
ssh_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
rdp_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
vnc_allowed_networks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

See [configuration.md](configuration.md) for the full reference.

### Start services

```bash
sudo systemctl enable --now persea
```

Verify: `curl -k https://localhost:8089/api/health`

## Step 3: Set Up HAProxy

HAProxy provides TLS termination, HTTP/2, WebSocket support, and Knocknoc integration.

**Using nginx, Caddy, Apache, or Traefik instead?** See [reverse-proxies.md](reverse-proxies.md) for per-proxy configs and an important `%2F` gotcha that affects nested folder paths on several of them.

### Install

```bash
sudo apt install haproxy
```

### Configure

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
    timeout tunnel  8h              # Long-lived WebSocket sessions
    timeout http-request 10s        # Slowloris protection

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

### TLS certificate

Use Let's Encrypt or your organisation's CA:

```bash
# Let's Encrypt example (certbot + HAProxy)
sudo certbot certonly --standalone -d console.example.com
sudo cat /etc/letsencrypt/live/console.example.com/{fullchain,privkey}.pem \
    > /etc/ssl/private/persea.pem
sudo systemctl restart haproxy
```

## Step 4: Prepare RDP Targets

### Linux (xrdp with H.264)

For the best video experience with Linux desktops, use xrdp with x264 H.264 encoding. A single setup script handles everything: desktop environment, audio, xrdp rebuild with x264, and GFX configuration:

```bash
# On the RDP target machine (not the persea server):
wget -O setup-xrdp-gfx.sh https://raw.githubusercontent.com/BarbellDwarf/persea/main/contrib/setup-xrdp-gfx.sh
sudo bash setup-xrdp-gfx.sh --desktop mate
```

The `--desktop` flag installs a desktop environment (default: `mate`). Options: `mate`, `xfce`, `kde`, `gnome`, `none`. MATE is recommended, it is lightweight, Windows-like, and works reliably over xrdp without GPU.

The script runs in three phases:
1. **Phase 1 (pure trixie):** Installs desktop, Firefox, Chromium, build tools, PulseAudio xrdp audio module, switches from PipeWire to real PulseAudio
2. **Phase 2 (temporary sid):** Adds Debian sid repo, installs matching xorgxrdp, rebuilds xrdp with `--enable-x264`, removes sid
3. **Phase 3 (configure):** Xorg backend, startwm.sh, gfx.toml with H.264 + x264 encoder

Run `bash setup-xrdp-gfx.sh --help` for all options, or `bash setup-xrdp-gfx.sh --diagnose` to troubleshoot after setup.

In the persea connections, enable these settings on the RDP entry:
- **Enable Graphics Pipeline (GFX)** -- checked
- **H.264 Passthrough** -- checked
- **Enable Desktop Composition** -- not needed for Linux (Windows-only DWM setting)

See [rdp-video-performance.md](rdp-video-performance.md) for manual setup and tuning.

### Windows

Windows RDP works out of the box. For video-heavy workloads:

```powershell
# On the Windows RDP server (as Administrator):
.\contrib\setup-rdp-performance.ps1

# With GPU hardware encoding:
.\contrib\setup-rdp-performance.ps1 -EnableGPU
```

This enables AVC 4:4:4, 60 FPS, desktop composition, and GPU encoding.

**Note:** Windows only sends H.264 when a GPU (physical or virtual) is available. Without GPU, it uses Planar/RemoteFX which guacd re-encodes as JPEG/WebP. This is still good quality, just not as low-latency as H.264 passthrough.

## Step 5: Configure Authentication

### OIDC Single Sign-On (recommended)

Add to `config.toml`:

```toml
[oidc]
issuer_url = "https://your-idp.example.com"
client_id = "persea"
redirect_uri = "https://console.example.com/auth/callback"
groups_claim = "groups"

# OIDC session TTL — re-authenticate after this period (default: 86400 = 24h)
auth_session_ttl_secs = 28800
```

Group-to-role mappings are configured via the Admin page (http://localhost:8089/admin.html)
or the API endpoint `POST /api/admin/group-mappings`.

Set the client secret in `/opt/persea/env`:

```bash
echo 'OIDC_CLIENT_SECRET=your-secret-here' | sudo tee -a /opt/persea/env
sudo chmod 600 /opt/persea/env
sudo systemctl restart persea
```

See [integrations.md](integrations.md) for provider-specific guides (Authentik, JumpCloud, Entra ID, etc.).

### Delete the bootstrap API key

Once OIDC is working and you have an admin user, remove the initial API key:

```bash
# List admin keys
/opt/persea/bin/persea --config /opt/persea/config.toml list-admins

# Delete by name
/opt/persea/bin/persea --config /opt/persea/config.toml delete-admin --name admin
```

API keys are powerful (full admin, no MFA). For day-to-day use, OIDC with group-based roles is more secure. If you need programmatic API access, create scoped [user API tokens](roles-and-access-control.md) instead.

## Step 6: Set Up the Connections (Vault or DB)

Connections stores connection entries in HashiCorp Vault/OpenBao, or — with the DB storage backend — in the local database with AES-256-GCM encrypted credentials. Credentials stay server-side, they never reach the browser. See [Configuration > `[storage]`](configuration.md#storage-section) for the backend choice.

### Configure Vault (optional, for Vault-backed Connections)

If you want the Vault-backed Connections UI:

1. **Install and initialize Vault**, see [Vault from Zero](integrations.md#vault-from-zero) in the integrations guide
2. **Enable KV v2** at the `secret` mount path
3. **Create the persea policy** with read/write access to `secret/data/persea/*`
4. **Enable AppRole** and get role_id + secret_id
5. **Add to config.toml:**
   ```toml
   [vault]
   addr = "http://127.0.0.1:8200"
   role_id = "<your-role-id>"
   ```
6. **Set the secret_id** in `/opt/persea/env`:
   ```
   VAULT_SECRET_ID=<your-secret-id>
   ```
7. **Verify:** restart persea and check logs for "Vault: authenticated via AppRole"

```bash
echo 'VAULT_SECRET_ID=your-secret-id' | sudo tee -a /opt/persea/env
sudo systemctl restart persea
```

See [integrations.md](integrations.md) for Vault setup, AppRole configuration, and mTLS.

## Step 7: Lock It Down with Knocknoc

[Knocknoc](https://knocknoc.io) removes the attack surface entirely. Instead of exposing persea's login page to the internet, Knocknoc gates access at the network layer:

1. **Before Knocknoc:** the login page is visible to scanners, bots, and attackers
2. **After Knocknoc:** the login page returns 403 unless the user has authenticated through Knocknoc first (SSO + MFA)

Only the front page (`/`) is gated. API endpoints, OIDC callbacks, and share links pass through to persea's own auth.

### HAProxy + Knocknoc configuration

Add to your HAProxy config:

```
# Dynamic ACL managed by knocknoc-agent
acl knoc_persea src -u 600
acl is_root path /

# Gate only the login page
use_backend persea if is_root knoc_persea
use_backend denied   if is_root
use_backend persea
```

Install and configure [knocknoc-agent](https://docs.knocknoc.io) to manage ACL #600 via the HAProxy admin socket.

### Why this matters

persea gives users administrative access to servers. Even with OIDC and strong passwords, exposing the login page means:
- Brute-force and credential-stuffing attacks
- Zero-day exploits against the web layer
- Reconnaissance by scanners

Knocknoc ensures the login page is only reachable after identity-verified network authentication. The attack surface goes from "the entire internet" to "zero".

## Step 8: Enable Drive Mapping (optional)

Drive mapping lets users transfer files to/from remote sessions.

### Basic (unencrypted)

```toml
[drive]
enabled = true
drive_path = "/opt/persea/drives"
drive_name = "Shared Drive"
```

### Encrypted (LUKS + Vault)

For environments requiring at-rest encryption:

```bash
sudo /opt/persea/bin/drive-setup.sh
```

This creates a LUKS-encrypted volume with the encryption key stored in Vault. See [integrations.md](integrations.md) for details.

## Step 9: Session Recording (optional)

Session recordings are enabled by default and stored in `/opt/persea/recordings`.

```toml
[recording]
enabled = true
path = "/opt/persea/recordings"
max_disk_percent = 80    # Auto-delete oldest when disk usage exceeds 80%
rotation_interval_secs = 300   # Check every 5 minutes
```

(The old top-level `recording_path` key is deprecated — see [Troubleshooting](troubleshooting.md#recording_path-deprecation-warning).)

Recordings can be played back in the browser via the Sessions page, or exported for compliance.

## Ongoing Operations

### Monitoring

- **Health check:** `GET /api/health` — shallow `{"status":"ok"}` without auth; authenticated operators get the deep check (guacd, DB, Vault, disk). See [API Reference](api.md#get-apihealth)
- **Metrics:** `GET /metrics` (Prometheus format, unauthenticated — see [API Reference](api.md#metrics))
- **System status:** `GET /api/system/status` (admin only) shows version, uptime, active sessions
- **Reports:** Session history, top connections, top users available at `/reports.html` (poweruser+ role)

### Upgrading

```bash
# Debian package
sudo apt install ./persea_new-version.deb
sudo systemctl restart persea
```

Config files are preserved across upgrades (`--force-confold`). Database migrations run on startup.

### Backup

Back up these paths:
- `/opt/persea/config.toml`, configuration
- `/opt/persea/data/persea.db`, users, tokens, session history
- `/opt/persea/env`, secrets (Vault secret ID, OIDC client secret)
- `/opt/persea/recordings/`, session recordings (if needed for compliance)

Connections data lives in Vault (when `[storage] backend = "vault"`) or encrypted in the database. Back up Vault separately if you use it; otherwise the DB backup above covers connections.

### Security checklist

- [ ] HAProxy terminates TLS with a valid certificate (not self-signed)
- [ ] persea listens on loopback only (`listen_addr = "127.0.0.1:8089"`)
- [ ] Network allowlists configured (prevent SSRF to unintended targets)
- [ ] OIDC configured with group-based role mappings
- [ ] Bootstrap API key deleted after OIDC setup
- [ ] Knocknoc gates the login page (optional but strongly recommended)
- [ ] Drive encryption enabled if file transfer is used in regulated environments
- [ ] Session recording enabled for audit compliance
- [ ] `/opt/persea/env` has `chmod 600` permissions
- [ ] Trusted proxies configured to match HAProxy IP

## Audit Logging Limitations

The audit log uses a SHA-256 hash chain for tamper evidence. This means:

- **Tamper-evident, not tamper-proof**: An attacker with database write access can regenerate a valid chain from a tampering point by recomputing hashes forward.
- **No external anchor**: The chain is self-contained — there's no external signature or timestamp authority.

### Recommended compensating controls

For enterprise deployments:
- **External anchoring**: Periodically export chain head hashes and sign them with an external key, or ship to a separate system
- **SIEM streaming**: Forward audit events to an external SIEM in real-time (before they're written to the local DB)
- **WORM storage**: Write audit logs to write-once-read-many storage if available
- **Database access controls**: Restrict who can write to the persea database
