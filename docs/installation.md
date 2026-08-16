# Installation

This guide covers getting persea running for the first time: system requirements, the three install options (Debian package, bare-metal script, Docker), the first-run setup wizard, and how to verify everything actually works.

If you are planning a larger production rollout, continue with the [Deployment Guide](deployment-guide.md) after installation.

## What you need

- **A Linux server.** persea is built and tested against **Debian 13 (Trixie)**. The prebuilt package and install script are for Debian 13; on other distributions use the Docker image (see [Other Linux distributions](#other-linux-distributions)).
- **Root access** on that server.
- **A machine you can reach it from**, with a modern browser (Chrome, Edge, Firefox, Safari).

persea itself is modest; a small server with 2–4 GB of RAM is fine for testing and light use. Keep in mind that every simultaneous RDP session costs roughly 150 MB of RAM in guacd, and web browser sessions each need their own Xvnc virtual display and Chromium instance.

Two programs run on the server: **persea** (the web server) and **guacd** (the protocol daemon that actually speaks SSH/RDP/VNC to your target machines). Both install options below set both up for you.

## Option A: Debian package (recommended on Debian 13)

Prebuilt `.deb` packages are published on the [releases page](https://github.com/persea-grove/persea/releases). On your server:

```bash
sudo apt install ./persea_*.deb
```

Using `apt install` (rather than `dpkg -i`) pulls in all the runtime dependencies automatically. The package installs persea and guacd to `/opt/persea` and creates two systemd services: `persea` (the web server) and `persea-guacd` (the protocol daemon).

Start everything:

```bash
sudo systemctl enable --now persea
```

This starts both services. Then open `https://your-server:8089` in a browser and complete the setup wizard (see [The setup wizard](#the-setup-wizard) below). The server generates a self-signed TLS certificate during install, so the browser will show a certificate warning: click through it. The certificate is set up so login works anyway; this is handled automatically.

Configuration lives in `/opt/persea/config.toml`. Secrets that should not sit in the config file (for example the Vault secret ID or the OIDC client secret) go in `/opt/persea/env`, which the service reads at start.

## Option B: Bare-metal install script

For fresh Debian 13 systems, `install.sh` builds everything from source:

```bash
sudo ./install.sh
```

The script:

1. Installs system packages (build tools, Xvnc, Chromium, cryptsetup, and the libraries guacd needs).
2. Installs the Rust toolchain if missing.
3. Downloads guacamole-server, applies the FreeRDP 3 patches this project ships in `patches/`, and builds guacd.
4. Builds persea (`cargo build --release`).
5. Creates a `persea` system user.
6. Generates a self-signed TLS certificate.
7. Installs binaries, web files, and a starter config to `/opt/persea`.
8. Sets up the two systemd services (`persea` and `persea-guacd`).

Useful flags:

| Flag | What it does |
|------|--------------|
| `--no-tls` | Skip TLS certificate generation; the server listens on plain HTTP port 8089 |
| `--hostname=FQDN` | Hostname embedded in the TLS certificate (default: the system hostname) |
| `--deps-only` | Only install system packages, then exit |
| `--no-deps` | Skip the apt package installation (you already have the packages) |

After it finishes, the layout under `/opt/persea` is:

```
bin/persea          the web server binary
bin/drive-setup.sh  optional encrypted file-transfer setup script
sbin/guacd          the protocol daemon
lib/                guacd's shared libraries
static/             web UI files
tls/                TLS certificates
data/               SQLite database
recordings/         session recordings
config.toml         configuration file
env                 environment variables for secrets
```

Start with `sudo systemctl enable --now persea`, then open the web interface at `https://your-server` (the script's default config listens on port 443), or `http://your-server:8089` if you installed with `--no-tls`. Follow the setup wizard from there.

## Option C: Docker

The Docker image bundles persea, guacd, FreeRDP, and all dependencies in one artifact, so it runs on any distribution with a recent Docker daemon. This is the recommended option on anything other than Debian 13.

```bash
docker pull ghcr.io/persea-grove/persea:latest
docker run -d -p 8089:8089 \
  -v persea-data:/opt/persea/data \
  -v persea-recordings:/opt/persea/recordings \
  -v persea-tls:/opt/persea/tls \
  ghcr.io/persea-grove/persea:latest
```

Or build the image from source:

```bash
docker build -t persea .
docker run -d -p 8089:8089 persea
```

What the image does on first start:

- Generates a self-signed TLS certificate (kept in the `persea-tls` volume so it survives container upgrades: **keep that volume**, otherwise the certificate changes on every recreate and browsers warn again).
- Starts guacd inside the container (TLS on loopback port 4822), then persea.
- Serves HTTPS on port 8089 with the self-signed cert. For production, put a reverse proxy with a real certificate in front, or mount your own certificate over `/opt/persea/tls/cert.pem` and `key.pem`.
- Writes an admin API key to `/opt/persea/data/admin-key.txt` for automation. You can still create a human admin account through the setup wizard: the two are independent.

### Customising the configuration

To keep a custom `config.toml` across container restarts, bind-mount it:

```bash
docker run --rm --entrypoint cat ghcr.io/persea-grove/persea:latest /opt/persea/config.toml.default > config.toml
```

Edit `config.toml` as needed (see [Configuration](configuration.md)), then mount it:

```bash
docker run -d -p 8089:8089 \
  -v "$PWD/config.toml:/opt/persea/config.toml" \
  -v persea-data:/opt/persea/data \
  -v persea-recordings:/opt/persea/recordings \
  -v persea-tls:/opt/persea/tls \
  ghcr.io/persea-grove/persea:latest
```

A Docker Compose equivalent:

```yaml
services:
  persea:
    image: ghcr.io/persea-grove/persea:latest
    ports:
      - "8089:8089"
    volumes:
      - ./config.toml:/opt/persea/config.toml
      - persea-data:/opt/persea/data
      - persea-recordings:/opt/persea/recordings
      - persea-tls:/opt/persea/tls
    environment:
      - RUST_LOG=info

volumes:
  persea-data:
  persea-recordings:
  persea-tls:
```

Ready-made Compose files ship in
[`docs/examples/`](examples/README.md): a minimal single-service stack
with the bundled SQLite database (`docker-compose.sqlite.yml`), and persea
plus a PostgreSQL or MySQL backend (`docker-compose.postgres.yml`,
`docker-compose.mysql.yml`). Each runs with
`docker compose -f docs/examples/docker-compose.<backend>.yml up -d` once
you replace the placeholder storage key and passwords.

Logs are visible with `docker logs persea` (the container name from `docker ps`).

### Using an existing guacd

If you already run Apache Guacamole's guacd container, persea can share it instead of running its own. Override the entrypoint so persea starts directly, and point `guacd_addr` at the existing guacd:

```yaml
services:
  guacd:
    image: guacamole/guacd:latest
    # ... your existing guacd config ...

  persea:
    image: ghcr.io/persea-grove/persea:latest
    entrypoint: ["/opt/persea/bin/persea"]
    command: ["--config", "/opt/persea/config.toml", "serve"]
    ports:
      - "8089:8089"
    volumes:
      - ./config.toml:/opt/persea/config.toml
      - persea-data:/opt/persea/data
      - persea-recordings:/opt/persea/recordings
      - persea-tls:/opt/persea/tls
    networks:
      - guac-network   # same Docker network as guacd
```

In `config.toml`:

```toml
guacd_addr = "guacd:4822"
```

Both applications can share the same guacd. Recordings are shared too, but each keeps its own users and session history.

## The setup wizard

The first time you open the web interface (before any user account exists), persea redirects to the setup wizard at `/setup` on your persea address, `https://your-server:8089/setup` for the package and Docker installs, `https://your-server/setup` for the install script's default config. It asks for everything persea needs to create the first admin account and write a starter config. Fill it in like this:

**Server**
- **Listen Address**: where the web server should listen. It is pre-filled with the machine's address, usually `0.0.0.0:8089` (all interfaces, port 8089). Behind a reverse proxy, `127.0.0.1:8089` is safer: the proxy is the only thing that talks to persea directly.
- **Database Path**: where the SQLite database file will live (default `/opt/persea/data/persea.db`). This is the file that holds users, connections, session history, and settings. Back it up.
- **Database URL (optional)**: leave empty to use the SQLite file above. To store everything in a managed database instead, enter a `postgres://`, `mysql://`, or `sqlite://` URL here. persea connects, creates the tables, and puts the admin account straight into that database; the URL is written into the config for every later start. If the server was already started with `db_url` configured, this field is pre-filled and cannot be changed here: edit the config file instead.

**guacd**
- **Mode**: *Embedded* means guacd runs on this same machine (the Debian package and install script set it up as the `persea-guacd` service; in Docker it starts automatically). *External* means you run guacd elsewhere: then fill in its **guacd Address** (default `127.0.0.1:4822`). For *Embedded*, leave the **guacd Binary Path** at its detected value (usually `/usr/sbin/guacd`). Either way, what matters is that guacd is actually running and reachable at the address in the config: persea never starts it on its own.

**Admin Account**
- **Email**: the admin's login name (for example `admin@example.com`).
- **Display Name**: the name shown in the interface.
- **Password**: at least the password-policy minimum (15 characters by default; configure it via `password.min_length` in `config.toml`). Pick something long; this is the master account.

**Features**: tick the optional features you plan to use (Proxmox VE, VMware vSphere, Session Recording, SSH Tunnels, Web Browser Sessions, and VDI Containers). Recording, tunnels, and Proxmox are ticked by default and need no further setup. The VMware checkbox writes a commented-out configuration template for you. The others are switched on by adding their configuration sections to `config.toml` (see the [Deployment Guide](deployment-guide.md) and the [Configuration reference](configuration.md)).

Press **Complete Setup**. persea creates the admin account, writes the config file, and sends you to the login page. If you entered a Database URL, restart the service once afterwards (`sudo systemctl restart persea`) so the running server matches the config file.

## Verifying it works

1. **Check the services are up** (bare metal):

   ```bash
   sudo systemctl status persea persea-guacd
   ```

   (Docker: `docker ps` and check the container is running.)

2. **Ask the health endpoint.** It answers without logging in:

   ```bash
   curl -k https://localhost:8089/api/health
   ```

   (For an install-script default config, use `https://localhost/api/health`: it listens on 443.) A healthy server replies `{"status":"ok"}`. Logged-in operators get a deeper report (guacd, database, disk): see [Troubleshooting](troubleshooting.md).

3. **Open the web interface** at the address persea listens on: `https://your-server:8089` (package and Docker installs) or `https://your-server` (install script without `--no-tls`). You should see the login page, or the setup wizard if you haven't completed it yet.

4. **Log in** with the admin email and password from the wizard.

5. **Create a connection.** Go to the **Connections** page and click to add a new entry. Pick a type you can test against, for example SSH to `localhost` or to another machine on your network, and fill in the host, port (22 for SSH), username, and a password or key.

6. **Connect.** Click the connect button on the entry. A terminal or desktop should appear in the browser. That is the whole loop working: browser → persea → guacd → target.

If any step fails, start with the [Troubleshooting](troubleshooting.md) guide: it covers the login page, failing logins, and sessions that won't start.

## Other Linux distributions

persea is built and tested on Debian 13. On other distributions the system FreeRDP version usually differs from the one the package was built against, and RDP sessions fail in odd ways even though the package installs cleanly (file transfer and audio channels silently fail with errors in the guacd log).

**Use the Docker image** (Option C above) on Ubuntu, RHEL/Rocky/Alma, Arch, and anything else. The image bundles its own guacd and FreeRDP, so there is nothing to clash.

Building from source on Ubuntu 24.04 is possible but unsupported: Ubuntu ships FreeRDP 3.5, older than the patches in this repo target (FreeRDP 3.15+ as shipped by Debian 13). If you try it, build guacamole-server against the system FreeRDP without the patches (the bugs the patches fix are not present in 3.5.x). Expect no CI coverage or prebuilt packages for this path; issues are generally answered with a pointer to the Docker image.

## Optional extras after install

- **Encrypted file-transfer storage**: `sudo /opt/persea/bin/drive-setup.sh` sets up a LUKS-encrypted volume for RDP drive redirection. See [Integrations](integrations.md).
- **VDI desktop containers**: install Docker and add the `persea` user to the `docker` group, then enable `[vdi]` in the config. See [VDI Desktop Containers](vdi.md).
- **Vault-backed connections**: by default connection credentials are stored encrypted in the database. To store them in HashiCorp Vault or OpenBao instead, run `./contrib/vault-quickstart.sh` (or follow the manual steps in [Integrations](integrations.md)).
- **Production hardening**: reverse proxy with a real certificate, sign-in via OIDC/SAML/LDAP, and the rest of the checklist: see the [Deployment Guide](deployment-guide.md).
