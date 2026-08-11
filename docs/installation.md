# Installation

> **Audience:** anyone installing persea for the first time (Debian package, Docker, bare-metal, dev builds).
> **Next:** [Deployment Guide](deployment-guide.md) for the production architecture, or [Configuration](configuration.md) for config reference.

> **Target platform**: persea is built and tested against **Debian 13
> (Trixie)**. The pre-built `.deb` package and `install.sh` script
> assume FreeRDP 3.15+ (Debian 13's `freerdp3-dev`). Other Linux
> distributions should use the Docker image (Option C) to avoid the
> FreeRDP ABI issue. See [Other Linux distributions](#other-linux-distributions).

## Option A: Debian package (recommended)

Pre-built `.deb` packages are available from the [releases page](https://github.com/BarbellDwarf/persea/releases) for Debian 13 (Trixie) and compatible distributions.

```bash
sudo apt install ./persea_*.deb
```

Using `apt install` (not `dpkg -i`) resolves all runtime dependencies.

The package installs to `/opt/persea` and creates systemd services for both guacd and persea.

### Post-install

1. **Start the services:**

```bash
sudo systemctl enable --now persea
```

This starts both `persea-guacd` (the protocol daemon) and `persea` (the web proxy).

2. **Complete the setup wizard** — open `https://your-server:8089` and follow
   `/setup`, which provisions the first admin user (email + password) and
   applies initial feature toggles. Log in with those credentials.

3. **Configure**, edit `/opt/persea/config.toml` as needed (see [Configuration](configuration.md)).

4. **Choose a storage backend for connections (default: local DB):**

The connections page is persea's primary user-facing feature. It stores SSH, RDP, VNC, web session, and VDI entries in the local database with AES-256-GCM encrypted credentials by default (`[storage] backend = "db"` — no Vault required), or in [HashiCorp Vault](https://www.vaultproject.io/) / [OpenBao](https://openbao.org/) KV v2 (`backend = "vault"`). The DB backend works out of the box; only switch to Vault if you need credentials stored outside the database.

For a Vault-backed install the fastest path is the bundled quickstart helper, which auto-detects vault or bao and provisions everything:

```bash
# Against an existing Vault or OpenBao:
export VAULT_ADDR=https://vault.example.com:8200
export VAULT_TOKEN=hvs.xxxxxxxx
./contrib/vault-quickstart.sh

# Or install Vault locally on this box with on-disk auto-unseal:
sudo ./contrib/vault-quickstart.sh --local
```

See [Vault / OpenBao Connections](integrations.md#vault--openbao-connections) for the manual walkthrough, mTLS, multi-instance setup, and the security caveat for `--local` mode.

6. **(Optional) Set up encrypted drive storage:**

```bash
sudo /opt/persea/bin/drive-setup.sh
```

See [Drive / File Transfer](integrations.md#drive--file-transfer--luks-encryption) for details.

7. **(Optional) Enable VDI desktop containers:**

If you want to use VDI sessions (ephemeral Docker desktop containers), install Docker and grant persea access:

```bash
# Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh

# Allow persea to manage containers
sudo usermod -aG docker persea
sudo systemctl restart persea
```

Then add a `[vdi]` section to your config, see [VDI Desktop Containers](vdi.md) for full setup.

## Verification

After installation, verify everything works:

1. **Check services are running:**
   ```bash
   sudo systemctl status persea persea-guacd
   ```

2. **Test the health endpoint:**
   ```bash
   curl -k https://localhost:8089/api/health
   # Should return: {"status":"ok"}
   ```

3. **Check for errors in logs:**
   ```bash
   journalctl -u persea -n 20 --no-pager
   journalctl -u persea-guacd -n 20 --no-pager
   ```

4. **Create the first admin via the setup wizard** (if not done during install):
   open `https://your-server:8089` and follow `/setup`. For automation/API
   access, create an admin API key instead:
   ```bash
   sudo -u persea /opt/persea/bin/persea add-admin --name admin
   ```

5. **Open the web interface** at `https://your-server:8089` and log in with the setup-wizard admin credentials (or the API key as `Authorization: Bearer` for the API).

6. **Test an SSH session**, create an ad-hoc SSH session to `localhost` or another machine on your network.

## Option B: Bare-metal install script

For fresh Debian 13 systems, the install script builds everything from source:

```bash
sudo ./install.sh
```

This performs the following steps:

1. Installs system packages (build tools, Xvnc, Chromium, cryptsetup, etc.)
2. Installs the Rust toolchain (if not present)
3. Clones and builds guacd from [guacamole-server](https://github.com/apache/guacamole-server) source, applying patches
4. Builds persea with `cargo build --release`
5. Creates the `persea` system user (home: `/home/persea`)
6. Generates a self-signed TLS certificate
7. Installs binaries, static files, and config to `/opt/persea`
8. Sets up systemd services

### Install flags

| Flag | Description |
|------|-------------|
| `--no-tls` | Skip TLS certificate generation, listen on HTTP port 8089 |
| `--hostname=FQDN` | Hostname for the TLS certificate (default: system hostname) |
| `--deps-only` | Only install system packages, then exit |
| `--no-deps` | Skip apt package installation |

### Installed layout

```
/opt/persea/
  bin/persea           # Main binary
  bin/drive-setup.sh     # LUKS drive setup script
  sbin/guacd             # Guacamole protocol daemon
  lib/                   # guacd shared libraries
  static/                # Web UI files
  tls/                   # TLS certificates
  data/                  # SQLite database
  recordings/            # Session recordings
  config.toml            # Configuration file
  env                    # Environment variables (VAULT_SECRET_ID, etc.)
```

### Systemd services

| Service | Description |
|---------|-------------|
| `persea-guacd` | guacd protocol daemon (TLS, loopback only) |
| `persea` | persea web proxy (depends on guacd) |

Both services run as the `persea` user and restart on failure.

The `persea` service loads environment variables from `/opt/persea/env` via systemd's `EnvironmentFile` directive. Use this for secrets like `VAULT_SECRET_ID` and `OIDC_CLIENT_SECRET`.

## Option C: Docker

Pre-built images are published to the GitHub Container Registry:

```bash
docker pull ghcr.io/barbelldwarf/persea:latest
docker run -d -p 8089:8089 ghcr.io/barbelldwarf/persea:latest
```

To build from source instead:

```bash
docker build -t persea .
docker run -d -p 8089:8089 persea
```

The Docker image:
- Uses a multi-stage build (Debian 13 trixie-slim runtime)
- Builds guacd from source with patches applied
- Generates a self-signed TLS certificate on first start (entrypoint, into `/opt/persea/tls`)
- Enables TLS between persea and guacd by default
- Serves HTTPS on port 8089 with the self-signed cert (put a reverse proxy in front for a trusted certificate)

### First run — setup wizard

On first start (when no database exists), persea redirects to the **setup wizard**
at `https://your-server:8089/setup`, which provisions the first admin user
(email, display name, password) and applies initial feature toggles.

After setup, log in with the admin credentials. The entrypoint also creates an
admin API key named `docker-admin` on first start and writes it to
`/opt/persea/data/admin-key.txt` (owner-read only) — useful for API automation
before you have a web login. Additional API keys are created separately when
needed:

```bash
docker exec persea /opt/persea/bin/persea \
    --config /opt/persea/config.toml add-admin --name my-admin
```

The printed key (`rgu_...`) is shown only once — save it immediately.

### Customizing the configuration

To persist config changes across container restarts, bind-mount a local `config.toml` into the container:

1. **Copy the default config** from the image:

```bash
docker run --rm --entrypoint cat ghcr.io/barbelldwarf/persea:latest /opt/persea/config.toml.default > config.toml
```

2. **Edit** `config.toml` as needed (see [Configuration](configuration.md)):

```toml
# Example: allow SSH to private networks
ssh_allowed_networks = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
```

3. **Mount it** in your Docker Compose file or `docker run` command (see below).

If no config file is mounted, the container uses a built-in default on first start.

### Docker Compose example

```yaml
services:
  persea:
    image: ghcr.io/barbelldwarf/persea:latest
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

> **Keep the TLS volume.** `persea-tls` holds the certificate the entrypoint generates on first start. Without it, every `docker compose down && up` (or image upgrade) regenerates the self-signed cert, changing the fingerprint and re-triggering browser warnings. Mount your own cert for production; when persea self-generates one it also sets `secure_cookies = false` in the config so the session cookie works over the untrusted HTTPS connection.

### Sharing guacd with Apache Guacamole

If you already run Apache Guacamole with its own guacd container, persea can share it. Override the entrypoint to skip the built-in guacd and point to the existing one:

```yaml
services:
  # Your existing guacd (from Apache Guacamole)
  guacd:
    image: guacamole/guacd:latest
    # ... your existing guacd config ...

  persea:
    image: ghcr.io/barbelldwarf/persea:latest
    entrypoint: ["/opt/persea/bin/persea"]
    command: ["--config", "/opt/persea/config.toml", "serve"]
    ports:
      - "8089:8089"
    volumes:
      - ./config.toml:/opt/persea/config.toml
      - persea-data:/opt/persea/data
      - persea-recordings:/opt/persea/recordings
      - persea-tls:/opt/persea/tls
    environment:
      - RUST_LOG=info
    # Must be on the same Docker network as guacd
    networks:
      - guac-network
```

In your `config.toml`, set `guacd_addr` to the guacd container's hostname:

```toml
guacd_addr = "guacd:4822"
```

Both Apache Guacamole and persea will use the same guacd daemon. They can share recordings, but each maintains its own session state and user database.

## Option D: RPM package (build from source)

Pre-built RPM packages are not currently provided. An RPM spec file (`persea.spec`) and build script (`build-rpm.sh`) are included for Red Hat / Fedora / Rocky Linux based systems. You will need FreeRDP 3.x development headers installed.

```bash
# Install build dependencies (example for Rocky/RHEL 9)
sudo dnf install -y epel-release
sudo dnf config-manager --set-enabled crb
sudo dnf install -y gcc gcc-c++ make git autoconf automake libtool \
    freerdp-devel cairo-devel libjpeg-turbo-devel libpng-devel libwebp-devel \
    libssh2-devel openssl-devel libvncserver-devel pango-devel \
    pulseaudio-libs-devel rpm-build

# Build the RPM
bash build-rpm.sh
sudo rpm -i persea-*.rpm
```

RPM builds are untested. Contributions and feedback are welcome.

## Option E: Development

```bash
# Clone guacamole-server alongside persea
git clone https://github.com/apache/guacamole-server.git ../guacamole-server

# Install build deps, build guacd, build + run persea
./dev.sh deps
./dev.sh build-guacd
./dev.sh start
```

For development with TLS:

```bash
./dev.sh generate-cert

cat > config.local.toml <<EOF
[tls]
cert_path = "cert.pem"
key_path = "key.pem"
guacd_cert_path = "cert.pem"
EOF

./dev.sh start
```

## Other Linux distributions

persea is built and tested against Debian 13 (Trixie). On other Linux
distributions the FreeRDP ABI is typically different, and the prebuilt
`.deb` will fail at runtime even if it installs cleanly. The most common
symptom is RDP sessions working visually but drive redirection and audio
failing with messages in the guacd log like:

```
Cannot create static channel "rdpdr": failed to load "guac-common-svc" plugin for FreeRDP.
Cannot create static channel "rdpsnd": failed to load "guac-common-svc" plugin for FreeRDP.
```

That is FreeRDP's plugin loader silently failing symbol resolution
against a different FreeRDP version than what guacd was compiled against.

### Recommended: Docker (Option C above)

The Docker image bundles guacd, FreeRDP, and all dependencies as a single
artifact and runs cleanly on any host that can run a recent Docker
daemon. This is the supported path for Ubuntu, RHEL/Rocky/Alma, Arch,
and any other non-Debian-13 distribution.

```bash
docker pull ghcr.io/barbelldwarf/persea:latest
```

See [Option C: Docker](#option-c-docker) above for the full setup.

### Untested: building from source on Ubuntu 24.04 LTS

If you need a bare-metal install on Ubuntu 24.04, you can build
locally, but be aware that **Ubuntu 24.04 ships FreeRDP 3.5.1**, which
is older than what the `patches/` directory targets (FreeRDP 3.15+ as
shipped by Debian 13). The patches will fail to apply or apply against
the wrong lines.

Two options:

**Option 1: skip the patches and build against system FreeRDP 3.5.**

```bash
# Build deps
sudo apt-get install -y \
    git build-essential autoconf automake libtool pkg-config cmake \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev libssh2-1-dev \
    libssl-dev libvncserver-dev libpango1.0-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libtelnet-dev libwebsockets-dev freerdp3-dev uuid-dev \
    chromium-browser tigervnc-standalone-server cryptsetup \
    curl ca-certificates

# Rust toolchain (1.80+ required for cfg_select support in libsqlite3-sys)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Build guacd against system FreeRDP 3.5 (skip the 3.15+ patches)
git clone https://github.com/BarbellDwarf/persea.git
git clone https://github.com/apache/guacamole-server.git
cd guacamole-server
git checkout de97609007c088b5e6afd827eff5e9076013a247   # same pin persea uses
autoreconf -fi
./configure --prefix=/opt/persea --with-rdp
make -j"$(nproc)"
sudo make install

# Build persea
cd ../persea
cargo build --release
bash build-deb.sh
sudo dpkg -i ../persea_*_amd64.deb
```

Drive redirection, audio, and clipboard should work. The 3.15-specific
bugs the patches address are not present in 3.5.x, so the unpatched
build is fine for that vintage of FreeRDP.

**Option 2: install FreeRDP 3.15+ from a third-party source** (e.g. a
PPA or build from source) and then run `install.sh` normally. Out of
scope for this guide.

Both paths are **untested**: no CI runs against Ubuntu 24.04 and no
`.deb`s are shipped for it. Ubuntu issues will be triaged as
best-effort and generally closed with a pointer to the Docker image.
If you run persea on Ubuntu (successfully or otherwise), reports via
GitHub issues help inform whether a CI target gets added.

### Other distributions

For RPM-based distros see [Option D: RPM package (build from source)](#option-d-rpm-package-build-from-source).
For everything else, the Docker image is the path of least resistance.

## System dependencies

For bare-metal installs, persea requires:

- **Rust toolchain** (1.80+)
- **guacd** (built from guacamole-server source)
- **Xvnc** (tigervnc-standalone-server) for web browser sessions
- **Chromium** for web browser sessions
- **cryptsetup** for LUKS encrypted drive storage
- **Build libraries** for guacd: libcairo2, libjpeg, libpng, libwebp, libssh2, libssl, libvncserver, libpango, libpulse, ffmpeg, freerdp3

See `install.sh` for the full package list.

## guacamole-server patches

guacd requires patches to build and run correctly with FreeRDP 3.15+ as shipped in Debian 13. These patches are in the `patches/` directory and are applied by all build scripts.

The patches fix:
1. **Autoconf `-Werror` vs deprecated FreeRDP headers**, FreeRDP 3.15 deprecates `codecs_free()`, breaking compile tests
2. **Deprecated function pointer API**, replaces `->input->MouseEvent()` etc. with safe FreeRDP 3.x functions
3. **NULL pointer dereference**, FreeRDP 3.x fires PubSub events before `guac_rdp_disp` is allocated
4. **Struct layout mismatch**, channel source files missing `config.h` see wrong field offsets when SSH support is enabled
