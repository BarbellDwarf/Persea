# =============================================================================
# Multi-stage Dockerfile for persea
#
# Stages:
#   1. guacd-builder  — compile guacd from guacamole-server source
#   2. rust-builder   — compile persea binary
#   3. runtime        — minimal image with both binaries + runtime deps
#
# Build:
#   docker build -t persea .
#
# Run:
#   docker run -d -p 8089:8089 persea
#
# Run with VDI (Docker desktop containers):
#   docker run -d -p 8089:8089 \
#     -v /var/run/docker.sock:/var/run/docker.sock \
#     --group-add $(getent group docker | cut -d: -f3) \
#     persea
#
# The image runs both guacd and persea under a simple entrypoint script.
# =============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build guacd from source
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS guacd-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake libtool pkg-config make gcc g++ git ca-certificates \
    libcairo2-dev libjpeg-dev libpng-dev libwebp-dev \
    libssh2-1-dev libssl-dev libvncserver-dev \
    libpango1.0-dev libpulse-dev \
    libavcodec-dev libavformat-dev libavutil-dev libswscale-dev \
    libcunit1-dev libtelnet-dev libwebsockets-dev \
    uuid-dev freerdp3-dev libspice-client-glib-2.0-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
# Pin to main HEAD (de97609, 2026-07-28) — the base the patch set is built
# against. The 1.6.0 tag predates the display-layer refactor the H.264 patch
# needs; staging/1.6.1 lacks the clipboard-recording API the SPICE patch uses.
# Fetch the exact commit rather than cloning main: a shallow clone of main
# cannot check out a pin once upstream moves past it.
RUN git init guacamole-server \
    && cd guacamole-server \
    && git remote add origin https://github.com/apache/guacamole-server.git \
    && git fetch --depth 1 origin de97609007c088b5e6afd827eff5e9076013a247 \
    && git checkout FETCH_HEAD

# Apply patches for FreeRDP 3.x / Debian 13 compatibility
COPY patches/ /build/patches/
WORKDIR /build/guacamole-server
RUN for patch in /build/patches/*.patch; do \
        [ -f "$patch" ] || continue; \
        echo "Applying patch: $(basename "$patch")"; \
        git apply "$patch"; \
    done

RUN autoreconf -fi

WORKDIR /build/guacd-build
# Same memory-safety cap as the rust stage: `make -j$(nproc)` ICEs gcc under
# memory pressure on wide machines.
ARG GUACD_JOBS=4
RUN /build/guacamole-server/configure \
        --prefix=/opt/persea \
        --with-ssh \
        --with-vnc \
        --with-rdp \
        --with-spice \
        --without-telnet \
        --without-kubernetes \
        --disable-guacenc \
        --disable-guaclog \
        --disable-guacclip \
        --disable-static \
    && make -j"${GUACD_JOBS}" \
    && make install \
    && mkdir -p /opt/persea/lib/freerdp3 \
    && cp /opt/persea/lib/libguac*.so* /opt/persea/lib/freerdp3/ \
    && cp /usr/lib/x86_64-linux-gnu/freerdp3/libguac*.so* /opt/persea/lib/freerdp3/ 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2: Build persea
# ---------------------------------------------------------------------------
FROM rust:1.97.1-bookworm AS rust-builder

# Cap parallel codegen: 16-way `cargo build --release` routinely SIGSEGVs
# rustc/cc under memory pressure (seen on constrained runners and nested
# container builds). 4 jobs is a safe default; override with
# --build-arg CARGO_JOBS=N for machines with more headroom.
ARG CARGO_JOBS=4
ENV CARGO_BUILD_JOBS=${CARGO_JOBS}

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY keys/ keys/

# Create dummy sources so cargo can resolve all [[bin]] targets during the
# dependency-cache build.  These are overwritten by the real COPYs below.
RUN mkdir -p src license-gen && echo 'fn main() {}' > src/main.rs && echo 'fn main() {}' > license-gen/main.rs

# Compile all dependencies once with a dummy main so the dependency layer is
# only rebuilt when Cargo.toml/Cargo.lock change, not on every source edit.
# The registry/git/target cache mounts persist between builds (exported to
# GHCR via the workflow's type=gha cache), so the second build below is
# incremental: only crates touched by the new sources recompile.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release

RUN apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/*

COPY src/ src/
COPY templates/ templates/
COPY migrations/ migrations/
COPY docs/ docs/
COPY static/ static/
COPY tailwind.config.js ./
RUN npx --yes tailwindcss@3 -i static/css/input.css -o static/css/tailwind.min.css --minify

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release

# The target dir lives inside a cache mount, which is ephemeral and not part
# of the image filesystem — copy the binary out so the runtime stage can
# COPY --from it.
RUN --mount=type=cache,target=/build/target \
    cp /build/target/release/persea /build/persea

# ---------------------------------------------------------------------------
# Stage 3: Runtime image
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

# Beta images (built by the beta workflow with --build-arg PERSEA_BETA=1)
# print the running version at startup; production builds leave this unset.
ARG PERSEA_BETA="0"
ENV PERSEA_BETA=${PERSEA_BETA}

# Runtime libraries for guacd
RUN apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libjpeg62-turbo libpng16-16t64 libwebp7 \
    libssh2-1 libssl3t64 libvncclient1 \
    libpango-1.0-0 libpulse0 \
    libavcodec61 libavformat61 libavutil59 libswscale8 \
    libtelnet2 libwebsockets19t64 \
    libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 \
    # Xvnc + Chromium for web browser sessions
    tigervnc-standalone-server \
    chromium chromium-sandbox \
    x11-utils \
    # Minimal runtime utilities
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install guacd
COPY --from=guacd-builder /opt/persea/sbin/ /opt/persea/sbin/
COPY --from=guacd-builder /opt/persea/lib/ /opt/persea/lib/

# Install persea binary
COPY --from=rust-builder /build/persea /opt/persea/bin/persea

# Install static web assets
COPY static/ /opt/persea/static/

# Library path for guacd
RUN echo "/opt/persea/lib" > /etc/ld.so.conf.d/persea.conf && ldconfig

# guacd config file. guacd main (post-1.6.0) requires this file to exist and
# fails with EBADF when it is missing, so ship a default matching the
# entrypoint's command-line settings.
RUN mkdir -p /etc/guacamole && cat > /etc/guacamole/guacd.conf <<'GUACD'
[server]
bind_host = 127.0.0.1
bind_port = 4822

[daemon]
log_level = info

[ssl]
server_certificate = /opt/persea/tls/cert.pem
server_key = /opt/persea/tls/key.pem
GUACD

# FreeRDP plugin setup: guacd loads "guac-common-svc" by name, which FreeRDP
# resolves to "guac-common-svc.so" in its plugin path. The build installs it as
# "libguac-common-svc-client.so", so we create a symlink with the expected name.
# We also ensure the system FreeRDP plugin dir exists and contains the plugins.
RUN mkdir -p /usr/lib/x86_64-linux-gnu/freerdp3 && \
    if [ -d /opt/persea/lib/freerdp3 ]; then \
        cp /opt/persea/lib/freerdp3/*.so* /usr/lib/x86_64-linux-gnu/freerdp3/ 2>/dev/null; \
        ln -sf libguac-common-svc-client.so /opt/persea/lib/freerdp3/guac-common-svc.so; \
        ln -sf libguac-common-svc-client.so /usr/lib/x86_64-linux-gnu/freerdp3/guac-common-svc.so; \
        echo "FreeRDP plugins installed:"; \
        ls /usr/lib/x86_64-linux-gnu/freerdp3/guac* /opt/persea/lib/freerdp3/guac-common-svc.so 2>/dev/null; \
    fi

# Create writable runtime directories
RUN mkdir -p /opt/persea/data /opt/persea/recordings /opt/persea/tls \
    /opt/persea/certs /opt/persea/drives /opt/persea/scripts \
    /opt/persea/vdi-homes

# Chromium policy: web session hardening.
# DeveloperToolsAvailability=0: CDP needed for login scripts. Users can't reach DevTools
# through the UI anyway — chrome://* is in URLBlocklist.
RUN mkdir -p /etc/chromium/policies/managed && \
    echo '{"AllowFileSelectionDialogs": false, "PasswordManagerEnabled": true, "ImportSavedPasswords": false, "DeveloperToolsAvailability": 0, "DownloadRestrictions": 3, "PrintingEnabled": false, "EditBookmarksEnabled": false, "BrowserSignin": 0, "SyncDisabled": true, "ExtensionInstallBlocklist": ["*"], "URLBlocklist": ["file://*", "chrome://*", "chrome-extension://*", "view-source:*", "javascript:*"], "URLAllowlist": ["chrome://policy"]}' \
    > /etc/chromium/policies/managed/persea.json

# Create non-root user with a real home directory (Chromium crashpad needs it)
RUN groupadd -r persea && useradd -r -g persea -m -d /home/persea -s /bin/sh persea

# Default config template (copied to config.toml on first run if not mounted)
RUN cat > /opt/persea/config.toml.default <<'EOF'
listen_addr = "0.0.0.0:8089"
guacd_addr = "127.0.0.1:4822"
recording_path = "/opt/persea/recordings"
static_path = "/opt/persea/static"
db_path = "/opt/persea/data/persea.db"
session_pending_timeout_secs = 60
xvnc_path = "Xvnc"
chromium_path = "chromium"
display_range_start = 100
display_range_end = 199

[tls]
cert_path = "/opt/persea/tls/cert.pem"
key_path = "/opt/persea/tls/key.pem"
guacd_cert_path = "/opt/persea/tls/cert.pem"

# VDI Docker desktop containers (uncomment to enable)
# Requires: -v /var/run/docker.sock:/var/run/docker.sock
# [vdi]
# enabled = true
# idle_timeout_mins = 60
# home_base = "/opt/persea/vdi-homes"
EOF

# Set ownership so the non-root user can write to runtime dirs.
# The top-level dir is chowned (not recursive) so loaders can create config.toml;
# subdirs are chowned recursively for data, certs, etc.
RUN chown persea:persea /opt/persea && \
    chown -R persea:persea /opt/persea/data /opt/persea/recordings \
    /opt/persea/tls /opt/persea/certs /opt/persea/drives \
    /opt/persea/scripts /opt/persea/vdi-homes /opt/persea/config.toml.default

# Entrypoint script: starts guacd in background, then persea in foreground
RUN cat > /opt/persea/entrypoint.sh <<'SCRIPT'
#!/bin/sh
set -e

# Copy default config on first run (if no config file is mounted/present)
CONFIG_PATH="/opt/persea/config.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No config.toml found — copying default configuration."
    cp /opt/persea/config.toml.default "$CONFIG_PATH"
fi

# Generate TLS cert at runtime if not already present (e.g. mounted)
TLS_DIR="/opt/persea/tls"
if [ ! -f "$TLS_DIR/cert.pem" ] || [ ! -f "$TLS_DIR/key.pem" ]; then
    echo "No TLS cert found — generating self-signed certificate..."
    /opt/persea/bin/persea generate-cert --hostname localhost --out-dir "$TLS_DIR"
    echo "==> Generated self-signed TLS cert. Mount your own cert for production. <=="
    # Self-signed certs cause browsers to block Secure cookies even after
    # clicking through the cert warning. Disable Secure attribute automatically.
    if ! grep -q 'secure_cookies' "$CONFIG_PATH" 2>/dev/null; then
        if grep -q '^\[tls\]' "$CONFIG_PATH" 2>/dev/null; then
            # A [tls] section already exists (cert_path/guacd_cert_path,
            # from the default config) — insert into it. A second [tls]
            # header is invalid TOML ("duplicate key") and breaks config
            # loading entirely on every fresh container.
            sed -i '/^\[tls\]/a secure_cookies = false  # self-signed cert — browsers block Secure cookies' "$CONFIG_PATH"
        else
            {
                echo ""
                echo "[tls]"
                echo "secure_cookies = false  # self-signed cert — browsers block Secure cookies"
            } >> "$CONFIG_PATH"
        fi
        echo "Added secure_cookies = false for self-signed cert."
    fi
fi

# Create admin API key on first run (if no DB exists yet)
DB_PATH="/opt/persea/data/persea.db"
if [ ! -f "$DB_PATH" ]; then
    echo "First run detected — creating admin API key..."
    ADMIN_KEY_FILE="/opt/persea/data/admin-key.txt"
    touch "$ADMIN_KEY_FILE"
    # Best-effort: some bind mounts (Windows/WSL, 9p, virtiofs) don't support
    # chmod and would otherwise kill the script under set -e, leaving the DB
    # uncreated and the container looping on first run forever.
    if ! chmod 600 "$ADMIN_KEY_FILE" 2>/dev/null; then
        echo "warning: could not set owner-only permissions on $ADMIN_KEY_FILE (filesystem does not support chmod) — the admin API key may be readable by other users on the host"
    fi
    /opt/persea/bin/persea --config "$CONFIG_PATH" add-admin --name docker-admin > "$ADMIN_KEY_FILE" 2>&1
    echo "Admin API key written to $ADMIN_KEY_FILE (owner-read only)"
fi

# Print the running version on beta images (PERSEA_BETA=1 set at build time
# by the beta workflow); production images skip this.
if [ "$PERSEA_BETA" = "1" ]; then
    echo "persea version: $(/opt/persea/bin/persea --version 2>&1)"
fi

# Start guacd in background
echo "Starting guacd..."
LD_LIBRARY_PATH=/opt/persea/lib FREERDP_ADDIN_PATH=/opt/persea/lib/freerdp3 \
    /opt/persea/sbin/guacd \
    -b 127.0.0.1 -l 4822 -L "${GUACD_LOG_LEVEL:-info}" -f \
    -C /opt/persea/tls/cert.pem -K /opt/persea/tls/key.pem &
GUACD_PID=$!

# Wait briefly to confirm guacd started
sleep 0.5
if ! kill -0 "$GUACD_PID" 2>/dev/null; then
    echo "ERROR: guacd failed to start"
    exit 1
fi
echo "guacd started (pid=$GUACD_PID)"

# Trap signals to shut down both processes
trap 'kill $GUACD_PID 2>/dev/null; wait; exit 0' TERM INT

# Run persea in foreground
echo "Starting persea..."
exec /opt/persea/bin/persea --config "$CONFIG_PATH" serve
SCRIPT
RUN chmod +x /opt/persea/entrypoint.sh

WORKDIR /opt/persea
EXPOSE 8089
VOLUME ["/opt/persea/data", "/opt/persea/recordings", "/opt/persea/drives", "/opt/persea/vdi-homes"]

ENV RUST_LOG=info
ENV GUACD_LOG_LEVEL=info
ENV HOME=/home/persea

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -skf https://localhost:8089/api/health || exit 1

USER persea
ENTRYPOINT ["/opt/persea/entrypoint.sh"]
