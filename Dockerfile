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
# Pin to known-good commit to avoid upstream -Werror breakage
RUN git clone --depth 1 https://github.com/apache/guacamole-server.git \
    && cd guacamole-server && git checkout 6719b20d

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
    && make -j"$(nproc)" \
    && make install \
    && mkdir -p /opt/persea/lib/freerdp3 \
    && cp /opt/persea/lib/libguac*.so* /opt/persea/lib/freerdp3/ \
    && cp /usr/lib/x86_64-linux-gnu/freerdp3/libguac*.so* /opt/persea/lib/freerdp3/ 2>/dev/null || true

# ---------------------------------------------------------------------------
# Stage 2: Build persea
# ---------------------------------------------------------------------------
FROM rust:1.96.1-bookworm AS rust-builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY build.rs ./
COPY src/ src/
COPY docs/ docs/
COPY static/ static/

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/local/rustup \
    cargo build --release

# ---------------------------------------------------------------------------
# Stage 3: Runtime image
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime

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
    && rm -rf /var/lib/apt/lists/*

# Install guacd
COPY --from=guacd-builder /opt/persea/sbin/ /opt/persea/sbin/
COPY --from=guacd-builder /opt/persea/lib/ /opt/persea/lib/

# Install persea binary
COPY --from=rust-builder /build/target/release/rustguac /opt/persea/bin/persea

# Install static web assets
COPY static/ /opt/persea/static/

# Library path for guacd
RUN echo "/opt/persea/lib" > /etc/ld.so.conf.d/persea.conf && ldconfig

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

# Generate self-signed cert for guacd TLS (internal loopback encryption)
RUN /opt/persea/bin/persea generate-cert --hostname localhost --out-dir /opt/persea/tls

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

# Create admin API key on first run (if no DB exists yet)
DB_PATH="/opt/persea/data/persea.db"
if [ ! -f "$DB_PATH" ]; then
    echo "First run detected — creating admin API key..."
    /opt/persea/bin/persea --config "$CONFIG_PATH" add-admin --name docker-admin
    echo ""
    echo "==> SAVE THE API KEY ABOVE — it is only shown once! <=="
    echo ""
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
    CMD curl -f http://localhost:8089/api/health || exit 1

USER persea
ENTRYPOINT ["/opt/persea/entrypoint.sh"]
