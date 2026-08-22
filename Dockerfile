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
# guacd source comes from the maintained fork
# persea-grove/persea-guacamole-server, branch persea-1.6.1-freerdp3: a fork
# of apache/guacamole-server at the pinned base commit de97609 with the
# former patch quilt (FreeRDP 3.x / Debian 13 fixes, Kerberos NLA, H.264,
# SPICE, multimonitor) applied as one commit per patch. Shallow-clone the
# branch so the image stays small.
RUN git clone --depth 1 --branch persea-1.6.1-freerdp3 \
    https://github.com/persea-grove/persea-guacamole-server.git guacamole-server

WORKDIR /build/guacamole-server
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
# build.rs renders docs/*.md into the DOCS const at compile time. It must
# see the real docs/ during the dependency-cache build too: the build-script
# output is cached (gha cache), and if the first run produced an empty const
# (no docs/ present), the second stage's build.rs does not re-run (COPY
# preserves mtimes, so the fingerprint matches the cache) and the image
# ships with an empty documentation page.
COPY docs/ docs/

# Create dummy sources so cargo can resolve all [[bin]] targets during the
# dependency-cache build.  These are overwritten by the real COPYs below.
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs

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
# krb5-user provides the Kerberos client (kinit/kvno) and libraries used by
# FreeRDP's Kerberos NLA wrapper. Its install prompts for a default realm via
# debconf — pre-seed an empty answer and force noninteractive so the build
# cannot hang; the real realm is written to /etc/krb5.conf at container start
# from the PERSEA_KRB5_* env vars.
RUN printf 'krb5-config krb5-config/default_realm string \n' | debconf-set-selections \
    && DEBIAN_FRONTEND=noninteractive apt-get update && apt-get install -y --no-install-recommends \
    libcairo2 libjpeg62-turbo libpng16-16t64 libwebp7 \
    libssh2-1 libssl3t64 libvncclient1 \
    libpango-1.0-0 libpulse0 \
    libavcodec61 libavformat61 libavutil59 libswscale8 \
    libtelnet2 libwebsockets19t64 \
    libfreerdp3-3 libfreerdp-client3-3 libwinpr3-3 \
    krb5-user \
    # Xvnc + Chromium for web browser sessions
    tigervnc-standalone-server \
    chromium chromium-sandbox \
    x11-utils \
    # Minimal runtime utilities
    ca-certificates \
    curl \
    # socat: the RDP relay's outbound leg (system binaries are typically
    # allowed by endpoint filters that block the gateway's own processes)
    socat \
    # gosu: the entrypoint starts as root, reconciles ownership of the app
    # dirs for bind mounts (PUID/PGID aware), then drops privileges
    gosu \
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

# The entrypoint runs as persea and writes /etc/krb5.conf at container start
# (generated from PERSEA_KRB5_* env vars, or an operator-mounted
# /opt/persea/krb5.conf copied into place) — make the file writable by the
# non-root user. touch also ensures the file exists even if the krb5-config
# postinst skipped writing it.
RUN touch /etc/krb5.conf && chown persea:persea /etc/krb5.conf

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

# Root-init: when started as root, reconcile ownership of the app dirs for
# the persea user (honoring optional PUID/PGID overrides), then drop
# privileges and re-execute this script unprivileged. When NOT started as
# root (Kubernetes runAsNonRoot / arbitrary UID platforms / docker --user),
# skip reconciliation entirely: mount permissions are the platform's job.
if [ "$(id -u)" = "0" ]; then
    PUID="${PUID:-996}"
    PGID="${PGID:-996}"
    CUR_UID=$(id -u persea)
    CUR_GID=$(id -g persea)
    if [ "$PGID" != "$CUR_GID" ]; then
        groupmod -o -g "$PGID" persea
    fi
    if [ "$PUID" != "$CUR_UID" ] || [ "$PGID" != "$CUR_GID" ]; then
        usermod -o -u "$PUID" -g "$PGID" persea
        chown -R persea:persea /home/persea
    fi
    for D in /opt/persea/data /opt/persea/recordings /opt/persea/tls \
             /opt/persea/certs /opt/persea/drives /opt/persea/scripts \
             /opt/persea/vdi-homes; do
        mkdir -p "$D"
        chown -R persea:persea "$D"
    done
    chown persea:persea /opt/persea/config.toml.default /opt/persea
    echo "Running as root at startup: reconciled ownership for uid=$PUID gid=$PGID, dropping to persea."
    exec gosu persea:persea "$0" "$@"
fi

# Copy default config on first run (if no config file is mounted/present)
CONFIG_PATH="/opt/persea/config.toml"
if [ ! -f "$CONFIG_PATH" ]; then
    echo "No config.toml found — copying default configuration."
    cp /opt/persea/config.toml.default "$CONFIG_PATH"
fi

# Generate a storage encryption key on first run if none is set: without
# one the server refuses to start (credentials would sit in plaintext).
# TOML-aware: inserts into an existing [storage] table, appends one only
# when absent, so admin-modified configs never get a duplicate table.
# Skipped when PERSEA_STORAGE_KEY is set: the env var wins, and a
# placeholder there must fail loudly at startup, not be papered over.
if [ -z "${PERSEA_STORAGE_KEY:-}" ] && ! grep -q '^encryption_key' "$CONFIG_PATH" 2>/dev/null; then
    KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if grep -q '^\[storage\]' "$CONFIG_PATH" 2>/dev/null; then
        sed -i '/^\[storage\]/a encryption_key = "'"$KEY"'"' "$CONFIG_PATH"
    else
        {
            echo ""
            echo "[storage]"
            echo "encryption_key = \"$KEY\""
        } >> "$CONFIG_PATH"
    fi
    echo "Generated storage encryption key."
fi
# The config now holds the encryption key: not world-readable. Best-effort:
# some bind mounts (Windows/WSL, 9p, virtiofs) don't support chmod.
chmod 600 "$CONFIG_PATH" 2>/dev/null || true

# The SQLite DB holds session tokens and encrypted credentials: never
# world-readable. Pre-create it with owner-only perms so the first `serve`
# start never creates a 0644 file. Best-effort like the chmod above.
DB_PATH="/opt/persea/data/persea.db"
if [ ! -f "$DB_PATH" ]; then
    touch "$DB_PATH" 2>/dev/null || true
fi
chmod 600 "$DB_PATH" 2>/dev/null || true

# Create admin API key on first run. This must happen BEFORE any other
# persea invocation: generate-cert and serve both run db migrations in
# main(), so a database they have touched is non-empty and a size check
# below it would skip credential creation on every boot forever (#259:
# fresh containers shipped with zero credentials).
ADMIN_KEY_FILE="/opt/persea/data/admin-key.txt"
if [ -s "$DB_PATH" ]; then
    echo "existing database detected; skipping admin bootstrap"
else
    echo "First run detected — creating admin API key..."
    touch "$ADMIN_KEY_FILE"
    # Best-effort: some bind mounts (Windows/WSL, 9p, virtiofs) don't support
    # chmod and would otherwise kill the script under set -e, leaving the DB
    # uncreated and the container looping on first run forever.
    if ! chmod 600 "$ADMIN_KEY_FILE" 2>/dev/null; then
        echo "warning: could not set owner-only permissions on $ADMIN_KEY_FILE (filesystem does not support chmod) — the admin API key may be readable by other users on the host"
    fi
    # --quiet prints ONLY the raw key on stdout; stderr goes to the container
    # log so startup noise never contaminates the credential file (#259).
    /opt/persea/bin/persea --config "$CONFIG_PATH" add-admin --name docker-admin --quiet > "$ADMIN_KEY_FILE"
    echo "Admin API key written to $ADMIN_KEY_FILE (owner-read only)"
fi

# Generate TLS cert at runtime if not already present (e.g. mounted)
TLS_DIR="/opt/persea/tls"
if [ ! -f "$TLS_DIR/cert.pem" ] || [ ! -f "$TLS_DIR/key.pem" ]; then
    echo "No TLS cert found — generating self-signed certificate..."
    /opt/persea/bin/persea generate-cert --hostname localhost --out-dir "$TLS_DIR"
    # The private key must not be world-readable. Best-effort: some bind
    # mounts don't support chmod.
    chmod 600 "$TLS_DIR/key.pem" 2>/dev/null || true
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

# Print the running version on beta images (PERSEA_BETA=1 set at build time
# by the beta workflow); production images skip this.
if [ "$PERSEA_BETA" = "1" ]; then
    echo "persea version: $(/opt/persea/bin/persea --version 2>&1)"
fi

# Generate /etc/krb5.conf for Kerberos NLA (RDP) when configured. An
# operator-mounted /opt/persea/krb5.conf takes precedence over generation.
if [ -f /opt/persea/krb5.conf ]; then
    echo "Using operator-mounted krb5.conf (/opt/persea/krb5.conf)"
    cp /opt/persea/krb5.conf /etc/krb5.conf
elif [ -n "${PERSEA_KRB5_REALM:-}" ]; then
    if [ -z "${PERSEA_KRB5_KDC:-}" ]; then
        echo "warning: PERSEA_KRB5_REALM is set but PERSEA_KRB5_KDC is not — skipping krb5.conf generation (Kerberos NLA will fail)" >&2
    else
        KRB5_KDC="${PERSEA_KRB5_KDC}"
        KRB5_ADMIN_SERVER="${PERSEA_KRB5_ADMIN_SERVER:-$KRB5_KDC}"
        KRB5_DOMAIN="${PERSEA_KRB5_DOMAIN:-}"
        {
            echo "[libdefaults]"
            echo "    default_realm = ${PERSEA_KRB5_REALM}"
            echo "    dns_lookup_kdc = true"
            echo "    dns_lookup_realm = false"
            echo "    forwardable = true"
            echo "    rdns = false"
            echo ""
            echo "[realms]"
            echo "    ${PERSEA_KRB5_REALM} = {"
            echo "        kdc = ${KRB5_KDC}"
            echo "        admin_server = ${KRB5_ADMIN_SERVER}"
            if [ -n "$KRB5_DOMAIN" ]; then
                echo "        default_domain = ${KRB5_DOMAIN}"
            fi
            echo "    }"
            if [ -n "$KRB5_DOMAIN" ]; then
                echo ""
                echo "[domain_realm]"
                echo "    .${KRB5_DOMAIN} = ${PERSEA_KRB5_REALM}"
                echo "    ${KRB5_DOMAIN} = ${PERSEA_KRB5_REALM}"
            fi
        } > /etc/krb5.conf
        echo "Generated /etc/krb5.conf (realm ${PERSEA_KRB5_REALM}, KDC ${KRB5_KDC})"

        # Lightweight, non-blocking KDC reachability check (TCP/88) so
        # operators see Kerberos problems at container start rather than in
        # RDP session errors. Uses nc or bash /dev/tcp — no extra deps.
        if command -v nc >/dev/null 2>&1; then
            if ! timeout 3 nc -z "$KRB5_KDC" 88 >/dev/null 2>&1; then
                echo "warning: KDC ${KRB5_KDC} not reachable on TCP/88 — Kerberos NLA will fail (check DNS, firewall, KDC service)" >&2
            fi
        elif command -v bash >/dev/null 2>&1; then
            if ! timeout 3 bash -c "exec 3<>/dev/tcp/${KRB5_KDC}/88" >/dev/null 2>&1; then
                echo "warning: KDC ${KRB5_KDC} not reachable on TCP/88 — Kerberos NLA will fail (check DNS, firewall, KDC service)" >&2
            fi
        fi
    fi
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

# No USER directive here on purpose: the entrypoint starts as root, reconciles
# ownership for bind mounts (PUID/PGID), and drops to persea via gosu. Starts
# that are already non-root (docker --user, Kubernetes runAsNonRoot) skip the
# reconciliation block entirely.
ENTRYPOINT ["/opt/persea/entrypoint.sh"]
