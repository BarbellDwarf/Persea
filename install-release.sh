#!/usr/bin/env bash
#
# install-release.sh — Install persea from a release tarball.
#
# This script is shipped inside the release tarball and installs
# pre-built binaries to /opt/persea with systemd services.
#
# Usage:
#   sudo ./install.sh
#   sudo ./install.sh --no-tls
#   sudo ./install.sh --hostname=myhost.example.com
#
set -euo pipefail

PREFIX="/opt/persea"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[install]${NC} $*"; }
warn()  { echo -e "${YELLOW}[install]${NC} $*"; }
error() { echo -e "${RED}[install]${NC} $*" >&2; }

NO_TLS=0
TLS_HOSTNAME=""
for arg in "$@"; do
    case "$arg" in
        --no-tls)      NO_TLS=1 ;;
        --hostname=*)  TLS_HOSTNAME="${arg#--hostname=}" ;;
        -h|--help)
            echo "Usage: sudo $0 [--no-tls] [--hostname=FQDN]"
            echo ""
            echo "Options:"
            echo "  --no-tls          Skip TLS certificate generation (plain HTTP only)"
            echo "  --hostname=FQDN   Hostname for the TLS certificate (default: system hostname)"
            exit 0
            ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo ./install.sh)"
    exit 1
fi

# ---------------------------------------------------------------------------
# Step 1: Create system user
# ---------------------------------------------------------------------------
if ! id -u persea >/dev/null 2>&1; then
    useradd --system --create-home --home-dir /home/persea --shell /usr/sbin/nologin persea
    info "Created system user 'persea'"
else
    info "System user 'persea' already exists"
fi

# ---------------------------------------------------------------------------
# Step 2: Install files
# ---------------------------------------------------------------------------
info "Installing persea to $PREFIX..."

mkdir -p "$PREFIX"/{bin,sbin,lib,static,data,recordings,tls}

# Binaries
install -m 755 "$SCRIPT_DIR/bin/persea" "$PREFIX/bin/persea"
install -m 755 "$SCRIPT_DIR/sbin/guacd"   "$PREFIX/sbin/guacd"

# Libraries
cp -a "$SCRIPT_DIR/lib/"*.so* "$PREFIX/lib/"

# Static web assets
cp -r "$SCRIPT_DIR/static/"* "$PREFIX/static/"

# Drive setup script (if present)
if [[ -d "$SCRIPT_DIR/scripts" ]]; then
    cp -r "$SCRIPT_DIR/scripts/"* "$PREFIX/bin/"
    chmod +x "$PREFIX/bin/"*.sh 2>/dev/null || true
fi

# Default config (don't overwrite existing)
if [[ ! -f "$PREFIX/config.toml" ]]; then
    cp "$SCRIPT_DIR/config.toml.default" "$PREFIX/config.toml"

    if [[ $NO_TLS -eq 0 ]]; then
        # config.toml.default already has [tls] section
        info "Created config at $PREFIX/config.toml (TLS enabled)"
    else
        # Remove TLS section for plain HTTP
        sed -i '/^\[tls\]/,$d' "$PREFIX/config.toml"
        sed -i 's/listen_addr = .*/listen_addr = "0.0.0.0:8089"/' "$PREFIX/config.toml"
        info "Created config at $PREFIX/config.toml (plain HTTP)"
    fi
else
    info "Config already exists at $PREFIX/config.toml (not overwritten)"
fi

# Generate a storage encryption key if the config has none: the server
# refuses to start without one (credentials would sit in plaintext).
# TOML-aware: inserts into an existing [storage] table, appends one only
# when absent, so admin-modified configs never get a duplicate table.
# Mirrors debian/postinst and the Docker entrypoint; respects an
# admin-set key.
if ! grep -q '^encryption_key' "$PREFIX/config.toml" 2>/dev/null; then
    KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    if grep -q '^\[storage\]' "$PREFIX/config.toml" 2>/dev/null; then
        sed -i '/^\[storage\]/a encryption_key = "'"$KEY"'"' "$PREFIX/config.toml"
    else
        {
            echo ""
            echo "[storage]"
            echo "encryption_key = \"$KEY\""
        } >> "$PREFIX/config.toml"
    fi
    info "Generated storage encryption key."
fi
# The config now holds the encryption key: not world-readable.
chmod 600 "$PREFIX/config.toml"

chown -R persea:persea "$PREFIX/data" "$PREFIX/recordings"

# The SQLite DB holds session tokens and encrypted credentials: never
# world-readable. Pre-create it with owner-only perms so the first service
# start (as persea) never creates a 0644 file; fix up existing files
# (re-run path). The data dir itself is locked to the service account.
DB="$PREFIX/data/persea.db"
if [ ! -f "$DB" ]; then
    touch "$DB"
fi
chown persea:persea "$DB"
chmod 600 "$DB"
chmod 750 "$PREFIX/data"

# FreeRDP 3 plugins (RDPDR/RDPSND channels: drive redirection, audio,
# printing) — install next to the system FreeRDP libraries so freerdp finds
# them at runtime. Mirrors the .deb layout.
FREERDP_PLUGIN_DIR="$(pkg-config --variable=libdir freerdp3 2>/dev/null || echo /usr/lib/x86_64-linux-gnu)/freerdp3"
if [ -d "$SCRIPT_DIR/lib/freerdp3" ]; then
    mkdir -p "$FREERDP_PLUGIN_DIR"
    cp -a "$SCRIPT_DIR/lib/freerdp3/"*.so* "$FREERDP_PLUGIN_DIR/" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 3: ldconfig
# ---------------------------------------------------------------------------
echo "$PREFIX/lib" > /etc/ld.so.conf.d/persea.conf
ldconfig
info "Library path configured"

# ---------------------------------------------------------------------------
# Step 4: systemd services
# ---------------------------------------------------------------------------
info "Installing systemd services..."
cp "$SCRIPT_DIR/systemd/persea.service"       /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/persea-guacd.service"  /etc/systemd/system/

systemctl daemon-reload
systemctl enable persea-guacd.service
systemctl enable persea.service

info "Systemd services installed and enabled"

# ---------------------------------------------------------------------------
# Step 5: TLS certificate
# ---------------------------------------------------------------------------
if [[ $NO_TLS -eq 0 ]]; then
    if [[ -f "$PREFIX/tls/cert.pem" && -f "$PREFIX/tls/key.pem" ]]; then
        info "TLS certificates already exist (not overwritten)"
    else
        CERT_HOSTNAME="${TLS_HOSTNAME:-$(hostname -f 2>/dev/null || hostname)}"
        info "Generating self-signed TLS certificate for: $CERT_HOSTNAME"
        "$PREFIX/bin/persea" generate-cert \
            --hostname "$CERT_HOSTNAME" \
            --out-dir "$PREFIX/tls"
        chown -R persea:persea "$PREFIX/tls"
        chmod 600 "$PREFIX/tls/key.pem"
        chmod 644 "$PREFIX/tls/cert.pem"
        info "TLS certificate generated at $PREFIX/tls/"
    fi
fi

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
echo ""
info "============================================"
info "  persea installed to $PREFIX"
info "============================================"
echo ""
info "Next steps:"
info "  1. Create an admin:"
info "     $PREFIX/bin/persea --config $PREFIX/config.toml add-admin --name admin"
info ""
info "  2. (Optional) Set up encrypted file transfer:"
info "     sudo $PREFIX/bin/drive-setup.sh"
info ""
info "  3. Start the services:"
info "     sudo systemctl start persea"
echo ""
if [[ $NO_TLS -eq 0 ]]; then
    info "  4. Open in browser:"
    info "     https://$(hostname -f 2>/dev/null || hostname)"
    info ""
    warn "  Using self-signed cert — browser will show a warning."
    warn "  Replace $PREFIX/tls/cert.pem and key.pem with real certs for production."
else
    info "  4. Open in browser:"
    info "     http://localhost:8089"
fi
echo ""
