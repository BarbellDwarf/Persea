#!/usr/bin/env bash
#
# dev.sh — Build and run persea + guacd for local development/testing.
#
# Usage:
#   ./dev.sh build-guacd    Build guacd from ../guacamole-server (fork branch persea-1.6.1-freerdp3) into .guacd-build/
#   ./dev.sh start-guacd    Start guacd in foreground on localhost:4822
#   ./dev.sh build           Build persea (cargo build)
#   ./dev.sh tailwind        Build Tailwind CSS (input.css -> tailwind.min.css)
#   ./dev.sh run             Build and run persea
#   ./dev.sh start           Build guacd (if needed), build persea, start both
#   ./dev.sh stop            Stop backgrounded guacd
#   ./dev.sh deps            Install build dependencies for guacd (apt, needs sudo)
#   ./dev.sh status          Show status of guacd and persea processes
#   ./dev.sh generate-cert   Generate self-signed TLS cert for dev (cert.pem + key.pem)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUACD_SRC="${SCRIPT_DIR}/../guacamole-server"
GUACD_BUILD="${SCRIPT_DIR}/.guacd-build"
GUACD_PREFIX="${GUACD_BUILD}/install"
GUACD_BIN="${GUACD_PREFIX}/sbin/guacd"
GUACD_PID="${GUACD_BUILD}/guacd.pid"
GUACD_PORT="${GUACD_PORT:-4822}"
GUACD_LOG_LEVEL="${GUACD_LOG_LEVEL:-info}"
RECORDINGS_DIR="${SCRIPT_DIR}/recordings"
DEV_CERT="${SCRIPT_DIR}/cert.pem"
DEV_KEY="${SCRIPT_DIR}/key.pem"
DEV_CONFIG="${SCRIPT_DIR}/config.local.toml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[dev]${NC} $*"; }
warn()  { echo -e "${YELLOW}[dev]${NC} $*"; }
error() { echo -e "${RED}[dev]${NC} $*" >&2; }

#--- Install build dependencies (Debian/Ubuntu) ---
cmd_deps() {
    info "Installing guacd build dependencies..."
    sudo apt-get update
    sudo apt-get install -y \
        autoconf automake libtool pkg-config make gcc g++ \
        libcairo2-dev libjpeg-dev libpng-dev libossp-uuid-dev libavcodec-dev \
        libavformat-dev libavutil-dev libswscale-dev \
        libpango1.0-dev libssh2-1-dev libssl-dev \
        libvncserver-dev libtelnet-dev libwebsockets-dev \
        libpulse-dev libwebp-dev libcunit1-dev \
        freerdp3-dev libspice-client-glib-2.0-dev

    # uuid-dev is the standard package on Debian; fall back to libossp-uuid-dev
    sudo apt-get install -y uuid-dev 2>/dev/null || true

    info "Dependencies installed."
}

#--- Build guacd from source ---
cmd_build_guacd() {
    if [[ ! -d "$GUACD_SRC" ]]; then
        error "guacamole-server source not found at $GUACD_SRC"
        error "Expected it at ../guacamole-server relative to persea"
        error "  (check out branch persea-1.6.1-freerdp3 of the fork"
        error "   persea-grove/persea-guacamole-server there — the former"
        error "   patches/ quilt now lives on that branch as commits)"
        exit 1
    fi

    info "Building guacd from $GUACD_SRC"
    info "Build dir:   $GUACD_BUILD"
    info "Install dir: $GUACD_PREFIX"

    mkdir -p "$GUACD_BUILD"

    # Run autoreconf in the source tree if configure doesn't exist
    if [[ ! -f "$GUACD_SRC/configure" ]]; then
        info "Running autoreconf..."
        (cd "$GUACD_SRC" && autoreconf -fi)
    fi

    # Configure out-of-tree build
    cd "$GUACD_BUILD"
    if [[ ! -f "$GUACD_BUILD/Makefile" ]]; then
        info "Configuring..."
        "$GUACD_SRC/configure" \
            --prefix="$GUACD_PREFIX" \
            --with-ssh \
            --with-vnc \
            --with-rdp \
            --with-spice \
            --without-telnet \
            --without-kubernetes \
            --disable-guacenc \
            --disable-guaclog \
            --disable-guacclip \
            --disable-static
    fi

    info "Compiling..."
    make -j"$(nproc)"

    info "Installing to $GUACD_PREFIX..."
    make install

    info "guacd built successfully: $GUACD_BIN"
    "$GUACD_BIN" -v
}

#--- Start guacd in foreground ---
cmd_start_guacd() {
    if [[ ! -x "$GUACD_BIN" ]]; then
        error "guacd not found at $GUACD_BIN"
        error "Run: ./dev.sh build-guacd"
        exit 1
    fi

    # Make sure the library path includes our build
    export LD_LIBRARY_PATH="${GUACD_PREFIX}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    info "Starting guacd on localhost:$GUACD_PORT (foreground, log_level=$GUACD_LOG_LEVEL)"
    exec "$GUACD_BIN" -b 127.0.0.1 -l "$GUACD_PORT" -L "$GUACD_LOG_LEVEL" -f
}

#--- Start guacd in background ---
start_guacd_bg() {
    if [[ ! -x "$GUACD_BIN" ]]; then
        error "guacd not found at $GUACD_BIN — run: ./dev.sh build-guacd"
        exit 1
    fi

    # Kill existing if running
    stop_guacd_quiet

    export LD_LIBRARY_PATH="${GUACD_PREFIX}/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

    info "Starting guacd in background on localhost:$GUACD_PORT..."
    "$GUACD_BIN" -b 127.0.0.1 -l "$GUACD_PORT" -L "$GUACD_LOG_LEVEL" -f \
        > "${GUACD_BUILD}/guacd.log" 2>&1 &
    local pid=$!
    echo "$pid" > "$GUACD_PID"
    info "guacd started (pid=$pid)"

    # Brief wait to check it didn't crash immediately
    sleep 0.5
    if ! kill -0 "$pid" 2>/dev/null; then
        error "guacd failed to start. Log:"
        cat "${GUACD_BUILD}/guacd.log"
        exit 1
    fi
}

#--- Stop backgrounded guacd ---
stop_guacd_quiet() {
    if [[ -f "$GUACD_PID" ]]; then
        local pid
        pid=$(cat "$GUACD_PID")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
        rm -f "$GUACD_PID"
    fi
    # Also kill any stray guacd from our build
    pkill -f "$GUACD_BIN" 2>/dev/null || true
}

cmd_stop() {
    info "Stopping guacd..."
    stop_guacd_quiet
    info "Stopped."
}

#--- Build persea ---
cmd_build() {
    info "Building persea..."
    cd "$SCRIPT_DIR"
    cargo build 2>&1
    info "persea built."
}

#--- Build Tailwind CSS ---
cmd_tailwind() {
    info "Building Tailwind CSS..."
    cd "$SCRIPT_DIR"
    npx --yes tailwindcss@3 -i static/css/input.css -o static/css/tailwind.min.css --minify
    info "Tailwind CSS built."
}

#--- Setup dev database with a dev admin ---
cmd_setup_db() {
    local DB_PATH="${SCRIPT_DIR}/persea.db"
    if [[ -f "$DB_PATH" ]]; then
        info "Database already exists at $DB_PATH"
        info "Current admins:"
        cd "$SCRIPT_DIR"
        cargo run -q -- list-admins
        return 0
    fi

    info "Creating dev database and admin..."
    cd "$SCRIPT_DIR"
    cargo run -q -- add-admin --name dev
    echo ""
    info "Save the API key above for testing. Example usage:"
    info "  curl -H 'Authorization: Bearer <key>' http://localhost:8089/api/sessions"
}

#--- Run persea ---
cmd_run() {
    cmd_build
    mkdir -p "$RECORDINGS_DIR"
    cmd_setup_db

    info "Starting persea..."
    cd "$SCRIPT_DIR"
    if [[ -f "$DEV_CONFIG" ]]; then
        info "Using config: $DEV_CONFIG"
        exec cargo run -- --config "$DEV_CONFIG"
    else
        exec cargo run
    fi
}

#--- Start everything ---
cmd_start() {
    # Build guacd if not already built
    if [[ ! -x "$GUACD_BIN" ]]; then
        warn "guacd not built yet, building..."
        cmd_build_guacd
    fi

    # Build persea
    cmd_build

    # Start guacd in background
    start_guacd_bg

    # Ensure recordings dir exists
    mkdir -p "$RECORDINGS_DIR"

    # Setup dev database if needed
    cmd_setup_db

    # Run persea in foreground (Ctrl+C stops it, then we clean up guacd)
    info "Starting persea on localhost:8089..."
    info "Press Ctrl+C to stop both."
    trap 'echo; info "Shutting down..."; pkill -f "target/debug/persea" 2>/dev/null; stop_guacd_quiet; exit 0' INT TERM

    cd "$SCRIPT_DIR"
    if [[ -f "$DEV_CONFIG" ]]; then
        info "Using config: $DEV_CONFIG"
        cargo run -- --config "$DEV_CONFIG" &
    else
        cargo run &
    fi
    local persea_pid=$!

    wait "$persea_pid" 2>/dev/null || true
    stop_guacd_quiet
}

#--- Status ---
cmd_status() {
    echo "=== guacd ==="
    if [[ -f "$GUACD_PID" ]] && kill -0 "$(cat "$GUACD_PID")" 2>/dev/null; then
        echo "  Running (pid=$(cat "$GUACD_PID"), port=$GUACD_PORT)"
    else
        echo "  Not running"
    fi
    if [[ -x "$GUACD_BIN" ]]; then
        echo "  Binary: $GUACD_BIN"
        echo "  Version: $("$GUACD_BIN" -v 2>&1 || echo unknown)"
    else
        echo "  Not built"
    fi

    echo ""
    echo "=== persea ==="
    if pgrep -f "target/debug/persea" > /dev/null 2>&1; then
        echo "  Running (pid=$(pgrep -f 'target/debug/persea'))"
    else
        echo "  Not running"
    fi
    if [[ -f "$SCRIPT_DIR/target/debug/persea" ]]; then
        echo "  Binary: $SCRIPT_DIR/target/debug/persea"
    else
        echo "  Not built"
    fi
}

#--- Generate self-signed TLS certificate for dev ---
cmd_generate_cert() {
    if [[ -f "$DEV_CERT" && -f "$DEV_KEY" ]]; then
        info "TLS cert already exists: $DEV_CERT"
        info "Delete cert.pem and key.pem to regenerate."
        return 0
    fi

    cmd_build

    info "Generating self-signed TLS certificate..."
    cd "$SCRIPT_DIR"
    cargo run -q -- generate-cert --hostname localhost --out-dir "$SCRIPT_DIR"
    info "Certificate generated: $DEV_CERT"
    info "Private key generated: $DEV_KEY"
    echo ""
    info "Add to config.local.toml:"
    info "  [tls]"
    info "  cert_path = \"$DEV_CERT\""
    info "  key_path = \"$DEV_KEY\""
}

#--- Main ---
case "${1:-help}" in
    deps)           cmd_deps ;;
    build-guacd)    cmd_build_guacd ;;
    start-guacd)    cmd_start_guacd ;;
    build)          cmd_build ;;
    tailwind)       cmd_tailwind ;;
    run)            cmd_run ;;
    start)          cmd_start ;;
    stop)           cmd_stop ;;
    status)         cmd_status ;;
    setup-db)       cmd_build && cmd_setup_db ;;
    generate-cert)  cmd_generate_cert ;;
    help|*)
        echo "Usage: $0 <command>"
        echo ""
        echo "Commands:"
        echo "  deps           Install system build dependencies for guacd (needs sudo)"
        echo "  build-guacd    Build guacd from ../guacamole-server into .guacd-build/"
        echo "  start-guacd    Start guacd in foreground (for debugging)"
        echo "  build          Build persea (cargo build)"
        echo "  tailwind       Build Tailwind CSS (input.css -> tailwind.min.css)"
        echo "  run            Build and run persea only"
        echo "  start          Build everything, start guacd + persea together"
        echo "  stop           Stop backgrounded guacd"
        echo "  setup-db       Create dev database and admin API key"
        echo "  generate-cert  Generate self-signed TLS cert+key for dev (localhost)"
        echo "  status         Show process status"
        echo ""
        echo "Environment:"
        echo "  GUACD_PORT       guacd listen port (default: 4822)"
        echo "  GUACD_LOG_LEVEL  guacd log level: trace/debug/info/warning/error (default: info)"
        ;;
esac
