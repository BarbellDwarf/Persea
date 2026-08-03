#!/usr/bin/env bash
#
# build-rpm.sh — Build an RPM package for persea (includes guacd).
#
# Prerequisites:
#   - Rust toolchain (cargo)
#   - guacd build deps (autoconf, automake, libtool, -devel packages)
#   - rpm-build, systemd-rpm-macros
#   - EPEL enabled (for ffmpeg-libs, libtelnet, libwebsockets, chromium)
#
# guacamole-server is cloned automatically if not found at ../guacamole-server.
#
# Usage:
#   ./build-rpm.sh
#
# Output:
#   ../persea-<version>-1.el9.x86_64.rpm
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUACD_SRC_URL="https://github.com/apache/guacamole-server.git"
# Pinned guacamole-server commit — must match build-deb.sh, install.sh, and release.yml
GUACD_COMMIT="6719b20d"
GUACD_SRC="${SCRIPT_DIR}/../guacamole-server"
STAGING="${SCRIPT_DIR}/rpm/staging"
PREFIX="/opt/persea"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[build-rpm]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build-rpm]${NC} $*"; }
error() { echo -e "${RED}[build-rpm]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Step 1: Determine version
# ---------------------------------------------------------------------------
CARGO_VERSION=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_HASH=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="${CARGO_VERSION}+g${GIT_HASH}"

info "Building persea ${VERSION}"

# ---------------------------------------------------------------------------
# Step 2: Build guacd into rpm/staging
# ---------------------------------------------------------------------------
apply_guacd_patches() {
    local src="$1"
    local patch_dir="${SCRIPT_DIR}/patches"

    if [[ ! -d "$patch_dir" ]]; then
        return 0
    fi

    for patch in "$patch_dir"/*.patch; do
        [[ -f "$patch" ]] || continue
        if git -C "$src" apply --check "$patch" 2>/dev/null; then
            info "Applying patch: $(basename "$patch")"
            git -C "$src" apply "$patch"
        else
            info "Patch already applied or N/A: $(basename "$patch")"
        fi
    done
}

build_guacd() {
    if [[ ! -d "$GUACD_SRC/.git" ]]; then
        info "guacamole-server not found at $GUACD_SRC — cloning..."
        git clone "$GUACD_SRC_URL" "$GUACD_SRC"
    fi

    info "Checking out guacd commit $GUACD_COMMIT..."
    git -C "$GUACD_SRC" -c advice.detachedHead=false checkout -q "$GUACD_COMMIT"

    apply_guacd_patches "$GUACD_SRC"

    info "Building guacd from $GUACD_SRC..."

    local BUILD_DIR
    BUILD_DIR=$(mktemp -d)
    trap "rm -rf '$BUILD_DIR'" EXIT

    # Run autoreconf if needed
    if [[ ! -f "$GUACD_SRC/configure" ]]; then
        info "Running autoreconf..."
        (cd "$GUACD_SRC" && autoreconf -fi)
    fi

    cd "$BUILD_DIR"

    info "Configuring guacd (prefix=$PREFIX)..."
    "$GUACD_SRC/configure" \
        --prefix="$PREFIX" \
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

    info "Compiling guacd..."
    make -j"$(nproc)"

    info "Installing guacd to staging..."
    rm -rf "$STAGING"
    make DESTDIR="$STAGING" install

    cd "$SCRIPT_DIR"
    info "guacd staged at $STAGING"
}

build_guacd

# ---------------------------------------------------------------------------
# Step 3: Build persea
# ---------------------------------------------------------------------------
info "Building persea (cargo build --release)..."
cd "$SCRIPT_DIR"
cargo build --release
info "persea built."

# ---------------------------------------------------------------------------
# Step 4: Build the RPM
# ---------------------------------------------------------------------------
RPMBUILD_DIR="$HOME/rpmbuild"
info "Setting up rpmbuild directory at $RPMBUILD_DIR..."
mkdir -p "$RPMBUILD_DIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

info "Running rpmbuild..."
rpmbuild -bb \
    --define "_topdir $RPMBUILD_DIR" \
    --define "_builddir $SCRIPT_DIR" \
    --define "_version ${CARGO_VERSION}" \
    "$SCRIPT_DIR/persea.spec"

# ---------------------------------------------------------------------------
# Step 5: Report results
# ---------------------------------------------------------------------------
RPM=$(find "$RPMBUILD_DIR/RPMS" -name "persea-*.rpm" -type f | head -1)
if [[ -n "$RPM" ]]; then
    cp "$RPM" "$SCRIPT_DIR/../"
    FINAL="$SCRIPT_DIR/../$(basename "$RPM")"
    echo ""
    info "============================================"
    info "  Package built: $FINAL"
    info "============================================"
    echo ""
    info "Install on target (Rocky/RHEL/Alma 9):"
    info "  scp $FINAL root@target:"
    info "  ssh root@target 'dnf install -y ./$(basename "$RPM")'"
else
    error "RPM not found — check build output above."
    exit 1
fi
