#!/usr/bin/env bash
#
# build-deb.sh — Build a .deb package for rustguac (includes guacd).
#
# Prerequisites:
#   - Rust toolchain (cargo)
#   - guacd build deps (autoconf, automake, libtool, -dev packages)
#   - dpkg-dev, debhelper, fakeroot
#
# guacamole-server is cloned automatically if not found at ../guacamole-server.
#
# Usage:
#   ./build-deb.sh
#
# Output:
#   ../rustguac_<version>_amd64.deb
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUACD_SRC_URL="https://github.com/apache/guacamole-server.git"
GUACD_SRC="${SCRIPT_DIR}/../guacamole-server"
STAGING="${SCRIPT_DIR}/debian/staging"
PREFIX="/opt/rustguac"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[build-deb]${NC} $*"; }
warn()  { echo -e "${YELLOW}[build-deb]${NC} $*"; }
error() { echo -e "${RED}[build-deb]${NC} $*" >&2; }

# ---------------------------------------------------------------------------
# Step 1: Determine version
# ---------------------------------------------------------------------------
CARGO_VERSION=$(grep '^version' "$SCRIPT_DIR/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
GIT_HASH=$(git -C "$SCRIPT_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
VERSION="${CARGO_VERSION}+g${GIT_HASH}"

info "Building rustguac ${VERSION}"

# ---------------------------------------------------------------------------
# Step 2: Generate debian/changelog
# ---------------------------------------------------------------------------
info "Generating debian/changelog..."
cat > "$SCRIPT_DIR/debian/changelog" <<EOF
rustguac (${VERSION}) unstable; urgency=medium

  * Built from git commit ${GIT_HASH}.

 -- rustguac build <rustguac@localhost>  $(date -R)
EOF

# ---------------------------------------------------------------------------
# Step 3: Build guacd into staging
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
        git clone --depth 1 "$GUACD_SRC_URL" "$GUACD_SRC"
    fi

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
# Step 4: Build rustguac
# ---------------------------------------------------------------------------
info "Building rustguac (cargo build --release)..."
cd "$SCRIPT_DIR"
cargo build --release
info "rustguac built."

# ---------------------------------------------------------------------------
# Step 5: Build the .deb
# ---------------------------------------------------------------------------
info "Running dpkg-buildpackage..."
cd "$SCRIPT_DIR"
dpkg-buildpackage -us -uc -b

# ---------------------------------------------------------------------------
# Step 6: Report results
# ---------------------------------------------------------------------------
DEB=$(ls -1t "$SCRIPT_DIR/../rustguac_${VERSION}_"*.deb 2>/dev/null | head -1)
if [[ -n "$DEB" ]]; then
    echo ""
    info "============================================"
    info "  Package built: $DEB"
    info "============================================"
    echo ""
    info "Install on target:"
    info "  scp $DEB root@target:"
    info "  ssh root@target 'dpkg -i $(basename "$DEB") && apt-get -f install -y'"
else
    error "Package not found — check build output above."
    exit 1
fi
