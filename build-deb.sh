#!/usr/bin/env bash
#
# build-deb.sh — Build a .deb package for persea (includes guacd).
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
#   ../persea_<version>_amd64.deb
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUACD_SRC_URL="https://github.com/apache/guacamole-server.git"
# Pinned guacamole-server commit. The patches in patches/ are rebased onto this
# EXACT commit, so it MUST stay in sync with release.yml (GUACD_COMMIT) and
# install.sh (GUACD_COMMIT). Do not bump it without re-rebasing the patch set.
GUACD_COMMIT="de97609007c088b5e6afd827eff5e9076013a247"
STAGING="${SCRIPT_DIR}/debian/staging"
PREFIX="/opt/persea"

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

info "Building persea ${VERSION}"

# ---------------------------------------------------------------------------
# Step 2: Generate debian/changelog
# ---------------------------------------------------------------------------
info "Generating debian/changelog..."
cat > "$SCRIPT_DIR/debian/changelog" <<EOF
persea (${VERSION}) unstable; urgency=medium

  * Built from git commit ${GIT_HASH}.

 -- persea build <persea@localhost>  $(date -R)
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
        info "Applying patch: $(basename "$patch")"
        if ! git -C "$src" apply "$patch"; then
            error "Patch FAILED to apply: $(basename "$patch")"
            error "guacamole-server pin ($GUACD_COMMIT) and patches/ are out of sync."
            error "Re-rebase the patches onto $GUACD_COMMIT (or fix the pin). Aborting."
            exit 1
        fi
    done
}

build_guacd() {
    # Reproducible by default: build guacd from a FRESH clone pinned to
    # $GUACD_COMMIT, so the package never drifts with upstream master and the
    # patch set always applies to the exact source it was rebased onto. For
    # local patch iteration set GUACD_SRC_OVERRIDE=/path/to/guacamole-server to
    # build from an existing (unpinned) working tree instead.
    local GUACD_SRC guacd_src_tmp=""
    if [[ -n "${GUACD_SRC_OVERRIDE:-}" ]]; then
        GUACD_SRC="$GUACD_SRC_OVERRIDE"
        warn "GUACD_SRC_OVERRIDE set — building guacd from $GUACD_SRC (UNPINNED; local dev only)"
    else
        GUACD_SRC=$(mktemp -d)
        guacd_src_tmp="$GUACD_SRC"
        info "Cloning guacamole-server, pinned to $GUACD_COMMIT..."
        git clone -q "$GUACD_SRC_URL" "$GUACD_SRC"
        git -C "$GUACD_SRC" -c advice.detachedHead=false checkout -q "$GUACD_COMMIT"
    fi

    apply_guacd_patches "$GUACD_SRC"

    info "Building guacd from $GUACD_SRC..."

    local BUILD_DIR
    BUILD_DIR=$(mktemp -d)
    trap "rm -rf '$BUILD_DIR' '$guacd_src_tmp'" EXIT

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
    # Memory-safety cap: -j$(nproc) ICEs gcc on wide/constrained machines.
    make -j"${GUACD_JOBS:-4}"

    info "Installing guacd to staging..."
    rm -rf "$STAGING"
    make DESTDIR="$STAGING" install

    cd "$SCRIPT_DIR"
    info "guacd staged at $STAGING"
}

build_guacd

# ---------------------------------------------------------------------------
# Step 4: Build persea
# ---------------------------------------------------------------------------
info "Building Tailwind CSS..."
npx --yes tailwindcss@3 -i static/css/input.css -o static/css/tailwind.min.css --minify

info "Building persea (cargo build --release)..."
cd "$SCRIPT_DIR"
cargo build --release
info "persea built."

# ---------------------------------------------------------------------------
# Step 5: Build the .deb
# ---------------------------------------------------------------------------
info "Running dpkg-buildpackage..."
cd "$SCRIPT_DIR"
dpkg-buildpackage -us -uc -b

# ---------------------------------------------------------------------------
# Step 6: Report results
# ---------------------------------------------------------------------------
DEB=$(ls -1t "$SCRIPT_DIR/../persea_${VERSION}_"*.deb 2>/dev/null | head -1)
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
