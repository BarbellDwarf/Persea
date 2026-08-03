#!/usr/bin/env bash
#
# drive-setup.sh — Set up encrypted LUKS drive for persea file transfer.
#
# Creates a LUKS-encrypted container, formats it, and installs sudoers rules
# so the persea service can mount/unmount it at runtime.
#
# Must be run as root (sudo).
#
# Env vars for non-interactive / automation:
#   PERSEA_DRIVE_SETUP=yes|no   — skip the prompt
#   PERSEA_DRIVE_SIZE=4G        — LUKS container size
#   PERSEA_DRIVE_MOUNT=/mnt/persea-drives
#   PERSEA_LUKS_DEVICE=/opt/persea/drives.luks
#   PERSEA_LUKS_NAME=persea-drives
#
# Usage:
#   sudo /opt/persea/bin/drive-setup.sh
#
set -euo pipefail

PREFIX="/opt/persea"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[drive-setup]${NC} $*"; }
warn()  { echo -e "${YELLOW}[drive-setup]${NC} $*"; }
error() { echo -e "${RED}[drive-setup]${NC} $*" >&2; }

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (sudo)."
    exit 1
fi

SETUP="${PERSEA_DRIVE_SETUP:-}"
DRIVE_SIZE="${PERSEA_DRIVE_SIZE:-4G}"
MOUNT_POINT="${PERSEA_DRIVE_MOUNT:-/mnt/persea-drives}"
LUKS_DEVICE="${PERSEA_LUKS_DEVICE:-$PREFIX/drives.luks}"
LUKS_NAME="${PERSEA_LUKS_NAME:-persea-drives}"

# If already set up, skip
if [[ -f "$LUKS_DEVICE" ]]; then
    info "LUKS container already exists at $LUKS_DEVICE"
    info "To recreate, remove the existing container first."
    exit 0
fi

# Check if cryptsetup is available
if ! command -v cryptsetup &>/dev/null; then
    error "cryptsetup not found."
    if command -v apt-get &>/dev/null; then
        error "Install with: sudo apt-get install -y cryptsetup-bin"
    elif command -v dnf &>/dev/null; then
        error "Install with: sudo dnf install -y cryptsetup"
    elif command -v yum &>/dev/null; then
        error "Install with: sudo yum install -y cryptsetup"
    fi
    exit 1
fi

# Check if persea user exists
if ! getent passwd persea >/dev/null 2>&1; then
    error "persea user not found. Install the persea package first."
    exit 1
fi

if [[ -z "$SETUP" ]]; then
    echo ""
    AVAIL=$(df -h "$(dirname "$LUKS_DEVICE")" | tail -1 | awk '{print $4}')
    info "Drive / File Transfer Setup"
    info "  Creates an encrypted LUKS volume for RDP file transfer storage."
    info "  Available space on $(dirname "$LUKS_DEVICE"): $AVAIL"
    info "  Default container size: $DRIVE_SIZE"
    echo ""
    read -rp "Set up encrypted drive volume? [y/N]: " SETUP
    if [[ "$SETUP" =~ ^[yY] ]]; then
        read -rp "Container size [$DRIVE_SIZE]: " USER_SIZE
        if [[ -n "$USER_SIZE" ]]; then
            DRIVE_SIZE="$USER_SIZE"
        fi
    fi
fi

if [[ ! "$SETUP" =~ ^[yY] ]]; then
    info "Aborted. Run again when ready."
    exit 0
fi

info "Creating LUKS container: $LUKS_DEVICE ($DRIVE_SIZE)"

# Parse size to MB for dd
SIZE_MB=0
if [[ "$DRIVE_SIZE" =~ ^([0-9]+)[gG]$ ]]; then
    SIZE_MB=$(( ${BASH_REMATCH[1]} * 1024 ))
elif [[ "$DRIVE_SIZE" =~ ^([0-9]+)[mM]$ ]]; then
    SIZE_MB="${BASH_REMATCH[1]}"
else
    error "Invalid size format: $DRIVE_SIZE (use e.g. 4G, 512M)"
    exit 1
fi

# Generate random key
LUKS_KEY=$(openssl rand -base64 32)

# Create the container file
dd if=/dev/zero of="$LUKS_DEVICE" bs=1M count="$SIZE_MB" status=progress 2>&1

# Format LUKS
echo -n "$LUKS_KEY" | cryptsetup luksFormat --batch-mode "$LUKS_DEVICE" -

# Open, format filesystem, close
echo -n "$LUKS_KEY" | cryptsetup open --type luks --key-file=- "$LUKS_DEVICE" "$LUKS_NAME"
mkfs.ext4 -q "/dev/mapper/$LUKS_NAME"
cryptsetup close "$LUKS_NAME"

# Create mount point
mkdir -p "$MOUNT_POINT"
chown persea:persea "$MOUNT_POINT"

# Set ownership of LUKS file
chown persea:persea "$LUKS_DEVICE"
chmod 600 "$LUKS_DEVICE"

# Install sudoers rules
info "Installing sudoers rules for LUKS management..."
cat > /etc/sudoers.d/persea-drive <<SUDOERS
# persea LUKS drive management — created by drive-setup.sh
persea ALL=(root) NOPASSWD: /usr/sbin/cryptsetup open --type luks --key-file=- $LUKS_DEVICE $LUKS_NAME
persea ALL=(root) NOPASSWD: /usr/sbin/cryptsetup close $LUKS_NAME
persea ALL=(root) NOPASSWD: /bin/mount /dev/mapper/$LUKS_NAME $MOUNT_POINT
persea ALL=(root) NOPASSWD: /usr/bin/mount /dev/mapper/$LUKS_NAME $MOUNT_POINT
persea ALL=(root) NOPASSWD: /bin/umount $MOUNT_POINT
persea ALL=(root) NOPASSWD: /usr/bin/umount $MOUNT_POINT
persea ALL=(root) NOPASSWD: /bin/chown *\:* $MOUNT_POINT
persea ALL=(root) NOPASSWD: /usr/bin/chown *\:* $MOUNT_POINT
SUDOERS
chmod 0440 /etc/sudoers.d/persea-drive

info "LUKS container created and formatted."
echo ""
info "IMPORTANT: Store this LUKS key in Vault:"
info "  vault kv put -mount=<mount> persea/luks-key key='$LUKS_KEY'"
echo ""
info "Then add to your config.toml:"
info "  [drive]"
info "  enabled = true"
info "  drive_path = \"$MOUNT_POINT\""
info "  luks_device = \"$LUKS_DEVICE\""
info "  luks_name = \"$LUKS_NAME\""
info "  luks_key_path = \"persea/luks-key\""
echo ""
warn "The LUKS key above is shown ONCE. Save it to Vault now."
