#!/usr/bin/env bash
#
# Test that a browser session renders content (not a black screen).
# Starts Xvnc + Chromium with isolated profile, screenshots the display,
# checks for non-black pixels.
#
# Usage: ./tests/test_browser_session.sh [URL]
#   Default URL: https://www.google.com

set -euo pipefail

URL="${1:-https://www.google.com}"
DISPLAY_NUM=199
VNC_PORT=$((5900 + DISPLAY_NUM))
WIDTH=1920
HEIGHT=1080
SCREENSHOT="/tmp/browser_test_screenshot.png"
XVNC_PID=""
CHROMIUM_PID=""
PROFILE_DIR=""

cleanup() {
    echo "--- Cleanup ---"
    [ -n "$CHROMIUM_PID" ] && kill "$CHROMIUM_PID" 2>/dev/null && echo "Killed Chromium ($CHROMIUM_PID)" || true
    [ -n "$XVNC_PID" ] && kill "$XVNC_PID" 2>/dev/null && echo "Killed Xvnc ($XVNC_PID)" || true
    [ -n "$CHROMIUM_PID" ] && wait "$CHROMIUM_PID" 2>/dev/null || true
    [ -n "$XVNC_PID" ] && wait "$XVNC_PID" 2>/dev/null || true
    [ -n "$PROFILE_DIR" ] && rm -rf "$PROFILE_DIR" && echo "Cleaned up profile dir" || true
    rm -f "/tmp/.X${DISPLAY_NUM}-lock" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Browser Session Rendering Test ==="
echo "URL:     $URL"
echo "Display: :${DISPLAY_NUM}"
echo "VNC:     localhost:${VNC_PORT}"
echo "Size:    ${WIDTH}x${HEIGHT}"
echo ""

# --- Step 1: Start Xvnc ---
echo "--- Step 1: Starting Xvnc ---"
rm -f "/tmp/.X${DISPLAY_NUM}-lock" 2>/dev/null || true

Xvnc ":${DISPLAY_NUM}" \
    -geometry "${WIDTH}x${HEIGHT}" \
    -depth 24 \
    -SecurityTypes None \
    -localhost \
    -AlwaysShared \
    >/dev/null 2>/tmp/xvnc_test_stderr.log &
XVNC_PID=$!
echo "Xvnc PID: $XVNC_PID"

echo "Waiting for VNC port ${VNC_PORT}..."
for i in $(seq 1 40); do
    if ss -tln | grep -q ":${VNC_PORT} "; then
        echo "VNC port ready after ~$((i * 50))ms"
        break
    fi
    sleep 0.05
done

if ! ss -tln | grep -q ":${VNC_PORT} "; then
    echo "FAIL: Xvnc never started listening on port ${VNC_PORT}"
    echo "Xvnc stderr:"
    cat /tmp/xvnc_test_stderr.log 2>/dev/null
    exit 1
fi

# --- Step 2: Verify X display ---
echo ""
echo "--- Step 2: Verify X display ---"
export DISPLAY=":${DISPLAY_NUM}"
xdpyinfo 2>/dev/null | head -3 || true
echo ""

# --- Step 3: Baseline screenshot ---
echo "--- Step 3: Baseline screenshot (before Chromium) ---"
xwd -root -silent -out /tmp/test_baseline.xwd
convert /tmp/test_baseline.xwd /tmp/test_baseline.png
BASELINE_MEAN=$(convert /tmp/test_baseline.png -colorspace Gray -format "%[fx:mean*255]" info:)
echo "Baseline mean pixel value: $BASELINE_MEAN"
rm -f /tmp/test_baseline.xwd /tmp/test_baseline.png

# --- Step 4: Start Chromium with isolated profile ---
echo ""
echo "--- Step 4: Starting Chromium ---"
PROFILE_DIR=$(mktemp -d /tmp/persea-test-profile-XXXXXX)
echo "Profile dir: $PROFILE_DIR"

chromium \
    --kiosk \
    --no-first-run \
    --noerrdialogs \
    --disable-infobars \
    --disable-translate \
    "--disable-features=TranslateUI,VizDisplayCompositor" \
    --no-sandbox \
    --disable-gpu \
    --disable-gpu-sandbox \
    --disable-gpu-compositing \
    --disable-software-rasterizer \
    --disable-dev-shm-usage \
    --use-gl=angle \
    --use-angle=swiftshader \
    --in-process-gpu \
    --disable-background-networking \
    --disable-sync \
    --disable-breakpad \
    --disable-crash-reporter \
    --no-default-browser-check \
    --window-position=0,0 \
    "--window-size=${WIDTH},${HEIGHT}" \
    "--user-data-dir=${PROFILE_DIR}" \
    "$URL" \
    >/dev/null 2>/tmp/chromium_test_stderr.log &
CHROMIUM_PID=$!
echo "Chromium PID: $CHROMIUM_PID"

# --- Step 5: Wait for rendering and screenshot ---
echo ""
echo "--- Step 5: Waiting for page to render ---"

for WAIT in 2 3 5; do
    echo "Waiting ${WAIT}s..."
    sleep "$WAIT"

    if ! kill -0 "$CHROMIUM_PID" 2>/dev/null; then
        echo "FAIL: Chromium exited prematurely"
        echo ""
        echo "Chromium stderr:"
        cat /tmp/chromium_test_stderr.log 2>/dev/null || true
        exit 1
    fi

    xwd -root -silent -out /tmp/test_chrome.xwd
    convert /tmp/test_chrome.xwd "$SCREENSHOT"
    rm -f /tmp/test_chrome.xwd

    MEAN=$(convert "$SCREENSHOT" -colorspace Gray -format "%[fx:mean*255]" info:)
    echo "Mean pixel value: $MEAN (baseline was $BASELINE_MEAN)"

    if awk "BEGIN { exit ($MEAN > 10.0) ? 0 : 1 }"; then
        echo ""
        echo "PASS: Screen has content (mean pixel value $MEAN > 10)"
        echo "Screenshot saved to: $SCREENSHOT"
        echo ""
        echo "--- X Window list ---"
        xwininfo -root -tree 2>/dev/null | grep -E '^\s+0x' | head -10 || true
        exit 0
    fi
done

echo ""
echo "FAIL: Screen appears to be black/empty after 10s"
echo "Screenshot saved to: $SCREENSHOT"
echo ""
echo "--- Diagnostics ---"
echo ""
echo "X Window tree:"
xwininfo -root -tree 2>/dev/null | head -40 || true
echo ""
echo "Xvnc stderr:"
tail -20 /tmp/xvnc_test_stderr.log 2>/dev/null || true
echo ""
echo "Chromium stderr (last 20 lines):"
tail -20 /tmp/chromium_test_stderr.log 2>/dev/null || true
echo ""
echo "Xvnc process:"
ps -p "$XVNC_PID" -o pid,cmd 2>/dev/null || echo "(not running)"
echo ""
echo "Chromium process:"
ps -p "$CHROMIUM_PID" -o pid,cmd 2>/dev/null || echo "(not running)"

exit 1
