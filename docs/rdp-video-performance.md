# RDP Video Performance

> **Audience:** admins tuning RDP video quality (H.264 passthrough, GFX pipeline) for persea sessions.
> **Next:** [Deployment Guide](deployment-guide.md#step-4-prepare-rdp-targets) for the full RDP target setup, or [Configuration](configuration.md) for the entry-level RDP settings.

This guide explains what makes RDP sessions look good or run smoothly through persea, and what to change when they don't, aimed at video monitoring and media-heavy workloads, but the same settings govern ordinary desktop use.

## What affects RDP quality

Five things, roughly in order of impact:

1. **Network bandwidth and latency**: every frame of the remote desktop has to travel from the RDP server to your browser. On a slow link, quality must drop or the session stutters.
2. **The encoding path**: the two big choices are the **GFX pipeline** (the RDP Graphics Pipeline Extension, which enables modern codecs including H.264) and the **legacy GDI path** (which re-encodes screen updates as JPEG/WebP/PNG on the server). With H.264 passthrough, the RDP server's own H.264 stream goes straight to your browser: the highest quality per bit.
3. **Lossless vs lossy**: forcing lossless (PNG-only) preserves every pixel but consumes dramatically more bandwidth; lossy codecs (JPEG/WebP/H.264) trade a little fidelity for a lot of throughput.
4. **Resize behaviour**: persea resizes the remote desktop through the RDP Display Control channel rather than reconnecting (see [The mod-16 quirk](#the-mod-16-quirk)).
5. **Multi-monitor**: each extra monitor adds a separate stream; total bandwidth and server load scale with the combined desktop size.

## Per-entry settings

Four per-entry fields control RDP video behaviour (settable via the address-book entry API; the Connections UI does not currently expose them):

- **`enable_gfx`: Graphics Pipeline.** Activates the RDP Graphics Pipeline Extension (RDPGFX), which enables the RemoteFX codec and, on supporting servers, H.264. Recommended for video monitoring and media-heavy sessions. persea always negotiates 32-bit colour depth, which GFX requires.
- **`enable_desktop_composition`: Desktop Composition.** Enables Windows Desktop Window Manager (DWM) compositing in the remote session. Improves rendering of video overlays, transparency, and smooth scrolling. Increases bandwidth slightly.
- **`force_lossless`: Force Lossless.** Forces PNG-only encoding (no JPEG/WebP lossy compression). Better for text-heavy workloads where visual fidelity matters. Uses significantly more bandwidth: not recommended for video content.
- **`enable_h264`: H.264 Passthrough.** Lets guacd forward the server's raw H.264 (AVC420/AVC444) stream to the browser's WebCodecs decoder instead of decoding and re-encoding it (see [H.264 passthrough](#h264-passthrough-pipeline)). Default: on. Requires GFX and an H.264-capable server (e.g. xrdp rebuilt with x264, or Windows with AVC enabled).

## For slow connections

When sessions feel sluggish on a constrained link:

- **Make sure H.264 passthrough is on** (`enable_h264`, the default). It is the most bandwidth-efficient path: one encoding pass, sent straight to the browser.
- **If the server cannot do H.264**, the fallback is guacd's JPEG/WebP re-encode: keep `force_lossless` off (lossless PNG is the most expensive option by far).
- **Turn off Desktop Composition** unless the workload needs it: DWM increases bandwidth.
- **Use a smaller window size.** The desktop resolution is what must travel over the wire; a 1920×1080 session uses roughly four times the bandwidth of a 960×540 one. Remember the [mod-16 sizing rule](#the-mod-16-quirk) when picking dimensions.
- **Avoid multi-monitor sessions** on slow links: each monitor adds bandwidth.
- On the Windows server side, the `wan` profile in the xrdp tuning example below caps bitrate; the equivalent on Windows is a lower colour depth / resolution policy (see [Windows RDP server tuning](#windows-rdp-server-tuning)).

## For maximum quality

- **Video content:** GFX + Desktop Composition on, H.264 passthrough on (the default). The server must support H.264: on Linux that means xrdp rebuilt with x264 ([below](#linux-xrdp-tuning-debian-13)); on Windows, AVC 4:4:4 enabled ([below](#windows-rdp-server-tuning)).
- **Text-heavy content:** `force_lossless` on: PNG preserves crisp text at the cost of bandwidth. Best combined with a fast network.
- **Everything:** run the RDP server at 60 FPS and, on Windows, enable GPU hardware encoding where available (see below).

## The mod-16 quirk

The RDP graphics pipeline encodes H.264 video in **16×16 pixel blocks** (macroblocks). If the negotiated desktop size is not a multiple of 16 pixels, the RDP server pads the encoded frame with empty blocks, and the padding can bleed a **saturated green band along the bottom edge** of the picture (a chroma-sampling artifact, typically `~#008700`).

To prevent this, persea's guacd rounds every requested desktop size **down to a multiple of 16** before negotiating it with the server:

- **1080p (1920×1080) becomes 1920×1072**: 1080 is not divisible by 16
- **4K (3840×2160) stays 3840×2160**: both dimensions are divisible by 16
- Multi-monitor layouts are rounded per monitor and tiled left-to-right, top-aligned

**Workarounds:**

- The green band itself is prevented by the rounding: you should never see it.
- The visible cost is a slim unused margin (up to 15 pixels) at the bottom (or right) of the canvas. To eliminate it, pick a session size whose width and height are already multiples of 16: e.g. 1920×1056 or 1920×1088 instead of 1920×1080, 1600×1024, or 3840×2160.
- Resizes use the RDP Display Control channel (`resize-method: display-update`), so the desktop renegotiates its size live instead of reconnecting.

## Which browsers support the H.264 path

H.264 passthrough decodes video in the browser with the **WebCodecs API** (`VideoDecoder`):

- **Chrome / Edge 94+**: supported
- **Firefox 130+**: supported
- **Older browsers without WebCodecs**: the H.264 stream is discarded client-side; the session still renders, because guacd also runs the normal decode for frame sync (the "standard pipeline" below). You lose the bandwidth and quality benefits, but not the session.

## How it works

### Standard pipeline (non-H.264 servers)

1. **RDP server** sends screen updates (Planar/RemoteFX codec)
2. **FreeRDP** (inside guacd) decodes them to bitmaps
3. **guacd** re-encodes the changed regions as JPEG, WebP, or PNG depending on content and settings
4. **persea** relays the result over WebSocket to the browser
5. **Browser** decodes and renders to an HTML canvas

Note: guacd does not implement latency-based quality adaptation in this codebase: no such logic exists in the server or the bundled client, so JPEG/WebP quality is whatever guacd applies by default. (The JPEG Quality slider in the session toolbar is a UI control only and is not wired to the encoder.)

### H.264 passthrough pipeline (xrdp with x264, or Windows with AVC)

When the RDP server sends H.264 (AVC420/AVC444), guacd passes the raw H.264 data straight to the browser, bypassing the decode-and-re-encode cycle:

1. **RDP server** encodes the screen as H.264 (x264 on Linux, AVC on Windows)
2. **FreeRDP** (inside guacd) receives the H.264 SurfaceCommand
3. **guacd** copies the raw H.264 NAL data and also runs the normal GDI decode (for frame sync)
4. On frame flush, guacd sends the raw H.264 data as a custom `h264` instruction
5. **persea** relays it over WebSocket to the browser
6. **Browser** decodes it with the WebCodecs `VideoDecoder` (hardware-accelerated where available)

Benefits:

- **Lower server CPU**: no decode + re-encode cycle on the server
- **Lower latency**: one fewer encoding pass
- **Consistent quality**: a single lossy encoding pass (x264/AVC) instead of H.264 → bitmap → JPEG/WebP

H.264 passthrough is on by default (`enable_h264`) and becomes active when the RDP server sends AVC420/AVC444 data. Servers that don't support H.264 use the standard pipeline automatically.

## Windows RDP server tuning

For the best video experience, configure the Windows RDP server (2022+).

### Quick setup with script

A PowerShell script is provided in `contrib/`. Run on the **Windows RDP target server** as Administrator:

```powershell
# Standard setup (software encoding, AVC444, 60fps)
.\setup-rdp-performance.ps1

# With GPU hardware encoding (requires DirectX 11+ GPU)
.\setup-rdp-performance.ps1 -EnableGPU
```

This configures: AVC 4:4:4, 60 FPS, desktop composition, RemoteFX, audio, and network tuning. A reboot is recommended after.

### Manual setup

#### Enable AVC 4:4:4 (H.264 full-colour)

Group Policy: `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Remote Session Environment`

- **Prioritize H.264/AVC 444 Graphics mode for Remote Desktop Connections** → Enabled

Or via registry:
```
HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services
  AVC444ModePreferred = 1 (DWORD)
  AVCHardwareEncodePreferred = 1 (DWORD)
```

#### Enable 60 FPS

Windows RDP defaults to 30 FPS. To enable 60 FPS:
```
HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations
  DWMFRAMEINTERVAL = 15 (DWORD)
```

#### Enable GPU hardware encoding

Any DirectX 11+ GPU (NVIDIA, Intel iGPU, AMD) can offload H.264 encoding. Enable via the same Group Policy path:

- **Configure H.264/AVC hardware encoding for Remote Desktop connections** → Enabled
- **Use hardware graphics adapters for all Remote Desktop Services sessions** → Enabled

#### Verify settings

Check Windows Event Viewer at `Applications and Services Logs > Microsoft > Windows > RemoteDesktopServices-RdpCoreTS`:

- **Event ID 162**: AVC444 mode is active
- **Event ID 170**: Hardware encoding is active

## Linux xrdp tuning (Debian 13)

Debian 13 (trixie) ships xrdp 0.10.x, but the stock package does **not** include x264 H.264 encoding support. The `contrib/setup-xrdp-gfx.sh` script rebuilds xrdp from the Debian sid source package with `--enable-x264` and configures the GFX pipeline.

### Quick setup

A single setup script handles everything: desktop, audio, xrdp rebuild, and configuration. Run **on the xrdp target machine** (not the persea server):

```bash
wget -O setup-xrdp-gfx.sh https://raw.githubusercontent.com/persea-grove/persea/main/contrib/setup-xrdp-gfx.sh
sudo bash setup-xrdp-gfx.sh --desktop mate
```

Desktop options: `mate` (default, recommended), `xfce`, `kde`, `gnome`, `cinnamon`, `none`. MATE is lightweight and works reliably over xrdp without GPU.

The script runs in three phases:

1. **Phase 1 (pure trixie):** desktop + Firefox + Chromium, build tools, PulseAudio xrdp audio module, PipeWire→PulseAudio switch
2. **Phase 2 (temporary sid):** adds the sid repo, installs the matching xorgxrdp, rebuilds xrdp with `--enable-x264`, removes sid
3. **Phase 3 (configure):** Xorg backend, Xwrapper, startwm.sh, gfx.toml with H.264 + x264

After setup, use `bash setup-xrdp-gfx.sh --diagnose` to troubleshoot, or `--help` for all options.

### Manual setup

#### Prerequisites

```bash
# Add sid repo for newer xrdp source
echo "deb http://deb.debian.org/debian sid main" > /etc/apt/sources.list.d/sid.list

# Pin trixie as default (prevent accidental sid upgrades)
cat > /etc/apt/preferences.d/pin-trixie << 'EOF'
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: *
Pin: release a=unstable
Pin-Priority: 100
EOF

apt-get update

# Install xorgxrdp from sid (must match xrdp version)
apt-get install -y -t unstable xorgxrdp

# Install x264 and build dependencies
apt-get install -y libx264-dev build-essential devscripts
apt-get build-dep -y xrdp
```

#### Rebuild xrdp with x264

The stock Debian xrdp package is built without `--enable-x264`. Rebuild from sid source:

```bash
cd /tmp
apt-get source xrdp=<sid-version>
cd xrdp-*
sed -i "s|--enable-opus|--enable-opus --enable-x264|" debian/rules
sed -i "s|^ autoconf,| libx264-dev,\n autoconf,|" debian/control
dpkg-buildpackage -b -uc -us -j$(nproc)
dpkg -i ../xrdp_*.deb
```

Verify x264 is linked: `ldd /usr/sbin/xrdp | grep libx264`

#### GFX pipeline (video)

The GFX pipeline requires the Xorg backend, not Xvnc. Set in `/etc/xrdp/xrdp.ini`:

```ini
autorun=Xorg
```

Allow non-root Xorg in `/etc/X11/Xwrapper.config`:

```
allowed_users=anybody
```

Create `/etc/xrdp/gfx.toml`:

```toml
[codec]
order = ["H.264", "RFX"]
h264_encoder = "x264"

[x264.default]
preset = "ultrafast"
tune = "zerolatency"
profile = "main"
vbv_max_bitrate = 0
vbv_buffer_size = 0
fps_num = 60
fps_den = 1
threads = 1

[x264.lan]
# inherits default: uncapped bitrate, 60fps

[x264.wan]
vbv_max_bitrate = 15000
vbv_buffer_size = 1500

[x264.broadband_high]
preset = "superfast"
vbv_max_bitrate = 8000
vbv_buffer_size = 800
```

#### Audio redirection

Debian 13 does not package `pulseaudio-module-xrdp`: it must be built from source. The `contrib/setup-xrdp-audio.sh` script automates this, or manually:

```bash
# Install build deps
apt install git build-essential dpkg-dev libpulse-dev autoconf libtool m4

# Clone and build
git clone --depth 1 https://github.com/neutrinolabs/pulseaudio-module-xrdp.git
cd pulseaudio-module-xrdp
scripts/install_pulseaudio_sources_apt.sh
./bootstrap
./configure PULSE_DIR=/root/pulseaudio.src
make
sudo make install
```

This installs `module-xrdp-sink.so` and `module-xrdp-source.so` into the PulseAudio modules directory, plus an XDG autostart entry that loads them automatically when an RDP session starts.

**Verify audio in a session:**
```bash
pactl list sinks short
# Should show: xrdp-sink  module-xrdp-sink.c  s16le 2ch 44100Hz  RUNNING
```

#### NVIDIA GPU acceleration

If the xrdp server has an NVIDIA GPU with NVENC support, set in `/etc/xrdp/sesman.ini`:

```ini
XRDP_USE_ACCEL_ASSIST=1
```

#### Restart

```bash
sudo systemctl restart xrdp
```

## Network requirements

Estimated bandwidth per session at different quality levels:

| Resolution | FPS | Encoding | Bandwidth |
|-----------|-----|----------|-----------|
| 1080p | 30 | JPEG (default) | ~10 Mbps |
| 1080p | 30 | WebP | ~7 Mbps |
| 1080p | 60 | JPEG | ~18 Mbps |
| 4K | 30 | WebP | ~29 Mbps |

For video monitoring workloads, a minimum of 20 Mbps per session is recommended. Use GFX + Desktop Composition for the best results.
