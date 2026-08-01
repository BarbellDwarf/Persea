# contrib/

Utility scripts and Docker images for rustguac.

## Scripts

- `setup-rdp-performance.ps1` — PowerShell script to optimize Windows RDP performance settings (disable wallpaper, animations, etc.)
- `setup-xrdp-audio.sh` — Configure PulseAudio for xrdp audio redirection
- `setup-xrdp-gfx.sh` — Enable GFX (H.264) acceleration for xrdp sessions
- `vault-quickstart.sh` — Bootstrap a local Vault dev server with AppRole auth for testing

## VDI Docker Images

- `vdi-test-image/` — Minimal Debian trixie image with xrdp + xfce4 for testing VDI sessions
- `vdi-image-pulseaudio/` — VDI base image with PulseAudio support
- `vdi-image-pulseaudio-x264/` — VDI base image with PulseAudio + H.264 GPU acceleration
