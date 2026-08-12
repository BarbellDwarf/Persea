# VDI Desktop Containers

> **Audience:** admins enabling VDI sessions (Docker desktop containers per user).
> **Next:** [Configuration](configuration.md#vdi-section) for the `[vdi]` section, or [Installation](installation.md) to set up Docker.

VDI (Virtual Desktop Infrastructure) gives each user their **own Linux desktop running in a Docker container**, streamed to their browser over RDP. persea creates the container on demand, connects guacd to it, and the user gets a full desktop — no client software installed, nothing running on their machine.

Use it when users need a real desktop environment (file manager, graphical apps, multiple windows) rather than a single application streamed by a web session.

## How it works

1. An admin creates a VDI entry in the connections, specifying a Docker image
2. When a user clicks Connect, persea creates a Docker container from that image
3. The container runs **xrdp** (the Linux Remote Desktop server) on port 3389; guacd connects to it via RDP
4. The user sees a full Linux desktop in their browser
5. On disconnect (tab close, network drop), the container **keeps running** so the user can reconnect
6. On logout from the desktop, the container is stopped and removed
7. Idle containers (no active session) are cleaned up automatically after a configurable timeout

## Prerequisites

- **Docker** on the same machine as persea. The `persea` system user must be able to manage containers:

  ```bash
  # Install Docker (if not already installed)
  curl -fsSL https://get.docker.com | sh

  # Allow the persea user to manage containers
  sudo usermod -aG docker persea
  sudo systemctl restart persea
  ```

- **At least one Docker image with xrdp** pre-pulled on the host. persea never pulls images automatically — the image must already exist locally (see [Docker image requirements](#docker-image-requirements)).

## Configuration

Add a `[vdi]` section to your config file:

```toml
[vdi]
enabled = true
# docker_socket = "/var/run/docker.sock"      # default
# default_cpu_limit = 2.0                     # cores, 0 = no limit
# default_memory_limit = 2048                 # MB, 0 = no limit
# ready_timeout_secs = 30                     # how long to wait for xrdp to start
# port_range_start = 39000                    # optional: restrict the localhost RDP port range
# port_range_end = 39999                      # (unset = Docker picks any free port)
# container_hook_script = "/opt/persea/vdi-container-hook.sh"
# container_hook_timeout_secs = 10
# idle_timeout_mins = 60                      # container lifetime after disconnect
# home_base = "/vdi-homes"                    # persistent home directories
# allowed_images = ["myregistry/desktop:latest"]   # whitelist, empty = allow all
```

VDI can also be toggled from **Admin → Settings** — the `enable_vdi` switch gates the feature (default: on). Sessions are refused while either the setting or `[vdi] enabled` is off.

## Docker image requirements

The image must run an xrdp server on port 3389. There are two ways to handle the user account:

### Pattern A: env-var driven (recommended)

The image's entrypoint reads `VDI_USERNAME` and `VDI_PASSWORD` from its environment, creates the account, and starts xrdp. This is the default flow:

- `VDI_USERNAME` derives from the operator's identity (everything before `@`, lowercased, non-alphanumeric characters replaced with `_`)
- `VDI_PASSWORD` is freshly generated per connect (32 random hex characters) — the user never sees it, because persea uses it for the RDP login automatically
- Container names are deterministic per operator — `persea-vdi-<username>` for ad-hoc sessions, `persea-vdi-<username>-<entry>` when connecting via a connections entry — so reconnects reuse the same container
- xrdp is configured with TLS certificates

A minimal example image lives at `contrib/vdi-test-image/` (Debian + xfce4).

### Pattern B: baked-in account

If your image has a hardcoded user account that ignores `VDI_USERNAME` / `VDI_PASSWORD`, set `container_username` and `container_password` on the entry. persea uses those values for the RDP login into the container.

`VDI_USERNAME` / `VDI_PASSWORD` are still injected with the override values, so an image that also happens to read them gets consistent state. Images that ignore the env vars simply keep using their baked-in account.

**Caution:** the container name is derived from the resolved username. With a fixed `container_username`, every operator connecting via that entry shares **one** container instance. Confirm that is what you want before using Pattern B at scale.

Both `container_username` and `container_password` support [credential variables](credential-variables.md), so the values can come from each operator's saved credentials rather than being stored in the entry.

### Example entrypoint

```bash
#!/bin/bash
set -e
USERNAME="${VDI_USERNAME:-user}"
PASSWORD="${VDI_PASSWORD:-password}"

if ! id "$USERNAME" &>/dev/null; then
    useradd -m -s /bin/bash "$USERNAME"
fi
echo "$USERNAME:$PASSWORD" | chpasswd
echo "xfce4-session" > /home/"$USERNAME"/.xsession
chown "$USERNAME":"$USERNAME" /home/"$USERNAME"/.xsession

# Configure TLS for xrdp
sed -i \
    -e 's|^certificate=.*|certificate=/etc/ssl/certs/ssl-cert-snakeoil.pem|' \
    -e 's|^key_file=.*|key_file=/etc/ssl/private/ssl-cert-snakeoil.key|' \
    /etc/xrdp/xrdp.ini

mkdir -p /run/dbus
dbus-daemon --system --fork 2>/dev/null || true
xrdp-sesman --nodaemon &
exec xrdp --nodaemon
```

## Connections setup

1. Create a folder in the connections (or use an existing one)
2. Add a new entry with type **VDI (Docker)**
3. Set the **Container Image** (e.g. `persea-vdi-test:latest`)
4. Optionally set per-entry overrides — CPU limit, memory limit, environment variables, idle timeout — as entry fields (`container_cpu_limit`, `container_memory_limit`, `container_env`, `container_idle_timeout_mins`). These are part of the entry schema/API; the Connections UI currently exposes only the container image and container password, so set the rest via the address-book API if needed
5. For Pattern B images, set `container_username` / `container_password` to match the baked-in account (the UI exposes the password; the username is set via the entry API). Otherwise leave them blank and the image's entrypoint provisions the account from `VDI_USERNAME` / `VDI_PASSWORD`
6. Click Save

Users in the folder's allowed groups can now click Connect to get a desktop.

## Container lifecycle

| Event | What happens |
|-------|-------------|
| User clicks Connect | Container created (or reused if already running) |
| User closes browser tab | Container keeps running |
| Network drops | Container keeps running (reconnect when back online) |
| User logs out of desktop | Container stopped and removed |
| Idle timeout expires | Container stopped and removed by a background reaper |
| Admin terminates session | Session ends, container keeps running |

## Persistent home directories

Set `home_base` to give users persistent storage — files survive container restarts:

```toml
[vdi]
home_base = "/vdi-homes"
```

Each user gets `{home_base}/{username}` mounted as `/home/{username}` inside the container. The directory is created automatically on first use.

In the Docker image, the `vdi-homes` volume is mounted at `/opt/persea/vdi-homes` — set `home_base` to that path there. On bare metal any writable directory works (e.g. `/vdi-homes`).

## Active Sessions

The connections page shows an **Active Sessions** section with thumbnail previews of running sessions (captured every 10 seconds). Click a thumbnail to reconnect. Dormant VDI containers (running but no active browser session) also appear with their last captured thumbnail.

## Container hook

Set `container_hook_script` when persea needs an external command to prepare or tear down access to a container's mapped RDP port — for example, to program a firewall rule so the localhost port is reachable. persea calls the script as:

```bash
/opt/persea/vdi-container-hook.sh up   <port> <container_id> <container_name>
/opt/persea/vdi-container-hook.sh down <port> <container_id> <container_name>
```

`up` runs after Docker has assigned the RDP port and before persea checks whether xrdp is ready on `127.0.0.1:<port>` — the script should return only once the local listener is available. `down` runs before persea stops and removes the container. Execution is limited by `container_hook_timeout_secs` (default: 10 seconds).

## Per-entry settings

Each VDI connections entry can override:

- **CPU limit** (cores) — overrides `default_cpu_limit`
- **Memory limit** (MB) — overrides `default_memory_limit`
- **Idle timeout** (minutes) — overrides `idle_timeout_mins`
- **Environment variables** — custom `KEY=VALUE` pairs passed to the container
- **Banner** — message shown before the session starts

## Resource notes

- Every active desktop is a running container: CPU, memory, and disk. Size the Docker host for the expected peak number of concurrent desktops, and use `default_cpu_limit` / `default_memory_limit` (and per-entry overrides) so one heavy desktop cannot starve the host.
- `idle_timeout_mins` (default 60) controls how long a disconnected container lingers. Lower it to reclaim resources faster; note that users lose unsaved work when an idle container is reaped.
- Images must be pre-pulled on the host — plan for image size and disk space.
- When `port_range_start`/`port_range_end` are set, Docker binds each container's RDP port inside that localhost range; when unset, Docker picks a random free port.

## Security notes

- Container images must be pre-pulled on the Docker host (no automatic pull)
- Use `allowed_images` to restrict which images can be used
- Containers run with default Docker isolation (no `--privileged`)
- Credentials are auto-generated per session (users never see the RDP password)
- The `persea` user needs Docker socket access but no other elevated permissions

## Troubleshooting

**"VDI ready timeout" / desktop never appears:**
- persea waits `ready_timeout_secs` (default 30) for xrdp to accept connections on the container's mapped port. Check the image actually starts xrdp (run it manually: `docker run --rm -it <image>` and verify `xrdp` is listening on 3389).
- The `persea` user must be in the `docker` group; check `docker ps` works as that user.

**"Image not allowed":**
- `allowed_images` is an exact-match whitelist. Either add the image or remove the restriction.

**Container starts but the screen stays black:**
- Check the container logs (`docker logs persea-vdi-<username>`) for xrdp or X session errors. A common failure is the X session not starting because the desktop environment is missing or `.xsession` is wrong.
- Verify the entry's `container_username`/`container_password` match the account the image actually created, if you're not using Pattern A.

**User's files are gone after a restart:**
- Home directories are ephemeral unless `home_base` is set. Enable it (see [Persistent home directories](#persistent-home-directories)) and check the mount path matches the image's layout.
