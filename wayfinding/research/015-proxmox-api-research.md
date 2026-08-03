# Proxmox VE API Research — Expansion Beyond SPICE

Research for ticket 015-proxmox-expansion.md. All endpoints under base URL `https://{host}:8006/api2/json/`.

## 1. VNC Console

### Endpoint
```
POST /nodes/{node}/qemu/{vmid}/vncproxy
POST /nodes/{node}/lxc/{vmid}/vncproxy
```

### Auth
Same as SPICE: `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`. Requires `VM.Console` permission.

### Response
```json
{
  "data": {
    "ticket": "PVEVNC:xxxxxxxx==",
    "upid": "UPID:pve:...:vncproxy:100:root@pam:",
    "port": "5900",
    "user": "root@pam",
    "cert": "-----BEGIN CERTIFICATE-----\n..."
  }
}
```

### How VNC Auth Works
- `ticket` (format `PVEVNC:xxx`) is used as the VNC password
- `cert` is the node's TLS certificate (for TLS-encrypted VNC connections)
- `port` is the VNC proxy port on the PVE node
- The ticket is **single-use** and expires in ~40 seconds (per Proxmox staff: "the ticket for vnc has to be used within 40 seconds")

### Two Connection Methods

**Method A: Direct TCP VNC (recommended for guacd)**
After `vncproxy`, Proxmox opens a TCP port on the node for ~10 seconds. Connect a VNC client directly to `node:port` using the ticket as password. This is how noVNC works in Proxmox's own UI — it's NOT a WebSocket, it's a plain TCP VNC listener. guacd can speak VNC natively, so this is the simplest path.

```
TCP connect to node_ip:port → RFB handshake → use ticket as password
```

**Method B: WebSocket proxy (for browser clients)**
```
GET /nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={url_encoded_ticket}
```
This upgrades to WebSocket. The first message from client must be `{user}:{ticket}\n`, server responds with `OK`. Then binary VNC frames flow through. Useful if building a web-based VNC client, but **guacd doesn't need this** — it speaks raw VNC.

### Implementation for persea
guacd already speaks VNC. Flow:
1. `POST .../vncproxy` → get `port` + `ticket`
2. Tell guacd to connect to `node_ip:port` with password = ticket
3. guacd handles the VNC protocol
4. No Websockify needed

### Params
- `websocket` (optional, 0 or 1) — if 1, the port is WebSocket-ready instead of raw TCP
- `generate-password` (optional, 0 or 1) — if 1, generates a random password instead of using the ticket (avoids the 8-char VNC password limit)

---

## 2. Serial Terminal (termproxy)

### Endpoint
```
POST /nodes/{node}/qemu/{vmid}/termproxy
POST /nodes/{node}/lxc/{vmid}/termproxy
POST /nodes/{node}/termproxy  (node shell)
```

### Response
```json
{
  "data": {
    "ticket": "PVEVNC:xxxxxxxx==",
    "upid": "UPID:pve:...:vncproxy:100:root@pam:",
    "port": "5901",
    "user": "root@pam"
  }
}
```

### How It Works
- `termproxy` spawns a process on the host (e.g. `qm terminal` for QEMU, `lxc-console` for LXC)
- Returns a VNC-format ticket + port — the serial console is exposed over the VNC protocol
- The same `vncwebsocket` endpoint can be used to connect, OR direct TCP to the port
- For QEMU: connects to the VM's serial console (`serial0` by default)
- For LXC: connects to `lxc-console`
- For nodes: connects to a host shell

### WebSocket Connection
```
GET /nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={ticket}
```
- Connect via WebSocket to the PVE host on port 8006 with the path above
- First message: `{user}:{ticket}\n` → expect `OK` response
- Then binary messages: `0:{len}:{data}` for sending, receive raw terminal output
- Keepalive: send `2` (binary) every 30s
- Resize: send `1:{height}:{width}:\n`

### xterm.js Protocol (binary VNC encoding over WebSocket)
The WebSocket transport uses a custom binary framing:
- **Login**: send `{user}:{ticket}\n` as first message
- **Data out**: `0:{length}:{data}` — binary message with length prefix
- **Data in**: raw terminal output (binary)
- **Resize**: `1:{height}:{width}:\n`
- **Ping**: `2` (single byte)

### API Token Limitation
⚠️ `vncshell` (node shell) does **NOT** work with API tokens — requires session cookie auth. `termproxy` on QEMU/LXC **does** work with API tokens. Per Proxmox staff: "You cannot use an API token to connect to [vncshell]. The API token needs VM.Console permissions for the VM for the vncproxy and termproxy API endpoints."

---

## 3. xterm.js Console (xtermjs)

### Endpoint
```
POST /nodes/{node}/qemu/{vmid}/xtermjs
POST /nodes/{node}/lxc/{vmid}/xtermjs
POST /nodes/{node}/xtermjs  (node shell)
```

### How It Works
- Returns a `ticket` + `port` just like `termproxy`
- The endpoint is essentially a wrapper around `termproxy` that sets up the xterm.js-compatible WebSocket transport
- The WebSocket connection flow is identical to termproxy: connect via WebSocket, send `{user}:{ticket}\n`, then use the `0:{len}:{data}` framing
- Per the forum discussion on "How to tell /vncwebsocket to reply in text mode": the `termproxy` ticket passed to `vncwebsocket` gives you a binary VNC stream. To get text-mode (xterm.js), you need to use the `xtermjs` endpoint specifically, which sets up the text-based transport

### Practical Difference from termproxy
Both `termproxy` and `xtermjs` expose a serial console. The difference is in how the WebSocket transport frames the data. `xtermjs` is designed for direct xterm.js integration. For persea, either works since we bridge to guacd.

---

## 4. LXC Container Support

### Available Endpoints (identical to QEMU)
```
POST /nodes/{node}/lxc/{vmid}/spiceproxy   (SPICE — but LXC doesn't have SPICE)
POST /nodes/{node}/lxc/{vmid}/vncproxy     (VNC)
POST /nodes/{node}/lxc/{vmid}/termproxy    (serial console)
POST /nodes/{node}/lxc/{vmid}/xtermjs      (xterm.js)
GET  /nodes/{node}/lxc/{vmid}/vncwebsocket (WebSocket transport)
```

### LXC Console Options
- **VNC proxy**: Works, same as QEMU. Exposes the container's console over VNC.
- **Serial terminal**: For LXC, `termproxy` runs `lxc-console` under the hood
- **xterm.js**: Same as QEMU path
- **SPICE**: LXC does NOT support SPICE (SPICE requires QEMU/KVM)

### LXC Lifecycle
```
POST /nodes/{node}/lxc/{vmid}/status/start
POST /nodes/{node}/lxc/{vmid}/status/stop
POST /nodes/{node}/lxc/{vmid}/status/shutdown
POST /nodes/{node}/lxc/{vmid}/status/suspend
GET  /nodes/{node}/lxc/{vmid}/status/current
```

---

## 5. VM Lifecycle (Power Management)

### Endpoints (same for qemu and lxc)
```
POST /nodes/{node}/qemu/{vmid}/status/start
POST /nodes/{node}/qemu/{vmid}/status/stop
POST /nodes/{node}/qemu/{vmid}/status/shutdown
POST /nodes/{node}/qemu/{vmid}/status/suspend
POST /nodes/{node}/qemu/{vmid}/status/resume
POST /nodes/{node}/qemu/{vmid}/status/reboot
GET  /nodes/{node}/qemu/{vmid}/status/current
```

### Auth
Requires `VM.PowerMgmt` permission.

### Response
Returns a UPID (task ID) on success:
```json
{ "data": "UPID:pve:00002F9D:000DC5EA:57500527:start:100:root@pam:" }
```

### Task Polling
Long-running operations return a UPID. Poll status:
```
GET /nodes/{node}/tasks/{upid}/status
```
Response includes `status` ("running" | "stopped") and `exitstatus` ("ok" | error message).

### Differences
- `shutdown` = ACPI shutdown (graceful, guest OS decides)
- `stop` = hard stop (like pulling the plug)
- `suspend` = save state to disk (RAM preserved)
- `reboot` = ACPI reboot

---

## 6. VM/Container Inventory

### Cluster-Wide Listing
```
GET /cluster/resources?type=vm
```

Returns all VMs and containers across the cluster:
```json
[
  {
    "cpu": 0.02,
    "disk": 27950000000,
    "id": "qemu/100",
    "maxcpu": 4,
    "maxdisk": 48910000000,
    "maxmem": 8589934592,
    "mem": 1710000000,
    "name": "web-server",
    "node": "pve01",
    "status": "running",
    "type": "qemu",
    "uptime": 1234567,
    "vmid": 100
  },
  {
    "id": "lxc/200",
    "name": "dns-container",
    "node": "pve01",
    "status": "running",
    "type": "lxc",
    "vmid": 200
  }
]
```

### Per-Node Listing
```
GET /nodes/{node}/qemu          (QEMU VMs on a specific node)
GET /nodes/{node}/lxc           (LXC containers on a specific node)
GET /nodes/{node}/status        (node health: CPU, memory, uptime)
```

### Node Discovery (already implemented)
```
GET /cluster/resources?type=vm
```
`PveBroker::resolve_node()` already uses this to find which node hosts a VM.

---

## 7. Connection Type Selection Strategy

### Options

**A. User-Chooseable (recommended)**
Let user select from available console types in the UI. Proxmox itself shows this in the web UI as a dropdown: "Console" → noVNC / SPICE / Serial / xterm.js.

**B. Auto-Detect by Resource Type**
- QEMU VMs: SPICE (best), VNC, serial, xterm.js all available
- LXC containers: VNC, serial, xterm.js available (NO SPICE)
- Node shells: serial, xterm.js only (no VNC, no SPICE)

**C. Priority Fallback**
1. SPICE (if QEMU)
2. VNC (if QEMU or LXC)
3. xterm.js (always available)
4. Serial (always available)

### Recommendation
Implement **user-chooseable with auto-fallback**:
- For QEMU: show SPICE, VNC, xterm.js as options
- For LXC: show VNC, xterm.js as options (hide SPICE)
- Default to VNC for QEMU (guacd speaks VNC natively), xterm.js for LXC

---

## 8. Implementation Plan for persea

### Phase 1: VNC Console (highest value)
1. Add `fetch_vnc_config()` to `PveBroker` — mirrors `fetch_spice_config()` pattern
2. Response struct: `PveVncConfig { port, ticket, cert, user }`
3. In `SessionManager::create_session`, add `Vnc` variant alongside `Spice`
4. For VNC: tell guacd to connect to `node_ip:port` with password = ticket
5. No Websockify needed — guacd speaks raw VNC

### Phase 2: Serial/xterm.js
1. Add `fetch_term_config()` and `fetch_xterm_config()` to `PveBroker`
2. These return ticket + port, same VNC-format transport
3. Implement the WebSocket binary framing (`0:{len}:{data}`, `1:{h}:{w}:`, keepalive `2`)
4. Bridge the WebSocket to a shell session (not guacd — this is a raw terminal)

### Phase 3: LXC Support
1. Change endpoint paths from `qemu` to `lxc` based on resource type
2. `cluster/resources?type=vm` already returns `type: "qemu" | "lxc"` — use this to select the right path
3. LXC has no SPICE, so hide that option

### Phase 4: VM Lifecycle
1. Add `start_vm()`, `stop_vm()`, `shutdown_vm()` methods to `PveBroker`
2. Add power management buttons to the connections UI
3. Poll task status with `GET /nodes/{node}/tasks/{upid}/status`

### Phase 5: Inventory
1. `cluster/resources?type=vm` returns everything — add a UI endpoint
2. Show VM list with name, node, status, CPU, memory, disk
3. Group by node or pool

---

## Key Gotchas

1. **VNC tickets expire in ~40 seconds** — must connect immediately after obtaining
2. **VNC password limit is 8 characters** — use `generate-password=1` param to bypass
3. **API tokens don't work for node shell** (`vncshell`) — only for VM console endpoints
4. **vncwebsocket is NOT a WebSocket upgrade** — it's a misleading name; after `vncproxy`, the port is a raw TCP VNC listener (unless `websocket=1` param is used)
5. **LXC has no SPICE** — must use VNC or serial/xterm.js
6. **Task UPIDs** — lifecycle operations return task IDs that must be polled for completion
7. **Self-signed certs** — PVE ships self-signed by default; `verify_tls` config option (already exists in `PveBroker`) controls this
