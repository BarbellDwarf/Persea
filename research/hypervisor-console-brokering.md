# Hypervisor Console Brokering Research

## 1. Proxmox VE API

### Console Endpoints (QEMU VMs)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/nodes/{node}/qemu/{vmid}/spiceproxy` | POST | Returns SPICE connection config (host, proxy, tls-port, ticket, ca, host-subject) |
| `/nodes/{node}/qemu/{vmid}/vncproxy` | POST | Creates TCP VNC proxy connection (returns port, ticket, cert) |
| `/nodes/{node}/qemu/{vmid}/vncwebsocket` | GET | Opens websocket for VNC traffic (port 5900-5999) |
| `/nodes/{node}/qemu/{vmid}/termproxy` | POST | Serial terminal/console proxy (serial0-3) |
| `/nodes/{node}/qemu/{vmid}/xtermjs` | POST | xterm.js shell console |

All console endpoints require `VM.Console` permission and return one-time tickets.

### Console Endpoints (LXC Containers)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/nodes/{node}/lxc/{vmid}/vncproxy` | POST | VNC proxy with width/height params |
| `/nodes/{node}/lxc/{vmid}/vncwebsocket` | GET | Websocket for VNC traffic |
| `/nodes/{node}/lxc/{vmid}/termproxy` | POST | Terminal proxy |
| `/nodes/{node}/lxc/{vmid}/spiceproxy` | POST | SPICE proxy for container |

### Node-level Console

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/nodes/{node}/vncshell` | POST | Opens VNC shell on the node itself |
| `/nodes/{node}/vncwebsocket` | GET | Websocket for node VNC |
| `/nodes/{node}/spiceshell` | POST | SPICE shell on the node |

### VM/Container Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/cluster/resources` | GET | List all VMs/containers across cluster (type=vm) |
| `/nodes/{node}/qemu` | GET | List QEMU VMs on a node |
| `/nodes/{node}/qemu/{vmid}/status/current` | GET | Get VM power status |
| `/nodes/{node}/qemu/{vmid}/status/start` | POST | Start VM |
| `/nodes/{node}/qemu/{vmid}/status/stop` | POST | Stop VM |
| `/nodes/{node}/qemu/{vmid}/status/suspend` | POST | Suspend VM |
| `/nodes/{node}/qemu/{vmid}/status/shutdown` | POST | Shutdown VM |
| `/nodes/{node}/lxc` | GET | List LXC containers |
| `/nodes/{node}/lxc/{vmid}/status/*` | POST | Container lifecycle |

### Authentication

**API Tokens (preferred for automation):**
```
Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET
```
- Token IDs are scoped: `/<path>/[<subpath>]` controls permissions
- Can be per-VM, per-node, or cluster-wide
- No session expiry — tokens persist until revoked

**Other methods:**
- PAM (system accounts)
- LDAP/AD integration via `/access/domains`
- Two-factor auth (TOTP, YubiKey)
- OpenID Connect (v8.0+)

### noVNC Proxy Architecture

Proxmox's noVNC proxy works in two phases:
1. `POST /nodes/{node}/qemu/{vmid}/vncproxy` → returns `{port, ticket, cert}`
2. Client connects via websocket to `wss://pve-host:8006/api2/json/nodes/{node}/qemu/{vmid}/vncwebsocket?port={port}&vncticket={ticket}`
3. PVE proxies VNC traffic over the websocket, authenticating with the ticket

### SPICE Proxy Architecture

1. `POST /nodes/{node}/qemu/{vmid}/spiceproxy` → returns connection block:
   - `host`: opaque routing token (e.g. `pvespiceproxy:...`)
   - `proxy`: HTTP URL of the SPICE proxy (e.g. `http://node:3128`)
   - `tls-port`: TLS port on the proxy (61000+)
   - `password`: one-time ticket (~30s expiry)
   - `ca`: cluster CA certificate (PEM)
   - `host-subject`: expected TLS subject
2. SPICE client connects through the proxy using TLS+ticket auth

---

## 2. VMware vSphere/ESXi

### APIs

**SOAP API (vSphere Web Services SDK):**
- Primary programmatic interface since vSphere 1.0
- Endpoint: `https://{vcenter}/sdk/vimService.wsdl`
- SOAP-based, complex but comprehensive
- Covers: VM lifecycle, inventory, networking, storage, console access
- Managed Object Reference (MOB) browser: `https://{vcenter}/mob/`

**REST API (vSphere Automation SDK):**
- Introduced in vSphere 6.5
- Base: `https://{vcenter}/rest/`
- Endpoints: `/rest/vcenter/vm`, `/rest/vcenter/datacenter`, etc.
- JSON-based, simpler for CRUD operations
- **Does NOT support console access** — REST API is for management only

**VMRC (VMware Remote Console):**
- Proprietary binary client from VMware
- Not web-based — requires local installation
- Protocol: VMware's MKS (Mouse/Keyboard/Screen) protocol
- Can be launched from vCenter: `vmrc://clone?vmid={vm-path}`
- Has a `VMRemoteConsoleSDK` but it's part of the SOAP API, not independently accessible

### Console Access in vSphere

**The fundamental problem:** VMware's console access is deeply proprietary.

| Method | Protocol | Web Accessible | Programmable |
|--------|----------|---------------|--------------|
| vSphere Client (HTML5) | WebSocket (DKS) | Yes | No — uses internal DKS protocol |
| VMRC | VMware MKS | No (native client) | Limited (VMRC SDK) |
| VNC | RFB | Yes (if enabled) | Yes |
| Serial console | Telnet/SSH | No | Via API |

**HTML5 Client Console:**
- The vSphere Client web console uses WebSocket-based display (Direct Kit/Display)
- Protocol is undocumented and changes between versions
- Not suitable for third-party brokering

**VNC on ESXi:**
- ESXi does NOT natively expose VNC for VMs by default
- Requires enabling VNC in VM config: `vga.vnc = "true"` + `vnc.ip = "0.0.0.0"` + `vnc.port = "5900"`
- VNC is not enabled by default in new VMs
- Once enabled, guacamole can connect directly (no intermediary needed)
- VNC is disabled when VM is migrated between hosts

**MKSRD (MKS Remote Display):**
- VMware's internal protocol used by vSphere Client console
- WebSocket-based, proprietary binary framing
- No public documentation or SDK for third-party use

### Authentication

| Method | Description |
|--------|-------------|
| SSO (Single Sign-On) | VMware's token-based auth via STS (Security Token Service) |
| LDAP/AD | vCenter integrates with Active Directory |
| Certificate-based | vCenter certificates for API auth |
| Session tickets | Obtained via `SessionManager.Login` SOAP call |

**Session management pattern:**
1. Call `SessionManager.Login` with username/password → returns session ticket
2. Pass ticket in `vmware-session-id` header for REST or SOAP header
3. Sessions expire after configurable timeout (default ~30 min)

### VM Lifecycle (SOAP API)

| Operation | Managed Object | Method |
|-----------|---------------|--------|
| List VMs | `Folder` | `CreateContainerView` + `PropertyCollector` |
| Get status | `VirtualMachine` | `Runtime.powerState` property |
| Power on | `VirtualMachine` | `PowerOnVM_Task()` |
| Power off | `VirtualMachine` | `PowerOffVM_Task()` |
| Suspend | `VirtualMachine` | `SuspendVM_Task()` |
| Reset | `VirtualMachine` | `ResetVM_Task()` |
| Console ticket | `VirtualMachine` | `AcquireMksTicket()` or `AcquireTicket()` |

### AcquireTicket API (vSphere 6.7+)

VMware added `VirtualMachine.AcquireTicket()` in vSphere 6.7:
```
ticket = vm.AcquireTicket(ticketType="webmks")
```
Returns: `{host, port, ticket, sslThumbprint}`

**webmks** ticket type is for the HTML5 console WebSocket — but the protocol is proprietary and not documented.

### VMware Horizon

VMware Horizon is a separate product for VDI brokering:
- Protocol: PCoIP (Teradici) or Blast Extreme
- Has its own REST API for session management
- Can launch remote desktops/apps via `https://{connection-server}/portal/...`
- Does NOT integrate with vSphere API for console access
- Horizon manages its own desktop pools and session brokering
- **Not relevant for hypervisor-level console brokering** — it's application-level VDI

---

## 3. Comparison: What persea Already Does for Proxmox

### Current Implementation (`src/pve.rs`)

persea has a **SPICE-only** Proxmox integration:

**What works:**
- `PveBroker` struct holds PVE API URL + API token
- `resolve_node(vmid)` — calls `/cluster/resources?type=vm` to find which node hosts a VM
- `fetch_spice_config(node, vmid, proxy)` — calls `/nodes/{node}/qemu/{vmid}/spiceproxy`
- Returns `PveSpiceConfig` with host, proxy, tls_port, ticket, ca_cert, host_subject
- SPICE session via guacd (guacd connects to the SPICE proxy, TLS + ticket auth)
- SSH tunnel support: PVE API and SPICE proxy can be tunneled through bastion hosts

**What's NOT implemented:**
- VNC console mode (PVE has `vncproxy` + `vncwebsocket`)
- Serial/xterm.js console mode
- VM lifecycle management (start/stop/suspend)
- VM listing/inventory (only vmid→node resolution exists)
- LXC container support (PVE API has LXC endpoints)
- No `PveSessionType` enum — always SPICE

### Comparison with VMware Integration

| Feature | Proxmox (current) | VMware (proposed) |
|---------|-------------------|-------------------|
| Console protocol | SPICE (via guacd) | VNC (if enabled) or MKS (no guacd support) |
| API type | REST/JSON | SOAP + REST |
| Auth | API tokens | SSO/LDAP/session tickets |
| Ticket mechanism | spiceproxy → ticket+TLS | AcquireTicket → webmks (proprietary) |
| VM listing | `/cluster/resources` | `Folder.CreateContainerView` |
| Lifecycle | `/status/start|stop` | `PowerOnVM_Task()` |
| Tunneling | SPICE proxy tunneled via SSH | VNC direct (no proxy needed) |

### Key Insight

**VMware console brokering is fundamentally harder than Proxmox:**

1. **No guacd protocol for VMware's native console.** guacd supports SSH/RDP/VNC/SPICE/Kubernetes — not VMware MKS/WebSocket. VMware's HTML5 console uses a proprietary WebSocket protocol.

2. **VNC is the only viable path**, but:
   - VNC must be manually enabled on each VM (not default)
   - VNC is disabled on vMotion/live migration
   - No TLS/auth by default (must configure manually)

3. **REST API can't do console access** — only SOAP API can call `AcquireTicket()` or `AcquireMksTicket()`.

---

## 4. Other Hypervisors

### Xen/XCP-ng
- XAPI (XML-RPC) API
- Has VNC console proxy built-in
- `xe vm-console` command available
- Can enable VNC per-VM
- Good candidate: REST wrapper exists

### oVirt (Red Hat)
- REST API (Java-based)
- Has console proxy (noVNC + SPICE)
- `GET /api/vms/{id}/graphicsconsole` — returns console ticket
- Similar pattern to Proxmox: one-time tickets
- Good candidate for integration

### Nutanix AHV
- REST API (Prism)
- Console via noVNC or PCoIP (with Citrix integration)
- Limited console API — mostly management
- Less viable for brokering

---

## 5. Apache Guacamole Hypervisor Support

### What Guacamole Actually Supports

Guacamole protocols (in `guacamole-server/src/protocols/`):
- **SSH** (libssh)
- **RDP** (FreeRDP)
- **VNC** (libvncclient)
- **Telnet**
- **Kubernetes** (exec/attach)
- **SPICE** (via guacamole-proxy-spice, not in mainline)

**Guacamole does NOT integrate with any hypervisor directly.** It connects to:
- SSH servers
- RDP servers
- VNC servers
- Telnet servers
- Kubernetes API servers

The `guacamole-server` repo confirms: protocols are `rdp`, `ssh`, `vnc`, `telnet`, `kubernetes` — no hypervisor-specific modules.

### Guacamole + Hypervisors Pattern

The standard pattern (used by Apache Guacamole itself and persea):
1. Hypervisor provides a proxy endpoint (SPICE proxy, VNC proxy, serial proxy)
2. guacd connects to that proxy using the standard protocol
3. The web client talks to guacd via the Guacamole protocol over WebSocket

This is exactly what persea's `src/pve.rs` does for Proxmox.

---

## 6. Recommendations for VMware Integration

### Option A: VNC Direct (Simplest)

**If VNC is enabled on target VMs:**
- Use vSphere SOAP API for VM lifecycle + inventory
- Connect guacd directly to VNC on the ESXi host port
- Requires: VNC enabled per-VM, no firewall blocking

**Pros:** Works with existing guacd, no new protocols
**Cons:** VNC not enabled by default, no TLS, breaks on vMotion

### Option B: VMware Console Proxy (Intermediate)

**Build a console proxy daemon:**
1. Use SOAP API's `AcquireTicket(ticketType="webmks")` to get MKS credentials
2. Build a proxy that translates between WebSocket (browser) and MKS protocol
3. Or: translate MKS→VNC and feed to guacd

**Pros:** Works with default VM configs, no VNC requirement
**Cons:** MKS protocol is undocumented, reverse-engineering needed

### Option C: VNC Proxy + Lifecycle Management (Recommended)

**A balanced approach:**
1. SOAP API for VM inventory + power management
2. Enable VNC on VMs via API when console session requested
3. guacd connects to VNC on ESXi host
4. Disable VNC when session ends

```rust
pub struct VsphereBroker {
    pub base_url: String,      // https://vcenter.example.com/sdk
    pub username: String,
    pub password: String,
    // or session ticket
}

impl VsphereBroker {
    pub async fn login(&mut self) -> Result<(), VsphereError>;
    pub async fn list_vms(&self) -> Result<Vec<VmInfo>, VsphereError>;
    pub async fn get_power_state(&self, vm_id: &str) -> Result<PowerState, VsphereError>;
    pub async fn power_on(&self, vm_id: &str) -> Result<(), VsphereError>;
    pub async fn power_off(&self, vm_id: &str) -> Result<(), VsphereError>;
    pub async fn enable_vnc(&self, vm_id: &str, port: u16) -> Result<(), VsphereError>;
    pub async fn disable_vnc(&self, vm_id: &str) -> Result<(), VsphereError>;
    pub async fn acquire_mks_ticket(&self, vm_id: &str) -> Result<MksTicket, VsphereError>;
}
```

### Option D: Horizon Integration (Separate Product)

If using VMware Horizon:
- Horizon has its own brokering (PCoIP/Blast)
- Not suitable for persea integration — it's a full VDI platform
- Horizon's value is desktop pools, not individual VM console access

### Recommendation

**Start with Option A/C hybrid:**
1. SOAP API for inventory + power management
2. Try VNC first (if enabled) → guacd VNC
3. Fall back to MKS ticket (for manual launch in VMRC or future proxy work)
4. Skip Horizon — it's a different product category

### Dependencies Needed for VMware Integration

```toml
[dependencies]
# SOAP client for vSphere SDK
reqwest = { version = "0.11", features = ["json"] }  # HTTP client
quick-xml = "0.28"  # SOAP XML parsing (or use reqwest with raw XML)
# For MKS/WebSocket (if pursuing Option B):
tokio-tungstenite = "0.20"  # WebSocket client
```

---

## 7. Summary

| Platform | Console Protocol | API | Auth | Integration Difficulty |
|----------|-----------------|-----|------|----------------------|
| **Proxmox VE** | SPICE/VNC/Serial | REST (JSON) | API tokens | **Easy** (done) |
| **VMware vSphere** | VNC (opt-in) / MKS (native) | SOAP + REST | SSO/LDAP | **Hard** (MKS undocumented) |
| **Xen/XCP-ng** | VNC | XML-RPC | Session | **Medium** |
| **oVirt** | SPICE/VNC | REST | OAuth/Tokens | **Medium** |
| **Nutanix AHV** | noVNC | REST | Basic auth | **Medium-Hard** |

The core challenge: VMware's native console protocol (MKS) is proprietary and undocumented. The only viable path for guacd-based brokering is VNC, which requires explicit opt-in per VM. This is a fundamental architectural limitation compared to Proxmox, where SPICE is first-class and the `spiceproxy` API was designed for exactly this use case.
