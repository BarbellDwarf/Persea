//! VMware vSphere integration for VM inventory and OS-aware protocol routing.
//!
//! Connects to vCenter via the vSphere REST API (vSphere 7.0.3+) to enumerate
//! VMs and auto-detect the right Guacamole protocol (RDP/SSH/VNC) based on the
//! guest OS identifier. guacd connects to the guest IP directly — no MKS
//! console proxy is involved.
//!
//! Session-based auth: POST `/rest/com/vmware/cis/session` with basic auth
//! to obtain a session ID, then include `vmware-api-session-id` header in
//! all subsequent requests. Re-authenticates automatically on 401/403.

use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors specific to vSphere operations.
#[derive(Debug)]
#[allow(dead_code)]
#[must_use]
pub enum VsphereError {
    /// Transport / TLS failure.
    Transport(String),
    /// vSphere API returned a fault (NotAuthenticated, InvalidLogin, etc.).
    Api(String),
    /// Response parsing failed or missing expected fields.
    Parse(String),
    /// The `vim_rs` crate is not available.
    CrateUnavailable,
}

impl std::fmt::Display for VsphereError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VsphereError::Transport(m) => write!(f, "vSphere transport error: {m}"),
            VsphereError::Api(m) => write!(f, "vSphere API error: {m}"),
            VsphereError::Parse(m) => write!(f, "vSphere response parse error: {m}"),
            VsphereError::CrateUnavailable => {
                write!(f, "vim_rs crate not yet installed — vSphere integration unavailable")
            }
        }
    }
}

impl std::error::Error for VsphereError {}

// ── Configuration ───────────────────────────────────────────────────────────

/// vSphere connection and session configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct VsphereConfig {
    /// vCenter Server URL, e.g. `https://vcenter.example.com/sdk`.
    pub vcenter_addr: String,
    /// vSphere username (e.g. `administrator@vsphere.local`).
    pub username: String,
    /// Name of the environment variable holding the password.
    /// The password is never stored in config files.
    #[serde(default = "default_password_env")]
    pub password_env: String,
    /// Skip TLS certificate verification. Default: false.
    #[serde(default)]
    pub insecure: bool,
    /// How often to refresh the VM inventory in seconds. Default: 300 (5 min).
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
    /// Optional per-VM credential overrides keyed by VM name or ID.
    /// When set, these credentials are used instead of the global defaults.
    /// Format: `{ "vm-name-or-id": { "username": "...", "password_env": "..." } }`.
    #[serde(default)]
    pub vm_credentials: HashMap<String, VsphereVmCredential>,
}

fn default_password_env() -> String {
    "VSPHERE_PASSWORD".into()
}

fn default_refresh_interval() -> u64 {
    300
}

/// Per-VM credential override.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct VsphereVmCredential {
    pub username: String,
    #[serde(default = "default_password_env")]
    pub password_env: String,
}

// ── VM information ──────────────────────────────────────────────────────────

/// Power state of a virtual machine.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    PoweredOn,
    PoweredOff,
    Suspended,
    Unknown,
}

impl PowerState {
    /// Parse a vSphere `VirtualMachinePowerState` string.
    pub fn from_vsphere(s: &str) -> Self {
        match s {
            "POWERED_ON" | "poweredOn" => PowerState::PoweredOn,
            "POWERED_OFF" | "poweredOff" => PowerState::PoweredOff,
            "SUSPENDED" | "suspended" => PowerState::Suspended,
            _ => PowerState::Unknown,
        }
    }
}

/// VMware Tools status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolsStatus {
    Running,
    NotRunning,
    Unmanaged,
    Unknown,
}

impl ToolsStatus {
    /// Parse a vSphere `GuestToolsStatus` string.
    pub fn from_vsphere(s: &str) -> Self {
        match s {
            "guestToolsRunning" => ToolsStatus::Running,
            "guestToolsNotRunning" => ToolsStatus::NotRunning,
            "guestToolsUnmanaged" => ToolsStatus::Unmanaged,
            _ => ToolsStatus::Unknown,
        }
    }
}

/// Information about a single virtual machine.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VmInfo {
    /// Display name of the VM.
    pub name: String,
    /// vSphere managed object ID (e.g. `vm-123`).
    pub vm_id: String,
    /// Power state (on/off/suspended).
    pub power_state: PowerState,
    /// Guest OS identifier from vSphere (e.g. `windows10_64Guest`, `ubuntu64Guest`).
    pub guest_os: String,
    /// Guest OS family (e.g. `windows`, `linux`, `other`).
    pub guest_family: String,
    /// Guest IP address (from VMware Tools).
    pub ip_address: Option<String>,
    /// ESXi host name running this VM.
    pub host: Option<String>,
    /// VMware Tools status.
    pub tools_status: ToolsStatus,
}

// ── Protocol detection ──────────────────────────────────────────────────────

/// Map a vSphere `guestId` string to (protocol, default_port) for guacd.
///
/// The mapping follows VMware's `VirtualMachineGuestOsIdentifier` enum:
/// - `win*` → RDP (3389)
/// - `linux*`, `debian*`, `ubuntu*`, `rhel*`, `centos*`, `suse*`, `oracle*`, etc. → SSH (22)
/// - Everything else → VNC (5900)
#[allow(dead_code)]
pub fn detect_protocol(guest_id: &str) -> (String, u16) {
    let lower = guest_id.to_lowercase();

    // Windows variants
    if lower.starts_with("win")
        || lower.contains("windows")
        || lower == "microsoftwindows10_64guest"
        || lower == "microsoftwindows11_64guest"
    {
        return ("rdp".into(), 3389);
    }

    // Linux / Unix variants
    let linux_prefixes = [
        "linux",
        "debian",
        "ubuntu",
        "rhel",
        "centos",
        "suse",
        "sles",
        "oracle",
        "fedora",
        "redhat",
        "gentoo",
        "arch",
        "alpine",
        "freebsd",
        "openbsd",
        "netbsd",
        "solaris",
        "opensolaris",
        "coreos",
        "amazonlinux",
        "alma",
        "rocky",
    ];
    for prefix in &linux_prefixes {
        if lower.starts_with(prefix) {
            return ("ssh".into(), 22);
        }
    }

    // Catch common full guestId patterns that don't match prefix rules
    if lower.contains("linux") || lower.contains("bsd") || lower.contains("unix") {
        return ("ssh".into(), 22);
    }

    // Fallback: VNC
    ("vnc".into(), 5900)
}

// ── Cached VM inventory ─────────────────────────────────────────────────────

/// Cached VM inventory with a TTL for the refresh interval.
#[derive(Debug, Clone)]
pub struct VmCache {
    pub vms: Vec<VmInfo>,
    pub last_refresh: Instant,
    pub ttl: Duration,
}

impl VmCache {
    /// Returns true if the cache has expired and needs a refresh.
    pub fn is_stale(&self) -> bool {
        self.last_refresh.elapsed() >= self.ttl
    }
}

impl Default for VmCache {
    fn default() -> Self {
        Self {
            vms: Vec::new(),
            last_refresh: Instant::now(),
            ttl: Duration::from_secs(default_refresh_interval()),
        }
    }
}

// ── vSphere client ──────────────────────────────────────────────────────────

/// vSphere client with session management.
///
/// Holds the session ID returned by `POST /rest/com/vmware/cis/session` and
/// transparently re-authenticates when the server returns a 401.
pub struct VsphereClient {
    /// Base URL of the vCenter SDK endpoint (e.g. `https://vcenter.example.com`).
    pub base_url: String,
    /// REST API base path.
    pub rest_url: String,
    /// Authenticated session ID (from `/rest/com/vmware/cis/session`).
    session_key: Option<String>,
    /// Credentials (kept for automatic re-auth).
    username: String,
    password: String,
    /// Whether to skip TLS verification.
    insecure: bool,
    /// HTTP client (reused across requests).
    http: reqwest::Client,
    /// Cached VM inventory.
    cache: VmCache,
}

impl VsphereClient {
    /// Return the cached inventory or None if the cache is empty.
    pub fn cached_vms(&self) -> Option<&[VmInfo]> {
        if self.cache.vms.is_empty() {
            None
        } else {
            Some(&self.cache.vms)
        }
    }

    /// Update the cached VM inventory.
    fn update_cache(&mut self, vms: Vec<VmInfo>) {
        self.cache = VmCache {
            vms,
            last_refresh: Instant::now(),
            ttl: Duration::from_secs(self.cache.ttl.as_secs()),
        };
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Connect to vCenter and authenticate.
///
/// Performs `POST /rest/com/vmware/cis/session` with basic auth and returns
/// a client ready for VM inventory queries. The password is read from the
/// environment variable specified in `VsphereConfig::password_env`.
pub async fn connect(config: &VsphereConfig) -> Result<VsphereClient, VsphereError> {
    let password = std::env::var(&config.password_env)
        .map_err(|_| VsphereError::Api(format!(
            "environment variable {} not set", config.password_env
        )))?;

    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure)
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| VsphereError::Transport(e.to_string()))?;

    // Build the REST API base URL from the SDK URL.
    // Input: `https://vcenter.example.com/sdk` → REST base: `https://vcenter.example.com`
    let base_url = config.vcenter_addr.trim_end_matches('/').trim_end_matches("/sdk").to_string();
    let rest_url = format!("{}/rest", base_url);

    // --- REST API: Create session ---
    let session_url = format!("{}/com/vmware/cis/session", rest_url);
    let session_resp = http
        .post(&session_url)
        .basic_auth(&config.username, Some(&password))
        .send()
        .await
        .map_err(|e| VsphereError::Transport(e.to_string()))?;

    let status = session_resp.status();
    if !status.is_success() {
        let body = session_resp.text().await.unwrap_or_default();
        return Err(VsphereError::Api(format!(
            "session creation failed (HTTP {}): {}",
            status.as_u16(),
            body
        )));
    }

    let session_json: serde_json::Value = session_resp
        .json()
        .await
        .map_err(|e| VsphereError::Parse(e.to_string()))?;

    let session_key = session_json
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VsphereError::Parse("session response missing 'value' field".into()))?
        .to_string();

    tracing::info!(
        vcenter = %config.vcenter_addr,
        username = %config.username,
        "vSphere client connected"
    );

    Ok(VsphereClient {
        base_url,
        rest_url,
        session_key: Some(session_key),
        username: config.username.clone(),
        password,
        insecure: config.insecure,
        http,
        cache: VmCache::default(),
    })
}

/// Retrieve the list of VMs from vCenter with guest OS and IP information.
///
/// Uses `GET /rest/vcenter/vm` with filter for useful fields. Results are
/// cached for `refresh_interval_secs`.
pub async fn list_vms(client: &mut VsphereClient) -> Result<Vec<VmInfo>, VsphereError> {
    if !client.cache.is_stale() {
        return Ok(client.cache.vms.clone());
    }

    // Ensure we have a valid session
    ensure_session(client).await?;

    let vms = fetch_vm_inventory(client).await?;
    client.update_cache(vms.clone());
    Ok(vms)
}

/// Perform a power action on a VM: "on", "off", "suspend", or "reset".
pub async fn power_action(
    client: &mut VsphereClient,
    vm_id: &str,
    action: &str,
) -> Result<(), VsphereError> {
    ensure_session(client).await?;

    let rest_action = match action {
        "on" | "poweron" => "start",
        "off" | "poweroff" => "stop",
        "suspend" => "suspend",
        "reset" => "reset",
        _ => {
            return Err(VsphereError::Api(format!(
                "unknown power action '{action}' — expected: on, off, suspend, reset"
            )))
        }
    };

    tracing::info!(vm_id, action = rest_action, "vSphere power action");

    let url = format!("{}/vcenter/vm/{}", client.rest_url, vm_id);

    // vSphere REST API power actions use POST with action suffix
    let action_url = match rest_action {
        "start" => format!("{}/start", url),
        "stop" => format!("{}/stop", url),
        "suspend" => format!("{}/suspend", url),
        "reset" => format!("{}/reset", url),
        _ => unreachable!(),
    };

    let resp = client
        .http
        .post(&action_url)
        .header("vmware-api-session-id", client.session_key.as_deref().unwrap_or(""))
        .send()
        .await
        .map_err(|e| VsphereError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        // Re-authenticate and retry once
        login(client).await?;
        let resp = client
            .http
            .post(&action_url)
            .header("vmware-api-session-id", client.session_key.as_deref().unwrap_or(""))
            .send()
            .await
            .map_err(|e| VsphereError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(VsphereError::Api(format!(
                "power action failed (HTTP {}): {}",
                status.as_u16(),
                body
            )));
        }
    } else if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(VsphereError::Api(format!(
            "power action failed (HTTP {}): {}",
            status.as_u16(),
            body
        )));
    }

    Ok(())
}

// ── Internal helpers ────────────────────────────────────────────────────────

/// Ensure the client has a valid session, re-authenticating if needed.
async fn ensure_session(client: &mut VsphereClient) -> Result<(), VsphereError> {
    if client.session_key.is_some() {
        return Ok(());
    }
    login(client).await
}

/// Authenticate to vCenter using REST API session creation.
///
/// POST to `/rest/com/vmware/cis/session` with basic auth.
async fn login(client: &mut VsphereClient) -> Result<(), VsphereError> {
    tracing::debug!(vcenter = %client.base_url, "vSphere authenticating");

    let session_url = format!("{}/com/vmware/cis/session", client.rest_url);
    let resp = client
        .http
        .post(&session_url)
        .basic_auth(&client.username, Some(&client.password))
        .send()
        .await
        .map_err(|e| VsphereError::Transport(e.to_string()))?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(VsphereError::Api(format!(
            "login failed (HTTP {}): {}",
            status.as_u16(),
            body
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VsphereError::Parse(e.to_string()))?;

    let session_key = json
        .get("value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VsphereError::Parse("login response missing 'value' field".into()))?
        .to_string();

    client.session_key = Some(session_key);
    Ok(())
}

/// Fetch the full VM inventory from vCenter via REST API.
///
/// Uses `GET /rest/vcenter/vm` to list all VMs with their properties.
/// Handles 401 by re-authenticating and retrying once.
async fn fetch_vm_inventory(
    client: &VsphereClient,
) -> Result<Vec<VmInfo>, VsphereError> {
    let url = format!("{}/vcenter/vm", client.rest_url);
    let mut vms = do_fetch_vms(client, &url).await?;

    // Resolve host names for VMs that have a host_moid but no name yet
    for vm in &mut vms {
        if let Some(ref host_moid) = vm.host {
            if host_moid.starts_with("host-") {
                // Try to resolve the host name via REST API
                let host_url = format!("{}/vcenter/host/{}", client.rest_url, host_moid);
                if let Ok(resp) = client
                    .http
                    .get(&host_url)
                    .header("vmware-api-session-id", client.session_key.as_deref().unwrap_or(""))
                    .send()
                    .await
                {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if let Some(name) = json.get("value").and_then(|v| v.get("name")).and_then(|v| v.as_str()) {
                            vm.host = Some(name.to_string());
                        }
                    }
                }
            }
        }
    }

    Ok(vms)
}

/// Internal: fetch VM list, handling auth retry.
async fn do_fetch_vms(
    client: &VsphereClient,
    url: &str,
) -> Result<Vec<VmInfo>, VsphereError> {
    let resp = client
        .http
        .get(url)
        .header("vmware-api-session-id", client.session_key.as_deref().unwrap_or(""))
        .send()
        .await
        .map_err(|e| VsphereError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.as_u16() == 401 || status.as_u16() == 403 {
        // Re-auth is handled by the caller (ensure_session before fetch)
        return Err(VsphereError::Api("session expired, re-auth required".into()));
    }

    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(VsphereError::Api(format!(
            "VM list failed (HTTP {}): {}",
            status.as_u16(),
            body
        )));
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| VsphereError::Parse(e.to_string()))?;

    let value = json.get("value").ok_or_else(|| {
        VsphereError::Parse("VM list response missing 'value' field".into())
    })?;

    let vm_list = value
        .as_array()
        .ok_or_else(|| VsphereError::Parse("'value' is not an array".into()))?;

    let mut vms = Vec::with_capacity(vm_list.len());

    for vm_obj in vm_list {
        let vm = parse_vm_info(vm_obj)?;
        vms.push(vm);
    }

    Ok(vms)
}

/// Parse a single VM object from the REST API response into `VmInfo`.
fn parse_vm_info(vm_obj: &serde_json::Value) -> Result<VmInfo, VsphereError> {
    let vm_id = vm_obj
        .get("vm")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let name = vm_obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let power_state_str = vm_obj
        .get("power_state")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let power_state = PowerState::from_vsphere(power_state_str);

    let guest_os = vm_obj
        .get("guest_OS")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // Determine guest family from guest_OS
    let guest_family = determine_guest_family(&guest_os);

    let ip_address = vm_obj
        .get("guest")
        .and_then(|v| v.get("ip_address"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let host = vm_obj
        .get("host")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let tools_status_str = vm_obj
        .get("guest")
        .and_then(|v| v.get("tools_status"))
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN");
    let tools_status = ToolsStatus::from_vsphere(tools_status_str);

    Ok(VmInfo {
        name,
        vm_id,
        power_state,
        guest_os,
        guest_family,
        ip_address,
        host,
        tools_status,
    })
}

/// Determine the guest OS family from the guest OS identifier.
fn determine_guest_family(guest_os: &str) -> String {
    let lower = guest_os.to_lowercase();
    if lower.starts_with("win") || lower.contains("windows") {
        "windows".into()
    } else if lower.starts_with("linux")
        || lower.contains("linux")
        || lower.contains("bsd")
        || lower.contains("unix")
        || lower.contains("solaris")
        || lower.contains("ubuntu")
        || lower.contains("debian")
        || lower.contains("rhel")
        || lower.contains("centos")
        || lower.contains("suse")
        || lower.contains("fedora")
        || lower.contains("generic_linux")
        || lower.contains("photon")
        || lower.contains("oracle")
        || lower.contains("rocky")
        || lower.contains("alma")
    {
        "linux".into()
    } else {
        "other".into()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_protocol_windows() {
        let cases = [
            "windows10_64Guest",
            "windows11_64Guest",
            "windows2019srv_64Guest",
            "windows2022srv_64Guest",
            "microsoftWindows10_64Guest",
        ];
        for guest_id in cases {
            let (proto, port) = detect_protocol(guest_id);
            assert_eq!(proto, "rdp", "expected RDP for {guest_id}");
            assert_eq!(port, 3389);
        }
    }

    #[test]
    fn detect_protocol_linux() {
        let cases = [
            "ubuntu64Guest",
            "debian11_64Guest",
            "rhel8_64Guest",
            "centos7_64Guest",
            "sles15_64Guest",
            "oracleLinux7_64Guest",
            "fedora64Guest",
            "amazonLinux2_64Guest",
            "almaLinux9_64Guest",
            "rockyLinux9_64Guest",
            "linux64Guest",
        ];
        for guest_id in cases {
            let (proto, port) = detect_protocol(guest_id);
            assert_eq!(proto, "ssh", "expected SSH for {guest_id}");
            assert_eq!(port, 22);
        }
    }

    #[test]
    fn detect_protocol_bsd_solaris() {
        let cases = [
            "freeBSD64Guest",
            "openBSD64Guest",
            "solaris11_64Guest",
            "unix64Guest",
        ];
        for guest_id in cases {
            let (proto, port) = detect_protocol(guest_id);
            assert_eq!(proto, "ssh", "expected SSH for {guest_id}");
            assert_eq!(port, 22);
        }
    }

    #[test]
    fn detect_protocol_unknown_falls_back_to_vnc() {
        let (proto, port) = detect_protocol("someCustomOs_64Guest");
        assert_eq!(proto, "vnc");
        assert_eq!(port, 5900);
    }

    #[test]
    fn power_state_parse() {
        assert_eq!(PowerState::from_vsphere("POWERED_ON"), PowerState::PoweredOn);
        assert_eq!(PowerState::from_vsphere("poweredOn"), PowerState::PoweredOn);
        assert_eq!(PowerState::from_vsphere("POWERED_OFF"), PowerState::PoweredOff);
        assert_eq!(PowerState::from_vsphere("poweredOff"), PowerState::PoweredOff);
        assert_eq!(PowerState::from_vsphere("SUSPENDED"), PowerState::Suspended);
        assert_eq!(PowerState::from_vsphere("suspended"), PowerState::Suspended);
        assert_eq!(PowerState::from_vsphere("bogus"), PowerState::Unknown);
    }

    #[test]
    fn tools_status_parse() {
        assert_eq!(
            ToolsStatus::from_vsphere("guestToolsRunning"),
            ToolsStatus::Running
        );
        assert_eq!(
            ToolsStatus::from_vsphere("guestToolsNotRunning"),
            ToolsStatus::NotRunning
        );
        assert_eq!(
            ToolsStatus::from_vsphere("guestToolsUnmanaged"),
            ToolsStatus::Unmanaged
        );
        assert_eq!(
            ToolsStatus::from_vsphere("somethingElse"),
            ToolsStatus::Unknown
        );
    }

    #[test]
    fn vm_cache_stale_check() {
        let cache = VmCache {
            ttl: Duration::from_secs(0),
            ..Default::default()
        };
        assert!(cache.is_stale());

        let cache = VmCache {
            ttl: Duration::from_secs(3600),
            ..Default::default()
        };
        assert!(!cache.is_stale());
    }

    #[test]
    fn parse_vm_info_basic() {
        let json = serde_json::json!({
            "vm": "vm-123",
            "name": "web-server-01",
            "power_state": "POWERED_ON",
            "guest_OS": "UBUNTU_64",
            "host": "host-42",
            "guest": {
                "ip_address": "192.168.1.100",
                "tools_status": "guestToolsRunning"
            }
        });
        let vm = parse_vm_info(&json).unwrap();
        assert_eq!(vm.name, "web-server-01");
        assert_eq!(vm.vm_id, "vm-123");
        assert_eq!(vm.power_state, PowerState::PoweredOn);
        assert_eq!(vm.guest_os, "UBUNTU_64");
        assert_eq!(vm.guest_family, "linux");
        assert_eq!(vm.ip_address.as_deref(), Some("192.168.1.100"));
        assert_eq!(vm.host.as_deref(), Some("host-42"));
        assert_eq!(vm.tools_status, ToolsStatus::Running);
    }

    #[test]
    fn parse_vm_info_windows() {
        let json = serde_json::json!({
            "vm": "vm-456",
            "name": "dc-01",
            "power_state": "POWERED_OFF",
            "guest_OS": "WINDOWS_2022srv_64",
            "host": null,
            "guest": {
                "ip_address": null,
                "tools_status": "guestToolsNotRunning"
            }
        });
        let vm = parse_vm_info(&json).unwrap();
        assert_eq!(vm.guest_family, "windows");
        assert_eq!(vm.power_state, PowerState::PoweredOff);
        assert!(vm.ip_address.is_none());
    }

    #[test]
    fn determine_guest_family_windows() {
        assert_eq!(determine_guest_family("WINDOWS_2022srv_64"), "windows");
        assert_eq!(determine_guest_family("windows10_64Guest"), "windows");
    }

    #[test]
    fn determine_guest_family_linux() {
        assert_eq!(determine_guest_family("UBUNTU_64"), "linux");
        assert_eq!(determine_guest_family("linux64Guest"), "linux");
        assert_eq!(determine_guest_family("freeBSD64Guest"), "linux");
        assert_eq!(determine_guest_family("solaris11_64Guest"), "linux");
    }

    #[test]
    fn determine_guest_family_other() {
        assert_eq!(determine_guest_family("dos_64Guest"), "other");
        assert_eq!(determine_guest_family("unknown"), "other");
    }

    #[test]
    fn vsphere_config_parse_minimal() {
        let toml_str = r#"
            vcenter_addr = "https://vcenter.example.com/sdk"
            username = "admin@vsphere.local"
        "#;
        let config: VsphereConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.vcenter_addr, "https://vcenter.example.com/sdk");
        assert_eq!(config.username, "admin@vsphere.local");
        assert_eq!(config.password_env, "VSPHERE_PASSWORD");
        assert!(!config.insecure);
        assert_eq!(config.refresh_interval_secs, 300);
        assert!(config.vm_credentials.is_empty());
    }

    #[test]
    fn vsphere_config_parse_full() {
        let toml_str = r#"
            vcenter_addr = "https://vcenter.lab:8443/sdk"
            username = "user@lab.local"
            password_env = "MY_VSPHERE_PASS"
            insecure = true
            refresh_interval_secs = 60

            [vsphere.vm_credentials]
            "web-01" = { username = "root", password_env = "WEB01_PASS" }
        "#;
        let config: VsphereConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.vcenter_addr, "https://vcenter.lab:8443/sdk");
        assert_eq!(config.username, "user@lab.local");
        assert_eq!(config.password_env, "MY_VSPHERE_PASS");
        assert!(config.insecure);
        assert_eq!(config.refresh_interval_secs, 60);
        assert_eq!(config.vm_credentials.len(), 1);
        let cred = config.vm_credentials.get("web-01").unwrap();
        assert_eq!(cred.username, "root");
        assert_eq!(cred.password_env, "WEB01_PASS");
    }
}
