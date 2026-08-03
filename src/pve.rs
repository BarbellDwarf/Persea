//! Proxmox VE API client for brokering console access (SPICE, VNC, serial,
//! xterm.js) and managing VM lifecycle.
//!
//! Proxmox issues short-lived, single-use tickets via its API, so a console
//! cannot use a stored password. We call the appropriate proxy endpoint
//! just-in-time and feed the returned credentials into guacamole-server.
//!
//! Auth: API token header `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`.
//!
//! Security: the API token and returned tickets are credentials. This module
//! never logs them, and it never includes response bodies (which carry tickets)
//! in error messages.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

/// A just-in-time SPICE connection config from the PVE `spiceproxy` endpoint.
#[derive(Debug)]
pub struct PveSpiceConfig {
    /// Opaque proxy-routing token PVE returns as `host` (e.g.
    /// `pvespiceproxy:…:vmid:node::…`). Passed to guacd as the SPICE hostname;
    /// the SPICE proxy uses it to route to the real VM.
    pub host: String,
    /// The actual connect endpoint, e.g. `http://pve.example.com:3128`.
    pub proxy: String,
    /// TLS port on the proxy (typically 61000+).
    pub tls_port: u16,
    /// Single-use SPICE ticket, valid ~30s. Delivered to guacd via argv.
    pub ticket: String,
    /// Cluster CA certificate (PEM, with real newlines).
    pub ca_cert: String,
    /// Expected TLS certificate subject of the host.
    pub host_subject: String,
}

/// VM type in PVE — determines which API sub-path to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PveVmType {
    Qemu,
    Lxc,
}

impl fmt::Display for PveVmType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PveVmType::Qemu => write!(f, "qemu"),
            PveVmType::Lxc => write!(f, "lxc"),
        }
    }
}

/// A just-in-time VNC connection config from the PVE `vncproxy` endpoint.
#[derive(Debug)]
pub struct VncConfig {
    /// Hostname/IP of the node running the VNC proxy.
    pub host: String,
    /// TCP port the VNC proxy is listening on.
    pub port: u16,
    /// Single-use ticket (used as VNC password). Valid ~30s.
    pub ticket: String,
    /// TLS certificate of the VNC proxy (PEM), if TLS is required.
    pub cert: String,
}

/// A just-in-time serial/termproxy config from the PVE `termproxy` endpoint.
#[derive(Debug)]
pub struct SerialConfig {
    /// Hostname/IP of the node running the serial proxy.
    pub host: String,
    /// TCP port the serial proxy is listening on.
    pub port: u16,
    /// Single-use ticket. Valid ~30s.
    pub ticket: String,
}

/// Config for an xterm.js WebSocket terminal from the PVE `xtermjs` endpoint.
#[derive(Debug)]
pub struct XtermConfig {
    /// Single-use ticket for the WebSocket session.
    pub ticket: String,
    /// WebSocket port. The full URL is `wss://{node}:{port}/ws?ticket={ticket}`.
    pub port: u16,
}

/// A VM or container resource as reported by `/cluster/resources?type=vm`.
#[derive(Debug, Clone)]
pub struct PveVm {
    /// Numeric VM/CT ID.
    pub vmid: u32,
    /// User-assigned name.
    pub name: String,
    /// Cluster node hosting this resource.
    pub node: String,
    /// Current status: "running", "stopped", "paused", etc.
    pub status: String,
    /// Whether this is a Qemu VM or LXC container.
    pub vm_type: PveVmType,
    /// OS type hint (e.g. "linux", "windows") if provided by PVE.
    pub os_type: String,
    /// Primary IP address, if PVE reports it (requires guest agent or cloud-init).
    pub ip_address: String,
}

/// A configured Proxmox VE API target (host + API token).
pub struct PveBroker {
    /// Base URL of the PVE API, e.g. `https://pve.example.com:8006`.
    pub base_url: String,
    /// API token, formatted `USER@REALM!TOKENID=SECRET`.
    pub api_token: String,
    /// Verify the PVE API server's TLS certificate. Proxmox ships a
    /// self-signed cluster cert by default, so this is often disabled unless
    /// the cluster CA is trusted on the persea host.
    pub verify_tls: bool,
}

#[derive(Debug)]
#[must_use]
pub enum PveError {
    /// Transport-level failure (connect, TLS, timeout). Never contains creds.
    Transport(String),
    /// The API returned a non-success status. Carries the status and the
    /// response body message. Safe to include: only a *successful* (2xx)
    /// spiceproxy response carries a ticket; error bodies do not.
    Api(u16, String),
    /// The response could not be parsed / was missing an expected field.
    Parse(String),
}

impl std::fmt::Display for PveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PveError::Transport(m) => write!(f, "PVE API transport error: {m}"),
            PveError::Api(code, msg) if msg.is_empty() => {
                write!(f, "PVE API returned HTTP {code}")
            }
            PveError::Api(code, msg) => write!(f, "PVE API returned HTTP {code}: {msg}"),
            PveError::Parse(m) => write!(f, "PVE API response parse error: {m}"),
        }
    }
}
impl std::error::Error for PveError {}

/// Render an error together with its `source()` chain. reqwest's top-level
/// message is often opaque ("builder error"); the cause carries the detail.
/// The chain contains the URL/kind at most, never the auth header.
fn err_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(": ");
        out.push_str(&s.to_string());
        src = s.source();
    }
    out
}

/// Build a `PveError::Api` from a non-success response, surfacing PVE's
/// human-readable reason. Safe: only a *successful* (2xx) spiceproxy response
/// carries a ticket — error bodies do not. PVE puts the reason in
/// `message`/`errors`; fall back to the raw body, truncated.
async fn api_error(code: u16, resp: reqwest::Response) -> PveError {
    let body = resp.text().await.unwrap_or_default();
    let msg = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| {
            v.get("message")
                .and_then(|m| m.as_str())
                .map(str::to_string)
                .or_else(|| v.get("errors").map(|e| e.to_string()))
        })
        .unwrap_or_else(|| body.chars().take(200).collect());
    PveError::Api(code, msg.trim().to_string())
}

impl PveBroker {
    /// Build an HTTP client for PVE API calls. PVE ships a self-signed cluster
    /// cert by default, so certificate verification follows `verify_tls`.
    fn http_client(&self) -> Result<reqwest::Client, PveError> {
        reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.verify_tls)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| PveError::Transport(err_chain(&e)))
    }

    /// Resolve which cluster node hosts a VM or container, via
    /// `/cluster/resources`. This endpoint returns both Qemu VMs and LXC
    /// containers when `type=vm` (PVE treats LXC as a VM resource type).
    pub async fn resolve_node(&self, vmid: u32) -> Result<String, PveError> {
        let url = format!(
            "{}/api2/json/cluster/resources?type=vm",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http_client()?
            .get(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let items = wrap
            .get("data")
            .and_then(|d| d.as_array())
            .ok_or_else(|| PveError::Parse("cluster/resources missing 'data' array".into()))?;
        for item in items {
            if item.get("vmid").and_then(|v| v.as_u64()) == Some(vmid as u64) {
                if let Some(node) = item.get("node").and_then(|n| n.as_str()) {
                    return Ok(node.to_string());
                }
            }
        }
        Err(PveError::Parse(format!(
            "VM {vmid} not found in the cluster (check the VM id, or that the token can see it)"
        )))
    }

    /// Fetch a just-in-time SPICE config for a VM/CT console. `proxy`
    /// optionally overrides the SPICE proxy node. `vm_type` selects between
    /// `qemu/` and `lxc/` API paths (LXC does not actually support SPICE, so
    /// callers should guard this). This performs a live API call and should be
    /// invoked at connect time, as the returned ticket expires within ~30s.
    pub async fn fetch_spice_config(
        &self,
        node: &str,
        vmid: u32,
        vm_type: PveVmType,
        proxy: Option<&str>,
    ) -> Result<PveSpiceConfig, PveError> {
        let url = format!(
            "{}/api2/json/nodes/{}/{}/{}/spiceproxy",
            self.base_url.trim_end_matches('/'),
            node,
            vm_type,
            vmid,
        );

        let client = self.http_client()?;

        let mut req = client
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token));
        if let Some(p) = proxy {
            req = req.form(&[("proxy", p)]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }

        // Response shape: {"data": { "host": ..., "proxy": ..., "tls-port": ...,
        // "password": <ticket>, "ca": ..., "host-subject": ..., ... }}
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let data: HashMap<String, serde_json::Value> =
            serde_json::from_value(wrap.get("data").cloned().unwrap_or_default())
                .map_err(|e| PveError::Parse(e.to_string()))?;

        let field = |k: &str| -> Option<String> {
            data.get(k).and_then(|v| v.as_str()).map(str::to_string)
        };
        let require = |k: &str| field(k).ok_or_else(|| PveError::Parse(format!("missing '{k}'")));

        // tls-port may be a JSON string or number depending on PVE version.
        let tls_port = data
            .get("tls-port")
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u16)
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            })
            .ok_or_else(|| PveError::Parse("missing or invalid 'tls-port'".into()))?;

        Ok(PveSpiceConfig {
            host: require("host")?,
            proxy: require("proxy")?,
            tls_port,
            ticket: require("password")?,
            // PVE escapes newlines in the CA PEM as literal "\n"; guacd needs
            // real newlines.
            ca_cert: field("ca").unwrap_or_default().replace("\\n", "\n"),
            host_subject: field("host-subject").unwrap_or_default(),
        })
    }

    /// Helper to build the API path prefix for a given node + vm type.
    fn vm_path(&self, node: &str, vm_type: PveVmType, vmid: u32) -> String {
        format!(
            "{}/api2/json/nodes/{}/{}/{}",
            self.base_url.trim_end_matches('/'),
            node,
            vm_type,
            vmid,
        )
    }

    /// Fetch a just-in-time VNC config from the `vncproxy` endpoint.
    /// Returns a host/port/ticket that guacd can connect to directly via TCP.
    pub async fn fetch_vnc_config(
        &self,
        node: &str,
        vmid: u32,
        vm_type: PveVmType,
    ) -> Result<VncConfig, PveError> {
        let url = format!("{}/vncproxy", self.vm_path(node, vm_type, vmid));
        let resp = self
            .http_client()?
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let data: HashMap<String, serde_json::Value> =
            serde_json::from_value(wrap.get("data").cloned().unwrap_or_default())
                .map_err(|e| PveError::Parse(e.to_string()))?;

        let field = |k: &str| -> Option<String> {
            data.get(k).and_then(|v| v.as_str()).map(str::to_string)
        };
        let require = |k: &str| field(k).ok_or_else(|| PveError::Parse(format!("missing '{k}'")));

        let port = data
            .get("port")
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u16)
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            })
            .ok_or_else(|| PveError::Parse("missing or invalid 'port'".into()))?;

        Ok(VncConfig {
            host: node.to_string(),
            port,
            ticket: require("ticket")?,
            cert: field("cert").unwrap_or_default(),
        })
    }

    /// Fetch a just-in-time serial/termproxy config from the `termproxy`
    /// endpoint. Returns a host/port/ticket for a serial console connection.
    pub async fn fetch_serial_config(
        &self,
        node: &str,
        vmid: u32,
        vm_type: PveVmType,
    ) -> Result<SerialConfig, PveError> {
        let url = format!("{}/termproxy", self.vm_path(node, vm_type, vmid));
        let resp = self
            .http_client()?
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let data: HashMap<String, serde_json::Value> =
            serde_json::from_value(wrap.get("data").cloned().unwrap_or_default())
                .map_err(|e| PveError::Parse(e.to_string()))?;

        let require = |k: &str| -> Result<String, PveError> {
            data.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| PveError::Parse(format!("missing '{k}'")))
        };

        let port = data
            .get("port")
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u16)
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            })
            .ok_or_else(|| PveError::Parse("missing or invalid 'port'".into()))?;

        Ok(SerialConfig {
            host: node.to_string(),
            port,
            ticket: require("ticket")?,
        })
    }

    /// Fetch xterm.js WebSocket terminal config from the `xtermjs` endpoint.
    /// Returns a ticket + port; the WebSocket URL is
    /// `wss://{node}:{port}/ws?ticket={ticket}`.
    pub async fn fetch_xtermjs_config(
        &self,
        node: &str,
        vmid: u32,
        vm_type: PveVmType,
    ) -> Result<XtermConfig, PveError> {
        let url = format!("{}/xtermjs", self.vm_path(node, vm_type, vmid));
        let resp = self
            .http_client()?
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let data: HashMap<String, serde_json::Value> =
            serde_json::from_value(wrap.get("data").cloned().unwrap_or_default())
                .map_err(|e| PveError::Parse(e.to_string()))?;

        let require = |k: &str| -> Result<String, PveError> {
            data.get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .ok_or_else(|| PveError::Parse(format!("missing '{k}'")))
        };

        let port = data
            .get("port")
            .and_then(|v| {
                v.as_u64()
                    .map(|n| n as u16)
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
            })
            .ok_or_else(|| PveError::Parse("missing or invalid 'port'".into()))?;

        Ok(XtermConfig {
            ticket: require("ticket")?,
            port,
        })
    }

    /// List all VMs and LXC containers across the cluster via
    /// `/cluster/resources?type=vm`. Returns every resource the API token can
    /// see, including stopped ones.
    pub async fn list_all_vms(&self) -> Result<Vec<PveVm>, PveError> {
        let url = format!(
            "{}/api2/json/cluster/resources?type=vm",
            self.base_url.trim_end_matches('/')
        );
        let resp = self
            .http_client()?
            .get(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        let items = wrap
            .get("data")
            .and_then(|d| d.as_array())
            .ok_or_else(|| PveError::Parse("cluster/resources missing 'data' array".into()))?;

        let mut vms = Vec::with_capacity(items.len());
        for item in items {
            let vmid = match item.get("vmid").and_then(|v| v.as_u64()) {
                Some(v) => v as u32,
                None => continue,
            };
            let vm_type = match item.get("type").and_then(|t| t.as_str()) {
                Some("qemu") => PveVmType::Qemu,
                Some("lxc") => PveVmType::Lxc,
                _ => continue,
            };
            vms.push(PveVm {
                vmid,
                name: item
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                node: item
                    .get("node")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                status: item
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                vm_type,
                os_type: item
                    .get("ostype")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                ip_address: item
                    .get("ip_address")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        Ok(vms)
    }

    /// Send a power action (start, stop, shutdown, suspend) to a VM or
    /// container. Returns the PVE task id on success.
    pub async fn power_action(
        &self,
        node: &str,
        vmid: u32,
        vm_type: PveVmType,
        action: &str,
    ) -> Result<String, PveError> {
        let valid = ["start", "stop", "shutdown", "suspend", "resume", "reboot"];
        if !valid.contains(&action) {
            return Err(PveError::Parse(format!(
                "invalid power action '{action}'; valid: {valid:?}"
            )));
        }
        let url = format!("{}/status/{}", self.vm_path(node, vm_type, vmid), action);
        let resp = self
            .http_client()?
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token))
            .send()
            .await
            .map_err(|e| PveError::Transport(err_chain(&e)))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(api_error(status.as_u16(), resp).await);
        }
        let body = resp
            .text()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let wrap: serde_json::Value =
            serde_json::from_str(&body).map_err(|e| PveError::Parse(e.to_string()))?;
        // PVE returns {"data": "UPID:node:..."} for successful power actions.
        wrap.get("data")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| PveError::Parse("power action returned no task id".into()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_spiceproxy_style_fields_and_unescapes_ca() {
        // Mirror of a real spiceproxy `data` payload (ticket/CA are dummies).
        let body = r#"{"data":{
            "type":"spice",
            "host":"pvespiceproxy:687ea156:10016:pve::abc",
            "proxy":"http://pve.example.com:3128",
            "tls-port":61002,
            "password":"one-time-ticket",
            "host-subject":"OU=PVE Cluster Node,CN=pve.example.com",
            "ca":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
        }}"#;
        let wrap: serde_json::Value = serde_json::from_str(body).unwrap();
        let data: std::collections::HashMap<String, serde_json::Value> =
            serde_json::from_value(wrap.get("data").cloned().unwrap()).unwrap();
        // Exercise the same extraction the client uses.
        assert!(data
            .get("host")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("pvespiceproxy"));
        let tls_port = data.get("tls-port").unwrap().as_u64().unwrap() as u16;
        assert_eq!(tls_port, 61002);
        let ca = data
            .get("ca")
            .unwrap()
            .as_str()
            .unwrap()
            .replace("\\n", "\n");
        assert!(ca.contains("-----BEGIN CERTIFICATE-----\n"));
        assert!(!ca.contains("\\n"));
    }
}
