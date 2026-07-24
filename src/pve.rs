//! Proxmox VE API client for brokering SPICE console access.
//!
//! Proxmox issues short-lived (~30s), single-use SPICE tickets via its API, so
//! a console cannot use a stored password. To open a VM console we call the
//! `spiceproxy` endpoint just-in-time and feed the returned host / proxy /
//! tls-port / ca / host-subject / ticket into a SPICE session (see the SPICE
//! branch of `session::SessionManager::create_session`).
//!
//! Endpoint: `POST /api2/json/nodes/{node}/qemu/{vmid}/spiceproxy` (optional
//! form param `proxy=<node>`). Auth: an API token header,
//! `Authorization: PVEAPIToken=USER@REALM!TOKENID=SECRET`.
//!
//! Security: the API token and the returned ticket are credentials. This
//! module never logs them, and it never includes the response body (which
//! carries the ticket) in error messages.

use std::collections::HashMap;
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

/// A configured Proxmox VE API target (host + API token).
pub struct PveBroker {
    /// Base URL of the PVE API, e.g. `https://pve.example.com:8006`.
    pub base_url: String,
    /// API token, formatted `USER@REALM!TOKENID=SECRET`.
    pub api_token: String,
    /// Verify the PVE API server's TLS certificate. Proxmox ships a
    /// self-signed cluster cert by default, so this is often disabled unless
    /// the cluster CA is trusted on the rustguac host.
    pub verify_tls: bool,
}

#[derive(Debug)]
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
                write!(f, "PVE spiceproxy returned HTTP {code}")
            }
            PveError::Api(code, msg) => write!(f, "PVE spiceproxy returned HTTP {code}: {msg}"),
            PveError::Parse(m) => write!(f, "PVE spiceproxy response parse error: {m}"),
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

    /// Resolve which cluster node hosts a VM, via `/cluster/resources`. Lets a
    /// caller omit the node — the PVE web UI resolves vmid→node the same way,
    /// so the node-scoped console API can be reached with only the VM id.
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

    /// Fetch a just-in-time SPICE config for a VM console. `proxy` optionally
    /// overrides the SPICE proxy node (defaults to the node handling the
    /// request). This performs a live API call and should be invoked at
    /// connect time, as the returned ticket expires within ~30s.
    pub async fn fetch_spice_config(
        &self,
        node: &str,
        vmid: u32,
        proxy: Option<&str>,
    ) -> Result<PveSpiceConfig, PveError> {
        let url = format!(
            "{}/api2/json/nodes/{}/qemu/{}/spiceproxy",
            self.base_url.trim_end_matches('/'),
            node,
            vmid
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
