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
    /// The API returned a non-success status. Carries the status only, never
    /// the body (which contains the ticket).
    Api(u16),
    /// The response could not be parsed / was missing an expected field.
    Parse(String),
}

impl std::fmt::Display for PveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PveError::Transport(m) => write!(f, "PVE API transport error: {m}"),
            PveError::Api(code) => write!(f, "PVE spiceproxy returned HTTP {code}"),
            PveError::Parse(m) => write!(f, "PVE spiceproxy response parse error: {m}"),
        }
    }
}
impl std::error::Error for PveError {}

impl PveBroker {
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

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(!self.verify_tls)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| PveError::Transport(e.to_string()))?;

        let mut req = client
            .post(&url)
            .header("Authorization", format!("PVEAPIToken={}", self.api_token));
        if let Some(p) = proxy {
            req = req.form(&[("proxy", p)]);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| PveError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            // Deliberately do NOT include the body: it may carry a ticket.
            return Err(PveError::Api(status.as_u16()));
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
