//! SSH tunnel (jump host / bastion) support.
//!
//! Creates an SSH connection to a jump host, then for each incoming local TCP
//! connection, opens a `direct-tcpip` channel to the real target and bridges
//! traffic bidirectionally. guacd connects to the local listener instead of
//! the real target.
//!
//! Supports multi-hop chains: You → hop0 → hop1 → ... → target.
//!
//! Local listeners bind loopback only (127.0.0.1) for the lifetime of the
//! session and are never reachable from the network. Caveat: while a session
//! is active, any process on this host can connect to a listener and pivot
//! through the jump host, so the persea host must be trusted by everyone
//! allowed to open sessions.

use russh::client;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{HashAlg, PublicKey};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

/// A single jump host in a multi-hop chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JumpHost {
    /// Hostname or IP address of the jump host.
    pub hostname: String,
    /// SSH port on the jump host. Defaults to 22.
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// SSH login user on the jump host.
    pub username: String,
    /// Password for password authentication. Tried after the private key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// PEM private key for public-key authentication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,
    /// SSH server host key to verify, either the SHA-256 fingerprint
    /// (e.g. "SHA256:...") or the server public key in OpenSSH format
    /// (e.g. "ssh-ed25519 AAAA..."). A public key is hashed to its
    /// fingerprint before comparison. When unset, the key is accepted on
    /// first contact (TOFU) and the fingerprint is recorded in known_hosts
    /// for subsequent connections.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key: Option<String>,
}

fn default_ssh_port() -> u16 {
    22
}

/// Non-secret jump host metadata for API responses.
#[derive(Debug, Clone, Serialize)]
pub struct JumpHostInfo {
    /// Hostname or IP address of the jump host.
    pub hostname: String,
    /// SSH port on the jump host.
    pub port: u16,
    /// SSH login user on the jump host.
    pub username: String,
    /// SSH server host key fingerprint (e.g. "SHA256:...") if pinned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
}

/// A running SSH tunnel. Dropping or cancelling shuts it down.
pub struct SshTunnel {
    /// Local address that the next hop (or guacd) should connect to.
    pub local_addr: SocketAddr,
    cancel: CancellationToken,
    _join_handle: JoinHandle<()>,
}

impl SshTunnel {
    /// Stop the tunnel (listener + SSH session).
    pub fn shutdown(&self) {
        self.cancel.cancel();
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

/// Configuration for establishing an SSH tunnel.
pub struct TunnelConfig {
    /// Hostname or IP address of the jump host.
    pub jump_host: String,
    /// SSH port on the jump host.
    pub jump_port: u16,
    /// SSH login user on the jump host.
    pub jump_username: String,
    /// Password for the jump host, used when no private key is set.
    pub jump_password: Option<String>,
    /// PEM private key for the jump host, tried before the password.
    pub jump_private_key: Option<String>,
    /// Hostname or IP the tunnel forwards to.
    pub target_host: String,
    /// TCP port the tunnel forwards to.
    pub target_port: u16,
    /// Expected SSH server host key, either the SHA-256 fingerprint
    /// ("SHA256:...") or the server public key in OpenSSH format
    /// ("ssh-ed25519 AAAA..."). A public key is hashed to its fingerprint
    /// before comparison. If set, the connection is rejected when the
    /// server presents a different key.
    pub expected_host_key: Option<String>,
    /// Path to the known_hosts file for trust-on-first-use persistence.
    pub known_hosts_path: Option<PathBuf>,
}

/// Errors from tunnel setup.
#[derive(Debug)]
#[must_use]
pub enum TunnelError {
    /// The SSH connection or channel failed at the given hop.
    Ssh(usize, String),
    /// Authentication against the jump host was rejected.
    Auth(usize, String),
    /// The local TCP listener could not be bound.
    Bind(usize, String),
    /// A private key could not be decoded or a host key check failed.
    Key(usize, String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ssh(hop, msg) => write!(f, "hop {}: SSH tunnel error: {}", hop, msg),
            Self::Auth(hop, msg) => write!(f, "hop {}: SSH tunnel auth failed: {}", hop, msg),
            Self::Bind(hop, msg) => write!(f, "hop {}: SSH tunnel bind failed: {}", hop, msg),
            Self::Key(hop, msg) => write!(f, "hop {}: SSH tunnel key error: {}", hop, msg),
        }
    }
}

/// Compute the SHA-256 fingerprint of an OpenSSH-format public key string.
pub fn fingerprint_openssh_key(openssh_key: &str) -> Result<String, String> {
    let pubkey = russh::keys::parse_public_key_base64(
        openssh_key.split_whitespace().nth(1).unwrap_or(openssh_key),
    )
    .map_err(|e| format!("invalid host key: {}", e))?;
    Ok(pubkey.fingerprint(HashAlg::Sha256).to_string())
}

/// Normalize a configured host key to its SHA-256 fingerprint form.
///
/// Accepts either the fingerprint itself ("SHA256:...") or the server
/// public key in OpenSSH format ("ssh-ed25519 AAAA..."); a public key is
/// hashed to its fingerprint so both can be compared against the key the
/// server presents.
pub fn normalize_host_key(expected: &str) -> Result<String, String> {
    let trimmed = expected.trim();
    if trimmed
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("sha256:"))
    {
        return Ok(format!("SHA256:{}", trimmed[7..].trim()));
    }
    fingerprint_openssh_key(trimmed)
}

/// Split the stored `jump_host` ("host" or "host:port") into its parts,
/// defaulting the port to 22 exactly as the pasted snippets did. Delegates
/// the cut to the shared last-colon splitter.
fn split_jump_host(jump_host: &str) -> (&str, u16) {
    let (host, port) = crate::net_util::split_host_port(jump_host);
    (host, crate::net_util::parse_port(port).unwrap_or(22))
}

/// Read the known_hosts file and return the pinned fingerprint for `host:port`,
/// or `None` if the host is not yet pinned.
fn read_known_hosts(path: &std::path::Path, host: &str, port: u16) -> Option<String> {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return None,
    };
    let prefix = format!("{}:{}:", host, port);
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        if let Some(fp) = line.strip_prefix(&prefix) {
            let fp = fp.trim().to_string();
            if !fp.is_empty() {
                return Some(fp);
            }
        }
    }
    None
}

/// Append a host:fingerprint entry to the known_hosts file.
fn append_known_host(
    path: &std::path::Path,
    host: &str,
    port: u16,
    fingerprint: &str,
) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("failed to open known_hosts for writing: {}", e))?;
    writeln!(file, "{}:{}:{}", host, port, fingerprint)
        .map_err(|e| format!("failed to write known_hosts entry: {}", e))
}

/// SSH client handler that verifies the server's host key against an expected
/// key stored in the address book. If no expected key is set (legacy entries),
/// the connection is accepted with a warning log.
struct TunnelHandler {
    expected_key: Option<String>,
    hop_index: usize,
    jump_host: String,
    known_hosts_path: Option<PathBuf>,
}

impl client::Handler for TunnelHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = server_public_key.fingerprint(HashAlg::Sha256);
        let algorithm = server_public_key.algorithm();

        // Determine the key to verify against: explicit pin takes precedence,
        // then check the on-disk known_hosts file.
        let effective_key = if let Some(ref expected) = self.expected_key {
            Some(expected.clone())
        } else {
            self.known_hosts_path.as_ref().and_then(|path| {
                let (host, port) = split_jump_host(&self.jump_host);
                read_known_hosts(path, host, port)
            })
        };

        let Some(ref expected) = effective_key else {
            // First use — no pin in address book or known_hosts.
            // Auto-pin: persist the fingerprint for future verification.
            if let Some(ref path) = self.known_hosts_path {
                let (host, port) = split_jump_host(&self.jump_host);
                match append_known_host(path, host, port, &fingerprint.to_string()) {
                    Ok(()) => {
                        tracing::info!(
                            hop = self.hop_index,
                            host = %self.jump_host,
                            fingerprint = %fingerprint,
                            algorithm = %algorithm,
                            "SSH host key auto-pinned (TOFU) — stored in known_hosts"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            hop = self.hop_index,
                            host = %self.jump_host,
                            error = %e,
                            "Failed to persist SSH host key — accepting on trust for this session"
                        );
                    }
                }
            } else {
                tracing::warn!(
                    hop = self.hop_index,
                    host = %self.jump_host,
                    fingerprint = %fingerprint,
                    algorithm = %algorithm,
                    "SSH host key not pinned and no known_hosts path — accepting on trust (TOFU)"
                );
            }
            return Ok(true);
        };

        // The stored key may be a fingerprint or an OpenSSH public key;
        // normalize it to a fingerprint before comparing.
        let expected_fp = match normalize_host_key(expected) {
            Ok(fp) => fp,
            Err(e) => {
                tracing::error!(
                    hop = self.hop_index,
                    host = %self.jump_host,
                    error = %e,
                    "Configured SSH host key could not be parsed — \
                     update the host key in the address book"
                );
                return Ok(false);
            }
        };
        if expected_fp == fingerprint.to_string() {
            tracing::debug!(
                hop = self.hop_index,
                host = %self.jump_host,
                fingerprint = %fingerprint,
                "SSH host key verified"
            );
            Ok(true)
        } else {
            tracing::error!(
                hop = self.hop_index,
                host = %self.jump_host,
                expected = %expected_fp,
                actual = %fingerprint,
                "SSH HOST KEY MISMATCH — possible MITM attack! \
                 Update the host key in the address book if the server was re-provisioned."
            );
            Ok(false)
        }
    }
}

/// Handler used by `probe_host_key` to capture the server's public key
/// during key exchange without authenticating.
struct ProbeHandler {
    captured_key: Arc<Mutex<Option<String>>>,
}

impl client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let openssh = server_public_key
            .to_openssh()
            .map_err(|e| russh::Error::Keys(russh::keys::Error::SshKey(e)))?;
        *self.captured_key.lock().await = Some(openssh);
        Ok(true)
    }
}

/// Probe an SSH server to retrieve its host key without authenticating.
/// Returns the public key in OpenSSH format.
pub async fn probe_host_key(hostname: &str, port: u16) -> Result<String, TunnelError> {
    let addr = format!("{}:{}", hostname, port);
    let captured = Arc::new(Mutex::new(None));

    let ssh_config = Arc::new(client::Config {
        ..Default::default()
    });

    let handler = ProbeHandler {
        captured_key: captured.clone(),
    };

    // Connect with a 10-second timeout — we only need the key exchange
    let handle = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        client::connect(ssh_config, &addr, handler),
    )
    .await
    .map_err(|_| TunnelError::Ssh(0, format!("timeout probing host key for {}", addr)))?
    .map_err(|e| TunnelError::Ssh(0, format!("failed to probe host key for {}: {}", addr, e)))?;

    // Disconnect cleanly
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    let result = captured
        .lock()
        .await
        .take()
        .ok_or_else(|| TunnelError::Ssh(0, format!("no host key received from {}", addr)));
    result
}

/// Start a multi-hop SSH tunnel chain.
///
/// Each hop connects through the previous hop's local listener.
/// Returns the full Vec of tunnels and the final local address
/// that guacd should connect to.
pub async fn start_chain(
    hops: &[JumpHost],
    target_host: &str,
    target_port: u16,
    known_hosts_path: Option<PathBuf>,
) -> Result<(Vec<SshTunnel>, SocketAddr), TunnelError> {
    let mut tunnels: Vec<SshTunnel> = Vec::with_capacity(hops.len());

    for (i, hop) in hops.iter().enumerate() {
        // Determine what this hop's SSH connects to
        let (connect_host, connect_port) = if i == 0 {
            // First hop connects directly to its hostname
            (hop.hostname.clone(), hop.port)
        } else {
            // Subsequent hops connect through the previous tunnel's local listener
            let prev_addr = tunnels[i - 1].local_addr;
            (prev_addr.ip().to_string(), prev_addr.port())
        };

        // Determine the direct-tcpip target for this hop
        let (fwd_host, fwd_port) = if i + 1 < hops.len() {
            // Not the last hop — forward to the next hop
            (hops[i + 1].hostname.clone(), hops[i + 1].port)
        } else {
            // Last hop — forward to the real target
            (target_host.to_string(), target_port)
        };

        let config = TunnelConfig {
            jump_host: connect_host,
            jump_port: connect_port,
            jump_username: hop.username.clone(),
            jump_password: hop.password.clone(),
            jump_private_key: hop.private_key.clone(),
            target_host: fwd_host,
            target_port: fwd_port,
            expected_host_key: hop.host_key.clone(),
            known_hosts_path: known_hosts_path.clone(),
        };

        let tunnel = start(config, i).await?;

        tracing::info!(
            hop = i,
            local_addr = %tunnel.local_addr,
            jump_host = %hop.hostname,
            "SSH tunnel hop established"
        );

        tunnels.push(tunnel);
    }

    let final_addr = tunnels
        .last()
        .expect("start_chain called with empty hops")
        .local_addr;

    Ok((tunnels, final_addr))
}

/// Shut down a chain of tunnels in reverse order (last hop first).
pub fn shutdown_chain(tunnels: &[SshTunnel]) {
    for tunnel in tunnels.iter().rev() {
        tunnel.shutdown();
    }
}

/// Start an SSH tunnel. Returns the tunnel handle with the local address.
pub async fn start(config: TunnelConfig, hop_index: usize) -> Result<SshTunnel, TunnelError> {
    let jump_addr = format!("{}:{}", config.jump_host, config.jump_port);

    // Connect to the jump host
    let ssh_config = Arc::new(client::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(300)),
        keepalive_interval: Some(std::time::Duration::from_secs(30)),
        ..Default::default()
    });

    let handler = TunnelHandler {
        expected_key: config.expected_host_key,
        hop_index,
        jump_host: jump_addr.clone(),
        known_hosts_path: config.known_hosts_path,
    };

    let mut handle = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        client::connect(ssh_config, &jump_addr, handler),
    )
    .await
    .map_err(|_| {
        TunnelError::Ssh(
            hop_index,
            format!("timeout connecting to jump host {}", jump_addr),
        )
    })?
    .map_err(|e| {
        TunnelError::Ssh(
            hop_index,
            format!("failed to connect to jump host {}: {}", jump_addr, e),
        )
    })?;

    tracing::debug!(hop = hop_index, "SSH connected to jump host {}", jump_addr);

    // Authenticate: try private key first, then password
    let auth_result = if let Some(ref key_pem) = config.jump_private_key {
        let private_key = russh::keys::decode_secret_key(key_pem, None).map_err(|e| {
            TunnelError::Key(hop_index, format!("failed to decode private key: {}", e))
        })?;
        let key = PrivateKeyWithHashAlg::new(Arc::new(private_key), None);
        handle
            .authenticate_publickey(&config.jump_username, key)
            .await
            .map_err(|e| TunnelError::Auth(hop_index, format!("public key auth error: {}", e)))?
    } else if let Some(ref password) = config.jump_password {
        handle
            .authenticate_password(&config.jump_username, password)
            .await
            .map_err(|e| TunnelError::Auth(hop_index, format!("password auth error: {}", e)))?
    } else {
        return Err(TunnelError::Auth(
            hop_index,
            "no password or private key provided for jump host".into(),
        ));
    };

    if !auth_result.success() {
        return Err(TunnelError::Auth(
            hop_index,
            format!(
                "authentication failed for {}@{}",
                config.jump_username, jump_addr
            ),
        ));
    }

    tracing::debug!(
        hop = hop_index,
        "SSH authenticated to jump host {} as {}",
        jump_addr,
        config.jump_username
    );

    // Bind a local TCP listener on an OS-assigned port. Loopback only: the
    // port is unreachable from the network and exists only for the lifetime
    // of the SSH session (guacd or the next hop connects while the session
    // is active). Local-only caveat: while the session runs, any process on
    // this host can connect to the port and pivot through the jump host —
    // the persea host must be trusted by everyone allowed to open sessions.
    let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
        TunnelError::Bind(hop_index, format!("failed to bind local listener: {}", e))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| TunnelError::Bind(hop_index, format!("failed to get local address: {}", e)))?;

    tracing::info!(
        "SSH tunnel listening on {} -> {}:{} via {}",
        local_addr,
        config.target_host,
        config.target_port,
        jump_addr
    );

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let target_host = config.target_host;
    let target_port = config.target_port;

    let join_handle = tokio::spawn(async move {
        tunnel_task(handle, listener, target_host, target_port, cancel_clone).await;
    });

    Ok(SshTunnel {
        local_addr,
        cancel,
        _join_handle: join_handle,
    })
}

/// Background task: accept TCP connections and bridge through SSH channels.
async fn tunnel_task(
    handle: client::Handle<TunnelHandler>,
    listener: TcpListener,
    target_host: String,
    target_port: u16,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("SSH tunnel cancelled, shutting down");
                break;
            }
            result = listener.accept() => {
                let (tcp_stream, peer) = match result {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("SSH tunnel listener accept error: {}", e);
                        continue;
                    }
                };

                tracing::debug!(
                    peer = %peer,
                    target = %format!("{}:{}", target_host, target_port),
                    "SSH tunnel: new connection"
                );

                let channel = match handle.channel_open_direct_tcpip(
                    target_host.clone(),
                    target_port as u32,
                    "127.0.0.1",
                    0,
                ).await {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::warn!("SSH tunnel: failed to open direct-tcpip channel: {}", e);
                        continue;
                    }
                };

                // Bridge TCP <-> SSH channel in a background task
                tokio::spawn(async move {
                    let mut ch_stream = channel.into_stream();
                    let mut tcp = tcp_stream;
                    match tokio::io::copy_bidirectional(&mut tcp, &mut ch_stream).await {
                        Ok((tx, rx)) => {
                            tracing::debug!(
                                peer = %peer,
                                tx_bytes = tx,
                                rx_bytes = rx,
                                "SSH tunnel: connection closed"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(peer = %peer, error = %e, "SSH tunnel: connection error");
                        }
                    }
                });
            }
        }
    }

    // Dropping the handle closes the SSH session
    tracing::debug!("SSH tunnel task exiting");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_is_22() {
        assert_eq!(default_ssh_port(), 22);
    }

    #[test]
    fn split_jump_host_bracketed_ipv6() {
        // Bracketed IPv6 endpoints survive the last-colon split with the
        // brackets intact, on both sides of the port.
        assert_eq!(split_jump_host("[::1]:22"), ("[::1]", 22));
        assert_eq!(
            split_jump_host("[2001:db8::1]:2222"),
            ("[2001:db8::1]", 2222)
        );
    }

    #[test]
    fn split_jump_host_plain_and_default() {
        assert_eq!(
            split_jump_host("bastion.example.com:2222"),
            ("bastion.example.com", 2222)
        );
        assert_eq!(
            split_jump_host("bastion.example.com"),
            ("bastion.example.com", 22)
        );
    }

    #[test]
    fn tunnel_error_display_ssh() {
        let err = TunnelError::Ssh(2, "connection refused".into());
        assert_eq!(
            err.to_string(),
            "hop 2: SSH tunnel error: connection refused"
        );
    }

    #[test]
    fn tunnel_error_display_auth() {
        let err = TunnelError::Auth(0, "bad credentials".into());
        assert_eq!(
            err.to_string(),
            "hop 0: SSH tunnel auth failed: bad credentials"
        );
    }

    #[test]
    fn tunnel_error_display_bind() {
        let err = TunnelError::Bind(1, "address in use".into());
        assert_eq!(
            err.to_string(),
            "hop 1: SSH tunnel bind failed: address in use"
        );
    }

    #[test]
    fn tunnel_error_display_key() {
        let err = TunnelError::Key(0, "invalid format".into());
        assert_eq!(
            err.to_string(),
            "hop 0: SSH tunnel key error: invalid format"
        );
    }

    #[test]
    fn jump_host_serde_roundtrip() {
        let host = JumpHost {
            hostname: "bastion.example.com".into(),
            port: 2222,
            username: "admin".into(),
            password: Some("secret".into()),
            private_key: None,
            host_key: None,
        };
        let json = serde_json::to_string(&host).unwrap();
        let deserialized: JumpHost = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.hostname, "bastion.example.com");
        assert_eq!(deserialized.port, 2222);
        assert_eq!(deserialized.username, "admin");
        assert_eq!(deserialized.password.as_deref(), Some("secret"));
        assert!(deserialized.private_key.is_none());
    }

    #[test]
    fn jump_host_default_port_deserialized() {
        let json = r#"{"hostname":"h","username":"u"}"#;
        let host: JumpHost = serde_json::from_str(json).unwrap();
        assert_eq!(host.port, 22);
        assert!(host.password.is_none());
        assert!(host.private_key.is_none());
        assert!(host.host_key.is_none());
    }

    #[test]
    fn jump_host_optional_fields_skipped_when_none() {
        let host = JumpHost {
            hostname: "h".into(),
            port: 22,
            username: "u".into(),
            password: None,
            private_key: None,
            host_key: None,
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(!json.contains("password"));
        assert!(!json.contains("private_key"));
        assert!(!json.contains("host_key"));
    }

    #[test]
    fn jump_host_info_serialization() {
        let info = JumpHostInfo {
            hostname: "jumphost.local".into(),
            port: 22,
            username: "user".into(),
            host_key_fingerprint: Some("SHA256:abc123".into()),
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("jumphost.local"));
        assert!(json.contains("SHA256:abc123"));
    }

    #[test]
    fn jump_host_info_fingerprint_skipped_when_none() {
        let info = JumpHostInfo {
            hostname: "h".into(),
            port: 22,
            username: "u".into(),
            host_key_fingerprint: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        assert!(!json.contains("fingerprint"));
    }

    #[test]
    fn fingerprint_openssh_key_invalid_input() {
        let result = fingerprint_openssh_key("not-a-valid-key");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid host key"));
    }

    #[test]
    fn fingerprint_openssh_key_empty_string() {
        let result = fingerprint_openssh_key("");
        assert!(result.is_err());
    }

    #[test]
    fn normalize_host_key_fingerprint_passthrough() {
        assert_eq!(
            normalize_host_key("SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog").unwrap(),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn normalize_host_key_lowercase_fingerprint_prefix() {
        assert_eq!(normalize_host_key("sha256:abc").unwrap(), "SHA256:abc");
    }

    #[test]
    fn normalize_host_key_openssh_public_key() {
        assert_eq!(
            normalize_host_key(
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILagOJFgwaMNhBWQINinKOXmqS4Gh5NgxgriXwdOoINJ"
            )
            .unwrap(),
            "SHA256:ldyiXa1JQakitNU5tErauu8DvWQ1dZ7aXu+rm7KQuog"
        );
    }

    #[test]
    fn normalize_host_key_invalid_input() {
        assert!(normalize_host_key("not-a-key").is_err());
        assert!(normalize_host_key("").is_err());
    }

    #[test]
    fn normalize_host_key_empty_fingerprint_prefix() {
        assert_eq!(normalize_host_key("SHA256:").unwrap(), "SHA256:");
    }

    #[test]
    fn normalize_host_key_trims_whitespace() {
        assert_eq!(normalize_host_key("  SHA256:abc  ").unwrap(), "SHA256:abc");
    }

    #[test]
    fn tunnel_config_fields() {
        let config = TunnelConfig {
            jump_host: "10.0.0.1".into(),
            jump_port: 22,
            jump_username: "tunnel".into(),
            jump_password: Some("p".into()),
            jump_private_key: None,
            target_host: "192.168.1.100".into(),
            target_port: 3389,
            expected_host_key: None,
            known_hosts_path: None,
        };
        assert_eq!(config.jump_host, "10.0.0.1");
        assert_eq!(config.target_port, 3389);
        assert!(config.expected_host_key.is_none());
    }

    #[test]
    fn tunnel_handler_with_no_expected_key_is_tofu() {
        let handler = TunnelHandler {
            expected_key: None,
            hop_index: 0,
            jump_host: "test.host".into(),
            known_hosts_path: None,
        };
        assert!(handler.expected_key.is_none());
        assert_eq!(handler.hop_index, 0);
    }

    #[test]
    fn tunnel_handler_with_expected_key() {
        let handler = TunnelHandler {
            expected_key: Some("ssh-ed25519 AAAA...".into()),
            hop_index: 1,
            jump_host: "bastion".into(),
            known_hosts_path: None,
        };
        assert!(handler.expected_key.is_some());
        assert_eq!(handler.hop_index, 1);
    }
}
