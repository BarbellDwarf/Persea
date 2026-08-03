//! RADIUS auth provider — authenticates users against a RADIUS server.
//!
//! Implements RFC 2865 (RADIUS) with PAP authentication and Access-Challenge
//! handling for MFA flows. Communicates over UDP to the RADIUS server.

use async_trait::async_trait;
use md5::Md5;
use sha2::Digest;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::Duration;

use crate::auth_provider::{AuthRequest, AuthResult, AuthProvider, Capabilities};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// RADIUS authentication protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthProtocol {
    /// Password Authentication Protocol (simplest, cleartext over RADIUS).
    Pap,
    /// Challenge-Handshake Authentication Protocol.
    Chap,
    /// Microsoft CHAP version 2.
    MsChapV2,
}

impl Default for AuthProtocol {
    fn default() -> Self {
        Self::Pap
    }
}

/// Provider mode — whether RADIUS is the primary authenticator or an MFA step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RadiusMode {
    /// RADIUS is the primary authentication method.
    Primary,
    /// RADIUS is used as a second factor (MFA) after primary auth.
    Mfa,
}

impl Default for RadiusMode {
    fn default() -> Self {
        Self::Primary
    }
}

/// Configuration for the RADIUS auth provider.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct RadiusConfig {
    /// RADIUS server hostname or IP.
    pub hostname: String,
    /// RADIUS server port (standard: 1812).
    #[serde(default = "default_port")]
    pub port: u16,
    /// Shared secret for RADIUS communication.
    pub shared_secret: String,
    /// Request timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Number of retries on timeout.
    #[serde(default = "default_retries")]
    pub retries: u32,
    /// NAS identifier string.
    #[serde(default = "default_nas_identifier")]
    pub nas_identifier: String,
    /// NAS IP address (reported to RADIUS server).
    pub nas_ip: Option<String>,
    /// Authentication protocol.
    #[serde(default)]
    pub auth_protocol: AuthProtocol,
    /// Provider mode (primary or MFA).
    #[serde(default)]
    pub mode: RadiusMode,
}

fn default_port() -> u16 {
    1812
}
fn default_timeout_secs() -> u64 {
    5
}
fn default_retries() -> u32 {
    3
}
fn default_nas_identifier() -> String {
    "persea".into()
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            hostname: "127.0.0.1".into(),
            port: default_port(),
            shared_secret: String::new(),
            timeout_secs: default_timeout_secs(),
            retries: default_retries(),
            nas_identifier: default_nas_identifier(),
            nas_ip: None,
            auth_protocol: AuthProtocol::default(),
            mode: RadiusMode::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// RADIUS packet constants and types
// ---------------------------------------------------------------------------

const CODE_ACCESS_REQUEST: u8 = 1;
const CODE_ACCESS_ACCEPT: u8 = 2;
const CODE_ACCESS_REJECT: u8 = 3;
const CODE_ACCESS_CHALLENGE: u8 = 11;

const ATTR_USER_NAME: u8 = 1;
const ATTR_USER_PASSWORD: u8 = 2;
const ATTR_NAS_IP_ADDRESS: u8 = 4;
const ATTR_NAS_PORT: u8 = 5;
const ATTR_STATE: u8 = 24;
const ATTR_REPLY_MESSAGE: u8 = 18;
const ATTR_NAS_IDENTIFIER: u8 = 32;

const MAX_PACKET_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// RADIUS packet builder and parser
// ---------------------------------------------------------------------------

/// A single RADIUS attribute (type + value bytes).
#[derive(Debug, Clone)]
struct RadiusAttribute {
    r#type: u8,
    value: Vec<u8>,
}

impl RadiusAttribute {
    fn new(r#type: u8, value: Vec<u8>) -> Self {
        Self { r#type, value }
    }

    /// Encode to wire format: type (1 byte) + length (1 byte) + value.
    fn encode(&self) -> Vec<u8> {
        let len = 1 + 1 + self.value.len(); // type + len + value
        let mut out = Vec::with_capacity(len);
        out.push(self.r#type);
        out.push(len as u8);
        out.extend_from_slice(&self.value);
        out
    }

    /// Total wire length (including type and length bytes).
    fn wire_len(&self) -> usize {
        2 + self.value.len()
    }
}

/// Parse attributes from a slice (after the 20-byte RADIUS header).
fn parse_attributes(data: &[u8]) -> Vec<RadiusAttribute> {
    let mut attrs = Vec::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let r#type = data[i];
        let len = data[i + 1] as usize;
        if len < 2 || i + len > data.len() {
            break;
        }
        let value = data[i + 2..i + len].to_vec();
        attrs.push(RadiusAttribute::new(r#type, value));
        i += len;
    }
    attrs
}

/// PAP password encryption per RFC 2865 §5.2.
///
/// The password is padded to a multiple of 16 bytes with null bytes, then
/// each 16-byte block is XORed with MD5(shared_secret || previous_block).
/// The first block uses the Request Authenticator as the "previous block".
fn pap_encrypt_password(password: &str, shared_secret: &[u8], request_auth: &[u8; 16]) -> Vec<u8> {
    let pw = password.as_bytes();
    let padded_len = ((pw.len() + 15) / 16) * 16;
    let mut padded = vec![0u8; padded_len];
    padded[..pw.len()].copy_from_slice(pw);

    let mut encrypted = Vec::with_capacity(padded_len);
    let mut prev = *request_auth;

    for chunk in padded.chunks(16) {
        // MD5(shared_secret || prev)
        let mut hasher = <Md5 as sha2::Digest>::new();
        hasher.update(shared_secret);
        hasher.update(prev);
        let key = hasher.finalize();

        // XOR
        let mut block = [0u8; 16];
        for (i, &b) in chunk.iter().enumerate() {
            block[i] = b ^ key[i];
        }
        prev = block;
        encrypted.extend_from_slice(&block);
    }

    encrypted
}

/// Verify Response Authenticator per RFC 2865 §4.2.
///
/// ResponseAuth = MD5(code + id + length + RequestAuth + response_attributes + shared_secret)
fn verify_response_authenticator(
    response: &[u8],
    request_auth: &[u8; 16],
    shared_secret: &[u8],
) -> bool {
    if response.len() < 20 {
        return false;
    }
    let mut hasher = <Md5 as sha2::Digest>::new();
    // code + id + length (first 4 bytes)
    hasher.update(&response[..4]);
    // Request Authenticator (bytes 4..20)
    hasher.update(request_auth);
    // response attributes (bytes 20..end)
    hasher.update(&response[20..]);
    // shared secret
    hasher.update(shared_secret);
    let computed = hasher.finalize();

    // Compare against stored Response Authenticator (bytes 4..20)
    computed[..] == response[4..20]
}

/// Build an Access-Request packet.
///
/// Returns (packet_bytes, request_authenticator).
fn build_access_request(
    id: u8,
    username: &str,
    password: &str,
    shared_secret: &[u8],
    nas_identifier: &str,
    nas_ip: Option<&Ipv4Addr>,
    state: Option<&[u8]>,
) -> (Vec<u8>, [u8; 16]) {
    // Generate random 16-byte Request Authenticator
    let request_auth = {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf);
        buf
    };

    let mut attributes: Vec<RadiusAttribute> = Vec::new();

    // User-Name (type 1)
    attributes.push(RadiusAttribute::new(
        ATTR_USER_NAME,
        username.as_bytes().to_vec(),
    ));

    // User-Password (type 2) — PAP encrypted
    if !password.is_empty() {
        let encrypted = pap_encrypt_password(password, shared_secret, &request_auth);
        attributes.push(RadiusAttribute::new(ATTR_USER_PASSWORD, encrypted));
    }

    // NAS-IP-Address (type 4) — 4 bytes, big-endian
    if let Some(ip) = nas_ip {
        attributes.push(RadiusAttribute::new(
            ATTR_NAS_IP_ADDRESS,
            ip.octets().to_vec(),
        ));
    }

    // NAS-Port (type 5) — port 22 for SSH-like, 3389 for RDP-like; use 0
    attributes.push(RadiusAttribute::new(ATTR_NAS_PORT, vec![0, 0, 0, 0]));

    // NAS-Identifier (type 32)
    attributes.push(RadiusAttribute::new(
        ATTR_NAS_IDENTIFIER,
        nas_identifier.as_bytes().to_vec(),
    ));

    // State (type 24) — for continuing an Access-Challenge exchange
    if let Some(s) = state {
        attributes.push(RadiusAttribute::new(ATTR_STATE, s.to_vec()));
    }

    // Calculate total length: 20-byte header + all attributes
    let attr_len: usize = attributes.iter().map(|a| a.wire_len()).sum();
    let total_len = 20 + attr_len;

    // Build packet
    let mut packet = Vec::with_capacity(total_len);
    packet.push(CODE_ACCESS_REQUEST); // code
    packet.push(id); // identifier
    packet.push((total_len >> 8) as u8); // length high
    packet.push((total_len & 0xFF) as u8); // length low
    packet.extend_from_slice(&request_auth); // authenticator (16 bytes)

    for attr in &attributes {
        packet.extend_from_slice(&attr.encode());
    }

    (packet, request_auth)
}

/// Parse a RADIUS response and extract attributes.
fn parse_response(data: &[u8]) -> Option<(u8, Vec<RadiusAttribute>)> {
    if data.len() < 20 {
        return None;
    }
    let code = data[0];
    let length = ((data[2] as usize) << 8) | (data[3] as usize);
    if length > data.len() || length < 20 {
        return None;
    }
    let attrs = parse_attributes(&data[20..length]);
    Some((code, attrs))
}

/// Find the first attribute of a given type in a list.
fn find_attribute(attrs: &[RadiusAttribute], r#type: u8) -> Option<&[u8]> {
    attrs.iter().find(|a| a.r#type == r#type).map(|a| a.value.as_slice())
}

// ---------------------------------------------------------------------------
// ChallengeStore — tracks in-flight Access-Challenge exchanges
// ---------------------------------------------------------------------------

/// State for an in-flight RADIUS Access-Challenge (e.g., token prompt).
#[derive(Debug, Clone)]
pub struct RadiusChallenge {
    /// State attribute from the RADIUS server (for continuing the exchange).
    pub state: Vec<u8>,
    /// The username being authenticated.
    pub username: String,
    /// Challenge message to display to the user.
    pub challenge_message: String,
    /// When the challenge was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Thread-safe store for pending RADIUS challenges.
///
/// Follows the same pattern as [`crate::auth::WsTicketStore`] — keyed by a
/// random challenge ID, auto-expires after a configurable TTL.
#[derive(Debug, Clone)]
pub struct ChallengeStore {
    inner: Arc<Mutex<HashMap<String, RadiusChallenge>>>,
    ttl_secs: u64,
}

impl ChallengeStore {
    /// Create a new challenge store with the given TTL.
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl_secs,
        }
    }

    /// Insert a challenge and return its ID.
    pub async fn insert(&self, challenge: RadiusChallenge) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        self.inner.lock().await.insert(id.clone(), challenge);
        id
    }

    /// Retrieve and remove a challenge by ID (if not expired).
    pub async fn take(&self, id: &str) -> Option<RadiusChallenge> {
        let mut map = self.inner.lock().await;
        if let Some(ch) = map.remove(id) {
            let age = (chrono::Utc::now() - ch.created_at).num_seconds() as u64;
            if age < self.ttl_secs {
                return Some(ch);
            }
        }
        None
    }

    /// Number of pending challenges.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Whether the store is empty.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RadiusClient — UDP transport
// ---------------------------------------------------------------------------

/// Low-level RADIUS client that handles UDP transport.
struct RadiusClient {
    server_addr: SocketAddr,
    shared_secret: Vec<u8>,
    timeout: Duration,
    retries: u32,
}

impl RadiusClient {
    fn new(config: &RadiusConfig) -> Self {
        let ip: Ipv4Addr = config
            .hostname
            .parse()
            .unwrap_or(Ipv4Addr::new(127, 0, 0, 1));
        Self {
            server_addr: SocketAddr::new(IpAddr::V4(ip), config.port),
            shared_secret: config.shared_secret.as_bytes().to_vec(),
            timeout: Duration::from_secs(config.timeout_secs),
            retries: config.retries,
        }
    }

    /// Send an Access-Request and receive the response.
    ///
    /// Returns (response_code, response_attributes, request_authenticator).
    fn send_access_request(
        &self,
        id: u8,
        username: &str,
        password: &str,
        nas_identifier: &str,
        nas_ip: Option<&Ipv4Addr>,
        state: Option<&[u8]>,
    ) -> Result<(u8, Vec<RadiusAttribute>, [u8; 16]), String> {
        let (packet, request_auth) = build_access_request(
            id,
            username,
            password,
            &self.shared_secret,
            nas_identifier,
            nas_ip,
            state,
        );

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("UDP bind failed: {e}"))?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| format!("set_read_timeout failed: {e}"))?;

        let mut last_err = String::new();
        for attempt in 0..=self.retries {
            socket
                .send_to(&packet, self.server_addr)
                .map_err(|e| format!("UDP send failed: {e}"))?;

            let mut buf = [0u8; MAX_PACKET_SIZE];
            match socket.recv_from(&mut buf) {
                Ok((n, _addr)) => {
                    let response = &buf[..n];
                    // Verify Response Authenticator
                    if !verify_response_authenticator(response, &request_auth, &self.shared_secret) {
                        tracing::warn!(
                            attempt,
                            "RADIUS response authenticator verification failed"
                        );
                        last_err = "Response authenticator verification failed".into();
                        continue;
                    }

                    if let Some((code, attrs)) = parse_response(response) {
                        return Ok((code, attrs, request_auth));
                    } else {
                        last_err = "Failed to parse RADIUS response".into();
                    }
                }
                Err(e) => {
                    tracing::debug!(attempt, error = %e, "RADIUS UDP recv timeout/error");
                    last_err = format!("UDP recv error: {e}");
                }
            }

            if attempt < self.retries {
                tracing::debug!(attempt, "Retrying RADIUS request");
            }
        }

        Err(last_err)
    }
}

// ---------------------------------------------------------------------------
// RadiusProvider
// ---------------------------------------------------------------------------

/// RADIUS authentication provider.
pub struct RadiusProvider {
    config: RadiusConfig,
    client: RadiusClient,
    challenge_store: ChallengeStore,
    /// Monotonically increasing packet ID.
    next_id: std::sync::atomic::AtomicU8,
}

impl RadiusProvider {
    /// Create a new RADIUS provider.
    pub fn new(config: RadiusConfig) -> Self {
        let client = RadiusClient::new(&config);
        Self {
            config,
            client,
            challenge_store: ChallengeStore::new(300), // 5 min challenge TTL
            next_id: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// Access the challenge store (for continuing Access-Challenge flows).
    pub fn challenge_store(&self) -> &ChallengeStore {
        &self.challenge_store
    }

    /// Config reference.
    pub fn config(&self) -> &RadiusConfig {
        &self.config
    }

    /// Build the NAS identifier bytes for RADIUS attribute 32.
    fn nas_identifier_bytes(&self) -> Vec<u8> {
        self.config.nas_identifier.as_bytes().to_vec()
    }

    /// Build the NAS-IP-Address attribute (type 4) if configured.
    fn nas_ip_bytes(&self) -> Option<Vec<u8>> {
        self.config.nas_ip.as_ref().and_then(|ip| {
            ip.parse::<std::net::Ipv4Addr>().ok().map(|addr| {
                addr.octets().to_vec()
            })
        })
    }

    /// Get next packet ID (wraps at 255).
    fn next_packet_id(&self) -> u8 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Extract a printable Reply-Message from attributes, if present.
    fn extract_reply_message(attrs: &[RadiusAttribute]) -> Option<String> {
        find_attribute(attrs, ATTR_REPLY_MESSAGE).map(|v| {
            String::from_utf8_lossy(v).to_string()
        })
    }
}

#[async_trait]
impl AuthProvider for RadiusProvider {
    fn id(&self) -> &str {
        "radius"
    }

    fn capabilities(&self) -> Capabilities {
        match self.config.mode {
            RadiusMode::Primary => Capabilities::AUTHENTICATE,
            RadiusMode::Mfa => Capabilities::MFA,
        }
    }

    async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        let username = match &request.username {
            Some(u) if !u.is_empty() => u.clone(),
            _ => return AuthResult::Failure("No username provided".into()),
        };
        let password = request.password.as_deref().unwrap_or("");
        let nas_ip = self.config.nas_ip.as_ref().and_then(|ip| ip.parse::<Ipv4Addr>().ok());

        // Check if this is a continuation of an Access-Challenge (MFA response)
        if let Some(callback) = &request.callback_params {
            if let Some(challenge_id) = callback.get("challenge_id") {
                let response_value = callback.get("response").cloned().unwrap_or_default();

                // Retrieve the stored challenge state
                let challenge = match self.challenge_store.take(challenge_id).await {
                    Some(ch) => ch,
                    None => return AuthResult::Failure("Challenge expired or not found".into()),
                };

                // Send Access-Request with State attribute and response
                let id = self.next_packet_id();
                match self.client.send_access_request(
                    id,
                    &challenge.username,
                    &response_value,
                    &self.config.nas_identifier,
                    nas_ip.as_ref(),
                    Some(&challenge.state),
                ) {
                    Ok((code, attrs, _)) => match code {
                        CODE_ACCESS_ACCEPT => {
                            let display_name = Self::extract_reply_message(&attrs)
                                .unwrap_or_else(|| challenge.username.clone());
                            AuthResult::Success {
                                subject: challenge.username,
                                display_name,
                                groups: Vec::new(),
                                role: None,
                            }
                        }
                        CODE_ACCESS_REJECT => {
                            let msg = Self::extract_reply_message(&attrs)
                                .unwrap_or_else(|| "Access rejected".into());
                            AuthResult::Failure(msg)
                        }
                        CODE_ACCESS_CHALLENGE => {
                            // Another challenge — store and return for client
                            let state = find_attribute(&attrs, ATTR_STATE)
                                .unwrap_or_default()
                                .to_vec();
                            let msg = Self::extract_reply_message(&attrs)
                                .unwrap_or_default();
                            let ch = RadiusChallenge {
                                state,
                                username: challenge.username,
                                challenge_message: msg,
                                created_at: chrono::Utc::now(),
                            };
                            let id = self.challenge_store.insert(ch).await;
                            AuthResult::Unavailable(format!("challenge:{id}"))
                        }
                        other => {
                            AuthResult::Failure(format!("Unexpected RADIUS response code: {other}"))
                        }
                    },
                    Err(e) => {
                        tracing::error!(error = %e, "RADIUS request failed during challenge response");
                        AuthResult::Unavailable(format!("RADIUS error: {e}"))
                    }
                }
            } else {
                // Normal authentication (no challenge context)
                self.do_authenticate(&username, password, nas_ip.as_ref())
                    .await
            }
        } else {
            self.do_authenticate(&username, password, nas_ip.as_ref())
                .await
        }
    }

    fn has_inline_login_form(&self) -> bool {
        true
    }
}

impl RadiusProvider {
    /// Perform a standard PAP authentication against the RADIUS server.
    async fn do_authenticate(
        &self,
        username: &str,
        password: &str,
        nas_ip: Option<&Ipv4Addr>,
    ) -> AuthResult {
        let id = self.next_packet_id();
        // Clone owned data for spawn_blocking (needs 'static)
        let client = RadiusClient::new(&self.config);
        let username_owned = username.to_string();
        let password_owned = password.to_string();
        let nas_id = self.config.nas_identifier.clone();
        let nas_ip_owned = nas_ip.copied();
        let username_for_log = username_owned.clone();

        // Run the blocking UDP I/O in a blocking thread
        let result = tokio::task::spawn_blocking(move || {
            client.send_access_request(id, &username_owned, &password_owned, &nas_id, nas_ip_owned.as_ref(), None)
        })
        .await;

        match result {
            Ok(Ok((code, attrs, _request_auth))) => match code {
                CODE_ACCESS_ACCEPT => {
                    let display_name = Self::extract_reply_message(&attrs)
                        .unwrap_or_else(|| username_for_log.clone());
                    tracing::info!(username = %username_for_log, "RADIUS authentication successful");
                    AuthResult::Success {
                        subject: username_for_log,
                        display_name,
                        groups: Vec::new(),
                        role: None,
                    }
                }
                CODE_ACCESS_REJECT => {
                    let msg = Self::extract_reply_message(&attrs)
                        .unwrap_or_else(|| "Access rejected by RADIUS server".into());
                    tracing::info!(username = %username_for_log, reason = %msg, "RADIUS authentication rejected");
                    AuthResult::Failure(msg)
                }
                CODE_ACCESS_CHALLENGE => {
                    // Store the challenge state for continuation
                    let state = find_attribute(&attrs, ATTR_STATE)
                        .unwrap_or_default()
                        .to_vec();
                    let msg = Self::extract_reply_message(&attrs)
                        .unwrap_or_default();
                    let ch = RadiusChallenge {
                        state,
                        username: username_for_log.clone(),
                        challenge_message: msg.clone(),
                        created_at: chrono::Utc::now(),
                    };
                    let challenge_id = self.challenge_store.insert(ch).await;
                    tracing::info!(
                        username = %username_for_log,
                        challenge_id = %challenge_id,
                        "RADIUS access-challenge initiated"
                    );
                    // Return Unavailable with the challenge ID so the client
                    // can re-authenticate with challenge_id in callback_params.
                    AuthResult::Unavailable(format!("challenge:{challenge_id}"))
                }
                other => {
                    tracing::warn!(code = other, "Unexpected RADIUS response code");
                    AuthResult::Failure(format!("Unexpected RADIUS response code: {other}"))
                }
            },
            Ok(Err(e)) => {
                tracing::error!(error = %e, "RADIUS request failed");
                AuthResult::Unavailable(format!("RADIUS error: {e}"))
            }
            Err(e) => {
                tracing::error!(error = %e, "RADIUS task panicked");
                AuthResult::Unavailable(format!("RADIUS internal error: {e}"))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radius_config_defaults() {
        let cfg = RadiusConfig::default();
        assert_eq!(cfg.hostname, "127.0.0.1");
        assert_eq!(cfg.port, 1812);
        assert_eq!(cfg.timeout_secs, 5);
        assert_eq!(cfg.retries, 3);
        assert_eq!(cfg.nas_identifier, "persea");
        assert_eq!(cfg.auth_protocol, AuthProtocol::Pap);
        assert_eq!(cfg.mode, RadiusMode::Primary);
    }

    #[test]
    fn radius_provider_capabilities_primary() {
        let provider = RadiusProvider::new(RadiusConfig::default());
        assert_eq!(provider.id(), "radius");
        assert!(provider.capabilities().contains(Capabilities::AUTHENTICATE));
        assert!(!provider.capabilities().contains(Capabilities::MFA));
    }

    #[test]
    fn radius_provider_capabilities_mfa() {
        let config = RadiusConfig {
            mode: RadiusMode::Mfa,
            ..Default::default()
        };
        let provider = RadiusProvider::new(config);
        assert!(provider.capabilities().contains(Capabilities::MFA));
        assert!(!provider.capabilities().contains(Capabilities::AUTHENTICATE));
    }

    #[tokio::test]
    async fn radius_provider_fails_without_username() {
        let provider = RadiusProvider::new(RadiusConfig::default());
        let result = provider.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[tokio::test]
    async fn radius_provider_unavailable_on_connection_refused() {
        let config = RadiusConfig {
            hostname: "127.0.0.1".into(),
            port: 19999, // unlikely to be open
            timeout_secs: 1,
            retries: 0,
            ..Default::default()
        };
        let provider = RadiusProvider::new(config);
        let req = AuthRequest {
            username: Some("test".into()),
            password: Some("pass".into()),
            ..Default::default()
        };
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Unavailable(_)));
    }

    #[test]
    fn radius_provider_has_inline_login_form() {
        let provider = RadiusProvider::new(RadiusConfig::default());
        assert!(provider.has_inline_login_form());
    }

    #[test]
    fn nas_identifier_bytes() {
        let provider = RadiusProvider::new(RadiusConfig::default());
        assert_eq!(provider.nas_identifier_bytes(), b"persea");
    }

    #[test]
    fn nas_ip_bytes_none_when_unset() {
        let provider = RadiusProvider::new(RadiusConfig::default());
        assert!(provider.nas_ip_bytes().is_none());
    }

    #[test]
    fn nas_ip_bytes_some_when_set() {
        let config = RadiusConfig {
            nas_ip: Some("10.0.0.1".into()),
            ..Default::default()
        };
        let provider = RadiusProvider::new(config);
        assert_eq!(provider.nas_ip_bytes(), Some(vec![10, 0, 0, 1]));
    }

    #[test]
    fn challenge_store_insert_and_take() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = ChallengeStore::new(60);
            let ch = RadiusChallenge {
                state: vec![1, 2, 3],
                username: "alice".into(),
                challenge_message: "Enter token".into(),
                created_at: chrono::Utc::now(),
            };
            let id = store.insert(ch).await;
            assert_eq!(store.len().await, 1);

            let taken = store.take(&id).await;
            assert!(taken.is_some());
            assert_eq!(taken.unwrap().username, "alice");
            assert_eq!(store.len().await, 0);

            // Taking again returns None.
            assert!(store.take(&id).await.is_none());
        });
    }

    #[test]
    fn challenge_store_expired() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let store = ChallengeStore::new(0); // 0 second TTL = always expired
            let ch = RadiusChallenge {
                state: vec![1],
                username: "bob".into(),
                challenge_message: "expired".into(),
                created_at: chrono::Utc::now() - chrono::Duration::seconds(1),
            };
            let id = store.insert(ch).await;
            assert!(store.take(&id).await.is_none());
        });
    }

    #[test]
    fn config_serialization_roundtrip() {
        let cfg = RadiusConfig {
            hostname: "radius.example.com".into(),
            port: 1813,
            shared_secret: "s3cret".into(),
            timeout_secs: 10,
            retries: 5,
            nas_identifier: "my-nas".into(),
            nas_ip: Some("192.168.1.1".into()),
            auth_protocol: AuthProtocol::MsChapV2,
            mode: RadiusMode::Mfa,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let back: RadiusConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.hostname, "radius.example.com");
        assert_eq!(back.port, 1813);
        assert_eq!(back.auth_protocol, AuthProtocol::MsChapV2);
        assert_eq!(back.mode, RadiusMode::Mfa);
    }

    #[test]
    fn pap_encrypt_decrypt_roundtrip() {
        let secret = b"sharedsecret";
        let mut request_auth = [0u8; 16];
        use rand::RngExt;
        rand::rng().fill(&mut request_auth);

        let password = "hello123";
        let encrypted = pap_encrypt_password(password, secret, &request_auth);

        // Verify we can XOR back to get the original password
        let mut prev = request_auth;
        let mut decrypted = Vec::new();
        for chunk in encrypted.chunks(16) {
            let mut hasher = <Md5 as sha2::Digest>::new();
            hasher.update(secret);
            hasher.update(prev);
            let key = hasher.finalize();

            let mut block = [0u8; 16];
            for (i, &b) in chunk.iter().enumerate() {
                block[i] = b ^ key[i];
            }
            prev = block;
            decrypted.extend_from_slice(&block);
        }

        // Trim null padding
        let trimmed = &decrypted[..password.len()];
        assert_eq!(trimmed, password.as_bytes());
    }

    #[test]
    fn build_access_request_format() {
        let secret = b"testsecret";
        let mut request_auth = [0u8; 16];
        use rand::RngExt;
        rand::rng().fill(&mut request_auth);

        let (packet, _ra) = build_access_request(
            42,
            "alice",
            "password123",
            secret,
            "nas1",
            None,
            None,
        );

        // Check header
        assert_eq!(packet[0], CODE_ACCESS_REQUEST); // code
        assert_eq!(packet[1], 42); // id
        let length = ((packet[2] as usize) << 8) | (packet[3] as usize);
        assert_eq!(length, packet.len());
        assert!(length >= 20); // At least header

        // Parse attributes
        let attrs = parse_attributes(&packet[20..]);
        assert!(!attrs.is_empty());

        // Should have User-Name
        let user_name = find_attribute(&attrs, ATTR_USER_NAME).unwrap();
        assert_eq!(user_name, b"alice");

        // Should have User-Password (encrypted, not cleartext)
        let user_pw = find_attribute(&attrs, ATTR_USER_PASSWORD).unwrap();
        assert_ne!(user_pw, b"password123");
        assert!(!user_pw.is_empty());

        // Should have NAS-Identifier
        let nas_id = find_attribute(&attrs, ATTR_NAS_IDENTIFIER).unwrap();
        assert_eq!(nas_id, b"nas1");
    }

    #[test]
    fn response_authenticator_verification() {
        let secret = b"mysecret";
        let request_auth = [0x01; 16];

        // Build a fake Access-Accept response
        let attrs_data: Vec<u8> = vec![ATTR_REPLY_MESSAGE, 5, b'O', b'K', 0];
        let total_len = 20 + attrs_data.len();

        let mut response = Vec::with_capacity(total_len);
        response.push(CODE_ACCESS_ACCEPT);
        response.push(1); // id
        response.push((total_len >> 8) as u8);
        response.push((total_len & 0xFF) as u8);
        response.extend_from_slice(&request_auth); // placeholder
        response.extend_from_slice(&attrs_data);

        // Compute correct Response Authenticator
        let mut hasher = <Md5 as sha2::Digest>::new();
        hasher.update(&response[..4]);
        hasher.update(request_auth);
        hasher.update(&attrs_data);
        hasher.update(secret);
        let resp_auth = hasher.finalize();
        response[4..20].copy_from_slice(&resp_auth);

        assert!(verify_response_authenticator(&response, &request_auth, secret));
    }
}
