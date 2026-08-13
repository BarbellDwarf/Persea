//! TOML configuration loading and defaults.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Canonical per-protocol session defaults (admin Settings → Session →
/// Session defaults).
///
/// These are the hardcoded values the session creation path used before
/// per-protocol global defaults existed, so an unset key changes nothing.
/// The settings API (`src/api/settings.rs`) seeds the admin page from this
/// table and the session creation path (`src/session/create.rs`) falls
/// back to it when a key is unset. Precedence at session creation:
/// entry/request value > stored global default > this code default.
///
/// Values are the canonical string forms the settings API persists:
/// "true"/"false" for booleans, plain numbers, or the raw string for
/// enums (RDP security).
pub const PROTOCOL_DEFAULT_KEYS: &[(&str, &str)] = &[
    // RDP
    ("default_rdp_width", "1920"),
    ("default_rdp_height", "1080"),
    ("default_rdp_dpi", "96"),
    ("default_rdp_security", "any"),
    ("default_rdp_h264", "true"),
    ("default_rdp_gfx", "true"),
    ("default_rdp_drive", "false"),
    // SSH
    ("default_ssh_width", "1920"),
    ("default_ssh_height", "1080"),
    // VNC
    ("default_vnc_color_depth", "24"),
    ("default_vnc_disable_copy", "false"),
    ("default_vnc_disable_paste", "false"),
];

/// TLS settings for the HTTPS listener and the guacd connection (`[tls]`).
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    /// Path to server TLS certificate (PEM). Required for HTTPS serving.
    pub cert_path: Option<PathBuf>,
    /// Path to server TLS private key (PEM). Required for HTTPS serving.
    pub key_path: Option<PathBuf>,
    /// Path to guacd's TLS certificate (PEM). When set, persea connects to guacd over TLS.
    /// This is independent of server HTTPS — you can use guacd TLS without serving HTTPS.
    pub guacd_cert_path: Option<PathBuf>,
    /// Whether to set the Secure attribute on session cookies. Defaults to true
    /// when TLS is enabled. Set to false when using self-signed certs — browsers
    /// block Secure cookies over connections with invalid certificates, which
    /// breaks login even after clicking through the cert warning.
    #[serde(default = "default_secure_cookies")]
    pub secure_cookies: bool,
}

/// OpenID Connect provider settings (`[oidc]`).
#[derive(Deserialize, Clone)]
pub struct OidcConfig {
    /// OIDC issuer discovery URL, e.g. "https://auth.example.com/realms/corp".
    pub issuer_url: String,
    /// Client id registered with the identity provider.
    pub client_id: String,
    /// OIDC client secret. May be set in config.toml or via the
    /// `OIDC_CLIENT_SECRET` environment variable; the env var wins when
    /// both are present. Validated at startup to be non-empty when
    /// `[oidc]` is configured (see Config::load).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Callback URL the provider redirects to after sign-in; must match
    /// the registered redirect URI.
    pub redirect_uri: String,
    /// Role assigned to OIDC users whose groups map to no role.
    /// Default: "operator".
    #[serde(default = "default_oidc_default_role")]
    pub default_role: String,
    /// Name of the OIDC claim containing group memberships (default: "groups").
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Extra OIDC scopes to request beyond openid/email/profile (e.g. ["groups"]).
    #[serde(default)]
    pub extra_scopes: Vec<String>,
    /// Skip TLS certificate verification for OIDC provider connections.
    /// WARNING: Only use this for debugging — disabling verification exposes
    /// client_secret and tokens to MITM attacks.
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Path to a custom CA certificate (PEM) for verifying the OIDC provider.
    /// Use this when your identity provider uses a private or internal CA.
    pub ca_cert: Option<String>,
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field("redirect_uri", &self.redirect_uri)
            .field("default_role", &self.default_role)
            .field("groups_claim", &self.groups_claim)
            .field("extra_scopes", &self.extra_scopes)
            .field("tls_skip_verify", &self.tls_skip_verify)
            .field("ca_cert", &self.ca_cert)
            .finish()
    }
}

fn default_oidc_default_role() -> String {
    "operator".into()
}

fn default_groups_claim() -> String {
    "groups".into()
}

/// Vault/OpenBao KV v2 backend configuration. Used for `[vault]` and the
/// optional `[vault_shared]`/`[vault_local]` overrides in [`Config`].
#[derive(Deserialize, Clone)]
pub struct VaultConfig {
    /// Vault server URL, e.g. "https://vault.example.com:8200".
    pub addr: String,
    /// KV secrets engine mount path. Default: "secret".
    #[serde(default = "default_vault_mount")]
    pub mount: String,
    /// Base path under the mount where persea stores its entries.
    /// Default: "persea".
    #[serde(default = "default_vault_base_path")]
    pub base_path: String,
    /// AppRole role id for authentication; the matching secret id comes
    /// from the environment at startup.
    pub role_id: String,
    /// Vault namespace applied to requests (Vault Enterprise).
    pub namespace: Option<String>,
    /// Instance name for instance-scoped address book entries.
    /// Entries under `<base_path>/shared/` are visible to all instances.
    /// Entries under `<base_path>/instance/<instance_name>/` are specific to this instance.
    /// If not set, only shared entries are used.
    pub instance_name: Option<String>,
    /// Skip TLS certificate verification for the Vault connection.
    /// Only use this for development with self-signed certificates.
    #[serde(default)]
    pub tls_skip_verify: bool,
    /// Path to a custom CA certificate (PEM) for verifying the Vault server.
    /// Use this when Vault/OpenBao uses a private or self-signed CA.
    pub ca_cert: Option<String>,
    /// Path to a client certificate (PEM) for mTLS authentication to Vault.
    pub client_cert: Option<String>,
    /// Path to the client private key (PEM) for mTLS authentication to Vault.
    pub client_key: Option<String>,
}

impl std::fmt::Debug for VaultConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultConfig")
            .field("addr", &self.addr)
            .field("mount", &self.mount)
            .field("base_path", &self.base_path)
            .field("role_id", &"[REDACTED]")
            .field("namespace", &self.namespace)
            .field("instance_name", &self.instance_name)
            .field("tls_skip_verify", &self.tls_skip_verify)
            .field("ca_cert", &self.ca_cert)
            .field("client_cert", &self.client_cert)
            .field(
                "client_key",
                &self.client_key.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Drive and file-transfer settings for RDP sessions and LUKS containers
/// (`[drive]`).
#[derive(Debug, Deserialize, Clone)]
pub struct DriveConfig {
    /// Enable drive/file transfer for sessions. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Base directory for per-session drive storage (RDP) or mount point for LUKS.
    /// Each RDP session gets a subdirectory: `<drive_path>/<session_id>/`.
    #[serde(default = "default_drive_path")]
    pub drive_path: PathBuf,
    /// Display name shown in the remote session's file browser.
    #[serde(default = "default_drive_name")]
    pub drive_name: String,
    /// Allow file download from the remote session. Default: true.
    #[serde(default = "default_true")]
    pub allow_download: bool,
    /// Allow file upload to the remote session. Default: true.
    #[serde(default = "default_true")]
    pub allow_upload: bool,
    /// Auto-delete session drive directories after session ends. Default: true.
    #[serde(default = "default_true")]
    pub cleanup_on_close: bool,
    /// Delay in seconds before cleaning up drive dirs (0 = immediate). Default: 0.
    #[serde(default)]
    #[allow(dead_code)]
    pub retention_secs: u64,
    /// LUKS container device/file path (e.g. "/opt/persea/drives.luks").
    /// When set (along with luks_key_path), persea manages LUKS open/close lifecycle.
    pub luks_device: Option<PathBuf>,
    /// Device-mapper name for the LUKS volume. Default: "persea-drives".
    #[serde(default = "default_luks_name")]
    pub luks_name: String,
    /// Vault KV path for the LUKS encryption key (e.g. "persea/luks-key").
    /// The secret must have a "key" field containing the passphrase.
    pub luks_key_path: Option<String>,
}

fn default_drive_path() -> PathBuf {
    PathBuf::from("./drives")
}

fn default_drive_name() -> String {
    "Shared Drive".into()
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_luks_name() -> String {
    "persea-drives".into()
}

impl Default for DriveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            drive_path: default_drive_path(),
            drive_name: default_drive_name(),
            allow_download: true,
            allow_upload: true,
            cleanup_on_close: true,
            retention_secs: 0,
            luks_device: None,
            luks_name: default_luks_name(),
            luks_key_path: None,
        }
    }
}

/// Session recording settings (`[recording]`).
#[derive(Debug, Deserialize, Clone)]
pub struct RecordingConfig {
    /// Path for recording files. Overrides top-level `recording_path`.
    #[serde(default = "default_recording_path")]
    pub path: PathBuf,
    /// Whether recording is enabled globally. Default: true.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Delete oldest recordings when disk usage exceeds this percent. 0 = disabled.
    #[serde(default = "default_max_disk_percent")]
    pub max_disk_percent: u8,
    /// Keep at most this many recordings globally. 0 = unlimited. Default: 1000.
    #[serde(default = "default_max_recordings")]
    pub max_recordings: u32,
    /// How often (in seconds) to run the rotation check. Default: 300 (5 min).
    #[serde(default = "default_rotation_interval_secs")]
    pub rotation_interval_secs: u64,
    /// Directory guacd writes SSH typescript (raw terminal text) files to
    /// (#159). When unset, no typescript is recorded. This is a guacd-side
    /// path: the guacd process must be able to write here. Applies to all
    /// SSH sessions, independent of the graphical (.guac) recording above.
    #[serde(default)]
    pub typescript_path: Option<PathBuf>,
    /// Base filename template for the typescript. guacd itself does NOT
    /// substitute tokens in this name (it uses it verbatim and appends a
    /// numeric suffix to avoid collisions), so persea expands its own
    /// brace tokens before passing it on: `{user}`, `{connection}`
    /// (address-book entry name, falls back to hostname), `{host}`,
    /// `{date}` (UTC YYYYMMDD), `{time}` (UTC HHMMSS), `{session}` (short
    /// session id). Substituted values are sanitised to `[A-Za-z0-9_-]`.
    /// Defaults to `{connection}-{user}-{date}-{time}` when unset.
    #[serde(default)]
    pub typescript_name: Option<String>,
    /// Ask guacd to create `typescript_path` if it doesn't already exist.
    #[serde(default)]
    pub create_typescript_path: bool,
    /// Encrypt recording files at rest using the storage encryption key.
    /// Default: true when `[storage].encryption_key` is set, false otherwise.
    #[serde(default)]
    pub encrypt_at_rest: Option<bool>,
}

fn default_max_recordings() -> u32 {
    1000
}

fn default_max_disk_percent() -> u8 {
    80
}

fn default_rotation_interval_secs() -> u64 {
    300
}

impl Default for RecordingConfig {
    fn default() -> Self {
        Self {
            path: default_recording_path(),
            enabled: true,
            max_disk_percent: default_max_disk_percent(),
            max_recordings: default_max_recordings(),
            rotation_interval_secs: default_rotation_interval_secs(),
            typescript_path: None,
            typescript_name: None,
            create_typescript_path: false,
            encrypt_at_rest: None,
        }
    }
}

/// VDI (Docker container) configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct VdiConfig {
    /// Enable VDI sessions. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Docker socket path. Default: "/var/run/docker.sock".
    #[serde(default = "default_docker_socket")]
    pub docker_socket: String,
    /// Default CPU limit for containers (fractional cores, e.g. 2.0). 0 = no limit.
    #[serde(default)]
    pub default_cpu_limit: f64,
    /// Default memory limit for containers in MB. 0 = no limit.
    #[serde(default)]
    pub default_memory_limit: u64,
    /// Seconds to wait for xrdp to become ready in a new container. Default: 30.
    #[serde(default = "default_ready_timeout_secs")]
    pub ready_timeout_secs: u64,
    /// First localhost port Docker may bind VDI RDP to. Unset = Docker chooses any random port.
    #[serde(default)]
    pub port_range_start: Option<u16>,
    /// Last localhost port Docker may bind VDI RDP to. Unset = Docker chooses any random port.
    #[serde(default)]
    pub port_range_end: Option<u16>,
    /// Optional script called when a VDI container's mapped RDP port should be
    /// prepared or torn down. Called as:
    ///   <script> up <port> <container_id> <container_name>
    ///   <script> down <port> <container_id> <container_name>
    #[serde(default)]
    pub container_hook_script: Option<String>,
    /// Seconds to wait for the VDI container hook script. Default: 10.
    #[serde(default = "default_container_hook_timeout_secs")]
    pub container_hook_timeout_secs: u64,
    /// Minutes a container persists after last session disconnect. Default: 60.
    /// Containers are kept running for reconnection. Set to 0 for immediate removal.
    #[serde(default = "default_idle_timeout_mins")]
    pub idle_timeout_mins: u64,
    /// Allowed Docker images (exact match). Empty = allow all.
    #[serde(default)]
    pub allowed_images: Vec<String>,
    /// Base directory for persistent user home directories.
    /// Each user gets `{home_base}/{username}` mounted as `/home/{username}` in the container.
    /// Unset = no persistent storage (ephemeral home dirs).
    #[serde(default)]
    pub home_base: Option<String>,
}

fn default_docker_socket() -> String {
    "/var/run/docker.sock".into()
}

fn default_ready_timeout_secs() -> u64 {
    30
}

fn default_container_hook_timeout_secs() -> u64 {
    10
}

fn default_idle_timeout_mins() -> u64 {
    60
}

fn default_vault_mount() -> String {
    "secret".into()
}

fn default_user_credentials_scope() -> String {
    "local".into()
}

fn default_vault_base_path() -> String {
    "persea".into()
}

/// Authentication chain configuration (`[auth]`).
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AuthConfig {
    /// Ordered list of primary auth methods. Example: ["ldap", "database", "oidc"]
    #[serde(default = "default_auth_methods")]
    pub methods: Vec<String>,
    /// LDAP/AD provider settings; active when "ldap" is in
    /// [`methods`](AuthConfig::methods).
    pub ldap: Option<crate::auth_providers::ldap::LdapConfig>,
    /// RADIUS provider settings; active when "radius" is in
    /// [`methods`](AuthConfig::methods).
    pub radius: Option<crate::auth_providers::radius::RadiusConfig>,
    /// SAML 2.0 provider settings; active when "saml" is in
    /// [`methods`](AuthConfig::methods).
    pub saml: Option<crate::auth_providers::saml::SamlConfig>,
    /// TOTP second-factor configuration.
    pub totp: Option<AuthTotpConfig>,
    /// When true, the username/password from password-based logins (database,
    /// LDAP, RADIUS, SAML) is stored encrypted and reused as fallback
    /// credentials for connection entries that carry none of their own.
    /// OIDC/SSO logins have no password to pass through. Off by default.
    #[serde(default)]
    pub pass_login_credentials: bool,
}

/// TOTP configuration for the auth chain (maps to `[auth.totp]` in TOML).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthTotpConfig {
    /// Issuer name shown in authenticator apps.
    #[serde(default = "default_totp_issuer")]
    pub issuer: String,
    /// TOTP digits (default: 6).
    #[serde(default = "default_totp_digits")]
    pub digits: u8,
    /// TOTP period in seconds (default: 30).
    #[serde(default = "default_totp_period")]
    pub period: u16,
    /// Clock skew tolerance (how many periods ahead/behind to accept).
    #[serde(default = "default_totp_skew")]
    pub skew: u8,
    /// Enforcement policy: "Off", "AdminsOnly", or "All".
    #[serde(default)]
    pub enforcement: crate::totp::TotpEnforcement,
}

fn default_totp_issuer() -> String {
    "persea".into()
}
fn default_totp_digits() -> u8 {
    6
}
fn default_totp_period() -> u16 {
    30
}
fn default_totp_skew() -> u8 {
    1
}
fn default_secure_cookies() -> bool {
    true
}

/// Password policy configuration (`[password]`).
///
/// Enforced at every point a password is set: the admin users API, the CLI
/// `create-user` command, and the account password-change endpoint.
#[derive(Debug, Deserialize, Clone)]
pub struct PasswordConfig {
    /// Minimum password length in characters. Default: 15.
    #[serde(default = "default_password_min_length")]
    pub min_length: usize,
    /// Number of recent password hashes kept per user for reuse rejection.
    /// A new password matching any of the last `history` passwords is
    /// rejected. Default: 5. Set to 0 to disable reuse checking.
    #[serde(default = "default_password_history")]
    pub history: usize,
}

fn default_password_min_length() -> usize {
    15
}

fn default_password_history() -> usize {
    5
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: default_password_min_length(),
            history: default_password_history(),
        }
    }
}

impl Default for AuthTotpConfig {
    fn default() -> Self {
        Self {
            issuer: default_totp_issuer(),
            digits: default_totp_digits(),
            period: default_totp_period(),
            skew: default_totp_skew(),
            enforcement: crate::totp::TotpEnforcement::Off,
        }
    }
}

fn default_auth_methods() -> Vec<String> {
    vec!["database".to_string()]
}

/// Fully-resolved server configuration.
///
/// Built by [`Config::load`] from layered sources: built-in defaults, an
/// optional TOML file, then `PERSEA_` environment variables. Call
/// [`Config::validate`] at startup so fatal misconfiguration fails fast
/// instead of surfacing as runtime errors.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Address the HTTP server listens on, e.g. "127.0.0.1:8089".
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// guacd address, e.g. "127.0.0.1:4822".
    #[serde(default = "default_guacd_addr")]
    pub guacd_addr: String,

    /// Deprecated: top-level recording path. Use `[recording].path`.
    #[serde(default)]
    pub recording_path: Option<PathBuf>,

    /// Directory for static assets; also holds the themes/ subdirectory.
    #[serde(default = "default_static_path")]
    pub static_path: PathBuf,

    /// SQLite database file path, used when `db_url` is unset.
    #[serde(default = "default_db_path")]
    pub db_path: PathBuf,

    /// Seconds a session may stay in "pending" before it is reaped.
    /// Default: 60.
    #[serde(default = "default_session_timeout_secs")]
    pub session_pending_timeout_secs: u64,

    /// Maximum duration for active sessions in seconds. Default: 8 hours.
    /// Sessions exceeding this duration are automatically terminated.
    #[serde(default = "default_session_max_duration_secs")]
    pub session_max_duration_secs: u64,

    /// Idle timeout for active sessions in seconds. Default: 1800 (30 min).
    /// Sessions whose `last_active` timestamp is older than this are
    /// terminated by the reaper with an "idle-timeout" status. Set to 0 to
    /// disable idle reaping (max duration still applies). `last_active` is
    /// refreshed by client-initiated session traffic (WebSocket input).
    #[serde(default = "default_session_idle_timeout_secs")]
    pub session_idle_timeout_secs: u64,

    /// OIDC auth session TTL in seconds. Default: 86400 (24 hours).
    /// After this period, users must re-authenticate via OIDC.
    #[serde(default = "default_auth_session_ttl_secs")]
    pub auth_session_ttl_secs: u64,

    /// Session history retention in days. Default: 90. Set to 0 to keep forever.
    #[serde(default = "default_session_history_retention_days")]
    pub session_history_retention_days: u32,

    /// Path to the Xvnc binary used for web browser sessions.
    /// Default: "Xvnc".
    #[serde(default = "default_xvnc_path")]
    pub xvnc_path: String,

    /// Path to the Chromium binary used for web browser sessions.
    /// Default: "chromium".
    #[serde(default = "default_chromium_path")]
    pub chromium_path: String,

    /// First X display number Xvnc may use. Default: 100.
    #[serde(default = "default_display_range_start")]
    pub display_range_start: u32,

    /// Last X display number Xvnc may use. Default: 199.
    #[serde(default = "default_display_range_end")]
    pub display_range_end: u32,

    /// First port of the Chromium DevTools (CDP) port range. Default: 9200.
    #[serde(default = "default_cdp_port_range_start")]
    pub cdp_port_range_start: u16,

    /// Last port of the Chromium DevTools (CDP) port range. Default: 9299.
    #[serde(default = "default_cdp_port_range_end")]
    pub cdp_port_range_end: u16,

    /// Seconds a web-session login script may run before it is killed.
    /// Default: 120.
    #[serde(default = "default_login_script_timeout_secs")]
    pub login_script_timeout_secs: u64,

    /// Directory holding login scripts for web sessions; entries reference
    /// scripts by filename. Default: /opt/persea/scripts.
    #[serde(default = "default_login_scripts_dir")]
    pub login_scripts_dir: String,

    /// Site title shown in the browser tab and page headers.
    #[serde(default = "default_site_title")]
    pub site_title: String,

    /// SSH terminal scrollback lines (default: 10000).
    #[serde(default = "default_ssh_scrollback")]
    pub ssh_scrollback: u32,

    /// When true, SSH sessions start under a tmux wrapper
    /// (`tmux attach-session -d || tmux new-session`) instead of a plain
    /// shell, so a reconnecting user takes over the remote session and any
    /// stale client left attached by an abrupt disconnect is kicked.
    /// Default: false (plain shell, no behavior change).
    #[serde(default = "default_false")]
    pub ssh_tmux_detach: bool,

    /// CIDR allowlist for SSH session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub ssh_allowed_networks: Vec<String>,

    /// CIDR allowlist for RDP session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub rdp_allowed_networks: Vec<String>,

    /// CIDR allowlist for VNC session targets. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub vnc_allowed_networks: Vec<String>,

    /// CIDR allowlist for web session URL hosts. Default: localhost only.
    #[serde(default = "default_localhost_networks")]
    pub web_allowed_networks: Vec<String>,

    /// Maximum concurrent sessions (all types). Default: 500. Set to 0 for unlimited.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Maximum concurrent sessions per user. Default: 50. Set to 0 for unlimited.
    #[serde(default = "default_max_sessions_per_user")]
    pub max_sessions_per_user: usize,

    /// Maximum concurrent viewers per session (share-token joins). Default: 10.
    /// Set to 0 for unlimited. The owner connection is not counted.
    #[serde(default = "default_max_viewers")]
    pub max_viewers: u32,

    /// Seconds to keep completed/error/expired sessions in memory before cleanup.
    /// Default: 300 (5 minutes). The session history in SQLite is not affected.
    #[serde(default = "default_session_cleanup_delay_secs")]
    pub session_cleanup_delay_secs: u64,

    /// Graceful shutdown timeout in seconds. Default: 30.
    /// After receiving SIGTERM/SIGINT, the server stops accepting new connections
    /// and waits this long for active sessions to drain before forcing exit.
    #[serde(default = "default_shutdown_timeout_secs")]
    pub shutdown_timeout_secs: u64,

    /// Enable API rate limiting. Default: false.
    /// When behind a reverse proxy (HAProxy, nginx) or access gateway (KnockNoc),
    /// rate limiting is typically handled upstream and not needed here.
    #[serde(default)]
    pub rate_limit: bool,

    /// Trusted proxy CIDRs. When the connecting IP matches one of these,
    /// the first address in X-Forwarded-For is used as the real client IP.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// Default scope for a NEW per-user credential variable when more than one
    /// Vault backend is configured: "local" (default — stays on this instance's
    /// Vault, survives a central outage) or "shared" (propagates fleet-wide via
    /// `[vault_shared]`). Ignored in a single-Vault deployment: with one store
    /// the shared/local distinction is meaningless and the UI hides the toggle.
    #[serde(default = "default_user_credentials_scope")]
    pub user_credentials_default_scope: String,

    /// Authentication provider chain settings (`[auth]`).
    pub auth: Option<AuthConfig>,
    /// TLS settings for HTTPS and the guacd connection (`[tls]`).
    pub tls: Option<TlsConfig>,
    /// OIDC provider settings; enables OIDC login when present (`[oidc]`).
    pub oidc: Option<OidcConfig>,
    /// Primary/default Vault backend. Serves any address-book scope that does
    /// not have a dedicated backend below, and is the home of unscoped secrets
    /// (the LUKS key). A bare `[vault]` with no overrides behaves exactly as a
    /// single-Vault deployment always has.
    pub vault: Option<VaultConfig>,
    /// Optional dedicated backend for the `shared` scope (e.g. a central,
    /// fleet-wide Vault). When set, shared-scope folders/entries route here
    /// instead of `[vault]`. Secret ID via `VAULT_SHARED_SECRET_ID`.
    pub vault_shared: Option<VaultConfig>,
    /// Optional dedicated backend for the `instance` (local) scope (e.g. a
    /// per-host Vault that stays reachable during a central outage). When set,
    /// instance-scope folders/entries route here. Secret ID via
    /// `VAULT_LOCAL_SECRET_ID`.
    pub vault_local: Option<VaultConfig>,
    /// Drive and file-transfer settings (`[drive]`).
    pub drive: Option<DriveConfig>,
    /// Theme overrides applied to the active preset (`[theme]`).
    pub theme: Option<ThemeConfig>,
    /// Session recording settings (`[recording]`).
    pub recording: Option<RecordingConfig>,
    /// VDI desktop container settings (`[vdi]`).
    pub vdi: Option<VdiConfig>,
    /// VMware vSphere integration for VM inventory and OS-aware protocol routing.
    pub vsphere: Option<crate::vsphere::VsphereConfig>,
    /// RDP-wide defaults for entries that leave fields unset (`[rdp]`).
    pub rdp: Option<RdpConfig>,
    /// Optional SQLx database URL for multi-backend support (PostgreSQL,
    /// MySQL, or SQLite via SQLx). When set, `DbPool` is initialised and
    /// made available via Extension. The existing rusqlite `Db` continues
    /// to work alongside it.
    pub db_url: Option<String>,

    /// Stable identifier for this instance, used by the shared HA
    /// session registry to mark session ownership. Must be unique
    /// across the fleet; defaults to `hostname-pid`. Recording rotation and
    /// the session reaper only operate on sessions/files this instance owns.
    #[serde(default = "default_instance_id")]
    pub instance_id: String,

    /// Public base URL of this instance (scheme + host + port), e.g.
    /// "https://persea-1.example.com". When a session created here is
    /// joined from another instance, browsers are redirected to this URL
    /// so the owner instance can serve the guacd stream. Unset: remote
    /// joins to this instance's sessions are rejected with a clear error.
    #[serde(default)]
    pub ha_base_url: Option<String>,

    /// Storage backend for the address book (connections, credentials).
    /// When `backend = "db"` (default), the DB stores folder/entry metadata
    /// and encrypted credentials. When `backend = "vault"`, metadata stays
    /// in DB but credentials are stored in Vault.
    pub storage: Option<StorageConfig>,
    /// Password policy (`[password]`): minimum length + reuse history.
    /// Materialised in `default_toml()` so absent sections cannot silently
    /// reset the defaults.
    #[serde(default = "default_password_config")]
    pub password: Option<PasswordConfig>,
    /// Desktop shell bridge settings (`[desktop]`). Materialised in
    /// `default_toml()` so an absent section cannot silently reset the
    /// defaults.
    #[serde(default = "default_desktop_config")]
    pub desktop: Option<DesktopConfig>,
    /// Session behaviour (`[session]`): connection reason enforcement.
    /// Materialised in `default_toml()` so an absent section cannot
    /// silently reset the defaults.
    #[serde(default = "default_session_config")]
    pub session: Option<SessionConfig>,
    /// Server version update checking (`[updates]`). Materialised in
    /// `default_toml()` so an absent section cannot silently reset the
    /// defaults.
    #[serde(default = "default_updates_config")]
    pub updates: Option<UpdatesConfig>,
}

fn default_password_config() -> Option<PasswordConfig> {
    Some(PasswordConfig::default())
}

/// Session behaviour configuration (`[session]`). Materialised in
/// `default_toml()` so an absent section cannot silently reset the
/// defaults.
#[derive(Debug, Deserialize, Clone)]
pub struct SessionConfig {
    /// Require a connection reason on every session creation. When true,
    /// `POST /api/sessions` (and the address-book connect flow) rejects
    /// creation without a `reason` with a 400 and a clear message. Default
    /// false — reasons stay optional.
    #[serde(default = "default_false")]
    pub reason_required: bool,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            reason_required: default_false(),
        }
    }
}

/// Server version update checking configuration (`[updates]`). Materialised
/// in `default_toml()` so an absent section cannot silently reset the
/// defaults.
#[derive(Debug, Deserialize, Clone)]
pub struct UpdatesConfig {
    /// Check `check_url` on a schedule for a newer persea release. Default:
    /// true. Set false in air-gapped deployments: no network call is ever
    /// made and the admin banner / status endpoint report nothing.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Release-list API URL. Default: the unauthenticated GitHub Releases
    /// API for the persea repository. Internal mirrors (e.g. Gitea) can
    /// point this at their own `/releases/latest` endpoint.
    #[serde(default = "default_update_check_url")]
    pub check_url: String,
    /// Hours between checks. Default: 24.
    #[serde(default = "default_update_check_interval_hours")]
    pub check_interval_hours: u64,
}

fn default_update_check_url() -> String {
    "https://api.github.com/repos/BarbellDwarf/persea/releases/latest".to_string()
}

fn default_update_check_interval_hours() -> u64 {
    24
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            check_url: default_update_check_url(),
            check_interval_hours: default_update_check_interval_hours(),
        }
    }
}

fn default_updates_config() -> Option<UpdatesConfig> {
    Some(UpdatesConfig::default())
}

fn default_session_config() -> Option<SessionConfig> {
    Some(SessionConfig::default())
}

/// Desktop shell bridge configuration (`[desktop]`).
#[derive(Debug, Deserialize, Clone)]
pub struct DesktopConfig {
    /// Allow the Tauri desktop shell to reach this instance over remote IPC.
    /// Default: false. When true, the page CSP `connect-src` additionally
    /// permits the Tauri IPC transports (`tauri://localhost` on macOS/Linux,
    /// `http://ipc.localhost` on Windows) and the desktop bridge script is
    /// served on every page. See config.example.toml for the security note.
    #[serde(default = "default_false")]
    pub allow_bridge: bool,
}

impl Default for DesktopConfig {
    fn default() -> Self {
        Self {
            allow_bridge: default_false(),
        }
    }
}

fn default_desktop_config() -> Option<DesktopConfig> {
    Some(DesktopConfig::default())
}

/// Startup mirror of the `[desktop] allow_bridge` flag, so the security
/// headers middleware and the template renderer can read it without the full
/// config. Initialised once at startup via [`init_allow_bridge`]; reads
/// default to false before that (tests, renders outside the server
/// lifecycle), which matches the config default.
static ALLOW_BRIDGE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Record the `[desktop] allow_bridge` flag at startup. Must be called once
/// after config load; mirrors `SecureCookies::init` (src/csrf.rs).
pub fn init_allow_bridge(allow: bool) {
    let _ = ALLOW_BRIDGE.set(allow);
}

/// Whether the desktop bridge is enabled for this instance. False until
/// [`init_allow_bridge`] ran, which matches the `allow_bridge = false`
/// default.
pub fn allow_bridge_enabled() -> bool {
    ALLOW_BRIDGE.get().copied().unwrap_or(false)
}

/// Storage backend configuration for the address book.
#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// Backend for address book credentials: "db" (default) or "vault".
    #[serde(default = "default_storage_backend")]
    pub backend: String,
    /// Encryption key for DB-stored credentials (required when backend = "db").
    /// 64-character hex string (32 bytes). Generate with: openssl rand -hex 32
    #[serde(default)]
    pub encryption_key: Option<String>,
}

fn default_storage_backend() -> String {
    "db".into()
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            encryption_key: None,
        }
    }
}

/// RDP-wide defaults applied when an address book entry (or ad-hoc
/// connect request) leaves a field unset.
///
/// `default_auth_pkg` picks the NLA/CredSSP authentication package
/// FreeRDP uses. Persea defaults to `"ntlm"` because Kerberos
/// requires a working KDC reachable via DNS, which most deployments
/// don't have, and the failure mode is a silent hang. Override here
/// with `"kerberos"` or `"negotiate"` if your environment actually
/// supports it.
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RdpConfig {
    /// NLA/CredSSP auth package: "ntlm" (default), "kerberos", or
    /// "negotiate".
    pub default_auth_pkg: Option<String>,
    /// Template for the RDP `client-name` parameter sent to guacd per
    /// session: `{user}` is the persea identity that created the session
    /// and `{host}` the reverse-DNS name of the connecting client (the raw
    /// IP when DNS fails or times out). Empty string disables the
    /// parameter, preserving the pre-template behavior.
    pub client_name_template: Option<String>,
}

/// Default `[rdp] client_name_template`: `{user}@{host}`.
pub const DEFAULT_RDP_CLIENT_NAME_TEMPLATE: &str = "{user}@{host}";

/// Fully-resolved theme palette with all 26 color fields.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThemeColors {
    /// Primary action color: buttons, links, active states.
    pub primary: String,
    /// `primary` in its hovered state.
    pub primary_hover: String,
    /// Accent color for highlights and secondary emphasis.
    pub accent: String,
    /// `accent` in its hovered state.
    pub accent_hover: String,
    /// Page background color.
    pub bg: String,
    /// Card and panel background color.
    pub surface: String,
    /// Form input background color.
    pub input: String,
    /// Primary text color.
    pub text: String,
    /// Secondary text color (descriptions, timestamps).
    pub text_muted: String,
    /// Border color for cards, inputs, and dividers.
    pub border: String,
    /// Tertiary text color (labels, metadata).
    pub text_dim: String,
    /// Text color used on top of `primary`.
    pub text_on_primary: String,
    /// Disabled button background color.
    pub btn_disabled: String,
    /// Color for sessions in the "pending" status.
    pub status_pending: String,
    /// Color for sessions in the "active" status.
    pub status_active: String,
    /// Color for sessions in the "completed" status.
    pub status_completed: String,
    /// Color for sessions in the "error" status.
    pub status_error: String,
    /// Color for sessions in the "expired" status.
    pub status_expired: String,
    /// SSH session-type badge background.
    pub type_ssh_bg: String,
    /// SSH session-type badge text.
    pub type_ssh_fg: String,
    /// RDP session-type badge background.
    pub type_rdp_bg: String,
    /// RDP session-type badge text.
    pub type_rdp_fg: String,
    /// VNC session-type badge background.
    pub type_vnc_bg: String,
    /// VNC session-type badge text.
    pub type_vnc_fg: String,
    /// Web session-type badge background.
    pub type_web_bg: String,
    /// Web session-type badge text.
    pub type_web_fg: String,
    /// VDI session-type badge background.
    pub type_vdi_bg: String,
    /// VDI session-type badge text.
    pub type_vdi_fg: String,
    /// Jump-host badge background.
    pub hop_bg: String,
    /// Jump-host badge text.
    pub hop_fg: String,
    /// CSS background-image value (gradient, pattern, or "none").
    #[serde(default = "default_bg_pattern")]
    pub bg_pattern: String,
}

fn default_bg_pattern() -> String {
    "none".into()
}

/// Returns all 6 built-in theme presets.
pub fn builtin_presets() -> Vec<(&'static str, ThemeColors)> {
    vec![
        (
            "dark",
            ThemeColors {
                primary: "#e94560".into(),
                primary_hover: "#c73652".into(),
                accent: "#5bc0be".into(),
                accent_hover: "#4aa3a1".into(),
                bg: "#1a1a2e".into(),
                surface: "#16213e".into(),
                input: "#0f3460".into(),
                text: "#e0e0e0".into(),
                text_muted: "#aaa".into(),
                border: "#333".into(),
                text_dim: "#666".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#555".into(),
                status_pending: "#f0c040".into(),
                status_active: "#5bc0be".into(),
                status_completed: "#888".into(),
                status_error: "#e94560".into(),
                status_expired: "#666".into(),
                type_ssh_bg: "#1b4332".into(),
                type_ssh_fg: "#52b788".into(),
                type_rdp_bg: "#3d1f00".into(),
                type_rdp_fg: "#f0a050".into(),
                type_vnc_bg: "#2d1b4e".into(),
                type_vnc_fg: "#b07ff0".into(),
                type_web_bg: "#1a1a4e".into(),
                type_web_fg: "#7b8ff0".into(),
                type_vdi_bg: "#0e2a2a".into(),
                type_vdi_fg: "#2dd4bf".into(),
                hop_bg: "#1b4332".into(),
                hop_fg: "#52b788".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "light",
            ThemeColors {
                primary: "#2563eb".into(),
                primary_hover: "#1d4ed8".into(),
                accent: "#0d9488".into(),
                accent_hover: "#0f766e".into(),
                bg: "#f8fafc".into(),
                surface: "#fff".into(),
                input: "#f1f5f9".into(),
                text: "#1e293b".into(),
                text_muted: "#64748b".into(),
                border: "#e2e8f0".into(),
                text_dim: "#94a3b8".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#cbd5e1".into(),
                status_pending: "#d97706".into(),
                status_active: "#0d9488".into(),
                status_completed: "#94a3b8".into(),
                status_error: "#dc2626".into(),
                status_expired: "#cbd5e1".into(),
                type_ssh_bg: "#dcfce7".into(),
                type_ssh_fg: "#166534".into(),
                type_rdp_bg: "#ffedd5".into(),
                type_rdp_fg: "#9a3412".into(),
                type_vnc_bg: "#f3e8ff".into(),
                type_vnc_fg: "#6b21a8".into(),
                type_web_bg: "#dbeafe".into(),
                type_web_fg: "#1e40af".into(),
                type_vdi_bg: "#ccfbf1".into(),
                type_vdi_fg: "#0f766e".into(),
                hop_bg: "#dcfce7".into(),
                hop_fg: "#166534".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "high-contrast",
            ThemeColors {
                primary: "#ff6b6b".into(),
                primary_hover: "#ff4444".into(),
                accent: "#00ffcc".into(),
                accent_hover: "#00ddaa".into(),
                bg: "#000".into(),
                surface: "#111".into(),
                input: "#1a1a1a".into(),
                text: "#fff".into(),
                text_muted: "#ccc".into(),
                border: "#555".into(),
                text_dim: "#999".into(),
                text_on_primary: "#000".into(),
                btn_disabled: "#444".into(),
                status_pending: "#ffdd00".into(),
                status_active: "#00ffcc".into(),
                status_completed: "#999".into(),
                status_error: "#ff4444".into(),
                status_expired: "#666".into(),
                type_ssh_bg: "#003300".into(),
                type_ssh_fg: "#00ff66".into(),
                type_rdp_bg: "#332200".into(),
                type_rdp_fg: "#ffaa00".into(),
                type_vnc_bg: "#220033".into(),
                type_vnc_fg: "#cc66ff".into(),
                type_web_bg: "#000033".into(),
                type_web_fg: "#6699ff".into(),
                type_vdi_bg: "#003333".into(),
                type_vdi_fg: "#00ffcc".into(),
                hop_bg: "#003300".into(),
                hop_fg: "#00ff66".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "terminal",
            ThemeColors {
                primary: "#f59e0b".into(),
                primary_hover: "#d97706".into(),
                accent: "#22c55e".into(),
                accent_hover: "#16a34a".into(),
                bg: "#0a0a0a".into(),
                surface: "#141414".into(),
                input: "#1e1e1e".into(),
                text: "#33ff33".into(),
                text_muted: "#22aa22".into(),
                border: "#2a2a2a".into(),
                text_dim: "#186818".into(),
                text_on_primary: "#000".into(),
                btn_disabled: "#333".into(),
                status_pending: "#f59e0b".into(),
                status_active: "#33ff33".into(),
                status_completed: "#22aa22".into(),
                status_error: "#ff3333".into(),
                status_expired: "#186818".into(),
                type_ssh_bg: "#0a200a".into(),
                type_ssh_fg: "#33ff33".into(),
                type_rdp_bg: "#201a0a".into(),
                type_rdp_fg: "#f59e0b".into(),
                type_vnc_bg: "#1a0a20".into(),
                type_vnc_fg: "#cc66ff".into(),
                type_web_bg: "#0a0a20".into(),
                type_web_fg: "#6699ff".into(),
                type_vdi_bg: "#0a2020".into(),
                type_vdi_fg: "#33ffcc".into(),
                hop_bg: "#0a200a".into(),
                hop_fg: "#33ff33".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "nord",
            ThemeColors {
                primary: "#88c0d0".into(),
                primary_hover: "#81a1c1".into(),
                accent: "#a3be8c".into(),
                accent_hover: "#8fbcbb".into(),
                bg: "#2e3440".into(),
                surface: "#3b4252".into(),
                input: "#434c5e".into(),
                text: "#eceff4".into(),
                text_muted: "#d8dee9".into(),
                border: "#4c566a".into(),
                text_dim: "#7b88a1".into(),
                text_on_primary: "#2e3440".into(),
                btn_disabled: "#4c566a".into(),
                status_pending: "#ebcb8b".into(),
                status_active: "#a3be8c".into(),
                status_completed: "#7b88a1".into(),
                status_error: "#bf616a".into(),
                status_expired: "#4c566a".into(),
                type_ssh_bg: "#384838".into(),
                type_ssh_fg: "#a3be8c".into(),
                type_rdp_bg: "#483e38".into(),
                type_rdp_fg: "#ebcb8b".into(),
                type_vnc_bg: "#3e3848".into(),
                type_vnc_fg: "#b48ead".into(),
                type_web_bg: "#384048".into(),
                type_web_fg: "#88c0d0".into(),
                type_vdi_bg: "#2e4040".into(),
                type_vdi_fg: "#8fbcbb".into(),
                hop_bg: "#384838".into(),
                hop_fg: "#a3be8c".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "corporate",
            ThemeColors {
                primary: "#3b82f6".into(),
                primary_hover: "#2563eb".into(),
                accent: "#f97316".into(),
                accent_hover: "#ea580c".into(),
                bg: "#0f172a".into(),
                surface: "#1e293b".into(),
                input: "#334155".into(),
                text: "#f1f5f9".into(),
                text_muted: "#94a3b8".into(),
                border: "#475569".into(),
                text_dim: "#64748b".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#475569".into(),
                status_pending: "#fbbf24".into(),
                status_active: "#34d399".into(),
                status_completed: "#64748b".into(),
                status_error: "#ef4444".into(),
                status_expired: "#475569".into(),
                type_ssh_bg: "#14532d".into(),
                type_ssh_fg: "#4ade80".into(),
                type_rdp_bg: "#431407".into(),
                type_rdp_fg: "#fb923c".into(),
                type_vnc_bg: "#3b0764".into(),
                type_vnc_fg: "#c084fc".into(),
                type_web_bg: "#172554".into(),
                type_web_fg: "#60a5fa".into(),
                type_vdi_bg: "#042f2e".into(),
                type_vdi_fg: "#2dd4bf".into(),
                hop_bg: "#14532d".into(),
                hop_fg: "#4ade80".into(),
                bg_pattern: "none".into(),
            },
        ),
        (
            "jaguar",
            ThemeColors {
                primary: "#d4a853".into(),
                primary_hover: "#b89040".into(),
                accent: "#50c878".into(),
                accent_hover: "#3dab60".into(),
                bg: "#0a100e".into(),
                surface: "#121c18".into(),
                input: "#1a2c26".into(),
                text: "#dce4e0".into(),
                text_muted: "#8a9e96".into(),
                border: "#243830".into(),
                text_dim: "#4a6058".into(),
                text_on_primary: "#0a100e".into(),
                btn_disabled: "#2a3e36".into(),
                status_pending: "#d4a853".into(),
                status_active: "#50c878".into(),
                status_completed: "#5a7068".into(),
                status_error: "#e05050".into(),
                status_expired: "#2a3e36".into(),
                type_ssh_bg: "#0e1e16".into(),
                type_ssh_fg: "#50c878".into(),
                type_rdp_bg: "#1e1a0e".into(),
                type_rdp_fg: "#d4a853".into(),
                type_vnc_bg: "#1a142a".into(),
                type_vnc_fg: "#a080d0".into(),
                type_web_bg: "#0e1a2a".into(),
                type_web_fg: "#6098d0".into(),
                type_vdi_bg: "#0e2420".into(),
                type_vdi_fg: "#50c8a0".into(),
                hop_bg: "#0e1e16".into(),
                hop_fg: "#50c878".into(),
                bg_pattern: "radial-gradient(ellipse at 20% 80%, rgba(80, 200, 120, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 10%, rgba(212, 168, 83, 0.06) 0%, transparent 45%)".into(),
            },
        ),
        (
            "aurora",
            ThemeColors {
                primary: "#3b82f6".into(),
                primary_hover: "#2563eb".into(),
                accent: "#22d3ee".into(),
                accent_hover: "#06b6d4".into(),
                bg: "#0b1120".into(),
                surface: "#111827".into(),
                input: "#1e293b".into(),
                text: "#e2e8f0".into(),
                text_muted: "#94a3b8".into(),
                border: "#1e3a5f".into(),
                text_dim: "#64748b".into(),
                text_on_primary: "#fff".into(),
                btn_disabled: "#334155".into(),
                status_pending: "#f59e0b".into(),
                status_active: "#22d3ee".into(),
                status_completed: "#64748b".into(),
                status_error: "#ef4444".into(),
                status_expired: "#334155".into(),
                type_ssh_bg: "#0d2818".into(),
                type_ssh_fg: "#34d399".into(),
                type_rdp_bg: "#1e1b4b".into(),
                type_rdp_fg: "#818cf8".into(),
                type_vnc_bg: "#2a1f0e".into(),
                type_vnc_fg: "#fbbf24".into(),
                type_web_bg: "#0c2340".into(),
                type_web_fg: "#60a5fa".into(),
                type_vdi_bg: "#042f2e".into(),
                type_vdi_fg: "#2dd4bf".into(),
                hop_bg: "#0d2818".into(),
                hop_fg: "#34d399".into(),
                bg_pattern: "radial-gradient(ellipse at 15% 0%, rgba(59, 130, 246, 0.15) 0%, transparent 50%), radial-gradient(ellipse at 85% 100%, rgba(34, 211, 238, 0.10) 0%, transparent 50%), radial-gradient(ellipse at 50% 50%, rgba(30, 58, 138, 0.12) 0%, transparent 70%)".into(),
            },
        ),
    ]
}

/// Admin-configurable theme overrides (`[theme]`), resolved to a full
/// palette by [`ThemeConfig::resolve`] or [`ThemeConfig::resolve_with`].
#[derive(Debug, Default, Deserialize, Serialize, Clone)]
pub struct ThemeConfig {
    /// Built-in preset name: aurora (default), dark, light, high-contrast,
    /// terminal, nord, corporate, jaguar.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
    /// Overrides the preset's `primary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
    /// Overrides the preset's `primary_hover`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_hover: Option<String>,
    /// Overrides the preset's `accent`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    /// Overrides the preset's `accent_hover`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_hover: Option<String>,
    /// Overrides the preset's `bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bg_color: Option<String>,
    /// Overrides the preset's `surface`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_color: Option<String>,
    /// Overrides the preset's `input`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_color: Option<String>,
    /// Overrides the preset's `text`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    /// Overrides the preset's `text_muted`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_muted: Option<String>,
    /// Overrides the preset's `border`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub border_color: Option<String>,
    /// Overrides the preset's `text_dim`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_dim: Option<String>,
    /// Overrides the preset's `text_on_primary`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_on_primary: Option<String>,
    /// Overrides the preset's `btn_disabled`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub btn_disabled: Option<String>,
    /// Overrides the preset's `status_pending`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_pending: Option<String>,
    /// Overrides the preset's `status_active`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_active: Option<String>,
    /// Overrides the preset's `status_completed`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_completed: Option<String>,
    /// Overrides the preset's `status_error`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_error: Option<String>,
    /// Overrides the preset's `status_expired`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_expired: Option<String>,
    /// Overrides the preset's `type_ssh_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_ssh_bg: Option<String>,
    /// Overrides the preset's `type_ssh_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_ssh_fg: Option<String>,
    /// Overrides the preset's `type_rdp_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_rdp_bg: Option<String>,
    /// Overrides the preset's `type_rdp_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_rdp_fg: Option<String>,
    /// Overrides the preset's `type_vnc_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vnc_bg: Option<String>,
    /// Overrides the preset's `type_vnc_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vnc_fg: Option<String>,
    /// Overrides the preset's `type_web_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_web_bg: Option<String>,
    /// Overrides the preset's `type_web_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_web_fg: Option<String>,
    /// Overrides the preset's `type_vdi_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vdi_bg: Option<String>,
    /// Overrides the preset's `type_vdi_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub type_vdi_fg: Option<String>,
    /// Overrides the preset's `hop_bg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_bg: Option<String>,
    /// Overrides the preset's `hop_fg`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hop_fg: Option<String>,
    /// Overrides the preset's `bg_pattern` (CSS background-image value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bg_pattern: Option<String>,
    /// URL of a custom logo for the header; when set it replaces the site
    /// title mark.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
}

impl ThemeConfig {
    /// Resolve config into a full ThemeColors palette using only the Rust
    /// built-in presets. Convenience wrapper over [`Self::resolve_with`] for
    /// callers that don't have a static_path to load disk themes from
    /// (notably tests). Production code in `main.rs` calls
    /// [`load_themes`] + [`Self::resolve_with`] so user-added `*.toml` files
    /// are honoured.
    #[allow(dead_code)]
    pub fn resolve(&self) -> (String, ThemeColors) {
        let themes: Vec<(String, ThemeColors)> = builtin_presets()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        self.resolve_with(&themes)
    }

    /// Same as [`resolve`], but the preset name is looked up in the supplied
    /// theme set (built-in + disk-loaded). When the `[theme]` config block is
    /// missing or its `preset` field is unset, falls back to `"aurora"`. If
    /// the requested preset is not in the set, the first theme in the set is
    /// used (matches the previous behaviour of `resolve` with `builtin_presets`).
    pub fn resolve_with(&self, themes: &[(String, ThemeColors)]) -> (String, ThemeColors) {
        let preset_name = self.preset.as_deref().unwrap_or("aurora");
        let mut colors = themes
            .iter()
            .find(|(name, _)| name == preset_name)
            .map(|(_, c)| c.clone())
            .unwrap_or_else(|| {
                themes
                    .first()
                    .map(|(_, c)| c.clone())
                    .unwrap_or_else(|| builtin_presets()[0].1.clone())
            });

        // Apply per-field overrides (same as resolve()).
        macro_rules! apply {
            ($field:ident, $src:ident) => {
                if let Some(ref v) = self.$src {
                    colors.$field = v.clone();
                }
            };
            ($field:ident) => {
                if let Some(ref v) = self.$field {
                    colors.$field = v.clone();
                }
            };
        }
        apply!(primary, primary_color);
        apply!(primary_hover);
        apply!(accent, accent_color);
        apply!(accent_hover);
        apply!(bg, bg_color);
        apply!(surface, surface_color);
        apply!(input, input_color);
        apply!(text, text_color);
        apply!(text_muted);
        apply!(border, border_color);
        apply!(text_dim);
        apply!(text_on_primary);
        apply!(btn_disabled);
        apply!(status_pending);
        apply!(status_active);
        apply!(status_completed);
        apply!(status_error);
        apply!(status_expired);
        apply!(type_ssh_bg);
        apply!(type_ssh_fg);
        apply!(type_rdp_bg);
        apply!(type_rdp_fg);
        apply!(type_vnc_bg);
        apply!(type_vnc_fg);
        apply!(type_web_bg);
        apply!(type_web_fg);
        apply!(type_vdi_bg);
        apply!(type_vdi_fg);
        apply!(hop_bg);
        apply!(hop_fg);
        apply!(bg_pattern);

        (preset_name.to_string(), colors)
    }
}

/// Load all themes from disk, merged with the Rust-baked built-ins.
///
/// Built-ins (the eight `aurora`/`dark`/`light`/... presets in [`builtin_presets`])
/// are always returned even if `<static_path>/themes/` is absent, so a fresh
/// install or a misconfigured static_path can never leave persea without
/// any themes. Operators add a new theme by dropping a `<name>.toml` file
/// into `<static_path>/themes/`; the filename (minus extension) is the theme
/// id. A disk theme with the same id as a built-in **overrides** the built-in,
/// so operators can re-brand `aurora` simply by editing `aurora.toml`.
///
/// Malformed or unreadable `.toml` files are skipped with a warning. The
/// returned vector preserves built-in order, with disk-only themes appended
/// in filename order.
/// Strict allowlist for theme names. Mirrors the rules we use for Vault
/// entry names (alphanumeric + `_` + `-`, 1-64 chars). Theme names end up
/// in JSON sent to the frontend picker, in log lines, and as match keys
/// for `[theme] preset = "..."`; this keeps them safe to render unescaped
/// and free of path-traversal / control-character / homoglyph mischief.
fn is_valid_theme_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Load all themes from disk, merged over the built-in presets.
///
/// Built-ins are always returned first, so a missing
/// `<static_path>/themes/` directory is not an error. A disk `<name>.toml`
/// with the same id as a built-in overrides it; new names are appended in
/// filename order. Malformed or unreadable files are skipped with a
/// warning.
pub fn load_themes(static_path: &std::path::Path) -> Vec<(String, ThemeColors)> {
    // Seed with built-ins (always available, in their defined order).
    let mut themes: Vec<(String, ThemeColors)> = builtin_presets()
        .into_iter()
        .map(|(n, c)| (n.to_string(), c))
        .collect();
    let mut index: std::collections::HashMap<String, usize> = themes
        .iter()
        .enumerate()
        .map(|(i, (n, _))| (n.clone(), i))
        .collect();

    let themes_dir = static_path.join("themes");
    let entries = match std::fs::read_dir(&themes_dir) {
        Ok(e) => e,
        Err(_) => {
            // No themes dir; built-ins are still the answer. Not an error.
            return themes;
        }
    };

    // Collect + sort filenames so disk-added themes appear in deterministic order.
    let mut files: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("toml"))
        .collect();
    files.sort();

    for path in files {
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => continue,
        };
        if !is_valid_theme_name(&name) {
            tracing::warn!(
                theme = %name,
                "skipping theme: name must be 1-64 chars of [a-zA-Z0-9_-]"
            );
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(theme = %name, error = %e, "skipping theme: read failed");
                continue;
            }
        };
        let colors: ThemeColors = match toml::from_str(&data) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(theme = %name, error = %e, "skipping theme: parse failed");
                continue;
            }
        };
        match index.get(&name) {
            Some(&i) => themes[i] = (name.clone(), colors), // override built-in
            None => {
                index.insert(name.clone(), themes.len());
                themes.push((name, colors));
            }
        }
    }

    themes
}

fn default_listen_addr() -> String {
    "127.0.0.1:8089".into()
}

fn default_guacd_addr() -> String {
    "127.0.0.1:4822".into()
}

fn default_recording_path() -> PathBuf {
    PathBuf::from("./recordings")
}

fn default_static_path() -> PathBuf {
    PathBuf::from("./static")
}

fn default_db_path() -> PathBuf {
    PathBuf::from("./persea.db")
}

fn default_session_timeout_secs() -> u64 {
    60
}

fn default_session_max_duration_secs() -> u64 {
    8 * 3600 // 8 hours
}

fn default_session_idle_timeout_secs() -> u64 {
    1800 // 30 minutes
}

fn default_max_sessions() -> usize {
    500
}

fn default_max_sessions_per_user() -> usize {
    50
}

fn default_max_viewers() -> u32 {
    10
}

fn default_session_cleanup_delay_secs() -> u64 {
    300 // 5 minutes
}

fn default_shutdown_timeout_secs() -> u64 {
    30
}

fn default_auth_session_ttl_secs() -> u64 {
    86400 // 24 hours
}

fn default_session_history_retention_days() -> u32 {
    90
}

fn default_xvnc_path() -> String {
    "Xvnc".into()
}

fn default_chromium_path() -> String {
    "chromium".into()
}

fn default_display_range_start() -> u32 {
    100
}

fn default_display_range_end() -> u32 {
    199
}

fn default_cdp_port_range_start() -> u16 {
    9200
}

fn default_cdp_port_range_end() -> u16 {
    9299
}

fn default_login_script_timeout_secs() -> u64 {
    120
}

fn default_login_scripts_dir() -> String {
    "/opt/persea/scripts".into()
}

fn default_site_title() -> String {
    "Persea".into()
}

fn default_localhost_networks() -> Vec<String> {
    vec![
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
        "127.0.0.0/8".into(),
        "::1/128".into(),
    ]
}

fn default_loopback_networks() -> Vec<String> {
    vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
}

fn default_ssh_scrollback() -> u32 {
    10000
}

/// Generate default configuration as TOML string for the config crate's layered builder.
fn default_toml() -> String {
    let mut s = String::new();
    s.push_str(&format!("listen_addr = \"{}\"\n", default_listen_addr()));
    s.push_str(&format!("guacd_addr = \"{}\"\n", default_guacd_addr()));
    s.push_str(&format!(
        "static_path = \"{}\"\n",
        default_static_path().to_string_lossy()
    ));
    s.push_str(&format!(
        "db_path = \"{}\"\n",
        default_db_path().to_string_lossy()
    ));
    s.push_str(&format!("instance_id = \"{}\"\n", default_instance_id()));
    s.push_str(&format!(
        "session_pending_timeout_secs = {}\n",
        default_session_timeout_secs()
    ));
    s.push_str(&format!(
        "session_max_duration_secs = {}\n",
        default_session_max_duration_secs()
    ));
    s.push_str(&format!(
        "session_idle_timeout_secs = {}\n",
        default_session_idle_timeout_secs()
    ));
    s.push_str(&format!(
        "auth_session_ttl_secs = {}\n",
        default_auth_session_ttl_secs()
    ));
    s.push_str(&format!(
        "session_history_retention_days = {}\n",
        default_session_history_retention_days()
    ));
    s.push_str(&format!("xvnc_path = \"{}\"\n", default_xvnc_path()));
    s.push_str(&format!(
        "chromium_path = \"{}\"\n",
        default_chromium_path()
    ));
    s.push_str(&format!(
        "display_range_start = {}\n",
        default_display_range_start()
    ));
    s.push_str(&format!(
        "display_range_end = {}\n",
        default_display_range_end()
    ));
    s.push_str(&format!(
        "cdp_port_range_start = {}\n",
        default_cdp_port_range_start()
    ));
    s.push_str(&format!(
        "cdp_port_range_end = {}\n",
        default_cdp_port_range_end()
    ));
    s.push_str(&format!(
        "login_script_timeout_secs = {}\n",
        default_login_script_timeout_secs()
    ));
    s.push_str(&format!(
        "login_scripts_dir = \"{}\"\n",
        default_login_scripts_dir()
    ));
    s.push_str(&format!("site_title = \"{}\"\n", default_site_title()));
    s.push_str(&format!("ssh_scrollback = {}\n", default_ssh_scrollback()));
    s.push_str(&format!("ssh_tmux_detach = {}\n", default_false()));
    s.push_str(&format!("max_sessions = {}\n", default_max_sessions()));
    s.push_str(&format!(
        "max_sessions_per_user = {}\n",
        default_max_sessions_per_user()
    ));
    s.push_str(&format!("max_viewers = {}\n", default_max_viewers()));
    s.push_str(&format!(
        "session_cleanup_delay_secs = {}\n",
        default_session_cleanup_delay_secs()
    ));
    s.push_str(&format!(
        "shutdown_timeout_secs = {}\n",
        default_shutdown_timeout_secs()
    ));
    s.push_str(&format!("rate_limit = {}\n", false));
    s.push_str(&format!(
        "user_credentials_default_scope = \"{}\"\n",
        default_user_credentials_scope()
    ));
    // Vec fields
    s.push_str("ssh_allowed_networks = ");
    s.push_str(&format!("{:?}\n", default_localhost_networks()));
    s.push_str("rdp_allowed_networks = ");
    s.push_str(&format!("{:?}\n", default_localhost_networks()));
    s.push_str("vnc_allowed_networks = ");
    s.push_str(&format!("{:?}\n", default_localhost_networks()));
    s.push_str("web_allowed_networks = ");
    s.push_str(&format!("{:?}\n", default_loopback_networks()));
    s.push_str("trusted_proxies = []\n");
    // [recording] — materialised so the merged config carries the previous
    // defaults (max_recordings=1000, max_disk_percent=80, enabled=true).
    s.push_str("[recording]\n");
    s.push_str(&format!(
        "path = \"{}\"\n",
        default_recording_path().to_string_lossy()
    ));
    s.push_str(&format!("enabled = {}\n", default_true()));
    s.push_str(&format!(
        "max_disk_percent = {}\n",
        default_max_disk_percent()
    ));
    s.push_str(&format!("max_recordings = {}\n", default_max_recordings()));
    s.push_str(&format!(
        "rotation_interval_secs = {}\n",
        default_rotation_interval_secs()
    ));
    // [storage] — backend defaults to "db" when the section is absent.
    s.push_str("[storage]\n");
    s.push_str(&format!("backend = \"{}\"\n", default_storage_backend()));
    // [password] — password policy (min length + reuse history). Materialised
    // so absent sections cannot silently reset the defaults.
    s.push_str("[password]\n");
    s.push_str(&format!("min_length = {}\n", default_password_min_length()));
    s.push_str(&format!("history = {}\n", default_password_history()));
    // [desktop] — desktop shell bridge. Materialised so an absent section
    // cannot silently reset the default (allow_bridge = false).
    s.push_str("[desktop]\n");
    s.push_str(&format!("allow_bridge = {}\n", default_false()));
    // [session] — session behaviour. Materialised so an absent section
    // cannot silently reset the default (reason_required = false).
    s.push_str("[session]\n");
    s.push_str(&format!("reason_required = {}\n", default_false()));
    // [rdp] — RDP-wide settings. Materialised so an absent section cannot
    // silently reset the client-name template default.
    s.push_str("[rdp]\n");
    s.push_str(&format!(
        "client_name_template = \"{}\"\n",
        DEFAULT_RDP_CLIENT_NAME_TEMPLATE
    ));
    s
}

/// Stable per-instance identifier for the HA session registry. Defaults to
/// `hostname-pid`, which is unique across a fleet even when several
/// instances run on the same host (the local HA demo runs two instances on
/// one machine). Operators may set a stable id per host instead; the id
/// must not change across restarts if per-instance recording rotation is
/// expected to follow a restarted instance.
fn default_instance_id() -> String {
    let hostname = {
        #[cfg(unix)]
        {
            let mut buf = [0u8; 256];
            // SAFETY: buf is a valid 256-byte buffer; gethostname never
            // writes past it (it truncates). Returns 0 on success.
            let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
            if rc == 0 {
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                String::from_utf8_lossy(&buf[..end]).into_owned()
            } else {
                "unknown-host".to_string()
            }
        }
        #[cfg(not(unix))]
        {
            std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown-host".to_string())
        }
    };
    format!("{}-{}", hostname, std::process::id())
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            guacd_addr: default_guacd_addr(),
            recording_path: None,
            static_path: default_static_path(),
            db_path: default_db_path(),
            session_pending_timeout_secs: default_session_timeout_secs(),
            session_max_duration_secs: default_session_max_duration_secs(),
            session_idle_timeout_secs: default_session_idle_timeout_secs(),
            auth_session_ttl_secs: default_auth_session_ttl_secs(),
            xvnc_path: default_xvnc_path(),
            chromium_path: default_chromium_path(),
            display_range_start: default_display_range_start(),
            display_range_end: default_display_range_end(),
            cdp_port_range_start: default_cdp_port_range_start(),
            cdp_port_range_end: default_cdp_port_range_end(),
            login_script_timeout_secs: default_login_script_timeout_secs(),
            login_scripts_dir: default_login_scripts_dir(),
            site_title: default_site_title(),
            ssh_allowed_networks: default_localhost_networks(),
            ssh_scrollback: default_ssh_scrollback(),
            ssh_tmux_detach: default_false(),
            rdp_allowed_networks: default_localhost_networks(),
            vnc_allowed_networks: default_localhost_networks(),
            web_allowed_networks: default_loopback_networks(),
            session_history_retention_days: default_session_history_retention_days(),
            max_sessions: default_max_sessions(),
            max_sessions_per_user: default_max_sessions_per_user(),
            max_viewers: default_max_viewers(),
            session_cleanup_delay_secs: default_session_cleanup_delay_secs(),
            shutdown_timeout_secs: default_shutdown_timeout_secs(),
            rate_limit: false,
            trusted_proxies: Vec::new(),
            user_credentials_default_scope: default_user_credentials_scope(),
            tls: None,
            auth: None,
            oidc: None,
            vault: None,
            vault_shared: None,
            vault_local: None,
            drive: None,
            theme: None,
            recording: None,
            vdi: None,
            vsphere: None,
            rdp: None,
            db_url: None,
            instance_id: default_instance_id(),
            ha_base_url: None,
            storage: None,
            password: default_password_config(),
            desktop: default_desktop_config(),
            session: default_session_config(),
            updates: default_updates_config(),
        }
    }
}

fn sanitize_cidr_list(proto: &str, list: &mut Vec<String>) {
    list.retain(|cidr| {
        if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
            eprintln!(
                "WARNING: invalid {}_allowed_networks CIDR '{}', removing",
                proto, cidr
            );
            false
        } else {
            true
        }
    });
}

/// Read and parse a TOML config file, returning a rich error message on failure.
/// The toml crate's Display impl already includes a line:column snippet with a
/// caret pointing at the broken token; we prepend the file path so the message
/// is unambiguous when multiple paths are searched.
impl Config {
    /// Load configuration from defaults, an optional TOML file, and
    /// `PERSEA_` environment variables.
    ///
    /// When an explicit path was given, or `/opt/persea/config.toml`
    /// exists, a broken config is fatal and the process exits with the
    /// parse error. Otherwise the built-in defaults win. Resolves
    /// `OIDC_CLIENT_SECRET` from the environment, fails startup when
    /// `[oidc]` is configured without any secret, and sanitizes CIDR
    /// lists in place.
    pub fn load(path: Option<&str>) -> Self {
        // Note: tracing is initialised later (in run_server), so config-load
        // diagnostics go to stderr directly. Misconfigurations are fatal when
        // the operator pointed us at a specific file — silently falling back
        // to defaults would leave them debugging a "working" server that ignored
        // everything they configured.
        let (path, required) = if let Some(p) = path {
            (Some(p.to_string()), true)
        } else if std::path::Path::new("/opt/persea/config.toml").exists() {
            (Some("/opt/persea/config.toml".to_string()), true)
        } else {
            (None, false)
        };

        // Layer 1: defaults from TOML
        let mut builder = config::Config::builder().add_source(config::File::from_str(
            &default_toml(),
            config::FileFormat::Toml,
        ));

        // Layer 2: config file (if exists). `required(false)` so a missing
        // or unreadable file (e.g. /dev/null in CI) falls back to defaults
        // instead of failing the whole build.
        if let Some(ref p) = path {
            builder =
                builder.add_source(config::File::new(p, config::FileFormat::Toml).required(false));
        }

        // Layer 3: environment variables (PERSEA_ prefix, nested via __)
        builder = builder.add_source(
            config::Environment::with_prefix("PERSEA")
                .separator("__")
                .prefix_separator("_"),
        );

        let mut config = match builder.build() {
            Ok(raw) => match raw.try_deserialize::<Config>() {
                Ok(c) => {
                    if let Some(ref p) = path {
                        eprintln!("[config] Loaded config from {}", p);
                    } else {
                        eprintln!(
                            "[config] No config file found; using built-in defaults + env vars"
                        );
                    }
                    c
                }
                Err(e) => {
                    eprintln!("[config] ERROR: failed to deserialize config:\n{}", e);
                    if required {
                        std::process::exit(1);
                    }
                    Self::default()
                }
            },
            Err(e) => {
                eprintln!("[config] ERROR: failed to build config:\n{}", e);
                if required {
                    std::process::exit(1);
                }
                Self::default()
            }
        };

        // OIDC client_secret resolution. The env var wins over whatever
        // is in the config file, and is the documented way to keep the
        // secret out of TOML on disk. Either source is fine, but at least
        // one must produce a non-empty value when `[oidc]` is present;
        // bug #121 was that the field was non-Optional in serde, so
        // omitting it from config.toml failed parsing before the env var
        // could fill it in.
        if let Some(ref mut oidc) = config.oidc {
            if let Ok(secret) = std::env::var("OIDC_CLIENT_SECRET") {
                if !secret.is_empty() {
                    oidc.client_secret = Some(secret);
                }
            }
            let has_secret = oidc
                .client_secret
                .as_ref()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
            if !has_secret {
                eprintln!(
                    "[config] ERROR: [oidc] is configured but no client_secret was provided.\n\
                     [config]        Set `client_secret = \"...\"` in config.toml, or export\n\
                     [config]        OIDC_CLIENT_SECRET in the persea environment\n\
                     [config]        (e.g. /opt/persea/env)."
                );
                std::process::exit(1);
            }
        }

        // Sanitize mutable config (remove invalid CIDRs, cap out-of-range values)
        config.sanitize();

        config
    }

    /// Validate configuration values. Returns `Err` with a fatal message
    /// if the server cannot start; returns `Ok(warnings)` with non-fatal
    /// advisory messages the caller should print.
    pub fn validate(&self) -> Result<Vec<String>, String> {
        let mut warnings = Vec::new();

        // ── Fatal errors ──────────────────────────────────────────────
        self.listen_addr
            .parse::<std::net::SocketAddr>()
            .map_err(|e| format!("invalid listen_addr '{}': {}", self.listen_addr, e))?;

        // guacd_addr accepts IP:port or hostname:port — validate port is numeric
        match self.guacd_addr.rsplit(':').next() {
            Some(port_str) if port_str.parse::<u16>().is_ok() => {}
            _ => return Err(format!("invalid guacd_addr: {}", self.guacd_addr)),
        }

        // CIDR entries must parse
        for cidr in &self.ssh_allowed_networks {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|e| format!("invalid ssh_allowed_networks CIDR '{}': {}", cidr, e))?;
        }
        for cidr in &self.rdp_allowed_networks {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|e| format!("invalid rdp_allowed_networks CIDR '{}': {}", cidr, e))?;
        }
        for cidr in &self.vnc_allowed_networks {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|e| format!("invalid vnc_allowed_networks CIDR '{}': {}", cidr, e))?;
        }
        for cidr in &self.web_allowed_networks {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|e| format!("invalid web_allowed_networks CIDR '{}': {}", cidr, e))?;
        }
        for cidr in &self.trusted_proxies {
            cidr.parse::<ipnetwork::IpNetwork>()
                .map_err(|e| format!("invalid trusted_proxies CIDR '{}': {}", cidr, e))?;
        }

        if self.display_range_start >= self.display_range_end {
            return Err(format!(
                "display_range_start ({}) must be less than display_range_end ({})",
                self.display_range_start, self.display_range_end
            ));
        }

        if self.session_pending_timeout_secs == 0 {
            return Err("session_pending_timeout_secs must be greater than 0".into());
        }

        if let Some(ref rec) = self.recording {
            if rec.max_disk_percent > 100 {
                return Err(format!(
                    "recording.max_disk_percent ({}) must be <= 100",
                    rec.max_disk_percent
                ));
            }
        }

        // ── Non-fatal warnings ────────────────────────────────────────
        if self
            .recording_path
            .as_ref()
            .filter(|p| !p.as_os_str().is_empty())
            .is_some()
        {
            if self.recording.is_some() {
                warnings.push(
                    "top-level 'recording_path' is deprecated in favour of [recording].path — \
                     the [recording] section takes precedence"
                        .into(),
                );
            } else {
                warnings.push(
                    "top-level 'recording_path' is deprecated; migrate to [recording] section"
                        .into(),
                );
            }
        }

        Ok(warnings)
    }

    /// Sanitize mutable config in place: remove invalid CIDRs, cap out-of-range
    /// values. Called during `Config::load()` before `validate()`.
    pub fn sanitize(&mut self) {
        sanitize_cidr_list("ssh", &mut self.ssh_allowed_networks);
        sanitize_cidr_list("rdp", &mut self.rdp_allowed_networks);
        sanitize_cidr_list("vnc", &mut self.vnc_allowed_networks);
        sanitize_cidr_list("web", &mut self.web_allowed_networks);

        self.trusted_proxies.retain(|cidr| {
            if cidr.parse::<ipnetwork::IpNetwork>().is_err() {
                eprintln!("WARNING: invalid trusted_proxies CIDR '{}', removing", cidr);
                false
            } else {
                true
            }
        });

        if self
            .recording
            .as_ref()
            .is_some_and(|r| r.max_disk_percent > 100)
        {
            eprintln!(
                "WARNING: recording.max_disk_percent ({}) > 100, capping at 100",
                self.recording.as_ref().unwrap().max_disk_percent
            );
            self.recording.as_mut().unwrap().max_disk_percent = 100;
        }
    }

    /// Effective recording path: `[recording].path` overrides top-level
    /// `recording_path`. An explicitly set but empty `recording_path` is
    /// treated as unset.
    pub fn effective_recording_path(&self) -> std::borrow::Cow<'_, std::path::Path> {
        if let Some(ref rec) = self.recording {
            std::borrow::Cow::Borrowed(&rec.path)
        } else if let Some(ref path) = self.recording_path {
            if path.as_os_str().is_empty() {
                std::borrow::Cow::Owned(default_recording_path())
            } else {
                std::borrow::Cow::Borrowed(path)
            }
        } else {
            std::borrow::Cow::Owned(default_recording_path())
        }
    }

    /// SSH typescript recording settings (#159), if `[recording]
    /// typescript_path` is configured. Returns `(path, name, create)`
    /// ready to hand to guacd; `None` means no typescript.
    pub fn ssh_typescript(&self) -> Option<(String, Option<String>, bool)> {
        let rec = self.recording.as_ref()?;
        let path = rec.typescript_path.as_ref()?;
        Some((
            path.to_string_lossy().into_owned(),
            rec.typescript_name.clone(),
            rec.create_typescript_path,
        ))
    }

    /// Whether recording is globally enabled. Defaults to true.
    pub fn recording_enabled(&self) -> bool {
        self.recording.as_ref().is_none_or(|r| r.enabled)
    }

    /// Whether a connection reason is mandatory on session creation
    /// (`[session] reason_required`). Defaults to false.
    pub fn session_reason_required(&self) -> bool {
        self.session
            .as_ref()
            .map(|s| s.reason_required)
            .unwrap_or(false)
    }

    /// Get recording config (or synthesized default that respects legacy `recording_path`).
    pub fn recording_config(&self) -> RecordingConfig {
        match self.recording.clone() {
            Some(r) => r,
            None => RecordingConfig {
                path: self
                    .recording_path
                    .clone()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(default_recording_path),
                ..RecordingConfig::default()
            },
        }
    }

    /// Whether the address book uses DB as the primary credential backend.
    /// Defaults to true when no `[storage]` section is configured.
    pub fn db_storage_backend(&self) -> bool {
        self.storage
            .as_ref()
            .map(|s| s.backend == "db")
            .unwrap_or(true)
    }

    /// Get the encryption key for DB-stored credentials.
    /// Also checks the `PERSEA_STORAGE_KEY` environment variable.
    pub fn storage_encryption_key(&self) -> Option<String> {
        if let Some(ref key) = self
            .storage
            .as_ref()
            .and_then(|s| s.encryption_key.as_ref())
        {
            if !key.is_empty() {
                return Some(key.to_string());
            }
        }
        std::env::var("PERSEA_STORAGE_KEY")
            .ok()
            .filter(|k| !k.is_empty())
    }

    /// Minimum password length enforced by the `[password]` policy.
    /// Default: 15.
    pub fn password_min_length(&self) -> usize {
        self.password
            .as_ref()
            .map(|p| p.min_length)
            .unwrap_or_else(default_password_min_length)
    }

    /// Number of recent password hashes kept per user for reuse rejection.
    /// Default: 5. 0 disables reuse checking.
    pub fn password_history_len(&self) -> usize {
        self.password
            .as_ref()
            .map(|p| p.history)
            .unwrap_or_else(default_password_history)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_presets_exist() {
        let presets = builtin_presets();
        assert!(presets.len() >= 6, "expected at least 6 presets");
        let names: Vec<&str> = presets.iter().map(|(n, _)| *n).collect();
        assert!(names.contains(&"dark"));
        assert!(names.contains(&"light"));
        assert!(names.contains(&"high-contrast"));
        assert!(names.contains(&"terminal"));
        assert!(names.contains(&"nord"));
        assert!(names.contains(&"corporate"));
    }

    #[test]
    fn test_builtin_presets_no_empty_colors() {
        for (name, colors) in builtin_presets() {
            assert!(!colors.primary.is_empty(), "{} has empty primary", name);
            assert!(!colors.bg.is_empty(), "{} has empty bg", name);
            assert!(!colors.text.is_empty(), "{} has empty text", name);
        }
    }

    #[test]
    fn test_theme_resolve_default_preset() {
        let cfg: ThemeConfig = toml::from_str("").unwrap();
        let (name, colors) = cfg.resolve();
        assert_eq!(name, "aurora");
        assert!(!colors.primary.is_empty());
    }

    #[test]
    fn test_theme_resolve_from_default_struct_is_aurora() {
        // When config.toml has no [theme] section at all, main.rs resolves
        // via ThemeConfig::default(). This must produce aurora, not dark or
        // whatever happens to be first in builtin_presets().
        let (name, colors) = ThemeConfig::default().resolve();
        assert_eq!(name, "aurora");
        let aurora = builtin_presets()
            .into_iter()
            .find(|(n, _)| *n == "aurora")
            .map(|(_, c)| c)
            .expect("aurora preset should exist");
        assert_eq!(colors.primary, aurora.primary);
        assert_eq!(colors.bg, aurora.bg);
    }

    #[test]
    fn test_theme_resolve_named_preset() {
        let cfg: ThemeConfig = toml::from_str(r#"preset = "light""#).unwrap();
        let (name, _) = cfg.resolve();
        assert_eq!(name, "light");
    }

    #[test]
    fn test_theme_resolve_override() {
        let cfg: ThemeConfig =
            toml::from_str("preset = \"dark\"\nprimary_color = \"#ff0000\"").unwrap();
        let (_, colors) = cfg.resolve();
        assert_eq!(colors.primary, "#ff0000");
    }

    #[test]
    fn test_theme_resolve_unknown_preset_falls_back() {
        let cfg: ThemeConfig = toml::from_str(r#"preset = "nonexistent""#).unwrap();
        let (name, colors) = cfg.resolve();
        assert_eq!(name, "nonexistent");
        // Falls back to first preset (dark)
        let dark = &builtin_presets()[0].1;
        assert_eq!(colors.primary, dark.primary);
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_listen_addr(), "127.0.0.1:8089");
        assert_eq!(default_guacd_addr(), "127.0.0.1:4822");
        assert_eq!(default_display_range_start(), 100);
        assert_eq!(default_display_range_end(), 199);
        assert_eq!(default_cdp_port_range_start(), 9200);
        assert_eq!(default_cdp_port_range_end(), 9299);
    }

    #[test]
    fn test_load_without_file_matches_previous_defaults() {
        // Regression guard: default_toml() must emit every section/key the
        // previous hand-rolled defaults covered, so the config crate's
        // layered merge (defaults → file → env) reproduces them exactly.
        // Loading with an empty path exercises the defaults layer alone.
        let loaded = Config::load(Some(""));
        let prev = Config::default();

        // Every top-level field must match the previous defaults.
        assert_eq!(loaded.listen_addr, prev.listen_addr);
        assert_eq!(loaded.guacd_addr, prev.guacd_addr);
        assert_eq!(loaded.recording_path, prev.recording_path);
        assert_eq!(loaded.static_path, prev.static_path);
        assert_eq!(loaded.db_path, prev.db_path);
        assert_eq!(
            loaded.session_pending_timeout_secs,
            prev.session_pending_timeout_secs
        );
        assert_eq!(
            loaded.session_max_duration_secs,
            prev.session_max_duration_secs
        );
        assert_eq!(loaded.auth_session_ttl_secs, prev.auth_session_ttl_secs);
        assert_eq!(
            loaded.session_history_retention_days,
            prev.session_history_retention_days
        );
        assert_eq!(loaded.xvnc_path, prev.xvnc_path);
        assert_eq!(loaded.chromium_path, prev.chromium_path);
        assert_eq!(loaded.display_range_start, prev.display_range_start);
        assert_eq!(loaded.display_range_end, prev.display_range_end);
        assert_eq!(loaded.cdp_port_range_start, prev.cdp_port_range_start);
        assert_eq!(loaded.cdp_port_range_end, prev.cdp_port_range_end);
        assert_eq!(
            loaded.login_script_timeout_secs,
            prev.login_script_timeout_secs
        );
        assert_eq!(loaded.login_scripts_dir, prev.login_scripts_dir);
        assert_eq!(loaded.site_title, prev.site_title);
        assert_eq!(loaded.ssh_scrollback, prev.ssh_scrollback);
        assert_eq!(loaded.ssh_tmux_detach, prev.ssh_tmux_detach);
        assert_eq!(loaded.ssh_allowed_networks, prev.ssh_allowed_networks);
        assert_eq!(loaded.rdp_allowed_networks, prev.rdp_allowed_networks);
        assert_eq!(loaded.vnc_allowed_networks, prev.vnc_allowed_networks);
        assert_eq!(loaded.web_allowed_networks, prev.web_allowed_networks);
        assert_eq!(loaded.max_sessions, prev.max_sessions);
        assert_eq!(loaded.max_sessions_per_user, prev.max_sessions_per_user);
        assert_eq!(loaded.max_viewers, prev.max_viewers);
        assert_eq!(
            loaded.session_cleanup_delay_secs,
            prev.session_cleanup_delay_secs
        );
        assert_eq!(loaded.shutdown_timeout_secs, prev.shutdown_timeout_secs);
        assert_eq!(loaded.rate_limit, prev.rate_limit);
        assert_eq!(loaded.trusted_proxies, prev.trusted_proxies);
        assert_eq!(
            loaded.user_credentials_default_scope,
            prev.user_credentials_default_scope
        );
        assert_eq!(loaded.db_url, prev.db_url);

        // Sections whose previous default was None must stay absent —
        // emitting them would flip is_some()-based behaviour (TLS UI flag,
        // auth-chain path, OIDC client_secret validation, Vault/drive flags).
        assert!(loaded.tls.is_none());
        assert!(loaded.auth.is_none());
        assert!(loaded.oidc.is_none());
        assert!(loaded.vault.is_none());
        assert!(loaded.vault_shared.is_none());
        assert!(loaded.vault_local.is_none());
        assert!(loaded.drive.is_none());
        assert!(loaded.theme.is_none());
        assert!(loaded.vdi.is_none());
        assert!(loaded.vsphere.is_none());

        // [recording] must be materialised with the previous defaults.
        let rec = loaded
            .recording
            .as_ref()
            .expect("[recording] defaults must be emitted");
        assert_eq!(rec.max_recordings, 1000);
        assert_eq!(rec.max_disk_percent, 80);
        assert!(rec.enabled);
        assert_eq!(rec.path, PathBuf::from("./recordings"));
        assert_eq!(rec.rotation_interval_secs, 300);
        assert!(rec.typescript_path.is_none());
        assert!(rec.typescript_name.is_none());
        assert!(!rec.create_typescript_path);
        assert!(rec.encrypt_at_rest.is_none());

        // [storage] must be materialised with the previous defaults.
        let st = loaded
            .storage
            .as_ref()
            .expect("[storage] defaults must be emitted");
        assert_eq!(st.backend, "db");
        assert!(st.encryption_key.is_none());

        // [session] must be materialised with the previous defaults.
        let sess = loaded
            .session
            .as_ref()
            .expect("[session] defaults must be emitted");
        assert!(!sess.reason_required);

        // [rdp] must be materialised with the previous defaults (the
        // client-name template default; default_auth_pkg stays absent so
        // resolve_rdp_auth_pkg still falls through to "ntlm").
        let rdp_cfg = loaded.rdp.as_ref().expect("[rdp] defaults must be emitted");
        assert_eq!(
            rdp_cfg.client_name_template.as_deref(),
            Some(DEFAULT_RDP_CLIENT_NAME_TEMPLATE)
        );
        assert!(rdp_cfg.default_auth_pkg.is_none());

        // [updates] must be materialised with the previous defaults.
        let upd = loaded
            .updates
            .as_ref()
            .expect("[updates] defaults must be emitted");
        assert!(upd.enabled);
        assert_eq!(
            upd.check_url,
            "https://api.github.com/repos/BarbellDwarf/persea/releases/latest"
        );
        assert_eq!(upd.check_interval_hours, 24);

        // Accessor-level equivalence with the previous effective defaults.
        assert_eq!(loaded.recording_config().max_recordings, 1000);
        assert!(loaded.recording_enabled());
        assert!(loaded.db_storage_backend());
        assert_eq!(
            loaded.effective_recording_path(),
            std::path::Path::new("./recordings")
        );
    }

    #[test]
    fn test_vault_config_deserialize_minimal() {
        let toml_str = r#"
            addr = "https://vault:8200"
            role_id = "test"
        "#;
        let config: VaultConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.addr, "https://vault:8200");
        assert_eq!(config.mount, "secret");
        assert_eq!(config.base_path, "persea");
        assert!(!config.tls_skip_verify);
        assert!(config.ca_cert.is_none());
    }

    #[test]
    fn test_single_vault_is_sufficient() {
        // Quick-start invariant: a lone [vault] block is all anyone needs; the
        // optional multi-Vault backends default to absent, so a single local
        // Vault "just works" with no extra config or env vars.
        let toml_str = r#"
            [vault]
            addr = "https://127.0.0.1:8200"
            role_id = "quickstart"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.vault.is_some());
        assert!(
            config.vault_shared.is_none(),
            "[vault_shared] must be optional"
        );
        assert!(
            config.vault_local.is_none(),
            "[vault_local] must be optional"
        );
    }

    #[test]
    fn oidc_config_parses_without_client_secret() {
        // Regression for #121: omitting client_secret from config.toml used
        // to fail TOML parsing before OIDC_CLIENT_SECRET could fill it in.
        // Now it's optional at parse time and validated at startup.
        let toml_str = r#"
            issuer_url = "https://idp.example.com/"
            client_id = "persea"
            redirect_uri = "https://console.example.com/oidc/callback"
        "#;
        let config: OidcConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_id, "persea");
        assert!(config.client_secret.is_none());
    }

    #[test]
    fn oidc_config_parses_with_client_secret() {
        let toml_str = r#"
            issuer_url = "https://idp.example.com/"
            client_id = "persea"
            client_secret = "from-config"
            redirect_uri = "https://console.example.com/oidc/callback"
        "#;
        let config: OidcConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.client_secret.as_deref(), Some("from-config"));
    }

    #[test]
    fn oidc_config_debug_redacts_client_secret() {
        let config = OidcConfig {
            issuer_url: "https://idp.example.com/".into(),
            client_id: "persea".into(),
            client_secret: Some("sensitive-value".into()),
            redirect_uri: "https://console.example.com/oidc/callback".into(),
            default_role: default_oidc_default_role(),
            groups_claim: default_groups_claim(),
            extra_scopes: vec![],
            tls_skip_verify: false,
            ca_cert: None,
        };
        let dbg = format!("{:?}", config);
        assert!(!dbg.contains("sensitive-value"), "got: {}", dbg);
        assert!(dbg.contains("[REDACTED]"));
    }

    // ── Theme TOML loader (v1.7.1) ──

    /// Helper: write the minimal set of fields required for ThemeColors to
    /// deserialise. Returns a TOML string that can be written to a file.
    fn theme_toml(primary: &str) -> String {
        let mut s = String::new();
        for f in [
            "primary",
            "primary_hover",
            "accent",
            "accent_hover",
            "bg",
            "surface",
            "input",
            "text",
            "text_muted",
            "border",
            "text_dim",
            "text_on_primary",
            "btn_disabled",
            "status_pending",
            "status_active",
            "status_completed",
            "status_error",
            "status_expired",
            "type_ssh_bg",
            "type_ssh_fg",
            "type_rdp_bg",
            "type_rdp_fg",
            "type_vnc_bg",
            "type_vnc_fg",
            "type_web_bg",
            "type_web_fg",
            "type_vdi_bg",
            "type_vdi_fg",
            "hop_bg",
            "hop_fg",
        ] {
            // primary gets a caller-controlled value so tests can verify
            // which theme the resolver picked; everything else is filler.
            let v = if f == "primary" { primary } else { "#000000" };
            s.push_str(&format!("{f} = \"{v}\"\n"));
        }
        s
    }

    #[test]
    fn load_themes_returns_builtins_when_no_themes_dir() {
        // Backward-compat: a static_path with no themes/ subdir loads
        // exactly the Rust-baked built-ins (8 of them, in their defined
        // order). Existing deployments upgrading to 1.7.1 see no change.
        let tmp = std::env::temp_dir().join(format!("persea-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let themes = load_themes(&tmp);
        assert_eq!(themes.len(), builtin_presets().len());
        let names: Vec<&str> = themes.iter().map(|(n, _)| n.as_str()).collect();
        let builtin_names: Vec<&str> = builtin_presets().iter().map(|(n, _)| *n).collect();
        assert_eq!(names, builtin_names);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_themes_adds_new_disk_theme() {
        // A new .toml in the themes dir is appended after the built-ins.
        let tmp = std::env::temp_dir().join(format!("persea-test-{}-add", std::process::id()));
        let themes_dir = tmp.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        std::fs::write(themes_dir.join("custom-brand.toml"), theme_toml("#ff00ff")).unwrap();
        let themes = load_themes(&tmp);
        let custom = themes.iter().find(|(n, _)| n == "custom-brand").unwrap();
        assert_eq!(custom.1.primary, "#ff00ff");
        // All built-ins still present and unchanged.
        assert_eq!(themes.len(), builtin_presets().len() + 1);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_themes_disk_overrides_builtin_with_same_name() {
        // A .toml named after a built-in (e.g. aurora.toml) replaces the
        // built-in. Operators re-brand by editing the file, not the Rust code.
        let tmp = std::env::temp_dir().join(format!("persea-test-{}-ovr", std::process::id()));
        let themes_dir = tmp.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        std::fs::write(themes_dir.join("aurora.toml"), theme_toml("#abcdef")).unwrap();
        let themes = load_themes(&tmp);
        let aurora = themes.iter().find(|(n, _)| n == "aurora").unwrap();
        assert_eq!(aurora.1.primary, "#abcdef");
        // Count is unchanged (override, not addition).
        assert_eq!(themes.len(), builtin_presets().len());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_themes_skips_invalid_filename() {
        // Security: theme names must match [a-zA-Z0-9_-]{1,64}. Anything else
        // is skipped with a log warning, not loaded. Protects the frontend
        // picker, log lines, and config-file matching from injection or
        // homoglyph confusion via crafted filenames.
        let tmp = std::env::temp_dir().join(format!("persea-test-{}-bad", std::process::id()));
        let themes_dir = tmp.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        // Whitespace, HTML, traversal-ish, and overlong all rejected.
        for bad in [
            "with space.toml",
            "<script>.toml",
            "..hidden.toml",
            &format!("{}.toml", "x".repeat(65)),
        ] {
            std::fs::write(themes_dir.join(bad), theme_toml("#111111")).unwrap();
        }
        // One valid sentinel to confirm the loader is otherwise working.
        std::fs::write(themes_dir.join("ok-theme.toml"), theme_toml("#222222")).unwrap();
        let themes = load_themes(&tmp);
        assert!(themes.iter().any(|(n, _)| n == "ok-theme"));
        for bad_name in ["with space", "<script>", "..hidden", &"x".repeat(65)] {
            assert!(
                !themes.iter().any(|(n, _)| n == bad_name),
                "invalid name should be rejected: {bad_name}"
            );
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn load_themes_skips_malformed_toml() {
        // A garbage .toml in the themes dir is skipped with a warning, not
        // fatal. The rest of the directory continues to load.
        let tmp = std::env::temp_dir().join(format!("persea-test-{}-bad-toml", std::process::id()));
        let themes_dir = tmp.join("themes");
        std::fs::create_dir_all(&themes_dir).unwrap();
        std::fs::write(themes_dir.join("bad.toml"), "this is = not\nvalid toml [[[").unwrap();
        std::fs::write(themes_dir.join("good.toml"), theme_toml("#333333")).unwrap();
        let themes = load_themes(&tmp);
        assert!(themes.iter().any(|(n, _)| n == "good"));
        assert!(!themes.iter().any(|(n, _)| n == "bad"));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn resolve_with_existing_preset_keeps_backward_compat() {
        // The classic case: user has [theme] preset = "aurora", overrides
        // nothing. After the refactor, resolve_with against the merged
        // builtins-only set must produce the same colors that the old
        // resolve() did.
        let cfg = ThemeConfig {
            preset: Some("aurora".into()),
            ..Default::default()
        };
        let builtins: Vec<(String, ThemeColors)> = builtin_presets()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        let (name, colors) = cfg.resolve_with(&builtins);
        let (legacy_name, legacy_colors) = cfg.resolve();
        assert_eq!(name, legacy_name);
        assert_eq!(name, "aurora");
        assert_eq!(colors.primary, legacy_colors.primary);
    }

    #[test]
    fn resolve_with_field_override_still_applies() {
        // Per-field overrides remain functional under resolve_with.
        let cfg = ThemeConfig {
            preset: Some("dark".into()),
            primary_color: Some("#ff0000".into()),
            ..Default::default()
        };
        let builtins: Vec<(String, ThemeColors)> = builtin_presets()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        let (_, colors) = cfg.resolve_with(&builtins);
        assert_eq!(colors.primary, "#ff0000");
    }

    #[test]
    fn existing_user_config_with_theme_section_keeps_working_after_upgrade() {
        // Backward-compat: a config.toml that already has a [theme] section
        // from a 1.7.0-or-earlier install must produce the exact same
        // resolved colors after the v1.7.1 refactor. This test loads three
        // realistic shapes of existing [theme] configs as if from
        // config.toml, then runs each through resolve() and resolve_with()
        // against the merged themes list and asserts they match.
        //
        // resolve() is now a thin wrapper over resolve_with(builtins), so
        // this also verifies the wrapper preserves the legacy contract.
        let cases = [
            // Common: preset only.
            r##"preset = "dark""##,
            // Power user: preset + per-field overrides.
            r##"
                preset = "light"
                primary_color = "#003366"
                accent_color = "#FF6600"
            "##,
            // Overrides without a preset (the implicit-aurora case).
            r##"
                primary_color = "#abcdef"
                bg_color = "#102030"
            "##,
            // Empty section — same as no [theme] block: defaults to aurora.
            "",
            // Typo'd preset name: falls back to the first built-in (dark).
            r##"preset = "this-does-not-exist""##,
        ];
        let merged: Vec<(String, ThemeColors)> = builtin_presets()
            .into_iter()
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        for src in cases {
            let cfg: ThemeConfig = toml::from_str(src).expect("valid theme TOML");
            let (legacy_name, legacy_colors) = cfg.resolve();
            let (new_name, new_colors) = cfg.resolve_with(&merged);
            assert_eq!(legacy_name, new_name, "preset name diverged for: {src}");
            // Every field must match, byte for byte.
            assert_eq!(
                legacy_colors.primary, new_colors.primary,
                "primary diverged for: {src}"
            );
            assert_eq!(legacy_colors.bg, new_colors.bg, "bg diverged for: {src}");
            assert_eq!(
                legacy_colors.accent, new_colors.accent,
                "accent diverged for: {src}"
            );
            assert_eq!(
                legacy_colors.text, new_colors.text,
                "text diverged for: {src}"
            );
            assert_eq!(
                legacy_colors.bg_pattern, new_colors.bg_pattern,
                "bg_pattern diverged for: {src}"
            );
        }
    }

    #[test]
    fn is_valid_theme_name_rules() {
        assert!(is_valid_theme_name("aurora"));
        assert!(is_valid_theme_name("catppuccin-macchiato"));
        assert!(is_valid_theme_name("corp_brand_v2"));
        assert!(is_valid_theme_name("a"));
        assert!(!is_valid_theme_name(""));
        assert!(!is_valid_theme_name("with space"));
        assert!(!is_valid_theme_name("with/slash"));
        assert!(!is_valid_theme_name("with.dot"));
        assert!(!is_valid_theme_name("with!bang"));
        assert!(!is_valid_theme_name(&"x".repeat(65)));
        assert!(is_valid_theme_name(&"x".repeat(64)));
    }

    // ── Config validation tests ──

    #[test]
    fn test_sanitize_removes_invalid_cidrs() {
        let mut config = Config::default();
        config.ssh_allowed_networks = vec![
            "10.0.0.0/8".into(),
            "not-a-cidr".into(),
            "192.168.0.0/16".into(),
            "".into(),
        ];
        config.sanitize();
        assert_eq!(
            config.ssh_allowed_networks,
            vec!["10.0.0.0/8", "192.168.0.0/16"]
        );
    }

    #[test]
    fn test_sanitize_keeps_valid_cidrs() {
        let mut config = Config::default();
        config.ssh_allowed_networks = vec![
            "10.0.0.0/8".into(),
            "172.16.0.0/12".into(),
            "::1/128".into(),
        ];
        config.sanitize();
        assert_eq!(config.ssh_allowed_networks.len(), 3);
    }

    #[test]
    fn test_sanitize_cidr_list_removes_bad_entries() {
        let mut list = vec!["valid/24".into(), "bad".into(), "10.0.0.0/8".into()];
        sanitize_cidr_list("test", &mut list);
        // "bad" removed, valid entries kept
        assert!(!list.iter().any(|s| s == "bad"));
        assert!(list.iter().any(|s| s == "10.0.0.0/8"));
    }

    #[test]
    fn test_default_allowed_networks_includes_private_ranges() {
        let defaults = default_localhost_networks();
        assert!(defaults.contains(&"10.0.0.0/8".to_string()));
        assert!(defaults.contains(&"172.16.0.0/12".to_string()));
        assert!(defaults.contains(&"192.168.0.0/16".to_string()));
        assert!(defaults.contains(&"127.0.0.0/8".to_string()));
        assert!(defaults.contains(&"::1/128".to_string()));
    }

    #[test]
    fn test_config_default_networks_use_private_ranges() {
        let config = Config::default();
        // SSH, RDP, VNC should use the expanded private-range defaults
        for networks in [
            &config.ssh_allowed_networks,
            &config.rdp_allowed_networks,
            &config.vnc_allowed_networks,
        ] {
            assert!(networks.contains(&"10.0.0.0/8".to_string()));
            assert!(networks.contains(&"172.16.0.0/12".to_string()));
            assert!(networks.contains(&"192.168.0.0/16".to_string()));
        }
        // Web should default to loopback-only
        assert_eq!(config.web_allowed_networks, vec!["127.0.0.0/8", "::1/128"]);
    }

    #[test]
    fn test_sanitize_trusted_proxies() {
        let mut config = Config::default();
        config.trusted_proxies = vec![
            "10.0.0.0/8".into(),
            "not-valid".into(),
            "192.168.0.0/16".into(),
        ];
        config.sanitize();
        assert_eq!(config.trusted_proxies, vec!["10.0.0.0/8", "192.168.0.0/16"]);
    }

    // ── validate() method tests ──

    #[test]
    fn test_validate_ok_default_config() {
        let config = Config::default();
        let result = config.validate();
        assert!(result.is_ok(), "default config should pass validation");
    }

    #[test]
    fn test_validate_bad_listen_addr() {
        let mut config = Config::default();
        config.listen_addr = "not-an-address".into();
        let err = config.validate().unwrap_err();
        assert!(err.contains("listen_addr"), "error: {}", err);
    }

    #[test]
    fn test_validate_bad_guacd_addr() {
        let mut config = Config::default();
        config.guacd_addr = "host:99999".into();
        let err = config.validate().unwrap_err();
        assert!(err.contains("guacd_addr"), "error: {}", err);
    }

    #[test]
    fn test_validate_bad_cidr_fatal() {
        let mut config = Config::default();
        config.ssh_allowed_networks = vec!["not-a-cidr".into()];
        let err = config.validate().unwrap_err();
        assert!(err.contains("ssh_allowed_networks"), "error: {}", err);
    }

    #[test]
    fn test_validate_display_range_start_ge_end() {
        let mut config = Config::default();
        config.display_range_start = 200;
        config.display_range_end = 100;
        let err = config.validate().unwrap_err();
        assert!(err.contains("display_range_start"), "error: {}", err);
    }

    #[test]
    fn test_validate_session_pending_timeout_zero() {
        let mut config = Config::default();
        config.session_pending_timeout_secs = 0;
        let err = config.validate().unwrap_err();
        assert!(
            err.contains("session_pending_timeout_secs"),
            "error: {}",
            err
        );
    }

    #[test]
    fn test_validate_max_disk_percent_over_100() {
        let mut config = Config::default();
        config.recording = Some(RecordingConfig {
            max_disk_percent: 120,
            ..RecordingConfig::default()
        });
        let err = config.validate().unwrap_err();
        assert!(err.contains("max_disk_percent"), "error: {}", err);
    }

    #[test]
    fn test_validate_recording_path_deprecation_warning() {
        // No warning when recording_path is unset (default) even with [recording].
        let mut config = Config::default();
        config.recording = Some(RecordingConfig::default());
        let warnings = config.validate().unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("recording_path")),
            "expected no deprecation warning for unset field, got: {:?}",
            warnings
        );

        // Warning fires when the deprecated top-level field is explicitly set.
        let mut config = Config::default();
        config.recording_path = Some(std::path::PathBuf::from("/tmp/rec"));
        let warnings = config.validate().unwrap();
        assert!(
            warnings.iter().any(|w| w.contains("recording_path")),
            "expected deprecation warning, got: {:?}",
            warnings
        );

        // An empty string is treated as unset: no warning, default path used.
        let mut config = Config::default();
        config.recording_path = Some(std::path::PathBuf::new());
        let warnings = config.validate().unwrap();
        assert!(
            !warnings.iter().any(|w| w.contains("recording_path")),
            "expected no deprecation warning for empty path, got: {:?}",
            warnings
        );
        assert_eq!(
            config.effective_recording_path(),
            std::path::Path::new(&default_recording_path())
        );
    }
}
