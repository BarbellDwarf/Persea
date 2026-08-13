use crate::browser::BrowserSession;
use crate::guacd::GuacdStream;
use crate::tunnel;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};
use uuid::Uuid;

/// Session type: SSH terminal, web browser, RDP, VNC, VDI container, direct
/// SPICE, or Proxmox VE console (SPICE brokered via the PVE spiceproxy API).
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SessionType {
    /// SSH terminal session.
    #[default]
    Ssh,
    /// Web browser session (headless Chromium on Xvnc).
    Web,
    /// Remote desktop protocol session.
    Rdp,
    /// VNC session.
    Vnc,
    /// Docker desktop container session (RDP to xrdp).
    Vdi,
    /// Direct SPICE session.
    Spice,
    /// Proxmox VE console session (SPICE brokered via spiceproxy).
    Proxmox,
}

/// SSH-specific session parameters.
///
/// Deserialized from the flat request JSON via `#[serde(flatten)]` on
/// `CreateSessionRequest`: any JSON key declared only here lands in this
/// struct regardless of `session_type`.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SshParams {
    /// PEM-encoded private key for key-based auth instead of a password.
    pub private_key: Option<String>,
    /// Generate an ephemeral Ed25519 keypair and inject it into the target's authorized_keys.
    pub generate_keypair: Option<bool>,
    /// Enable SSH typescript recording for this session (#159). Default
    /// off; SSH only; requires `[recording].typescript_path` configured.
    pub record_typescript: Option<bool>,
}

/// RDP-specific session parameters (NLA, RemoteApp, GFX pipeline, ...).
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RdpParams {
    /// Windows domain for the login user (NTLM/Kerberos).
    pub domain: Option<String>,
    /// RDP security layer: "any", "rdp", "tls", or "nla".
    pub security: Option<String>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Kerberos ticket cache path (optional).
    pub kerberos_cache: Option<String>,
    // RDP RemoteApp (RAIL)
    /// RemoteApp program path (RAIL): launch a single application instead of the full desktop.
    pub remote_app: Option<String>,
    /// RemoteApp working directory.
    pub remote_app_dir: Option<String>,
    /// RemoteApp command-line arguments.
    pub remote_app_args: Option<String>,
    /// Enable RDP Graphics Pipeline Extension (GFX).
    pub enable_gfx: Option<bool>,
    /// Enable desktop composition (DWM) for RDP.
    pub enable_desktop_composition: Option<bool>,
    /// Show the remote desktop wallpaper (RDP).
    pub enable_wallpaper: Option<bool>,
    /// Enable window/control theming (RDP).
    pub enable_theming: Option<bool>,
    /// Show window contents while dragging (RDP).
    pub enable_full_window_drag: Option<bool>,
    /// Force lossless encoding (PNG only) for RDP.
    pub force_lossless: Option<bool>,
    /// Enable H.264 passthrough for RDP.
    pub enable_h264: Option<bool>,
}

/// VNC-specific session parameters.
///
/// `color_depth` is also honoured by SPICE sessions (shared display option);
/// this struct is its canonical flattened home — serde flatten claims a key
/// once, in declaration order, so the key must not be duplicated elsewhere.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VncParams {
    /// Color depth in bits per pixel (also honoured by SPICE sessions).
    pub color_depth: Option<u8>,
}

/// Web-browser session parameters (Xvnc + Chromium).
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct WebParams {
    /// URL the browser session starts on.
    pub url: Option<String>,
    /// Login script filename to run after browser spawns (web sessions only).
    pub login_script: Option<String>,
    /// Autofill credentials JSON for web sessions.
    /// Array of {"url", "username", "password"} with $USERNAME/$PASSWORD placeholders.
    pub autofill: Option<String>,
    /// Allowed domains for web sessions. When set, Chromium can only reach these domains.
    pub allowed_domains: Option<Vec<String>>,
}

/// VDI (Docker desktop container) session parameters.
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct VdiParams {
    /// Docker image for VDI sessions (e.g. "myregistry/desktop:latest").
    pub container_image: Option<String>,
    /// CPU limit override for VDI container (fractional cores).
    pub container_cpu_limit: Option<f64>,
    /// Memory limit override for VDI container in MB.
    pub container_memory_limit: Option<u64>,
    /// Extra environment variables for VDI container.
    pub container_env: Option<std::collections::HashMap<String, String>>,
    /// Override idle timeout for VDI container in minutes.
    pub container_idle_timeout_mins: Option<u64>,
    /// Fixed VDI container username override (matches the baked-in account
    /// in container images that don't honour VDI_USERNAME). Auto-derived
    /// from the operator's identity when unset.
    pub container_username: Option<String>,
    /// Fixed VDI container password override matching `container_username`.
    /// Ephemerally generated when unset.
    pub container_password: Option<String>,
}

/// SPICE-specific session parameters (TLS, CA verification, proxy).
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct SpiceParams {
    /// SPICE: connect using TLS.
    pub spice_tls: Option<bool>,
    /// SPICE: TLS port (if the encrypted port differs from `port`).
    pub spice_tls_port: Option<u16>,
    /// SPICE: PEM CA certificate for verifying the server's TLS (e.g. a
    /// Proxmox cluster CA).
    pub spice_ca_cert: Option<String>,
    /// SPICE: expected TLS certificate subject (Proxmox "host-subject").
    pub spice_cert_subject: Option<String>,
    /// SPICE: proxy URL, e.g. a Proxmox SPICE proxy "http://host:3128".
    pub spice_proxy: Option<String>,
}

/// Proxmox VE console session parameters (SPICE brokered via PVE spiceproxy).
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct ProxmoxParams {
    /// PVE API base URL, a full URL including scheme and port
    /// (e.g. "https://pve.example.com:8006"). persea fetches a just-in-time
    /// SPICE ticket + config from the PVE spiceproxy API at connect.
    pub proxmox_url: Option<String>,
    /// Proxmox node name hosting the VM (e.g. "pve").
    pub proxmox_node: Option<String>,
    /// Proxmox VM id (QEMU) whose console to open.
    pub proxmox_vmid: Option<u32>,
    /// Proxmox API token id ("user@realm!tokenname") — the non-secret half.
    pub proxmox_token_id: Option<String>,
    /// Proxmox API token secret (the UUID half). Joined with the id as
    /// "id=secret" for the API. Kept separate so the id can be shown while the
    /// secret stays masked.
    pub proxmox_token_secret: Option<String>,
    /// Verify the PVE API server's TLS certificate (default false; PVE ships a
    /// self-signed cluster cert). Also controls SPICE-proxy cert verification.
    pub proxmox_verify_tls: Option<bool>,
}

/// Parameters for creating a new session.
///
/// Protocol-specific parameters live in the flattened sub-structs
/// (`ssh`, `rdp`, `vnc`, `web`, `vdi`, `spice`, `proxmox`); fields shared by
/// several protocols stay on this struct. The JSON wire format is flat —
/// `#[serde(flatten)]` routes each key to the sub-struct that declares it.
/// serde flatten claims each key exactly once (first declared struct wins),
/// so no key is duplicated across sub-structs.
#[derive(Debug, Default, Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default)]
    /// Which protocol family the session uses; defaults to SSH when omitted.
    pub session_type: SessionType,
    // Network/credential fields shared by SSH/RDP/VNC/SPICE (and used for
    // $RUSTGUAC_USERNAME/$RUSTGUAC_PASSWORD substitution in web URLs).
    /// Remote host for SSH/RDP/VNC/SPICE sessions (also substituted into web session URLs).
    pub hostname: Option<String>,
    /// Remote port for SSH/RDP/VNC/SPICE sessions.
    pub port: Option<u16>,
    /// Login username for the target (also substituted into web session URLs).
    pub username: Option<String>,
    /// Login password for the target (also substituted into web session URLs).
    pub password: Option<String>,
    /// Ignore TLS/certificate errors (RDP NLA and SPICE TLS).
    pub ignore_cert: Option<bool>,
    /// Total number of monitors to offer (RDP/SPICE/Proxmox/VDI
    /// multi-monitor). guacd is told `secondary-monitors = max_monitors - 1`,
    /// which it advertises to the client. Default 1 (single monitor).
    pub max_monitors: Option<u32>,
    // SSH tunnel / jump host fields (multi-hop)
    /// Ordered chain of SSH jump hosts to tunnel the target connection through.
    pub jump_hosts: Option<Vec<tunnel::JumpHost>>,
    // Legacy flat fields for backward compat (single jump host)
    /// Legacy single jump host (superseded by `jump_hosts`).
    pub jump_host: Option<String>,
    /// Legacy single jump host port.
    pub jump_port: Option<u16>,
    /// Legacy single jump host username.
    pub jump_username: Option<String>,
    /// Legacy single jump host password.
    pub jump_password: Option<String>,
    /// Legacy single jump host private key.
    pub jump_private_key: Option<String>,
    // Common display / session settings
    /// Initial display width in pixels (RDP/VNC/SPICE/VDI) or terminal columns (SSH).
    pub width: Option<u32>,
    /// Initial display height in pixels (RDP/VNC/SPICE/VDI) or terminal rows (SSH).
    pub height: Option<u32>,
    /// Reported display density in DPI.
    pub dpi: Option<u32>,
    /// Notice text shown to the user in the client when the session connects.
    pub banner: Option<String>,
    /// Override drive/file transfer setting for this session.
    pub enable_drive: Option<bool>,
    /// Disable clipboard copy (server → client).
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server).
    pub disable_paste: Option<bool>,
    // Recording / reporting metadata
    /// Record this session to a .guac file (requires recording config).
    pub enable_recording: Option<bool>,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    pub entry_display_name: Option<String>,
    /// Per-entry max recordings to keep.
    pub max_recordings: Option<u32>,
    // Sharing / client behaviour flags
    /// Allow the owner to generate a Share URL for this session.
    /// Default false. For entry-derived sessions this is populated from
    /// the entry's `allow_sharing` flag; ad-hoc sessions are never
    /// shareable (per GitHub-less admin gating requirement).
    pub allow_sharing: Option<bool>,
    /// Open the client in fullscreen on connect (#154). Populated from
    /// the source entry's `fullscreen_on_connect` flag; ad-hoc sessions
    /// leave it None and the client behaves as if false.
    pub fullscreen_on_connect: Option<bool>,
    /// Auto-hide the clipboard/files side tabs when idle (they reappear
    /// when the pointer nears the left edge). Populated from the source
    /// entry; ad-hoc sessions leave it None (client behaves as if false).
    pub autohide_side_tabs: Option<bool>,
    // Protocol-specific parameters (flat JSON keys route into these).
    /// SSH-specific parameters (`private_key`, `generate_keypair`, ...).
    #[serde(flatten)]
    pub ssh: Option<SshParams>,
    /// RDP-specific parameters (NLA, RemoteApp, GFX pipeline, ...).
    #[serde(flatten)]
    pub rdp: Option<RdpParams>,
    /// VNC-specific parameters (`color_depth`; also honoured by SPICE).
    #[serde(flatten)]
    pub vnc: Option<VncParams>,
    /// Web-browser session parameters (`url`, `login_script`, `autofill`, ...).
    #[serde(flatten)]
    pub web: Option<WebParams>,
    /// VDI container parameters (`container_image`, resource limits, ...).
    #[serde(flatten)]
    pub vdi: Option<VdiParams>,
    /// SPICE parameters (TLS, CA verification, proxy).
    #[serde(flatten)]
    pub spice: Option<SpiceParams>,
    /// Proxmox VE console parameters (PVE API URL, node, VM id, API token).
    #[serde(flatten)]
    pub proxmox: Option<ProxmoxParams>,
}

/// Session status in the lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum SessionStatus {
    /// guacd connected, waiting for browser
    Pending,
    /// Browser connected, session active
    Active,
    /// Session ended normally
    Completed,
    /// Session ended due to error
    Error,
    /// Session expired (no browser connected in time)
    Expired,
    /// Browser disconnected but session remains in manager for reconnection
    Disconnected,
}

impl SessionStatus {
    /// True for terminal states (completed/error/expired): the session can
    /// no longer be joined or resumed.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            SessionStatus::Completed | SessionStatus::Error | SessionStatus::Expired
        )
    }
}

/// Public session info returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    /// Unique session identifier.
    pub session_id: Uuid,
    /// Protocol family of the session.
    pub session_type: SessionType,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Last real activity (WebSocket traffic or thumbnail uploads); absent
    /// when the session never saw activity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<DateTime<Utc>>,
    /// When the session entered a terminal state (completed/error/expired);
    /// absent while the session is still live.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    /// Path to the client page for this session.
    pub client_url: String,
    /// Share URL, present when sharing is allowed; omitted otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_url: Option<String>,
    /// WebSocket path for the session stream.
    pub ws_url: String,
    /// Target hostname.
    pub hostname: String,
    /// Login username on the target.
    pub username: String,
    /// Number of connected viewers (owner plus joins and shadows).
    pub active_connections: u32,
    /// Identity of the user who created the session.
    pub created_by: String,
    /// Notice text shown to the user in the client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    /// URL the web-browser session opened (web sessions only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_display_name: Option<String>,
    /// Path to the session's thumbnail image, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_url: Option<String>,
    /// Open the client in fullscreen on connect (#154). Read by client.html
    /// from the /api/sessions/:id fetch; omitted when false/unset.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub fullscreen_on_connect: bool,
    /// Auto-hide the clipboard/files side tabs when idle. Read by
    /// client.html from the /api/sessions/:id fetch; omitted when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub autohide_side_tabs: bool,
    /// Whether file transfer (RDP drive / SSH SFTP) is enabled for this
    /// session. Read by client.html to show/hide the upload button.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub drive_enabled: bool,
    /// Enterprise HA: the instance id that owns this session, when it
    /// is NOT this instance. `remote = true` means the session lives in the
    /// shared registry only and its guacd stream is on `owner_instance`
    /// (join/shadow are redirected to `owner_base_url`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_instance: Option<String>,
    /// Enterprise HA: public base URL of the owning instance, for
    /// cross-instance join/shadow redirects.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_base_url: Option<String>,
    /// Enterprise HA: true when this session is hosted by another
    /// instance (seen via the shared registry, not the local map).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub remote: bool,
}

/// Kind of a session lifecycle event on the event feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEventKind {
    /// A session was created (status `pending`).
    SessionStarted,
    /// A live session changed status (e.g. pending → active,
    /// active → disconnected).
    StatusChanged,
    /// A session entered a terminal state (completed/error/expired).
    SessionEnded,
}

impl SessionEventKind {
    /// The SSE `event:` field value.
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionEventKind::SessionStarted => "session_started",
            SessionEventKind::StatusChanged => "status_changed",
            SessionEventKind::SessionEnded => "session_ended",
        }
    }
}

/// One session lifecycle event on the `GET /api/sessions/events` feed.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEvent {
    /// Monotonic cursor, unique per manager lifetime. Clients replay with
    /// `?since=<id>` and resume SSE with `Last-Event-ID: <id>`.
    pub id: u64,
    /// Event kind: `session_started`, `status_changed`, or `session_ended`.
    pub event: SessionEventKind,
    /// The session that changed.
    pub session_id: Uuid,
    /// Protocol family of the session.
    pub session_type: SessionType,
    /// Status after the transition.
    pub status: SessionStatus,
    /// Identity of the user who created the session.
    pub created_by: String,
    /// When the event was published.
    pub timestamp: DateTime<Utc>,
}

/// Internal session state including the guacd connection.
pub struct Session {
    /// Unique session identifier.
    pub id: Uuid,
    /// Protocol family of the session.
    pub session_type: SessionType,
    /// Current lifecycle status.
    pub status: SessionStatus,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// Target hostname.
    pub hostname: String,
    /// Login username on the target.
    pub username: String,
    /// URL the web-browser session opened (web sessions only).
    pub url: Option<String>,
    /// Notice text shown to the user in the client.
    pub banner: Option<String>,
    /// Live guacd connection, taken by the owner's WebSocket on connect.
    pub guacd_stream: Option<GuacdStream>,
    /// guacd-assigned connection id, used to join the session.
    pub connection_id: String,
    /// Long-lived owner share token (hex), validated on share URL connect.
    pub share_token: String,
    /// Initial display width in pixels.
    pub width: u32,
    /// Initial display height in pixels.
    pub height: u32,
    /// Number of connected viewers.
    pub active_connections: u32,
    /// Identity of the user who created the session.
    pub created_by: String,
    /// Cancelled to end the session and drop the guacd connection.
    pub cancel: tokio_util::sync::CancellationToken,
    /// Running browser (Xvnc + Chromium) for web sessions.
    pub browser_session: Option<BrowserSession>,
    /// Connection params for deferred guacd connection (ephemeral keypair sessions).
    /// When set, the guacd connection is established when the WebSocket connects
    /// instead of at session creation time.
    pub deferred_params: Option<crate::guacd::ConnectionParams>,
    /// Per-session drive directory path (RDP sessions with drive enabled).
    pub drive_path: Option<std::path::PathBuf>,
    /// Whether file transfer (RDP drive / SSH SFTP) is enabled for this session.
    pub drive_enabled: bool,
    /// SSH tunnel chain (jump hosts) — kept alive for the session duration.
    pub tunnels: Vec<tunnel::SshTunnel>,
    /// Docker container ID for VDI sessions.
    pub container_id: Option<String>,
    /// Docker container name for VDI sessions.
    pub container_name: Option<String>,
    /// Whether recording is enabled for this session.
    pub recording_enabled: bool,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    pub entry_display_name: Option<String>,
    /// Per-entry max recordings to keep (from address book entry).
    pub max_recordings: Option<u32>,
    /// Login script task handle (aborted on session cleanup).
    pub login_script_handle: Option<tokio::task::JoinHandle<()>>,
    /// Short-lived admin-issued viewer tokens (Shadow — plan in
    /// project_shadow_sessions_plan.md). Stores only a sha256 hex of the
    /// raw token, the admin that issued it, and expiry. Validated
    /// alongside share_token in validate_share_token; expired entries
    /// are pruned when new tokens are minted.
    pub shadow_tokens: Vec<ShadowToken>,
    /// Admin-controlled: does this session allow user-initiated
    /// sharing? Copied from the source entry's `allow_sharing` at
    /// creation. When false, `SessionInfo.share_url` is `None` — the
    /// Connections card hides its Share button. Does not block admin
    /// shadow (`/shadow`), which has its own audit trail.
    pub share_allowed: bool,
    /// Copied from the source entry's `fullscreen_on_connect` flag
    /// (#154). Surfaced verbatim in `SessionInfo` so client.html can
    /// trigger fullscreen on first user gesture after CONNECTED.
    pub fullscreen_on_connect: bool,
    /// Copied from the source entry's `autohide_side_tabs` flag.
    /// Surfaced in `SessionInfo` so client.html can auto-hide the
    /// clipboard/files side tabs.
    pub autohide_side_tabs: bool,
    /// Last activity timestamp (epoch seconds). Updated on every WebSocket
    /// input event from the browser. Used by the idle-session reaper.
    pub last_activity: AtomicI64,
    /// IP address of the client that created this session.
    pub source_ip: Option<String>,
    /// OIDC user ID (or created_by for non-OIDC sessions) for per-user
    /// concurrent session limits.
    pub user_id: Option<String>,
}

/// A short-lived viewer token issued by an admin to shadow an active session.
/// The raw token is handed to the admin once; only the hash is persisted in
/// memory so the token can't be lifted from a runtime snapshot.
#[derive(Debug, Clone)]
pub struct ShadowToken {
    /// SHA-256 hex of the raw token; the raw value is never stored.
    pub token_hash: String,
    /// Identity of the admin who minted the token.
    pub issued_by: String,
    /// When the token stops validating; expired tokens are pruned on mint.
    pub expires_at: DateTime<Utc>,
}

/// Result of validating a share-or-shadow token. Callers use this to tell
/// owner traffic from admin-minted shadow viewers, and to audit each shadow
/// use (the raw mint is audited separately; re-use is logged per connection
/// so a leaked token's blast radius is observable after the fact).
#[derive(Debug, Clone, PartialEq)]
pub enum ShareTokenValidation {
    /// The provided token matched nothing.
    Invalid,
    /// The provided token is the session owner's share token.
    Owner,
    /// The provided token is an admin-minted shadow token, issued by the named admin.
    Shadow {
        /// Identity of the admin who minted the token.
        issued_by: String,
    },
}

impl ShareTokenValidation {
    /// True for `Owner` and `Shadow`, false for `Invalid`.
    pub fn is_valid(&self) -> bool {
        !matches!(self, ShareTokenValidation::Invalid)
    }
}

/// Why a session operation failed. Produced by the manager's join and
/// delete paths; the string payloads carry the underlying message.
#[derive(Debug)]
#[must_use]
pub enum SessionError {
    /// Could not reach guacd, or the handshake failed; carries the underlying message.
    GuacdConnection(String),
    /// No session with the requested id exists.
    NotFound,
    /// The session exists but is not in a joinable state.
    NotActive,
    /// The request parameters failed validation; carries the reason.
    ValidationError(String),
    /// Xvnc or Chromium failed to start; carries the underlying message.
    BrowserSpawn(String),
    /// Docker container lifecycle failed; carries the underlying message.
    VdiError(String),
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionError::GuacdConnection(msg) => write!(f, "guacd connection failed: {}", msg),
            SessionError::NotFound => write!(f, "session not found"),
            SessionError::NotActive => write!(f, "session is not active"),
            SessionError::ValidationError(msg) => write!(f, "validation error: {}", msg),
            SessionError::BrowserSpawn(msg) => write!(f, "browser spawn failed: {}", msg),
            SessionError::VdiError(msg) => write!(f, "VDI error: {}", msg),
        }
    }
}

impl Session {
    /// Update last_activity to the current epoch seconds (atomic, lock-free).
    pub fn touch_activity(&self) {
        let now = Utc::now().timestamp();
        self.last_activity.store(now, Ordering::Relaxed);
    }

    /// Read the last_activity timestamp (epoch seconds).
    pub fn last_activity_secs(&self) -> i64 {
        self.last_activity.load(Ordering::Relaxed)
    }

    /// Build the public `SessionInfo` view used by API responses.
    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id,
            session_type: self.session_type.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
            last_activity: {
                let secs = self.last_activity_secs();
                if secs > 0 {
                    chrono::DateTime::from_timestamp(secs, 0)
                } else {
                    None
                }
            },
            ended_at: None, // attached by the manager from its terminal-state registry
            client_url: format!("/client/{}", self.id),
            share_url: if self.share_allowed {
                Some(format!("/client/{}?token={}", self.id, self.share_token))
            } else {
                None
            },
            ws_url: format!("/ws/{}", self.id),
            hostname: self.hostname.clone(),
            username: self.username.clone(),
            active_connections: self.active_connections,
            created_by: self.created_by.clone(),
            banner: self.banner.clone(),
            url: self.url.clone(),
            address_book_entry: self.address_book_entry.clone(),
            address_book_folder: self.address_book_folder.clone(),
            entry_display_name: self.entry_display_name.clone(),
            thumbnail_url: Some(format!("/api/sessions/{}/thumbnail", self.id)),
            fullscreen_on_connect: self.fullscreen_on_connect,
            autohide_side_tabs: self.autohide_side_tabs,
            drive_enabled: self.drive_enabled,
            owner_instance: None,
            owner_base_url: None,
            remote: false,
        }
    }
}

impl SessionInfo {
    /// Build the public info for a session that exists only in the shared
    /// registry: it is owned by another instance, so every field is
    /// what the registry recorded — no local state, no tokens.
    pub fn from_registry(row: &crate::db::SessionRegistryRow) -> Option<SessionInfo> {
        use chrono::NaiveDateTime;
        let session_type: SessionType =
            serde_json::from_str(&format!("\"{}\"", row.session_type.to_lowercase()))
                .unwrap_or_default();
        let status: SessionStatus =
            serde_json::from_str(&format!("\"{}\"", row.status.to_lowercase()))
                .unwrap_or(SessionStatus::Error);
        let created_at = NaiveDateTime::parse_from_str(&row.created_at, "%Y-%m-%d %H:%M:%S")
            .ok()
            .map(|ndt| ndt.and_utc())
            .unwrap_or_else(chrono::Utc::now);
        let id = Uuid::parse_str(&row.session_id).ok()?;
        Some(SessionInfo {
            session_id: id,
            session_type,
            status,
            created_at,
            last_activity: None,
            ended_at: None,
            client_url: format!("/client/{}", id),
            share_url: None,
            ws_url: format!("/ws/{}", id),
            hostname: row.hostname.clone(),
            username: row.username.clone(),
            active_connections: 0,
            created_by: row.created_by.clone(),
            banner: None,
            url: None,
            address_book_entry: None,
            address_book_folder: None,
            entry_display_name: None,
            thumbnail_url: None,
            fullscreen_on_connect: false,
            autohide_side_tabs: false,
            drive_enabled: false,
            owner_instance: Some(row.owner_instance.clone()),
            owner_base_url: if row.owner_base_url.is_empty() {
                None
            } else {
                Some(row.owner_base_url.clone())
            },
            remote: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The API accepts flat JSON (e.g. `{"session_type":"ssh","hostname":"x"}`).
    /// With `#[serde(flatten)]`, each flat key must land in exactly the
    /// sub-struct that declares it — serde flatten claims keys once, in
    /// declaration order, so no key may be duplicated across sub-structs.
    #[test]
    fn flat_json_deserializes_into_substructs() {
        // SSH: network fields on the parent, SSH-specific in SshParams.
        let json = r#"{
            "session_type":"ssh",
            "hostname":"example.com","port":22,"username":"root","password":"secret",
            "private_key":"KEY","generate_keypair":true,"record_typescript":true
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hostname.as_deref(), Some("example.com"));
        assert_eq!(req.port, Some(22));
        assert_eq!(req.username.as_deref(), Some("root"));
        assert_eq!(req.password.as_deref(), Some("secret"));
        let ssh = req.ssh.as_ref().expect("ssh params");
        assert_eq!(ssh.private_key.as_deref(), Some("KEY"));
        assert_eq!(ssh.generate_keypair, Some(true));
        assert_eq!(ssh.record_typescript, Some(true));
        // No other sub-struct must claim these keys (flattened Option structs
        // are always Some; absence is expressed by None fields).
        assert!(req.rdp.as_ref().unwrap().domain.is_none());
        assert!(req.vnc.as_ref().unwrap().color_depth.is_none());
        assert!(req.web.as_ref().unwrap().url.is_none());

        // RDP: RDP-specific keys land in RdpParams.
        let json = r#"{
            "session_type":"rdp","hostname":"winbox","port":3389,
            "domain":"CORP","security":"any","auth_pkg":"ntlm",
            "remote_app":"notepad","enable_gfx":true,"enable_h264":true
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        let rdp = req.rdp.as_ref().expect("rdp params");
        assert_eq!(rdp.domain.as_deref(), Some("CORP"));
        assert_eq!(rdp.security.as_deref(), Some("any"));
        assert_eq!(rdp.auth_pkg.as_deref(), Some("ntlm"));
        assert_eq!(rdp.remote_app.as_deref(), Some("notepad"));
        assert_eq!(rdp.enable_gfx, Some(true));
        assert_eq!(rdp.enable_h264, Some(true));
        assert!(
            req.ssh.as_ref().unwrap().private_key.is_none(),
            "hostname must not leak into SshParams"
        );

        // VNC: color_depth is the only VNC-specific key.
        let json = r#"{"session_type":"vnc","hostname":"kvm1","port":5900,"color_depth":24}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.vnc.as_ref().and_then(|v| v.color_depth), Some(24));

        // Web: URL/browser keys land in WebParams.
        let json = r#"{
            "session_type":"web","url":"https://app.example.com",
            "login_script":"/opt/scripts/login.sh",
            "autofill":"[{\"url\":\"https://app.example.com\",\"username\":\"u\",\"password\":\"p\"}]",
            "allowed_domains":["app.example.com"]
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        let web = req.web.as_ref().expect("web params");
        assert_eq!(web.url.as_deref(), Some("https://app.example.com"));
        assert_eq!(web.login_script.as_deref(), Some("/opt/scripts/login.sh"));
        assert!(web
            .autofill
            .as_deref()
            .unwrap_or("")
            .contains("app.example.com"));
        assert_eq!(
            web.allowed_domains.as_deref(),
            Some(&["app.example.com".to_string()][..])
        );

        // VDI: container keys land in VdiParams.
        let json = r#"{
            "session_type":"vdi",
            "container_image":"registry.example.com/desktop:latest",
            "container_cpu_limit":2.0,"container_memory_limit":4096,
            "container_username":"vdi-user","container_idle_timeout_mins":60
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        let vdi = req.vdi.as_ref().expect("vdi params");
        assert_eq!(
            vdi.container_image.as_deref(),
            Some("registry.example.com/desktop:latest")
        );
        assert_eq!(vdi.container_cpu_limit, Some(2.0));
        assert_eq!(vdi.container_memory_limit, Some(4096));
        assert_eq!(vdi.container_username.as_deref(), Some("vdi-user"));

        // SPICE: spice_* keys land in SpiceParams; color_depth still routes
        // to VncParams (its canonical home, shared with SPICE).
        let json = r#"{
            "session_type":"spice","hostname":"qemu1","port":5900,
            "spice_tls":true,"spice_tls_port":5910,
            "spice_ca_cert":"CERT","spice_cert_subject":"subject","spice_proxy":"http://proxy:3128",
            "color_depth":16
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        let spice = req.spice.as_ref().expect("spice params");
        assert_eq!(spice.spice_tls, Some(true));
        assert_eq!(spice.spice_tls_port, Some(5910));
        assert_eq!(spice.spice_ca_cert.as_deref(), Some("CERT"));
        assert_eq!(spice.spice_cert_subject.as_deref(), Some("subject"));
        assert_eq!(spice.spice_proxy.as_deref(), Some("http://proxy:3128"));
        assert_eq!(req.vnc.as_ref().and_then(|v| v.color_depth), Some(16));

        // Proxmox: proxmox_* keys land in ProxmoxParams.
        let json = r#"{
            "session_type":"proxmox",
            "proxmox_url":"https://pve.example.com:8006","proxmox_node":"pve1",
            "proxmox_vmid":100,"proxmox_token_id":"root@pam!persea",
            "proxmox_token_secret":"aaaa-bbbb","proxmox_verify_tls":true
        }"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        let proxmox = req.proxmox.as_ref().expect("proxmox params");
        assert_eq!(
            proxmox.proxmox_url.as_deref(),
            Some("https://pve.example.com:8006")
        );
        assert_eq!(proxmox.proxmox_node.as_deref(), Some("pve1"));
        assert_eq!(proxmox.proxmox_vmid, Some(100));
        assert_eq!(proxmox.proxmox_token_id.as_deref(), Some("root@pam!persea"));
        assert_eq!(proxmox.proxmox_token_secret.as_deref(), Some("aaaa-bbbb"));
        assert_eq!(proxmox.proxmox_verify_tls, Some(true));
    }

    #[test]
    fn empty_flat_json_defaults_to_ssh_with_all_none() {
        let req: CreateSessionRequest = serde_json::from_str("{}").unwrap();
        assert_eq!(req.session_type, SessionType::Ssh);
        assert!(req.hostname.is_none());
        // Flattened Option structs are always Some; absence is None fields.
        assert!(req.ssh.as_ref().unwrap().private_key.is_none());
        assert!(req.rdp.as_ref().unwrap().domain.is_none());
        assert!(req.web.as_ref().unwrap().url.is_none());
        assert!(req.proxmox.as_ref().unwrap().proxmox_url.is_none());
    }

    #[test]
    fn unknown_flat_keys_are_silently_ignored() {
        let json = r#"{"session_type":"ssh","hostname":"x","bogus_key":42}"#;
        let req: CreateSessionRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.hostname.as_deref(), Some("x"));
        assert!(req.ssh.as_ref().unwrap().private_key.is_none());
        assert!(req.rdp.as_ref().unwrap().domain.is_none());
    }
}
