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
    #[default]
    Ssh,
    Web,
    Rdp,
    Vnc,
    Vdi,
    Spice,
    Proxmox,
}

/// Parameters for creating a new session.
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    #[serde(default)]
    pub session_type: SessionType,
    // SSH fields (optional for backwards compat)
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub generate_keypair: Option<bool>,
    // Web fields
    pub url: Option<String>,
    // RDP fields
    pub domain: Option<String>,
    pub security: Option<String>,
    pub ignore_cert: Option<bool>,
    /// NLA auth package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional).
    pub kdc_url: Option<String>,
    /// Kerberos ticket cache path (optional).
    pub kerberos_cache: Option<String>,
    // VNC fields
    pub color_depth: Option<u8>,
    // SSH tunnel / jump host fields (multi-hop)
    pub jump_hosts: Option<Vec<tunnel::JumpHost>>,
    // Legacy flat fields for backward compat (single jump host)
    pub jump_host: Option<String>,
    pub jump_port: Option<u16>,
    pub jump_username: Option<String>,
    pub jump_password: Option<String>,
    pub jump_private_key: Option<String>,
    // Common
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub dpi: Option<u32>,
    pub banner: Option<String>,
    /// Override drive/file transfer setting for this session.
    pub enable_drive: Option<bool>,
    // RDP RemoteApp (RAIL)
    pub remote_app: Option<String>,
    pub remote_app_dir: Option<String>,
    pub remote_app_args: Option<String>,
    // Recording overrides
    pub enable_recording: Option<bool>,
    /// Enable SSH typescript recording for this session (#159). Default
    /// off; SSH only; requires `[recording].typescript_path` configured.
    pub record_typescript: Option<bool>,
    /// Address book entry key (e.g. "shared/folder/entry") for recording metadata.
    pub address_book_entry: Option<String>,
    /// Address book folder name (for reporting).
    pub address_book_folder: Option<String>,
    /// Display name of the address book entry (for reporting).
    pub entry_display_name: Option<String>,
    /// Per-entry max recordings to keep.
    pub max_recordings: Option<u32>,
    /// Login script filename to run after browser spawns (web sessions only).
    pub login_script: Option<String>,
    /// Autofill credentials JSON for web sessions.
    /// Array of {"url", "username", "password"} with $USERNAME/$PASSWORD placeholders.
    pub autofill: Option<String>,
    /// Allowed domains for web sessions. When set, Chromium can only reach these domains.
    pub allowed_domains: Option<Vec<String>>,
    /// Disable clipboard copy (server → client).
    pub disable_copy: Option<bool>,
    /// Disable clipboard paste (client → server).
    pub disable_paste: Option<bool>,
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
    // VDI fields
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
    /// Proxmox VE console (SessionType::Proxmox): PVE API base URL, a full URL
    /// including scheme and port (e.g. "https://pve.example.com:8006"). persea
    /// fetches a just-in-time SPICE ticket + config from the PVE spiceproxy API
    /// at connect.
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
    /// Total number of monitors to offer (SPICE/Proxmox multi-monitor). guacd
    /// is told `secondary-monitors = max_monitors - 1`, which it advertises to
    /// the client. Default 1 (single monitor).
    pub max_monitors: Option<u32>,
}

/// Session status in the lifecycle.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Hash)]
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
}

/// Public session info returned by the API.
#[derive(Debug, Clone, Serialize)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub session_type: SessionType,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub client_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub share_url: Option<String>,
    pub ws_url: String,
    pub hostname: String,
    pub username: String,
    pub active_connections: u32,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_entry: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_book_folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_display_name: Option<String>,
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
}

/// Internal session state including the guacd connection.
pub struct Session {
    pub id: Uuid,
    pub session_type: SessionType,
    pub status: SessionStatus,
    pub created_at: DateTime<Utc>,
    pub hostname: String,
    pub username: String,
    pub url: Option<String>,
    pub banner: Option<String>,
    pub guacd_stream: Option<GuacdStream>,
    pub connection_id: String,
    pub share_token: String,
    pub width: u32,
    pub height: u32,
    pub active_connections: u32,
    pub created_by: String,
    pub cancel: tokio_util::sync::CancellationToken,
    pub browser_session: Option<BrowserSession>,
    /// Connection params for deferred guacd connection (ephemeral keypair sessions).
    /// When set, the guacd connection is established when the WebSocket connects
    /// instead of at session creation time.
    pub deferred_params: Option<crate::guacd::ConnectionParams>,
    /// Per-session drive directory path (RDP sessions with drive enabled).
    pub drive_path: Option<std::path::PathBuf>,
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
    pub token_hash: String,
    pub issued_by: String,
    pub expires_at: DateTime<Utc>,
}

/// Result of validating a share-or-shadow token. Callers use this to tell
/// owner traffic from admin-minted shadow viewers, and to audit each shadow
/// use (the raw mint is audited separately; re-use is logged per connection
/// so a leaked token's blast radius is observable after the fact).
#[derive(Debug, Clone, PartialEq)]
pub enum ShareTokenValidation {
    Invalid,
    Owner,
    Shadow { issued_by: String },
}

impl ShareTokenValidation {
    pub fn is_valid(&self) -> bool {
        !matches!(self, ShareTokenValidation::Invalid)
    }
}

#[derive(Debug)]
#[must_use]
pub enum SessionError {
    GuacdConnection(String),
    NotFound,
    NotActive,
    ValidationError(String),
    BrowserSpawn(String),
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

    pub fn info(&self) -> SessionInfo {
        SessionInfo {
            session_id: self.id,
            session_type: self.session_type.clone(),
            status: self.status.clone(),
            created_at: self.created_at,
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
        }
    }
}
