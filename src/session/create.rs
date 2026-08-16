use super::manager::SessionManager;
use super::types::*;
use crate::drive;
use crate::guacd;
use crate::tunnel;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use std::net::ToSocketAddrs;
use url::Url;
use uuid::Uuid;

use tokio::time;

use std::time::Duration;

/// Command used when `ssh_tmux_detach` is enabled: attach to the most
/// recent tmux session with `-d` (kicking any stale client left attached
/// by an abrupt disconnect), or create a fresh session if none exists.
const TMUX_DETACH_WRAPPER: &str = "tmux attach-session -d 2>/dev/null || tmux new-session";

/// Maximum length of the RDP `client-name` value. guacd truncates the
/// FreeRDP client hostname to 32 bytes (`RDP_CLIENT_HOSTNAME_SIZE`);
/// persea truncates first so the value on the wire matches what Windows
/// records.
const RDP_CLIENT_NAME_MAX_CHARS: usize = 32;

/// Maximum jump-host hops in a chain. Every hop spawns an SSH session and
/// a local listener, so unbounded chains are a resource-exhaustion risk.
const MAX_JUMP_HOST_HOPS: usize = 8;

/// Expand the `[rdp] client_name_template` into the RDP `client-name`
/// value: `{user}` = the persea identity that created the session,
/// `{host}` = the resolved client hostname (or IP). Any other placeholder
/// passes through verbatim.
fn expand_rdp_client_name_template(template: &str, user: &str, host: &str) -> String {
    template
        .replace("{user}", user)
        .replace("{host}", host)
        .chars()
        .take(RDP_CLIENT_NAME_MAX_CHARS)
        .collect()
}

/// Resolve the connecting client's hostname via reverse DNS with a 1
/// second budget. Any failure (missing IP, unparseable address, NXDOMAIN,
/// timeout) falls back to the raw IP so session creation is never delayed
/// by DNS. An unknown IP (no value at all) yields "unknown".
async fn resolve_client_host(client_ip: Option<&str>) -> String {
    let Some(ip_str) = client_ip.filter(|s| !s.is_empty()) else {
        return "unknown".to_string();
    };
    let Ok(addr) = ip_str.parse::<std::net::IpAddr>() else {
        return ip_str.to_string();
    };
    let lookup = async {
        tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&addr))
            .await
            .unwrap_or_else(|e| Err(std::io::Error::other(e)))
    };
    match tokio::time::timeout(Duration::from_secs(1), lookup).await {
        Ok(Ok(name)) => {
            let name = name.trim().trim_end_matches('.').to_string();
            if name.is_empty() {
                ip_str.to_string()
            } else {
                name
            }
        }
        _ => ip_str.to_string(),
    }
}

/// Effective per-protocol global defaults for one session creation (admin
/// Settings → Session → Session defaults). Precedence: the request/entry
/// value wins, then the stored global default (system_settings), then this
/// struct's code defaults — the hardcoded values the create path used
/// before the feature existed. Read once per create from the DB settings
/// overlay loaded at the top of `create_session`, so a settings change
/// affects new sessions only.
struct ProtocolDefaults {
    width: u32,
    height: u32,
    dpi: u32,
    rdp_security: Option<String>,
    rdp_h264: bool,
    rdp_gfx: bool,
    rdp_drive: Option<bool>,
    vnc_color_depth: Option<u8>,
    vnc_disable_copy: bool,
    vnc_disable_paste: bool,
}

impl ProtocolDefaults {
    fn from_settings(session_type: &SessionType, settings: &[(String, String)]) -> Self {
        let stored_u32 = |key: &str, code: u32| {
            settings
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.parse::<u32>().ok())
                .unwrap_or(code)
        };
        let stored_bool = |key: &str| match settings
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
        {
            Some("true") => Some(true),
            Some("false") => Some(false),
            _ => None,
        };
        let stored_str = |key: &str| {
            settings
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        let (width, height) = match session_type {
            SessionType::Ssh => (
                stored_u32("default_ssh_width", 1920),
                stored_u32("default_ssh_height", 1080),
            ),
            SessionType::Rdp => (
                stored_u32("default_rdp_width", 1920),
                stored_u32("default_rdp_height", 1080),
            ),
            _ => (1920, 1080),
        };
        Self {
            width,
            height,
            dpi: match session_type {
                SessionType::Rdp => stored_u32("default_rdp_dpi", 96),
                _ => 96,
            },
            rdp_security: stored_str("default_rdp_security")
                .filter(|s| matches!(s.as_str(), "any" | "rdp" | "tls" | "nla")),
            rdp_h264: stored_bool("default_rdp_h264").unwrap_or(true),
            rdp_gfx: stored_bool("default_rdp_gfx").unwrap_or(true),
            rdp_drive: stored_bool("default_rdp_drive"),
            vnc_color_depth: settings
                .iter()
                .find(|(k, _)| k == "default_vnc_color_depth")
                .and_then(|(_, v)| v.parse::<u8>().ok()),
            vnc_disable_copy: stored_bool("default_vnc_disable_copy").unwrap_or(false),
            vnc_disable_paste: stored_bool("default_vnc_disable_paste").unwrap_or(false),
        }
    }
}

/// Resolve the container username for a VDI session. The per-entry
/// override wins when set; otherwise the operator's identity (the part
/// before any `@` domain) is used. Either way the result is reduced to
/// `[a-z0-9_]` so it is safe in the home bind-mount path, the
/// `VDI_USERNAME` env var, and `chpasswd`. The override is additionally
/// rejected outright when it contains a path separator or a traversal
/// component: it becomes part of a host path, and mapping `..` away
/// would silently change the identity a baked-in account expects.
fn vdi_container_username(
    container_username: Option<&str>,
    created_by: &str,
) -> Result<String, SessionError> {
    let raw = match container_username.filter(|s| !s.is_empty()) {
        Some(raw) => raw,
        None => {
            return Ok(created_by
                .split('@')
                .next()
                .unwrap_or(created_by)
                .to_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>())
        }
    };
    if raw.contains('/') || raw.contains('\\') || raw.contains("..") {
        return Err(SessionError::ValidationError(
            "container_username must not contain '/', '\\', or '..'".into(),
        ));
    }
    let sanitized = raw
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect::<String>();
    if sanitized.is_empty() {
        return Err(SessionError::ValidationError(
            "container_username must contain at least one letter or digit".into(),
        ));
    }
    Ok(sanitized)
}

/// Count sessions in Pending|Active state: the only states that hold a
/// live connection, and therefore the only ones that should count
/// against the global session cap. Terminal states (completed, expired,
/// errored, logged out) stay in the map until the cleanup reaper runs
/// and must not block new sessions.
async fn count_live_sessions(
    sessions: &std::collections::HashMap<Uuid, std::sync::Arc<tokio::sync::Mutex<Session>>>,
) -> usize {
    let mut count = 0usize;
    for session in sessions.values() {
        if matches!(
            session.lock().await.status,
            SessionStatus::Pending | SessionStatus::Active
        ) {
            count += 1;
        }
    }
    count
}

impl SessionManager {
    /// Create a new session: connect to guacd, perform handshake, return session info.
    /// `client_ip` is the connecting client's IP (from the HTTP layer,
    /// already X-Forwarded-For aware); RDP sessions use it for the
    /// `client-name` parameter.
    pub async fn create_session(
        self: &std::sync::Arc<Self>,
        req: CreateSessionRequest,
        created_by: String,
        client_ip: Option<String>,
    ) -> Result<SessionInfo, SessionError> {
        // Enforce the per-user session limit (only counts Pending|Active
        // sessions). The global limit is enforced under the sessions map
        // write lock at insert time, so concurrent creates cannot race
        // past it.
        {
            let sessions = self.sessions.read().await;
            let max_per_user = self.config.max_sessions_per_user;

            if max_per_user > 0 {
                let mut user_count = 0usize;
                for session in sessions.values() {
                    let s = session.lock().await;
                    if s.created_by == created_by
                        && matches!(s.status, SessionStatus::Pending | SessionStatus::Active)
                    {
                        user_count += 1;
                    }
                }
                if user_count >= max_per_user {
                    return Err(SessionError::ValidationError(format!(
                        "maximum sessions per user reached ({})",
                        max_per_user
                    )));
                }
            }
        }

        // Reject new sessions during graceful shutdown
        if self.is_shutting_down() {
            return Err(SessionError::ValidationError(
                "server is shutting down — new sessions are not accepted".into(),
            ));
        }

        // Admin lockdown toggles from the Settings page — a disabled
        // protocol must not spawn sessions. The DB overlay is read once per
        // creation attempt (live: flipping a toggle takes effect without a
        // restart); unset or unreadable toggles default to enabled so
        // existing deployments behave exactly as before.
        let settings: Vec<(String, String)> = match &self.db {
            Some(db) => {
                let db = db.clone();
                match tokio::task::spawn_blocking(move || {
                    crate::settings_merge::load_db_settings(&db)
                })
                .await
                {
                    Ok(rows) => rows.unwrap_or_default(),
                    Err(_) => Vec::new(),
                }
            }
            None => Vec::new(),
        };
        let toggle = |key: &str| crate::settings_merge::toggle_enabled(&settings, key, true);
        check_session_type_enabled(&req.session_type, req.address_book_entry.as_deref(), toggle)?;

        // Effective per-protocol global defaults (admin Settings → Session
        // → Session defaults). Precedence: the request/entry value wins,
        // then the stored global default, then the code defaults inside
        // `ProtocolDefaults`. Read once per create — a settings change
        // affects new sessions only, never existing ones.
        let defaults = ProtocolDefaults::from_settings(&req.session_type, &settings);

        let session_id = Uuid::new_v4();
        // V09: connection reason, trimmed and normalized before any of
        // `req`'s fields are moved into the session literal below.
        let reason = req
            .reason
            .as_deref()
            .map(str::trim)
            .filter(|r| !r.is_empty())
            .map(str::to_string);
        // Protocol-specific params land in flattened sub-structs (see
        // CreateSessionRequest); bind them up-front for ergonomic access.
        let ssh = req.ssh.as_ref();
        let rdp = req.rdp.as_ref();
        let vnc = req.vnc.as_ref();
        let web = req.web.as_ref();
        // On Windows the Vdi arm returns at the guard, so this binding is
        // unused there — the feature stays compiled (runtime guard).
        #[allow(unused_variables)]
        let vdi_params = req.vdi.as_ref();
        let spice = req.spice.as_ref();
        let proxmox = req.proxmox.as_ref();
        let raw_width = req.width.unwrap_or(defaults.width);
        let raw_height = req.height.unwrap_or(defaults.height);
        let raw_dpi = req.dpi.unwrap_or(defaults.dpi);
        let width = raw_width.clamp(640, 8192);
        let height = raw_height.clamp(480, 8192);
        let dpi = raw_dpi.clamp(16, 384);
        if width != raw_width || height != raw_height || dpi != raw_dpi {
            tracing::warn!(
                session_id = %session_id,
                raw_width, raw_height, raw_dpi,
                clamped_width = width, clamped_height = height, clamped_dpi = dpi,
                "Clamped session dimensions to safe range"
            );
        }

        // Derive the known_hosts path for SSH trust-on-first-use persistence.
        let known_hosts_path = self.config.db_path.parent().map(|p| p.join("known_hosts"));

        // Resolve jump hosts (SSH tunnel chain) up-front: the Proxmox branch
        // needs them to tunnel its PVE API + SPICE-proxy connections in-branch,
        // and the generic tunnel setup after the match uses them for the other
        // session types.
        let jump_hops: Vec<tunnel::JumpHost> = if let Some(hops) = req.jump_hosts {
            if hops.len() > MAX_JUMP_HOST_HOPS {
                return Err(SessionError::ValidationError(format!(
                    "jump host chain is too long: at most {} hops are supported (got {})",
                    MAX_JUMP_HOST_HOPS,
                    hops.len()
                )));
            }
            hops
        } else if let Some(ref jh) = req.jump_host {
            if !jh.is_empty() {
                vec![tunnel::JumpHost {
                    hostname: jh.clone(),
                    port: req.jump_port.unwrap_or(22),
                    username: req.jump_username.clone().unwrap_or_default(),
                    password: req.jump_password.clone(),
                    private_key: req.jump_private_key.clone(),
                    host_key: None,
                }]
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        };
        // Tunnels the Proxmox branch establishes in-branch (PVE API + SPICE
        // proxy hops); merged into the session's tunnel list after the match.
        let mut proxmox_tunnels: Vec<tunnel::SshTunnel> = Vec::new();

        let mut pending_net_check: Option<(String, u16, Vec<String>)> = None;

        let (
            mut conn_params,
            hostname,
            username,
            url,
            mut browser_session,
            banner_override,
            session_drive_path,
            container_id,
            container_name,
        ) = match req.session_type {
            SessionType::Ssh => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for SSH sessions".into())
                })?;
                let port = req.port.unwrap_or(22);
                let username = req.username.clone().unwrap_or_default();

                pending_net_check = Some((
                    hostname.clone(),
                    port,
                    self.config.ssh_allowed_networks.clone(),
                ));

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    "Creating new SSH session"
                );

                let (private_key, ssh_banner) = if ssh
                    .and_then(|s| s.generate_keypair)
                    .unwrap_or(false)
                {
                    let keypair = ssh_key::PrivateKey::random(
                        &mut ssh_key::rand_core::OsRng,
                        ssh_key::Algorithm::Ed25519,
                    )
                    .map_err(|e| {
                        SessionError::ValidationError(format!("keypair generation failed: {}", e))
                    })?;

                    let private_pem = keypair.to_openssh(ssh_key::LineEnding::LF).map_err(|e| {
                        SessionError::ValidationError(format!("private key export failed: {}", e))
                    })?;

                    let public_key = format!(
                        "{} persea-ephemeral",
                        keypair.public_key().to_openssh().map_err(|e| {
                            SessionError::ValidationError(format!(
                                "public key export failed: {}",
                                e
                            ))
                        })?
                    );

                    let auth_keys_path = if username.is_empty() {
                        "~/.ssh/authorized_keys".to_string()
                    } else {
                        format!("~{}/.ssh/authorized_keys", username)
                    };

                    let mut banner = format!(
                        "Add this public key to {} on the target host:\n\n{}\n\nDo not click Continue until the key is installed — authentication will fail.",
                        auth_keys_path, public_key
                    );
                    if let Some(ref user_banner) = req.banner {
                        banner = format!("{}\n\n{}", user_banner, banner);
                    }

                    tracing::info!(session_id = %session_id, "Generated ephemeral SSH keypair");
                    (Some(private_pem.to_string()), Some(banner))
                } else {
                    (ssh.and_then(|s| s.private_key.clone()), None)
                };

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive)
                    && toggle("enable_file_transfer");
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);

                // SSH typescript recording (#159): per-connection opt-in
                // (default off), and only when a global typescript_path is
                // configured. persea expands the name template (guacd
                // uses it verbatim) so audit files are identifiable per
                // user + connection.
                let typescript = self
                    .config
                    .ssh_typescript()
                    .filter(|_| ssh.is_some_and(|s| s.record_typescript == Some(true)))
                    .map(|(path, name, create)| {
                        let template = name.as_deref().unwrap_or(DEFAULT_TYPESCRIPT_NAME);
                        let connection = req
                            .entry_display_name
                            .as_deref()
                            .filter(|s| !s.is_empty())
                            .unwrap_or(&hostname);
                        let expanded = expand_typescript_name(
                            template,
                            &username,
                            &hostname,
                            connection,
                            &session_id,
                            Utc::now(),
                        );
                        (path, expanded, create)
                    });
                let params = guacd::ConnectionParams::Ssh(guacd::SshParams {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    private_key,
                    width,
                    height,
                    dpi,
                    enable_sftp: drive_enabled,
                    sftp_disable_download: !drive_cfg.allow_download,
                    sftp_disable_upload: !drive_cfg.allow_upload,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    scrollback: self.config.ssh_scrollback,
                    typescript_path: typescript.as_ref().map(|(p, _, _)| p.clone()),
                    typescript_name: typescript.as_ref().map(|(_, n, _)| n.clone()),
                    create_typescript_path: typescript
                        .as_ref()
                        .map(|(_, _, c)| *c)
                        .unwrap_or(false),
                    command: self
                        .config
                        .ssh_tmux_detach
                        .then(|| TMUX_DETACH_WRAPPER.to_string()),
                });
                (
                    params, hostname, username, None, None, ssh_banner, None, None, None,
                )
            }
            SessionType::Rdp => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for RDP sessions".into())
                })?;
                let port = req.port.unwrap_or(3389);
                let username = req.username.clone().unwrap_or_default();

                pending_net_check = Some((
                    hostname.clone(),
                    port,
                    self.config.rdp_allowed_networks.clone(),
                ));

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    width, height, dpi,
                    "Creating new RDP session"
                );

                // RDP drive: request/entry override wins, then the global
                // default_rdp_drive setting, then the [drive] config
                // section (drive on only when configured and enabled).
                let drive_enabled = drive::is_drive_enabled(
                    &self.config.drive,
                    req.enable_drive.or(defaults.rdp_drive),
                ) && toggle("enable_file_transfer");
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);
                tracing::info!(
                    %session_id,
                    drive_enabled,
                    entry_enable_drive = ?req.enable_drive,
                    has_drive_config = self.config.drive.is_some(),
                    drive_path = ?drive_cfg.drive_path,
                    "Drive configuration"
                );

                // Create per-session drive directory for RDP
                let session_drive_path = if drive_enabled {
                    match drive::create_session_dir(&drive_cfg, session_id) {
                        Ok(path) => Some(path),
                        Err(e) => {
                            tracing::warn!(session_id = %session_id, "Failed to create drive dir: {}", e);
                            None
                        }
                    }
                } else {
                    None
                };

                let rdp_ignore_cert = req.ignore_cert.unwrap_or(false);
                // RDP security: request/entry value wins, else the global
                // default_rdp_security setting; unset passes None through
                // (guacd falls back to "any").
                let rdp_security = rdp
                    .and_then(|s| s.security.clone())
                    .or_else(|| defaults.rdp_security.clone());
                let rdp_enable_drive = session_drive_path.is_some();
                // RDP client-name: expand `[rdp] client_name_template`
                // ({user} = persea identity, {host} = reverse-DNS of the
                // connecting client or its IP). An empty template disables
                // the parameter, keeping the pre-feature handshake.
                let client_name_template = self
                    .config
                    .rdp
                    .as_ref()
                    .and_then(|r| r.client_name_template.as_deref())
                    .unwrap_or(crate::config::DEFAULT_RDP_CLIENT_NAME_TEMPLATE);
                let client_name = if client_name_template.trim().is_empty() {
                    None
                } else {
                    let host = resolve_client_host(client_ip.as_deref()).await;
                    tracing::info!(
                        session_id = %session_id,
                        client_ip = ?client_ip,
                        resolved_host = %host,
                        template = %client_name_template,
                        "RDP client name resolved"
                    );
                    Some(expand_rdp_client_name_template(
                        client_name_template,
                        &created_by,
                        &host,
                    ))
                };
                tracing::info!(
                    %session_id,
                    ignore_cert = rdp_ignore_cert,
                    security = ?rdp_security,
                    enable_drive = rdp_enable_drive,
                    drive_path = ?session_drive_path,
                    domain = ?rdp.and_then(|s| s.domain.as_ref()),
                    has_password = req.password.is_some(),
                    client_name = ?client_name,
                    "RDP session params"
                );
                let params = guacd::ConnectionParams::Rdp(Box::new(guacd::RdpParams {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    domain: rdp.and_then(|s| s.domain.clone()),
                    security: rdp_security,
                    client_name,
                    width,
                    height,
                    dpi,
                    ignore_cert: rdp_ignore_cert,
                    enable_drive: rdp_enable_drive,
                    drive_path: session_drive_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string()),
                    drive_name: drive_cfg.drive_name.clone(),
                    disable_download: !drive_cfg.allow_download,
                    disable_upload: !drive_cfg.allow_upload,
                    auth_pkg: super::resolve_rdp_auth_pkg(
                        rdp.and_then(|s| s.auth_pkg.as_deref()),
                        &self.config,
                    ),
                    kdc_url: rdp.and_then(|s| s.kdc_url.clone()),
                    kerberos_cache: rdp.and_then(|s| s.kerberos_cache.clone()),
                    remote_app: rdp.and_then(|s| s.remote_app.clone()),
                    remote_app_dir: rdp.and_then(|s| s.remote_app_dir.clone()),
                    remote_app_args: rdp.and_then(|s| s.remote_app_args.clone()),
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_gfx: rdp.and_then(|s| s.enable_gfx).unwrap_or(defaults.rdp_gfx),
                    enable_desktop_composition: rdp
                        .and_then(|s| s.enable_desktop_composition)
                        .unwrap_or(false),
                    enable_wallpaper: rdp.and_then(|s| s.enable_wallpaper).unwrap_or(false),
                    enable_theming: rdp.and_then(|s| s.enable_theming).unwrap_or(false),
                    enable_full_window_drag: rdp
                        .and_then(|s| s.enable_full_window_drag)
                        .unwrap_or(false),
                    force_lossless: rdp.and_then(|s| s.force_lossless).unwrap_or(false),
                    enable_h264: rdp.and_then(|s| s.enable_h264).unwrap_or(defaults.rdp_h264),
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                }));
                (
                    params,
                    hostname,
                    username,
                    None,
                    None,
                    None,
                    session_drive_path,
                    None,
                    None,
                )
            }
            SessionType::Vnc => {
                let hostname = req.hostname.ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for VNC sessions".into())
                })?;
                let port = req.port.unwrap_or(5900);
                let username = req.username.clone().unwrap_or_default();

                pending_net_check = Some((
                    hostname.clone(),
                    port,
                    self.config.vnc_allowed_networks.clone(),
                ));

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    width, height, dpi,
                    "Creating new VNC session"
                );

                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: hostname.clone(),
                    port,
                    password: req.password.clone(),
                    color_depth: vnc.and_then(|s| s.color_depth).or(defaults.vnc_color_depth),
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(defaults.vnc_disable_copy),
                    disable_paste: req.disable_paste.unwrap_or(defaults.vnc_disable_paste),
                });
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
            }
            SessionType::Spice => {
                let username = req.username.clone().unwrap_or_default();

                // Direct SPICE connection to a SPICE server (e.g. libvirt/QEMU).
                let hostname = req.hostname.clone().ok_or_else(|| {
                    SessionError::ValidationError("hostname is required for SPICE sessions".into())
                })?;
                let port = req.port.unwrap_or(5900);
                check_allowed_network(&hostname, port, &self.config.vnc_allowed_networks).await?;

                let spice = guacd::SpiceParams {
                    hostname: hostname.clone(),
                    port,
                    password: req.password.clone(),
                    username: req.username.clone(),
                    tls: spice.and_then(|s| s.spice_tls).unwrap_or(false),
                    tls_port: spice.and_then(|s| s.spice_tls_port),
                    ca_cert: spice.and_then(|s| s.spice_ca_cert.clone()),
                    cert_subject: spice.and_then(|s| s.spice_cert_subject.clone()),
                    ignore_cert: req.ignore_cert.unwrap_or(false),
                    proxy: spice.and_then(|s| s.spice_proxy.clone()),
                    color_depth: vnc.and_then(|s| s.color_depth),
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_audio: false,
                    // Secondary monitors = total requested minus the primary.
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                };
                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    width, height, dpi,
                    "Creating new SPICE session"
                );

                let params = guacd::ConnectionParams::Spice(Box::new(spice));
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
            }
            SessionType::Proxmox => {
                let username = req.username.clone().unwrap_or_default();

                // Proxmox VE console: SPICE brokered through the PVE spiceproxy
                // API. Tickets are one-time and short-lived, so fetch a
                // just-in-time SPICE config at connect rather than storing it.
                let pve_url = proxmox.and_then(|s| s.proxmox_url.clone()).ok_or_else(|| {
                    SessionError::ValidationError("Proxmox sessions require proxmox_url".into())
                })?;

                let (pve_host, pve_port) = parse_host_port(&pve_url, 8006)?;
                check_allowed_network(&pve_host, pve_port, &self.config.web_allowed_networks)
                    .await?;
                reject_denied_target(&pve_host)?;

                let vmid = proxmox.and_then(|s| s.proxmox_vmid).unwrap_or(0);
                if vmid == 0 {
                    return Err(SessionError::ValidationError(
                        "Proxmox sessions require proxmox_vmid".into(),
                    ));
                }
                let verify_tls = proxmox.and_then(|s| s.proxmox_verify_tls).unwrap_or(true);

                // Join the token id and secret into PVE's "id=secret" form. If
                // the secret is empty, treat the id as already-joined (lenient:
                // allows pasting a full "id=secret" into the id field).
                let token_id = proxmox
                    .and_then(|s| s.proxmox_token_id.clone())
                    .unwrap_or_default();
                let secret = proxmox
                    .and_then(|s| s.proxmox_token_secret.clone())
                    .unwrap_or_default();
                if token_id.is_empty() {
                    return Err(SessionError::ValidationError(
                        "Proxmox API token ID is required (format user@realm!tokenid, e.g. root@pam!persea)".into(),
                    ));
                }
                if secret.is_empty() {
                    return Err(SessionError::ValidationError(
                        "Proxmox API token secret is required".into(),
                    ));
                }
                let api_token = if secret.is_empty() {
                    token_id
                } else {
                    format!("{token_id}={secret}")
                };

                // If jump hosts are configured, tunnel the PVE API endpoint so
                // the broker call reaches it through the bastion. The tunnelled
                // endpoint is 127.0.0.1, which no PVE cert matches, so cert
                // verification is disabled for this hop (the SSH tunnel secures
                // the transport). The SPICE server cert is still verified below.
                let (broker_base, broker_verify) = if !jump_hops.is_empty() {
                    let (api_host, api_port) = parse_host_port(&pve_url, 8006)?;
                    let (mut tuns, api_local) = tunnel::start_chain(
                        &jump_hops,
                        &api_host,
                        api_port,
                        known_hosts_path.clone(),
                    )
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox API tunnel failed: {e}"))
                    })?;
                    proxmox_tunnels.append(&mut tuns);
                    tracing::info!(
                        session_id = %session_id,
                        api_local = %api_local,
                        hops = jump_hops.len(),
                        "Tunnelled Proxmox PVE API through jump host(s)"
                    );
                    (format!("https://{api_local}"), false)
                } else {
                    (pve_url, verify_tls)
                };

                let broker = crate::pve::PveBroker {
                    base_url: broker_base,
                    api_token,
                    verify_tls: broker_verify,
                };

                // The node is optional: if not given, resolve which node hosts
                // the VM via /cluster/resources (as the PVE web UI does), so the
                // node-scoped console API can be reached with only the VM id.
                let node = match proxmox
                    .and_then(|s| s.proxmox_node.clone())
                    .filter(|n| !n.trim().is_empty())
                {
                    Some(n) => n,
                    None => broker.resolve_node(vmid).await.map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox node lookup failed: {e}"))
                    })?,
                };

                let mut cfg = broker
                    .fetch_spice_config(&node, vmid, crate::pve::PveVmType::Qemu, None)
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!("Proxmox SPICE broker failed: {e}"))
                    })?;
                tracing::info!(
                    session_id = %session_id,
                    node = %node,
                    vmid,
                    proxy = %cfg.proxy,
                    "Creating Proxmox VE SPICE console session"
                );

                // Tunnel the SPICE proxy too, and point guacd at the local
                // forward. The proxy hop is plain HTTP; the SPICE-over-TLS link
                // is tunnelled transparently inside the proxy CONNECT, so the
                // SPICE server cert still verifies.
                if !jump_hops.is_empty() {
                    let (proxy_host, proxy_port) = parse_host_port(&cfg.proxy, 3128)?;
                    let (mut tuns, proxy_local) = tunnel::start_chain(
                        &jump_hops,
                        &proxy_host,
                        proxy_port,
                        known_hosts_path.clone(),
                    )
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!(
                            "Proxmox SPICE proxy tunnel failed: {e}"
                        ))
                    })?;
                    proxmox_tunnels.append(&mut tuns);
                    tracing::info!(
                        session_id = %session_id,
                        proxy_local = %proxy_local,
                        "Tunnelled Proxmox SPICE proxy through jump host(s)"
                    );
                    cfg.proxy = format!("http://{proxy_local}");
                }

                // Proxmox SPICE is TLS-only: no plaintext port (guacd sends an
                // empty "port" arg whenever tls is set). The one-time ticket is
                // the SPICE password. PVE ships a self-signed cluster cert; when
                // verification is requested, verify against the returned cluster
                // CA + host subject, otherwise skip verification entirely.
                let spice = guacd::SpiceParams {
                    hostname: cfg.host.clone(),
                    port: 0,
                    password: Some(cfg.ticket),
                    username: req.username.clone(),
                    tls: true,
                    tls_port: Some(cfg.tls_port),
                    ca_cert: if verify_tls { Some(cfg.ca_cert) } else { None },
                    cert_subject: if verify_tls {
                        Some(cfg.host_subject)
                    } else {
                        None
                    },
                    ignore_cert: !verify_tls,
                    proxy: Some(cfg.proxy),
                    color_depth: vnc.and_then(|s| s.color_depth),
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_audio: false,
                    // Secondary monitors = total requested minus the primary.
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                };

                // `cfg.host` is an opaque PVE routing token, used as the display
                // hostname for the session.
                let hostname = cfg.host;
                let params = guacd::ConnectionParams::Spice(Box::new(spice));
                (
                    params, hostname, username, None, None, None, None, None, None,
                )
            }
            SessionType::Web => {
                let raw_url = web.and_then(|s| s.url.clone()).ok_or_else(|| {
                    SessionError::ValidationError("url is required for web sessions".into())
                })?;

                // Step 1: Validate raw URL template (scheme must be http/https)
                let parsed = Url::parse(&raw_url)
                    .map_err(|e| SessionError::ValidationError(format!("invalid URL: {}", e)))?;
                match parsed.scheme() {
                    "http" | "https" => {}
                    s => {
                        return Err(SessionError::ValidationError(format!(
                            "URL scheme '{}' not allowed (must be http or https)",
                            s
                        )))
                    }
                }

                // Step 2: URL-encode and substitute credential placeholders
                let enc_user = urlencoding::encode(req.username.as_deref().unwrap_or(""));
                let enc_pass = urlencoding::encode(req.password.as_deref().unwrap_or(""));
                let url = raw_url
                    .replace("$RUSTGUAC_USERNAME", &enc_user)
                    .replace("$RUSTGUAC_PASSWORD", &enc_pass);

                // Step 3: Re-validate substituted URL
                let parsed = Url::parse(&url).map_err(|e| {
                    SessionError::ValidationError(format!(
                        "URL invalid after credential substitution: {}",
                        e
                    ))
                })?;
                match parsed.scheme() {
                    "http" | "https" => {}
                    s => {
                        return Err(SessionError::ValidationError(format!(
                            "URL scheme '{}' after substitution not allowed",
                            s
                        )))
                    }
                }

                let url_host = parsed
                    .host_str()
                    .ok_or_else(|| SessionError::ValidationError("URL has no host".into()))?;
                let url_port =
                    parsed
                        .port()
                        .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });

                check_allowed_network(url_host, url_port, &self.config.web_allowed_networks)
                    .await?;

                reject_denied_target(url_host)?;

                tracing::info!(
                    session_id = %session_id,
                    url = %url,
                    has_login_script = web.is_some_and(|s| s.login_script.is_some()),
                    "Creating new web session"
                );

                // Defer browser spawning — we may need to rewrite the URL
                // if jump hosts are configured (tunnel gets set up below).
                // Store a placeholder VNC params with port 0; will be updated
                // after browser spawn.
                let params = guacd::ConnectionParams::Vnc(guacd::VncParams {
                    hostname: "127.0.0.1".into(),
                    port: 0, // placeholder — updated after browser spawn
                    password: None,
                    color_depth: None,
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                });
                (
                    params,
                    "localhost".into(),
                    String::new(),
                    Some(url),
                    None, // browser spawned after tunnel setup
                    None,
                    None,
                    None,
                    None,
                )
            }
            SessionType::Vdi => {
                // Runtime feature guard (not compile-out): VDI needs Docker
                // container management, unsupported on Windows. Fails with a
                // clear error instead of a confusing "driver not initialized".
                #[cfg(windows)]
                {
                    return Err(SessionError::VdiError(
                        "VDI (Docker containers) is not supported on Windows — \
                         run persea on Linux for VDI desktops"
                            .into(),
                    ));
                }
                // On Windows the guard above returns, so the rest of the arm
                // is unreachable — by design (runtime guard, not compile-out).
                #[allow(unreachable_code)]
                let vdi_cfg = self
                    .config
                    .vdi
                    .as_ref()
                    .filter(|v| v.enabled)
                    .ok_or_else(|| SessionError::VdiError("VDI feature is not enabled".into()))?;
                let vdi = self
                    .vdi_driver
                    .as_ref()
                    .ok_or_else(|| SessionError::VdiError("VDI driver not initialized".into()))?;

                let image = vdi_params
                    .and_then(|s| s.container_image.clone())
                    .ok_or_else(|| {
                        SessionError::ValidationError(
                            "container_image is required for VDI sessions".into(),
                        )
                    })?;

                // Check allowed images whitelist
                if !vdi_cfg.allowed_images.is_empty() && !vdi_cfg.allowed_images.contains(&image) {
                    return Err(SessionError::VdiError(format!(
                        "image '{}' is not in the allowed list",
                        image
                    )));
                }

                // Username: per-entry override if set (for images with baked-in
                // accounts that don't honour VDI_USERNAME), otherwise derived
                // from the operator's identity. The derived form is also used
                // as the deterministic container-name suffix, so containers
                // are scoped per-operator. When the override is set the same
                // container is shared by everyone connecting with that entry,
                // which is the desired behaviour for shared baked-in accounts.
                // Both forms are sanitized; the override is rejected if it
                // carries a path separator or traversal component (it becomes
                // part of the home bind-mount path).
                let vdi_username = vdi_container_username(
                    vdi_params.and_then(|s| s.container_username.as_deref()),
                    &created_by,
                )?;
                let vdi_password = vdi_params
                    .and_then(|s| s.container_password.as_ref())
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(super::generate_share_token); // 32 hex chars

                // Merge env vars. We still set VDI_USERNAME/VDI_PASSWORD even
                // when the override is in use - that way images which DO read
                // the env vars get the right values, and images which ignore
                // them aren't affected. User-provided env never overrides the
                // core VDI vars.
                let mut env = vdi_params
                    .and_then(|s| s.container_env.clone())
                    .unwrap_or_default();
                env.insert("VDI_USERNAME".into(), vdi_username.clone());
                env.insert("VDI_PASSWORD".into(), vdi_password.clone());

                // Resolve resource limits: entry overrides > config defaults
                let cpu_limit = vdi_params
                    .and_then(|s| s.container_cpu_limit)
                    .unwrap_or(vdi_cfg.default_cpu_limit);
                let memory_limit_mb = vdi_params
                    .and_then(|s| s.container_memory_limit)
                    .unwrap_or(vdi_cfg.default_memory_limit);

                let spec = crate::vdi::ContainerSpec {
                    image: image.clone(),
                    username: vdi_username.clone(),
                    password: vdi_password.clone(),
                    cpu_limit,
                    memory_limit: memory_limit_mb * 1024 * 1024, // MB to bytes
                    env,
                    home_base: vdi_cfg.home_base.clone(),
                    entry_key: req.address_book_entry.clone(),
                    idle_timeout_mins: vdi_params.and_then(|s| s.container_idle_timeout_mins),
                };

                tracing::info!(
                    session_id = %session_id,
                    image = %image,
                    username = %vdi_username,
                    "Creating VDI session"
                );

                let info = vdi
                    .start_or_reuse(&spec)
                    .await
                    .map_err(|e| SessionError::VdiError(e.to_string()))?;

                // Clear stale VDI thumbnail now that the driver has resolved
                // the deterministic container name.
                let stale_thumb = self.vdi_thumbnail_path(&info.container_name);
                let _ = std::fs::remove_file(&stale_thumb);

                if info.reused {
                    tracing::info!(
                        session_id = %session_id,
                        container_id = %info.container_id,
                        "Reusing existing VDI container"
                    );
                }

                let params = guacd::ConnectionParams::Rdp(Box::new(guacd::RdpParams {
                    hostname: info.rdp_host,
                    port: info.rdp_port,
                    username: vdi_username.clone(),
                    password: Some(vdi_password),
                    domain: None,
                    security: None,
                    width,
                    height,
                    dpi,
                    ignore_cert: true,
                    enable_drive: false,
                    drive_path: None,
                    drive_name: String::new(),
                    disable_download: true,
                    disable_upload: true,
                    auth_pkg: None,
                    kdc_url: None,
                    kerberos_cache: None,
                    remote_app: None,
                    remote_app_dir: None,
                    remote_app_args: None,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
                    enable_gfx: true,
                    enable_desktop_composition: true,
                    enable_wallpaper: false,
                    enable_theming: false,
                    enable_full_window_drag: false,
                    force_lossless: false,
                    enable_h264: true,
                    secondary_monitors: req.max_monitors.unwrap_or(1).saturating_sub(1),
                    client_name: None,
                }));
                (
                    params,
                    image,
                    vdi_username,
                    None,
                    None,
                    None,
                    None,
                    Some(info.container_id),
                    Some(info.container_name),
                )
            }
        };

        // Set up SSH tunnel chain if jump hosts are configured.
        // For SSH/RDP/VNC: overrides hostname/port in conn_params so guacd
        // connects to the local tunnel listener instead of the real target.
        // For Web: tunnels to the URL's host:port and rewrites the browser URL.
        // Proxmox is excluded: it tunnels its own PVE API + SPICE-proxy hops
        // in-branch (the routing token / proxy field don't fit this rewrite).
        let is_web = url.is_some() && browser_session.is_none();
        let is_proxmox = matches!(req.session_type, SessionType::Proxmox);
        let ssh_tunnels = if !jump_hops.is_empty() && !is_proxmox {
            let (target_host, target_port) = if is_web {
                // Web session: tunnel to the URL's host:port
                let parsed = Url::parse(url.as_ref().unwrap())
                    .map_err(|e| SessionError::ValidationError(format!("invalid URL: {}", e)))?;
                let host = parsed.host_str().unwrap_or("localhost").to_string();
                let port = parsed.port_or_known_default().unwrap_or(80);
                (host, port)
            } else {
                match &conn_params {
                    guacd::ConnectionParams::Ssh(p) => (p.hostname.clone(), p.port),
                    guacd::ConnectionParams::Rdp(p) => (p.hostname.clone(), p.port),
                    guacd::ConnectionParams::Vnc(p) => (p.hostname.clone(), p.port),
                    // TLS SPICE connects on tls_port, so tunnel that port.
                    guacd::ConnectionParams::Spice(p) => {
                        if p.tls {
                            (p.hostname.clone(), p.tls_port.unwrap_or(p.port))
                        } else {
                            (p.hostname.clone(), p.port)
                        }
                    }
                }
            };

            let (tunnels, final_addr) =
                tunnel::start_chain(&jump_hops, &target_host, target_port, known_hosts_path)
                    .await
                    .map_err(|e| {
                        SessionError::ValidationError(format!("SSH tunnel failed: {}", e))
                    })?;

            if !is_web {
                // Override connection params to point at the final tunnel endpoint
                match &mut conn_params {
                    guacd::ConnectionParams::Ssh(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Rdp(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Vnc(p) => {
                        p.hostname = final_addr.ip().to_string();
                        p.port = final_addr.port();
                    }
                    guacd::ConnectionParams::Spice(p) => {
                        p.hostname = final_addr.ip().to_string();
                        // Rewrite the port guacd actually dials. Cert-subject
                        // verification still holds (the server presents the same
                        // cert regardless of the tunnel).
                        if p.tls {
                            p.tls_port = Some(final_addr.port());
                        } else {
                            p.port = final_addr.port();
                        }
                    }
                }
            }

            let hop_names: Vec<&str> = jump_hops.iter().map(|h| h.hostname.as_str()).collect();
            tracing::info!(
                session_id = %session_id,
                final_addr = %final_addr,
                hops = ?hop_names,
                "SSH tunnel chain established ({} hops)",
                tunnels.len()
            );

            Some((tunnels, final_addr))
        } else {
            None
        };

        // For web sessions, spawn the browser now (after tunnels are set up).
        // If a tunnel is active, rewrite the URL to go through it.
        if is_web {
            let browser_url = if let Some((_, ref final_addr)) = ssh_tunnels {
                let parsed = Url::parse(url.as_ref().unwrap()).unwrap();
                let scheme = parsed.scheme();
                let path_and_query = if let Some(q) = parsed.query() {
                    format!("{}?{}", parsed.path(), q)
                } else {
                    parsed.path().to_string()
                };
                let rewritten = format!(
                    "{}://127.0.0.1:{}{}",
                    scheme,
                    final_addr.port(),
                    path_and_query,
                );
                tracing::info!(
                    session_id = %session_id,
                    original_url = %url.as_ref().unwrap(),
                    rewritten_url = %rewritten,
                    "Rewrote web session URL to use SSH tunnel"
                );
                rewritten
            } else {
                url.as_ref().unwrap().clone()
            };

            let need_cdp = web.is_some_and(|s| s.login_script.is_some());

            // Parse autofill credentials JSON and substitute placeholders
            let autofill_creds = parse_autofill_credentials(
                web.and_then(|s| s.autofill.as_deref()),
                req.username.as_deref(),
                req.password.as_deref(),
            );

            let browser = self
                .browser_manager
                .spawn(
                    &browser_url,
                    width,
                    height,
                    need_cdp,
                    autofill_creds.as_deref(),
                    web.and_then(|s| s.allowed_domains.as_deref()),
                )
                .await
                .map_err(|e| SessionError::BrowserSpawn(e.to_string()))?;

            let vnc_port = browser.vnc_port;
            tracing::info!(
                session_id = %session_id,
                vnc_port = %vnc_port,
                display = %browser.display,
                "Browser processes ready, connecting guacd via VNC"
            );

            // Update the VNC params with the actual port
            if let guacd::ConnectionParams::Vnc(ref mut p) = conn_params {
                p.port = vnc_port;
            }
            browser_session = Some(browser);
        }

        // Determine if drive/file transfer is available for this session.
        // For SSH: guacd enables SFTP when enable_sftp is set.
        // For RDP: guacd enables drive when session_drive_path is set.
        let drive_enabled = match &conn_params {
            guacd::ConnectionParams::Ssh(p) => p.enable_sftp,
            guacd::ConnectionParams::Rdp(_) => session_drive_path.is_some(),
            _ => false,
        };

        let mut ssh_tunnels = ssh_tunnels.map(|(t, _)| t).unwrap_or_default();
        // Fold in any tunnels the Proxmox branch established in-branch.
        ssh_tunnels.append(&mut proxmox_tunnels);

        // For ephemeral keypair sessions, defer the guacd connection until
        // the user dismisses the banner (i.e. when the WebSocket connects).
        // This gives the user time to copy the public key and add it to
        // authorized_keys before guacd attempts SSH authentication.
        let deferred = banner_override.is_some();

        let (guacd_stream, connection_id, deferred_params) = if deferred {
            if let Some((h, p, nets)) = pending_net_check.take() {
                check_allowed_network(&h, p, &nets).await?;
            }
            tracing::info!(
                session_id = %session_id,
                "Deferring guacd connection (ephemeral keypair — waiting for user to add public key)"
            );
            (None, String::new(), Some(conn_params))
        } else {
            let guacd_addr = self.config.guacd_addr.clone();
            let guacd_tls = self.guacd_tls.clone();

            // R05: hostname targets resolve DNS (allowlist validation) in
            // parallel with the guacd connect — guacd resolves the
            // hostname itself, so the DNS result does not gate the TCP
            // connect. tokio::try_join! aborts the guacd future the
            // moment the DNS/allowlist branch errors (dropping the TCP
            // stream mid-connect), and returns the guacd error when the
            // connect fails while DNS succeeds. IP targets need no DNS, so
            // they keep the sequential path (no resolution to overlap).
            let hostname_target = pending_net_check
                .as_ref()
                .is_some_and(|(h, _, _)| h.parse::<std::net::IpAddr>().is_err());

            let (stream, connection_id) = if hostname_target {
                let ((), (stream, connection_id)) = tokio::try_join!(
                    async {
                        if let Some((h, p, nets)) = pending_net_check.take() {
                            check_allowed_network(&h, p, &nets)
                                .await
                                .map_err(|e| e.to_string())
                        } else {
                            Ok(())
                        }
                    },
                    async {
                        guacd::connect_and_handshake(&guacd_addr, &conn_params, guacd_tls.as_ref())
                            .await
                            .map_err(|e| e.to_string())
                    }
                )
                .map_err(SessionError::GuacdConnection)?;
                (stream, connection_id)
            } else {
                if let Some((h, p, nets)) = pending_net_check.take() {
                    check_allowed_network(&h, p, &nets).await?;
                }
                guacd::connect_and_handshake(&guacd_addr, &conn_params, guacd_tls.as_ref())
                    .await
                    .map_err(|e| SessionError::GuacdConnection(e.to_string()))?
            };

            tracing::info!(
                session_id = %session_id,
                connection_id = %connection_id,
                "guacd connection established"
            );
            (Some(stream), connection_id, None)
        };

        // `enable_recordings` lockdown — when the admin switched
        // recordings off, no session may record regardless of request or
        // config (the toggle defaults to enabled when unset).
        let recording_enabled = req
            .enable_recording
            .unwrap_or(self.config.recording_enabled())
            && toggle("enable_recordings");

        // Spawn login script if configured (web sessions with CDP port)
        let login_script_handle = if let (Some(script), Some(bs)) = (
            web.and_then(|s| s.login_script.as_ref()),
            browser_session.as_ref(),
        ) {
            if let Some(cdp_port) = bs.cdp_port {
                match self.browser_manager.run_login_script(
                    script,
                    bs.display,
                    cdp_port,
                    url.as_deref().unwrap_or(""),
                    req.username.as_deref(),
                    req.password.as_deref(),
                    &session_id.to_string(),
                ) {
                    Ok(handle) => Some(handle),
                    Err(e) => {
                        tracing::warn!(
                            session_id = %session_id,
                            error = %e,
                            "Login script failed to start (session continues)"
                        );
                        None
                    }
                }
            } else {
                tracing::warn!(
                    session_id = %session_id,
                    "Login script configured but no CDP port allocated"
                );
                None
            }
        } else {
            None
        };

        // Gate:
        //  - If the request explicitly sets allow_sharing, honour it.
        //  - Otherwise: entry-derived sessions default off (admin opt-in
        //    per entry via allow_sharing), ad-hoc sessions default on
        //    (preserves the long-standing API-key session-creation
        //    behaviour where share_url is expected in the response).
        let share_allowed = req
            .allow_sharing
            .unwrap_or(req.address_book_entry.is_none());

        let session = Session {
            id: session_id,
            session_type: req.session_type,
            status: SessionStatus::Pending,
            created_at: Utc::now(),
            hostname,
            username,
            url,
            banner: banner_override.or(req.banner),
            guacd_stream,
            connection_id,
            share_token: super::generate_share_token(),
            width,
            height,
            active_connections: 0,
            created_by: created_by.clone(),
            cancel: tokio_util::sync::CancellationToken::new(),
            browser_session,
            deferred_params,
            drive_path: session_drive_path,
            drive_enabled,
            tunnels: ssh_tunnels,
            container_id,
            container_name,
            recording_enabled,
            address_book_entry: req.address_book_entry,
            address_book_folder: req.address_book_folder,
            entry_display_name: req.entry_display_name,
            max_recordings: req.max_recordings,
            login_script_handle,
            shadow_tokens: Vec::new(),
            share_allowed,
            fullscreen_on_connect: req.fullscreen_on_connect.unwrap_or(false),
            autohide_side_tabs: req.autohide_side_tabs.unwrap_or(false),
            last_activity: std::sync::atomic::AtomicI64::new(Utc::now().timestamp()),
            source_ip: client_ip.clone(),
            user_id: Some(created_by),
        };

        let info = session.info();
        self.publish_session_started(&session);
        let session = tokio::sync::Mutex::new(session);

        // Enforce the global session cap inside the same write-lock
        // critical section as the insert: a check-then-insert elsewhere
        // races with concurrent creates and lets the map exceed the cap.
        // Only Pending|Active sessions count — terminal states linger in
        // the map until the cleanup reaper removes them.
        {
            let mut sessions = self.sessions.write().await;
            let max_global = self.config.max_sessions;
            if max_global > 0 && count_live_sessions(&sessions).await >= max_global {
                return Err(SessionError::ValidationError(format!(
                    "maximum concurrent sessions reached ({})",
                    max_global
                )));
            }
            sessions.insert(session_id, std::sync::Arc::new(session));
        }

        crate::metrics::session_total_inc();

        // Enterprise HA: mirror the live session in the shared
        // registry so other instances can see/join it. No-op without a
        // shared backend (single-instance mode unchanged).
        if self.ha_enabled() {
            if let Some(ref db) = self.db {
                let db = db.clone();
                let session_id_str = session_id.to_string();
                let owner = self.config.instance_id.clone();
                let base_url = self.config.ha_base_url.clone().unwrap_or_default();
                let st = format!("{:?}", info.session_type).to_lowercase();
                let hostname = info.hostname.clone();
                let username = info.username.clone();
                let created_by = info.created_by.clone();
                let created_at = crate::db::registry_ts(info.created_at);
                let now = crate::db::registry_ts(chrono::Utc::now());
                let _ = tokio::task::spawn_blocking(move || {
                    crate::db::registry_upsert_session(
                        &db,
                        &session_id_str,
                        &owner,
                        &base_url,
                        &st,
                        "pending",
                        &hostname,
                        &username,
                        &created_by,
                        &created_at,
                        &now,
                        "",
                    )
                })
                .await;
            }
        }

        // Record in session history (non-blocking, fire-and-forget, R02):
        // the insert runs on the blocking pool and the response is not
        // held up waiting for it. Session history is audit-only — a late
        // insert is harmless, so the JoinHandle is dropped un-awaited.
        if let Some(ref db) = self.db {
            let db = db.clone();
            let session_id_str = session_id.to_string();
            let st = format!("{:?}", info.session_type).to_lowercase();
            let hostname = info.hostname.clone();
            let username = info.username.clone();
            let created_by = info.created_by.clone();
            let address_book_entry = info.address_book_entry.clone();
            let address_book_folder = info.address_book_folder.clone();
            let entry_display_name = info.entry_display_name.clone();
            let reason = reason.clone();
            // Explicit drop: detach the blocking task (fire-and-forget).
            // Dropping the JoinHandle does not cancel spawn_blocking work;
            // the insert runs to completion on the blocking pool.
            drop(tokio::task::spawn_blocking(move || {
                let _ = crate::db::insert_session_history(
                    &db,
                    &session_id_str,
                    &st,
                    &hostname,
                    None,
                    &username,
                    &created_by,
                    address_book_entry.as_deref(),
                    address_book_folder.as_deref(),
                    entry_display_name.as_deref(),
                    client_ip.as_deref(),
                );
                if let Some(r) = reason.as_deref() {
                    let _ = crate::db::update_session_history_reason(&db, &session_id_str, r);
                }
            }));
        }

        // Spawn timeout task for pending sessions
        let sessions_ref = std::sync::Arc::clone(&self.sessions);
        let browser_mgr = std::sync::Arc::clone(&self.browser_manager);
        let timeout_secs = self.config.session_pending_timeout_secs;
        let (cleanup_on_close, retention_secs) = super::drive_cleanup_settings(&self.config.drive);
        // Mark the registry row expired when the pending window lapses
        // (the store functions no-op without a shared backend pool).
        let registry_db = self.db.clone();
        let registry_ha = self.ha_enabled();
        let publisher = std::sync::Arc::clone(self);
        tokio::spawn(async move {
            time::sleep(time::Duration::from_secs(timeout_secs)).await;
            let mut was_pending = false;
            {
                let sessions_read = sessions_ref.read().await;
                if let Some(session) = sessions_read.get(&session_id) {
                    let mut session = session.lock().await;
                    if session.status == SessionStatus::Pending {
                        tracing::warn!(session_id = %session_id, "Session expired (no browser connected)");
                        session.status = SessionStatus::Expired;
                        publisher.publish_transition(&SessionStatus::Pending, &session);
                        was_pending = true;
                        session.guacd_stream = None;
                        super::cleanup_browser(
                            &browser_mgr,
                            &mut session,
                            cleanup_on_close,
                            retention_secs,
                        )
                        .await;
                    }
                }
            }
            // Mark the registry row expired only when the session was
            // still pending — a session that already connected must keep its
            // live status.
            if was_pending {
                // Close the history row too: a pending session that never
                // connected is "expired", not stuck "active" forever.
                publisher.end_session_history(session_id, "expired", 0, false);
            }
            if was_pending && registry_ha {
                if let Some(ref db) = registry_db {
                    let db = db.clone();
                    let sid = session_id.to_string();
                    let now = crate::db::registry_ts(chrono::Utc::now());
                    let _ = tokio::task::spawn_blocking(move || {
                        crate::db::registry_set_status(&db, &sid, "expired", &now)
                    })
                    .await;
                }
            }
        });

        Ok(info)
    }
}

/// Default typescript filename template when `[recording].typescript_name`
/// is unset. Produces audit-friendly per-session names (#159).
const DEFAULT_TYPESCRIPT_NAME: &str = "{connection}-{user}-{date}-{time}";

/// Expand persea's brace tokens in a typescript filename template (#159).
///
/// guacd uses the typescript name verbatim (it appends a numeric suffix
/// only to avoid clobbering an existing file), so persea does this
/// substitution itself to produce audit-friendly, per-session filenames
/// like `coreswitch01-alice-20260610-143022`. Every substituted value is
/// sanitised to `[A-Za-z0-9_-]`, so the result is always a safe basename:
/// no path separators, no traversal, no surprises from OIDC usernames or
/// free-text entry names.
///
/// Tokens: `{user}`, `{connection}`, `{host}`, `{date}` (UTC YYYYMMDD),
/// `{time}` (UTC HHMMSS), `{session}` (first 8 chars of the session id).
/// Unknown braces are left untouched.
fn expand_typescript_name(
    template: &str,
    username: &str,
    hostname: &str,
    connection: &str,
    session_id: &Uuid,
    when: DateTime<Utc>,
) -> String {
    fn sanitize(s: &str) -> String {
        let mapped: String = s
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let collapsed = mapped
            .split('-')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-");
        if collapsed.is_empty() {
            "unknown".to_string()
        } else {
            collapsed
        }
    }

    let short_session: String = session_id.simple().to_string().chars().take(8).collect();

    template
        .replace("{user}", &sanitize(username))
        .replace("{connection}", &sanitize(connection))
        .replace("{host}", &sanitize(hostname))
        .replace("{date}", &when.format("%Y%m%d").to_string())
        .replace("{time}", &when.format("%H%M%S").to_string())
        .replace("{session}", &short_session)
}

/// Parse autofill credentials JSON and substitute $USERNAME/$PASSWORD placeholders.
/// Returns None if autofill is not configured or the JSON is invalid.
fn parse_autofill_credentials(
    autofill_json: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> Option<Vec<(String, String, String)>> {
    let json_str = autofill_json?;
    if json_str.is_empty() {
        return None;
    }

    let entries: Vec<serde_json::Value> = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "Invalid autofill JSON, ignoring");
            return None;
        }
    };

    let user = username.unwrap_or("");
    let pass = password.unwrap_or("");

    let creds: Vec<(String, String, String)> = entries
        .iter()
        .filter_map(|entry| {
            let url = entry.get("url")?.as_str()?;
            let u = entry.get("username")?.as_str()?;
            let p = entry.get("password")?.as_str()?;

            let url = url.to_string();
            let u = u.replace("$USERNAME", user);
            let p = p.replace("$PASSWORD", pass);

            Some((url, u, p))
        })
        .collect();

    if creds.is_empty() {
        None
    } else {
        Some(creds)
    }
}

/// Parse a host and port from a full URL ("https://host:8006") or a bare
/// authority ("host:3128" / "host"), falling back to `default_port` when the
/// input carries no explicit port. Used to tunnel Proxmox's PVE API and SPICE
/// proxy endpoints through a jump-host chain.
fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16), SessionError> {
    let parsed = if input.contains("://") {
        Url::parse(input)
    } else {
        Url::parse(&format!("tcp://{input}"))
    }
    .map_err(|e| SessionError::ValidationError(format!("invalid host/URL '{input}': {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SessionError::ValidationError(format!("no host in '{input}'")))?
        .to_string();
    let port = parsed.port().unwrap_or(default_port);
    Ok((host, port))
}

/// Link-local / cloud-metadata networks denied as session targets
/// regardless of the configured allowlist (S06, S02). 169.254.169.254 is
/// the AWS/GCP/Azure metadata endpoint; the deny covers the whole
/// 169.254.0.0/16 link-local block, strictly stronger than the
/// ticket's 169.254.169.254/32. Applied AFTER the allowlist check, as
/// defense in depth for when operators widen the allowlist (e.g. to
/// 0.0.0.0/0).
const DENIED_TARGET_NETWORKS: &[&str] = &["169.254.0.0/16"];

/// Reject hosts inside the hardcoded deny list. Only direct IP targets
/// are matched (a hostname's resolved addresses are checked against the
/// allowlist by [`check_allowed_network`]).
fn reject_denied_target(host: &str) -> Result<(), SessionError> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        for cidr in DENIED_TARGET_NETWORKS {
            if cidr
                .parse::<ipnetwork::IpNetwork>()
                .is_ok_and(|net| net.contains(ip))
            {
                return Err(SessionError::ValidationError(format!(
                    "access to link-local / cloud metadata network {} is blocked",
                    cidr
                )));
            }
        }
    }
    Ok(())
}

/// Check that a host resolves to an IP within the allowed CIDR networks.
async fn check_allowed_network(
    host: &str,
    port: u16,
    allowed: &[String],
) -> Result<(), SessionError> {
    if host.contains("://") || host.starts_with("http") {
        return Err(SessionError::ValidationError(
            "hostname must be a host or IP address, not a URL (use a Web entry for browser sessions)".into(),
        ));
    }

    let networks: Vec<IpNetwork> = allowed
        .iter()
        .filter_map(|s| s.parse::<IpNetwork>().ok())
        .collect();

    if networks.is_empty() {
        return Err(SessionError::ValidationError(
            "no valid CIDR networks configured in allowlist".into(),
        ));
    }

    // Try parsing host as an IP address directly first
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if networks.iter().any(|net| net.contains(ip)) {
            return Ok(());
        }
        return Err(SessionError::ValidationError(format!(
            "host {} is not in the allowed network list",
            host
        )));
    }

    // Resolve hostname to IP addresses (spawn_blocking to avoid blocking
    // tokio), with a 3s budget so a hanging resolver cannot stall session
    // creation indefinitely (mirrors `resolve_client_host`).
    let host_owned = host.to_owned();
    let addrs: Vec<std::net::SocketAddr> = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::task::spawn_blocking(move || format!("{}:{}", host_owned, port).to_socket_addrs()),
    )
    .await
    .map_err(|_| {
        SessionError::ValidationError(format!("DNS resolution for host '{}' timed out", host))
    })?
    .map_err(|e| SessionError::ValidationError(format!("DNS task join error: {}", e)))?
    .map_err(|e| {
        SessionError::ValidationError(format!("failed to resolve host '{}': {}", host, e))
    })?
    .collect();

    if addrs.is_empty() {
        return Err(SessionError::ValidationError(format!(
            "host '{}' did not resolve to any addresses",
            host
        )));
    }

    for addr in &addrs {
        if networks.iter().any(|net| net.contains(addr.ip())) {
            return Ok(());
        }
    }

    Err(SessionError::ValidationError(format!(
        "host '{}' resolves to addresses not in the allowed network list",
        host
    )))
}

/// Which `enable_*` lockdown toggle gates a session type. `Vnc` and `Ssh`
/// have no toggles (the settings page offers none) and are never blocked
/// here — SSH is always allowed like VNC; `enable_ssh_tunnels` only gates
/// the jump-host management UI, not SSH sessions.
fn protocol_toggle(session_type: &SessionType) -> Option<&'static str> {
    match session_type {
        SessionType::Rdp => Some("enable_rdp"),
        SessionType::Ssh => None,
        SessionType::Spice => Some("enable_spice"),
        SessionType::Proxmox => Some("enable_proxmox"),
        SessionType::Web => Some("enable_web_sessions"),
        SessionType::Vdi => Some("enable_vdi"),
        SessionType::Vnc => None,
    }
}

/// Human label for the disabled-protocol error message.
fn protocol_label(session_type: &SessionType) -> &'static str {
    match session_type {
        SessionType::Rdp => "RDP",
        SessionType::Ssh => "SSH",
        SessionType::Spice => "SPICE",
        SessionType::Proxmox => "Proxmox VE",
        SessionType::Web => "Web browser",
        SessionType::Vdi => "VDI",
        SessionType::Vnc => "VNC",
    }
}

/// Enforce the admin lockdown toggles at session creation. Rejects
/// with a clear error when the effective setting forbids the session type.
/// VMware sessions are plain RDP/SSH/VNC sessions routed from the vSphere
/// API with an `address_book_entry` of the form `vsphere/<vm name>`; they
/// additionally require `enable_vmware`.
fn check_session_type_enabled(
    session_type: &SessionType,
    address_book_entry: Option<&str>,
    toggle: impl Fn(&str) -> bool,
) -> Result<(), SessionError> {
    if let Some(key) = protocol_toggle(session_type) {
        if !toggle(key) {
            return Err(SessionError::ValidationError(format!(
                "{} sessions are disabled by an administrator",
                protocol_label(session_type)
            )));
        }
    }
    if address_book_entry.is_some_and(|e| e.starts_with("vsphere/")) && !toggle("enable_vmware") {
        return Err(SessionError::ValidationError(
            "VMware sessions are disabled by an administrator".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod auth_pkg_tests {
    use crate::config::Config;
    use crate::session::resolve_rdp_auth_pkg;

    fn cfg(default_auth_pkg: Option<&str>) -> Config {
        Config {
            rdp: Some(crate::config::RdpConfig {
                default_auth_pkg: default_auth_pkg.map(|s| s.to_string()),
                client_name_template: None,
            }),
            ..Config::default()
        }
    }

    #[test]
    fn entry_value_wins_over_server_default() {
        let c = cfg(Some("ntlm"));
        assert_eq!(
            resolve_rdp_auth_pkg(Some("kerberos"), &c),
            Some("kerberos".into())
        );
    }

    #[test]
    fn empty_entry_value_falls_through_to_server_default() {
        let c = cfg(Some("kerberos"));
        assert_eq!(resolve_rdp_auth_pkg(Some(""), &c), Some("kerberos".into()));
        assert_eq!(
            resolve_rdp_auth_pkg(Some("   "), &c),
            Some("kerberos".into())
        );
    }

    #[test]
    fn no_entry_no_config_defaults_to_ntlm() {
        let c = Config::default();
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("ntlm".into()));
    }

    #[test]
    fn empty_config_default_falls_through_to_ntlm() {
        let c = cfg(Some(""));
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("ntlm".into()));
    }

    #[test]
    fn server_default_applies_when_entry_none() {
        let c = cfg(Some("negotiate"));
        assert_eq!(resolve_rdp_auth_pkg(None, &c), Some("negotiate".into()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Typescript filename templating (#159) ──

    fn ts_when() -> DateTime<Utc> {
        // 2026-06-10 14:30:22 UTC
        DateTime::from_timestamp(1_781_101_822, 0).unwrap()
    }

    fn ts_id() -> Uuid {
        Uuid::parse_str("0123abcd-1111-2222-3333-444455556666").unwrap()
    }

    #[test]
    fn typescript_name_expands_all_tokens() {
        let got = expand_typescript_name(
            "{connection}-{user}-{date}-{time}-{host}-{session}",
            "alice",
            "switch01",
            "Core Switch 01",
            &ts_id(),
            ts_when(),
        );
        assert_eq!(
            got,
            "Core-Switch-01-alice-20260610-143022-switch01-0123abcd"
        );
    }

    #[test]
    fn typescript_name_default_template() {
        let got = expand_typescript_name(
            DEFAULT_TYPESCRIPT_NAME,
            "bob",
            "rtr-2",
            "Edge Router",
            &ts_id(),
            ts_when(),
        );
        assert_eq!(got, "Edge-Router-bob-20260610-143022");
    }

    #[test]
    fn typescript_name_sanitises_path_traversal_and_oidc_email() {
        // A crafted entry name must not escape the typescript dir, and an
        // OIDC email username must reduce to a safe basename.
        let got = expand_typescript_name(
            "{connection}-{user}",
            "alice@example.com",
            "h",
            "../../etc/cron.d/evil",
            &ts_id(),
            ts_when(),
        );
        assert!(!got.contains('/'), "no path separators: {got}");
        assert!(!got.contains(".."), "no traversal: {got}");
        assert_eq!(got, "etc-cron-d-evil-alice-example-com");
    }

    #[test]
    fn typescript_name_empty_value_falls_back_to_unknown() {
        let got = expand_typescript_name("{user}", "", "h", "c", &ts_id(), ts_when());
        assert_eq!(got, "unknown");
    }

    #[test]
    fn typescript_name_unknown_token_left_literal() {
        let got = expand_typescript_name("pre-{bogus}-{user}", "x", "h", "c", &ts_id(), ts_when());
        assert_eq!(got, "pre-{bogus}-x");
    }

    // ── RDP client-name template ──

    #[test]
    fn rdp_client_name_expands_user_and_host() {
        let got = expand_rdp_client_name_template("{user}@{host}", "alice", "switch01");
        assert_eq!(got, "alice@switch01");
    }

    #[test]
    fn rdp_client_name_custom_template_and_unknown_placeholder() {
        assert_eq!(
            expand_rdp_client_name_template("{user}:{host}", "bob", "192.0.2.5"),
            "bob:192.0.2.5"
        );
        assert_eq!(
            expand_rdp_client_name_template("persea-{bogus}-{user}", "carol", "h1"),
            "persea-{bogus}-carol"
        );
    }

    #[test]
    fn rdp_client_name_truncates_to_guacd_32_char_limit() {
        let got = expand_rdp_client_name_template(
            "{user}@{host}",
            "alice",
            "very-long-fqdn.corp.example.com",
        );
        assert_eq!(got.chars().count(), RDP_CLIENT_NAME_MAX_CHARS);
        assert_eq!(got, "alice@very-long-fqdn.corp.exampl");
    }

    #[test]
    fn rdp_client_name_empty_template_expands_to_empty() {
        assert_eq!(expand_rdp_client_name_template("", "alice", "h1"), "");
        assert_eq!(
            expand_rdp_client_name_template("   ", "alice", "h1"),
            "   ",
            "disable check happens on the trimmed template in the RDP branch"
        );
    }

    #[tokio::test]
    async fn resolve_client_host_missing_or_invalid_ip_falls_back() {
        assert_eq!(resolve_client_host(None).await, "unknown");
        assert_eq!(resolve_client_host(Some("")).await, "unknown");
        assert_eq!(resolve_client_host(Some("not-an-ip")).await, "not-an-ip");
    }

    #[tokio::test]
    async fn resolve_client_host_unresolvable_ip_returns_raw_ip() {
        // 203.0.113.7 is TEST-NET-3 (RFC 5737): no PTR record exists, so
        // the reverse lookup must fail (NXDOMAIN or the 1s timeout) and
        // the raw IP must come back.
        assert_eq!(
            resolve_client_host(Some("203.0.113.7")).await,
            "203.0.113.7"
        );
    }

    // ── Per-protocol global defaults ──

    fn stored(rows: &[(&str, &str)]) -> Vec<(String, String)> {
        rows.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn protocol_defaults_unset_settings_match_code_defaults() {
        let d = ProtocolDefaults::from_settings(&SessionType::Rdp, &[]);
        assert_eq!((d.width, d.height, d.dpi), (1920, 1080, 96));
        assert_eq!(d.rdp_security, None);
        assert!(d.rdp_h264, "H.264 must default on");
        assert!(d.rdp_gfx, "GFX must default on");
        assert_eq!(d.rdp_drive, None);
        assert_eq!(d.vnc_color_depth, None);
        assert!(!d.vnc_disable_copy);
        assert!(!d.vnc_disable_paste);
    }

    #[test]
    fn protocol_defaults_apply_per_protocol_settings() {
        let settings = stored(&[
            ("default_rdp_width", "1280"),
            ("default_rdp_height", "800"),
            ("default_rdp_dpi", "120"),
            ("default_rdp_security", "nla"),
            ("default_rdp_h264", "false"),
            ("default_rdp_gfx", "false"),
            ("default_rdp_drive", "true"),
            ("default_ssh_width", "200"),
            ("default_ssh_height", "60"),
            ("default_vnc_color_depth", "16"),
            ("default_vnc_disable_copy", "true"),
            ("default_vnc_disable_paste", "true"),
        ]);
        let rdp = ProtocolDefaults::from_settings(&SessionType::Rdp, &settings);
        assert_eq!((rdp.width, rdp.height, rdp.dpi), (1280, 800, 120));
        assert_eq!(rdp.rdp_security.as_deref(), Some("nla"));
        assert!(!rdp.rdp_h264);
        assert!(!rdp.rdp_gfx);
        assert_eq!(rdp.rdp_drive, Some(true));
        assert_eq!(
            rdp.vnc_color_depth,
            Some(16),
            "all groups are populated; only the session's protocol branch reads its own"
        );

        let ssh = ProtocolDefaults::from_settings(&SessionType::Ssh, &settings);
        assert_eq!(
            (ssh.width, ssh.height),
            (200, 60),
            "SSH width must come from default_ssh_width, not default_rdp_width"
        );
        assert_eq!(ssh.dpi, 96, "SSH has no per-protocol DPI setting");
        assert!(
            !ssh.rdp_h264,
            "the RDP H.264 default still populates the struct; only the RDP branch reads it"
        );

        let vnc = ProtocolDefaults::from_settings(&SessionType::Vnc, &settings);
        assert_eq!(vnc.vnc_color_depth, Some(16));
        assert!(vnc.vnc_disable_copy);
        assert!(vnc.vnc_disable_paste);
        assert_eq!(
            (vnc.width, vnc.height),
            (1920, 1080),
            "VNC has no per-protocol resolution settings"
        );
    }

    #[test]
    fn protocol_defaults_other_types_stay_on_code_defaults() {
        for st in [
            SessionType::Web,
            SessionType::Spice,
            SessionType::Vdi,
            SessionType::Proxmox,
        ] {
            let d = ProtocolDefaults::from_settings(&st, &[]);
            assert_eq!((d.width, d.height, d.dpi), (1920, 1080, 96));
            assert!(d.rdp_h264);
            assert!(d.rdp_gfx);
        }
    }

    #[test]
    fn protocol_defaults_garbage_stored_values_fall_back() {
        let settings = stored(&[
            ("default_rdp_width", "wide"),
            ("default_rdp_h264", "maybe"),
            ("default_rdp_security", ""),
            ("default_rdp_drive", "yes"),
            ("default_vnc_color_depth", "deep"),
        ]);
        let d = ProtocolDefaults::from_settings(&SessionType::Rdp, &settings);
        assert_eq!(d.width, 1920);
        assert!(d.rdp_h264);
        assert_eq!(d.rdp_security, None);
        assert_eq!(d.rdp_drive, None);
        assert_eq!(d.vnc_color_depth, None);
    }

    #[test]
    fn protocol_defaults_unknown_security_mode_falls_back() {
        // A manually-edited DB value outside the accepted modes must not
        // reach guacd: fall back to the pass-through code default.
        let settings = stored(&[("default_rdp_security", "ssl3")]);
        let d = ProtocolDefaults::from_settings(&SessionType::Rdp, &settings);
        assert_eq!(d.rdp_security, None);
        let settings = stored(&[("default_rdp_security", "tls")]);
        let d = ProtocolDefaults::from_settings(&SessionType::Rdp, &settings);
        assert_eq!(d.rdp_security.as_deref(), Some("tls"));
    }

    #[tokio::test]
    async fn test_check_allowed_network_ipv4_match() {
        assert!(
            check_allowed_network("127.0.0.1", 22, &["127.0.0.0/8".into()])
                .await
                .is_ok()
        );
        assert!(
            check_allowed_network("10.1.2.3", 80, &["10.0.0.0/8".into()])
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_check_allowed_network_ipv4_denied() {
        let err = check_allowed_network("8.8.8.8", 22, &["127.0.0.0/8".into()]).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn test_check_allowed_network_empty_allowlist() {
        let err = check_allowed_network("127.0.0.1", 22, &[]).await;
        assert!(err.is_err());
        let msg = format!("{}", err.unwrap_err());
        assert!(msg.contains("no valid CIDR"), "got: {}", msg);
    }

    #[tokio::test]
    async fn test_check_allowed_network_multiple_cidrs() {
        let cidrs = vec!["10.0.0.0/8".into(), "192.168.0.0/16".into()];
        assert!(check_allowed_network("10.1.1.1", 22, &cidrs).await.is_ok());
        assert!(check_allowed_network("192.168.1.1", 22, &cidrs)
            .await
            .is_ok());
        assert!(check_allowed_network("172.16.0.1", 22, &cidrs)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_check_allowed_network_localhost_resolves() {
        // "localhost" should resolve to 127.0.0.1 or ::1
        let cidrs = vec!["127.0.0.0/8".into(), "::1/128".into()];
        assert!(check_allowed_network("localhost", 80, &cidrs).await.is_ok());
    }

    #[test]
    fn test_parse_autofill_none() {
        assert!(parse_autofill_credentials(None, None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_empty_string() {
        assert!(parse_autofill_credentials(Some(""), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_invalid_json() {
        assert!(parse_autofill_credentials(Some("not json"), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_empty_array() {
        assert!(parse_autofill_credentials(Some("[]"), None, None).is_none());
    }

    #[test]
    fn test_parse_autofill_basic() {
        let json = r#"[{"url":"https://example.com","username":"alice","password":"secret"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, "https://example.com");
        assert_eq!(creds[0].1, "alice");
        assert_eq!(creds[0].2, "secret");
    }

    #[test]
    fn test_parse_autofill_placeholder_substitution() {
        let json = r#"[{"url":"https://ex.com","username":"$USERNAME","password":"$PASSWORD"}]"#;
        let creds = parse_autofill_credentials(Some(json), Some("bob"), Some("pass123")).unwrap();
        assert_eq!(creds[0].1, "bob");
        assert_eq!(creds[0].2, "pass123");
    }

    #[test]
    fn test_parse_autofill_placeholder_no_credentials() {
        // Placeholders with no username/password should substitute empty strings
        let json = r#"[{"url":"https://ex.com","username":"$USERNAME","password":"$PASSWORD"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds[0].1, "");
        assert_eq!(creds[0].2, "");
    }

    #[test]
    fn test_parse_autofill_multiple_entries() {
        let json = r#"[
            {"url":"https://app.com","username":"$USERNAME","password":"$PASSWORD"},
            {"url":"https://idp.com","username":"$USERNAME","password":"$PASSWORD"}
        ]"#;
        let creds = parse_autofill_credentials(Some(json), Some("alice"), Some("secret")).unwrap();
        assert_eq!(creds.len(), 2);
        assert_eq!(creds[0].0, "https://app.com");
        assert_eq!(creds[1].0, "https://idp.com");
    }

    #[test]
    fn test_parse_autofill_missing_fields_skipped() {
        // Entries missing required fields are silently skipped
        let json =
            r#"[{"url":"https://ex.com"},{"url":"https://ok.com","username":"a","password":"b"}]"#;
        let creds = parse_autofill_credentials(Some(json), None, None).unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].0, "https://ok.com");
    }

    // ── Protocol lockdown toggles ──

    const ALL_TYPES: [SessionType; 7] = [
        SessionType::Ssh,
        SessionType::Web,
        SessionType::Rdp,
        SessionType::Vnc,
        SessionType::Vdi,
        SessionType::Spice,
        SessionType::Proxmox,
    ];

    fn only_off<'a>(disabled: &'a [&'a str]) -> impl Fn(&str) -> bool + 'a {
        let disabled = disabled.to_vec();
        move |k: &str| !disabled.contains(&k)
    }

    #[test]
    fn all_protocols_allowed_when_toggles_unset() {
        for st in ALL_TYPES {
            assert!(
                check_session_type_enabled(&st, None, |_| true).is_ok(),
                "{:?} should be allowed when everything is enabled",
                st
            );
        }
    }

    #[test]
    fn rdp_disabled_blocks_rdp_sessions() {
        let err = check_session_type_enabled(&SessionType::Rdp, None, only_off(&["enable_rdp"]))
            .unwrap_err();
        assert!(
            format!("{}", err).contains("RDP sessions are disabled by an administrator"),
            "got: {}",
            err
        );
    }

    #[test]
    fn ssh_has_no_toggle_and_is_never_blocked() {
        // Semantic change (T03): enable_ssh_tunnels no longer gates SSH
        // sessions — it only controls the jump-host management UI.
        assert!(check_session_type_enabled(&SessionType::Ssh, None, |_| false).is_ok());
    }

    #[test]
    fn spice_proxmox_web_vdi_each_gated_by_own_toggle() {
        for (st, key, label) in [
            (SessionType::Spice, "enable_spice", "SPICE"),
            (SessionType::Proxmox, "enable_proxmox", "Proxmox VE"),
            (SessionType::Web, "enable_web_sessions", "Web browser"),
            (SessionType::Vdi, "enable_vdi", "VDI"),
        ] {
            let err = check_session_type_enabled(&st, None, only_off(&[key])).unwrap_err();
            assert!(
                format!("{}", err).contains(&format!(
                    "{} sessions are disabled by an administrator",
                    label
                )),
                "got: {}",
                err
            );
        }
    }

    #[test]
    fn a_disabled_toggle_only_blocks_its_own_protocol() {
        for st in ALL_TYPES {
            if st == SessionType::Spice {
                assert!(
                    check_session_type_enabled(&st, None, only_off(&["enable_spice"])).is_err()
                );
            } else {
                assert!(
                    check_session_type_enabled(&st, None, only_off(&["enable_spice"])).is_ok(),
                    "{:?} must not be affected by enable_spice",
                    st
                );
            }
        }
    }

    #[test]
    fn vnc_has_no_toggle_and_is_never_blocked() {
        assert!(check_session_type_enabled(&SessionType::Vnc, None, |_| false).is_ok());
    }

    #[test]
    fn vmware_entries_gated_by_enable_vmware() {
        let err = check_session_type_enabled(
            &SessionType::Rdp,
            Some("vsphere/webserver-01"),
            only_off(&["enable_vmware"]),
        )
        .unwrap_err();
        assert!(
            format!("{}", err).contains("VMware sessions are disabled by an administrator"),
            "got: {}",
            err
        );
        assert!(check_session_type_enabled(
            &SessionType::Rdp,
            Some("vsphere/webserver-01"),
            |_| true
        )
        .is_ok());
        assert!(
            check_session_type_enabled(
                &SessionType::Rdp,
                Some("shared/folder/entry"),
                only_off(&["enable_vmware"]),
            )
            .is_ok(),
            "non-vSphere entries must not be gated by enable_vmware"
        );
    }

    // ── VDI container username sanitization ──

    #[test]
    fn vdi_username_derives_from_identity_without_domain() {
        assert_eq!(
            vdi_container_username(None, "Alice.Smith@corp.example").unwrap(),
            "alice_smith"
        );
        assert_eq!(
            vdi_container_username(None, "bob@example.com").unwrap(),
            "bob"
        );
    }

    #[test]
    fn vdi_username_empty_override_falls_through_to_identity() {
        assert_eq!(vdi_container_username(Some(""), "alice").unwrap(), "alice");
        assert_eq!(
            vdi_container_username(Some(""), "alice@corp").unwrap(),
            "alice"
        );
    }

    #[test]
    fn vdi_username_sanitizes_override_to_safe_charset() {
        assert_eq!(
            vdi_container_username(Some("Vdi-User@corp"), "alice").unwrap(),
            "vdi_user_corp"
        );
        assert_eq!(
            vdi_container_username(Some("bench001"), "alice").unwrap(),
            "bench001"
        );
    }

    #[test]
    fn vdi_username_rejects_path_traversal_in_override() {
        // The override becomes part of the host bind-mount path; a
        // separator or traversal component must be rejected outright.
        for bad in ["../alice", "a/b", "a\\b", "..", "a..b", "sub/../../etc"] {
            let err = vdi_container_username(Some(bad), "alice").unwrap_err();
            assert!(
                format!("{}", err).contains("container_username must not contain"),
                "input {:?} got: {}",
                bad,
                err
            );
        }
    }

    #[test]
    fn vdi_username_rejects_override_with_no_alphanumerics() {
        let out = vdi_container_username(Some("@@@"), "alice").unwrap();
        assert_eq!(out, "___");
        assert!(vdi_container_username(Some("___"), "alice").is_ok());
        assert!(vdi_container_username(Some("../etc"), "alice").is_err());
        assert!(vdi_container_username(Some("a/b"), "alice").is_err());
    }

    // ── Global session limit counting ──

    fn test_session(status: SessionStatus) -> Session {
        Session {
            id: Uuid::new_v4(),
            session_type: SessionType::Ssh,
            status,
            created_at: Utc::now(),
            hostname: "test-host".into(),
            username: "alice".into(),
            url: None,
            banner: None,
            guacd_stream: None,
            connection_id: "conn-test".into(),
            share_token: "share-token".into(),
            width: 1024,
            height: 768,
            active_connections: 0,
            created_by: "alice".into(),
            cancel: tokio_util::sync::CancellationToken::new(),
            browser_session: None,
            deferred_params: None,
            drive_path: None,
            drive_enabled: false,
            tunnels: Vec::new(),
            container_id: None,
            container_name: None,
            recording_enabled: false,
            address_book_entry: None,
            address_book_folder: None,
            entry_display_name: None,
            max_recordings: None,
            login_script_handle: None,
            shadow_tokens: Vec::new(),
            share_allowed: true,
            fullscreen_on_connect: false,
            autohide_side_tabs: false,
            last_activity: std::sync::atomic::AtomicI64::new(chrono::Utc::now().timestamp()),
            source_ip: None,
            user_id: Some("alice".into()),
        }
    }

    #[tokio::test]
    async fn live_session_count_excludes_terminal_states() {
        // The global cap must count only Pending|Active sessions; the
        // terminal states linger in the map until the cleanup reaper runs.
        let mut map: std::collections::HashMap<Uuid, std::sync::Arc<tokio::sync::Mutex<Session>>> =
            std::collections::HashMap::new();
        for status in [
            SessionStatus::Pending,
            SessionStatus::Active,
            SessionStatus::Completed,
            SessionStatus::Error,
            SessionStatus::Expired,
            SessionStatus::Disconnected,
            SessionStatus::LoggedOut,
        ] {
            map.insert(
                Uuid::new_v4(),
                std::sync::Arc::new(tokio::sync::Mutex::new(test_session(status))),
            );
        }
        assert_eq!(count_live_sessions(&map).await, 2);
    }

    #[tokio::test]
    async fn live_session_count_empty_map_is_zero() {
        let map: std::collections::HashMap<Uuid, std::sync::Arc<tokio::sync::Mutex<Session>>> =
            std::collections::HashMap::new();
        assert_eq!(count_live_sessions(&map).await, 0);
    }
}
