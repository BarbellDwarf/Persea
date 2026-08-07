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

/// Command used when `ssh_tmux_detach` is enabled: attach to the most
/// recent tmux session with `-d` (kicking any stale client left attached
/// by an abrupt disconnect), or create a fresh session if none exists.
const TMUX_DETACH_WRAPPER: &str = "tmux attach-session -d 2>/dev/null || tmux new-session";

impl SessionManager {
    /// Create a new session: connect to guacd, perform handshake, return session info.
    pub async fn create_session(
        &self,
        req: CreateSessionRequest,
        created_by: String,
    ) -> Result<SessionInfo, SessionError> {
        // Enforce session limits (only count active/pending sessions)
        {
            let sessions = self.sessions.read().await;
            let max_global = self.config.max_sessions;
            let max_per_user = self.config.max_sessions_per_user;

            if max_global > 0 {
                let active_count = sessions.values().count(); // includes all states still in HashMap
                if active_count >= max_global {
                    return Err(SessionError::ValidationError(format!(
                        "maximum concurrent sessions reached ({})",
                        max_global
                    )));
                }
            }

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

        let session_id = Uuid::new_v4();
        // Protocol-specific params land in flattened sub-structs (see
        // CreateSessionRequest); bind them up-front for ergonomic access.
        let ssh = req.ssh.as_ref();
        let rdp = req.rdp.as_ref();
        let vnc = req.vnc.as_ref();
        let web = req.web.as_ref();
        let vdi_params = req.vdi.as_ref();
        let spice = req.spice.as_ref();
        let proxmox = req.proxmox.as_ref();
        let raw_width = req.width.unwrap_or(1920);
        let raw_height = req.height.unwrap_or(1080);
        let raw_dpi = req.dpi.unwrap_or(96);
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

        // Resolve jump hosts (SSH tunnel chain) up-front: the Proxmox branch
        // needs them to tunnel its PVE API + SPICE-proxy connections in-branch,
        // and the generic tunnel setup after the match uses them for the other
        // session types.
        let jump_hops: Vec<tunnel::JumpHost> = if let Some(hops) = req.jump_hosts {
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

                check_allowed_network(&hostname, port, &self.config.ssh_allowed_networks).await?;

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

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive);
                let drive_cfg = drive::drive_config_or_default(&self.config.drive);

                // SSH typescript recording (#159): per-connection opt-in
                // (default off), and only when a global typescript_path is
                // configured. persea expands the name template (guacd
                // uses it verbatim) so audit files are identifiable per
                // user + connection.
                let typescript = self
                    .config
                    .ssh_typescript()
                    .filter(|_| ssh.map_or(false, |s| s.record_typescript == Some(true)))
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

                check_allowed_network(&hostname, port, &self.config.rdp_allowed_networks).await?;

                tracing::info!(
                    session_id = %session_id,
                    hostname = %hostname,
                    username = %username,
                    width, height, dpi,
                    "Creating new RDP session"
                );

                let drive_enabled = drive::is_drive_enabled(&self.config.drive, req.enable_drive);
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
                let rdp_security = rdp.and_then(|s| s.security.clone());
                let rdp_enable_drive = session_drive_path.is_some();
                tracing::info!(
                    %session_id,
                    ignore_cert = rdp_ignore_cert,
                    security = ?rdp_security,
                    enable_drive = rdp_enable_drive,
                    drive_path = ?session_drive_path,
                    domain = ?rdp.and_then(|s| s.domain.as_ref()),
                    has_password = req.password.is_some(),
                    "RDP session params"
                );
                let params = guacd::ConnectionParams::Rdp(Box::new(guacd::RdpParams {
                    hostname: hostname.clone(),
                    port,
                    username: username.clone(),
                    password: req.password.clone(),
                    domain: rdp.and_then(|s| s.domain.clone()),
                    security: rdp_security,
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
                    enable_gfx: rdp.and_then(|s| s.enable_gfx).unwrap_or(false),
                    enable_desktop_composition: rdp
                        .and_then(|s| s.enable_desktop_composition)
                        .unwrap_or(false),
                    enable_wallpaper: rdp.and_then(|s| s.enable_wallpaper).unwrap_or(false),
                    enable_theming: rdp.and_then(|s| s.enable_theming).unwrap_or(false),
                    enable_full_window_drag: rdp
                        .and_then(|s| s.enable_full_window_drag)
                        .unwrap_or(false),
                    force_lossless: rdp.and_then(|s| s.force_lossless).unwrap_or(false),
                    enable_h264: rdp.and_then(|s| s.enable_h264).unwrap_or(false),
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

                check_allowed_network(&hostname, port, &self.config.vnc_allowed_networks).await?;

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
                    color_depth: vnc.and_then(|s| s.color_depth),
                    width,
                    height,
                    dpi,
                    disable_copy: req.disable_copy.unwrap_or(false),
                    disable_paste: req.disable_paste.unwrap_or(false),
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

                let vmid = proxmox.and_then(|s| s.proxmox_vmid).unwrap_or(0);
                if vmid == 0 {
                    return Err(SessionError::ValidationError(
                        "Proxmox sessions require proxmox_vmid".into(),
                    ));
                }
                let verify_tls = proxmox.and_then(|s| s.proxmox_verify_tls).unwrap_or(false);

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
                    let (mut tuns, api_local) =
                        tunnel::start_chain(&jump_hops, &api_host, api_port)
                            .await
                            .map_err(|e| {
                                SessionError::ValidationError(format!(
                                    "Proxmox API tunnel failed: {e}"
                                ))
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
                    let (mut tuns, proxy_local) =
                        tunnel::start_chain(&jump_hops, &proxy_host, proxy_port)
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

                tracing::info!(
                    session_id = %session_id,
                    url = %url,
                    has_login_script = web.map_or(false, |s| s.login_script.is_some()),
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
                // accounts that don't honour VDI_USERNAME), otherwise derive
                // from the operator's identity. The derived form is also used
                // as the deterministic container-name suffix, so containers
                // are scoped per-operator. When the override is set the same
                // container is shared by everyone connecting with that entry,
                // which is the desired behaviour for shared baked-in accounts.
                let vdi_username = vdi_params
                    .and_then(|s| s.container_username.as_ref())
                    .filter(|s| !s.is_empty())
                    .cloned()
                    .unwrap_or_else(|| {
                        created_by
                            .split('@')
                            .next()
                            .unwrap_or(&created_by)
                            .to_lowercase()
                            .chars()
                            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                            .collect::<String>()
                    });
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

            let (tunnels, final_addr) = tunnel::start_chain(&jump_hops, &target_host, target_port)
                .await
                .map_err(|e| SessionError::ValidationError(format!("SSH tunnel failed: {}", e)))?;

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

            let need_cdp = web.map_or(false, |s| s.login_script.is_some());

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

        let mut ssh_tunnels = ssh_tunnels.map(|(t, _)| t).unwrap_or_default();
        // Fold in any tunnels the Proxmox branch established in-branch.
        ssh_tunnels.append(&mut proxmox_tunnels);

        // For ephemeral keypair sessions, defer the guacd connection until
        // the user dismisses the banner (i.e. when the WebSocket connects).
        // This gives the user time to copy the public key and add it to
        // authorized_keys before guacd attempts SSH authentication.
        let deferred = banner_override.is_some();

        let (guacd_stream, connection_id, deferred_params) = if deferred {
            tracing::info!(
                session_id = %session_id,
                "Deferring guacd connection (ephemeral keypair — waiting for user to add public key)"
            );
            (None, String::new(), Some(conn_params))
        } else {
            // Connect to guacd and perform handshake
            let handshake_result = guacd::connect_and_handshake(
                &self.config.guacd_addr,
                &conn_params,
                self.guacd_tls.as_ref(),
            )
            .await;

            // If handshake fails, clean up browser processes
            let (stream, connection_id) = match handshake_result {
                Ok(result) => result,
                Err(e) => {
                    if let Some(mut bs) = browser_session {
                        self.browser_manager.kill(&mut bs).await;
                    }
                    tracing::error!(session_id = %session_id, error = %e, "Failed to connect to guacd");
                    return Err(SessionError::GuacdConnection(e.to_string()));
                }
            };

            tracing::info!(
                session_id = %session_id,
                connection_id = %connection_id,
                "guacd connection established"
            );
            (Some(stream), connection_id, None)
        };

        let recording_enabled = req
            .enable_recording
            .unwrap_or(self.config.recording_enabled());

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
            source_ip: None,
            user_id: Some(created_by),
        };

        let info = session.info();
        let session = tokio::sync::Mutex::new(session);

        self.sessions
            .write()
            .await
            .insert(session_id, std::sync::Arc::new(session));

        crate::metrics::session_total_inc();

        // Record in session history
        if let Some(ref db) = self.db {
            let st = format!("{:?}", info.session_type).to_lowercase();
            if let Err(e) = crate::db::insert_session_history(
                db,
                &session_id.to_string(),
                &st,
                &info.hostname,
                None,
                &info.username,
                &info.created_by,
                info.address_book_entry.as_deref(),
                info.address_book_folder.as_deref(),
                info.entry_display_name.as_deref(),
            ) {
                tracing::warn!(session_id = %session_id, error = %e, "Failed to record session history");
            }
        }

        // Spawn timeout task for pending sessions
        let sessions_ref = std::sync::Arc::clone(&self.sessions);
        let browser_mgr = std::sync::Arc::clone(&self.browser_manager);
        let timeout_secs = self.config.session_pending_timeout_secs;
        let (cleanup_on_close, retention_secs) = super::drive_cleanup_settings(&self.config.drive);
        tokio::spawn(async move {
            time::sleep(time::Duration::from_secs(timeout_secs)).await;
            let sessions_read = sessions_ref.read().await;
            if let Some(session) = sessions_read.get(&session_id) {
                let mut session = session.lock().await;
                if session.status == SessionStatus::Pending {
                    tracing::warn!(session_id = %session_id, "Session expired (no browser connected)");
                    session.status = SessionStatus::Expired;
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

    // Resolve hostname to IP addresses (spawn_blocking to avoid blocking tokio)
    let host_owned = host.to_owned();
    let addrs: Vec<std::net::SocketAddr> =
        tokio::task::spawn_blocking(move || format!("{}:{}", host_owned, port).to_socket_addrs())
            .await
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

#[cfg(test)]
mod auth_pkg_tests {
    use crate::config::Config;
    use crate::session::resolve_rdp_auth_pkg;

    fn cfg(default_auth_pkg: Option<&str>) -> Config {
        Config {
            rdp: Some(crate::config::RdpConfig {
                default_auth_pkg: default_auth_pkg.map(|s| s.to_string()),
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
            "alice@sol1.com.au",
            "h",
            "../../etc/cron.d/evil",
            &ts_id(),
            ts_when(),
        );
        assert!(!got.contains('/'), "no path separators: {got}");
        assert!(!got.contains(".."), "no traversal: {got}");
        assert_eq!(got, "etc-cron-d-evil-alice-sol1-com-au");
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
}
