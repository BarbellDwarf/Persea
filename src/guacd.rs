//! guacd connection and Guacamole protocol handshake.

use crate::protocol::{Instruction, InstructionParser};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Apply TCP keepalive to a connected guacd socket. Long-lived guacd sockets
/// can sit idle for minutes (idle terminal, idle desktop). Without keepalive,
/// a silent network drop (NAT eviction, intermediate firewall rebuild) is only
/// caught when something tries to write — which can be never if both sides are
/// quiet. 30s/10s/3 means a dead path is detected within ~60s.
fn apply_keepalive(stream: &TcpStream) {
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10))
        .with_retries(3);
    let sock = socket2::SockRef::from(stream);
    if let Err(e) = sock.set_tcp_keepalive(&keepalive) {
        tracing::warn!(error = %e, "failed to enable TCP keepalive on guacd socket");
    }
    if let Err(e) = sock.set_tcp_nodelay(true) {
        tracing::warn!(error = %e, "failed to set TCP_NODELAY on guacd socket");
    }
}

/// Combined trait for async bidirectional streams.
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

/// A type-erased async stream for the guacd connection (plain TCP or TLS).
pub type GuacdStream = Box<dyn AsyncStream>;

/// SSH connection parameters to pass to guacd.
pub struct SshParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub enable_sftp: bool,
    pub sftp_disable_download: bool,
    pub sftp_disable_upload: bool,
    pub disable_copy: bool,
    pub disable_paste: bool,
    /// Terminal scrollback buffer size in lines.
    pub scrollback: u32,
    /// SSH typescript recording (#159). guacd writes the raw terminal
    /// session to a plain-text file (compatible with `scriptreplay`).
    /// An empty `typescript_path` disables it (guacd records nothing).
    /// These are guacd-side paths: the guacd process must be able to
    /// write to `typescript_path`.
    pub typescript_path: Option<String>,
    /// Base filename for the typescript, already expanded by persea
    /// (guacd does not substitute tokens here). Empty falls back to
    /// guacd's own default of "typescript".
    pub typescript_name: Option<String>,
    /// Ask guacd to create `typescript_path` if it doesn't exist.
    pub create_typescript_path: bool,
    /// Command to run instead of the default shell (guacd SSH `command`
    /// connect arg). When set, guacd runs `libssh2_channel_exec` with this
    /// command rather than a login shell. Used for the optional tmux
    /// wrapper (`ssh_tmux_detach`); `None` means plain shell.
    pub command: Option<String>,
}

/// VNC connection parameters to pass to guacd.
pub struct VncParams {
    pub hostname: String,
    pub port: u16,
    pub password: Option<String>,
    pub color_depth: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub disable_copy: bool,
    pub disable_paste: bool,
}

/// SPICE connection parameters to pass to guacd.
///
/// Credentials (`password`/`username`) are sent as connect args: guacd's SPICE
/// client authenticates during `connect` without awaiting an `argv` stream, so
/// argv delivery would race the auth. The TLS + proxy + cert-subject fields
/// support brokered Proxmox VE consoles (which connect via a SPICE proxy with a
/// one-time ticket and cluster-CA TLS).
pub struct SpiceParams {
    pub hostname: String,
    pub port: u16,
    /// SPICE ticket / password, sent as the `password` connect arg.
    pub password: Option<String>,
    /// Optional SPICE username, sent as the `username` connect arg.
    pub username: Option<String>,
    pub tls: bool,
    pub tls_port: Option<u16>,
    /// PEM CA certificate for verifying the SPICE server's TLS (Proxmox cluster CA).
    pub ca_cert: Option<String>,
    /// Expected TLS certificate subject (Proxmox "host-subject").
    pub cert_subject: Option<String>,
    pub ignore_cert: bool,
    /// SPICE proxy URL, e.g. "http://proxy.example.com:3128" (Proxmox SPICE proxy).
    pub proxy: Option<String>,
    pub color_depth: Option<u8>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub disable_copy: bool,
    pub disable_paste: bool,
    pub enable_audio: bool,
    /// Number of secondary monitors to allow (beyond the primary). guacd
    /// advertises this to the client as `secondary-monitors` so a multi-monitor
    /// client can offer the right number of monitor windows. 0 = single monitor.
    pub secondary_monitors: u32,
}

/// RDP connection parameters to pass to guacd.
pub struct RdpParams {
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub domain: Option<String>,
    pub security: Option<String>,
    pub width: u32,
    pub height: u32,
    pub dpi: u32,
    pub ignore_cert: bool,
    pub enable_drive: bool,
    pub drive_path: Option<String>,
    pub drive_name: String,
    pub disable_download: bool,
    pub disable_upload: bool,
    /// NLA authentication package: "kerberos", "ntlm", or empty (negotiate).
    pub auth_pkg: Option<String>,
    /// Kerberos KDC URL (optional, uses system krb5.conf if unset).
    pub kdc_url: Option<String>,
    /// Path to Kerberos ticket cache file (optional).
    pub kerberos_cache: Option<String>,
    /// RemoteApp program path (RAIL).
    pub remote_app: Option<String>,
    /// RemoteApp working directory.
    pub remote_app_dir: Option<String>,
    /// RemoteApp command-line arguments.
    pub remote_app_args: Option<String>,
    pub disable_copy: bool,
    pub disable_paste: bool,
    /// Enable Graphics Pipeline Extension (GFX/RDPGFX). Enables RemoteFX codec, 32bpp.
    pub enable_gfx: bool,
    /// Enable desktop composition (DWM). Required for smooth video overlay rendering.
    pub enable_desktop_composition: bool,
    /// Show the remote desktop wallpaper. Disabled by default to save bandwidth.
    pub enable_wallpaper: bool,
    /// Enable window/control theming (visual styles). Disabled by default to save bandwidth.
    pub enable_theming: bool,
    /// Show window contents while dragging. Disabled by default to save bandwidth.
    pub enable_full_window_drag: bool,
    /// Force lossless encoding (PNG only). Better for text-heavy workloads.
    pub force_lossless: bool,
    /// Enable H.264 passthrough. Raw H.264 NAL units sent to browser WebCodecs decoder.
    pub enable_h264: bool,
    /// Number of secondary monitors to allow (beyond the primary). guacd
    /// advertises this to the client as `secondary-monitors` and drives RDP
    /// multi-monitor via the Display Control channel. 0 = single monitor.
    pub secondary_monitors: u32,
}

/// Connection parameters — SSH, VNC, or RDP.
pub enum ConnectionParams {
    Ssh(SshParams),
    Vnc(VncParams),
    Rdp(Box<RdpParams>),
    Spice(Box<SpiceParams>),
}

/// Connect to guacd and perform the Guacamole protocol handshake.
///
/// Returns the connected stream (ready for bidirectional instruction streaming)
/// and the connection ID assigned by guacd.
pub async fn connect_and_handshake(
    guacd_addr: &str,
    params: &ConnectionParams,
    tls: Option<&tokio_rustls::TlsConnector>,
) -> Result<(GuacdStream, String), GuacdError> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(guacd_addr))
        .await
        .map_err(|_| {
            GuacdError::Connection(format!("Timeout connecting to guacd at {}", guacd_addr))
        })?
        .map_err(|e| {
            GuacdError::Connection(format!(
                "Failed to connect to guacd at {}: {}",
                guacd_addr, e
            ))
        })?;

    apply_keepalive(&tcp);
    tracing::debug!("Connected to guacd at {}", guacd_addr);

    let mut stream: GuacdStream = wrap_tls(tcp, tls, guacd_addr).await?;

    // Send select instruction to choose protocol
    let protocol = match params {
        ConnectionParams::Ssh(_) => "ssh",
        ConnectionParams::Vnc(_) => "vnc",
        ConnectionParams::Rdp(_) => "rdp",
        ConnectionParams::Spice(_) => "spice",
    };
    let select = Instruction::new("select", vec![protocol.into()]);
    stream
        .write_all(select.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    tracing::debug!("Sent select instruction for {}", protocol);

    // Read the args instruction from guacd — this tells us what parameters it expects
    let args_instruction = read_instruction(&mut stream).await?;
    if args_instruction.opcode != "args" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'args' instruction, got '{}'",
            args_instruction.opcode
        )));
    }

    tracing::debug!(
        "Received args instruction with {} parameters: {:?}",
        args_instruction.args.len(),
        args_instruction.args
    );

    // Build the connect instruction with values matching the args order.
    let arg_values: Vec<String> = args_instruction
        .args
        .iter()
        .map(|name| match params {
            ConnectionParams::Ssh(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "username" => p.username.clone(),
                "password" => p.password.clone().unwrap_or_default(),
                "private-key" => p.private_key.clone().unwrap_or_default(),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "color-scheme" => "gray-black".into(),
                "font-size" => "12".into(),
                "font-name" => "monospace".into(),
                "terminal-type" => "xterm-256color".into(),
                "scrollback" => p.scrollback.to_string(),
                "backspace" => "127".into(),
                "enable-sftp" => if p.enable_sftp { "true" } else { "false" }.into(),
                "sftp-disable-download" => if p.sftp_disable_download {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "sftp-disable-upload" => if p.sftp_disable_upload {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                "read-only" => "false".into(),
                "locale" => "en_US.UTF-8".into(),
                "server-alive-interval" => "0".into(),
                "command" => p.command.clone().unwrap_or_default(),
                "typescript-path" => p.typescript_path.clone().unwrap_or_default(),
                "typescript-name" => p.typescript_name.clone().unwrap_or_default(),
                "create-typescript-path" => if p.create_typescript_path {
                    "true"
                } else {
                    "false"
                }
                .into(),
                _ => {
                    tracing::debug!("Unknown guacd SSH parameter '{}', sending empty", name);
                    String::new()
                }
            },
            ConnectionParams::Vnc(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "password" => p.password.clone().unwrap_or_default(),
                "color-depth" => p.color_depth.map_or("24".into(), |d| d.to_string()),
                "cursor" => "local".into(),
                "read-only" => "false".into(),
                "swap-red-blue" => "false".into(),
                "dest-host" => String::new(),
                "dest-port" => String::new(),
                "enable-audio" => "false".into(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                _ => {
                    tracing::debug!("Unknown guacd VNC parameter '{}', sending empty", name);
                    String::new()
                }
            },
            ConnectionParams::Rdp(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                "port" => p.port.to_string(),
                "username" => p.username.clone(),
                "password" => p.password.clone().unwrap_or_default(),
                "domain" => p.domain.clone().unwrap_or_default(),
                "security" => p.security.clone().unwrap_or_else(|| "any".into()),
                "width" => p.width.to_string(),
                "height" => p.height.to_string(),
                "dpi" => p.dpi.to_string(),
                "color-depth" => "32".into(),
                "ignore-cert" => if p.ignore_cert { "true" } else { "false" }.into(),
                "disable-auth" => "false".into(),
                "cursor" => "local".into(),
                "enable-wallpaper" => if p.enable_wallpaper { "true" } else { "false" }.into(),
                "enable-theming" => if p.enable_theming { "true" } else { "false" }.into(),
                "enable-font-smoothing" => "true".into(),
                "enable-full-window-drag" => if p.enable_full_window_drag {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "enable-desktop-composition" => if p.enable_desktop_composition {
                    "true"
                } else {
                    "false"
                }
                .into(),
                "enable-menu-animations" => "false".into(),
                "disable-bitmap-caching" => "false".into(),
                "disable-offscreen-caching" => "false".into(),
                "resize-method" => "display-update".into(),
                "secondary-monitors" => p.secondary_monitors.to_string(),
                "read-only" => "false".into(),
                "gateway-hostname" => String::new(),
                "gateway-port" => String::new(),
                "gateway-domain" => String::new(),
                "gateway-username" => String::new(),
                "gateway-password" => String::new(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                "console" => "false".into(),
                "server-layout" => String::new(),
                "timezone" => String::new(),
                "disable-audio" => "false".into(),
                "enable-audio-input" => "false".into(),
                "enable-printing" => "false".into(),
                "enable-drive" => if p.enable_drive { "true" } else { "false" }.into(),
                "drive-path" => p.drive_path.clone().unwrap_or_default(),
                "create-drive-path" => if p.enable_drive { "true" } else { "false" }.into(),
                "drive-name" => p.drive_name.clone(),
                "disable-download" => if p.disable_download { "true" } else { "false" }.into(),
                "disable-upload" => if p.disable_upload { "true" } else { "false" }.into(),
                "auth-pkg" => p.auth_pkg.clone().unwrap_or_default(),
                "kdc-url" => p.kdc_url.clone().unwrap_or_default(),
                "kerberos-cache" => p.kerberos_cache.clone().unwrap_or_default(),
                "disable-gfx" => if p.enable_gfx { "false" } else { "true" }.into(),
                "force-lossless" => if p.force_lossless { "true" } else { "false" }.into(),
                "enable-h264" => if p.enable_h264 { "true" } else { "false" }.into(),
                "remote-app" => p.remote_app.clone().unwrap_or_default(),
                "remote-app-dir" => p.remote_app_dir.clone().unwrap_or_default(),
                "remote-app-args" => p.remote_app_args.clone().unwrap_or_default(),
                _ => {
                    tracing::debug!("Unknown guacd RDP parameter '{}', sending empty", name);
                    String::new()
                }
            },
            // Note: SPICE has no width/height/dpi connect args (it sizes via the
            // `size` instruction) and no `password` arg (delivered via argv below).
            ConnectionParams::Spice(p) => match name.as_str() {
                "hostname" => p.hostname.clone(),
                // TLS SPICE (e.g. Proxmox) is TLS-only: send an empty plain
                // port so guacd/spice-gtk connects via tls-port with TLS rather
                // than plaintext against a TLS endpoint.
                "port" => {
                    if p.tls {
                        String::new()
                    } else {
                        p.port.to_string()
                    }
                }
                // Credentials go in the connect args (not a post-connect argv
                // stream): guacd's SPICE client sets settings->password on the
                // session and authenticates during connect without awaiting
                // argv, so argv delivery races the auth. The connect arg is set
                // before the server connection is opened.
                "username" => p.username.clone().unwrap_or_default(),
                "password" => p.password.clone().unwrap_or_default(),
                "tls" => if p.tls { "true" } else { "false" }.into(),
                "tls-port" => p.tls_port.map(|x| x.to_string()).unwrap_or_default(),
                "ca-cert" => p.ca_cert.clone().unwrap_or_default(),
                "cert-subject" => p.cert_subject.clone().unwrap_or_default(),
                "ignore-cert" => if p.ignore_cert { "true" } else { "false" }.into(),
                "proxy" => p.proxy.clone().unwrap_or_default(),
                "color-depth" => p.color_depth.map_or("24".into(), |d| d.to_string()),
                "read-only" => "false".into(),
                "swap-red-blue" => "false".into(),
                "enable-audio" => if p.enable_audio { "true" } else { "false" }.into(),
                "disable-copy" => if p.disable_copy { "true" } else { "false" }.into(),
                "disable-paste" => if p.disable_paste { "true" } else { "false" }.into(),
                "secondary-monitors" => p.secondary_monitors.to_string(),
                _ => {
                    tracing::debug!("Unknown guacd SPICE parameter '{}', sending empty", name);
                    String::new()
                }
            },
        })
        .collect();

    // Send handshake instructions: size, audio, video, image, timezone, connect
    let (width, height, dpi, h264) = match &params {
        ConnectionParams::Ssh(p) => (p.width, p.height, p.dpi, false),
        ConnectionParams::Vnc(p) => (p.width, p.height, p.dpi, false),
        ConnectionParams::Rdp(p) => (p.width, p.height, p.dpi, p.enable_h264),
        ConnectionParams::Spice(p) => (p.width, p.height, p.dpi, false),
    };
    send_handshake(&mut stream, width, height, dpi, h264).await?;

    let connect = Instruction::new("connect", arg_values);
    stream
        .write_all(connect.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    tracing::debug!("Sent handshake instructions");

    // Read the ready instruction — confirms connection is established
    let ready = read_instruction(&mut stream).await?;
    if ready.opcode != "ready" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'ready' instruction, got '{}' (args: {:?})",
            ready.opcode, ready.args
        )));
    }

    let connection_id = ready
        .args
        .first()
        .cloned()
        .unwrap_or_else(|| "unknown".into());

    // Send environ instruction for SSH sessions to set LANG.
    // guacd applies these to the remote shell environment.
    if matches!(params, ConnectionParams::Ssh(_)) {
        let environ = Instruction::new("environ", vec!["LANG".into(), "en_US.UTF-8".into()]);
        stream
            .write_all(environ.encode().as_bytes())
            .await
            .map_err(|e| GuacdError::Io(e.to_string()))?;
        tracing::debug!("Sent environ instruction: LANG=en_US.UTF-8");
    }

    tracing::info!("guacd handshake complete, connection_id={}", connection_id);

    Ok((stream, connection_id))
}

/// Join an existing guacd connection by its connection_id.
///
/// Opens a new TCP connection to guacd and sends `select` with the connection_id
/// instead of a protocol name. guacd routes this to the existing session process,
/// allowing multiple users to share the same session.
pub async fn join_connection(
    guacd_addr: &str,
    connection_id: &str,
    width: u32,
    height: u32,
    dpi: u32,
    tls: Option<&tokio_rustls::TlsConnector>,
) -> Result<GuacdStream, GuacdError> {
    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(guacd_addr))
        .await
        .map_err(|_| {
            GuacdError::Connection(format!("Timeout connecting to guacd at {}", guacd_addr))
        })?
        .map_err(|e| {
            GuacdError::Connection(format!(
                "Failed to connect to guacd at {}: {}",
                guacd_addr, e
            ))
        })?;

    apply_keepalive(&tcp);
    tracing::debug!(
        "Connected to guacd for join, connection_id={}",
        connection_id
    );

    let mut stream: GuacdStream = wrap_tls(tcp, tls, guacd_addr).await?;

    // Send select with the connection_id to join the existing session
    let select = Instruction::new("select", vec![connection_id.into()]);
    stream
        .write_all(select.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    // Read args instruction (guacd still sends args for joining users)
    let args_instruction = read_instruction(&mut stream).await?;
    if args_instruction.opcode != "args" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'args' from join, got '{}'",
            args_instruction.opcode
        )));
    }

    tracing::debug!("Join args: {:?}", args_instruction.args);

    // For joining, send empty values for all args (the connection is already configured)
    let arg_values: Vec<String> = args_instruction
        .args
        .iter()
        .map(|name| match name.as_str() {
            "read-only" => "false".into(),
            _ => String::new(),
        })
        .collect();

    // Send handshake instructions (joining user — h264 inherited from session)
    send_handshake(&mut stream, width, height, dpi, false).await?;

    let connect = Instruction::new("connect", arg_values);
    stream
        .write_all(connect.encode().as_bytes())
        .await
        .map_err(|e| GuacdError::Io(e.to_string()))?;

    // Read ready
    let ready = read_instruction(&mut stream).await?;
    if ready.opcode != "ready" {
        return Err(GuacdError::Protocol(format!(
            "Expected 'ready' from join, got '{}' (args: {:?})",
            ready.opcode, ready.args
        )));
    }

    tracing::info!("Joined existing connection {}", connection_id);

    Ok(stream)
}

/// Optionally wrap a TCP stream in TLS. Returns a boxed GuacdStream.
/// Derives the TLS server name from `guacd_addr` (host:port format).
async fn wrap_tls(
    tcp: TcpStream,
    tls: Option<&tokio_rustls::TlsConnector>,
    guacd_addr: &str,
) -> Result<GuacdStream, GuacdError> {
    match tls {
        Some(connector) => {
            // Extract hostname from "host:port" address
            let hostname = guacd_addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(guacd_addr);
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(hostname.to_string())
                    .map_err(|e| {
                        GuacdError::Connection(format!(
                            "Invalid TLS server name '{}': {}",
                            hostname, e
                        ))
                    })?
                    .to_owned();
            let tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
                GuacdError::Connection(format!("TLS handshake with guacd failed: {}", e))
            })?;
            tracing::debug!(
                "TLS connection to guacd established (server_name={})",
                hostname
            );
            Ok(Box::new(tls_stream))
        }
        None => Ok(Box::new(tcp)),
    }
}

/// Send the common handshake instructions (size, audio, video, image, timezone).
async fn send_handshake(
    stream: &mut (impl AsyncWrite + Unpin),
    width: u32,
    height: u32,
    dpi: u32,
    enable_h264: bool,
) -> Result<(), GuacdError> {
    let video_args = if enable_h264 {
        vec!["video/h264".into()]
    } else {
        vec![]
    };

    let instructions = [
        Instruction::new(
            "size",
            vec![width.to_string(), height.to_string(), dpi.to_string()],
        ),
        Instruction::new("audio", vec!["audio/L16".into(), "audio/L8".into()]),
        Instruction::new("video", video_args),
        Instruction::new(
            "image",
            vec!["image/png".into(), "image/jpeg".into(), "image/webp".into()],
        ),
        Instruction::new("timezone", vec!["Australia/Brisbane".into()]),
    ];

    for inst in &instructions {
        stream
            .write_all(inst.encode().as_bytes())
            .await
            .map_err(|e| GuacdError::Io(e.to_string()))?;
    }

    Ok(())
}

/// Read a single complete instruction from an async stream.
async fn read_instruction(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Instruction, GuacdError> {
    let mut parser = InstructionParser::new();
    let mut buf = [0u8; 4096];

    loop {
        let n = stream
            .read(&mut buf)
            .await
            .map_err(|e| GuacdError::Io(e.to_string()))?;
        if n == 0 {
            return Err(GuacdError::Connection("guacd closed connection".into()));
        }
        let data = std::str::from_utf8(&buf[..n])
            .map_err(|e| GuacdError::Protocol(format!("Invalid UTF-8 from guacd: {}", e)))?;

        let results = parser.receive(data);
        if let Some(result) = results.into_iter().next() {
            return result.map_err(|e| GuacdError::Protocol(e.to_string()));
        }
    }
}

#[derive(Debug)]
#[must_use]
pub enum GuacdError {
    Connection(String),
    Io(String),
    Protocol(String),
}

impl std::fmt::Display for GuacdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuacdError::Connection(msg) => write!(f, "connection error: {}", msg),
            GuacdError::Io(msg) => write!(f, "I/O error: {}", msg),
            GuacdError::Protocol(msg) => write!(f, "protocol error: {}", msg),
        }
    }
}

impl std::error::Error for GuacdError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    struct MockStream {
        written: Vec<u8>,
    }
    impl MockStream {
        fn new() -> Self {
            Self {
                written: Vec::new(),
            }
        }
        fn output(&self) -> &str {
            std::str::from_utf8(&self.written).unwrap()
        }
    }
    impl AsyncWrite for MockStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, std::io::Error>> {
            self.written.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), std::io::Error>> {
            Poll::Ready(Ok(()))
        }
    }
    #[tokio::test]
    async fn send_handshake_ssh_wiresize() {
        let mut s = MockStream::new();
        send_handshake(&mut s, 1920, 1080, 96, false).await.unwrap();
        assert_eq!(s.output(), "4.size,4.1920,4.1080,2.96;5.audio,9.audio/L16,8.audio/L8;5.video;5.image,9.image/png,10.image/jpeg,10.image/webp;8.timezone,18.Australia/Brisbane;");
    }
    #[tokio::test]
    async fn send_handshake_rdp_with_h264() {
        let mut s = MockStream::new();
        send_handshake(&mut s, 1280, 720, 72, true).await.unwrap();
        assert_eq!(s.output(), "4.size,4.1280,3.720,2.72;5.audio,9.audio/L16,8.audio/L8;5.video,10.video/h264;5.image,9.image/png,10.image/jpeg,10.image/webp;8.timezone,18.Australia/Brisbane;");
    }
    #[tokio::test]
    async fn send_handshake_vnc() {
        let mut s = MockStream::new();
        send_handshake(&mut s, 1024, 768, 72, false).await.unwrap();
        assert_eq!(s.output(), "4.size,4.1024,3.768,2.72;5.audio,9.audio/L16,8.audio/L8;5.video;5.image,9.image/png,10.image/jpeg,10.image/webp;8.timezone,18.Australia/Brisbane;");
    }
    #[tokio::test]
    async fn send_handshake_spice() {
        let mut s = MockStream::new();
        send_handshake(&mut s, 2560, 1440, 120, false)
            .await
            .unwrap();
        assert_eq!(s.output(), "4.size,4.2560,4.1440,3.120;5.audio,9.audio/L16,8.audio/L8;5.video;5.image,9.image/png,10.image/jpeg,10.image/webp;8.timezone,18.Australia/Brisbane;");
    }
    #[tokio::test]
    async fn send_handshake_each_instruction_is_well_formed() {
        let mut s = MockStream::new();
        send_handshake(&mut s, 800, 600, 96, false).await.unwrap();
        for seg in s.output().split(';').filter(|x| !x.is_empty()) {
            Instruction::parse(&format!("{};", seg)).unwrap();
        }
    }
    #[tokio::test]
    async fn select_for_ssh() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new("select", vec!["ssh".into()])
                .encode()
                .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(s.output(), "6.select,3.ssh;");
    }
    #[tokio::test]
    async fn select_for_rdp() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new("select", vec!["rdp".into()])
                .encode()
                .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(s.output(), "6.select,3.rdp;");
    }
    #[tokio::test]
    async fn select_for_vnc() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new("select", vec!["vnc".into()])
                .encode()
                .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(s.output(), "6.select,3.vnc;");
    }
    #[tokio::test]
    async fn select_for_spice() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new("select", vec!["spice".into()])
                .encode()
                .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(s.output(), "6.select,5.spice;");
    }
    #[tokio::test]
    async fn connect_instruction_args() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new(
                "connect",
                vec![
                    "10.0.0.5".into(),
                    "22".into(),
                    "admin".into(),
                    "secret".into(),
                ],
            )
            .encode()
            .as_bytes(),
        )
        .await
        .unwrap();
        let parsed = Instruction::parse(s.output()).unwrap();
        assert_eq!(parsed.args[0], "10.0.0.5");
        assert_eq!(parsed.args[3], "secret");
    }
    #[tokio::test]
    async fn full_handshake_sequence_ssh() {
        let mut s = MockStream::new();
        s.write_all(
            Instruction::new("select", vec!["ssh".into()])
                .encode()
                .as_bytes(),
        )
        .await
        .unwrap();
        send_handshake(&mut s, 1920, 1080, 96, false).await.unwrap();
        s.write_all(
            Instruction::new(
                "connect",
                vec![
                    "10.0.0.5".into(),
                    "22".into(),
                    "admin".into(),
                    "password".into(),
                    "".into(),
                    "1920".into(),
                    "1080".into(),
                    "96".into(),
                ],
            )
            .encode()
            .as_bytes(),
        )
        .await
        .unwrap();
        assert_eq!(s.output().matches(';').count(), 7);
    }
    #[test]
    fn mock_guacd_connection_captures_instructions() {
        use crate::testing::MockGuacdConnection;
        let m = MockGuacdConnection::new();
        assert!(m.drain_sent().is_empty());
    }
}
