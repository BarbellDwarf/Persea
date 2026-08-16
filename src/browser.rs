//! Process lifecycle manager for Xvnc + Chromium browser sessions.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{timeout, Duration};

#[cfg(test)]
use aes::cipher::{block_padding::Pkcs7, BlockModeEncrypt, KeyIvInit};
#[cfg(test)]
use hmac::Hmac;
#[cfg(test)]
use sha1::Sha1;

/// Allocates numbers from a fixed range pool.
struct RangeAllocator {
    in_use: Mutex<HashSet<u32>>,
    range_start: u32,
    range_end: u32,
}

impl RangeAllocator {
    fn new(range_start: u32, range_end: u32) -> Self {
        Self {
            in_use: Mutex::new(HashSet::new()),
            range_start,
            range_end,
        }
    }

    fn allocate(&self) -> Option<u32> {
        let mut in_use = self.in_use.lock().unwrap();
        for n in self.range_start..=self.range_end {
            if !in_use.contains(&n) {
                in_use.insert(n);
                return Some(n);
            }
        }
        None
    }

    fn release(&self, n: u32) {
        let mut in_use = self.in_use.lock().unwrap();
        in_use.remove(&n);
    }
}

/// Handles for the spawned Xvnc and Chromium processes.
pub struct BrowserSession {
    /// X display number allocated from the pool for this session.
    pub display: u32,
    /// VNC port Xvnc listens on (`5900 + display`).
    pub vnc_port: u16,
    /// Handle to the spawned Xvnc process.
    pub xvnc_child: Child,
    /// Handle to the spawned Chromium process.
    pub chromium_child: Child,
    /// Per-session Chromium profile directory, removed when the session ends.
    pub profile_dir: PathBuf,
    /// CDP port allocated for this session (if login script requested).
    pub cdp_port: Option<u16>,
}

/// Manages spawning and killing browser sessions.
pub struct BrowserManager {
    display_allocator: RangeAllocator,
    cdp_allocator: RangeAllocator,
    xvnc_path: String,
    chromium_path: String,
    login_scripts_dir: PathBuf,
    login_script_timeout_secs: u64,
}

impl BrowserManager {
    #[allow(clippy::too_many_arguments)]
    /// Create a manager with the given binary paths, display-number and
    /// CDP port pools, and login script settings.
    pub fn new(
        xvnc_path: String,
        chromium_path: String,
        display_range_start: u32,
        display_range_end: u32,
        cdp_port_range_start: u16,
        cdp_port_range_end: u16,
        login_scripts_dir: PathBuf,
        login_script_timeout_secs: u64,
    ) -> Self {
        Self {
            display_allocator: RangeAllocator::new(display_range_start, display_range_end),
            cdp_allocator: RangeAllocator::new(
                cdp_port_range_start as u32,
                cdp_port_range_end as u32,
            ),
            xvnc_path,
            chromium_path,
            login_scripts_dir,
            login_script_timeout_secs,
        }
    }

    /// Spawn Xvnc and Chromium for the given URL.
    /// If `need_cdp` is true, allocates a CDP port and starts Chromium with
    /// `--remote-debugging-port` so login scripts can connect via DevTools Protocol.
    /// If `autofill_credentials` is provided, pre-populates Chromium's Login Data
    /// SQLite before launch so autofill works natively on matching forms.
    pub async fn spawn(
        &self,
        url: &str,
        width: u32,
        height: u32,
        need_cdp: bool,
        autofill_credentials: Option<&[(String, String, String)]>,
        allowed_domains: Option<&[String]>,
    ) -> Result<BrowserSession, BrowserError> {
        // Runtime feature guard (not compile-out): the Xvnc + Chromium
        // session stack is Linux-only; on Windows the feature stays in the
        // binary and fails with a clear error when used.
        #[cfg(windows)]
        {
            let _ = (
                self,
                url,
                width,
                height,
                need_cdp,
                autofill_credentials,
                allowed_domains,
            );
            return Err(BrowserError::ChromiumSpawn(
                "web sessions (Xvnc + Chromium) are not supported on Windows — \
                 use SSH, RDP, or VNC sessions, or run persea on Linux"
                    .into(),
            ));
        }
        // Default-deny non-http(s) schemes. On Windows the guard above
        // returns, so everything here is unreachable by design — the runtime
        // guard keeps the code compiled in the one binary.
        #[allow(unreachable_code)]
        if let Ok(parsed) = url::Url::parse(url) {
            if !matches!(parsed.scheme(), "http" | "https") {
                return Err(BrowserError::ChromiumSpawn(format!(
                    "URL scheme '{}' is not allowed (only http/https)",
                    parsed.scheme()
                )));
            }
        }

        let display_num = self.display_allocator.allocate().ok_or_else(|| {
            tracing::error!(
                "No X display numbers available (range {}–{})",
                self.display_allocator.range_start,
                self.display_allocator.range_end
            );
            BrowserError::NoDisplayAvailable
        })?;

        let cdp_port = if need_cdp {
            let port = self.cdp_allocator.allocate().ok_or_else(|| {
                self.display_allocator.release(display_num);
                tracing::error!(
                    "No CDP ports available (range {}–{})",
                    self.cdp_allocator.range_start,
                    self.cdp_allocator.range_end
                );
                BrowserError::NoCdpPortAvailable
            })?;
            Some(port as u16)
        } else {
            None
        };

        let vnc_port = 5900 + display_num as u16;
        let geometry = format!("{}x{}", width, height);

        // Create a unique profile directory for this session (UUID avoids stale crash state)
        let profile_dir =
            std::env::temp_dir().join(format!("persea-chromium-{}", uuid::Uuid::new_v4()));
        let _ = std::fs::remove_dir_all(&profile_dir); // clean slate
        if let Err(e) = std::fs::create_dir_all(&profile_dir) {
            self.display_allocator.release(display_num);
            if let Some(p) = cdp_port {
                self.cdp_allocator.release(p as u32);
            }
            let msg = format!("Failed to create profile dir {:?}: {}", profile_dir, e);
            tracing::error!("{}", msg);
            return Err(BrowserError::ChromiumSpawn(msg));
        }
        // Restrictive permissions on the profile dir (unix only — the whole
        // browser feature is runtime-guarded off on Windows anyway).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&profile_dir, std::fs::Permissions::from_mode(0o700));
        }

        // Pre-populate Chromium autofill database if credentials are provided
        if let Some(creds) = autofill_credentials {
            if let Err(e) = populate_login_data(&profile_dir, creds) {
                tracing::warn!(
                    error = %e,
                    "Failed to populate Chromium autofill (session continues without autofill)"
                );
            } else {
                tracing::info!(
                    count = creds.len(),
                    "Pre-populated Chromium Login Data with {} credential(s)",
                    creds.len()
                );
            }
        }

        tracing::info!(
            xvnc_path = %self.xvnc_path,
            display = %display_num,
            vnc_port = %vnc_port,
            geometry = %geometry,
            "Spawning Xvnc"
        );

        // Spawn Xvnc
        let mut xvnc_child = Command::new(&self.xvnc_path)
            .arg(format!(":{}", display_num))
            .args([
                "-geometry",
                &geometry,
                "-depth",
                "24",
                "-SecurityTypes",
                "None",
                "-localhost",
                "-AlwaysShared",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| {
                self.display_allocator.release(display_num);
                if let Some(p) = cdp_port {
                    self.cdp_allocator.release(p as u32);
                }
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.xvnc_path, e);
                tracing::error!("{}", msg);
                BrowserError::XvncSpawn(msg)
            })?;

        tracing::info!(
            display = %display_num,
            pid = ?xvnc_child.id(),
            "Xvnc process spawned, waiting for VNC port {} to accept connections",
            vnc_port
        );

        // Wait for VNC port to accept connections (up to 2s)
        let addr = format!("127.0.0.1:{}", vnc_port);
        let port_ready = timeout(Duration::from_secs(2), async {
            loop {
                if TcpStream::connect(&addr).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;

        if port_ready.is_err() {
            // Collect stderr to help diagnose why Xvnc didn't start
            let stderr_output = collect_stderr(&mut xvnc_child).await;
            let _ = xvnc_child.kill().await;
            let _ = xvnc_child.wait().await;
            self.display_allocator.release(display_num);
            if let Some(p) = cdp_port {
                self.cdp_allocator.release(p as u32);
            }
            let _ = std::fs::remove_dir_all(&profile_dir);
            let msg = format!(
                "Xvnc did not start listening on port {} within 2s{}",
                vnc_port,
                if stderr_output.is_empty() {
                    String::new()
                } else {
                    format!("; stderr: {}", stderr_output)
                }
            );
            tracing::error!("{}", msg);
            return Err(BrowserError::XvncSpawn(msg));
        }

        tracing::info!(display = %display_num, vnc_port = %vnc_port, "Xvnc is ready and accepting connections");

        tracing::info!(
            chromium_path = %self.chromium_path,
            display = %display_num,
            profile_dir = %profile_dir.display(),
            url = %url,
            cdp_port = ?cdp_port,
            "Spawning Chromium"
        );

        // Spawn Chromium with isolated profile
        let window_size = format!("--window-size={},{}", width, height);
        let user_data_dir = format!("--user-data-dir={}", profile_dir.display());
        let cdp_arg = cdp_port.map(|p| format!("--remote-debugging-port={}", p));

        let mut chromium_args = vec![
            "--start-fullscreen",
            "--no-first-run",
            "--noerrdialogs",
            "--disable-infobars",
            "--disable-translate",
            "--disable-features=TranslateUI,VizDisplayCompositor,AutofillServerCommunication,MediaRouter,PasswordImport",
            // GPU / rendering — safe for headless VMs without GPU
            "--disable-gpu",
            "--disable-gpu-compositing",
            "--disable-software-rasterizer",
            "--disable-dev-shm-usage",
            "--use-gl=angle",
            "--use-angle=swiftshader",
            "--in-process-gpu",
            // Stability
            "--disable-background-networking",
            "--disable-sync",
            "--disable-breakpad",
            "--disable-crash-reporter",
            "--no-default-browser-check",
            "--window-position=0,0",
            // Disable autofill/credential storage for ephemeral VDI sessions
            "--disable-autofill",
        ];
        // Owned strings that need to outlive the args slice
        chromium_args.push(&window_size);
        chromium_args.push(&user_data_dir);
        if let Some(ref arg) = cdp_arg {
            chromium_args.push(arg);
        }

        // Per-session domain allowlist via --host-rules.
        // Maps all hosts to a non-routable address except the allowed ones.
        // Always blocks internal/metadata IPs (localhost, 127.0.0.1,
        // 169.254.0.0/16) even without an explicit allowlist.
        let host_rules_arg = Some(format!(
            "--host-rules={}",
            build_host_rules(allowed_domains)
        ));
        if let Some(ref arg) = host_rules_arg {
            chromium_args.push(arg);
            // Suppress the "unsupported command-line flag" infobar.
            // Shows "controlled by automated test software" bar instead, which is acceptable.
            // Cannot use --test-type here as it disables the password manager (breaks autofill).
            chromium_args.push("--enable-automation");
        }

        // Note: In Docker containers, the process runs as non-root (USER persea),
        // so Chromium's sandbox is active. This --no-sandbox is only for local
        // development when running as root.
        let no_sandbox;
        #[cfg(unix)]
        {
            // SAFETY: geteuid() is a simple POSIX syscall that returns the
            // effective user ID of the calling process. It is always safe to
            // call and has no side effects or preconditions.
            if unsafe { libc::geteuid() } == 0 {
                no_sandbox = "--no-sandbox".to_string();
                chromium_args.push(&no_sandbox);
                tracing::debug!("Running as root, adding --no-sandbox to Chromium");
            }
        }
        #[cfg(not(unix))]
        {
            let _ = &mut chromium_args;
            no_sandbox = String::new();
        }

        chromium_args.push(url);

        // Optional hardening: per-session resource limits (RLIMIT_AS,
        // RLIMIT_CPU, RLIMIT_NOFILE) can be applied here via pre_exec +
        // setrlimit on the Command if a session needs a hard cap; not
        // applied because limits are set at the process supervisor or
        // container level in deployments.
        let chromium_result = Command::new(&self.chromium_path)
            .env("DISPLAY", format!(":{}", display_num))
            .args(&chromium_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn();

        let mut chromium_child = match chromium_result {
            Ok(child) => {
                tracing::info!(
                    display = %display_num,
                    pid = ?child.id(),
                    url = %url,
                    "Chromium process spawned"
                );
                child
            }
            Err(e) => {
                let _ = xvnc_child.kill().await;
                let _ = xvnc_child.wait().await;
                self.display_allocator.release(display_num);
                if let Some(p) = cdp_port {
                    self.cdp_allocator.release(p as u32);
                }
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!("Failed to spawn '{}': {}", self.chromium_path, e);
                tracing::error!("{}", msg);
                return Err(BrowserError::ChromiumSpawn(msg));
            }
        };

        // Post-spawn liveness check: give Chromium a moment to crash on startup
        // (e.g. sandbox failures, missing libs). If it exits immediately, capture
        // stderr so we can log something useful instead of a silent black screen.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        match chromium_child.try_wait() {
            Ok(Some(status)) => {
                // Chromium exited already — capture stderr for diagnostics
                let mut stderr_msg = String::new();
                if let Some(mut stderr) = chromium_child.stderr.take() {
                    use tokio::io::AsyncReadExt;
                    let mut buf = Vec::new();
                    let _ = stderr.read_to_end(&mut buf).await;
                    stderr_msg = String::from_utf8_lossy(&buf).to_string();
                    // Trim to a reasonable length for logging
                    if stderr_msg.len() > 2000 {
                        stderr_msg.truncate(2000);
                        stderr_msg.push_str("...(truncated)");
                    }
                }
                let _ = xvnc_child.kill().await;
                let _ = xvnc_child.wait().await;
                self.display_allocator.release(display_num);
                if let Some(p) = cdp_port {
                    self.cdp_allocator.release(p as u32);
                }
                let _ = std::fs::remove_dir_all(&profile_dir);
                let msg = format!(
                    "Chromium exited immediately ({}). stderr: {}",
                    status,
                    if stderr_msg.is_empty() {
                        "(empty)".to_string()
                    } else {
                        stderr_msg
                    }
                );
                tracing::error!(display = %display_num, "{}", msg);
                return Err(BrowserError::ChromiumSpawn(msg));
            }
            Ok(None) => {
                // Still running — good
                tracing::debug!(display = %display_num, "Chromium still alive after 500ms");
            }
            Err(e) => {
                tracing::warn!(display = %display_num, "Could not check Chromium status: {}", e);
            }
        }

        Ok(BrowserSession {
            display: display_num,
            vnc_port,
            xvnc_child,
            chromium_child,
            profile_dir,
            cdp_port,
        })
    }

    /// Kill both Chromium and Xvnc, release the display number and CDP port,
    /// and clean up the profile dir.
    pub async fn kill(&self, session: &mut BrowserSession) {
        tracing::info!(
            display = %session.display,
            chromium_pid = ?session.chromium_child.id(),
            xvnc_pid = ?session.xvnc_child.id(),
            "Killing browser session processes"
        );
        let _ = session.chromium_child.kill().await;
        let _ = session.chromium_child.wait().await;
        let _ = session.xvnc_child.kill().await;
        let _ = session.xvnc_child.wait().await;
        self.display_allocator.release(session.display);
        if let Some(p) = session.cdp_port.take() {
            self.cdp_allocator.release(p as u32);
        }

        // Clean up the per-session Chromium profile directory
        let profile_dir = session.profile_dir.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = std::fs::remove_dir_all(&profile_dir) {
                tracing::warn!(path = %profile_dir.display(), error = %e, "Failed to clean up Chromium profile dir");
            }
        });

        tracing::info!(display = %session.display, "Browser session cleaned up, display released");
    }

    /// Run a login script as a child process with env vars for CDP port, credentials, etc.
    /// Returns a `JoinHandle` that completes when the script finishes (or times out).
    /// Script failures log a warning but do not kill the session.
    #[allow(clippy::too_many_arguments)]
    pub fn run_login_script(
        &self,
        script_name: &str,
        display: u32,
        cdp_port: u16,
        url: &str,
        username: Option<&str>,
        password: Option<&str>,
        session_id: &str,
    ) -> Result<tokio::task::JoinHandle<()>, BrowserError> {
        // Validate: resolve relative to login_scripts_dir, block path traversal
        let script_path = self.login_scripts_dir.join(script_name);
        let canonical = script_path.canonicalize().map_err(|e| {
            BrowserError::LoginScript(format!("login script '{}' not found: {}", script_name, e))
        })?;
        let canonical_base = self.login_scripts_dir.canonicalize().map_err(|e| {
            BrowserError::LoginScript(format!(
                "login_scripts_dir '{}' not found: {}",
                self.login_scripts_dir.display(),
                e
            ))
        })?;
        if !canonical.starts_with(&canonical_base) {
            return Err(BrowserError::LoginScript(format!(
                "login script '{}' is outside scripts directory",
                script_name
            )));
        }

        // Check the script is executable
        if !is_executable(&canonical) {
            return Err(BrowserError::LoginScript(format!(
                "login script '{}' is not executable",
                script_name
            )));
        }

        let timeout_secs = self.login_script_timeout_secs;
        let script_path_owned = canonical;
        let url_owned = url.to_string();
        let username_owned = username.unwrap_or("").to_string();
        let password_owned = password.unwrap_or("").to_string();
        let session_id_owned = session_id.to_string();

        let handle = tokio::spawn(async move {
            tracing::info!(
                script = %script_path_owned.display(),
                session_id = %session_id_owned,
                cdp_port = %cdp_port,
                "Running login script"
            );

            // Build credentials JSON for stdin
            let stdin_json = serde_json::json!({
                "username": username_owned,
                "password": password_owned,
                "url": url_owned,
                "cdp_port": cdp_port,
                "session_id": session_id_owned,
            })
            .to_string();

            let result = timeout(Duration::from_secs(timeout_secs), async {
                let mut child = match Command::new(&script_path_owned)
                    .env("DISPLAY", format!(":{}", display))
                    .env("RUSTGUAC_CDP_PORT", cdp_port.to_string())
                    .env("RUSTGUAC_URL", &url_owned)
                    .env("RUSTGUAC_SESSION_ID", &session_id_owned)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    // Kill the script if the timeout future is dropped
                    // mid-run; the reaper task then reaps the pid.
                    .kill_on_drop(true)
                    .spawn()
                {
                    Ok(child) => child,
                    Err(e) => {
                        tracing::warn!(
                            script = %script_path_owned.display(),
                            error = %e,
                            "Failed to spawn login script"
                        );
                        return;
                    }
                };

                // Write credentials JSON to stdin, then close
                if let Some(mut stdin) = child.stdin.take() {
                    use tokio::io::AsyncWriteExt;
                    let _ = stdin.write_all(stdin_json.as_bytes()).await;
                    // stdin dropped here, closing the pipe
                }

                match child.wait_with_output().await {
                    Ok(output) => {
                        if output.status.success() {
                            tracing::info!(
                                script = %script_path_owned.display(),
                                session_id = %session_id_owned,
                                "Login script completed successfully"
                            );
                        } else {
                            tracing::warn!(
                                script = %script_path_owned.display(),
                                session_id = %session_id_owned,
                                exit_code = ?output.status.code(),
                                "Login script failed"
                            );
                        }
                        // Script output may carry credentials (scripts echo
                        // what they type), so it is logged truncated and at
                        // debug level only, never verbatim at info/warn.
                        if !output.stdout.is_empty() {
                            tracing::debug!(
                                session_id = %session_id_owned,
                                "Login script stdout: {}",
                                truncate_for_log(&output.stdout)
                            );
                        }
                        if !output.stderr.is_empty() {
                            tracing::debug!(
                                session_id = %session_id_owned,
                                "Login script stderr: {}",
                                truncate_for_log(&output.stderr)
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(
                            script = %script_path_owned.display(),
                            error = %e,
                            "Failed to wait for login script"
                        );
                    }
                }
            })
            .await;

            if result.is_err() {
                tracing::warn!(
                    script = %script_path_owned.display(),
                    session_id = %session_id_owned,
                    timeout_secs = timeout_secs,
                    "Login script timed out, killing"
                );
            }
        });

        Ok(handle)
    }
}

/// Build the `--host-rules` value for a browser session. Every host maps to
/// `~NOTFOUND` (lookup fails) except allowlisted domains, which are excluded
/// from the mapping and resolve normally. localhost, 127.0.0.1, and the
/// 169.254.0.0/16 link-local range (host-rules patterns are globs, so the
/// range is written `169.254.*`) are mapped explicitly and can never be
/// unblocked by an allowlist.
fn build_host_rules(allowed_domains: Option<&[String]>) -> String {
    let mut rules = String::from(
        "MAP * ~NOTFOUND, MAP localhost ~NOTFOUND, MAP 127.0.0.1 ~NOTFOUND, \
         MAP 169.254.* ~NOTFOUND",
    );
    if let Some(domains) = allowed_domains {
        for domain in domains {
            let d = domain.trim();
            if !d.is_empty() && !is_always_blocked(d) {
                rules.push_str(&format!(", EXCLUDE {}", d));
                if !d.starts_with("*.") {
                    rules.push_str(&format!(", EXCLUDE *.{}", d));
                }
            }
        }
    }
    rules
}

/// True if a domain pattern names a host that must stay unreachable from
/// browser sessions regardless of allowlist: localhost (and its subdomains),
/// the loopback literal 127.0.0.1, and the 169.254.0.0/16 link-local range
/// (exact IPs or the `169.254.*` glob form).
fn is_always_blocked(pattern: &str) -> bool {
    let p = pattern.trim().to_ascii_lowercase();
    p == "localhost"
        || p.ends_with(".localhost")
        || p == "127.0.0.1"
        || p.strip_prefix("169.254")
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('.'))
}

/// Encrypt a password using Chromium's Linux "basic" os_crypt backend.
///
/// On Linux without a keyring (our case — headless Xvnc), Chromium uses:
/// 1. PBKDF2("peanuts", "saltysalt", 1 iteration, SHA-1) → 16-byte AES key
/// 2. AES-128-CBC with IV = 16 × 0x20 (space chars)
#[cfg(test)]
/// 3. Blob format: "v10" prefix + encrypted ciphertext
fn encrypt_chromium_password(plaintext: &str) -> Result<Vec<u8>, String> {
    // Derive the AES key: PBKDF2(password="peanuts", salt="saltysalt", iterations=1, dkLen=16)
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2::<Hmac<Sha1>>(b"peanuts", b"saltysalt", 1, &mut key)
        .map_err(|e| format!("PBKDF2 derivation failed: {}", e))?;

    // IV is 16 space characters (0x20)
    let iv = [0x20u8; 16];

    // Encrypt with AES-128-CBC + PKCS7 padding
    type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
    let plaintext_bytes = plaintext.as_bytes();
    // Buffer needs room for plaintext + up to one block of padding
    let mut buf = vec![0u8; plaintext_bytes.len() + 16];
    buf[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
    let encrypted = Aes128CbcEnc::new(&key.into(), &iv.into())
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext_bytes.len())
        .map_err(|e| format!("AES encryption failed: {}", e))?;

    // Prepend "v10" version tag
    let mut blob = Vec::with_capacity(3 + encrypted.len());
    blob.extend_from_slice(b"v10");
    blob.extend_from_slice(encrypted);
    Ok(blob)
}

/// Pre-populate Chromium's Login Data SQLite with credentials for autofill.
///
/// Creates the `{profile_dir}/Default/Login Data` SQLite database with the
/// `logins` table and inserts encrypted credentials for each (origin_url,
/// username, password) tuple.
fn populate_login_data(
    _profile_dir: &Path,
    _credentials: &[(String, String, String)],
) -> Result<(), String> {
    // VDI sessions are ephemeral — don't populate Chromium's password store.
    // Users enter credentials manually during the session.
    Ok(())
}

/// Check if a path is an executable file.
fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            meta.is_file() && (meta.permissions().mode() & 0o111 != 0)
        } else {
            false
        }
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

/// Truncate child process output for logging so a credential echo cannot
/// be captured whole; 200 chars keeps enough context to diagnose failures.
fn truncate_for_log(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let trimmed = text.trim();
    let mut snippet: String = trimmed.chars().take(200).collect();
    if trimmed.len() > snippet.len() {
        snippet.push_str("...(truncated)");
    }
    snippet
}

/// Read whatever stderr is available from a child process (non-blocking, best-effort).
async fn collect_stderr(child: &mut Child) -> String {
    use tokio::io::AsyncReadExt;
    if let Some(ref mut stderr) = child.stderr {
        let mut buf = vec![0u8; 4096];
        match timeout(Duration::from_millis(200), stderr.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => String::from_utf8_lossy(&buf[..n]).trim().to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    }
}

/// Errors from spawning or running a browser session.
#[derive(Debug)]
#[must_use]
pub enum BrowserError {
    /// The X display number pool is exhausted.
    NoDisplayAvailable,
    /// The CDP port pool is exhausted.
    NoCdpPortAvailable,
    /// Xvnc failed to start or never opened its VNC port.
    XvncSpawn(String),
    /// Chromium failed to spawn or exited immediately after launch.
    ChromiumSpawn(String),
    /// The login script is missing, not executable, or escapes the scripts
    /// directory.
    LoginScript(String),
}

impl std::fmt::Display for BrowserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrowserError::NoDisplayAvailable => write!(f, "no X display numbers available"),
            BrowserError::NoCdpPortAvailable => write!(f, "no CDP ports available"),
            BrowserError::XvncSpawn(msg) => write!(f, "Xvnc spawn failed: {}", msg),
            BrowserError::ChromiumSpawn(msg) => write!(f, "Chromium spawn failed: {}", msg),
            BrowserError::LoginScript(msg) => write!(f, "login script error: {}", msg),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_chromium_password_v10_prefix() {
        let blob = encrypt_chromium_password("secret").unwrap();
        assert_eq!(&blob[..3], b"v10");
    }

    #[test]
    fn test_encrypt_chromium_password_deterministic() {
        let a = encrypt_chromium_password("test123").unwrap();
        let b = encrypt_chromium_password("test123").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_encrypt_chromium_password_different_inputs() {
        let a = encrypt_chromium_password("password1").unwrap();
        let b = encrypt_chromium_password("password2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_encrypt_chromium_password_block_aligned() {
        // AES-128-CBC with PKCS7: output is always multiple of 16 bytes
        let blob = encrypt_chromium_password("short").unwrap();
        let ciphertext_len = blob.len() - 3; // minus "v10" prefix
        assert_eq!(ciphertext_len % 16, 0);
    }

    #[test]
    fn test_encrypt_chromium_password_empty() {
        let blob = encrypt_chromium_password("").unwrap();
        assert_eq!(&blob[..3], b"v10");
        // Empty plaintext + PKCS7 padding = one full block
        assert_eq!(blob.len(), 3 + 16);
    }

    #[test]
    fn test_populate_login_data_noop() {
        let dir = std::env::temp_dir().join("persea-test-login-data");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let creds = vec![(
            "https://example.com".into(),
            "alice".into(),
            "secret".into(),
        )];
        populate_login_data(&dir, &creds).unwrap();

        // VDI sessions are ephemeral — Login Data must NOT be created
        let db_path = dir.join("Default/Login Data");
        assert!(
            !db_path.exists(),
            "Login Data SQLite should not be created for VDI sessions"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_range_allocator() {
        let alloc = RangeAllocator::new(100, 102);
        let a = alloc.allocate().unwrap();
        let b = alloc.allocate().unwrap();
        let c = alloc.allocate().unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        // Pool exhausted
        assert!(alloc.allocate().is_none());
        // Release one and re-allocate
        alloc.release(b);
        let d = alloc.allocate().unwrap();
        assert_eq!(d, b);
    }

    #[test]
    fn test_host_rules_default_deny_blocks_metadata() {
        let rules = build_host_rules(None);
        assert!(rules.contains("MAP * ~NOTFOUND"));
        assert!(rules.contains("MAP localhost ~NOTFOUND"));
        assert!(rules.contains("MAP 127.0.0.1 ~NOTFOUND"));
        assert!(rules.contains("MAP 169.254.* ~NOTFOUND"));
        // No EXCLUDE entries without an allowlist: everything stays blocked
        assert!(!rules.contains("EXCLUDE"));
    }

    #[test]
    fn test_host_rules_excludes_only_allowed_domains() {
        let domains: Vec<String> = vec!["app.example.com".into(), "*.wiki.example.com".into()];
        let rules = build_host_rules(Some(&domains));
        assert!(rules.contains("EXCLUDE app.example.com"));
        assert!(rules.contains("EXCLUDE *.app.example.com"));
        assert!(rules.contains("EXCLUDE *.wiki.example.com"));
        // Blocked names are never excluded
        assert!(!rules.contains("EXCLUDE localhost"));
        assert!(!rules.contains("EXCLUDE 127.0.0.1"));
        assert!(!rules.contains("EXCLUDE 169.254.169.254"));
        // Explicit MAP entries are always present
        assert!(rules.contains("MAP localhost ~NOTFOUND"));
        assert!(rules.contains("MAP 127.0.0.1 ~NOTFOUND"));
        assert!(rules.contains("MAP 169.254.* ~NOTFOUND"));
    }

    #[test]
    fn test_host_rules_allowlist_cannot_unblock_metadata() {
        let domains: Vec<String> = vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "169.254.169.254".into(),
            "169.254.*".into(),
            "example.com".into(),
        ];
        let rules = build_host_rules(Some(&domains));
        assert!(!rules.contains("EXCLUDE localhost"));
        assert!(!rules.contains("EXCLUDE 127.0.0.1"));
        assert!(!rules.contains("EXCLUDE 169.254"));
        assert!(!rules.contains("EXCLUDE *.169.254"));
        assert!(rules.contains("EXCLUDE example.com"));
        assert!(rules.contains("EXCLUDE *.example.com"));
    }

    #[test]
    fn test_host_rules_link_local_suffix_hostname_stays_allowable() {
        let domains: Vec<String> = vec!["foo.169.254.169.254".into()];
        let rules = build_host_rules(Some(&domains));
        assert!(rules.contains("EXCLUDE foo.169.254.169.254"));
    }

    #[test]
    fn test_is_always_blocked() {
        assert!(is_always_blocked("localhost"));
        assert!(is_always_blocked("foo.localhost"));
        assert!(is_always_blocked("127.0.0.1"));
        assert!(is_always_blocked("169.254.169.254"));
        assert!(is_always_blocked("169.254.0.1"));
        assert!(is_always_blocked("169.254.*"));
        assert!(is_always_blocked(" 169.254.5.5 "));
        assert!(!is_always_blocked("example.com"));
        assert!(!is_always_blocked("169.2540.1"));
        assert!(!is_always_blocked("foo.169.254.169.254"));
    }

    #[test]
    fn test_truncate_for_log() {
        assert_eq!(truncate_for_log(b"hello"), "hello");
        assert_eq!(truncate_for_log(b"  padded  "), "padded");
        let long = vec![b'a'; 500];
        let snippet = truncate_for_log(&long);
        assert_eq!(snippet.len(), 200 + "(...truncated)".len());
        assert!(snippet.ends_with("...(truncated)"));
    }
}
