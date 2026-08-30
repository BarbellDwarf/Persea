use super::types::*;
use crate::browser::BrowserManager;
use crate::config::Config;
use crate::guacd;
use crate::guacd::GuacdStream;
use crate::protocol::Instruction;
use chrono::{DateTime, Utc};
use rand::RngExt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{watch, Mutex, RwLock};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Upper bound on a single guacd interaction (connect, join, or one
/// instruction read). A stalled guacd must never hold up the session map,
/// so every guacd I/O from the manager runs inside this budget. Shared by
/// the reconnect path and session creation so a stalled guacd fails fast
/// everywhere.
pub(crate) const GUACD_IO_TIMEOUT: Duration = Duration::from_secs(15);

/// Map a guacd socket I/O error onto the join error surface.
fn join_io_error(e: std::io::Error) -> SessionError {
    SessionError::GuacdConnection(format!("guacd I/O error: {}", e))
}

/// Manages all active sessions.
pub struct SessionManager {
    /// Live sessions keyed by id. `pub(crate)` so API-layer tests can seed
    /// sessions directly; production code only touches it via the session
    /// module's methods.
    pub(crate) sessions: Arc<RwLock<HashMap<Uuid, Arc<Mutex<Session>>>>>,
    pub(super) config: Config,
    pub(super) browser_manager: Arc<BrowserManager>,
    pub(super) guacd_tls: Option<TlsConnector>,
    pub(super) db: Option<crate::db::Db>,
    pub(super) vdi_driver: Option<Arc<dyn crate::vdi::VdiDriver>>,
    /// Set to `true` when a shutdown signal is received. Prevents new session
    /// creation while allowing existing sessions to drain gracefully.
    pub(super) shutdown: Arc<AtomicBool>,
    /// Effective recording directory, resolved once at construction.
    ///
    /// `Config` is immutable after `SessionManager::new` (it is moved into the
    /// manager and never mutated), so caching the resolution here keeps
    /// `recording_path()` zero-copy without drifting from `recording_config()`.
    pub(super) recording_dir: std::path::PathBuf,
    /// Notified when `shutdown` flips to `true` so background tasks can exit.
    pub(super) shutdown_notify: Arc<tokio::sync::Notify>,
    /// Session lifecycle event feed (S02): bounded retained log + watch
    /// broadcast backing `GET /api/sessions/events` (SSE + replay).
    pub(super) event_bus: SessionEventBus,
    /// Per-user cap on live SSE event streams (at most one per identity).
    pub(super) sse_subscribers: std::sync::Mutex<HashSet<String>>,
    /// When each session entered a terminal state (completed/error/
    /// expired). Attached to `SessionInfo.ended_at` by list/get and
    /// pruned when the session leaves the map.
    pub(super) ended_at: std::sync::Mutex<HashMap<Uuid, DateTime<Utc>>>,
    /// Sessions whose owner currently holds the guacd stream. The
    /// per-session viewer cap counts viewers only, so the owner's slot is
    /// excluded. Inserted by the owner paths (take/reconnect), removed by
    /// the WebSocket teardown and every terminal transition.
    owner_connected: std::sync::Mutex<HashSet<Uuid>>,
    /// When each session entered `Disconnected`. The cleanup reaper
    /// measures the reconnect window from this timestamp, not from
    /// creation: otherwise any session older than the cleanup delay is
    /// removed the moment it disconnects, with no reconnect window at all.
    disconnected_at: std::sync::Mutex<HashMap<Uuid, DateTime<Utc>>>,
    /// Transient session-scoped login credentials (persea#245): encrypted
    /// login passwords retained per auth session when
    /// `[auth] forward_session_credentials` is enabled. In-memory only,
    /// keyed by the auth-session token hash, TTL-bound to the session,
    /// cleared by logout/expiry/revocation (see `credentials.rs`).
    session_credentials: super::credentials::SessionCredentialStore,
}

/// Bounded retained log + watch broadcast backing the session event feed.
///
/// The log is the source of truth: replay filters it by cursor, and SSE
/// subscribers re-read it on every watch change, so no event is missed or
/// delivered twice even when a publish races a subscriber's read. The
/// watch value (the latest event id) is only a change notification.
pub(super) struct SessionEventBus {
    log: std::sync::Mutex<EventLog>,
    tx: watch::Sender<u64>,
    /// Held so the channel stays open when no subscriber is connected:
    /// `watch` closes (and drops sends) when the last receiver is gone,
    /// which would lose the cursor value between subscribers.
    _rx: watch::Receiver<u64>,
}

/// Retained event window state.
struct EventLog {
    events: VecDeque<SessionEvent>,
    next_id: u64,
}

/// Maximum number of lifecycle events retained for replay / SSE resume.
const SESSION_EVENT_LOG_CAP: usize = 500;

impl SessionEventBus {
    fn new() -> Self {
        let (tx, rx) = watch::channel(0);
        Self {
            log: std::sync::Mutex::new(EventLog {
                events: VecDeque::new(),
                next_id: 1,
            }),
            tx,
            _rx: rx,
        }
    }

    /// Append an event, assign its monotonic cursor, and notify
    /// subscribers. The log is appended before the watch value is bumped,
    /// so a reader that sees the new id always finds the event.
    fn publish(&self, mut event: SessionEvent) {
        let id = {
            let mut log = self.log.lock().unwrap();
            event.id = log.next_id;
            log.next_id += 1;
            log.events.push_back(event);
            while log.events.len() > SESSION_EVENT_LOG_CAP {
                log.events.pop_front();
            }
            log.next_id - 1
        };
        // No subscribers is not an error: the log keeps the event for
        // later replay.
        let _ = self.tx.send(id);
    }
}

impl SessionManager {
    /// Build a manager with an attached database handle (session history,
    /// registry, audit trail).
    pub fn new_with_db(config: Config, guacd_tls: Option<TlsConnector>, db: crate::db::Db) -> Self {
        let mut mgr = Self::new(config, guacd_tls);
        mgr.db = Some(db);
        mgr
    }

    /// Enterprise HA is active when a shared backend pool is installed.
    /// Without one, every HA code path stays inert and behavior is
    /// byte-for-byte single-instance.
    pub fn ha_enabled(&self) -> bool {
        crate::db::active_pool().is_some()
    }

    /// This instance's stable identifier (registry owner tag).
    pub fn instance_id(&self) -> &str {
        &self.config.instance_id
    }

    /// This instance's public base URL, if configured (cross-instance
    /// join/shadow redirect target).
    pub fn owner_base_url(&self) -> Option<&str> {
        self.config.ha_base_url.as_deref()
    }

    // ── Registry persistence (enterprise HA) ────────────────────────────────────
    //
    // All writes are gated on `ha_enabled()` (shared backend pool); the
    // store functions also no-op without a pool, so single-instance mode
    // is unchanged.

    fn registry_set_status(&self, id: Uuid, status: &str) {
        // Without a shared backend this is a no-op — single-instance
        // behavior unchanged, byte-for-byte.
        if !self.ha_enabled() {
            return;
        }
        let Some(ref db) = self.db else { return };
        let now = crate::db::registry_ts(Utc::now());
        if let Err(e) = crate::db::registry_set_status(db, &id.to_string(), status, &now) {
            tracing::warn!(session_id = %id, error = %e, "Failed to update session registry status");
        }
    }

    /// Build a manager: creates the recording directory with restrictive
    /// permissions, initializes the browser manager, and wires up the VDI
    /// driver when enabled in config.
    pub fn new(config: Config, guacd_tls: Option<TlsConnector>) -> Self {
        // Ensure recording directory exists with restrictive permissions
        let recording_dir = config.effective_recording_path().into_owned();
        if let Err(e) = std::fs::create_dir_all(&recording_dir) {
            tracing::warn!("Failed to create recording directory: {}", e);
        } else {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(
                    &recording_dir,
                    std::fs::Permissions::from_mode(0o750),
                );
            }
        }

        let browser_manager = Arc::new(BrowserManager::new(
            config.xvnc_path.clone(),
            config.chromium_path.clone(),
            config.display_range_start,
            config.display_range_end,
            config.cdp_port_range_start,
            config.cdp_port_range_end,
            std::path::PathBuf::from(&config.login_scripts_dir),
            config.login_script_timeout_secs,
        ));

        let vdi_driver = Self::init_vdi_driver(&config);

        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            config,
            browser_manager,
            guacd_tls,
            db: None,
            vdi_driver,
            shutdown: Arc::new(AtomicBool::new(false)),
            recording_dir,
            shutdown_notify: Arc::new(tokio::sync::Notify::new()),
            event_bus: SessionEventBus::new(),
            sse_subscribers: std::sync::Mutex::new(HashSet::new()),
            ended_at: std::sync::Mutex::new(HashMap::new()),
            owner_connected: std::sync::Mutex::new(HashSet::new()),
            disconnected_at: std::sync::Mutex::new(HashMap::new()),
            session_credentials: super::credentials::SessionCredentialStore::new(),
        }
    }

    fn init_vdi_driver(config: &Config) -> Option<Arc<dyn crate::vdi::VdiDriver>> {
        // Runtime feature guard (not compile-out): Docker-desktop VDI is
        // deliberately unsupported on Windows — the driver is never
        // initialised and VDI session creation fails with a clear error.
        #[cfg(windows)]
        {
            if config.vdi.as_ref().map(|v| v.enabled).unwrap_or(false) {
                tracing::warn!(
                    "VDI (Docker containers) is not supported on Windows — \
                     VDI desktops will be unavailable; run persea on Linux for VDI"
                );
            }
            return None;
        }
        // On Windows the guard above returns, so the rest of the function is
        // unreachable — by design (runtime guard, not compile-out).
        #[allow(unreachable_code)]
        let vdi_cfg = config.vdi.as_ref()?;
        if !vdi_cfg.enabled {
            return None;
        }
        match crate::vdi::DockerDriver::new(&vdi_cfg.docker_socket) {
            Ok(driver) => {
                let mut driver = driver
                    .with_ready_timeout(vdi_cfg.ready_timeout_secs)
                    .with_container_hook(
                        vdi_cfg.container_hook_script.clone(),
                        vdi_cfg.container_hook_timeout_secs,
                    );
                match (vdi_cfg.port_range_start, vdi_cfg.port_range_end) {
                    (Some(start), Some(end)) => {
                        driver = match driver.with_host_port_range(start, end) {
                            Ok(driver) => driver,
                            Err(e) => {
                                tracing::error!("Failed to initialize VDI Docker driver: {}", e);
                                return None;
                            }
                        };
                    }
                    (None, None) => {}
                    _ => {
                        tracing::error!(
                            "Failed to initialize VDI Docker driver: port_range_start and port_range_end must be set together"
                        );
                        return None;
                    }
                }
                tracing::info!(
                    socket = %vdi_cfg.docker_socket,
                    idle_timeout_mins = vdi_cfg.idle_timeout_mins,
                    port_range_start = ?vdi_cfg.port_range_start,
                    port_range_end = ?vdi_cfg.port_range_end,
                    container_hook_script = ?vdi_cfg.container_hook_script,
                    "VDI Docker driver initialized"
                );
                Some(Arc::new(driver))
            }
            Err(e) => {
                tracing::error!("Failed to initialize VDI Docker driver: {}", e);
                None
            }
        }
    }

    /// Get the VDI driver (if enabled).
    pub fn vdi_driver(&self) -> Option<&dyn crate::vdi::VdiDriver> {
        self.vdi_driver.as_deref()
    }

    /// Read-only access to the config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Access to the database (if initialized).
    pub fn db(&self) -> Option<&crate::db::Db> {
        self.db.as_ref()
    }

    /// Terminal statuses: sessions that can no longer be joined. Remote
    /// (registry-only) sessions in these states are hidden from list/get —
    /// the row lives on only so the owning instance can rotate the
    /// recording file; the stale sweep removes it within 24h.
    fn row_is_live(row: &crate::db::SessionRegistryRow) -> bool {
        !matches!(row.status.as_str(), "completed" | "error" | "expired")
    }

    /// List all sessions: the local map plus (when enterprise HA is active)
    /// registry rows for live sessions owned by other instances. Registry-only
    /// sessions are marked `remote` with their owner instance.
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();
        for session in sessions.values() {
            let session = session.lock().await;
            let mut info = session.info();
            info.ended_at = self.ended_at.lock().unwrap().get(&info.session_id).copied();
            result.push(info);
        }
        drop(sessions);

        if self.ha_enabled() {
            if let Some(ref db) = self.db {
                let local_ids: std::collections::HashSet<String> =
                    result.iter().map(|s| s.session_id.to_string()).collect();
                match crate::db::registry_list_sessions(db) {
                    Ok(rows) => {
                        for row in rows {
                            if local_ids.contains(&row.session_id) {
                                continue;
                            }
                            if !Self::row_is_live(&row) {
                                continue;
                            }
                            if let Some(info) = SessionInfo::from_registry(&row) {
                                result.push(info);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to list session registry rows");
                    }
                }
            }
        }
        result
    }

    /// Count live sessions: the number of in-memory sessions whose
    /// status is Active, Pending, or Disconnected (the frontend's "live"
    /// bucket — disconnected sessions are still within the reconnect
    /// window). Remote HA registry sessions are included when a shared
    /// backend pool is active.
    ///
    /// This is the single source of truth for "active session count"
    /// across the API, admin, and reports surfaces, replacing the
    /// DB-zombie-prone `SELECT COUNT(*) WHERE status='active'` that
    /// counts rows whose status never gets cleared by crashed processes
    /// (persea#273).
    pub async fn active_session_count(&self) -> usize {
        self.list_sessions()
            .await
            .iter()
            .filter(|s| {
                matches!(
                    s.status,
                    SessionStatus::Active | SessionStatus::Pending | SessionStatus::Disconnected
                )
            })
            .count()
    }

    /// Get a specific session's info: local map first, then the shared
    /// registry (remote sessions, enterprise HA only). Terminal remote
    /// sessions are reported as absent (nothing joinable remains).
    pub async fn get_session(&self, id: Uuid) -> Option<SessionInfo> {
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&id) {
                let session = session.lock().await;
                let mut info = session.info();
                info.ended_at = self.ended_at.lock().unwrap().get(&id).copied();
                return Some(info);
            }
        }
        if self.ha_enabled() {
            if let Some(ref db) = self.db {
                if let Ok(Some(row)) = crate::db::registry_get_session(db, &id.to_string()) {
                    if !Self::row_is_live(&row) {
                        return None;
                    }
                    return SessionInfo::from_registry(&row);
                }
            }
        }
        None
    }

    /// Take the guacd stream from a session (for the owner/first WebSocket connection).
    /// Transitions the session to Active. Returns the stream and a cancellation token.
    /// For deferred connections (ephemeral keypair), connects to guacd here.
    ///
    /// The deferred connect runs OUTSIDE the session locks and inside
    /// [`GUACD_IO_TIMEOUT`]: a stalled guacd must not hold up the session
    /// map, and a concurrent caller must not block on this one. The
    /// deferred params are restored after the connect so a later reconnect
    /// can re-establish the connection (each owner connection gets a fresh
    /// guacd session to the target).
    pub async fn take_guacd_stream(&self, id: Uuid) -> Option<(GuacdStream, CancellationToken)> {
        // Phase 1: check status and take the deferred params, then drop
        // every lock before any guacd I/O.
        let deferred = {
            let sessions = self.sessions.read().await;
            let session_arc = sessions.get(&id)?;
            let mut session = session_arc.lock().await;
            if session.status != SessionStatus::Pending {
                return None;
            }
            session.deferred_params.take()
        };

        // Phase 2: deferred connect, no locks held, bounded.
        let connected = match &deferred {
            Some(params) => {
                tracing::info!(session_id = %id, "Establishing deferred guacd connection");
                match tokio::time::timeout(
                    GUACD_IO_TIMEOUT,
                    guacd::connect_and_handshake(
                        &self.config.guacd_addr,
                        params,
                        self.guacd_tls.as_ref(),
                    ),
                )
                .await
                {
                    Ok(Ok((stream, connection_id))) => {
                        tracing::info!(
                            session_id = %id,
                            connection_id = %connection_id,
                            "Deferred guacd connection established"
                        );
                        Some((stream, connection_id))
                    }
                    Ok(Err(e)) => {
                        tracing::error!(session_id = %id, error = %e, "Deferred guacd connection failed");
                        self.mark_connect_failed(id, SessionStatus::Pending).await;
                        return None;
                    }
                    Err(_) => {
                        tracing::error!(session_id = %id, "Deferred guacd connection timed out");
                        self.mark_connect_failed(id, SessionStatus::Pending).await;
                        return None;
                    }
                }
            }
            None => None,
        };

        // Phase 3: re-acquire, install the stream, transition.
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&id)?;
        let mut session = session_arc.lock().await;
        if session.status != SessionStatus::Pending {
            return None;
        }
        if let Some((stream, connection_id)) = connected {
            session.guacd_stream = Some(stream);
            session.connection_id = connection_id;
        }
        // Restore the params: ephemeral-keypair sessions reconnect with a
        // fresh guacd connection to the target, so the params must survive
        // the first connect.
        session.deferred_params = deferred;
        let stream = session.guacd_stream.take()?;
        let cancel = session.cancel.clone();
        session.status = SessionStatus::Active;
        self.publish_transition(&SessionStatus::Pending, &session);
        session.active_connections += 1;
        crate::metrics::session_active_inc();
        tracing::info!(session_id = %id, "Session now active (owner connected)");
        drop(session);
        drop(sessions);
        self.mark_owner_connected(id);
        self.registry_set_status(id, "active");
        Some((stream, cancel))
    }

    /// Mark a session `Error` after a deferred connect failed, but only if
    /// it is still in `from`: the session may have moved on (or been
    /// removed) while the connect was in flight.
    async fn mark_connect_failed(&self, id: Uuid, from: SessionStatus) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == from {
                session.status = SessionStatus::Error;
                self.publish_transition(&from, &session);
            }
        }
    }

    /// Record that the session's owner holds the guacd stream (the viewer
    /// cap counts viewers only).
    pub(crate) fn mark_owner_connected(&self, id: Uuid) {
        self.owner_connected.lock().unwrap().insert(id);
    }

    /// Record that the session's owner connection ended.
    pub(crate) fn mark_owner_disconnected(&self, id: Uuid) {
        self.owner_connected.lock().unwrap().remove(&id);
    }

    /// Whether the session's owner currently holds the guacd stream.
    pub(crate) fn owner_is_connected(&self, id: Uuid) -> bool {
        self.owner_connected.lock().unwrap().contains(&id)
    }

    /// Atomically reserve a viewer slot for a share/shadow join: counts
    /// viewers only (the owner's connection is excluded) and rejects at
    /// the configured cap. The reservation IS the increment, so two
    /// concurrent joins cannot both pass the check. Callers release the
    /// slot with `disconnect_viewer` when the join fails.
    pub(crate) async fn reserve_viewer_slot(
        &self,
        id: Uuid,
        max_viewers: u32,
    ) -> Result<(), SessionError> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id).ok_or(SessionError::NotFound)?;
        let mut session = session.lock().await;
        if session.status != SessionStatus::Active {
            return Err(SessionError::NotActive);
        }
        let viewers = session
            .active_connections
            .saturating_sub(if self.owner_is_connected(id) { 1 } else { 0 });
        if max_viewers > 0 && viewers >= max_viewers {
            return Err(SessionError::ViewerLimit {
                viewers,
                max: max_viewers,
            });
        }
        session.active_connections += 1;
        Ok(())
    }

    /// Join an active session as a viewer (share token or shadow token
    /// holder). Reserves the viewer slot atomically against the cap before
    /// connecting, so concurrent joins cannot exceed `max_viewers` (0 =
    /// unlimited). `read_only` joins (shadow tokens) tell guacd to reject
    /// the user's input. The guacd join is bounded by [`GUACD_IO_TIMEOUT`]
    /// and runs without any session locks held.
    pub async fn join_session_as_viewer(
        &self,
        id: Uuid,
        max_viewers: u32,
        read_only: bool,
    ) -> Result<(GuacdStream, CancellationToken), SessionError> {
        self.reserve_viewer_slot(id, max_viewers).await?;

        let (connection_id, width, height, cancel) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or(SessionError::NotFound)?;
            let session = session.lock().await;
            (
                session.connection_id.clone(),
                session.width,
                session.height,
                session.cancel.clone(),
            )
        };

        let stream = match self
            .join_connection(&connection_id, width, height, 96, read_only)
            .await
        {
            Ok(stream) => stream,
            Err(e) => {
                // Release the reserved slot: no proxy will run to release
                // it at teardown.
                tracing::error!(session_id = %id, error = %e, "Failed to join guacd session");
                self.disconnect_viewer(id).await;
                return Err(e);
            }
        };

        tracing::info!(session_id = %id, read_only = read_only, "Viewer joined session");
        Ok((stream, cancel))
    }

    /// Open a second guacd connection to an existing session (join).
    ///
    /// Mirrors `guacd::join_connection` (same wire sequence) but lets the
    /// caller choose the `read-only` connect arg, which guacd uses to
    /// reject input for that user. Shadow (view-only) joins pass `true`;
    /// share-token joins do not. Every read is bounded by
    /// [`GUACD_IO_TIMEOUT`] so a stalled guacd cannot hang the session map.
    async fn join_connection(
        &self,
        connection_id: &str,
        width: u32,
        height: u32,
        dpi: u32,
        read_only: bool,
    ) -> Result<GuacdStream, SessionError> {
        let tcp = tokio::time::timeout(
            GUACD_IO_TIMEOUT,
            TcpStream::connect(&self.config.guacd_addr),
        )
        .await
        .map_err(|_| {
            SessionError::GuacdConnection(format!(
                "timeout connecting to guacd at {}",
                self.config.guacd_addr
            ))
        })?
        .map_err(|e| {
            SessionError::GuacdConnection(format!(
                "failed to connect to guacd at {}: {}",
                self.config.guacd_addr, e
            ))
        })?;

        // Same socket tuning as `guacd::apply_keepalive`.
        {
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10))
                .with_retries(3);
            let sock = socket2::SockRef::from(&tcp);
            let _ = sock.set_tcp_keepalive(&keepalive);
            let _ = sock.set_tcp_nodelay(true);
        }

        let mut stream: GuacdStream = if let Some(connector) = self.guacd_tls.as_ref() {
            let hostname = self
                .config
                .guacd_addr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(&self.config.guacd_addr);
            let server_name =
                tokio_rustls::rustls::pki_types::ServerName::try_from(hostname.to_string())
                    .map_err(|e| {
                        SessionError::GuacdConnection(format!(
                            "invalid TLS server name '{}': {}",
                            hostname, e
                        ))
                    })?
                    .to_owned();
            Box::new(connector.connect(server_name, tcp).await.map_err(|e| {
                SessionError::GuacdConnection(format!("TLS handshake with guacd failed: {}", e))
            })?)
        } else {
            Box::new(tcp)
        };

        let select = Instruction::new("select", vec![connection_id.into()]);
        stream
            .write_all(select.encode().as_bytes())
            .await
            .map_err(join_io_error)?;

        let args_instruction = Self::read_guacd_instruction(&mut stream).await?;
        if args_instruction.opcode != "args" {
            return Err(SessionError::GuacdConnection(format!(
                "expected 'args' from join, got '{}'",
                args_instruction.opcode
            )));
        }

        // The connection is already configured; only the per-user
        // read-only flag is meaningful (shared mapping with
        // `guacd::join_connection`).
        let arg_values = guacd::join_arg_values(&args_instruction.args, read_only);

        Self::send_join_handshake(&mut stream, width, height, dpi).await?;

        let connect = Instruction::new("connect", arg_values);
        stream
            .write_all(connect.encode().as_bytes())
            .await
            .map_err(join_io_error)?;

        let ready = Self::read_guacd_instruction(&mut stream).await?;
        if ready.opcode != "ready" {
            return Err(SessionError::GuacdConnection(format!(
                "expected 'ready' from join, got '{}' (args: {:?})",
                ready.opcode, ready.args
            )));
        }

        tracing::info!(
            connection_id = %connection_id,
            read_only = read_only,
            "Joined existing connection"
        );
        Ok(stream)
    }

    /// Read one complete instruction from a guacd stream, bounded by
    /// [`GUACD_IO_TIMEOUT`] per read.
    async fn read_guacd_instruction(
        stream: &mut (impl AsyncRead + Unpin),
    ) -> Result<Instruction, SessionError> {
        let mut parser = crate::protocol::InstructionParser::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(GUACD_IO_TIMEOUT, stream.read(&mut buf))
                .await
                .map_err(|_| {
                    SessionError::GuacdConnection(
                        "timed out waiting for an instruction from guacd".into(),
                    )
                })?
                .map_err(join_io_error)?;
            if n == 0 {
                return Err(SessionError::GuacdConnection(
                    "guacd closed the connection".into(),
                ));
            }
            let data = std::str::from_utf8(&buf[..n]).map_err(|e| {
                SessionError::GuacdConnection(format!("invalid UTF-8 from guacd: {}", e))
            })?;
            let results = parser.receive(data);
            if let Some(result) = results.into_iter().next() {
                return result.map_err(|e| SessionError::GuacdConnection(e.to_string()));
            }
        }
    }

    /// Send the common join handshake instructions (size, audio, video,
    /// image, timezone): the same wire sequence `guacd::send_handshake`
    /// emits for joins (no H.264).
    async fn send_join_handshake(
        stream: &mut (impl AsyncWrite + Unpin),
        width: u32,
        height: u32,
        dpi: u32,
    ) -> Result<(), SessionError> {
        let instructions = [
            Instruction::new(
                "size",
                vec![width.to_string(), height.to_string(), dpi.to_string()],
            ),
            Instruction::new("audio", vec!["audio/L16".into(), "audio/L8".into()]),
            Instruction::new("video", Vec::new()),
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
                .map_err(join_io_error)?;
        }
        Ok(())
    }

    /// Validate a share-or-shadow token for a session (constant-time
    /// comparison). Returns which kind of token matched so callers can
    /// audit shadow uses; returns `Invalid` if neither matches or the
    /// session is unknown.
    ///
    /// Enterprise HA: when the session is not local (registry-only),
    /// the in-memory check cannot match — the registry row carries the
    /// admin-minted shadow token instead (see `mint_remote_shadow_token`),
    /// so shadowing works from any instance.
    pub async fn validate_share_token(&self, id: Uuid, token: &str) -> ShareTokenValidation {
        {
            let sessions = self.sessions.read().await;
            if let Some(session) = sessions.get(&id) {
                let session = session.lock().await;
                let v = super::check_share_token_match(
                    &session.share_token,
                    &session.shadow_tokens,
                    token,
                    Utc::now(),
                );
                if v != ShareTokenValidation::Invalid {
                    return v;
                }
            }
        }
        if self.ha_enabled() {
            if let Some(ref db) = self.db {
                if let Ok(Some(row)) = crate::db::registry_get_session(db, &id.to_string()) {
                    let (Some(hash), Some(issued_by), Some(expires_at)) = (
                        row.shadow_token_hash,
                        row.shadow_issued_by,
                        row.shadow_expires_at,
                    ) else {
                        return ShareTokenValidation::Invalid;
                    };
                    // Expiry check first (fail closed on unparseable values).
                    let expires =
                        chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%d %H:%M:%S")
                            .map(|ndt| ndt.and_utc());
                    match expires {
                        Ok(exp) if exp <= Utc::now() => return ShareTokenValidation::Invalid,
                        Err(_) => return ShareTokenValidation::Invalid,
                        _ => {}
                    }
                    use sha2::{Digest, Sha256};
                    use subtle::ConstantTimeEq;
                    let provided_hex = hex::encode(Sha256::digest(token.as_bytes()));
                    if hash.len() == provided_hex.len()
                        && hash.as_bytes().ct_eq(provided_hex.as_bytes()).into()
                    {
                        return ShareTokenValidation::Shadow { issued_by };
                    }
                }
            }
        }
        ShareTokenValidation::Invalid
    }

    /// Mint a shadow token for a session hosted by ANOTHER instance: the
    /// hash + issuer + expiry are written to the shared registry row
    /// instead of a local in-memory session, so the owning instance (and
    /// any other) can validate it. Returns the raw token and its expiry.
    pub async fn mint_remote_shadow_token(
        &self,
        id: Uuid,
        issued_by: &str,
    ) -> Option<(String, DateTime<Utc>)> {
        use sha2::{Digest, Sha256};
        let db = self.db.as_ref()?;

        let mut rng = rand::rng();
        let bytes: [u8; 16] = rng.random();
        let raw = hex::encode(bytes);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let expires_at = Utc::now() + chrono::Duration::minutes(10);
        let expires_str = crate::db::registry_ts(expires_at);
        if let Err(e) = crate::db::registry_set_shadow_token(
            db,
            &id.to_string(),
            &hash,
            issued_by,
            &expires_str,
        ) {
            tracing::warn!(session_id = %id, error = %e, "Failed to persist remote shadow token");
            return None;
        }
        Some((raw, expires_at))
    }

    /// Delete registry rows that can no longer be live:
    /// - rows still `pending` past `max(pending_timeout × 2, 60s)` — the
    ///   owner's pending-timeout task would have marked them `expired`;
    /// - rows in a terminal status past 24h — kept so the owning instance's
    ///   recording rotation can still attribute the recording file;
    /// - live rows owned by OTHER instances past `max_duration + 2h` (their
    ///   owner must be dead — a live owner would have reaped the session at
    ///   max duration). Disabled when max_duration is 0 (unlimited): no age
    ///   proves death.
    pub fn registry_sweep_stale(&self) -> usize {
        if !self.ha_enabled() {
            return 0;
        }
        let Some(ref db) = self.db else { return 0 };
        let now = Utc::now();
        let pending_cutoff_secs = (self.config.session_pending_timeout_secs * 2).max(60);
        let pending_cutoff =
            crate::db::registry_ts(now - chrono::Duration::seconds(pending_cutoff_secs as i64));
        let terminal_cutoff = crate::db::registry_ts(now - chrono::Duration::hours(24));
        let live_cutoff = if self.config.session_max_duration_secs > 0 {
            Some(crate::db::registry_ts(
                now - chrono::Duration::seconds(
                    self.config.session_max_duration_secs as i64 + 7200,
                ),
            ))
        } else {
            None
        };
        match crate::db::registry_delete_stale(
            db,
            &self.config.instance_id,
            &pending_cutoff,
            &terminal_cutoff,
            live_cutoff.as_deref(),
        ) {
            Ok(n) => {
                if n > 0 {
                    tracing::info!(deleted = n, "Reaped stale session registry rows");
                }
                n
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to sweep stale session registry rows");
                0
            }
        }
    }

    /// Remove every registry row owned by this instance. Kept as an
    /// operational tool (e.g. a deliberately retired instance clearing its
    /// rows); NOT called on graceful shutdown — rows are left in terminal
    /// state so recording rotation can still attribute the files, and the
    /// stale sweep bounds their lifetime.
    pub fn registry_delete_all_owned(&self) -> usize {
        if !self.ha_enabled() {
            return 0;
        }
        let Some(ref db) = self.db else { return 0 };
        match crate::db::registry_delete_all_owned(db, &self.config.instance_id) {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to clear own session registry rows");
                0
            }
        }
    }

    // ── Transient session credentials (persea#245) ─────────────────────────────
    //
    // Retained login passwords live in memory on the manager, keyed by the
    // auth-session token hash, and are handed back only to the owning
    // session. See `credentials.rs` for the storage and security notes.

    /// Store an encrypted login credential for an auth session. Called by
    /// the password login handler when `[auth] forward_session_credentials`
    /// is enabled; `password_enc` must already be encrypted with the
    /// storage encryption key. `session_token` is the raw `persea_session`
    /// cookie value — only its SHA-256 hash is kept as the map key.
    /// `ttl_secs` bounds the entry to the session lifetime. Replaces any
    /// previous entry for the session.
    pub fn store_session_credentials(
        &self,
        session_token: &str,
        user_id: i64,
        username: &str,
        password_enc: String,
        ttl_secs: u64,
    ) {
        self.session_credentials.prune_expired();
        self.session_credentials.store(
            session_token,
            super::credentials::RetainedSessionCredential {
                user_id,
                username: username.to_string(),
                password_enc,
                expires_at: Utc::now() + chrono::Duration::seconds(ttl_secs as i64),
            },
        );
    }

    /// Owning-session lookup: the retained credential for `session_token`,
    /// only when it exists, is unexpired, and belongs to `user_id`. Any
    /// other outcome is `None` (fail closed). Returns ciphertext only; the
    /// connect flow decrypts it with the storage key.
    pub fn session_credentials(
        &self,
        session_token: &str,
        user_id: i64,
    ) -> Option<super::credentials::RetainedSessionCredential> {
        self.session_credentials.get(session_token, user_id)
    }

    /// Remove the retained credential for a session (logout/revocation
    /// paths). Returns true when an entry was removed.
    pub fn clear_session_credentials(&self, session_token: &str) -> bool {
        self.session_credentials.remove(session_token)
    }

    /// Drop retained credentials that can no longer be used: entries past
    /// their TTL, and entries whose `auth_sessions` row is gone (logout,
    /// admin revocation, or DB-side session expiry). Runs from the
    /// periodic cleanup reaper, so dead ciphertext leaves memory within
    /// one cleanup cycle. The connect-time lookup is separately fail-closed
    /// through the auth middleware: a logged-out or revoked session cookie
    /// never authenticates, so a stale entry can never be retrieved.
    pub async fn prune_session_credentials(&self) {
        self.session_credentials.prune_expired();
        let Some(db) = self.db.clone() else { return };
        let hashes = self.session_credentials.keys();
        if hashes.is_empty() {
            return;
        }
        let db_for_check = db.clone();
        let hashes_for_check = hashes.clone();
        let live: HashSet<String> = tokio::task::spawn_blocking(move || {
            hashes_for_check
                .iter()
                .filter(|h| crate::db::auth_session_is_live(&db_for_check, h).unwrap_or(false))
                .cloned()
                .collect()
        })
        .await
        .unwrap_or_default();
        for key in &hashes {
            if !live.contains(key) {
                self.session_credentials.remove_key(key);
            }
        }
    }

    /// Number of retained session credentials (test/diagnostic helper).
    pub fn session_credentials_len(&self) -> usize {
        self.session_credentials.len()
    }

    /// Mint a new short-lived (10 min) shadow token for a session.
    /// Returns the raw token (hand to admin once) and its expiry.
    /// Expired tokens on the session are pruned on mint.
    pub async fn mint_shadow_token(
        &self,
        id: Uuid,
        issued_by: &str,
    ) -> Option<(String, DateTime<Utc>)> {
        use sha2::{Digest, Sha256};
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let mut session = session.lock().await;

        let now = Utc::now();
        session.shadow_tokens.retain(|t| t.expires_at > now);

        let mut rng = rand::rng();
        let bytes: [u8; 16] = rng.random();
        let raw = hex::encode(bytes);
        let hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let expires_at = now + chrono::Duration::minutes(10);
        session.shadow_tokens.push(ShadowToken {
            token_hash: hash,
            issued_by: issued_by.to_string(),
            expires_at,
        });
        Some((raw, expires_at))
    }

    /// Decrement active connection count when a WebSocket disconnects.
    pub async fn disconnect_viewer(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            session.active_connections = session.active_connections.saturating_sub(1);
        }
    }

    /// Mark a session as completed (terminal — cannot be reconnected).
    pub async fn complete_session(&self, id: Uuid) {
        let mut did_transition = false;
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active
                || session.status == SessionStatus::Disconnected
            {
                let old_status = session.status.clone();
                session.status = SessionStatus::Completed;
                self.publish_transition(&old_status, &session);
                did_transition = true;
                crate::metrics::session_active_dec();
                let (c, r) = super::drive_cleanup_settings(&self.config.drive);
                super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
                tracing::info!(session_id = %id, "Session completed");
            }
        }
        drop(sessions);
        if did_transition {
            self.mark_owner_disconnected(id);
            self.registry_set_status(id, "completed");
        }
    }

    /// Mark a session as disconnected — the browser closed the WebSocket but the
    /// session remains in the manager and can be reconnected.
    pub async fn disconnect_session(&self, id: Uuid) {
        let mut did_transition = false;
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active {
                let old_status = session.status.clone();
                session.status = SessionStatus::Disconnected;
                self.publish_transition(&old_status, &session);
                did_transition = true;
                session.guacd_stream = None;
                crate::metrics::session_active_dec();
                let (c, r) = super::drive_cleanup_settings(&self.config.drive);
                super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
                tracing::info!(session_id = %id, "Session disconnected (reconnectable)");
            }
        }
        drop(sessions);
        if did_transition {
            // The reconnect window starts at the disconnect, not at
            // creation: the cleanup reaper measures from this timestamp.
            self.disconnected_at.lock().unwrap().insert(id, Utc::now());
            self.mark_owner_disconnected(id);
            self.registry_set_status(id, "disconnected");
        }
    }

    /// Attempt to reconnect an owner to a disconnected session. Returns the
    /// guacd stream and cancellation token if the session has reconnect data.
    ///
    /// Like `take_guacd_stream`, the deferred connect runs outside the
    /// session locks and inside [`GUACD_IO_TIMEOUT`], and the params are
    /// restored so repeated reconnects keep working.
    pub async fn reconnect_session(&self, id: Uuid) -> Option<(GuacdStream, CancellationToken)> {
        let deferred = {
            let sessions = self.sessions.read().await;
            let session_arc = sessions.get(&id)?;
            let mut session = session_arc.lock().await;
            if session.status != SessionStatus::Disconnected {
                return None;
            }
            session.deferred_params.take()
        };

        let connected = match &deferred {
            Some(params) => {
                tracing::info!(session_id = %id, "Re-establishing deferred guacd connection for reconnect");
                match tokio::time::timeout(
                    GUACD_IO_TIMEOUT,
                    guacd::connect_and_handshake(
                        &self.config.guacd_addr,
                        params,
                        self.guacd_tls.as_ref(),
                    ),
                )
                .await
                {
                    Ok(Ok((stream, connection_id))) => {
                        tracing::info!(
                            session_id = %id,
                            connection_id = %connection_id,
                            "Deferred guacd connection re-established"
                        );
                        Some((stream, connection_id))
                    }
                    Ok(Err(e)) => {
                        tracing::error!(session_id = %id, error = %e, "Reconnect: deferred guacd connection failed");
                        self.mark_connect_failed(id, SessionStatus::Disconnected)
                            .await;
                        return None;
                    }
                    Err(_) => {
                        tracing::error!(session_id = %id, "Reconnect: deferred guacd connection timed out");
                        self.mark_connect_failed(id, SessionStatus::Disconnected)
                            .await;
                        return None;
                    }
                }
            }
            None => None,
        };

        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&id)?;
        let mut session = session_arc.lock().await;
        if session.status != SessionStatus::Disconnected {
            return None;
        }
        if let Some((stream, connection_id)) = connected {
            session.guacd_stream = Some(stream);
            session.connection_id = connection_id;
        }
        session.deferred_params = deferred;
        let stream = session.guacd_stream.take()?;
        let cancel = session.cancel.clone();
        session.status = SessionStatus::Active;
        self.publish_transition(&SessionStatus::Disconnected, &session);
        session.active_connections += 1;
        crate::metrics::session_active_inc();
        tracing::info!(session_id = %id, "Session reconnected (owner)");
        drop(session);
        drop(sessions);
        self.disconnected_at.lock().unwrap().remove(&id);
        self.mark_owner_connected(id);
        self.registry_set_status(id, "active");
        Some((stream, cancel))
    }

    /// Mark a session as errored.
    pub async fn error_session(&self, id: Uuid) {
        let mut did_transition = false;
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status != SessionStatus::Error {
                let old_status = session.status.clone();
                if old_status == SessionStatus::Active {
                    crate::metrics::session_active_dec();
                }
                session.status = SessionStatus::Error;
                self.publish_transition(&old_status, &session);
                did_transition = true;
                session.guacd_stream = None;
                let (c, r) = super::drive_cleanup_settings(&self.config.drive);
                super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
            }
        }
        drop(sessions);
        if did_transition {
            self.mark_owner_disconnected(id);
            self.registry_set_status(id, "error");
        }
    }

    /// Record session end in history table.
    pub fn end_session_history(&self, id: Uuid, status: &str, duration_secs: u64, recording: bool) {
        if let Some(ref db) = self.db {
            let rec_file = if recording {
                Some(format!("{}.guac", id))
            } else {
                None
            };
            if let Err(e) = crate::db::end_session_history(
                db,
                &id.to_string(),
                status,
                duration_secs,
                rec_file.as_deref(),
            ) {
                tracing::warn!(session_id = %id, error = %e, "Failed to update session history");
            }
        }
    }

    /// Check if a session is in Pending status (owner not yet connected).
    pub async fn is_session_pending(&self, id: Uuid) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            session.status == SessionStatus::Pending
        } else {
            false
        }
    }

    /// Check if a session is in Disconnected status (browser disconnected, reconnection possible).
    pub async fn is_session_disconnected(&self, id: Uuid) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            session.status == SessionStatus::Disconnected
        } else {
            false
        }
    }

    /// Get the creator of a session.
    pub async fn get_session_creator(&self, id: Uuid) -> Option<String> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some(session.created_by.clone())
    }

    /// Get session type and container metadata for a session (used for VDI cleanup).
    pub async fn get_vdi_info(
        &self,
        id: Uuid,
    ) -> Option<(SessionType, Option<String>, Option<String>)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some((
            session.session_type.clone(),
            session.container_id.clone(),
            session.container_name.clone(),
        ))
    }

    /// Stop and remove the VDI container for a session.
    pub async fn stop_vdi_container(&self, id: Uuid) {
        let container_id = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id);
            if let Some(session) = session {
                let mut session = session.lock().await;
                session.container_id.take()
            } else {
                None
            }
        };

        if let Some(cid) = container_id {
            if let Some(ref vdi) = self.vdi_driver {
                tracing::info!(session_id = %id, container_id = %cid, "Stopping VDI container (session ended by server)");
                if let Err(e) = vdi.stop_container(&cid).await {
                    tracing::warn!(container_id = %cid, "Failed to stop VDI container: {}", e);
                }
            }
        }
    }

    /// Terminate a session. Cancels all active proxy connections.
    ///
    /// Teardown contract: cancelling the session's `CancellationToken` is
    /// what actively ends the guacd connection. `proxy_ws_guacd` selects on
    /// the token, and once it fires aborts both I/O tasks so the split
    /// guacd socket is dropped and guacd sees EOF — the remote session
    /// (SSH shell, RDP connection, VNC, …) is actually ended, not just
    /// forgotten. The idle/max-duration reapers funnel through here, so a
    /// reaped session ends its remote session too. Sessions that never
    /// reached the proxy (still `Pending` with a live guacd stream) have
    /// the stream dropped directly below, which closes the socket the same
    /// way.
    pub async fn delete_session(&self, id: Uuid) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(&id) {
            let mut session = session.lock().await;
            let old_status = session.status.clone();
            if old_status == SessionStatus::Active {
                crate::metrics::session_active_dec();
            }
            session.cancel.cancel();
            session.status = SessionStatus::Completed;
            self.publish_transition(&old_status, &session);
            session.guacd_stream = None;
            let (c, r) = super::drive_cleanup_settings(&self.config.drive);
            super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
            tracing::info!(session_id = %id, "Session terminated by API");
            drop(session);
            drop(sessions);
            // The session is gone from the map — drop its terminal
            // timestamp entries (the event feed already carried the event).
            self.ended_at.lock().unwrap().remove(&id);
            self.disconnected_at.lock().unwrap().remove(&id);
            self.mark_owner_disconnected(id);
            // Keep the registry row in a terminal state so the owning
            // instance's recording rotation can still attribute the file;
            // the stale sweep removes the row within 24h.
            self.registry_set_status(id, "completed");
            true
        } else {
            false
        }
    }

    /// Reap active sessions that have exceeded the max duration.
    /// Returns the number of sessions reaped.
    ///
    /// History rows are closed with the terminal "max-duration" status and
    /// the session's real lifetime before the map entry is removed.
    /// `session_max_duration_secs = 0` disables the reaper entirely.
    pub async fn reap_expired_sessions(&self) -> usize {
        if self.config.session_max_duration_secs == 0 {
            return 0;
        }
        let max_duration = std::time::Duration::from_secs(self.config.session_max_duration_secs);
        let now = Utc::now();
        let mut to_delete = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                let session = session.lock().await;
                if session.status == SessionStatus::Active
                    || session.status == SessionStatus::Pending
                {
                    let age = now.signed_duration_since(session.created_at);
                    if age.to_std().unwrap_or_default() > max_duration {
                        to_delete.push((*id, session.created_at, session.recording_enabled));
                    }
                }
            }
        }

        let count = to_delete.len();
        for (id, created_at, recording) in to_delete {
            tracing::warn!(session_id = %id, "Reaping session (exceeded max duration)");
            let duration = now.signed_duration_since(created_at).num_seconds().max(0) as u64;
            self.end_session_history(id, "max-duration", duration, recording);
            self.delete_session(id).await;
        }
        count
    }

    /// Reap sessions idle past the configured idle timeout.
    /// Returns the number of sessions reaped.
    ///
    /// Semantics: `last_activity` is refreshed by client-initiated session
    /// traffic (WebSocket input) only — the client's own tunnel keepalive
    /// pings do NOT count as activity, so a live-but-silent session is
    /// still reaped. `session_idle_timeout_secs = 0` disables idle reaping
    /// (max duration still applies).
    ///
    /// Terminated sessions are recorded in the session history with status
    /// "idle-timeout" (distinguishable from max-duration reaping) and the
    /// session's real lifetime, cancelled, and their in-memory status moves
    /// to the terminal state used by `delete_session`. A
    /// `SessionStatus::IdleTimeout` variant does not exist yet
    /// (src/session/types.rs): when one lands, flip the status
    /// here and in `delete_session` for a live-API-distinguishable label.
    pub async fn reap_idle_sessions(&self) -> usize {
        let idle_timeout = self.config.session_idle_timeout_secs;
        if idle_timeout == 0 {
            return 0;
        }
        let to_delete = self.get_idle_sessions(idle_timeout as i64).await;
        let now = Utc::now();
        for id in &to_delete {
            let (created_at, recording) = {
                let sessions = self.sessions.read().await;
                match sessions.get(id) {
                    Some(session) => {
                        let session = session.lock().await;
                        (session.created_at, session.recording_enabled)
                    }
                    None => continue,
                }
            };
            let duration = now.signed_duration_since(created_at).num_seconds().max(0) as u64;
            self.end_session_history(*id, "idle-timeout", duration, recording);
            tracing::warn!(
                session_id = %id,
                idle_timeout_secs = idle_timeout,
                "Reaping session (idle timeout)"
            );
            self.delete_session(*id).await;
        }
        to_delete.len()
    }

    /// Remove sessions in terminal states (Completed, Error, Expired) that have
    /// been in that state longer than the configured cleanup delay, and
    /// finalize `Disconnected` sessions past the reconnect window. The session
    /// history in SQLite is not affected — this only frees in-memory state.
    ///
    /// Disconnected sessions survive within the documented reconnect window
    /// (`session_cleanup_delay_secs`, measured from the disconnect): the owner
    /// can reconnect until then. Past the window the session gets its terminal
    /// transition (`Disconnected` to `Expired`, publishing `session_ended`), a
    /// history row with the terminal "expired" status and the session's real
    /// lifetime, and its VDI container is stopped: the same lifecycle the
    /// pending-timeout path performs for sessions that never connected.
    pub async fn reap_completed_sessions(&self) -> usize {
        let delay = std::time::Duration::from_secs(self.config.session_cleanup_delay_secs);
        let now = Utc::now();
        let mut to_remove = Vec::new();
        let mut to_finalize = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                let session = session.lock().await;
                match session.status {
                    SessionStatus::Completed | SessionStatus::Error | SessionStatus::Expired => {
                        let age = now.signed_duration_since(session.created_at);
                        if age.to_std().unwrap_or_default() > delay {
                            to_remove.push(*id);
                        }
                    }
                    SessionStatus::Disconnected => {
                        let disconnected_at = self
                            .disconnected_at
                            .lock()
                            .unwrap()
                            .get(id)
                            .copied()
                            .unwrap_or(session.created_at);
                        let age = now.signed_duration_since(disconnected_at);
                        if age.to_std().unwrap_or_default() > delay {
                            to_finalize.push((*id, session.created_at, session.recording_enabled));
                        }
                    }
                    _ => {}
                }
            }
        }

        for (id, created_at, recording) in to_finalize {
            // History first: the row is still open (no terminal status was
            // recorded at disconnect) and must not stay open forever.
            let duration = now.signed_duration_since(created_at).num_seconds().max(0) as u64;
            self.end_session_history(id, "expired", duration, recording);
            // Terminal transition: publishes session_ended with `expired`.
            {
                let sessions = self.sessions.read().await;
                if let Some(session) = sessions.get(&id) {
                    let mut session = session.lock().await;
                    if session.status == SessionStatus::Disconnected {
                        session.status = SessionStatus::Expired;
                        self.publish_transition(&SessionStatus::Disconnected, &session);
                    }
                }
            }
            // The reconnect window is over. The VDI container (if any)
            // is stopped here, not at the browser disconnect.
            self.stop_vdi_container(id).await;
            to_remove.push(id);
        }

        if !to_remove.is_empty() {
            let mut sessions = self.sessions.write().await;
            for id in &to_remove {
                sessions.remove(id);
                // The terminal timestamp entries die with the session.
                self.ended_at.lock().unwrap().remove(id);
                self.disconnected_at.lock().unwrap().remove(id);
                self.mark_owner_disconnected(*id);
                // The registry row intentionally stays (terminal
                // state) so recording rotation can still attribute the
                // file — the stale sweep removes it within 24h.
            }
        }

        // Periodic housekeeping: drop retained session credentials whose
        // auth session has ended (logout, revocation, DB-side expiry) so
        // dead ciphertext leaves memory within one cleanup cycle
        // (persea#245).
        self.prune_session_credentials().await;

        to_remove.len()
    }

    /// Directory where .guac recordings and thumbnails are stored,
    /// resolved once at construction.
    pub fn recording_path(&self) -> &std::path::Path {
        &self.recording_dir
    }

    /// Path to the thumbnails directory (under recording_path).
    pub fn thumbnails_dir(&self) -> std::path::PathBuf {
        self.recording_dir.join("thumbnails")
    }

    /// Path to a specific session's thumbnail file.
    pub fn thumbnail_path(&self, session_id: Uuid) -> std::path::PathBuf {
        self.thumbnails_dir().join(format!("{}.jpg", session_id))
    }

    /// Path to a VDI container's thumbnail (persists across sessions).
    pub fn vdi_thumbnail_path(&self, container_name: &str) -> std::path::PathBuf {
        self.thumbnails_dir()
            .join(format!("vdi-{}.jpg", container_name))
    }

    /// Check if recording is enabled for a given session.
    pub async fn is_recording_enabled(&self, id: Uuid) -> bool {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let session = session.lock().await;
            session.recording_enabled
        } else {
            false
        }
    }

    /// Get recording metadata for a session (address_book_entry, max_recordings).
    pub async fn get_recording_meta(&self, id: Uuid) -> Option<(Option<String>, Option<u32>)> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some((session.address_book_entry.clone(), session.max_recordings))
    }

    /// Check if any active session references the given Docker container ID.
    pub async fn has_active_vdi_session(&self, container_id: &str) -> bool {
        let sessions = self.sessions.read().await;
        for session in sessions.values() {
            let session = session.lock().await;
            if session.container_id.as_deref() == Some(container_id)
                && (session.status == SessionStatus::Active
                    || session.status == SessionStatus::Pending)
            {
                return true;
            }
        }
        false
    }

    /// Configured maximum session lifetime in seconds (0 = unlimited).
    pub fn session_max_duration_secs(&self) -> u64 {
        self.config.session_max_duration_secs
    }

    /// The resolved `[recording]` settings (rotation, max recordings).
    pub fn recording_config(&self) -> crate::config::RecordingConfig {
        self.config.recording_config()
    }

    /// Update the last_activity timestamp on a session (called on WebSocket
    /// input events from the browser). The atomic store avoids a full mutex
    /// lock for this hot path.
    pub async fn update_activity(&self, session_id: &Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(session_id) {
            let session = session.lock().await;
            session.touch_activity();
        }
    }

    // ── Session event feed (S02) ──────────────────────────────────────────

    /// Subscribe to session lifecycle events. The watch value is the
    /// latest event cursor; the retained log (see `replay_events`) is the
    /// authoritative source of events.
    pub fn subscribe_events(&self) -> watch::Receiver<u64> {
        self.event_bus.tx.subscribe()
    }

    /// Replay retained lifecycle events with id > `since`, plus the
    /// latest cursor. Both come from the same locked log that publishes
    /// to, so an SSE subscriber that reads events and then awaits its
    /// watch receiver picks up anything published after the read on the
    /// next change — no loss, no duplication.
    pub fn replay_events(&self, since: u64) -> (u64, Vec<SessionEvent>) {
        let log = self.event_bus.log.lock().unwrap();
        let cursor = log.next_id.saturating_sub(1);
        let events = log
            .events
            .iter()
            .filter(|e| e.id > since)
            .cloned()
            .collect();
        (cursor, events)
    }

    /// Claim one of the per-user live-stream slots for `identity`.
    /// Returns false when the slot is already taken (at most one
    /// concurrent SSE stream per user).
    pub fn try_claim_sse_subscription(&self, identity: &str) -> bool {
        self.sse_subscribers
            .lock()
            .unwrap()
            .insert(identity.to_string())
    }

    /// Release a claimed live-stream slot (stream ended / client gone).
    pub fn release_sse_subscription(&self, identity: &str) {
        self.sse_subscribers.lock().unwrap().remove(identity);
    }

    /// Publish the `session_started` event for a newly created session.
    /// Called by the session creation path (create.rs) after the session
    /// lands in the map.
    pub fn publish_session_started(&self, session: &Session) {
        self.publish_event(SessionEventKind::SessionStarted, session);
    }

    /// Publish one lifecycle event for a session; the bus assigns the
    /// cursor id.
    fn publish_event(&self, kind: SessionEventKind, session: &Session) {
        let event = SessionEvent {
            id: 0,
            event: kind,
            session_id: session.id,
            session_type: session.session_type.clone(),
            status: session.status.clone(),
            created_by: session.created_by.clone(),
            timestamp: Utc::now(),
        };
        self.event_bus.publish(event);
    }

    /// Publish a status transition: exactly one event per real transition,
    /// nothing when the status did not change (duplicate notify). Terminal
    /// statuses publish `session_ended` and record `ended_at`; everything
    /// else publishes `status_changed`. `pub(crate)` so the session
    /// creation path (create.rs) can publish the pending → expired
    /// transition from its timeout task.
    pub(crate) fn publish_transition(&self, old: &SessionStatus, session: &Session) {
        if old == &session.status {
            return;
        }
        if session.status.is_terminal() {
            self.ended_at.lock().unwrap().insert(session.id, Utc::now());
        }
        let kind = if session.status.is_terminal() {
            SessionEventKind::SessionEnded
        } else {
            SessionEventKind::StatusChanged
        };
        self.publish_event(kind, session);
    }

    /// Test seam: insert a session directly into the manager's map so
    /// integration tests can drive lifecycle transitions without a guacd
    /// connection. Production code uses `create_session`.
    pub async fn seed_session_for_testing(&self, session: Session) -> Uuid {
        let id = session.id;
        self.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));
        id
    }

    /// Return session IDs whose last_activity is older than `idle_timeout_secs`
    /// seconds ago. Only considers Active or Pending sessions.
    pub async fn get_idle_sessions(&self, idle_timeout_secs: i64) -> Vec<Uuid> {
        let now = Utc::now().timestamp();
        let sessions = self.sessions.read().await;
        let mut idle = Vec::new();
        for (id, session) in sessions.iter() {
            let session = session.lock().await;
            if matches!(
                session.status,
                SessionStatus::Active | SessionStatus::Pending
            ) {
                let last = session.last_activity_secs();
                if last > 0 && (now - last) > idle_timeout_secs {
                    idle.push(*id);
                }
            }
        }
        idle
    }

    /// Return session IDs that have been alive longer than `max_duration_secs`.
    /// Only considers Active or Pending sessions.
    pub async fn get_expired_sessions(&self, max_duration_secs: i64) -> Vec<Uuid> {
        let now = Utc::now();
        let sessions = self.sessions.read().await;
        let mut expired = Vec::new();
        for (id, session) in sessions.iter() {
            let session = session.lock().await;
            if matches!(
                session.status,
                SessionStatus::Active | SessionStatus::Pending
            ) {
                let age = now.signed_duration_since(session.created_at);
                if age.num_seconds() > max_duration_secs {
                    expired.push(*id);
                }
            }
        }
        expired
    }

    /// Count active/pending sessions belonging to `user_id` (matched
    /// against the session's `user_id`, the stable identity; falls back
    /// to `created_by` for sessions that predate identity keying).
    pub async fn get_user_session_count(&self, user_id: &str) -> usize {
        let sessions = self.sessions.read().await;
        let mut count = 0usize;
        for session in sessions.values() {
            let session = session.lock().await;
            if session.user_id.as_deref().unwrap_or(&session.created_by) == user_id
                && matches!(
                    session.status,
                    SessionStatus::Pending | SessionStatus::Active
                )
            {
                count += 1;
            }
        }
        count
    }

    /// Returns true if `user_id` has fewer than `limit` active/pending sessions.
    /// A limit of 0 means unlimited.
    pub async fn check_concurrent_limit(&self, user_id: &str, limit: usize) -> bool {
        if limit == 0 {
            return true;
        }
        self.get_user_session_count(user_id).await < limit
    }

    /// Persist session metadata to the session_history table. This is an
    /// audit-trail write — credentials are never stored.
    pub fn save_session_metadata(&self, session: &Session) {
        if let Some(ref db) = self.db {
            let st = format!("{:?}", session.session_type).to_lowercase();
            if let Err(e) = crate::db::insert_session_history(
                db,
                &session.id.to_string(),
                &st,
                &session.hostname,
                None,
                &session.username,
                &session.created_by,
                session.address_book_entry.as_deref(),
                session.address_book_folder.as_deref(),
                session.entry_display_name.as_deref(),
                session.source_ip.as_deref(),
            ) {
                tracing::warn!(
                    session_id = %session.id,
                    error = %e,
                    "Failed to save session metadata"
                );
            }
        }
    }

    /// Mark the server as shutting down. Returns `false` if already shutting down.
    /// New session creation is blocked after this call.
    pub fn initiate_shutdown(&self) -> bool {
        let was = self.shutdown.swap(true, Ordering::SeqCst);
        if !was {
            self.shutdown_notify.notify_waiters();
        }
        !was
    }

    /// Returns `true` if a shutdown signal has been received.
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Wait until the shutdown signal is received.
    pub async fn wait_for_shutdown(&self) {
        if self.is_shutting_down() {
            return;
        }
        self.shutdown_notify.notified().await;
    }

    /// Cancel all active sessions (cancel their CancellationToken) and
    /// return the count of sessions that were signalled.
    pub async fn cancel_all_sessions(&self) -> usize {
        let sessions = self.sessions.read().await;
        let mut count = 0;
        for (id, session) in sessions.iter() {
            let session = session.lock().await;
            if matches!(
                session.status,
                SessionStatus::Active | SessionStatus::Pending
            ) {
                session.cancel.cancel();
                tracing::debug!(session_id = %id, "Signalled session for shutdown");
                count += 1;
            }
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_manager() -> SessionManager {
        let mut config = Config::default();
        let tmp = std::env::temp_dir().join(format!("persea-mgr-test-{}", uuid::Uuid::new_v4()));
        config.recording_path = Some(tmp.clone());
        config.xvnc_path = "/bin/true".into();
        config.chromium_path = "/bin/true".into();
        config.login_scripts_dir = "/tmp".into();
        SessionManager::new(config, None)
    }

    fn test_session(status: SessionStatus) -> Session {
        Session {
            id: uuid::Uuid::new_v4(),
            session_type: SessionType::Ssh,
            status,
            created_at: Utc::now(),
            hostname: "test-host".into(),
            username: "alice".into(),
            url: None,
            banner: None,
            auto_size: true,
            guacd_stream: None,
            connection_id: "conn-test".into(),
            share_token: "owner-secret".into(),
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
            last_activity: std::sync::atomic::AtomicI64::new(Utc::now().timestamp()),
            source_ip: None,
            user_id: Some("alice".into()),
        }
    }

    async fn seed(mgr: &SessionManager, session: Session) -> Uuid {
        let id = session.id;
        mgr.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));
        id
    }

    #[tokio::test]
    async fn reap_completed_keeps_disconnected_within_reconnect_window() {
        let mgr = test_manager();
        let id = seed(&mgr, test_session(SessionStatus::Active)).await;
        mgr.disconnect_session(id).await;
        // Fresh disconnect: the session must survive cleanup.
        assert_eq!(mgr.reap_completed_sessions().await, 0);
        assert!(mgr.is_session_disconnected(id).await);
    }

    #[tokio::test]
    async fn reap_completed_finalizes_disconnected_past_reconnect_window() {
        let mgr = test_manager();
        let id = seed(&mgr, test_session(SessionStatus::Active)).await;
        mgr.disconnect_session(id).await;
        // Age the disconnect past the cleanup delay (300s default).
        mgr.disconnected_at
            .lock()
            .unwrap()
            .insert(id, Utc::now() - chrono::Duration::minutes(10));

        assert_eq!(mgr.reap_completed_sessions().await, 1);
        assert!(!mgr.is_session_disconnected(id).await);

        // The finalization is a real terminal transition: the event feed
        // carries a session_ended with `expired`.
        let (_, events) = mgr.replay_events(0);
        let ended = events
            .iter()
            .filter(|e| e.event == SessionEventKind::SessionEnded && e.session_id == id)
            .collect::<Vec<_>>();
        assert_eq!(ended.len(), 1);
        assert_eq!(ended[0].status, SessionStatus::Expired);
    }

    #[tokio::test]
    async fn reap_completed_finalizes_disconnected_once() {
        let mgr = test_manager();
        let id = seed(&mgr, test_session(SessionStatus::Active)).await;
        mgr.disconnect_session(id).await;
        mgr.disconnected_at
            .lock()
            .unwrap()
            .insert(id, Utc::now() - chrono::Duration::minutes(10));
        assert_eq!(mgr.reap_completed_sessions().await, 1);
        // Second pass: nothing left to finalize (session already removed).
        assert_eq!(mgr.reap_completed_sessions().await, 0);
    }

    #[tokio::test]
    async fn reap_expired_zero_max_duration_is_disabled() {
        let mut config = Config::default();
        config.session_max_duration_secs = 0;
        let mgr = SessionManager::new(config, None);
        let mut session = test_session(SessionStatus::Active);
        session.created_at = Utc::now() - chrono::Duration::hours(10);
        let id = seed(&mgr, session).await;
        // 0 = unlimited: the session must NOT be reaped.
        assert_eq!(mgr.reap_expired_sessions().await, 0);
        assert!(mgr.get_session(id).await.is_some());
    }

    #[tokio::test]
    async fn reap_expired_reaps_past_max_duration() {
        let mut config = Config::default();
        config.session_max_duration_secs = 60;
        let mgr = SessionManager::new(config, None);
        let mut session = test_session(SessionStatus::Active);
        session.created_at = Utc::now() - chrono::Duration::minutes(10);
        let id = seed(&mgr, session).await;
        assert_eq!(mgr.reap_expired_sessions().await, 1);
        assert!(mgr.get_session(id).await.is_none());
    }

    #[tokio::test]
    async fn owner_connection_tracking_excludes_owner_from_viewer_cap() {
        let mgr = test_manager();
        let mut session = test_session(SessionStatus::Active);
        session.active_connections = 10; // 1 owner + 9 viewers
        let id = seed(&mgr, session).await;

        // Without the owner slot, 10 connections are 10 viewers: at the cap.
        assert!(matches!(
            mgr.reserve_viewer_slot(id, 10).await,
            Err(SessionError::ViewerLimit {
                viewers: 10,
                max: 10
            })
        ));

        // With the owner slot tracked, they count as 9 viewers: a 10th may
        // join.
        mgr.mark_owner_connected(id);
        assert!(mgr.reserve_viewer_slot(id, 10).await.is_ok());
    }

    // ── Shadow join wire format ───────────────────────────────────────

    /// Mock guacd for a join: answers `select` with the join args list,
    /// then returns the parsed `connect` args once the client sends them.
    /// `None` when the client never sends a `connect`.
    async fn mock_guacd_join(
        listener: tokio::net::TcpListener,
    ) -> tokio::task::JoinHandle<Option<Vec<String>>> {
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut parser = crate::protocol::InstructionParser::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    return None;
                }
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                for instr in parser.receive(&chunk).into_iter().flatten() {
                    if instr.opcode == "select" {
                        sock.write_all(
                            Instruction::new("args", vec!["read-only".into(), "hostname".into()])
                                .encode()
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    } else if instr.opcode == "connect" {
                        sock.write_all(
                            Instruction::new("ready", vec!["conn-1".into()])
                                .encode()
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                        return Some(instr.args);
                    }
                }
            }
        })
    }

    #[tokio::test]
    async fn join_connection_sends_read_only_true_for_shadow() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = mock_guacd_join(listener).await;

        let mut config = Config::default();
        config.guacd_addr = addr.to_string();
        let mgr = SessionManager::new(config, None);
        let stream = mgr
            .join_connection("conn-1", 800, 600, 96, true)
            .await
            .unwrap();
        drop(stream);

        let connect_args = server.await.unwrap().expect("mock guacd saw the connect");
        assert_eq!(connect_args, vec!["true".to_string(), String::new()]);
    }

    #[tokio::test]
    async fn join_connection_sends_read_only_false_for_share_viewer() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = mock_guacd_join(listener).await;

        let mut config = Config::default();
        config.guacd_addr = addr.to_string();
        let mgr = SessionManager::new(config, None);
        let stream = mgr
            .join_connection("conn-1", 800, 600, 96, false)
            .await
            .unwrap();
        drop(stream);

        let connect_args = server.await.unwrap().expect("mock guacd saw the connect");
        assert_eq!(connect_args, vec!["false".to_string(), String::new()]);
    }

    // ── Transient session credentials (persea#245) ─────────────────────────

    #[tokio::test]
    async fn session_credentials_roundtrip_owning_session_only() {
        let mgr = test_manager();
        mgr.store_session_credentials("session-token", 7, "alice", "enc:v1:aaa".to_string(), 3600);

        // Same token, same user: resolved.
        let got = mgr
            .session_credentials("session-token", 7)
            .expect("owning session");
        assert_eq!(got.username, "alice");
        assert_eq!(got.password_enc, "enc:v1:aaa");
        // Different token or different user: fail closed.
        assert!(mgr.session_credentials("other-token", 7).is_none());
        assert!(mgr.session_credentials("session-token", 8).is_none());
    }

    #[tokio::test]
    async fn session_credentials_clear_on_logout_and_expire() {
        let mgr = test_manager();
        mgr.store_session_credentials("session-token", 7, "alice", "enc:v1:abc".to_string(), 3600);
        assert_eq!(mgr.session_credentials_len(), 1);

        // Logout clears the entry for that session.
        assert!(mgr.clear_session_credentials("session-token"));
        assert!(mgr.session_credentials("session-token", 7).is_none());
        assert_eq!(mgr.session_credentials_len(), 0);

        // A zero-TTL entry is already expired: retrieval fails closed and
        // the prune removes it.
        mgr.store_session_credentials("expired-token", 7, "alice", "enc:v1:abc".to_string(), 0);
        assert!(mgr.session_credentials("expired-token", 7).is_none());
        mgr.prune_session_credentials().await;
        assert_eq!(mgr.session_credentials_len(), 0);
    }

    #[tokio::test]
    async fn prune_drops_credentials_whose_session_was_revoked() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        // A user + live auth session row, exactly as a password login leaves
        // behind.
        let hash = crate::password::hash_password("s3cret-p@ssword-long").unwrap();
        crate::db::create_user_with_password(
            &db,
            "alice@example.com",
            "Alice",
            &hash,
            "poweruser",
            "database",
        )
        .unwrap();
        let user = crate::db::get_user_by_email(&db, "alice@example.com").unwrap();
        let token = crate::db::create_auth_session(&db, user.id, 3600).unwrap();

        let mut config = Config::default();
        let tmp = std::env::temp_dir().join(format!("persea-mgr-prune-{}", uuid::Uuid::new_v4()));
        config.recording_path = Some(tmp.clone());
        let mgr = SessionManager::new_with_db(config, None, db.clone());
        mgr.store_session_credentials(&token, user.id, "alice", "enc:v1:abc".to_string(), 3600);
        assert_eq!(mgr.session_credentials_len(), 1);

        // Live session: the prune keeps the entry.
        mgr.prune_session_credentials().await;
        assert_eq!(mgr.session_credentials_len(), 1);
        assert!(mgr.session_credentials(&token, user.id).is_some());

        // Revocation (force logout): the auth session row is deleted, so
        // the next prune drops the retained credential.
        crate::db::delete_auth_session(&db, &token).unwrap();
        mgr.prune_session_credentials().await;
        assert_eq!(mgr.session_credentials_len(), 0);
        assert!(mgr.session_credentials(&token, user.id).is_none());
    }

    // ── active_session_count (persea#273) ────────────────────────────

    #[tokio::test]
    async fn active_session_count_matches_live_bucket() {
        let mgr = test_manager();
        // Seed one session in each status and verify the count.
        let _id_active = seed(&mgr, test_session(SessionStatus::Active)).await;
        let _id_pending = seed(&mgr, test_session(SessionStatus::Pending)).await;
        let id_disconnected = seed(&mgr, test_session(SessionStatus::Active)).await;
        let id_completed = seed(&mgr, test_session(SessionStatus::Completed)).await;
        let id_error = seed(&mgr, test_session(SessionStatus::Error)).await;

        // Disconnect one session so it enters the Disconnected state.
        mgr.disconnect_session(id_disconnected).await;

        // active_session_count should return 3: Active + Pending + Disconnected.
        let count = mgr.active_session_count().await;
        assert_eq!(
            count, 3,
            "active_session_count must count Active|Pending|Disconnected"
        );

        // Terminal sessions must not inflate the count.
        mgr.sessions.write().await.remove(&id_completed);
        mgr.sessions.write().await.remove(&id_error);
        assert_eq!(mgr.active_session_count().await, 3);
    }
}
