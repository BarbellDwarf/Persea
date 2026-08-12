use super::types::*;
use crate::browser::BrowserManager;
use crate::config::Config;
use crate::guacd;
use crate::guacd::GuacdStream;
use chrono::{DateTime, Utc};
use rand::RngExt;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Manages all active sessions.
pub struct SessionManager {
    pub(super) sessions: Arc<RwLock<HashMap<Uuid, Arc<Mutex<Session>>>>>,
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
}

impl SessionManager {
    pub fn new_with_db(config: Config, guacd_tls: Option<TlsConnector>, db: crate::db::Db) -> Self {
        let mut mgr = Self::new(config, guacd_tls);
        mgr.db = Some(db);
        mgr
    }

    /// Whether the given enterprise feature is licensed. Delegates to the
    /// process-global license handle (`crate::license::set_global`, set
    /// once at startup) since callers of this method (e.g. the WebSocket
    /// recording-encryption check) aren't axum handlers and can't take an
    /// `Extension<LicenseManager>` directly.
    pub fn has_feature(&self, feature: &str) -> bool {
        crate::license::global().is_some_and(|lm| lm.has_feature(feature))
    }

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
        }
    }

    fn init_vdi_driver(config: &Config) -> Option<Arc<dyn crate::vdi::VdiDriver>> {
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

    /// List all sessions.
    pub async fn list_sessions(&self) -> Vec<SessionInfo> {
        let sessions = self.sessions.read().await;
        let mut result = Vec::new();
        for session in sessions.values() {
            let session = session.lock().await;
            result.push(session.info());
        }
        result
    }

    /// Get a specific session's info.
    pub async fn get_session(&self, id: Uuid) -> Option<SessionInfo> {
        let sessions = self.sessions.read().await;
        let session = sessions.get(&id)?;
        let session = session.lock().await;
        Some(session.info())
    }

    /// Take the guacd stream from a session (for the owner/first WebSocket connection).
    /// Transitions the session to Active. Returns the stream and a cancellation token.
    /// For deferred connections (ephemeral keypair), connects to guacd here.
    pub async fn take_guacd_stream(&self, id: Uuid) -> Option<(GuacdStream, CancellationToken)> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&id)?;
        let mut session = session_arc.lock().await;
        if session.status != SessionStatus::Pending {
            return None;
        }

        // If this is a deferred connection, connect to guacd now
        if let Some(params) = session.deferred_params.take() {
            tracing::info!(session_id = %id, "Establishing deferred guacd connection");
            match guacd::connect_and_handshake(
                &self.config.guacd_addr,
                &params,
                self.guacd_tls.as_ref(),
            )
            .await
            {
                Ok((stream, connection_id)) => {
                    tracing::info!(
                        session_id = %id,
                        connection_id = %connection_id,
                        "Deferred guacd connection established"
                    );
                    session.guacd_stream = Some(stream);
                    session.connection_id = connection_id;
                }
                Err(e) => {
                    tracing::error!(session_id = %id, error = %e, "Deferred guacd connection failed");
                    session.status = SessionStatus::Error;
                    return None;
                }
            }
        }

        let stream = session.guacd_stream.take()?;
        let cancel = session.cancel.clone();
        session.status = SessionStatus::Active;
        session.active_connections += 1;
        crate::metrics::session_active_inc();
        tracing::info!(session_id = %id, "Session now active (owner connected)");
        Some((stream, cancel))
    }

    /// Join an active session by opening a new guacd connection.
    /// Returns a new GuacdStream and the session's cancellation token.
    pub async fn join_session(
        &self,
        id: Uuid,
    ) -> Result<(GuacdStream, CancellationToken), SessionError> {
        let (connection_id, width, height, cancel) = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(&id).ok_or(SessionError::NotFound)?;
            let session = session.lock().await;
            if session.status != SessionStatus::Active {
                return Err(SessionError::NotActive);
            }
            (
                session.connection_id.clone(),
                session.width,
                session.height,
                session.cancel.clone(),
            )
        };

        let stream = guacd::join_connection(
            &self.config.guacd_addr,
            &connection_id,
            width,
            height,
            96,
            self.guacd_tls.as_ref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(session_id = %id, error = %e, "Failed to join guacd session");
            SessionError::GuacdConnection(e.to_string())
        })?;

        // Increment active connections
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            session.active_connections += 1;
        }

        tracing::info!(session_id = %id, "Viewer joined session");
        Ok((stream, cancel))
    }

    /// Validate a share-or-shadow token for a session (constant-time
    /// comparison). Returns which kind of token matched so callers can
    /// audit shadow uses; returns `Invalid` if neither matches or the
    /// session is unknown.
    pub async fn validate_share_token(&self, id: Uuid, token: &str) -> ShareTokenValidation {
        let sessions = self.sessions.read().await;
        let Some(session) = sessions.get(&id) else {
            return ShareTokenValidation::Invalid;
        };
        let session = session.lock().await;
        super::check_share_token_match(
            &session.share_token,
            &session.shadow_tokens,
            token,
            Utc::now(),
        )
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
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active
                || session.status == SessionStatus::Disconnected
            {
                session.status = SessionStatus::Completed;
                crate::metrics::session_active_dec();
                let (c, r) = super::drive_cleanup_settings(&self.config.drive);
                super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
                tracing::info!(session_id = %id, "Session completed");
            }
        }
    }

    /// Mark a session as disconnected — the browser closed the WebSocket but the
    /// session remains in the manager and can be reconnected.
    pub async fn disconnect_session(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active {
                session.status = SessionStatus::Disconnected;
                session.guacd_stream = None;
                crate::metrics::session_active_dec();
                let (c, r) = super::drive_cleanup_settings(&self.config.drive);
                super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
                tracing::info!(session_id = %id, "Session disconnected (reconnectable)");
            }
        }
    }

    /// Attempt to reconnect an owner to a disconnected session. Returns the
    /// guacd stream and cancellation token if the session has reconnect data.
    pub async fn reconnect_session(&self, id: Uuid) -> Option<(GuacdStream, CancellationToken)> {
        let sessions = self.sessions.read().await;
        let session_arc = sessions.get(&id)?;
        let mut session = session_arc.lock().await;
        if session.status != SessionStatus::Disconnected {
            return None;
        }

        if let Some(params) = session.deferred_params.take() {
            tracing::info!(session_id = %id, "Re-establishing deferred guacd connection for reconnect");
            match guacd::connect_and_handshake(
                &self.config.guacd_addr,
                &params,
                self.guacd_tls.as_ref(),
            )
            .await
            {
                Ok((stream, connection_id)) => {
                    session.guacd_stream = Some(stream);
                    session.connection_id = connection_id;
                }
                Err(e) => {
                    tracing::error!(session_id = %id, error = %e, "Reconnect: deferred guacd connection failed");
                    session.status = SessionStatus::Error;
                    return None;
                }
            }
        }

        let stream = session.guacd_stream.take()?;
        let cancel = session.cancel.clone();
        session.status = SessionStatus::Active;
        session.active_connections += 1;
        crate::metrics::session_active_inc();
        tracing::info!(session_id = %id, "Session reconnected (owner)");
        Some((stream, cancel))
    }

    /// Mark a session as errored.
    pub async fn error_session(&self, id: Uuid) {
        let sessions = self.sessions.read().await;
        if let Some(session) = sessions.get(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active {
                crate::metrics::session_active_dec();
            }
            session.status = SessionStatus::Error;
            session.guacd_stream = None;
            let (c, r) = super::drive_cleanup_settings(&self.config.drive);
            super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
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
    pub async fn delete_session(&self, id: Uuid) -> bool {
        let mut sessions = self.sessions.write().await;
        if let Some(session) = sessions.remove(&id) {
            let mut session = session.lock().await;
            if session.status == SessionStatus::Active {
                crate::metrics::session_active_dec();
            }
            session.cancel.cancel();
            session.status = SessionStatus::Completed;
            session.guacd_stream = None;
            let (c, r) = super::drive_cleanup_settings(&self.config.drive);
            super::cleanup_browser(&self.browser_manager, &mut session, c, r).await;
            tracing::info!(session_id = %id, "Session terminated by API");
            true
        } else {
            false
        }
    }

    /// Reap active sessions that have exceeded the max duration.
    /// Returns the number of sessions reaped.
    pub async fn reap_expired_sessions(&self) -> usize {
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
                        to_delete.push(*id);
                    }
                }
            }
        }

        let count = to_delete.len();
        for id in to_delete {
            tracing::warn!(session_id = %id, "Reaping session (exceeded max duration)");
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
    /// "idle-timeout" (distinguishable from max-duration reaping), cancelled,
    /// and their in-memory status moves to the terminal state used by
    /// `delete_session`. A `SessionStatus::IdleTimeout` variant does not
    /// exist yet (src/session/types.rs) — when one lands, flip the status
    /// here and in `delete_session` for a live-API-distinguishable label.
    pub async fn reap_idle_sessions(&self) -> usize {
        let idle_timeout = self.config.session_idle_timeout_secs;
        if idle_timeout == 0 {
            return 0;
        }
        let to_delete = self.get_idle_sessions(idle_timeout as i64).await;
        for id in &to_delete {
            let recording = self.is_recording_enabled(*id).await;
            self.end_session_history(*id, "idle-timeout", 0, recording);
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
    /// been in that state longer than the configured cleanup delay. The session
    /// history in SQLite is not affected — this only frees in-memory state.
    pub async fn reap_completed_sessions(&self) -> usize {
        let delay = std::time::Duration::from_secs(self.config.session_cleanup_delay_secs);
        let now = Utc::now();
        let mut to_remove = Vec::new();

        {
            let sessions = self.sessions.read().await;
            for (id, session) in sessions.iter() {
                let session = session.lock().await;
                match session.status {
                    SessionStatus::Completed
                    | SessionStatus::Error
                    | SessionStatus::Expired
                    | SessionStatus::Disconnected => {
                        let age = now.signed_duration_since(session.created_at);
                        if age.to_std().unwrap_or_default() > delay {
                            to_remove.push(*id);
                        }
                    }
                    _ => {}
                }
            }
        }

        if !to_remove.is_empty() {
            let mut sessions = self.sessions.write().await;
            for id in &to_remove {
                sessions.remove(id);
            }
        }

        to_remove.len()
    }

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

    pub fn session_max_duration_secs(&self) -> u64 {
        self.config.session_max_duration_secs
    }

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

    /// Count active/pending sessions belonging to `user_id` (matched against
    /// `created_by`).
    pub async fn get_user_session_count(&self, user_id: &str) -> usize {
        let sessions = self.sessions.read().await;
        let mut count = 0usize;
        for session in sessions.values() {
            let session = session.lock().await;
            if session.created_by == user_id
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
