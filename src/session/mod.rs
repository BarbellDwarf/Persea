mod create;
mod manager;
mod types;

pub use manager::SessionManager;
pub use types::*;

use crate::browser::BrowserManager;
use crate::config::DriveConfig;
use crate::drive;
use crate::tunnel;
use chrono::{DateTime, Utc};
use rand::RngExt;
use std::sync::Arc;

/// Pure token-matching helper — constant-time comparison of a provided
/// token against the owner's long-lived `share_token` and the in-memory
/// set of short-lived admin shadow tokens. Factored out so the logic is
/// unit-testable without spinning up a full `SessionManager`.
pub(crate) fn check_share_token_match(
    share_token: &str,
    shadow_tokens: &[ShadowToken],
    provided: &str,
    now: DateTime<Utc>,
) -> ShareTokenValidation {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;

    let provided_digest = Sha256::digest(provided.as_bytes());

    // 1. Owner's long-lived share token.
    let expected = Sha256::digest(share_token.as_bytes());
    if bool::from(expected.ct_eq(&provided_digest)) {
        return ShareTokenValidation::Owner;
    }

    // 2. Short-lived admin shadow tokens (sha256 compared to the
    //    pre-hashed hex stored on the session).
    let provided_hex = hex::encode(provided_digest);
    for t in shadow_tokens {
        if t.expires_at <= now {
            continue;
        }
        if t.token_hash.len() == provided_hex.len()
            && t.token_hash
                .as_bytes()
                .ct_eq(provided_hex.as_bytes())
                .into()
        {
            return ShareTokenValidation::Shadow {
                issued_by: t.issued_by.clone(),
            };
        }
    }
    ShareTokenValidation::Invalid
}

/// Generate a random 32-char hex share token.
pub(super) fn generate_share_token() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    hex::encode(bytes)
}

/// Resolve the RDP NLA authentication package for this session.
///
/// Precedence: per-entry (or per-request) value if non-empty, else the
/// server-wide `[rdp] default_auth_pkg`, else `"ntlm"`. We default to
/// NTLM because Kerberos requires a KDC reachable via DNS (often over
/// TCP) and its failure mode is a silent hang that looks like a stuck
/// RDP connection. Admins who actually run Kerberos-integrated hosts
/// can set `default_auth_pkg = "kerberos"` or `"negotiate"` in
/// `config.toml`.
pub(super) fn resolve_rdp_auth_pkg(entry_value: Option<&str>, config: &crate::config::Config) -> Option<String> {
    if let Some(v) = entry_value {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(ref rdp) = config.rdp {
        if let Some(ref pkg) = rdp.default_auth_pkg {
            let trimmed = pkg.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    Some("ntlm".to_string())
}

/// Kill browser processes if this is a web session, clean up drive directory,
/// abort any running login script, and shut down any SSH tunnel.
///
/// `cleanup_on_close` and `retention_secs` are sourced from `[drive]` config
/// at each call site (see `drive_cleanup_settings`). Per-session drive dirs
/// are only removed when `cleanup_on_close = true`. `retention_secs > 0`
/// schedules the removal that long after session end. With `cleanup_on_close
/// = false` the directory is left in place; the field is also cleared from
/// the session struct so subsequent reads don't think we still own it.
///
/// Note: cross-session persistence (the new session reading the old
/// session's files on disk) is NOT what these flags control. Each session
/// gets its own per-UUID subdirectory under `drive_path`, so even with
/// cleanup_on_close=false the next session sees an empty drive view.
pub(super) async fn cleanup_browser(
    browser_manager: &BrowserManager,
    session: &mut Session,
    cleanup_on_close: bool,
    retention_secs: u64,
) {
    // Abort login script if still running
    if let Some(handle) = session.login_script_handle.take() {
        handle.abort();
    }

    if let Some(ref mut bs) = session.browser_session {
        browser_manager.kill(bs).await;
    }
    session.browser_session = None;

    // Clean up per-session drive directory if configured to do so.
    if let Some(drive_path) = session.drive_path.take() {
        if cleanup_on_close {
            drive::cleanup_session_dir(drive_path, session.id, retention_secs).await;
        } else {
            tracing::debug!(
                session_id = %session.id,
                "drive cleanup_on_close=false; leaving session drive directory on disk"
            );
        }
    }

    // Shut down SSH tunnel chain (reverse order)
    tunnel::shutdown_chain(&session.tunnels);
    session.tunnels.clear();
}

/// Resolve cleanup behaviour from optional `[drive]` config. Falls back to
/// the historical "always wipe immediately" defaults when no config is set
/// (preserves existing behaviour for installs that never enabled drive).
pub(super) fn drive_cleanup_settings(drive: &Option<DriveConfig>) -> (bool, u64) {
    match drive {
        Some(d) => (d.cleanup_on_close, d.retention_secs),
        None => (true, 0),
    }
}

/// Spawn a background reaper that periodically:
/// 1. Reaps sessions idle longer than `idle_secs` (calls `delete_session`).
/// 2. Reaps sessions exceeding `max_secs` of total lifetime.
/// 3. Persists session metadata to the DB audit trail for reaped sessions.
///
/// The reaper runs every `max(min(idle_secs, max_secs) / 2, 30)` seconds.
pub async fn spawn_reaper(
    manager: Arc<SessionManager>,
    idle_secs: i64,
    max_secs: i64,
) {
    let check_secs = std::cmp::max(
        std::cmp::min(idle_secs, max_secs) / 2,
        30,
    ) as u64;

    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(check_secs));
        interval.tick().await; // skip immediate first tick
        loop {
            interval.tick().await;

            // 1. Reap idle sessions
            if idle_secs > 0 {
                let idle_sessions = manager.get_idle_sessions(idle_secs).await;
                for id in &idle_sessions {
                    // Save metadata before deletion
                    {
                        let sessions = manager.sessions.read().await;
                        if let Some(session) = sessions.get(id) {
                            let session = session.lock().await;
                            manager.save_session_metadata(&session);
                        }
                    }
                    tracing::warn!(session_id = %id, idle_secs = idle_secs, "Reaping idle session");
                    manager.delete_session(*id).await;
                }
                if !idle_sessions.is_empty() {
                    tracing::info!("Reaped {} idle sessions", idle_sessions.len());
                }
            }

            // 2. Reap expired sessions (max duration)
            if max_secs > 0 {
                let expired = manager.get_expired_sessions(max_secs).await;
                for id in &expired {
                    // Save metadata before deletion
                    {
                        let sessions = manager.sessions.read().await;
                        if let Some(session) = sessions.get(id) {
                            let session = session.lock().await;
                            manager.save_session_metadata(&session);
                        }
                    }
                    tracing::warn!(session_id = %id, max_secs = max_secs, "Reaping expired session (max duration)");
                    manager.delete_session(*id).await;
                }
                if !expired.is_empty() {
                    tracing::info!("Reaped {} expired sessions (max duration)", expired.len());
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[test]
    fn drive_cleanup_settings_no_config_uses_legacy_defaults() {
        // No drive config = legacy "always wipe immediately" so existing
        // installs that never touched [drive] keep prior behaviour.
        assert_eq!(drive_cleanup_settings(&None), (true, 0));
    }

    #[test]
    fn drive_cleanup_settings_passes_through_config() {
        let cfg = DriveConfig {
            enabled: true,
            cleanup_on_close: false,
            retention_secs: 600,
            ..DriveConfig::default()
        };
        assert_eq!(drive_cleanup_settings(&Some(cfg)), (false, 600));
    }

    #[test]
    fn drive_cleanup_settings_default_drive_config() {
        // The default DriveConfig uses cleanup_on_close=true, retention=0.
        let cfg = DriveConfig::default();
        assert_eq!(drive_cleanup_settings(&Some(cfg)), (true, 0));
    }

    // ── Share token / shadow token tests ──

    fn make_shadow(raw: &str, issued_by: &str, expires_at: DateTime<Utc>) -> ShadowToken {
        use sha2::{Digest, Sha256};
        ShadowToken {
            token_hash: hex::encode(Sha256::digest(raw.as_bytes())),
            issued_by: issued_by.to_string(),
            expires_at,
        }
    }

    #[test]
    fn share_token_owner_match() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", &[], "owner-secret", now);
        assert_eq!(v, ShareTokenValidation::Owner);
    }

    #[test]
    fn share_token_wrong_returns_invalid() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", &[], "wrong", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_empty_provided_invalid() {
        let now = Utc::now();
        let v = check_share_token_match("owner-secret", &[], "", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_shadow_hit_returns_issued_by() {
        let now = Utc::now();
        let shadow = make_shadow(
            "shadow-raw",
            "admin@example.com",
            now + chrono::Duration::minutes(5),
        );
        let v = check_share_token_match("owner-secret", &[shadow], "shadow-raw", now);
        assert_eq!(
            v,
            ShareTokenValidation::Shadow {
                issued_by: "admin@example.com".into()
            }
        );
    }

    #[test]
    fn share_token_expired_shadow_rejected() {
        let now = Utc::now();
        let expired = make_shadow("shadow-raw", "admin", now - chrono::Duration::minutes(1));
        let v = check_share_token_match("owner-secret", &[expired], "shadow-raw", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_expires_at_now_treated_as_expired() {
        // Boundary: expires_at <= now must reject.
        let now = Utc::now();
        let at_boundary = make_shadow("shadow-raw", "admin", now);
        let v = check_share_token_match("owner-secret", &[at_boundary], "shadow-raw", now);
        assert_eq!(v, ShareTokenValidation::Invalid);
    }

    #[test]
    fn share_token_multiple_shadows_one_matches() {
        let now = Utc::now();
        let ttl = now + chrono::Duration::minutes(5);
        let a = make_shadow("aaa", "admin1", ttl);
        let b = make_shadow("bbb", "admin2", ttl);
        let c = make_shadow("ccc", "admin3", ttl);
        let shadows = vec![a, b, c];
        let v = check_share_token_match("owner", &shadows, "bbb", now);
        assert_eq!(
            v,
            ShareTokenValidation::Shadow {
                issued_by: "admin2".into()
            }
        );
    }

    #[test]
    fn share_token_owner_wins_over_shadow_of_same_string() {
        // If somehow a shadow's raw value equalled the owner's share token,
        // the owner path takes precedence (owner is checked first).
        let now = Utc::now();
        let shadow = make_shadow("collide", "admin", now + chrono::Duration::minutes(5));
        let v = check_share_token_match("collide", &[shadow], "collide", now);
        assert_eq!(v, ShareTokenValidation::Owner);
    }

    #[test]
    fn share_token_validation_is_valid_helper() {
        assert!(ShareTokenValidation::Owner.is_valid());
        assert!(ShareTokenValidation::Shadow {
            issued_by: "x".into()
        }
        .is_valid());
        assert!(!ShareTokenValidation::Invalid.is_valid());
    }

    // ── SessionManager async tests (in-memory, no disk/browser/guacd) ──
    //
    // These exercise the mint → validate → audit path end-to-end without
    // spinning up guacd, a browser, or touching the real recording dir.

    fn seed_test_session(share_token: &str) -> Session {
        Session {
            id: uuid::Uuid::new_v4(),
            session_type: SessionType::Ssh,
            status: SessionStatus::Active,
            created_at: Utc::now(),
            hostname: "test-host".into(),
            username: "alice".into(),
            url: None,
            banner: None,
            guacd_stream: None,
            connection_id: "conn-test".into(),
            share_token: share_token.to_string(),
            width: 1024,
            height: 768,
            active_connections: 0,
            created_by: "alice".into(),
            cancel: tokio_util::sync::CancellationToken::new(),
            browser_session: None,
            deferred_params: None,
            drive_path: None,
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

    fn new_manager_for_tests() -> SessionManager {
        // Build a config pointing at a unique temp recording dir so the
        // real dir isn't touched and parallel tests don't collide.
        let mut config = crate::config::Config::default();
        let tmp = std::env::temp_dir().join(format!(
            "rustguac-sessmgr-test-{}",
            uuid::Uuid::new_v4()
        ));
        config.recording_path = tmp.clone();
        // xvnc/chromium paths are only stored, not exec'd — placeholders are fine.
        config.xvnc_path = "/bin/true".into();
        config.chromium_path = "/bin/true".into();
        config.login_scripts_dir = "/tmp".into();
        SessionManager::new(config, None)
    }

    async fn insert_session(mgr: &SessionManager, session: Session) -> uuid::Uuid {
        let id = session.id;
        mgr.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));
        id
    }

    #[tokio::test]
    async fn manager_owner_token_validates() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner-secret")).await;
        assert_eq!(
            mgr.validate_share_token(id, "owner-secret").await,
            ShareTokenValidation::Owner
        );
        assert_eq!(
            mgr.validate_share_token(id, "wrong").await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_mint_shadow_then_validate() {
        let mgr = new_manager_for_tests();
        let id = insert_session(&mgr, seed_test_session("owner-secret")).await;

        let (raw, expires_at) = mgr
            .mint_shadow_token(id, "admin@example.com")
            .await
            .expect("mint");
        assert!(expires_at > Utc::now());
        // 10-minute TTL — allow small scheduling drift.
        let ttl_ms = (expires_at - Utc::now()).num_milliseconds();
        assert!(ttl_ms > 9 * 60 * 1000 && ttl_ms <= 10 * 60 * 1000);

        // Shadow validates and returns the issuer.
        match mgr.validate_share_token(id, &raw).await {
            ShareTokenValidation::Shadow { issued_by } => {
                assert_eq!(issued_by, "admin@example.com")
            }
            other => panic!("expected Shadow variant, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn manager_shadow_token_is_session_scoped() {
        // IDOR guard: a shadow token minted for session A must NOT validate
        // against session B.
        let mgr = new_manager_for_tests();
        let id_a = insert_session(&mgr, seed_test_session("owner-a")).await;
        let id_b = insert_session(&mgr, seed_test_session("owner-b")).await;
        let (raw, _) = mgr.mint_shadow_token(id_a, "admin").await.expect("mint");
        assert_eq!(
            mgr.validate_share_token(id_b, &raw).await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_mint_prunes_expired_shadow_tokens() {
        let mgr = new_manager_for_tests();
        let mut session = seed_test_session("owner");
        let id = session.id;
        // Seed an already-expired shadow token directly.
        session.shadow_tokens.push(ShadowToken {
            token_hash: "deadbeef".into(),
            issued_by: "stale".into(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
        });
        mgr.sessions
            .write()
            .await
            .insert(id, Arc::new(Mutex::new(session)));

        // Mint pruning is documented on mint_shadow_token.
        let _ = mgr.mint_shadow_token(id, "admin").await.unwrap();

        let sessions = mgr.sessions.read().await;
        let guard = sessions.get(&id).unwrap().lock().await;
        assert_eq!(guard.shadow_tokens.len(), 1, "expired should be pruned");
        assert_ne!(guard.shadow_tokens[0].issued_by, "stale");
    }

    #[tokio::test]
    async fn manager_validate_rejects_unknown_session() {
        let mgr = new_manager_for_tests();
        let phantom = uuid::Uuid::new_v4();
        assert_eq!(
            mgr.validate_share_token(phantom, "anything").await,
            ShareTokenValidation::Invalid
        );
    }

    #[tokio::test]
    async fn manager_disconnect_viewer_saturating_decrement() {
        let mgr = new_manager_for_tests();
        let mut seed = seed_test_session("owner");
        seed.active_connections = 2;
        let id = insert_session(&mgr, seed).await;

        mgr.disconnect_viewer(id).await;
        mgr.disconnect_viewer(id).await;
        // One extra call must NOT underflow to u32::MAX.
        mgr.disconnect_viewer(id).await;

        let sessions = mgr.sessions.read().await;
        let guard = sessions.get(&id).unwrap().lock().await;
        assert_eq!(guard.active_connections, 0);
    }
}
