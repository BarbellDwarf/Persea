//! Server version update checking.
//!
//! A background task polls the GitHub Releases API (or a configured
//! mirror) every `[updates] check_interval_hours` and compares the latest
//! release against the running version. The result is cached in shared
//! state ([`UpdateState`]) that the anonymous `GET /api/auth/status`
//! handler reads for the admin update banner.
//!
//! The task never blocks startup: the first check runs immediately but in
//! the background, and a failed check logs a warning (never the check URL)
//! and simply waits for the next interval, keeping the previous result.
//! Air-gapped deployments disable the feature with `[updates]
//! enabled = false`: the spawn function then returns before any HTTP
//! client exists, so no network call is ever made.

use crate::config::UpdatesConfig;
use semver::Version;
use std::sync::{Arc, RwLock};

/// Result of the most recent release check, cached for the API handlers.
#[derive(Debug, Clone, Default)]
pub struct UpdateInfo {
    /// Newest release version, semver without the leading `v`. `None` when
    /// the check never succeeded (disabled, not yet checked, or every
    /// attempt failed so far).
    pub latest_version: Option<String>,
    /// RFC 3339 timestamp of the last successful check.
    pub checked_at: Option<String>,
    /// Sanitised failure reason of the last failed check (no URLs).
    pub error: Option<String>,
}

/// Shared handle the background task writes and the API handlers read.
#[derive(Clone)]
pub struct UpdateState {
    /// Cached check result.
    pub info: Arc<RwLock<UpdateInfo>>,
}

impl UpdateState {
    /// Fresh state: never checked, nothing cached.
    pub fn new() -> Self {
        Self {
            info: Arc::new(RwLock::new(UpdateInfo::default())),
        }
    }
}

impl Default for UpdateState {
    fn default() -> Self {
        Self::new()
    }
}

/// Start the periodic version-check loop.
///
/// The first check runs immediately (in the background, so startup is
/// never blocked), then every `check_interval_hours`. With
/// `[updates] enabled = false` no task is spawned and no network call is
/// made. Returns the [`UpdateState`] the caller layers as an axum
/// `Extension` for `GET /api/auth/status`.
pub fn spawn_update_checker(cfg: UpdatesConfig) -> UpdateState {
    let state = UpdateState::new();
    if !cfg.enabled {
        tracing::info!("Version update checking is disabled");
        return state;
    }
    tracing::info!(
        check_interval_hours = cfg.check_interval_hours,
        "Version update checker started"
    );
    let task_state = state.clone();
    tokio::spawn(async move {
        let client = match build_client() {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(error = %error, "Version update checker cannot start");
                return;
            }
        };
        check_and_store(&client, &cfg, &task_state).await;
        let interval_secs = cfg.check_interval_hours.max(1) * 3600;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
        interval.tick().await; // first tick fires immediately; the initial check above already ran
        loop {
            interval.tick().await;
            check_and_store(&client, &cfg, &task_state).await;
        }
    });
    state
}

/// One check round: fetch + parse + compare, then store the outcome.
/// A failed check logs a warning and keeps the previous result.
async fn check_and_store(client: &reqwest::Client, cfg: &UpdatesConfig, state: &UpdateState) {
    match check_for_update(client, &cfg.check_url).await {
        Ok(latest) => {
            *state.info.write().unwrap() = UpdateInfo {
                latest_version: Some(latest.clone()),
                checked_at: Some(chrono::Utc::now().to_rfc3339()),
                error: None,
            };
            if version_newer(&latest, env!("CARGO_PKG_VERSION")) {
                tracing::info!(latest_version = %latest, "A newer persea version is available");
            } else {
                tracing::debug!(latest_version = %latest, "Persea is up to date");
            }
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "Version update check failed; keeping the previous result"
            );
            state.info.write().unwrap().error = Some(error.to_string());
        }
    }
}

/// HTTP client for release checks: 15s timeout, `persea/<version>`
/// User-Agent (the GitHub Releases API rejects requests without one).
pub fn build_client() -> Result<reqwest::Client, UpdateCheckError> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .user_agent(concat!("persea/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| UpdateCheckError::Client(e.to_string()))
}

/// Fetch the latest release from `check_url` and return its version
/// (semver, leading `v` stripped). Errors never embed the check URL.
pub async fn check_for_update(
    client: &reqwest::Client,
    check_url: &str,
) -> Result<String, UpdateCheckError> {
    let resp = client.get(check_url).send().await.map_err(|e| {
        // The reqwest error string embeds the URL, so log only the kind.
        if e.is_timeout() {
            UpdateCheckError::Transport("request timed out")
        } else if e.is_connect() {
            UpdateCheckError::Transport("connection failed")
        } else {
            UpdateCheckError::Transport("request failed")
        }
    })?;
    let status = resp.status();
    let body = resp.text().await.map_err(|_| UpdateCheckError::Body)?;
    if !status.is_success() {
        return Err(UpdateCheckError::HttpStatus(status.as_u16()));
    }
    parse_release_response(&body)
}

/// Parse a GitHub-style `/releases/latest` payload and return the
/// `tag_name` with a leading `v` stripped.
pub fn parse_release_response(body: &str) -> Result<String, UpdateCheckError> {
    #[derive(serde::Deserialize)]
    struct Release {
        tag_name: String,
    }
    let release: Release =
        serde_json::from_str(body).map_err(|e| UpdateCheckError::Parse(e.to_string()))?;
    let tag = release.tag_name;
    Ok(tag.strip_prefix('v').unwrap_or(&tag).to_string())
}

/// True when `latest` is a release newer than `running`, under the
/// pre-release rule: a pre-release tag (e.g. `1.3.0-beta.1`) never counts
/// as newer unless `running` is itself a pre-release. Unparseable versions
/// are never "newer".
pub fn version_newer(latest: &str, running: &str) -> bool {
    let Ok(latest) = Version::parse(latest) else {
        return false;
    };
    let Ok(running) = Version::parse(running) else {
        return false;
    };
    if !running.pre.is_empty() {
        return latest > running;
    }
    latest > running && latest.pre.is_empty()
}

/// Why a release check failed. Messages are sanitised: they never contain
/// the check URL or any credentials.
#[derive(Debug, thiserror::Error)]
pub enum UpdateCheckError {
    /// Request-level failure (timeout, refused, DNS): reason only, never
    /// the URL.
    #[error("release check failed: {0}")]
    Transport(&'static str),
    /// Non-success HTTP status.
    #[error("release check failed: HTTP {0}")]
    HttpStatus(u16),
    /// Response body could not be read.
    #[error("release check failed: response body unreadable")]
    Body,
    /// Body is not a release object with a `tag_name`.
    #[error("release check failed: unexpected response: {0}")]
    Parse(String),
    /// HTTP client could not be built.
    #[error("release check failed: {0}")]
    Client(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_stable_counts() {
        assert!(version_newer("1.2.0", "1.1.1"));
        assert!(version_newer("2.0.0", "1.9.9"));
        assert!(version_newer("1.2.3", "1.2.2"));
    }

    #[test]
    fn equal_or_older_never_counts() {
        assert!(!version_newer("1.1.1", "1.1.1"));
        assert!(!version_newer("1.1.0", "1.1.1"));
        assert!(!version_newer("0.9.0", "1.1.1"));
    }

    #[test]
    fn pre_release_does_not_count_against_stable_running() {
        assert!(!version_newer("1.3.0-beta.1", "1.1.1"));
        assert!(!version_newer("1.3.0-rc.1", "1.1.1"));
        assert!(!version_newer("1.1.2-beta.1", "1.1.1"));
    }

    #[test]
    fn pre_release_counts_when_running_is_pre_release() {
        assert!(version_newer("1.3.0", "1.3.0-beta.1"));
        assert!(version_newer("1.3.0-beta.2", "1.3.0-beta.1"));
        assert!(!version_newer("1.3.0-beta.1", "1.3.0-beta.2"));
    }

    #[test]
    fn garbage_versions_never_count() {
        assert!(!version_newer("not-a-version", "1.1.1"));
        assert!(!version_newer("1.2.0", "not-a-version"));
        assert!(!version_newer("", "1.1.1"));
    }

    #[test]
    fn parse_github_payload_strips_v() {
        assert_eq!(
            parse_release_response(r#"{"tag_name":"v1.2.3","name":"1.2.3"}"#).unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn parse_payload_without_v_prefix() {
        assert_eq!(
            parse_release_response(r#"{"tag_name":"1.2.3"}"#).unwrap(),
            "1.2.3"
        );
    }

    #[test]
    fn parse_missing_tag_name_fails() {
        assert!(parse_release_response(r#"{"name":"1.2.3"}"#).is_err());
        assert!(parse_release_response("not json at all").is_err());
    }

    #[test]
    fn error_messages_never_contain_urls() {
        let err = UpdateCheckError::Transport("connection failed");
        assert!(!err.to_string().contains("http"));
        assert!(!err.to_string().contains("api.github.com"));
        let err = UpdateCheckError::Parse("missing field `tag_name`".to_string());
        assert!(!err.to_string().contains("http"));
    }
}
