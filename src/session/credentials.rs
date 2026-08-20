//! Transient session-scoped credential retention (persea#245).
//!
//! When `[auth] forward_session_credentials` is enabled, the password from
//! a successful LDAP/database login is retained in memory for the lifetime
//! of the auth session that minted it, encrypted with the storage
//! encryption key. The connect flow retries it for connection entries that
//! carry no credentials of their own, after the entry and preset
//! credentials miss and before the prompt.
//!
//! Storage is deliberately in-memory and session-scoped:
//!
//! - entries live on the [`SessionManager`](super::SessionManager), keyed
//!   by the SHA-256 hash of the auth session token — the same token-hash
//!   convention as the `auth_sessions.token_hash` column, so the plaintext
//!   token is never kept anywhere, not even in memory;
//! - nothing is ever written to the database or to disk, so a process
//!   restart clears every entry and no table or migration exists;
//! - every entry is bound to the owning user id and a TTL equal to the
//!   session lifetime; lookups fail closed on expiry or user mismatch;
//! - the `auth_sessions` row is the source of truth for logout, expiry,
//!   and revocation: a deleted or expired row stops the auth middleware
//!   from authenticating the cookie, so the credential is never handed
//!   out, and the periodic reaper prune drops the stale entry from memory
//!   within one cleanup cycle.
//!
//! The plaintext password never enters a log line, an API response, or the
//! database; only the ciphertext is stored, and only the owning session
//! can retrieve it.

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// One retained login credential, scoped to an auth session.
#[derive(Debug, Clone)]
pub struct RetainedSessionCredential {
    /// The user the credential belongs to (`users.id`). The owning-session
    /// check requires a lookup to present the same id.
    pub user_id: i64,
    /// Login username as typed at login, reused for entries without one.
    pub username: String,
    /// `enc:v1:` ciphertext of the login password (storage encryption key).
    /// The connect flow decrypts it with the storage key, exactly like the
    /// preset and login pass-through fallbacks.
    pub password_enc: String,
    /// Session end: lookups fail closed past this instant. Bounds the
    /// entry to the auth session's own TTL.
    pub expires_at: DateTime<Utc>,
}

/// The SHA-256 hex key for a session token, matching the
/// `auth_sessions.token_hash` convention.
fn session_key(session_token: &str) -> String {
    hex::encode(Sha256::digest(session_token.as_bytes()))
}

/// In-memory, session-keyed store of retained login credentials.
///
/// [`SessionManager`](super::SessionManager) owns one instance. All
/// operations are short synchronous critical sections (no awaits inside),
/// safe to call from async handlers.
pub(crate) struct SessionCredentialStore {
    entries: Mutex<HashMap<String, RetainedSessionCredential>>,
}

impl Default for SessionCredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionCredentialStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Store a credential for a session, replacing any previous entry for
    /// the same session. Expired entries are pruned first so the map never
    /// grows beyond the set of live sessions.
    pub(crate) fn store(&self, session_token: &str, cred: RetainedSessionCredential) {
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, e| e.expires_at > Utc::now());
        entries.insert(session_key(session_token), cred);
    }

    /// Owning-session lookup: the entry for `session_token` only when it
    /// exists, is unexpired, and belongs to `user_id`. Any other outcome
    /// returns `None` (fail closed). Expired entries are pruned as a side
    /// effect.
    pub(crate) fn get(
        &self,
        session_token: &str,
        user_id: i64,
    ) -> Option<RetainedSessionCredential> {
        let mut entries = self.entries.lock().unwrap();
        let now = Utc::now();
        entries.retain(|_, e| e.expires_at > now);
        let key = session_key(session_token);
        entries
            .get(&key)
            .filter(|e| e.user_id == user_id)
            .cloned()
    }

    /// Remove the entry for a session (logout/revocation paths). Returns
    /// true when an entry was removed.
    pub(crate) fn remove(&self, session_token: &str) -> bool {
        self.entries.lock().unwrap().remove(&session_key(session_token)).is_some()
    }

    /// Remove entries that have passed their TTL. Returns how many were
    /// removed.
    pub(crate) fn prune_expired(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        let now = Utc::now();
        entries.retain(|_, e| e.expires_at > now);
        before - entries.len()
    }

    /// All current entry keys (token hashes), for the DB-liveness prune.
    pub(crate) fn keys(&self) -> Vec<String> {
        self.entries.lock().unwrap().keys().cloned().collect()
    }

    /// Remove the entry for a known key (token hash).
    pub(crate) fn remove_key(&self, key: &str) -> bool {
        self.entries.lock().unwrap().remove(key).is_some()
    }

    /// Drop every entry. Used by the login handler test path and by tests.
    pub(crate) fn clear_all(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Number of retained entries.
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Whether the store holds no entries.
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cred(user_id: i64, username: &str, enc: &str, ttl_secs: i64) -> RetainedSessionCredential {
        RetainedSessionCredential {
            user_id,
            username: username.to_string(),
            password_enc: enc.to_string(),
            expires_at: Utc::now() + chrono::Duration::seconds(ttl_secs),
        }
    }

    #[test]
    fn store_and_get_roundtrip() {
        let store = SessionCredentialStore::new();
        assert!(store.is_empty());
        store.store("session-token", cred(7, "alice", "enc:v1:aaa", 3600));
        assert_eq!(store.len(), 1);
        let got = store.get("session-token", 7).expect("same token, same user");
        assert_eq!(got.username, "alice");
        assert_eq!(got.password_enc, "enc:v1:aaa");
        assert_eq!(got.user_id, 7);
    }

    #[test]
    fn different_token_does_not_resolve() {
        let store = SessionCredentialStore::new();
        store.store("token-a", cred(7, "alice", "enc:v1:aaa", 3600));
        assert!(store.get("token-b", 7).is_none());
    }

    #[test]
    fn different_user_does_not_resolve() {
        let store = SessionCredentialStore::new();
        store.store("token-a", cred(7, "alice", "enc:v1:aaa", 3600));
        assert!(store.get("token-a", 8).is_none(), "owning-session check");
    }

    #[test]
    fn expired_entry_fails_closed_and_is_pruned() {
        let store = SessionCredentialStore::new();
        store.store("token-a", cred(7, "alice", "enc:v1:aaa", -1));
        assert!(store.get("token-a", 7).is_none(), "expired must fail closed");
        assert!(store.is_empty(), "get prunes expired entries");
    }

    #[test]
    fn store_prunes_expired_entries() {
        let store = SessionCredentialStore::new();
        store.store("token-old", cred(7, "alice", "enc:v1:aaa", -1));
        store.store("token-new", cred(7, "alice", "enc:v1:bbb", 3600));
        assert_eq!(store.len(), 1, "the expired entry was pruned on store");
        assert!(store.get("token-new", 7).is_some());
    }

    #[test]
    fn remove_and_clear() {
        let store = SessionCredentialStore::new();
        store.store("token-a", cred(7, "alice", "enc:v1:aaa", 3600));
        assert!(store.remove("token-a"));
        assert!(!store.remove("token-a"));
        store.store("token-b", cred(7, "bob", "enc:v1:bbb", 3600));
        store.clear_all();
        assert!(store.is_empty());
    }

    #[test]
    fn key_is_a_hash_not_the_token() {
        let store = SessionCredentialStore::new();
        store.store("secret-token-value", cred(7, "alice", "enc:v1:aaa", 3600));
        // The plaintext token must not be a key in the map.
        let keys = store.keys();
        assert!(!keys.iter().any(|k| k == "secret-token-value"));
        assert_eq!(keys.len(), 1);
    }
}
