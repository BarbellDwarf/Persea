//! REST API routes.

pub mod address_book;
pub mod admin;
pub mod reports;
pub mod sessions;
pub mod tokens;
pub mod users;

use crate::vault::{AddressBookEntry, FolderConfig, VaultClient, VaultError};
use std::sync::Arc;

pub type AppState = Arc<crate::session::SessionManager>;

/// Site title from config, shared via Extension.
#[derive(Clone)]
pub struct SiteTitle(pub String);

/// Resolved theme data shared via Extension.
#[derive(Clone)]
pub struct ThemeData {
    /// Admin-configured preset name (e.g. "dark").
    pub admin_preset: String,
    /// Fully-resolved admin theme colors (preset + overrides).
    pub admin_colors: crate::config::ThemeColors,
    /// Optional custom logo URL.
    pub logo_url: Option<String>,
    /// All built-in preset palettes for client-side switching.
    pub presets: std::collections::HashMap<String, crate::config::ThemeColors>,
}

/// Marker for whether OIDC is configured.
#[derive(Clone)]
pub struct OidcEnabled(pub bool);

/// Marker for whether Vault is configured (has [vault] in config).
/// Distinct from VaultState which tracks whether it's currently connected.
#[derive(Clone)]
pub struct VaultConfigured(pub bool);

/// Marker for whether [drive] is configured.
#[derive(Clone)]
pub struct DriveConfigured(pub bool);

/// Default scope ("local" | "shared") for a new per-user credential variable
/// (from `[user_credentials_default_scope]`). Only meaningful when more than
/// one Vault backend is configured.
#[derive(Clone)]
pub struct CredentialDefaultScope(pub String);

/// One Vault backend connection cell — `None` until connected / while down.
pub type VaultCell = Arc<tokio::sync::RwLock<Option<Arc<VaultClient>>>>;

/// The set of Vault backends persea talks to.
///
/// In the single-Vault default, `shared` and `local` both alias `default`, so
/// behaviour is identical to a single `VaultClient`. A multi-Vault split (see
/// `[vault_shared]` / `[vault_local]`) routes the `shared` and `instance`
/// address-book scopes to dedicated backends, each with its own connection and
/// retry lifecycle, so one backend being down cannot take the others with it.
pub struct VaultBackends {
    /// `[vault]`: fallback for any scope without a dedicated backend, and home
    /// of unscoped secrets (the LUKS key; user credential variables for now).
    pub default: VaultCell,
    /// Serves the `shared` scope. Aliases `default` unless `[vault_shared]` is
    /// configured.
    pub shared: VaultCell,
    /// Serves the `instance` (local) scope. Aliases `default` unless
    /// `[vault_local]` is configured.
    pub local: VaultCell,
}

impl VaultBackends {
    /// The backend cell serving a given address-book scope (`"shared"` or
    /// `"instance"`). Anything else falls back to the shared backend.
    pub fn cell_for_scope(&self, scope: &str) -> &VaultCell {
        match scope {
            "instance" => &self.local,
            _ => &self.shared,
        }
    }

    /// Resolve the connected client for `scope`, or `Unavailable` if that
    /// backend is down / not yet connected.
    async fn scoped(&self, scope: &str) -> Result<Arc<VaultClient>, VaultError> {
        self.cell_for_scope(scope)
            .read()
            .await
            .clone()
            .ok_or(VaultError::Unavailable)
    }

    /// True if at least one configured backend is currently connected.
    pub async fn any_connected(&self) -> bool {
        self.default.read().await.is_some()
            || self.shared.read().await.is_some()
            || self.local.read().await.is_some()
    }

    // ── Scope-routed address-book operations (dispatch to the scope's backend) ──

    pub async fn list_subfolders(
        &self,
        scope: &str,
        parent: &str,
    ) -> Result<Vec<crate::vault::FolderInfo>, VaultError> {
        self.scoped(scope)
            .await?
            .list_subfolders(scope, parent)
            .await
    }

    pub async fn list_entries(&self, scope: &str, folder: &str) -> Result<Vec<String>, VaultError> {
        self.scoped(scope).await?.list_entries(scope, folder).await
    }

    pub async fn get_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<AddressBookEntry, VaultError> {
        self.scoped(scope)
            .await?
            .get_entry(scope, folder, entry)
            .await
    }

    pub async fn put_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
        data: &AddressBookEntry,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .put_entry(scope, folder, entry, data)
            .await
    }

    pub async fn delete_entry(
        &self,
        scope: &str,
        folder: &str,
        entry: &str,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .delete_entry(scope, folder, entry)
            .await
    }

    pub async fn get_folder_config(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<FolderConfig, VaultError> {
        self.scoped(scope)
            .await?
            .get_folder_config(scope, folder)
            .await
    }

    pub async fn put_folder_config(
        &self,
        scope: &str,
        folder: &str,
        config: &FolderConfig,
    ) -> Result<(), VaultError> {
        self.scoped(scope)
            .await?
            .put_folder_config(scope, folder, config)
            .await
    }

    pub async fn delete_folder(
        &self,
        scope: &str,
        folder: &str,
    ) -> Result<(usize, usize), VaultError> {
        self.scoped(scope).await?.delete_folder(scope, folder).await
    }

    pub async fn resolve_folder_access(
        &self,
        scope: &str,
        folder: &str,
        user_groups: &[String],
    ) -> Result<bool, VaultError> {
        self.scoped(scope)
            .await?
            .resolve_folder_access(scope, folder, user_groups)
            .await
    }

    // ── Per-user credential variables ──

    pub fn creds_split(&self) -> bool {
        !Arc::ptr_eq(&self.shared, &self.local)
    }

    async fn cred_client(&self, shared: bool) -> Result<Arc<VaultClient>, VaultError> {
        let cell = if shared { &self.shared } else { &self.local };
        cell.read().await.clone().ok_or(VaultError::Unavailable)
    }

    pub async fn get_user_credentials_scoped(
        &self,
        email: &str,
        shared: bool,
    ) -> Result<std::collections::HashMap<String, String>, VaultError> {
        self.cred_client(shared)
            .await?
            .get_user_credentials(email)
            .await
    }

    pub async fn put_user_credentials_scoped(
        &self,
        email: &str,
        shared: bool,
        creds: &std::collections::HashMap<String, String>,
    ) -> Result<(), VaultError> {
        self.cred_client(shared)
            .await?
            .put_user_credentials(email, creds)
            .await
    }

    pub async fn get_user_credentials(
        &self,
        email: &str,
    ) -> Result<std::collections::HashMap<String, String>, VaultError> {
        let local = self
            .get_user_credentials_scoped(email, false)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "reading local credentials failed");
                std::collections::HashMap::new()
            });
        if !self.creds_split() {
            return Ok(local);
        }
        let mut merged = self
            .get_user_credentials_scoped(email, true)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "reading shared credentials failed");
                std::collections::HashMap::new()
            });
        merged.extend(local);
        Ok(merged)
    }

    // ── Fan-out across scopes ──

    pub async fn list_all_folders(
        &self,
    ) -> Result<(Vec<crate::vault::FolderInfo>, Vec<String>), VaultError> {
        let mut folders = Vec::new();
        let mut unavailable = Vec::new();
        let mut any = false;
        for scope in ["shared", "instance"] {
            match self.cell_for_scope(scope).read().await.clone() {
                Some(client) => {
                    any = true;
                    match client.list_folders_in_scope(scope).await {
                        Ok(fs) => folders.extend(fs),
                        Err(VaultError::NotFound) => {}
                        Err(e) => {
                            tracing::warn!(scope, error = %e, "listing folders for scope failed");
                            unavailable.push(scope.to_string());
                        }
                    }
                }
                None => unavailable.push(scope.to_string()),
            }
        }
        if !any {
            return Err(VaultError::Unavailable);
        }
        Ok((folders, unavailable))
    }
}

pub type VaultState = Arc<VaultBackends>;

// ── Re-exports for main.rs compatibility ──

pub use address_book::*;
pub use admin::*;
pub use reports::*;
pub use sessions::*;
pub use tokens::*;
pub use users::*;

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
mod tests {
    use super::tokens::partition_credential_writes;
    use super::address_book::html_escape;
    use super::reports::is_safe_recording_name;

    fn hm(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn test_html_escape_special_chars() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("a&b"), "a&amp;b");
        assert_eq!(html_escape(r#"x"y"#), "x&quot;y");
        assert_eq!(html_escape("it's"), "it&#x27;s");
    }

    #[test]
    fn test_html_escape_passthrough() {
        assert_eq!(html_escape("hello world"), "hello world");
        assert_eq!(html_escape(""), "");
    }

    #[test]
    fn test_partition_single_vault_writes_one_store() {
        let existing = hm(&[("corp_user", "alice"), ("corp_password", "old")]);
        let incoming = hm(&[("corp_password", "new")]);
        let scopes = hm(&[("corp_password", "shared")]);
        let (local, shared) = partition_credential_writes(
            existing,
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            false,
        );
        assert_eq!(local.get("corp_user").unwrap(), "alice");
        assert_eq!(local.get("corp_password").unwrap(), "new");
        assert!(shared.is_empty(), "single store must not populate shared");
    }

    #[test]
    fn test_partition_blank_keeps_existing() {
        let existing = hm(&[("corp_password", "secret")]);
        let incoming = hm(&[("corp_password", "")]);
        let (local, _shared) = partition_credential_writes(
            existing,
            std::collections::HashMap::new(),
            &incoming,
            &std::collections::HashMap::new(),
            "local",
            false,
        );
        assert_eq!(local.get("corp_password").unwrap(), "secret");
    }

    #[test]
    fn test_partition_split_routes_by_scope() {
        let incoming = hm(&[("shared_pw", "s"), ("local_pw", "l")]);
        let scopes = hm(&[("shared_pw", "shared"), ("local_pw", "local")]);
        let (local, shared) = partition_credential_writes(
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            true,
        );
        assert_eq!(shared.get("shared_pw").unwrap(), "s");
        assert!(!shared.contains_key("local_pw"));
        assert_eq!(local.get("local_pw").unwrap(), "l");
        assert!(!local.contains_key("shared_pw"));
    }

    #[test]
    fn test_partition_split_moves_between_scopes_keeping_value() {
        let existing_local = hm(&[("corp_pw", "keepme")]);
        let incoming = hm(&[("corp_pw", "")]);
        let scopes = hm(&[("corp_pw", "shared")]);
        let (local, shared) = partition_credential_writes(
            existing_local,
            std::collections::HashMap::new(),
            &incoming,
            &scopes,
            "local",
            true,
        );
        assert!(!local.contains_key("corp_pw"), "must leave the local store");
        assert_eq!(shared.get("corp_pw").unwrap(), "keepme");
    }

    #[test]
    fn test_partition_split_default_scope_applies() {
        let incoming = hm(&[("corp_pw", "v")]);
        let (local, shared) = partition_credential_writes(
            std::collections::HashMap::new(),
            std::collections::HashMap::new(),
            &incoming,
            &std::collections::HashMap::new(),
            "shared",
            true,
        );
        assert_eq!(shared.get("corp_pw").unwrap(), "v");
        assert!(local.is_empty());
    }

    #[test]
    fn test_html_escape_multiple() {
        assert_eq!(
            html_escape(r#"<a href="x">&</a>"#),
            "&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;"
        );
    }

    #[test]
    fn test_safe_recording_name_valid() {
        let dir = std::env::temp_dir().join("persea-test-recordings");
        let _ = std::fs::create_dir_all(&dir);
        let f1 = dir.join("session-abc123.guac");
        let f2 = dir.join("2024-01-01_recording.guac");
        std::fs::write(&f1, b"").unwrap();
        std::fs::write(&f2, b"").unwrap();
        assert!(is_safe_recording_name("session-abc123.guac", &dir));
        assert!(is_safe_recording_name("2024-01-01_recording.guac", &dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_safe_recording_name_no_guac_extension() {
        use std::path::Path;
        assert!(!is_safe_recording_name("session.mp4", Path::new("/tmp")));
        assert!(!is_safe_recording_name("session", Path::new("/tmp")));
    }

    #[test]
    fn test_safe_recording_name_path_traversal() {
        use std::path::Path;
        assert!(!is_safe_recording_name(
            "../etc/passwd.guac",
            Path::new("/tmp")
        ));
        assert!(!is_safe_recording_name("foo/bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name("foo\\bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name(
            "..%2F..%2Fetc.guac",
            Path::new("/tmp")
        ));
    }

    #[test]
    fn test_safe_recording_name_empty_and_bare_extension() {
        use std::path::Path;
        assert!(!is_safe_recording_name("", Path::new("/tmp")));
        assert!(!is_safe_recording_name(".guac", Path::new("/tmp")));
    }

    #[test]
    fn test_safe_recording_name_nul_byte_rejected() {
        use std::path::Path;
        assert!(!is_safe_recording_name("session\0.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name(
            "sess.guac\0.txt",
            Path::new("/tmp")
        ));
    }

    #[test]
    fn test_safe_recording_name_hidden_traversal() {
        use std::path::Path;
        assert!(!is_safe_recording_name("foo..bar.guac", Path::new("/tmp")));
        assert!(!is_safe_recording_name("..guac", Path::new("/tmp")));
    }

    #[test]
    fn test_safe_recording_name_extension_case_sensitive() {
        use std::path::Path;
        assert!(!is_safe_recording_name("session.GUAC", Path::new("/tmp")));
        assert!(!is_safe_recording_name("session.Guac", Path::new("/tmp")));
    }

    #[test]
    fn test_is_jpeg_magic_happy_path() {
        use super::sessions::is_jpeg_magic;
        assert!(is_jpeg_magic(&[0xFF, 0xD8, 0xFF]));
        assert!(is_jpeg_magic(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]));
    }

    #[test]
    fn test_is_jpeg_magic_rejects_short_body() {
        use super::sessions::is_jpeg_magic;
        assert!(!is_jpeg_magic(&[]));
        assert!(!is_jpeg_magic(&[0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD8]));
    }

    #[test]
    fn test_is_jpeg_magic_rejects_other_formats() {
        use super::sessions::is_jpeg_magic;
        assert!(!is_jpeg_magic(b"\x89PNG\r\n\x1a\n"));
        assert!(!is_jpeg_magic(b"GIF89a"));
        assert!(!is_jpeg_magic(b"%PDF-1.4"));
        assert!(!is_jpeg_magic(b"<!DOCTYPE html>"));
    }

    #[test]
    fn test_is_jpeg_magic_off_by_one_byte() {
        use super::sessions::is_jpeg_magic;
        assert!(!is_jpeg_magic(&[0xFE, 0xD8, 0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD7, 0xFF]));
        assert!(!is_jpeg_magic(&[0xFF, 0xD8, 0xFE]));
    }
}
