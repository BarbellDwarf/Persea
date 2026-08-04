use async_trait::async_trait;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use serde::Deserialize;
use std::time::Duration;
use tracing::{debug, warn};

use crate::auth_provider::{AuthProvider, AuthRequest, AuthResult, Capabilities, UserInfo};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// LDAP provider configuration (TOML `[auth.ldap]`).
#[derive(Debug, Clone, Deserialize)]
pub struct LdapConfig {
    /// LDAP server URL, e.g. `ldap://ldap.example.com:389` or `ldaps://ldap.example.com:636`.
    pub url: String,

    /// Bind DN for the service account, e.g. `cn=admin,dc=example,dc=com`.
    pub bind_dn: String,

    /// Bind password for the service account.
    pub bind_password: String,

    /// Base DN for user searches, e.g. `ou=users,dc=example,dc=com`.
    pub user_search_base: String,

    /// Search filter with `{}` as username placeholder.
    /// Example: `(uid={})` or `(sAMAccountName={})`.
    pub user_search_filter: String,

    /// Optional base DN for group searches. If omitted, groups are not resolved.
    #[serde(default)]
    pub group_search_base: Option<String>,

    /// Group search filter with `{}` as user DN placeholder.
    /// Example: `(member={})` for memberOf-style, or `(uniqueMember={})`.
    /// If both `group_search_base` and `group_search_filter` are present,
    /// groups are resolved via a direct search.
    #[serde(default)]
    pub group_search_filter: Option<String>,

    /// Skip TLS certificate verification (for self-signed certs).
    /// Only applies to ldaps:// or StartTLS connections.
    #[serde(default)]
    pub tls_skip_verify: bool,

    /// Use StartTLS instead of ldaps://.
    /// When true, connects on port 389 and upgrades to TLS.
    #[serde(default)]
    pub starttls: bool,

    /// Connection timeout in seconds.
    #[serde(default = "default_timeout_secs")]
    pub connect_timeout_secs: u64,

    /// The attribute on user entries that holds the display name.
    #[serde(default = "default_display_name_attr")]
    pub display_name_attr: String,

    /// The attribute on user entries that holds the email.
    #[serde(default = "default_email_attr")]
    pub email_attr: String,
}

fn default_timeout_secs() -> u64 {
    10
}
fn default_display_name_attr() -> String {
    "cn".into()
}
fn default_email_attr() -> String {
    "mail".into()
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// LDAP auth provider.  Connects per-request (acceptable for auth, ~10-50ms).
pub struct LdapProvider {
    config: LdapConfig,
}

impl LdapProvider {
    pub fn new(config: LdapConfig) -> Self {
        Self { config }
    }

    /// Build an `LdapConn` with configured TLS / timeout settings.
    fn connect(&self) -> Result<LdapConn, String> {
        let settings = LdapConnSettings::new()
            .set_conn_timeout(Duration::from_secs(self.config.connect_timeout_secs))
            .set_no_tls_verify(self.config.tls_skip_verify)
            .set_starttls(self.config.starttls);

        LdapConn::with_settings(settings, &self.config.url)
            .map_err(|e| format!("LDAP connect failed: {e}"))
    }

    /// Bind with the service account credentials.
    fn bind_service_account(&self, conn: &mut LdapConn) -> Result<(), String> {
        let res = conn
            .simple_bind(&self.config.bind_dn, &self.config.bind_password)
            .map_err(|e| format!("LDAP bind request failed: {e}"))?;
        if res.rc != 0 {
            return Err(format!(
                "LDAP service bind failed: rc={} {}",
                res.rc, res.text
            ));
        }
        debug!("LDAP service bind succeeded: {}", res.rc);
        Ok(())
    }

    /// Check that an LDAP result code indicates success.
    fn check_result(rc: u32, text: &str, context: &str) -> Result<(), String> {
        if rc != 0 {
            Err(format!("{context}: rc={rc} {text}"))
        } else {
            Ok(())
        }
    }

    /// Search for a user by username and return (user_dn, entry).
    fn find_user(
        &self,
        conn: &mut LdapConn,
        username: &str,
    ) -> Result<(String, SearchEntry), String> {
        let filter = self.config.user_search_filter.replace("{}", username);
        debug!(
            "LDAP user search: base={}, filter={}",
            self.config.user_search_base, filter
        );

        let search_result = conn
            .search(
                &self.config.user_search_base,
                Scope::Subtree,
                &filter,
                vec!["dn"],
            )
            .map_err(|e| format!("LDAP user search failed: {e}"))?;
        let (entries, rs) = search_result
            .success()
            .map_err(|e| format!("LDAP user search returned error: {e}"))?;

        Self::check_result(rs.rc, &rs.text, "LDAP user search")?;

        let search_entries: Vec<SearchEntry> =
            entries.into_iter().map(SearchEntry::construct).collect();

        match search_entries.len() {
            0 => Err(format!("no LDAP user found for '{username}'")),
            1 => {
                let entry = search_entries.into_iter().next().unwrap();
                let dn = entry.dn.clone();
                debug!("LDAP found user: dn={dn}");
                Ok((dn, entry))
            }
            _ => Err(format!(
                "ambiguous: {} LDAP users matched '{username}'",
                search_entries.len()
            )),
        }
    }

    /// Attempt to bind as the found user DN with their password.
    fn bind_as_user(&self, user_dn: &str, password: &str) -> Result<(), String> {
        let mut conn = self.connect()?;
        let res = conn
            .simple_bind(user_dn, password)
            .map_err(|e| format!("LDAP user bind request failed: {e}"))?;
        if res.rc != 0 {
            return Err(format!(
                "LDAP user bind rejected: rc={} {}",
                res.rc, res.text
            ));
        }
        Ok(())
    }

    /// Resolve groups for a user DN.
    fn resolve_groups(&self, conn: &mut LdapConn, user_dn: &str) -> Vec<String> {
        let base = match &self.config.group_search_base {
            Some(b) => b,
            None => return vec![],
        };
        let filter = match &self.config.group_search_filter {
            Some(f) => f.replace("{}", user_dn),
            None => return vec![],
        };

        debug!("LDAP group search: base={base}, filter={filter}");

        let search_result = match conn.search(base, Scope::Subtree, &filter, vec!["cn"]) {
            Ok(r) => r,
            Err(e) => {
                warn!("LDAP group search failed: {e}");
                return vec![];
            }
        };
        let (entries, rs) = match search_result.success() {
            Ok(v) => v,
            Err(e) => {
                warn!("LDAP group search returned error: {e}");
                return vec![];
            }
        };

        if rs.rc != 0 {
            warn!("LDAP group search: rc={} {}", rs.rc, rs.text);
            return vec![];
        }

        entries
            .into_iter()
            .map(|raw| {
                let entry = SearchEntry::construct(raw);
                entry
                    .attrs
                    .get("cn")
                    .and_then(|v: &Vec<String>| v.first())
                    .cloned()
                    .unwrap_or(entry.dn)
            })
            .collect()
    }

    /// Extract a display attribute from the search entry.
    fn get_attr(entry: &SearchEntry, attr: &str) -> Option<String> {
        entry
            .attrs
            .get(attr)
            .and_then(|v: &Vec<String>| v.first())
            .cloned()
    }
}

// ---------------------------------------------------------------------------
// AuthProvider impl
// ---------------------------------------------------------------------------

#[async_trait]
impl AuthProvider for LdapProvider {
    fn id(&self) -> &str {
        "ldap"
    }

    fn capabilities(&self) -> Capabilities {
        let mut caps = Capabilities::AUTHENTICATE;
        if self.config.group_search_base.is_some() && self.config.group_search_filter.is_some() {
            caps |= Capabilities::RESOLVE_GROUPS;
        }
        caps
    }

    fn has_inline_login_form(&self) -> bool {
        true
    }

    async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        let username = match &request.username {
            Some(u) if !u.is_empty() => u.clone(),
            _ => return AuthResult::Failure("missing username".into()),
        };
        let password = match &request.password {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return AuthResult::Failure("missing password".into()),
        };

        // 1. Connect as service account.
        let mut conn = match self.connect() {
            Ok(c) => c,
            Err(e) => return AuthResult::Unavailable(e),
        };
        if let Err(e) = self.bind_service_account(&mut conn) {
            return AuthResult::Unavailable(e);
        }

        // 2. Find the user entry.
        let (user_dn, entry) = match self.find_user(&mut conn, &username) {
            Ok(v) => v,
            Err(e) => return AuthResult::Failure(e),
        };

        // 3. Bind as the user to verify password.
        if let Err(e) = self.bind_as_user(&user_dn, &password) {
            debug!("LDAP bind as user failed for '{username}': {e}");
            return AuthResult::Failure("invalid credentials".into());
        }

        // 4. Resolve groups.
        let groups = self.resolve_groups(&mut conn, &user_dn);

        // 5. Build result.
        let display_name = Self::get_attr(&entry, &self.config.display_name_attr)
            .unwrap_or_else(|| username.clone());

        debug!(
            "LDAP auth success: user={username}, dn={user_dn}, groups={:?}",
            groups
        );

        AuthResult::Success {
            subject: user_dn,
            display_name,
            groups,
            role: None,
        }
    }

    async fn lookup_user(&self, subject: &str) -> Option<UserInfo> {
        let mut conn = self.connect().ok()?;
        self.bind_service_account(&mut conn).ok()?;

        let filter = &self.config.user_search_filter.replace("{}", subject);
        let search_result = conn
            .search(
                subject,
                Scope::Base,
                filter,
                vec![&self.config.display_name_attr, &self.config.email_attr],
            )
            .ok()?;

        let (entries, rs) = search_result.success().ok()?;

        if rs.rc != 0 {
            return None;
        }

        let entry = entries.into_iter().next()?;
        let entry = SearchEntry::construct(entry);

        let groups = self.resolve_groups(&mut conn, subject);

        Some(UserInfo {
            subject: subject.to_string(),
            display_name: Self::get_attr(&entry, &self.config.display_name_attr)
                .unwrap_or_else(|| subject.to_string()),
            email: Self::get_attr(&entry, &self.config.email_attr),
            groups,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_defaults() {
        let toml_str = r#"
            url = "ldap://localhost:389"
            bind_dn = "cn=admin,dc=example,dc=com"
            bind_password = "secret"
            user_search_base = "ou=users,dc=example,dc=com"
            user_search_filter = "(uid={})"
        "#;
        let config: LdapConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.url, "ldap://localhost:389");
        assert!(!config.tls_skip_verify);
        assert!(!config.starttls);
        assert_eq!(config.connect_timeout_secs, 10);
        assert_eq!(config.display_name_attr, "cn");
        assert!(config.group_search_base.is_none());
    }

    #[test]
    fn config_with_groups() {
        let toml_str = r#"
            url = "ldaps://ldap.example.com:636"
            bind_dn = "cn=bind,dc=example,dc=com"
            bind_password = "s3cret"
            user_search_base = "ou=people,dc=example,dc=com"
            user_search_filter = "(sAMAccountName={})"
            group_search_base = "ou=groups,dc=example,dc=com"
            group_search_filter = "(member={})"
            tls_skip_verify = true
            starttls = false
        "#;
        let config: LdapConfig = toml::from_str(toml_str).unwrap();
        assert!(config.tls_skip_verify);
        assert_eq!(
            config.group_search_base.as_deref(),
            Some("ou=groups,dc=example,dc=com")
        );
        assert_eq!(config.group_search_filter.as_deref(), Some("(member={})"));
    }

    fn make_provider(group_base: Option<&str>, group_filter: Option<&str>) -> LdapProvider {
        LdapProvider::new(LdapConfig {
            url: "ldap://localhost".into(),
            bind_dn: "cn=a".into(),
            bind_password: "b".into(),
            user_search_base: "ou=u".into(),
            user_search_filter: "(uid={})".into(),
            group_search_base: group_base.map(Into::into),
            group_search_filter: group_filter.map(Into::into),
            tls_skip_verify: false,
            starttls: false,
            connect_timeout_secs: 10,
            display_name_attr: "cn".into(),
            email_attr: "mail".into(),
        })
    }

    #[test]
    fn capabilities_include_groups_when_configured() {
        let provider = make_provider(Some("ou=g"), Some("(member={})"));
        assert!(provider
            .capabilities()
            .contains(Capabilities::RESOLVE_GROUPS));
    }

    #[test]
    fn capabilities_exclude_groups_when_not_configured() {
        let provider = make_provider(None, None);
        assert!(!provider
            .capabilities()
            .contains(Capabilities::RESOLVE_GROUPS));
    }

    #[test]
    fn has_inline_login_form() {
        let provider = make_provider(None, None);
        assert!(provider.has_inline_login_form());
    }

    #[tokio::test]
    async fn authenticate_missing_username() {
        let provider = make_provider(None, None);
        let req = AuthRequest {
            username: None,
            password: Some("pass".into()),
            ..Default::default()
        };
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[tokio::test]
    async fn authenticate_missing_password() {
        let provider = make_provider(None, None);
        let req = AuthRequest {
            username: Some("user".into()),
            password: None,
            ..Default::default()
        };
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[tokio::test]
    async fn authenticate_empty_username() {
        let provider = make_provider(None, None);
        let req = AuthRequest {
            username: Some("".into()),
            password: Some("pass".into()),
            ..Default::default()
        };
        let result = provider.authenticate(&req).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[test]
    fn check_result_ok() {
        assert!(LdapProvider::check_result(0, "", "test").is_ok());
    }

    #[test]
    fn check_result_error() {
        let err = LdapProvider::check_result(32, "no such object", "test").unwrap_err();
        assert!(err.contains("no such object"));
    }
}
