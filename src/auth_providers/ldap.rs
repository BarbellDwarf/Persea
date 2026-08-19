use async_trait::async_trait;
use ldap3::{LdapConn, LdapConnSettings, Scope, SearchEntry};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, warn};

use crate::auth_provider::{
    AuthProvider, AuthRequest, AuthResult, Capabilities, RecheckVerdict, UserInfo,
};

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
    /// Accepts `search_base` as an alias (admin UI provider config).
    #[serde(alias = "search_base")]
    pub user_search_base: String,

    /// Search filter with `{}` as username placeholder.
    /// Example: `(uid={})` or `(sAMAccountName={})`.
    /// Accepts `search_filter` as an alias (admin UI provider config).
    #[serde(alias = "search_filter")]
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
    /// Accepts `start_tls` as an alias (admin UI provider config).
    #[serde(default, alias = "start_tls")]
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

/// Escape LDAP filter special characters (RFC 4515) — `pub` so regression
/// tests in `tests/security_regression.rs` exercise the real implementation
/// instead of a hand-maintained copy that could silently diverge from it.
pub fn ldap_escape(input: &str) -> String {
    input
        .replace('\\', "\\5c")
        .replace('*', "\\2a")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// LDAP auth provider.  Connects per-request (acceptable for auth, ~10-50ms).
#[derive(Clone)]
pub struct LdapProvider {
    config: LdapConfig,
}

impl LdapProvider {
    /// Create a provider from the given config.
    pub fn new(config: LdapConfig) -> Self {
        let provider = Self { config };
        // Register for scoped-token account re-validation (persea#226):
        // the token validation path consults this registry for every
        // `scoped` token, so a rotated, locked, disabled, or expired
        // account kills its tokens within the re-check interval. Both
        // construction sites (config file and DB-configured providers)
        // go through this constructor.
        crate::db::revalidation::register(Arc::new(provider.clone()));
        provider
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
    ///
    /// Ok(None) means the search succeeded but matched no user. Search or
    /// result-code errors are Err — but callers must treat both the same
    /// as "invalid credentials" so unknown users are indistinguishable
    /// from wrong passwords.
    fn find_user(
        &self,
        conn: &mut LdapConn,
        username: &str,
    ) -> Result<Option<(String, SearchEntry)>, String> {
        let filter = self
            .config
            .user_search_filter
            .replace("{}", &ldap_escape(username));
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
            0 => Ok(None),
            1 => {
                let entry = search_entries.into_iter().next().unwrap();
                let dn = entry.dn.clone();
                debug!("LDAP found user: dn={dn}");
                Ok(Some((dn, entry)))
            }
            _ => Err(format!(
                "ambiguous: {} LDAP users matched the search filter",
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

    /// A DN that cannot match a real user, used to burn an equivalent bind
    /// round trip when the searched username does not exist.
    fn synthetic_dn(&self) -> String {
        format!("cn=notfound,{}", self.config.user_search_base)
    }

    /// Resolve groups for a user DN.
    fn resolve_groups(&self, conn: &mut LdapConn, user_dn: &str) -> Vec<String> {
        let base = match &self.config.group_search_base {
            Some(b) => b,
            None => return vec![],
        };
        let filter = match &self.config.group_search_filter {
            Some(f) => f.replace("{}", &ldap_escape(user_dn)),
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
// Account re-validation (scoped-token re-check, persea#226)
// ---------------------------------------------------------------------------

/// AD `userAccountControl` bit: the account is disabled.
const UAC_ACCOUNTDISABLE: u32 = 0x0000_0002;
/// AD `userAccountControl` bit: the account is locked out.
const UAC_LOCKOUT: u32 = 0x0000_0010;

/// Whether an AD `userAccountControl` value marks the account disabled
/// or locked out.
fn uac_disabled_or_locked(uac: u32) -> bool {
    uac & (UAC_ACCOUNTDISABLE | UAC_LOCKOUT) != 0
}

/// AD `accountExpires` is a FILETIME (100 ns intervals since 1601-01-01);
/// 0 and `i64::MAX` mean "never expires".
fn ad_account_expired(account_expires: i64, now_unix_secs: i64) -> bool {
    if account_expires == 0 || account_expires == i64::MAX {
        return false;
    }
    let unix_secs = account_expires / 10_000_000 - 11_644_473_600;
    unix_secs < now_unix_secs
}

/// Whether `dn` is `base` itself or a descendant of it. DN attribute
/// names and most values are case-insensitive, so the suffix match is
/// case-insensitive too. Used to keep each LDAP provider re-checking
/// only the accounts under its own search base.
fn dn_under_base(dn: &str, base: &str) -> bool {
    if dn.eq_ignore_ascii_case(base) {
        return true;
    }
    let suffix = format!(",{base}");
    if dn.len() <= suffix.len() {
        return false;
    }
    let start = dn.len() - suffix.len();
    if !dn.is_char_boundary(start) {
        return false;
    }
    dn[start..].eq_ignore_ascii_case(&suffix)
}

/// Whether the password-last-set marker changed since the last
/// successful re-check (AD `pwdLastSet` rotation detection). A missing
/// marker on either side means the directory does not expose one, so no
/// rotation signal.
fn pwd_rotated(previous: Option<&str>, current: Option<&str>) -> bool {
    match (previous, current) {
        (Some(prev), Some(cur)) => prev != cur,
        _ => false,
    }
}

/// Case-insensitive attribute lookup: LDAP attribute names are
/// case-insensitive and servers differ in the casing they return.
fn entry_attr<'a>(entry: &'a SearchEntry, name: &str) -> Option<&'a str> {
    entry
        .attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(String::as_str)
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

        // 2. Find the user entry. An unknown user and a failed bind must
        // produce identical results and comparable timing, or the search
        // doubles as a username oracle. A synthetic bind with the supplied
        // password burns the same round trips as the real user bind below.
        let (user_dn, entry) = match self.find_user(&mut conn, &username) {
            Ok(Some(v)) => v,
            Ok(None) => {
                let _ = self.bind_as_user(&self.synthetic_dn(), &password);
                return AuthResult::Failure("invalid credentials".into());
            }
            Err(e) => {
                debug!("LDAP user search failed for '{username}': {e}");
                return AuthResult::Failure("invalid credentials".into());
            }
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

        let filter = &self
            .config
            .user_search_filter
            .replace("{}", &ldap_escape(subject));
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

    async fn revalidate_account(
        &self,
        subject: &str,
        previous_pwd_last_set: Option<&str>,
    ) -> RecheckVerdict {
        // Only DN-shaped subjects can be LDAP accounts; a bare email
        // (database/OIDC user) is not one of ours, and the shape check
        // avoids a round trip for every non-LDAP scoped token.
        if !subject.contains('=') {
            return RecheckVerdict::NotApplicable;
        }
        // The subject must live under this provider's search base, so
        // multiple LDAP providers each re-check only their own tree.
        if !dn_under_base(subject, &self.config.user_search_base) {
            return RecheckVerdict::NotApplicable;
        }

        let mut conn = match self.connect() {
            Ok(c) => c,
            Err(e) => {
                debug!("LDAP re-validation connect failed: {e}");
                return RecheckVerdict::Unavailable;
            }
        };
        if let Err(e) = self.bind_service_account(&mut conn) {
            debug!("LDAP re-validation service bind failed: {e}");
            return RecheckVerdict::Unavailable;
        }

        // Base-scope search on the user DN: the entry's existence is the
        // account-state check, and the requested attributes carry the
        // status flags (AD) when the directory exposes them.
        let search_result = match conn.search(
            subject,
            Scope::Base,
            "(objectClass=*)",
            vec!["userAccountControl", "accountExpires", "pwdLastSet"],
        ) {
            Ok(r) => r,
            Err(e) => {
                debug!("LDAP re-validation search failed: {e}");
                return RecheckVerdict::Unavailable;
            }
        };
        let (entries, rs) = match search_result.success() {
            Ok(v) => v,
            Err(e) => {
                debug!("LDAP re-validation search returned error: {e}");
                return RecheckVerdict::Unavailable;
            }
        };
        match rs.rc {
            // No such object: the account was deleted or moved.
            32 => return RecheckVerdict::Invalid,
            // Invalid DN syntax: not an LDAP account after all.
            34 => return RecheckVerdict::NotApplicable,
            rc if rc != 0 => {
                debug!("LDAP re-validation search: rc={rc} {}", rs.text);
                return RecheckVerdict::Unavailable;
            }
            _ => {}
        }
        let Some(entry) = entries.into_iter().next() else {
            // Search succeeded but matched nothing: the account is gone.
            return RecheckVerdict::Invalid;
        };
        let entry = SearchEntry::construct(entry);

        // AD status attributes, interpreted only when present so generic
        // directories (OpenLDAP, FreeIPA) get the existence check alone.
        if let Some(uac) = entry_attr(&entry, "userAccountControl")
            .and_then(|v| v.parse::<u32>().ok())
        {
            if uac_disabled_or_locked(uac) {
                debug!(
                    "LDAP re-validation: account disabled or locked (userAccountControl={uac})"
                );
                return RecheckVerdict::Invalid;
            }
        }
        if let Some(exp) = entry_attr(&entry, "accountExpires")
            .and_then(|v| v.parse::<i64>().ok())
        {
            if ad_account_expired(exp, chrono::Utc::now().timestamp()) {
                debug!("LDAP re-validation: account expired (accountExpires={exp})");
                return RecheckVerdict::Invalid;
            }
        }

        // AD pwdLastSet: a change since the last successful re-check
        // means the credentials rotated. The caller stores the marker and
        // passes it back on the next re-check.
        let pwd_last_set = entry_attr(&entry, "pwdLastSet").map(str::to_string);
        if pwd_rotated(previous_pwd_last_set, pwd_last_set.as_deref()) {
            debug!("LDAP re-validation: credentials rotated (pwdLastSet changed)");
            return RecheckVerdict::Invalid;
        }

        RecheckVerdict::Valid { pwd_last_set }
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

    #[test]
    fn synthetic_dn_cannot_match_a_real_user() {
        // The dummy bind target for unknown users lives under the search
        // base with an RDN no real entry uses, so it always rejects.
        let provider = make_provider(None, None);
        assert_eq!(
            provider.synthetic_dn(),
            "cn=notfound,ou=u",
            "synthetic DN must be a non-matching entry under the search base"
        );
    }

    #[test]
    fn uac_flags_detect_disable_and_lockout() {
        // 512 = normal user; the flag bits are additive on top.
        assert!(!uac_disabled_or_locked(512));
        assert!(uac_disabled_or_locked(514), "disabled (512 | 0x2)");
        assert!(uac_disabled_or_locked(528), "locked (512 | 0x10)");
        assert!(uac_disabled_or_locked(530), "disabled + locked");
        assert!(!uac_disabled_or_locked(0));
    }

    #[test]
    fn account_expires_parses_filestamp() {
        // 0 and i64::MAX mean "never expires".
        assert!(!ad_account_expired(0, 1_700_000_000));
        assert!(!ad_account_expired(i64::MAX, 1_700_000_000));
        // A FILETIME in the past (2020-01-01) is expired.
        let past = (1_577_836_800 + 11_644_473_600) * 10_000_000;
        assert!(ad_account_expired(past, 1_700_000_000));
        // A FILETIME in the future (2027-01-01) is not.
        let future = (1_800_000_000 + 11_644_473_600) * 10_000_000;
        assert!(!ad_account_expired(future, 1_700_000_000));
    }

    #[test]
    fn dn_under_base_matches_descendants_only() {
        let base = "ou=users,dc=example,dc=com";
        assert!(dn_under_base("uid=alice,ou=users,dc=example,dc=com", base));
        assert!(dn_under_base("UID=alice,OU=Users,DC=example,DC=com", base));
        assert!(dn_under_base(base, base));
        assert!(!dn_under_base("uid=alice,ou=people,dc=example,dc=com", base));
        assert!(!dn_under_base("alice@example.com", base));
        assert!(!dn_under_base("", base));
    }

    #[test]
    fn entry_attr_matches_case_insensitively() {
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("userAccountControl".to_string(), vec!["514".to_string()]);
        let entry = SearchEntry {
            dn: "uid=alice,ou=users,dc=example,dc=com".into(),
            attrs,
        };
        assert_eq!(entry_attr(&entry, "userAccountControl"), Some("514"));
        assert_eq!(entry_attr(&entry, "useraccountcontrol"), Some("514"));
        assert_eq!(entry_attr(&entry, "USERACCOUNTCONTROL"), Some("514"));
        assert_eq!(entry_attr(&entry, "accountExpires"), None);
    }

    #[test]
    fn pwd_rotated_detects_marker_changes_only() {
        assert!(pwd_rotated(Some("T1"), Some("T2")));
        assert!(!pwd_rotated(Some("T1"), Some("T1")));
        // A missing marker on either side is not a rotation signal.
        assert!(!pwd_rotated(None, Some("T1")));
        assert!(!pwd_rotated(Some("T1"), None));
        assert!(!pwd_rotated(None, None));
    }
}
