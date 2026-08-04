//! Auth provider trait and types for the pluggable auth chain.
//!
//! Each authentication backend (OIDC, LDAP, database, API key, RADIUS, SAML,
//! TOTP) implements [`AuthProvider`]. The [`AuthChain`](crate::auth_chain)
//! tries providers in config order — first success wins.

use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Capabilities bitflags
// ---------------------------------------------------------------------------

bitflags::bitflags! {
    /// Capability flags advertising what a provider can do.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Capabilities: u32 {
        /// Can authenticate users (password, token, etc.)
        const AUTHENTICATE     = 0b0000_0001;
        /// Is a second-factor authenticator (TOTP, WebAuthn, etc.)
        const MFA              = 0b0000_0010;
        /// Redirects to an external IdP (OIDC, SAML)
        const REDIRECT         = 0b0000_0100;
        /// Can verify / provide password hashes
        const STORE_PASSWORDS  = 0b0000_1000;
        /// Returns group memberships
        const RESOLVE_GROUPS   = 0b0001_0000;
        /// Can auto-provision users on first login
        const AUTO_CREATE_USER = 0b0010_0000;
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        let mut write_flag = |name: &str, f: &mut fmt::Formatter<'_>| -> fmt::Result {
            if !first {
                write!(f, " | ")?;
            }
            first = false;
            write!(f, "{}", name)
        };

        if self.contains(Self::AUTHENTICATE) {
            write_flag("AUTHENTICATE", f)?;
        }
        if self.contains(Self::MFA) {
            write_flag("MFA", f)?;
        }
        if self.contains(Self::REDIRECT) {
            write_flag("REDIRECT", f)?;
        }
        if self.contains(Self::STORE_PASSWORDS) {
            write_flag("STORE_PASSWORDS", f)?;
        }
        if self.contains(Self::RESOLVE_GROUPS) {
            write_flag("RESOLVE_GROUPS", f)?;
        }
        if self.contains(Self::AUTO_CREATE_USER) {
            write_flag("AUTO_CREATE_USER", f)?;
        }
        if first {
            write!(f, "(empty)")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AuthResult
// ---------------------------------------------------------------------------

/// The outcome of an authentication attempt.
#[derive(Debug, Clone)]
pub enum AuthResult {
    /// Authentication succeeded.
    Success {
        subject: String,
        display_name: String,
        groups: Vec<String>,
        role: Option<String>,
    },
    /// Authentication failed (bad credentials, account locked, etc.).
    Failure(String),
    /// Provider needs more input — redirect the user to the given URL.
    Redirect(String),
    /// Provider is not available (upstream error, misconfiguration).
    Unavailable(String),
}

impl fmt::Display for AuthResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthResult::Success { subject, .. } => write!(f, "Success({subject})"),
            AuthResult::Failure(msg) => write!(f, "Failure({msg})"),
            AuthResult::Redirect(url) => write!(f, "Redirect({url})"),
            AuthResult::Unavailable(msg) => write!(f, "Unavailable({msg})"),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthRequest
// ---------------------------------------------------------------------------

/// Context passed to [`AuthProvider::authenticate`].
#[derive(Debug, Clone)]
pub struct AuthRequest {
    /// IP address of the connecting client.
    pub client_ip: IpAddr,
    /// Username supplied by the client (login form / basic auth).
    pub username: Option<String>,
    /// Password supplied by the client.
    pub password: Option<String>,
    /// Callback parameters from an external IdP redirect (OIDC / SAML).
    pub callback_params: Option<HashMap<String, String>>,
    /// Bearer / API key token.
    pub bearer_token: Option<String>,
    /// Raw request headers — providers that need special headers can read them
    /// here without coupling to axum.
    pub headers: HashMap<String, String>,
}

impl Default for AuthRequest {
    fn default() -> Self {
        Self {
            client_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            username: None,
            password: None,
            callback_params: None,
            bearer_token: None,
            headers: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

/// User information returned by providers that support user lookup.
#[derive(Debug, Clone)]
pub struct UserInfo {
    /// Unique identifier (email, username, sub claim).
    pub subject: String,
    /// Human-readable display name.
    pub display_name: String,
    /// Email address, if known.
    pub email: Option<String>,
    /// Group memberships resolved by the provider.
    pub groups: Vec<String>,
}

// ---------------------------------------------------------------------------
// AuthProvider trait
// ---------------------------------------------------------------------------

/// A trait for anything that can authenticate users.
///
/// All methods except `id()`, `capabilities()`, and `authenticate()` have
/// default implementations so providers only need to override what they
/// actually support.
#[async_trait]
pub trait AuthProvider: Send + Sync {
    /// Provider's config key (e.g. `"oidc"`, `"ldap"`, `"database"`,
    /// `"api_key"`, `"totp"`).
    fn id(&self) -> &str;

    /// What this provider can do.
    fn capabilities(&self) -> Capabilities;

    /// Primary authentication: validate credentials and return identity.
    ///
    /// For redirect providers (OIDC / SAML) return `AuthResult::Redirect`.
    /// For inline providers (LDAP, DB, API key) return `Success` or `Failure`.
    async fn authenticate(&self, request: &AuthRequest) -> AuthResult;

    /// Verify a second factor (TOTP code, WebAuthn assertion, etc.).
    ///
    /// Only called on providers with `Capabilities::MFA`.  Returns `true` if
    /// the factor is valid for the given subject.
    async fn verify_second_factor(&self, _subject: &str, _factor_data: &str) -> bool {
        false
    }

    /// Look up a user by identifier (for session refresh / user info).
    ///
    /// Only needed by providers that can resolve user info independently.
    async fn lookup_user(&self, _subject: &str) -> Option<UserInfo> {
        None
    }

    /// Whether this provider renders an inline username + password login form.
    ///
    /// `true` for LDAP / Database, `false` for API key / OIDC (redirect).
    fn has_inline_login_form(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_flags_combine() {
        let caps = Capabilities::AUTHENTICATE | Capabilities::RESOLVE_GROUPS;
        assert!(caps.contains(Capabilities::AUTHENTICATE));
        assert!(caps.contains(Capabilities::RESOLVE_GROUPS));
        assert!(!caps.contains(Capabilities::MFA));
    }

    #[test]
    fn capability_display() {
        let caps = Capabilities::AUTHENTICATE | Capabilities::REDIRECT;
        assert_eq!(caps.to_string(), "AUTHENTICATE | REDIRECT");
    }

    #[test]
    fn capability_display_empty() {
        let caps = Capabilities::empty();
        assert_eq!(caps.to_string(), "(empty)");
    }

    #[test]
    fn auth_result_display() {
        let r = AuthResult::Failure("bad password".into());
        assert_eq!(r.to_string(), "Failure(bad password)");
    }

    #[test]
    fn auth_request_default() {
        let req = AuthRequest::default();
        assert!(req.username.is_none());
        assert!(req.password.is_none());
    }

    /// Stub provider for testing the trait.
    struct StubProvider;

    #[async_trait]
    impl AuthProvider for StubProvider {
        fn id(&self) -> &str {
            "stub"
        }

        fn capabilities(&self) -> Capabilities {
            Capabilities::AUTHENTICATE
        }

        async fn authenticate(&self, _request: &AuthRequest) -> AuthResult {
            AuthResult::Success {
                subject: "test-user".into(),
                display_name: "Test User".into(),
                groups: vec!["admins".into()],
                role: None,
            }
        }
    }

    #[tokio::test]
    async fn stub_provider_works() {
        let provider = StubProvider;
        assert_eq!(provider.id(), "stub");
        assert!(provider.capabilities().contains(Capabilities::AUTHENTICATE));
        assert!(!provider.has_inline_login_form());

        let result = provider.authenticate(&AuthRequest::default()).await;
        match result {
            AuthResult::Success { subject, .. } => assert_eq!(subject, "test-user"),
            other => panic!("expected Success, got {other}"),
        }
    }

    #[tokio::test]
    async fn default_verify_second_factor_returns_false() {
        let provider = StubProvider;
        assert!(!provider.verify_second_factor("any", "123456").await);
    }

    #[tokio::test]
    async fn default_lookup_user_returns_none() {
        let provider = StubProvider;
        assert!(provider.lookup_user("any").await.is_none());
    }
}
