//! Auth chain — ordered sequence of providers, first match wins.
//!
//! The chain is built at startup from config. During a request it tries each
//! primary provider in order; the first `Success` or `Redirect` wins.
//! An optional MFA provider (TOTP) is applied after primary auth.

use crate::auth_provider::{AuthRequest, AuthResult, AuthProvider};

/// An ordered chain of auth providers.  First match wins.
pub struct AuthChain {
    /// Primary providers in config order.  Each is tried sequentially.
    providers: Vec<Box<dyn AuthProvider>>,
    /// Optional second-factor provider (e.g. TOTP).  Applied after primary
    /// auth succeeds.
    mfa_provider: Option<Box<dyn AuthProvider>>,
}

impl std::fmt::Debug for AuthChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthChain")
            .field("providers", &self.provider_ids())
            .field("mfa", &self.mfa_provider.as_ref().map(|p| p.id()))
            .finish()
    }
}

impl AuthChain {
    /// Build an empty chain (no providers).
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
            mfa_provider: None,
        }
    }

    /// Build a chain from an explicit list of providers.
    pub fn new(providers: Vec<Box<dyn AuthProvider>>) -> Self {
        Self {
            providers,
            mfa_provider: None,
        }
    }

    /// Set the MFA (second-factor) provider.
    pub fn with_mfa(mut self, provider: Box<dyn AuthProvider>) -> Self {
        debug_assert!(
            provider.capabilities().contains(crate::auth_provider::Capabilities::MFA),
            "MFA provider should have MFA capability"
        );
        self.mfa_provider = Some(provider);
        self
    }

    /// Build a chain from a config method list and a map of provider ID → provider.
    ///
    /// `methods` is the ordered list of provider identifiers (e.g.
    /// `["oidc", "ldap", "api_key"]`).  Each id must have a corresponding
    /// entry in `providers`.  An `"totp"` entry is placed as the MFA provider.
    ///
    /// # Errors
    ///
    /// Returns an error string if an unknown method name is encountered or
    /// more than one MFA provider is specified.
    pub fn from_config(
        methods: &[String],
        mut providers: std::collections::HashMap<String, Box<dyn AuthProvider>>,
    ) -> Result<Self, String> {
        let mut primary = Vec::new();
        let mut mfa: Option<Box<dyn AuthProvider>> = None;

        for method in methods {
            if method == "totp" {
                if mfa.is_some() {
                    return Err("only one MFA provider allowed".into());
                }
                mfa = Some(
                    providers
                        .remove(method)
                        .ok_or_else(|| format!("totp configured but provider not provided"))?,
                );
                continue;
            }
            match providers.remove(method) {
                Some(p) => primary.push(p),
                None => return Err(format!("unknown auth method: {method}")),
            }
        }

        Ok(Self {
            providers: primary,
            mfa_provider: mfa,
        })
    }

    /// Try each primary provider in order.
    ///
    /// Returns on the first `Success` or `Redirect`.  If every provider
    /// returns `Failure` or `Unavailable`, returns a generic failure.
    pub async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        for provider in &self.providers {
            let result = provider.authenticate(request).await;
            match &result {
                AuthResult::Success { .. } | AuthResult::Redirect(_) => return result,
                AuthResult::Failure(_) | AuthResult::Unavailable(_) => continue,
            }
        }
        AuthResult::Failure("no provider could authenticate".into())
    }

    /// Verify a second factor via the MFA provider, if one is configured.
    ///
    /// Returns `true` if the factor is valid, `false` if invalid or if no
    /// MFA provider is configured.
    pub async fn verify_second_factor(&self, subject: &str, factor_data: &str) -> bool {
        match &self.mfa_provider {
            Some(mfa) => mfa.verify_second_factor(subject, factor_data).await,
            None => false,
        }
    }

    /// Whether any primary provider has inline login form capability.
    pub fn has_inline_login_form(&self) -> bool {
        self.providers
            .iter()
            .any(|p| p.has_inline_login_form())
    }

    /// Look up a user across all providers that support it.
    pub async fn lookup_user(&self, subject: &str) -> Option<crate::auth_provider::UserInfo> {
        for provider in &self.providers {
            if let Some(info) = provider.lookup_user(subject).await {
                return Some(info);
            }
        }
        None
    }

    /// The MFA provider, if configured.
    pub fn mfa_provider(&self) -> Option<&dyn AuthProvider> {
        self.mfa_provider.as_deref()
    }

    /// Number of primary providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// IDs of all primary providers (for diagnostics / admin UI).
    pub fn provider_ids(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.id()).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_provider::{AuthRequest, AuthResult, AuthProvider, Capabilities};
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// Stub that always succeeds.
    struct OkProvider;

    #[async_trait]
    impl AuthProvider for OkProvider {
        fn id(&self) -> &str { "ok" }
        fn capabilities(&self) -> Capabilities { Capabilities::AUTHENTICATE }
        async fn authenticate(&self, _: &AuthRequest) -> AuthResult {
            AuthResult::Success {
                subject: "ok-user".into(),
                display_name: "OK".into(),
                groups: vec![],
                role: None,
            }
        }
    }

    /// Stub that always fails.
    struct FailProvider;

    #[async_trait]
    impl AuthProvider for FailProvider {
        fn id(&self) -> &str { "fail" }
        fn capabilities(&self) -> Capabilities { Capabilities::AUTHENTICATE }
        async fn authenticate(&self, _: &AuthRequest) -> AuthResult {
            AuthResult::Failure("nope".into())
        }
    }

    /// Stub that redirects.
    struct RedirectProvider;

    #[async_trait]
    impl AuthProvider for RedirectProvider {
        fn id(&self) -> &str { "redirect" }
        fn capabilities(&self) -> Capabilities {
            Capabilities::AUTHENTICATE | Capabilities::REDIRECT
        }
        async fn authenticate(&self, _: &AuthRequest) -> AuthResult {
            AuthResult::Redirect("https://idp.example.com/login".into())
        }
    }

    #[tokio::test]
    async fn chain_first_success_wins() {
        let chain = AuthChain::new(vec![
            Box::new(FailProvider),
            Box::new(OkProvider),
        ]);
        let result = chain.authenticate(&AuthRequest::default()).await;
        match result {
            AuthResult::Success { subject, .. } => assert_eq!(subject, "ok-user"),
            other => panic!("expected Success, got {other}"),
        }
    }

    #[tokio::test]
    async fn chain_all_fail_returns_failure() {
        let chain = AuthChain::new(vec![
            Box::new(FailProvider),
            Box::new(FailProvider),
        ]);
        let result = chain.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[tokio::test]
    async fn chain_redirect_short_circuits() {
        let chain = AuthChain::new(vec![
            Box::new(FailProvider),
            Box::new(RedirectProvider),
            Box::new(OkProvider), // should never be reached
        ]);
        let result = chain.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Redirect(_)));
    }

    #[tokio::test]
    async fn chain_empty_always_fails() {
        let chain = AuthChain::empty();
        let result = chain.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Failure(_)));
    }

    #[test]
    fn chain_provider_ids() {
        let chain = AuthChain::new(vec![
            Box::new(FailProvider),
            Box::new(OkProvider),
        ]);
        assert_eq!(chain.provider_ids(), vec!["fail", "ok"]);
        assert_eq!(chain.provider_count(), 2);
    }

    #[test]
    fn chain_has_inline_login_form() {
        let chain = AuthChain::new(vec![Box::new(FailProvider)]);
        assert!(!chain.has_inline_login_form());
    }

    #[tokio::test]
    async fn chain_verify_second_factor_no_mfa() {
        let chain = AuthChain::empty();
        assert!(!chain.verify_second_factor("u", "123").await);
    }

    #[test]
    fn from_config_basic() {
        let mut providers: HashMap<String, Box<dyn AuthProvider>> = HashMap::new();
        providers.insert("ok".into(), Box::new(OkProvider));
        providers.insert("fail".into(), Box::new(FailProvider));

        let methods = vec!["fail".into(), "ok".into()];
        let chain = AuthChain::from_config(&methods, providers).unwrap();
        assert_eq!(chain.provider_ids(), vec!["fail", "ok"]);
    }

    #[test]
    fn from_config_unknown_method() {
        let providers: HashMap<String, Box<dyn AuthProvider>> = HashMap::new();
        let methods = vec!["nonexistent".into()];
        let err = AuthChain::from_config(&methods, providers).unwrap_err();
        assert!(err.contains("unknown auth method"));
    }
}
