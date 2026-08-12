//! TOTP MFA auth provider — verifies second-factor TOTP codes.

use async_trait::async_trait;

use crate::auth_provider::{AuthProvider, AuthRequest, AuthResult, Capabilities};
use crate::db::Db;
use crate::totp;

/// TOTP MFA provider configuration.
#[derive(Debug, Clone)]
pub struct TotpProviderConfig {
    /// Issuer name shown in authenticator apps.
    pub issuer: String,
    /// TOTP digits (default: 6).
    pub digits: u8,
    /// TOTP period in seconds (default: 30).
    pub period: u16,
    /// Algorithm: SHA1, SHA256, SHA512.
    pub algorithm: totp_rs::Algorithm,
    /// Clock skew tolerance (how many periods ahead/behind to accept).
    pub skew: u8,
}

impl Default for TotpProviderConfig {
    fn default() -> Self {
        Self {
            issuer: "persea".into(),
            digits: 6,
            period: 30,
            algorithm: totp_rs::Algorithm::SHA1,
            skew: 1,
        }
    }
}

/// TOTP MFA auth provider.
pub struct TotpProvider {
    config: TotpProviderConfig,
    db: Db,
}

impl TotpProvider {
    /// Create a provider bound to the given config and database.
    pub fn new(config: TotpProviderConfig, db: Db) -> Self {
        Self { config, db }
    }
}

#[async_trait]
impl AuthProvider for TotpProvider {
    fn id(&self) -> &str {
        "totp"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::MFA
    }

    async fn authenticate(&self, _request: &AuthRequest) -> AuthResult {
        // TOTP is a second-factor provider; it doesn't do primary authentication.
        AuthResult::Unavailable("TOTP is a second-factor provider only".into())
    }

    async fn verify_second_factor(&self, subject: &str, factor_data: &str) -> bool {
        // Look up the user by email to get their user_id
        let user = match crate::db::get_user_by_email(&self.db, subject) {
            Ok(u) => u,
            Err(_) => return false,
        };

        totp::verify_user_code(&self.db, user.id, factor_data, self.config.skew)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_provider::{AuthRequest, AuthResult};

    #[test]
    fn totp_provider_capabilities() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        let provider = TotpProvider::new(TotpProviderConfig::default(), db);
        assert_eq!(provider.id(), "totp");
        assert!(provider.capabilities().contains(Capabilities::MFA));
        assert!(!provider.capabilities().contains(Capabilities::AUTHENTICATE));
    }

    #[tokio::test]
    async fn totp_provider_authenticate_returns_unavailable() {
        let db = crate::db::init_db(std::path::Path::new(":memory:")).unwrap();
        let provider = TotpProvider::new(TotpProviderConfig::default(), db);
        let result = provider.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Unavailable(_)));
    }
}
