//! TOTP management module — enrollment, verification, and DB persistence.

use crate::db::{self, Db};
use totp_rs::{Algorithm, Secret, TOTP};

/// TOTP configuration parameters.
#[derive(Debug, Clone)]
pub struct TotpConfig {
    pub issuer: String,
    pub digits: u8,
    pub period: u16,
    pub algorithm: Algorithm,
    pub skew: u8,
    /// Enforcement policy: "Off", "AdminsOnly", or "All".
    pub enforcement: TotpEnforcement,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            issuer: "persea".into(),
            digits: 6,
            period: 30,
            algorithm: Algorithm::SHA1,
            skew: 1,
            enforcement: TotpEnforcement::Off,
        }
    }
}

/// TOTP enforcement policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TotpEnforcement {
    #[default]
    Off,
    AdminsOnly,
    All,
}

impl std::fmt::Display for TotpEnforcement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Off => write!(f, "Off"),
            Self::AdminsOnly => write!(f, "AdminsOnly"),
            Self::All => write!(f, "All"),
        }
    }
}

/// Result of a TOTP enrollment (secret + QR code data).
#[derive(Debug, Clone)]
pub struct TotpEnrollment {
    /// Base32-encoded secret (shown to user for manual entry).
    pub secret_b32: String,
    /// Full otpauth:// URI (for QR code scanning).
    pub otpauth_url: String,
    /// Raw PNG bytes of the QR code image.
    pub qr_png: Vec<u8>,
}

/// Generate a TOTP enrollment for a user: create a secret, build the
/// otpauth:// URL, and render a QR code as PNG bytes.
pub fn generate_enrollment(user_email: &str, issuer: &str) -> Result<TotpEnrollment, TotpError> {
    let secret = Secret::generate_secret();
    let secret_b32 = secret.to_encoded().to_string();

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1, // skew
        30,
        secret
            .to_bytes()
            .map_err(|e| TotpError::Generation(e.to_string()))?,
        Some(issuer.to_string()),
        user_email.to_string(),
    )
    .map_err(|e| TotpError::Generation(e.to_string()))?;

    let otpauth_url = totp.get_url().to_string();

    let qr_png = totp.get_qr_png().map_err(TotpError::QrCode)?;

    Ok(TotpEnrollment {
        secret_b32,
        otpauth_url,
        qr_png,
    })
}

/// Verify a TOTP code against a stored secret.
pub fn verify_code(
    secret_b32: &str,
    code: &str,
    algorithm: Algorithm,
    digits: u8,
    period: u16,
    skew: u8,
) -> bool {
    let secret = Secret::Encoded(secret_b32.to_string());

    let totp = match TOTP::new(
        algorithm,
        digits.into(),
        skew,
        period.into(),
        match secret.to_bytes() {
            Ok(b) => b,
            Err(_) => return false,
        },
        None,
        String::new(),
    ) {
        Ok(t) => t,
        Err(_) => return false,
    };

    totp.check_current(code).unwrap_or(false)
}

/// Verify a TOTP code for a user by looking up their stored secret in the DB.
pub fn verify_user_code(db: &Db, user_id: i64, code: &str, skew: u8) -> bool {
    let secret = match db::get_totp_secret(db, user_id) {
        Ok(Some(s)) if s.enabled => s,
        _ => return false,
    };

    let algorithm = match secret.algorithm.as_str() {
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };

    verify_code(
        &secret.secret_b32,
        code,
        algorithm,
        secret.digits,
        secret.period,
        skew,
    )
}

/// Resolve the `totp-rs` algorithm enum from a string name.
pub fn algorithm_from_str(s: &str) -> Algorithm {
    match s {
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    }
}

/// Error type for TOTP operations.
#[derive(Debug)]
#[must_use]
pub enum TotpError {
    Generation(String),
    QrCode(String),
    Database(rusqlite::Error),
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Generation(e) => write!(f, "TOTP generation failed: {e}"),
            Self::QrCode(e) => write!(f, "QR code generation failed: {e}"),
            Self::Database(e) => write!(f, "Database error: {e}"),
        }
    }
}

impl std::error::Error for TotpError {}

impl From<rusqlite::Error> for TotpError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Database(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_code_roundtrip() {
        let secret = Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let secret_bytes = secret.to_bytes().unwrap();

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1, // skew
            30,
            secret_bytes,
            None,
            String::new(),
        )
        .unwrap();

        let code = totp.generate_current().unwrap();
        // Use the same TOTP instance to avoid timing issues across 30s boundaries.
        assert!(totp.check_current(&code).unwrap());
        // verify_code (creates a new instance) should also work with generous skew.
        assert!(verify_code(&secret_b32, &code, Algorithm::SHA1, 6, 30, 5));
        // Wrong code should fail
        assert!(!verify_code(
            &secret_b32,
            "000000",
            Algorithm::SHA1,
            6,
            30,
            1
        ));
    }

    #[test]
    fn algorithm_from_str_default() {
        assert!(matches!(algorithm_from_str("SHA1"), Algorithm::SHA1));
        assert!(matches!(algorithm_from_str("SHA256"), Algorithm::SHA256));
        assert!(matches!(algorithm_from_str("SHA512"), Algorithm::SHA512));
        assert!(matches!(algorithm_from_str("unknown"), Algorithm::SHA1));
    }

    #[test]
    fn totp_enforcement_display() {
        assert_eq!(TotpEnforcement::Off.to_string(), "Off");
        assert_eq!(TotpEnforcement::AdminsOnly.to_string(), "AdminsOnly");
        assert_eq!(TotpEnforcement::All.to_string(), "All");
    }
}
