//! Enterprise license key validation and feature gating.
//!
//! License format: `PSEA-<base64url JSON>` where the JSON payload contains
//! a signature, customer name, expiry date, and enabled feature flags.
//! HMAC-SHA256 is used for offline validation (the signing key can be swapped
//! for a full PKI setup later).

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::RwLock;

type HmacSha256 = Hmac<Sha256>;

/// HMAC signing key for license validation.
/// In production this would be a public key; for now it's a hardcoded test key.
const LICENSE_HMAC_KEY: &[u8] = b"persea-license-hmac-test-key-2024";

/// 30-day evaluation period in seconds.
const EVAL_PERIOD_SECS: i64 = 30 * 24 * 3600;

/// Path for the evaluation period first-start timestamp file.
const EVAL_MARKER_PATH: &str = "persea-eval";

// ── Feature name constants ──

/// SAML single sign-on.
pub const FEAT_SAML: &str = "saml";
/// Fine-grained RBAC permissions.
pub const FEAT_RBAC: &str = "rbac";
/// TOTP/MFA enforcement.
pub const FEAT_TOTP: &str = "totp";
/// Audit log retention and compliance exports.
pub const FEAT_AUDIT_RETENTION: &str = "audit_retention";
/// Encrypted session recording.
pub const FEAT_ENCRYPTED_RECORDING: &str = "encrypted_recording";
/// High availability / clustering.
pub const FEAT_HA: &str = "ha";

/// All enterprise feature names.
pub const ALL_FEATURES: &[&str] = &[
    FEAT_SAML,
    FEAT_RBAC,
    FEAT_TOTP,
    FEAT_AUDIT_RETENTION,
    FEAT_ENCRYPTED_RECORDING,
    FEAT_HA,
];

// ── License data structures ──

/// Deserialized license key payload (the JSON inside the base64 encoding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicensePayload {
    /// HMAC-SHA256 signature of the remaining fields.
    pub signature: String,
    /// Customer or organization name.
    pub customer: String,
    /// License expiry date (ISO 8601 / RFC 3339).
    pub expiry: DateTime<Utc>,
    /// Enabled enterprise feature identifiers.
    pub features: Vec<String>,
}

/// Fully validated license key.
#[derive(Debug, Clone)]
pub struct LicenseKey {
    /// Customer name from the license.
    pub customer_name: String,
    /// When the license expires.
    pub expiry: DateTime<Utc>,
    /// Enabled enterprise feature identifiers.
    pub features: Vec<String>,
}

/// Status of the current license.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LicenseStatus {
    /// Valid commercial license, not expired.
    Valid,
    /// Commercial license exists but has expired.
    Expired,
    /// No license key configured, but still within the 30-day evaluation.
    Evaluating { days_remaining: i64 },
    /// No license configured and evaluation period has ended.
    NoLicense,
}

/// Errors during license key validation.
#[derive(Debug, thiserror::Error)]
pub enum LicenseError {
    #[error("invalid license format: expected 'PSEA-' prefix")]
    InvalidFormat,
    #[error("invalid base64 encoding: {0}")]
    InvalidBase64(String),
    #[error("invalid JSON payload: {0}")]
    InvalidPayload(String),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("license has expired (expired {expiry})")]
    Expired { expiry: DateTime<Utc> },
}

// ── Core validation ──

/// Validate a license key string offline.
///
/// Returns the parsed [`LicenseKey`] on success, or a [`LicenseError`]
/// describing what went wrong.
pub fn validate_license(key: &str) -> Result<LicenseKey, LicenseError> {
    let raw = key
        .strip_prefix("PSEA-")
        .ok_or(LicenseError::InvalidFormat)?;

    let payload_bytes = decode_base64url(raw).map_err(|e| LicenseError::InvalidBase64(e))?;
    let payload_json =
        String::from_utf8(payload_bytes).map_err(|e| LicenseError::InvalidBase64(e.to_string()))?;

    let payload: LicensePayload = serde_json::from_str(&payload_json)
        .map_err(|e| LicenseError::InvalidPayload(e.to_string()))?;

    verify_signature(&payload)?;

    if Utc::now() > payload.expiry {
        return Err(LicenseError::Expired {
            expiry: payload.expiry,
        });
    }

    Ok(LicenseKey {
        customer_name: payload.customer,
        expiry: payload.expiry,
        features: payload.features,
    })
}

/// Check whether a specific enterprise feature is enabled.
///
/// A valid, non-expired license must list the feature. Returns `false`
/// for `NoLicense`; callers should use [`LicenseManager`] to handle the
/// evaluation period.
pub fn is_feature_enabled(license: Option<&LicenseKey>, feature: &str) -> bool {
    license
        .map(|l| l.features.iter().any(|f| f == feature))
        .unwrap_or(false)
}

// ── LicenseManager ──

/// Shared license state, safe to pass via axum `Extension`.
pub struct LicenseManager {
    inner: RwLock<LicenseManagerInner>,
}

struct LicenseManagerInner {
    /// The parsed commercial license key (if any).
    license: Option<LicenseKey>,
    /// Current computed status.
    status: LicenseStatus,
    /// Raw key string for display / re-validation.
    raw_key: Option<String>,
}

impl LicenseManager {
    /// Create a new manager with an optional pre-loaded license key.
    pub fn new(license_key: Option<&str>) -> Self {
        let manager = Self {
            inner: RwLock::new(LicenseManagerInner {
                license: None,
                status: LicenseStatus::NoLicense,
                raw_key: None,
            }),
        };

        if let Some(key) = license_key {
            if let Err(e) = manager.set_key(key) {
                tracing::warn!(error = %e, "invalid license key in config");
            }
        } else {
            manager.refresh_status();
        }

        manager
    }

    /// Validate and set a new license key. Returns `Ok(())` on success.
    pub fn set_key(&self, key: &str) -> Result<(), LicenseError> {
        let license = validate_license(key)?;
        let mut inner = self.inner.write().unwrap();
        inner.license = Some(license);
        inner.raw_key = Some(key.to_string());
        inner.status = LicenseStatus::Valid;
        Ok(())
    }

    /// Clear the license key (revert to evaluation / no-license).
    pub fn clear(&self) {
        let mut inner = self.inner.write().unwrap();
        inner.license = None;
        inner.raw_key = None;
        drop(inner);
        self.refresh_status();
    }

    /// Refresh the status (checks expiry, evaluation period).
    pub fn refresh_status(&self) {
        let mut inner = self.inner.write().unwrap();

        if let Some(ref lic) = inner.license {
            if Utc::now() > lic.expiry {
                inner.status = LicenseStatus::Expired;
            } else {
                inner.status = LicenseStatus::Valid;
            }
            return;
        }

        // No license — check evaluation period
        let eval_remaining = eval_seconds_remaining();
        if eval_remaining > 0 {
            inner.status = LicenseStatus::Evaluating {
                days_remaining: eval_remaining / 86400,
            };
        } else {
            inner.status = LicenseStatus::NoLicense;
        }
    }

    /// Get the current license status (cloned).
    pub fn status(&self) -> LicenseStatus {
        self.refresh_status();
        self.inner.read().unwrap().status.clone()
    }

    /// Get the parsed license key, if any.
    pub fn license(&self) -> Option<LicenseKey> {
        self.inner.read().unwrap().license.clone()
    }

    /// Check if a specific enterprise feature is enabled.
    pub fn has_feature(&self, feature: &str) -> bool {
        let inner = self.inner.read().unwrap();
        match &inner.status {
            LicenseStatus::Valid => inner
                .license
                .as_ref()
                .map(|l| l.features.iter().any(|f| f == feature))
                .unwrap_or(false),
            LicenseStatus::Evaluating { .. } => true,
            LicenseStatus::Expired | LicenseStatus::NoLicense => false,
        }
    }

    /// Raw license key string, if set.
    pub fn raw_key(&self) -> Option<String> {
        self.inner.read().unwrap().raw_key.clone()
    }
}

impl std::fmt::Debug for LicenseManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().unwrap();
        f.debug_struct("LicenseManager")
            .field("status", &inner.status)
            .field("has_license", &inner.license.is_some())
            .finish()
    }
}

// ── Evaluation period ──

/// Record the first-start timestamp if not already present.
/// Returns the number of seconds remaining in the evaluation window.
pub fn init_eval_period() {
    let path = std::path::PathBuf::from(EVAL_MARKER_PATH);
    if !path.exists() {
        let ts = Utc::now().to_rfc3339();
        if let Err(e) = std::fs::write(&path, &ts) {
            tracing::warn!(error = %e, "failed to write evaluation marker");
        }
    }
}

/// Seconds remaining in the 30-day evaluation period, or 0 if expired/absent.
fn eval_seconds_remaining() -> i64 {
    let path = std::path::PathBuf::from(EVAL_MARKER_PATH);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    let first_start = match DateTime::parse_from_rfc3339(contents.trim()) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return 0,
    };
    let expiry = first_start + chrono::Duration::seconds(EVAL_PERIOD_SECS);
    let remaining = (expiry - Utc::now()).num_seconds();
    remaining.max(0)
}

// ── Internal helpers ──

/// Compute HMAC-SHA256 signature of the payload data (everything except `signature`).
fn compute_signature(payload: &LicensePayload) -> String {
    let mut mac =
        HmacSha256::new_from_slice(LICENSE_HMAC_KEY).expect("HMAC accepts any key length");

    let signable = format!(
        "{}\n{}\n{}",
        payload.customer,
        payload.expiry.to_rfc3339(),
        payload.features.join(",")
    );
    mac.update(signable.as_bytes());
    let result = mac.finalize();
    base64url_encode(&result.into_bytes())
}

/// Verify the HMAC signature in a license payload.
fn verify_signature(payload: &LicensePayload) -> Result<(), LicenseError> {
    let expected = compute_signature(payload);
    use subtle::ConstantTimeEq;
    let a = expected.as_bytes();
    let b = payload.signature.as_bytes();
    if a.len() != b.len() || a.ct_ne(b).into() {
        return Err(LicenseError::InvalidSignature);
    }
    Ok(())
}

/// Encode bytes to URL-safe base64 (no padding).
fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode URL-safe base64 (no padding) to bytes.
fn decode_base64url(input: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| e.to_string())
}

/// Create a signed license key string from raw fields (for testing / admin UI).
pub fn create_license_key(customer: &str, expiry: DateTime<Utc>, features: Vec<String>) -> String {
    let payload = LicensePayload {
        signature: String::new(), // placeholder
        customer: customer.to_string(),
        expiry,
        features,
    };
    let sig = compute_signature(&payload);
    let payload = LicensePayload {
        signature: sig,
        ..payload
    };
    let json = serde_json::to_string(&payload).expect("license payload serializes");
    format!("PSEA-{}", base64url_encode(json.as_bytes()))
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_roundtrip() {
        let expiry = Utc::now() + chrono::Duration::days(365);
        let features = vec![FEAT_SAML.to_string(), FEAT_RBAC.to_string()];
        let key = create_license_key("Test Corp", expiry, features.clone());

        let lic = validate_license(&key).expect("valid key should validate");
        assert_eq!(lic.customer_name, "Test Corp");
        assert_eq!(lic.features, features);
    }

    #[test]
    fn test_validate_rejects_bad_prefix() {
        assert!(matches!(
            validate_license("XXXX-not-a-key"),
            Err(LicenseError::InvalidFormat)
        ));
    }

    #[test]
    fn test_validate_rejects_bad_base64() {
        assert!(matches!(
            validate_license("PSEA-!!!invalid!!!"),
            Err(LicenseError::InvalidBase64(_))
        ));
    }

    #[test]
    fn test_validate_rejects_bad_signature() {
        let expiry = Utc::now() + chrono::Duration::days(365);
        let features = vec![FEAT_SAML.to_string()];
        let key = create_license_key("Test", expiry, features);

        // Tamper with one character in the signature portion
        let mut chars: Vec<char> = key.chars().collect();
        // Find a signature character (near the end) and flip it
        for c in chars.iter_mut().rev().take(5) {
            if *c != 'A' {
                *c = 'A';
                break;
            }
        }
        let tampered: String = chars.into_iter().collect();
        let result = validate_license(&tampered);
        assert!(
            matches!(
                result,
                Err(LicenseError::InvalidSignature) | Err(LicenseError::InvalidPayload(_))
            ),
            "expected signature or payload error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_expired_license() {
        let expiry = Utc::now() - chrono::Duration::days(1);
        let features = vec![FEAT_SAML.to_string()];
        let key = create_license_key("Expired Co", expiry, features);

        let result = validate_license(&key);
        assert!(matches!(result, Err(LicenseError::Expired { .. })));
    }

    #[test]
    fn test_feature_enabled_check() {
        let lic = LicenseKey {
            customer_name: "Test".into(),
            expiry: Utc::now() + chrono::Duration::days(365),
            features: vec![FEAT_SAML.to_string(), FEAT_RBAC.to_string()],
        };
        assert!(is_feature_enabled(Some(&lic), FEAT_SAML));
        assert!(is_feature_enabled(Some(&lic), FEAT_RBAC));
        assert!(!is_feature_enabled(Some(&lic), FEAT_HA));
        assert!(!is_feature_enabled(None, FEAT_SAML));
    }

    #[test]
    fn test_all_features_constant() {
        assert_eq!(ALL_FEATURES.len(), 6);
        assert!(ALL_FEATURES.contains(&FEAT_SAML));
        assert!(ALL_FEATURES.contains(&FEAT_RBAC));
        assert!(ALL_FEATURES.contains(&FEAT_TOTP));
        assert!(ALL_FEATURES.contains(&FEAT_AUDIT_RETENTION));
        assert!(ALL_FEATURES.contains(&FEAT_ENCRYPTED_RECORDING));
        assert!(ALL_FEATURES.contains(&FEAT_HA));
    }

    #[test]
    fn test_license_manager_has_feature_during_eval() {
        let mgr = LicenseManager::new(None);
        // Without a license, check status — eval depends on marker file
        let status = mgr.status();
        match status {
            LicenseStatus::Evaluating { .. } => {
                assert!(mgr.has_feature(FEAT_SAML));
            }
            LicenseStatus::NoLicense => {
                assert!(!mgr.has_feature(FEAT_SAML));
            }
            _ => panic!("unexpected status for no-license manager"),
        }
    }

    #[test]
    fn test_license_manager_with_valid_key() {
        let expiry = Utc::now() + chrono::Duration::days(365);
        let features = vec![FEAT_SAML.to_string()];
        let key = create_license_key("Test", expiry, features);

        let mgr = LicenseManager::new(Some(&key));
        assert_eq!(mgr.status(), LicenseStatus::Valid);
        assert!(mgr.has_feature(FEAT_SAML));
        assert!(!mgr.has_feature(FEAT_RBAC));
        assert_eq!(mgr.raw_key(), Some(key));
    }

    #[test]
    fn test_license_manager_clear() {
        let expiry = Utc::now() + chrono::Duration::days(365);
        let features = vec![FEAT_SAML.to_string()];
        let key = create_license_key("Test", expiry, features);

        let mgr = LicenseManager::new(Some(&key));
        assert_eq!(mgr.status(), LicenseStatus::Valid);
        mgr.clear();
        assert_ne!(mgr.status(), LicenseStatus::Valid);
        assert!(mgr.raw_key().is_none());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world! \x00\x01\x02";
        let encoded = base64url_encode(data);
        let decoded = decode_base64url(&encoded).unwrap();
        assert_eq!(data.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_create_license_key_format() {
        let expiry = Utc::now() + chrono::Duration::days(365);
        let key = create_license_key("Acme", expiry, vec![]);
        assert!(key.starts_with("PSEA-"));
        // Key should be reasonably long (JSON payload + signature)
        assert!(key.len() > 50);
    }
}
