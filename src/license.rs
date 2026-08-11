//! Enterprise license key validation and feature gating.
//!
//! License format: `PSEA-<base64url JSON>` where the JSON payload contains
//! a signature, customer name, expiry date, and enabled feature flags.
//!
//! Signatures are Ed25519 (asymmetric): the vendor signs license keys with a
//! private key that never ships, and this binary verifies them with the
//! public key embedded from `keys/license_public_key`. That file is in
//! OpenSSH public key format (`ssh-ed25519 <base64> <comment>`, as produced
//! by `ssh-keygen -t ed25519`); only the public half is committed. The
//! signature covers the canonical string `customer\nexpiry\nfeatures.join(",")`.

use chrono::{DateTime, Utc};
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::sync::{OnceLock, RwLock};

/// Embedded Ed25519 public key (OpenSSH format) used to verify license
/// signatures. Generated with `ssh-keygen -t ed25519`; only the public half
/// ships in the binary — the private key never leaves the vendor's machine.
const LICENSE_PUBLIC_KEY: &[u8] = include_bytes!("../keys/license_public_key");

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
    /// Ed25519 signature of the remaining fields.
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
    validate_license_with_key(key, license_public_key_bytes())
}

/// Validate a license key against a specific Ed25519 public key.
///
/// Used by [`validate_license`] with the embedded production key; tests use
/// it with a throwaway test keypair.
fn validate_license_with_key(key: &str, public_key: &[u8]) -> Result<LicenseKey, LicenseError> {
    let raw = key
        .strip_prefix("PSEA-")
        .ok_or(LicenseError::InvalidFormat)?;

    let payload_bytes = decode_base64url(raw).map_err(|e| LicenseError::InvalidBase64(e))?;
    let payload_json =
        String::from_utf8(payload_bytes).map_err(|e| LicenseError::InvalidBase64(e.to_string()))?;

    let payload: LicensePayload = serde_json::from_str(&payload_json)
        .map_err(|e| LicenseError::InvalidPayload(e.to_string()))?;

    verify_signature(&payload, public_key)?;

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

/// Process-global handle, for call sites that aren't axum handlers (e.g.
/// `src/websocket.rs`'s post-session encryption-at-rest check) and so can't
/// receive it via `Extension<T>`. Set once at startup, alongside the
/// `Extension` that request handlers use — same pattern as
/// `crate::csrf::SecureCookies`.
static GLOBAL: OnceLock<std::sync::Arc<LicenseManager>> = OnceLock::new();

/// Set the process-global handle (call once at startup, right after
/// constructing the manager).
pub fn set_global(manager: std::sync::Arc<LicenseManager>) {
    let _ = GLOBAL.set(manager);
}

/// Read the process-global handle. Returns `None` if `set_global` was never
/// called (shouldn't happen outside of tests that don't boot the full app).
pub fn global() -> Option<std::sync::Arc<LicenseManager>> {
    GLOBAL.get().cloned()
}

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
        Self::new_with_public_key(license_key, license_public_key_bytes())
    }

    /// Create a manager that verifies against a specific public key (tests).
    fn new_with_public_key(license_key: Option<&str>, public_key: &[u8]) -> Self {
        let manager = Self {
            inner: RwLock::new(LicenseManagerInner {
                license: None,
                status: LicenseStatus::NoLicense,
                raw_key: None,
            }),
        };

        if let Some(key) = license_key {
            if let Err(e) = manager.set_key_with_public_key(key, public_key) {
                tracing::warn!(error = %e, "invalid license key in config");
            }
        } else {
            manager.refresh_status();
        }

        manager
    }

    /// Validate and set a new license key. Returns `Ok(())` on success.
    pub fn set_key(&self, key: &str) -> Result<(), LicenseError> {
        self.set_key_with_public_key(key, license_public_key_bytes())
    }

    /// Set a license key verified against a specific public key (tests).
    fn set_key_with_public_key(&self, key: &str, public_key: &[u8]) -> Result<(), LicenseError> {
        let license = validate_license_with_key(key, public_key)?;
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

/// The canonical string a license signature covers.
///
/// `pub` so the license generator CLI (`license-gen/`) signs the exact same
/// string the server verifies — no format drift between the two.
pub fn signable_string(payload: &LicensePayload) -> String {
    format!(
        "{}\n{}\n{}",
        payload.customer,
        payload.expiry.to_rfc3339(),
        payload.features.join(",")
    )
}

/// Verify the Ed25519 signature in a license payload against a public key.
fn verify_signature(payload: &LicensePayload, public_key: &[u8]) -> Result<(), LicenseError> {
    let sig_bytes =
        decode_base64url(&payload.signature).map_err(|_| LicenseError::InvalidSignature)?;
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(signable_string(payload).as_bytes(), &sig_bytes)
        .map_err(|_| LicenseError::InvalidSignature)
}

/// The embedded Ed25519 public key, parsed once on first use.
fn license_public_key_bytes() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let text =
            std::str::from_utf8(LICENSE_PUBLIC_KEY).expect("license public key file is UTF-8");
        let pk = ssh_key::PublicKey::from_openssh(text)
            .expect("license public key file is a valid OpenSSH public key");
        match pk.key_data() {
            ssh_key::public::KeyData::Ed25519(ed) => *ed.as_ref(),
            _ => panic!("license public key file is not an Ed25519 key"),
        }
    })
}

/// Encode bytes to URL-safe base64 (no padding).
///
/// `pub` so the license generator CLI (`license-gen/`) produces keys in the
/// exact same encoding the server parses.
pub fn base64url_encode(data: &[u8]) -> String {
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

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SecureRandom;
    use ring::signature::Ed25519KeyPair;
    use ring::signature::KeyPair;

    /// Generate a throwaway Ed25519 keypair for tests (never the production key).
    fn test_keypair() -> Ed25519KeyPair {
        let rng = ring::rand::SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).expect("system rng fills seed");
        Ed25519KeyPair::from_seed_unchecked(&seed).expect("valid Ed25519 seed")
    }

    /// Sign a payload with a test keypair, returning the base64url signature.
    fn sign_payload(payload: &LicensePayload, keypair: &Ed25519KeyPair) -> String {
        let sig = keypair.sign(signable_string(payload).as_bytes());
        base64url_encode(sig.as_ref())
    }

    /// Build a signed license key string using a test keypair.
    fn create_test_license_key(
        keypair: &Ed25519KeyPair,
        customer: &str,
        expiry: DateTime<Utc>,
        features: Vec<String>,
    ) -> String {
        let payload = LicensePayload {
            signature: String::new(), // placeholder
            customer: customer.to_string(),
            expiry,
            features,
        };
        let sig = sign_payload(&payload, keypair);
        let payload = LicensePayload {
            signature: sig,
            ..payload
        };
        let json = serde_json::to_string(&payload).expect("license payload serializes");
        format!("PSEA-{}", base64url_encode(json.as_bytes()))
    }

    #[test]
    fn test_committed_public_key_parses() {
        let text = std::str::from_utf8(LICENSE_PUBLIC_KEY).expect("key file is UTF-8");
        let pk = ssh_key::PublicKey::from_openssh(text).expect("key parses as OpenSSH");
        let ed = match pk.key_data() {
            ssh_key::public::KeyData::Ed25519(ed) => ed,
            _ => panic!("committed key is not Ed25519"),
        };
        assert_eq!(ed.as_ref().len(), 32);
    }

    #[test]
    fn test_create_and_validate_roundtrip() {
        let keypair = test_keypair();
        let expiry = Utc::now() + chrono::Duration::days(365);
        let features = vec![FEAT_SAML.to_string(), FEAT_RBAC.to_string()];
        let key = create_test_license_key(&keypair, "Test Corp", expiry, features.clone());

        let lic = validate_license_with_key(&key, keypair.public_key().as_ref())
            .expect("valid key should validate");
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
    fn test_validate_rejects_tampered_signature() {
        let keypair = test_keypair();
        let key = create_test_license_key(
            &keypair,
            "Test",
            Utc::now() + chrono::Duration::days(365),
            vec![FEAT_SAML.to_string()],
        );

        // Flip a character in the signature (keep it valid base64url)
        let raw = key.strip_prefix("PSEA-").unwrap();
        let mut payload: LicensePayload =
            serde_json::from_slice(&decode_base64url(raw).unwrap()).unwrap();
        let mut sig: Vec<char> = payload.signature.chars().collect();
        for c in sig.iter_mut() {
            if *c != 'A' {
                *c = 'A';
                break;
            }
        }
        payload.signature = sig.into_iter().collect();
        let json = serde_json::to_string(&payload).unwrap();
        let tampered = format!("PSEA-{}", base64url_encode(json.as_bytes()));

        let result = validate_license_with_key(&tampered, keypair.public_key().as_ref());
        assert!(matches!(result, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn test_validate_rejects_wrong_key() {
        let signer = test_keypair();
        let other = test_keypair();
        let key = create_test_license_key(
            &signer,
            "Test",
            Utc::now() + chrono::Duration::days(365),
            vec![FEAT_SAML.to_string()],
        );

        let result = validate_license_with_key(&key, other.public_key().as_ref());
        assert!(matches!(result, Err(LicenseError::InvalidSignature)));
    }

    #[test]
    fn test_expired_license() {
        let keypair = test_keypair();
        let key = create_test_license_key(
            &keypair,
            "Expired Co",
            Utc::now() - chrono::Duration::days(1),
            vec![FEAT_SAML.to_string()],
        );

        let result = validate_license_with_key(&key, keypair.public_key().as_ref());
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
        let keypair = test_keypair();
        let key = create_test_license_key(
            &keypair,
            "Test",
            Utc::now() + chrono::Duration::days(365),
            vec![FEAT_SAML.to_string()],
        );

        let mgr = LicenseManager::new_with_public_key(Some(&key), keypair.public_key().as_ref());
        assert_eq!(mgr.status(), LicenseStatus::Valid);
        assert!(mgr.has_feature(FEAT_SAML));
        assert!(!mgr.has_feature(FEAT_RBAC));
        assert_eq!(mgr.raw_key(), Some(key));
    }

    #[test]
    fn test_license_manager_clear() {
        let keypair = test_keypair();
        let key = create_test_license_key(
            &keypair,
            "Test",
            Utc::now() + chrono::Duration::days(365),
            vec![FEAT_SAML.to_string()],
        );

        let mgr = LicenseManager::new_with_public_key(Some(&key), keypair.public_key().as_ref());
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
        let keypair = test_keypair();
        let key = create_test_license_key(
            &keypair,
            "Acme",
            Utc::now() + chrono::Duration::days(365),
            vec![],
        );
        assert!(key.starts_with("PSEA-"));
        // Key should be reasonably long (JSON payload + signature)
        assert!(key.len() > 50);
    }
}
