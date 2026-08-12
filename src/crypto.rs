use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::Engine as _;

/// 12-byte nonce size for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Tag length (bytes) appended by aes-gcm.
const TAG_LEN: usize = 16;

/// Prefix for encrypted values to allow future key rotation / format changes.
const ENC_PREFIX: &str = "enc:v1:";

/// Holds a 32-byte AES-256 key.
#[derive(Clone)]
pub struct EncryptionKey {
    key: Key<Aes256Gcm>,
}

impl EncryptionKey {
    /// Create from a 32-byte raw key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            key: Key::<Aes256Gcm>::try_from(bytes.as_slice()).expect("key length mismatch"),
        }
    }

    /// Create from a 64-character hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "encryption key must be 32 bytes (got {})",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }
}

/// Errors during encryption / decryption.
#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum CryptoError {
    /// The key is not valid hex, or is not 32 bytes long.
    #[error("invalid encryption key: {0}")]
    InvalidKey(String),
    /// The value lacks the `enc:v1:` prefix or is too short to decrypt.
    #[error("ciphertext format invalid: {0}")]
    InvalidCiphertext(String),
    /// AES-256-GCM encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    /// Decryption failed, including authentication-tag mismatches.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
}

/// Encrypt plaintext with AES-256-GCM.
///
/// Returns `enc:v1:<base64(nonce || ciphertext || tag)>`.
pub fn encrypt_value(key: &EncryptionKey, plaintext: &str) -> Result<String, CryptoError> {
    let cipher = Aes256Gcm::new(&key.key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes[..]);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce length mismatch");

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    // ciphertext already includes the 16-byte auth tag from aes-gcm
    let mut buf = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    buf.extend_from_slice(&nonce_bytes);
    buf.extend_from_slice(&ciphertext);

    let b64 = base64::engine::general_purpose::STANDARD.encode(&buf);
    Ok(format!("{ENC_PREFIX}{b64}"))
}

/// Decrypt an `enc:v1:` prefixed value back to plaintext.
pub fn decrypt_value(key: &EncryptionKey, encrypted: &str) -> Result<String, CryptoError> {
    let b64 = encrypted
        .strip_prefix(ENC_PREFIX)
        .ok_or_else(|| CryptoError::InvalidCiphertext("missing enc:v1: prefix".into()))?;

    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CryptoError::InvalidCiphertext(e.to_string()))?;

    if raw.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::InvalidCiphertext(format!(
            "encoded data too short ({} bytes, need at least {})",
            raw.len(),
            NONCE_LEN + TAG_LEN
        )));
    }

    let (nonce_bytes, ciphertext) = raw.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| CryptoError::InvalidCiphertext("nonce length mismatch".into()))?;

    let cipher = Aes256Gcm::new(&key.key);
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    String::from_utf8(plaintext)
        .map_err(|e| CryptoError::DecryptionFailed(format!("invalid UTF-8: {e}")))
}

/// Encrypt raw bytes using AES-256-GCM.
///
/// Returns `nonce (12 bytes) || ciphertext || tag (16 bytes)`.
pub fn encrypt_bytes(key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new(&key.key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::fill(&mut nonce_bytes[..]);
    let nonce = Nonce::try_from(nonce_bytes.as_slice()).expect("nonce length mismatch");

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt raw bytes encrypted with [`encrypt_bytes`].
pub fn decrypt_bytes(key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::DecryptionFailed(format!(
            "data too short ({} bytes, need at least {})",
            data.len(),
            NONCE_LEN + TAG_LEN,
        )));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|_| CryptoError::InvalidCiphertext("nonce length mismatch".into()))?;

    let cipher = Aes256Gcm::new(&key.key);
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Returns `true` if the value starts with the `enc:v1:` encryption prefix.
pub fn is_encrypted(value: &str) -> bool {
    value.starts_with(ENC_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EncryptionKey {
        EncryptionKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let plaintext = "s3cret-password";
        let enc = encrypt_value(&key, plaintext).unwrap();
        assert!(is_encrypted(&enc));
        let dec = decrypt_value(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn different_nonces_each_time() {
        let key = test_key();
        let enc1 = encrypt_value(&key, "same").unwrap();
        let enc2 = encrypt_value(&key, "same").unwrap();
        // encodings differ because nonces are random
        assert_ne!(enc1, enc2);
        // but both decrypt to the same plaintext
        assert_eq!(decrypt_value(&key, &enc1).unwrap(), "same");
        assert_eq!(decrypt_value(&key, &enc2).unwrap(), "same");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = EncryptionKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let key2 = EncryptionKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let enc = encrypt_value(&key1, "secret").unwrap();
        assert!(decrypt_value(&key2, &enc).is_err());
    }

    #[test]
    fn is_encrypted_checks_prefix() {
        assert!(is_encrypted("enc:v1:AAAA"));
        assert!(!is_encrypted("plaintext"));
        assert!(!is_encrypted(""));
    }

    #[test]
    fn bad_prefix_rejected() {
        let key = test_key();
        assert!(decrypt_value(&key, "not-encrypted").is_err());
    }

    #[test]
    fn from_hex_wrong_length() {
        assert!(EncryptionKey::from_hex("aabb").is_err());
    }

    #[test]
    fn from_hex_invalid_hex() {
        assert!(EncryptionKey::from_hex("zzzz").is_err());
    }

    #[test]
    fn roundtrip_empty_string() {
        let key = test_key();
        let enc = encrypt_value(&key, "").unwrap();
        let dec = decrypt_value(&key, &enc).unwrap();
        assert_eq!(dec, "");
    }

    #[test]
    fn roundtrip_long_string() {
        let key = test_key();
        let plaintext = "x".repeat(10_000);
        let enc = encrypt_value(&key, &plaintext).unwrap();
        let dec = decrypt_value(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_decrypt_bytes_roundtrip() {
        let key = test_key();
        let plaintext = b"binary data \x00\x01\x02\xff";
        let enc = encrypt_bytes(&key, plaintext).unwrap();
        assert_ne!(enc, plaintext);
        let dec = decrypt_bytes(&key, &enc).unwrap();
        assert_eq!(dec, plaintext);
    }

    #[test]
    fn encrypt_decrypt_bytes_empty() {
        let key = test_key();
        let enc = encrypt_bytes(&key, b"").unwrap();
        let dec = decrypt_bytes(&key, &enc).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn encrypt_decrypt_bytes_different_nonces() {
        let key = test_key();
        let enc1 = encrypt_bytes(&key, b"same").unwrap();
        let enc2 = encrypt_bytes(&key, b"same").unwrap();
        assert_ne!(enc1, enc2);
        assert_eq!(decrypt_bytes(&key, &enc1).unwrap(), b"same");
        assert_eq!(decrypt_bytes(&key, &enc2).unwrap(), b"same");
    }

    #[test]
    fn decrypt_bytes_wrong_key_fails() {
        let key1 = EncryptionKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();
        let key2 = EncryptionKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000002",
        )
        .unwrap();
        let enc = encrypt_bytes(&key1, b"secret").unwrap();
        assert!(decrypt_bytes(&key2, &enc).is_err());
    }

    #[test]
    fn decrypt_bytes_too_short() {
        let key = test_key();
        assert!(decrypt_bytes(&key, &[]).is_err());
        assert!(decrypt_bytes(&key, &[0u8; 5]).is_err());
        assert!(decrypt_bytes(&key, &[0u8; 27]).is_err());
    }
}
