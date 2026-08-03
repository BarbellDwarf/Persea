//! Password hashing utilities — Argon2id with OWASP-recommended parameters.
//!
//! Default: 46 MiB memory, 3 iterations, 1 parallelism, 32-byte output.

use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};

/// OWASP-recommended Argon2id parameters.
const OWASP_MEMORY_KIB: u32 = 46 * 1024; // 46 MiB
const OWASP_ITERATIONS: u32 = 3;
const OWASP_PARALLELISM: u32 = 1;

/// Hash a plaintext password using Argon2id with OWASP parameters.
///
/// Returns a PHC-encoded string containing the hash and all parameters.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(OWASP_MEMORY_KIB, OWASP_ITERATIONS, OWASP_PARALLELISM, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against a stored PHC hash string.
///
/// Parameters are auto-detected from the stored hash — no need to supply
/// the same OWASP params at verify time.
pub fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_and_verify_roundtrip() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h).unwrap());
        assert!(!verify_password("wrong", &h).unwrap());
    }

    #[test]
    fn different_hashes_for_same_password() {
        let h1 = hash_password("same").unwrap();
        let h2 = hash_password("same").unwrap();
        // Different salts → different hash strings
        assert_ne!(h1, h2);
        // But both verify
        assert!(verify_password("same", &h1).unwrap());
        assert!(verify_password("same", &h2).unwrap());
    }

    #[test]
    fn hash_contains_argon2id_marker() {
        let h = hash_password("test").unwrap();
        assert!(h.starts_with("$argon2id$"));
    }

    #[test]
    fn reject_invalid_hash_string() {
        assert!(verify_password("pw", "not-a-hash").is_err());
    }
}
