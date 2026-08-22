//! Self-signed TLS certificate generation (rcgen — no openssl dependency).
//!
//! Used by the CLI subcommands (`--init`, `generate-cert`) and by the serve
//! path's first-run auto-provisioning: when configured certificate paths are
//! absent on disk, a throwaway self-signed pair is generated there so the
//! server comes up over https instead of panicking on the missing files.

/// Generate a self-signed certificate/key pair and return the PEMs.
/// SANs always include `hostname`, `localhost`, and `127.0.0.1`, plus any
/// extras that are not already present.
fn generate_pair(hostname: &str, extra_sans: &[String]) -> Result<(String, String), String> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};

    let mut sans = vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    for san in extra_sans {
        if !sans.contains(san) {
            sans.push(san.clone());
        }
    }

    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(sans)
        .map_err(|e| format!("certificate generation failed: {}", e))?;

    Ok((cert.pem(), signing_key.serialize_pem()))
}

/// The private key must not be world-readable: 0600 on Unix (a no-op
/// elsewhere, where the file inherits the directory ACL).
fn restrict_key_permissions(key_path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = key_path;
    }
}

/// Generate a self-signed certificate (rcgen — no openssl) and write
/// cert.pem/key.pem into `out_dir`. localhost and 127.0.0.1 are always in
/// the SANs. Returns the written paths.
pub fn write_self_signed_cert(
    hostname: &str,
    out_dir: &std::path::Path,
    extra_sans: &[String],
) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let (cert_pem, key_pem) = generate_pair(hostname, extra_sans)?;

    let cert_path = out_dir.join("cert.pem");
    let key_path = out_dir.join("key.pem");

    std::fs::write(&cert_path, cert_pem).map_err(|e| format!("failed to write cert.pem: {}", e))?;
    std::fs::write(&key_path, key_pem).map_err(|e| format!("failed to write key.pem: {}", e))?;
    restrict_key_permissions(&key_path);

    Ok((cert_path, key_path))
}

/// Ensure a certificate pair exists at exactly `cert_path`/`key_path`,
/// generating a self-signed pair only when either file is missing. Existing
/// files are never overwritten, so operator-provided certificates survive.
/// Returns true when a pair was generated.
pub fn ensure_self_signed_pair(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    hostname: &str,
    extra_sans: &[String],
) -> Result<bool, String> {
    if cert_path.exists() && key_path.exists() {
        return Ok(false);
    }

    let (cert_pem, key_pem) = generate_pair(hostname, extra_sans)?;
    std::fs::write(cert_path, cert_pem)
        .map_err(|e| format!("failed to write {}: {}", cert_path.display(), e))?;
    std::fs::write(key_path, key_pem)
        .map_err(|e| format!("failed to write {}: {}", key_path.display(), e))?;
    restrict_key_permissions(key_path);

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch directory under the OS temp dir, removed on drop. Hand-rolled
    /// (no tempfile dev-dependency): unique enough via pid plus wall clock.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let dir = std::env::temp_dir().join(format!(
                "persea-tls-gen-{}-{}-{}",
                tag,
                std::process::id(),
                nanos
            ));
            std::fs::create_dir_all(&dir).expect("failed to create scratch dir");
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn generates_when_missing() {
        let tmp = TempDir::new("generate");
        let cert = tmp.0.join("cert.pem");
        let key = tmp.0.join("key.pem");

        let generated =
            ensure_self_signed_pair(&cert, &key, "persea.test", &[]).expect("generation succeeds");

        assert!(generated);
        assert!(cert.exists(), "cert.pem must be created");
        assert!(key.exists(), "key.pem must be created");
        let pem = std::fs::read_to_string(&cert).expect("cert readable");
        assert!(pem.contains("BEGIN CERTIFICATE"), "cert.pem holds PEM data");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&key)
                .expect("key metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "private key must be owner-only");
        }
    }

    #[test]
    fn present_files_are_untouched() {
        let tmp = TempDir::new("present");
        let cert = tmp.0.join("cert.pem");
        let key = tmp.0.join("key.pem");
        std::fs::write(&cert, "pre-existing cert\n").expect("seed cert");
        std::fs::write(&key, "pre-existing key\n").expect("seed key");

        let generated =
            ensure_self_signed_pair(&cert, &key, "persea.test", &[]).expect("no-op succeeds");

        assert!(!generated, "existing pair must not be regenerated");
        assert_eq!(
            std::fs::read_to_string(&cert).expect("cert readable"),
            "pre-existing cert\n",
            "mounted cert must not be overwritten"
        );
        assert_eq!(
            std::fs::read_to_string(&key).expect("key readable"),
            "pre-existing key\n",
            "mounted key must not be overwritten"
        );
    }
}
