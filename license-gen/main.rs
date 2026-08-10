//! Offline enterprise license key generator for persea (vendor tool).
//!
//! The server binary embeds only the Ed25519 public key
//! (`keys/license_public_key`) and cannot sign; this tool signs license keys
//! with the private key, which never leaves the vendor's machine.
//!
//! License format (shared with src/license.rs): `PSEA-<base64url JSON>`
//! where the JSON payload is `{"signature","customer","expiry","features"}`
//! and the Ed25519 signature covers `signable_string` from the persea lib.
//!
//! Usage:
//!   license_gen gen-keypair [--output <path>]
//!   license_gen issue --customer <name> --expiry <date> [--features <csv>]
//!                    [--private-key <path>]
//!
//! The private key may be given via `--private-key <path>` (OpenSSH format,
//! as produced by `ssh-keygen -t ed25519` or `gen-keypair`) or the
//! `PERSEA_LICENSE_PRIVATE_KEY` environment variable.

use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use persea::license::{base64url_encode, signable_string, ALL_FEATURES, LicensePayload};
use ring::rand::SecureRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use ssh_key::private::KeypairData;
use ssh_key::rand_core::{impls, CryptoRng, RngCore};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Environment variable holding the private key (OpenSSH format) as an
/// alternative to `--private-key`.
const PRIVATE_KEY_ENV: &str = "PERSEA_LICENSE_PRIVATE_KEY";

/// Default output path for `gen-keypair`.
const DEFAULT_KEY_PATH: &str = "license_ed25519";

/// Error shown when the supplied key is not an Ed25519 key.
const WRONG_KEY_TYPE_MSG: &str =
    "private key is not an Ed25519 key (expected an OpenSSH ed25519 key)";

/// Adapter implementing rand_core's RNG traits over ring's SystemRandom so
/// ssh-key can generate keys from the OS CSPRNG.
struct SystemRng(ring::rand::SystemRandom);

impl RngCore for SystemRng {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill(dest).expect("OS randomness failure");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), ssh_key::rand_core::Error> {
        self.0
            .fill(dest)
            .map_err(|_| ssh_key::rand_core::Error::new("OS randomness failure"))
    }
}

impl CryptoRng for SystemRng {}

#[derive(Parser)]
#[command(
    name = "license_gen",
    version,
    about = "Generate persea enterprise license keys"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 keypair in OpenSSH format
    GenKeypair {
        /// Output path for the private key file
        #[arg(long, default_value = DEFAULT_KEY_PATH)]
        output: PathBuf,
    },
    /// Issue a signed enterprise license key
    Issue {
        /// Customer or organization name
        #[arg(long)]
        customer: String,
        /// Expiry date (ISO 8601: YYYY-MM-DD or RFC 3339)
        #[arg(long)]
        expiry: String,
        /// Comma-separated enterprise features (saml, rbac, totp, audit_retention, encrypted_recording, ha)
        #[arg(long, default_value = "")]
        features: String,
        /// Path to the Ed25519 private key (OpenSSH format)
        #[arg(long)]
        private_key: Option<PathBuf>,
    },
    /// Verify a license key against the embedded public key
    Verify {
        /// The license key to verify (PSEA-...)
        #[arg(long)]
        key: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::GenKeypair { output } => gen_keypair(&output),
        Command::Issue {
            customer,
            expiry,
            features,
            private_key,
        } => issue(&customer, &expiry, &features, private_key.as_deref()),
        Command::Verify { key } => verify(&key),
    };
    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn verify(key: &str) -> Result<(), String> {
    match persea::license::validate_license(key) {
        Ok(lic) => {
            println!(
                "valid: customer={} expiry={} features={}",
                lic.customer_name,
                lic.expiry,
                lic.features.join(",")
            );
            Ok(())
        }
        Err(e) => Err(format!("invalid license: {e}")),
    }
}

fn gen_keypair(output: &Path) -> Result<(), String> {
    let mut rng = SystemRng(ring::rand::SystemRandom::new());
    let mut key = ssh_key::PrivateKey::random(&mut rng, ssh_key::Algorithm::Ed25519)
        .map_err(|e| format!("failed to generate keypair: {e}"))?;
    key.set_comment("persea-license-key");

    let pem = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| format!("failed to encode private key: {e}"))?;
    write_private_key_file(output, pem.as_bytes())?;

    let public = key
        .public_key()
        .to_openssh()
        .map_err(|e| format!("failed to encode public key: {e}"))?;
    println!("{public}");
    eprintln!("private key written to {} (mode 0600)", output.display());
    eprintln!("embed the public key above in keys/license_public_key");
    Ok(())
}

fn issue(
    customer: &str,
    expiry: &str,
    features_csv: &str,
    key_path: Option<&Path>,
) -> Result<(), String> {
    if customer.trim().is_empty() {
        return Err("customer must not be empty".into());
    }
    let features = parse_features(features_csv)?;
    let expiry = parse_expiry(expiry)?;
    let key = load_private_key(key_path)?;
    let license = sign_license(&key, customer, expiry, &features)?;
    println!("{license}");
    Ok(())
}

fn parse_features(csv: &str) -> Result<Vec<String>, String> {
    let mut features = Vec::new();
    for f in csv.split(',').map(str::trim) {
        if f.is_empty() {
            continue;
        }
        if !ALL_FEATURES.contains(&f) {
            return Err(format!(
                "unknown feature '{f}' (valid features: {})",
                ALL_FEATURES.join(", ")
            ));
        }
        features.push(f.to_string());
    }
    Ok(features)
}

fn parse_expiry(input: &str) -> Result<DateTime<Utc>, String> {
    if let Ok(dt) = DateTime::parse_from_rfc3339(input) {
        return Ok(dt.with_timezone(&Utc));
    }
    let date = NaiveDate::parse_from_str(input, "%Y-%m-%d").map_err(|_| {
        format!("invalid expiry '{input}': expected YYYY-MM-DD or an RFC 3339 timestamp")
    })?;
    date.and_hms_opt(0, 0, 0)
        .map(|ndt| ndt.and_utc())
        .ok_or_else(|| format!("invalid expiry '{input}'"))
}

fn load_private_key(path: Option<&Path>) -> Result<ssh_key::PrivateKey, String> {
    let (source, pem) = match path {
        Some(path) => {
            let pem = std::fs::read_to_string(path)
                .map_err(|e| format!("failed to read private key {}: {e}", path.display()))?;
            (path.display().to_string(), pem)
        }
        None => {
            let pem = std::env::var(PRIVATE_KEY_ENV).map_err(|_| {
                format!("no private key: pass --private-key <path> or set {PRIVATE_KEY_ENV}")
            })?;
            (format!("${PRIVATE_KEY_ENV}"), pem)
        }
    };
    ssh_key::PrivateKey::from_openssh(pem.as_bytes())
        .map_err(|e| format!("invalid private key ({source}): {e}"))
}

fn sign_license(
    key: &ssh_key::PrivateKey,
    customer: &str,
    expiry: DateTime<Utc>,
    features: &[String],
) -> Result<String, String> {
    let keypair = match key.key_data() {
        KeypairData::Ed25519(ed) => ed,
        _ => return Err(WRONG_KEY_TYPE_MSG.into()),
    };

    let signing = Ed25519KeyPair::from_seed_unchecked(keypair.private.as_ref())
        .map_err(|e| format!("invalid Ed25519 private key: {e}"))?;
    if signing.public_key().as_ref() != keypair.public.as_ref() {
        return Err("private key does not match its public half — refusing to sign".into());
    }

    let payload = LicensePayload {
        signature: String::new(), // placeholder
        customer: customer.to_string(),
        expiry,
        features: features.to_vec(),
    };
    let signable = signable_string(&payload);
    let sig_bytes = signing.sign(signable.as_bytes());
    let public_key = signing.public_key().as_ref();
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(signable.as_bytes(), sig_bytes.as_ref())
        .map_err(|_| "self-verification failed — refusing to issue".to_string())?;

    let payload = LicensePayload {
        signature: base64url_encode(sig_bytes.as_ref()),
        ..payload
    };
    let json =
        serde_json::to_string(&payload).map_err(|e| format!("failed to serialize license: {e}"))?;
    Ok(format!("PSEA-{}", base64url_encode(json.as_bytes())))
}

fn write_private_key_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = open_private_key_file(path)?;
    file.write_all(contents)
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn open_private_key_file(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn open_private_key_file(path: &Path) -> Result<std::fs::File, String> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("failed to create {}: {e}", path.display()))
}
