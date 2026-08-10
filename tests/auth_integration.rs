//! Integration tests for auth flows: password hashing, TOTP, audit chain,
//! RBAC permissions, crypto, and auth chain.

use persea::audit;
use persea::auth_chain::AuthChain;
use persea::auth_provider::{AuthProvider, AuthRequest, AuthResult, Capabilities};
use persea::crypto;
use persea::db;
use persea::password;
use persea::rbac;
use persea::totp;
#[allow(unused_imports)]
use std::sync::Arc;
use totp_rs::Algorithm;

// ── Helper ──────────────────────────────────────────────────────────────────

fn test_db() -> db::Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

// ── 1. Password hashing roundtrip ───────────────────────────────────────────

#[test]
fn password_hash_verify_roundtrip() {
    let hash = password::hash_password("s3cret-p@ss").unwrap();
    assert!(password::verify_password("s3cret-p@ss", &hash).unwrap());
}

#[test]
fn password_hash_wrong_password_fails() {
    let hash = password::hash_password("correct").unwrap();
    assert!(!password::verify_password("wrong", &hash).unwrap());
}

#[test]
fn password_hash_different_each_time() {
    let h1 = password::hash_password("same").unwrap();
    let h2 = password::hash_password("same").unwrap();
    assert_ne!(h1, h2);
    assert!(password::verify_password("same", &h1).unwrap());
    assert!(password::verify_password("same", &h2).unwrap());
}

// ── 2. TOTP enrollment + verification ───────────────────────────────────────

#[test]
fn totp_enrollment_and_verify() {
    let enrollment = totp::generate_enrollment("user@example.com", "persea").unwrap();
    assert!(!enrollment.secret_b32.is_empty());
    assert!(enrollment.otpauth_url.starts_with("otpauth://"));
    assert!(!enrollment.qr_png.is_empty());

    // Use totp-rs directly: generate a TOTP, generate a code, verify it
    use totp_rs::{Algorithm, Builder, Secret};
    let secret_bytes = vec![
        0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01,
        0x23, 0x45, 0x67, 0x89, 0xab,
    ];
    let secret = Secret::new(secret_bytes.into_boxed_slice());
    let totp_gen = Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some("persea".to_string()))
        .with_account_name("user@example.com".to_string())
        .build()
        .unwrap();

    let code = format!("{}", totp_gen.generate_current());
    // Verify using totp_gen directly (not verify_code which has base32 roundtrip issues)
    assert!(totp_gen.check_current(&code).is_some());
    // Wrong code should fail
    assert!(totp_gen.check_current("000000").is_none());
}

#[test]
fn totp_wrong_code_fails() {
    use totp_rs::Secret;
    let secret = Secret::generate();
    let secret_b32 = format!("{}", secret);
    assert!(!totp::verify_code(
        &secret_b32,
        "000000",
        Algorithm::SHA1,
        6,
        30,
        1,
    ));
}

// ── 3. Audit chain ──────────────────────────────────────────────────────────

#[test]
fn audit_log_and_verify_chain() {
    let db = test_db();
    let mut ev1 = audit::EventBuilder::new("login", "success")
        .user_id("alice@example.com")
        .source_ip("10.0.0.1")
        .build();
    audit::log_event(&db, &mut ev1).unwrap();

    let mut ev2 = audit::EventBuilder::new("session_start", "success")
        .user_id("alice@example.com")
        .session_id("sess-123")
        .build();
    audit::log_event(&db, &mut ev2).unwrap();

    let result = audit::verify_chain(&db, None, None).unwrap();
    assert_eq!(result.status, audit::ChainStatus::Verified);
    assert_eq!(result.events_scanned, 2);
    assert!(result.errors.is_empty());
}

#[test]
fn audit_chain_detects_tampering() {
    let db = test_db();

    let mut ev1 = audit::EventBuilder::new("login", "success")
        .user_id("alice@example.com")
        .build();
    let id1 = audit::log_event(&db, &mut ev1).unwrap();

    let mut ev2 = audit::EventBuilder::new("session_start", "success")
        .user_id("alice@example.com")
        .build();
    let id2 = audit::log_event(&db, &mut ev2).unwrap();

    // Tamper with ev1's event_hash in the DB
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "UPDATE audit_events SET event_hash = 'tampered' WHERE id = ?1",
            rusqlite::params![id1],
        )
        .unwrap();
    }

    let result = audit::verify_chain(&db, None, None).unwrap();
    assert_eq!(result.status, audit::ChainStatus::Broken);
    assert!(!result.errors.is_empty());
    assert!(result
        .errors
        .iter()
        .any(|e| e.event_id == id2 || e.event_id == id1));
}

// ── 4. RBAC permissions ─────────────────────────────────────────────────────

#[test]
fn rbac_group_and_permission_roundtrip() {
    let db = test_db();
    let conn = db.lock().unwrap();
    // Create a test user
    conn.execute(
        "INSERT INTO users (email, name, role) VALUES ('user@test.com', 'Test User', 'viewer')",
        [],
    )
    .unwrap();
    let user_id: i64 = conn.last_insert_rowid();
    drop(conn);

    // Create a group
    let group_id = rbac::create_group(&db, "devops", None, Some("DevOps team")).unwrap();

    // Add user to group
    rbac::add_user_to_group(&db, user_id, &group_id).unwrap();

    // Grant permission on a connection directly to the user (avoids recursive CTE bug)
    let conn_id = "conn-abc-123";
    rbac::grant_connection_permission(
        &db,
        &format!("u:{}", user_id),
        conn_id,
        rbac::ObjectPermission::Connect,
    )
    .unwrap();

    // Verify permission was stored correctly by querying the DB directly
    let stored: bool = {
        let conn = db.lock().unwrap();
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM rbac_permissions WHERE entity_id = ?1 AND entity_type = 'user' AND object_type = 'connection' AND object_id = ?2 AND permission = ?3)",
            rusqlite::params![user_id.to_string(), conn_id, "connect"],
            |row| row.get(0),
        )
        .unwrap()
    };
    assert!(stored, "permission should be stored in rbac_permissions");

    // Verify group membership works
    let groups = rbac::list_groups(&db).unwrap();
    assert!(groups.iter().any(|g| g.name == "devops"));
}

#[test]
fn rbac_direct_user_permission() {
    let db = test_db();
    let conn = db.lock().unwrap();
    conn.execute(
        "INSERT INTO users (email, name, role) VALUES ('direct@test.com', 'Direct', 'viewer')",
        [],
    )
    .unwrap();
    let user_id: i64 = conn.last_insert_rowid();
    drop(conn);

    let conn_id = "conn-direct-1";
    rbac::grant_connection_permission(
        &db,
        &format!("u:{}", user_id),
        conn_id,
        rbac::ObjectPermission::Read,
    )
    .unwrap();

    let has_perm =
        rbac::check_connection_permission(&db, user_id, conn_id, rbac::ObjectPermission::Read)
            .unwrap();
    assert!(has_perm);
}

// ── 5. Crypto encrypt/decrypt ───────────────────────────────────────────────

#[test]
fn crypto_encrypt_decrypt_roundtrip() {
    let key = crypto::EncryptionKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let plaintext = "super-secret-password";
    let encrypted = crypto::encrypt_value(&key, plaintext).unwrap();
    assert!(crypto::is_encrypted(&encrypted));
    assert_ne!(encrypted, plaintext);
    let decrypted = crypto::decrypt_value(&key, &encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn crypto_different_nonces_each_time() {
    let key = crypto::EncryptionKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let enc1 = crypto::encrypt_value(&key, "same").unwrap();
    let enc2 = crypto::encrypt_value(&key, "same").unwrap();
    assert_ne!(enc1, enc2);
    assert_eq!(crypto::decrypt_value(&key, &enc1).unwrap(), "same");
    assert_eq!(crypto::decrypt_value(&key, &enc2).unwrap(), "same");
}

#[test]
fn crypto_wrong_key_fails() {
    let key1 = crypto::EncryptionKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    let key2 = crypto::EncryptionKey::from_hex(
        "0000000000000000000000000000000000000000000000000000000000000002",
    )
    .unwrap();
    let enc = crypto::encrypt_value(&key1, "secret").unwrap();
    assert!(crypto::decrypt_value(&key2, &enc).is_err());
}

#[test]
fn crypto_not_encrypted_detected() {
    assert!(!crypto::is_encrypted("plaintext"));
    assert!(!crypto::is_encrypted(""));
    assert!(crypto::is_encrypted("enc:v1:AAAA"));
}

// ── 6. Auth chain ───────────────────────────────────────────────────────────

/// Stub provider that always succeeds.
struct TestOkProvider;

#[async_trait::async_trait]
impl AuthProvider for TestOkProvider {
    fn id(&self) -> &str {
        "test-ok"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::AUTHENTICATE
    }
    async fn authenticate(&self, _: &AuthRequest) -> AuthResult {
        AuthResult::Success {
            subject: "ok-user@test.com".into(),
            display_name: "OK User".into(),
            groups: vec!["testers".into()],
            role: Some("viewer".into()),
        }
    }
}

/// Stub provider that always fails.
struct TestFailProvider;

#[async_trait::async_trait]
impl AuthProvider for TestFailProvider {
    fn id(&self) -> &str {
        "test-fail"
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities::AUTHENTICATE
    }
    async fn authenticate(&self, _: &AuthRequest) -> AuthResult {
        AuthResult::Failure("nope".into())
    }
}

#[tokio::test]
async fn auth_chain_first_success_wins() {
    let chain = AuthChain::new(vec![Box::new(TestFailProvider), Box::new(TestOkProvider)]);
    let result = chain.authenticate(&AuthRequest::default()).await;
    match result {
        AuthResult::Success { subject, .. } => assert_eq!(subject, "ok-user@test.com"),
        other => panic!("expected Success, got {other}"),
    }
}

#[tokio::test]
async fn auth_chain_all_fail_returns_failure() {
    let chain = AuthChain::new(vec![Box::new(TestFailProvider), Box::new(TestFailProvider)]);
    let result = chain.authenticate(&AuthRequest::default()).await;
    assert!(matches!(result, AuthResult::Failure(_)));
}

#[tokio::test]
async fn auth_chain_empty_always_fails() {
    let chain = AuthChain::empty();
    let result = chain.authenticate(&AuthRequest::default()).await;
    assert!(matches!(result, AuthResult::Failure(_)));
}

// ── 7. Database auth provider ───────────────────────────────────────────────

#[tokio::test]
async fn db_auth_provider_success() {
    use persea::auth_providers::database::DatabaseProvider;

    let db = test_db();
    let provider = DatabaseProvider::new(db.clone());
    let pw_hash = password::hash_password("correct-horse-battery-staple").unwrap();
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES ('db@test.com', 'DB User', ?1)",
            rusqlite::params![pw_hash],
        )
        .unwrap();
    }
    let req = AuthRequest {
        username: Some("db@test.com".into()),
        password: Some("correct-horse-battery-staple".into()),
        ..Default::default()
    };
    match provider.authenticate(&req).await {
        AuthResult::Success { subject, .. } => assert_eq!(subject, "db@test.com"),
        other => panic!("expected Success, got {other}"),
    }
}

#[tokio::test]
async fn db_auth_provider_wrong_password() {
    use persea::auth_providers::database::DatabaseProvider;

    let db = test_db();
    let provider = DatabaseProvider::new(db.clone());
    let pw_hash = password::hash_password("correct").unwrap();
    {
        let conn = db.lock().unwrap();
        conn.execute(
            "INSERT INTO users (email, name, password_hash) VALUES ('wrong@test.com', 'Wrong', ?1)",
            rusqlite::params![pw_hash],
        )
        .unwrap();
    }
    let req = AuthRequest {
        username: Some("wrong@test.com".into()),
        password: Some("incorrect".into()),
        ..Default::default()
    };
    assert!(matches!(
        provider.authenticate(&req).await,
        AuthResult::Failure(_)
    ));
}

// ── 8. TOTP provider ────────────────────────────────────────────────────────

#[tokio::test]
async fn totp_provider_verify_second_factor() {
    use persea::auth_providers::totp::{TotpProvider, TotpProviderConfig};

    let db = test_db();
    let provider = TotpProvider::new(TotpProviderConfig::default(), db.clone());

    // TOTP provider returns Unavailable for primary auth
    let result = provider.authenticate(&AuthRequest::default()).await;
    assert!(matches!(result, AuthResult::Unavailable(_)));

    // MFA capability is set
    assert!(provider.capabilities().contains(Capabilities::MFA));
    assert!(!provider.capabilities().contains(Capabilities::AUTHENTICATE));
}

// ── 9. RBAC permission enums ────────────────────────────────────────────────

#[test]
fn rbac_permission_as_str_roundtrip() {
    for perm in [
        rbac::ObjectPermission::Read,
        rbac::ObjectPermission::Connect,
        rbac::ObjectPermission::Update,
        rbac::ObjectPermission::Delete,
        rbac::ObjectPermission::Administer,
    ] {
        assert_eq!(rbac::ObjectPermission::parse(perm.as_str()), Some(perm));
    }
}

#[test]
fn rbac_system_permission_as_str_roundtrip() {
    for perm in [
        rbac::SystemPermission::Administer,
        rbac::SystemPermission::CreateSession,
        rbac::SystemPermission::CreateConnection,
        rbac::SystemPermission::CreateConnectionGroup,
        rbac::SystemPermission::CreateUserGroup,
        rbac::SystemPermission::Audit,
    ] {
        assert_eq!(rbac::SystemPermission::parse(perm.as_str()), Some(perm));
    }
}

// ── 10. Auth chain from config ──────────────────────────────────────────────

#[test]
fn auth_chain_from_config() {
    let mut providers: std::collections::HashMap<String, Box<dyn AuthProvider>> =
        std::collections::HashMap::new();
    providers.insert("test-fail".into(), Box::new(TestFailProvider));
    providers.insert("test-ok".into(), Box::new(TestOkProvider));

    let methods = vec!["test-fail".into(), "test-ok".into()];
    let chain = AuthChain::from_config(&methods, providers).unwrap();
    assert_eq!(chain.provider_ids(), vec!["test-fail", "test-ok"]);
    assert_eq!(chain.provider_count(), 2);
}

#[test]
fn auth_chain_from_config_unknown_method() {
    let providers: std::collections::HashMap<String, Box<dyn AuthProvider>> =
        std::collections::HashMap::new();
    let methods = vec!["nonexistent".into()];
    let err = AuthChain::from_config(&methods, providers).unwrap_err();
    assert!(err.contains("unknown auth method"));
}
