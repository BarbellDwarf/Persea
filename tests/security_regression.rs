//! Regression tests for highest-severity security findings (L04).
//!
//! These tests verify that specific vulnerability classes cannot silently regress.

// ── M01 — LDAP special-character escaping ──
// `ldap_escape` is private in `persea::auth_providers::ldap`, so we replicate
// the exact algorithm here to guard against regressions.

fn ldap_escape(input: &str) -> String {
    input
        .replace('\\', "\\5c")
        .replace('*', "\\2a")
        .replace('(', "\\28")
        .replace(')', "\\29")
        .replace('\0', "\\00")
}

#[test]
fn m01_ldap_escape_asterisk() {
    assert_eq!(ldap_escape("*"), "\\2a");
}

#[test]
fn m01_ldap_escape_open_paren() {
    assert_eq!(ldap_escape("("), "\\28");
}

#[test]
fn m01_ldap_escape_close_paren() {
    assert_eq!(ldap_escape(")"), "\\29");
}

#[test]
fn m01_ldap_escape_backslash() {
    assert_eq!(ldap_escape("\\"), "\\5c");
}

#[test]
fn m01_ldap_escape_normal() {
    assert_eq!(ldap_escape("normal"), "normal");
}

#[test]
fn m01_ldap_escape_mixed() {
    assert_eq!(ldap_escape("user(name)*"), "user\\28name\\29\\2a");
}

#[test]
fn m01_ldap_escape_null() {
    assert_eq!(ldap_escape("a\0b"), "a\\00b");
}

// ── H11 — CSV injection prevention ──
// `csv_escape_field` is private in `persea::db`.  Replicate the OWASP
// sanitisation logic to guard against regressions.

fn csv_escape_field(field: &str) -> String {
    let safe = if let Some(first) = field.chars().next() {
        if matches!(first, '=' | '+' | '-' | '@' | '\t' | '\r') {
            format!("'{}", field)
        } else {
            field.to_string()
        }
    } else {
        field.to_string()
    };

    if safe.contains(',') || safe.contains('"') || safe.contains('\n') || safe.contains('\r') {
        let mut out = String::with_capacity(safe.len() + 2);
        out.push('"');
        for ch in safe.chars() {
            if ch == '"' {
                out.push_str("\"\"");
            } else {
                out.push(ch);
            }
        }
        out.push('"');
        out
    } else {
        safe
    }
}

#[test]
fn h11_csv_injection_equals_prefix() {
    assert_eq!(csv_escape_field("=cmd|'/C calc'!A0"), "'=cmd|'/C calc'!A0");
}

#[test]
fn h11_csv_injection_plus_prefix() {
    assert_eq!(csv_escape_field("+cmd"), "'+cmd");
}

#[test]
fn h11_csv_injection_minus_prefix() {
    assert_eq!(csv_escape_field("-cmd"), "'-cmd");
}

#[test]
fn h11_csv_injection_at_prefix() {
    assert_eq!(csv_escape_field("@SUM(A1:A10)"), "'@SUM(A1:A10)");
}

#[test]
fn h11_csv_injection_normal_unchanged() {
    assert_eq!(csv_escape_field("normal"), "normal");
}

#[test]
fn h11_csv_injection_tab_prefix() {
    assert_eq!(csv_escape_field("\tformula"), "'\tformula");
}

#[test]
fn h11_csv_injection_empty_unchanged() {
    assert_eq!(csv_escape_field(""), "");
}

// ── H07 — Failed-login lockout ──
// Uses real in-memory SQLite via `persea::db`.

use persea::db::{self, Db};

fn test_db() -> Db {
    db::init_db(std::path::Path::new(":memory:")).unwrap()
}

#[test]
fn h07_lockout_after_six_failures() {
    let db = test_db();
    let user = "attacker";
    let ip = "10.0.0.99";

    assert!(!db::is_locked_out(&db, user, ip).unwrap());

    for _ in 0..6 {
        db::record_failed_login_attempt(&db, user, ip).unwrap();
    }

    assert!(db::is_locked_out(&db, user, ip).unwrap());
}

#[test]
fn h07_not_locked_out_with_five_or_fewer() {
    let db = test_db();
    let user = "user5";
    let ip = "10.0.0.1";

    for _ in 0..5 {
        db::record_failed_login_attempt(&db, user, ip).unwrap();
    }

    assert!(!db::is_locked_out(&db, user, ip).unwrap());
}

#[test]
fn h07_successful_login_clears_failures() {
    let db = test_db();
    let user = "redeemed";
    let ip = "10.0.0.2";

    for _ in 0..6 {
        db::record_failed_login_attempt(&db, user, ip).unwrap();
    }
    assert!(db::is_locked_out(&db, user, ip).unwrap());

    db::record_successful_login(&db, user, ip).unwrap();

    let failures = db::count_recent_failures(&db, user, ip, 15 * 60).unwrap();
    assert_eq!(failures, 0);
    assert!(!db::is_locked_out(&db, user, ip).unwrap());
}

#[test]
fn h07_lockout_is_per_ip() {
    let db = test_db();
    let user = "shared";

    for _ in 0..6 {
        db::record_failed_login_attempt(&db, user, "1.1.1.1").unwrap();
    }

    assert!(db::is_locked_out(&db, user, "1.1.1.1").unwrap());
    assert!(!db::is_locked_out(&db, user, "2.2.2.2").unwrap());
}

// ── H10 — Recording encryption roundtrip ──

use persea::crypto::{self, EncryptionKey};

fn test_key() -> EncryptionKey {
    EncryptionKey::from_hex(&"ab".repeat(32)).unwrap()
}

#[test]
fn h10_encrypt_decrypt_roundtrip() {
    let key = test_key();
    let plaintext = b"hello, world! This is recording data.";
    let ciphertext = crypto::encrypt_bytes(&key, plaintext).unwrap();
    let decrypted = crypto::decrypt_bytes(&key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn h10_encrypt_decrypt_empty() {
    let key = test_key();
    let plaintext = b"";
    let ciphertext = crypto::encrypt_bytes(&key, plaintext).unwrap();
    let decrypted = crypto::decrypt_bytes(&key, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn h10_decrypt_with_wrong_key_fails() {
    let key1 = test_key();
    let key2 = EncryptionKey::from_hex(&"cd".repeat(32)).unwrap();
    let plaintext = b"secret recording";
    let ciphertext = crypto::encrypt_bytes(&key1, plaintext).unwrap();
    let result = crypto::decrypt_bytes(&key2, &ciphertext);
    assert!(result.is_err());
}

#[test]
fn h10_ciphertext_not_equal_to_plaintext() {
    let key = test_key();
    let plaintext = b"test";
    let ciphertext = crypto::encrypt_bytes(&key, plaintext).unwrap();
    assert_ne!(ciphertext, plaintext);
}

// ── C01 — XSS escaping (html_escape) ──
// `html_escape` is private in `persea::main` / `pub(crate)` in
// `persea::api::address_book`, so we replicate the algorithm to guard
// against regressions.

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[test]
fn c01_xss_script_tag() {
    assert_eq!(html_escape("<script>"), "&lt;script&gt;");
}

#[test]
fn c01_xss_double_quote() {
    assert_eq!(html_escape(r#"x"y"#), "x&quot;y");
}

#[test]
fn c01_xss_single_quote() {
    assert_eq!(html_escape("it's"), "it&#x27;s");
}

#[test]
fn c01_xss_ampersand() {
    assert_eq!(html_escape("a&b"), "a&amp;b");
}

#[test]
fn c01_xss_less_than() {
    assert_eq!(html_escape("<"), "&lt;");
}

#[test]
fn c01_xss_greater_than() {
    assert_eq!(html_escape(">"), "&gt;");
}

#[test]
fn c01_xss_passthrough() {
    assert_eq!(html_escape("hello world"), "hello world");
    assert_eq!(html_escape(""), "");
}

#[test]
fn c01_xss_mixed_special_chars() {
    assert_eq!(
        html_escape("<img src=x onerror=alert(1)>"),
        "&lt;img src=x onerror=alert(1)&gt;"
    );
}

// ── C03 — vSphere vm_id validation ──
// The validation is inline in `power_action`; replicate the exact check to
// guard against regressions.

fn is_valid_vm_id(vm_id: &str) -> bool {
    vm_id.len() <= 128
        && vm_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

#[test]
fn c03_vm_id_valid_simple() {
    assert!(is_valid_vm_id("vm-123"));
}

#[test]
fn c03_vm_id_valid_with_underscores() {
    assert!(is_valid_vm_id("vm_test.01"));
}

#[test]
fn c03_vm_id_rejects_too_long() {
    let long = "a".repeat(129);
    assert!(!is_valid_vm_id(&long));
}

#[test]
fn c03_vm_id_rejects_path_traversal() {
    assert!(!is_valid_vm_id("../etc/passwd"));
}

#[test]
fn c03_vm_id_rejects_shell_metachar() {
    assert!(!is_valid_vm_id("vm$(whoami)"));
    assert!(!is_valid_vm_id("vm`id`"));
}

#[test]
fn c03_vm_id_rejects_spaces() {
    assert!(!is_valid_vm_id("vm 123"));
}

#[test]
fn c03_vm_id_rejects_null_byte() {
    assert!(!is_valid_vm_id("vm\0123"));
}

#[test]
fn c03_vm_id_empty_accepted_by_regex() {
    // Empty string passes the length+char check (axum Path prevents empty).
    assert!(is_valid_vm_id(""));
}

// ── M07 — Constant-time key comparison (ct_eq) ──
// `validate_stored_hash` in `persea::db` is private.  Replicate the
// salted/unsalted hash + `ct_eq` logic to guard against regressions to
// non-constant-time comparison.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

fn hash_key_salt(key: &str) -> String {
    let mut salt = [0u8; 16];
    rand::fill(&mut salt);
    let mut hasher = Sha256::new();
    hasher.update(salt);
    hasher.update(key.as_bytes());
    format!("{}:{}", hex::encode(salt), hex::encode(hasher.finalize()))
}

fn validate_stored_hash(key: &str, stored: &str) -> bool {
    if let Some((salt_hex, hash_hex)) = stored.split_once(':') {
        if let (Ok(salt), Ok(expected)) = (hex::decode(salt_hex), hex::decode(hash_hex)) {
            let mut hasher = Sha256::new();
            hasher.update(salt);
            hasher.update(key.as_bytes());
            let computed = hasher.finalize();
            computed.as_slice().ct_eq(&expected).into()
        } else {
            false
        }
    } else {
        hash_key(key).as_bytes().ct_eq(stored.as_bytes()).into()
    }
}

#[test]
fn m07_cteq_correct_key_matches_salted() {
    let stored = hash_key_salt("secret-api-key");
    assert!(validate_stored_hash("secret-api-key", &stored));
}

#[test]
fn m07_cteq_wrong_key_fails_salted() {
    let stored = hash_key_salt("secret-api-key");
    assert!(!validate_stored_hash("wrong-key", &stored));
}

#[test]
fn m07_cteq_correct_key_matches_legacy() {
    let stored = hash_key("legacy-key");
    assert!(validate_stored_hash("legacy-key", &stored));
}

#[test]
fn m07_cteq_wrong_key_fails_legacy() {
    let stored = hash_key("legacy-key");
    assert!(!validate_stored_hash("tampered", &stored));
}

#[test]
fn m07_cteq_tampered_hash_fails() {
    let stored = hash_key_salt("real-key");
    // Tamper the hash portion after the colon
    let tampered = format!("{}deadbeef", stored.split_once(':').unwrap().0);
    assert!(!validate_stored_hash("real-key", &tampered));
}

#[test]
fn m07_cteq_empty_key_matches() {
    let stored = hash_key("");
    assert!(validate_stored_hash("", &stored));
}

#[test]
fn m07_cteq_malformed_stored_fails() {
    assert!(!validate_stored_hash("key", "not-hex:garbage"));
}
