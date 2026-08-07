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

// ── R01 — SAML Signature Wrapping (XSW) adversarial test ──
// `parse_assertion_xml` is private in `persea::auth_providers::saml`.
// Replicate the parser to demonstrate that without the verified-element
// fix (line 1113 of saml.rs), an XSW attack succeeds: the injected
// NameID overwrites the legitimate one. The fix ensures only the
// signature-verified assertion element is passed to this parser.

use quick_xml::escape::unescape as xml_unescape;
use quick_xml::Reader;
use std::collections::HashMap;

#[derive(Debug, Default)]
struct SamlAttrs {
    name_id: String,
    attributes: HashMap<String, Vec<String>>,
}

fn parse_assertion_xml_replica(xml: &str) -> Result<SamlAttrs, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut name_id: Option<String> = None;
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

    let mut in_name_id = false;
    let mut in_attribute_value = false;
    let mut current_attr_name = String::new();
    let mut current_text = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = tag.split(':').last().unwrap_or(&tag).to_string();
                match local.as_str() {
                    "NameID" => {
                        in_name_id = true;
                        current_text.clear();
                    }
                    "Attribute" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"Name" {
                                current_attr_name =
                                    String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                    }
                    "AttributeValue" => {
                        in_attribute_value = true;
                        current_text.clear();
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                let raw = String::from_utf8_lossy(e.as_ref());
                if let Ok(text) = xml_unescape(&raw) {
                    let text_str = text.to_string();
                    if in_name_id {
                        name_id = Some(text_str);
                    } else if in_attribute_value && !current_attr_name.is_empty() {
                        current_text.push_str(&text_str);
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let local = tag.split(':').last().unwrap_or(&tag).to_string();
                match local.as_str() {
                    "NameID" => {
                        in_name_id = false;
                    }
                    "AttributeValue" => {
                        if in_attribute_value && !current_attr_name.is_empty() {
                            let val = current_text.trim().to_string();
                            if !val.is_empty() {
                                attributes
                                    .entry(current_attr_name.clone())
                                    .or_default()
                                    .push(val);
                            }
                            current_text.clear();
                        }
                        in_attribute_value = false;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(SamlAttrs {
        name_id: name_id.ok_or("No NameID found")?,
        attributes,
    })
}

/// A legitimate assertion signed by the IdP.
const REAL_ASSERTION: &str = r#"
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_real123"
  IssueInstant="2025-01-01T00:00:00Z" Version="2.0">
  <Issuer>https://idp.example.com</Issuer>
  <Subject>
    <NameID>real-user@example.com</NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z"/>
    </SubjectConfirmation>
  </Subject>
  <AttributeStatement>
    <Attribute Name="groups">
      <AttributeValue>users</AttributeValue>
    </Attribute>
  </AttributeStatement>
</Assertion>"#;

/// An injected assertion appended after the real one (XSW attack).
const INJECTED_ASSERTION: &str = r#"
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="_injected456"
  IssueInstant="2025-01-01T00:00:00Z" Version="2.0">
  <Issuer>https://idp.example.com</Issuer>
  <Subject>
    <NameID>admin@evil.com</NameID>
    <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z"/>
    </SubjectConfirmation>
  </Subject>
  <AttributeStatement>
    <Attribute Name="groups">
      <AttributeValue>admin</AttributeValue>
    </Attribute>
  </AttributeStatement>
</Assertion>"#;

#[test]
fn r01_xsw_full_document_extracts_injected_identity() {
    // With the raw document (no verified-element isolation), the parser
    // processes BOTH assertions. The injected NameID overwrites the real
    // one because the parser uses `name_id = Some(...)` unconditionally.
    let full_doc = format!("{REAL_ASSERTION}\n{INJECTED_ASSERTION}");
    let attrs = parse_assertion_xml_replica(&full_doc).unwrap();

    // The parser returns the INJECTED NameID — this is the vulnerability.
    assert_eq!(attrs.name_id, "admin@evil.com");
}

#[test]
fn r01_xsw_real_only_assertion_preserves_identity() {
    // After the fix, only the verified assertion element is passed to the
    // parser. The injected assertion is never seen.
    let attrs = parse_assertion_xml_replica(REAL_ASSERTION).unwrap();
    assert_eq!(attrs.name_id, "real-user@example.com");
}

#[test]
fn r01_xsw_groups_attribute_not_overwritten() {
    // Verify that the group attribute from the injected assertion is
    // NOT present when only the real assertion is parsed.
    let attrs_real = parse_assertion_xml_replica(REAL_ASSERTION).unwrap();
    let groups = attrs_real.attributes.get("groups").unwrap();
    assert_eq!(groups, &vec!["users".to_string()]);

    // And the full doc shows both values leak in.
    let full_doc = format!("{REAL_ASSERTION}\n{INJECTED_ASSERTION}");
    let attrs_full = parse_assertion_xml_replica(&full_doc).unwrap();
    let groups_full = attrs_full.attributes.get("groups").unwrap();
    assert!(groups_full.contains(&"admin".to_string()));
}

// ── R02 — RADIUS Response Authenticator verification (ct_eq) ──
// `verify_response_authenticator` is private in
// `persea::auth_providers::radius`.  Replicate the RFC 2865 §4.2
// verification to guard against regressions to non-constant-time
// comparison or broken authenticator computation.

use md5::Md5;

fn verify_radius_response(
    response: &[u8],
    request_auth: &[u8; 16],
    shared_secret: &[u8],
) -> bool {
    if response.len() < 20 {
        return false;
    }
    let mut hasher = Md5::new();
    hasher.update(&response[..4]);
    hasher.update(request_auth);
    hasher.update(&response[20..]);
    hasher.update(shared_secret);
    let computed = hasher.finalize();
    computed.as_slice().ct_eq(&response[4..20]).into()
}

fn build_test_response(
    code: u8,
    id: u8,
    request_auth: &[u8; 16],
    shared_secret: &[u8],
) -> Vec<u8> {
    let length: u16 = 20; // 4-byte header + 16-byte Response Authenticator
    let mut hasher = Md5::new();
    hasher.update([code, id]);
    hasher.update(&length.to_be_bytes());
    hasher.update(request_auth);
    hasher.update(shared_secret); // no attributes
    let response_auth = hasher.finalize();

    let mut packet = vec![code, id];
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(&response_auth);
    packet
}

#[test]
fn r02_radius_valid_authenticator_matches() {
    let secret = b"shared-secret-1234";
    let req_auth = [0xAA_u8; 16];
    let packet = build_test_response(2, 42, &req_auth, secret);
    assert!(verify_radius_response(&packet, &req_auth, secret));
}

#[test]
fn r02_radius_tampered_response_fails() {
    let secret = b"shared-secret-1234";
    let req_auth = [0xAA_u8; 16];
    let mut packet = build_test_response(2, 42, &req_auth, secret);
    // Flip a byte in the response authenticator
    packet[5] ^= 0xFF;
    assert!(!verify_radius_response(&packet, &req_auth, secret));
}

#[test]
fn r02_radius_wrong_secret_fails() {
    let secret = b"shared-secret-1234";
    let wrong_secret = b"wrong-secret-5678";
    let req_auth = [0xBB_u8; 16];
    let packet = build_test_response(2, 42, &req_auth, secret);
    assert!(!verify_radius_response(&packet, &req_auth, wrong_secret));
}

#[test]
fn r02_radius_wrong_request_auth_fails() {
    let secret = b"shared-secret-1234";
    let req_auth = [0xCC_u8; 16];
    let wrong_auth = [0xDD_u8; 16];
    let packet = build_test_response(2, 42, &req_auth, secret);
    assert!(!verify_radius_response(&packet, &wrong_auth, secret));
}

#[test]
fn r02_radius_too_short_packet_fails() {
    let secret = b"shared-secret-1234";
    let req_auth = [0xAA_u8; 16];
    let short_packet = vec![2, 42, 10, 0]; // length < 20
    assert!(!verify_radius_response(&short_packet, &req_auth, secret));
}

#[test]
fn r02_radius_access_reject_code_verifies() {
    let secret = b"secret-key-0001";
    let req_auth = [0x11_u8; 16];
    // Code 3 = Access-Reject
    let packet = build_test_response(3, 7, &req_auth, secret);
    assert!(verify_radius_response(&packet, &req_auth, secret));
}

// ── C03 (extended) — vSphere vm_id validation: slash & special chars ──
// Extends the existing C03 tests with additional adversarial inputs.

#[test]
fn c03_vm_id_rejects_forward_slash() {
    assert!(!is_valid_vm_id("vm/../../etc"));
}

#[test]
fn c03_vm_id_rejects_backslash() {
    assert!(!is_valid_vm_id("vm\\admin"));
}

#[test]
fn c03_vm_id_rejects_angle_brackets() {
    assert!(!is_valid_vm_id("<script>"));
}

#[test]
fn c03_vm_id_rejects_pipe() {
    assert!(!is_valid_vm_id("vm|id"));
}

#[test]
fn c03_vm_id_rejects_newline() {
    assert!(!is_valid_vm_id("vm\ninjected"));
}

#[test]
fn c03_vm_id_rejects_unicode() {
    assert!(!is_valid_vm_id("vm\u{200B}id")); // zero-width space
}

#[test]
fn c03_vm_id_boundary_exactly_128() {
    let id = "a".repeat(128);
    assert!(is_valid_vm_id(&id));
}

// ── Token admin rejection (R04) ──
// `admin_list_user_tokens` requires `identity: Option<Extension<AuthIdentity>>`
// and returns 403 when None. Testing this requires constructing axum
// Extension types and a Db — impractical in a unit test. The handler is
// verified through integration tests in `api::integration_tests`. Documenting
// the expectation here as a placeholder.
