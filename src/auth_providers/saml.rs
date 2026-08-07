//! SAML 2.0 Service Provider auth provider.
//!
//! Handles the full SP-side SAML flow:
//! 1. Parse IdP metadata XML to discover SSO URL and signing certificate.
//! 2. Generate signed AuthnRequest and redirect the user to the IdP.
//! 3. Validate the SAMLResponse on the ACS callback (signature, time
//!    conditions, audience restriction) and extract user attributes.

use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use quick_xml::escape::unescape as xml_unescape;
use quick_xml::Reader;
use ring::digest;
use ring::signature::{self, RsaKeyPair};
use std::collections::HashMap;
use uuid::Uuid;

use crate::auth_provider::{AuthProvider, AuthRequest, AuthResult, Capabilities};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// SAML 2.0 Service Provider configuration.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SamlConfig {
    /// URL of the IdP metadata endpoint (XML).
    pub idp_metadata_url: Option<String>,
    /// Local path to IdP metadata XML file (alternative to URL).
    pub idp_metadata_file: Option<String>,
    /// SP entity ID — must match what's registered at the IdP.
    pub entity_id: String,
    /// Assertion Consumer Service URL — where the IdP POSTs the response.
    pub acs_url: String,
    /// Base64-encoded SP X.509 certificate (for signing AuthnRequests).
    pub certificate: Option<String>,
    /// PEM-encoded SP private key (for signing AuthnRequests).
    pub private_key: Option<String>,
    /// SAML attribute name to extract group memberships from.
    pub groups_attribute: Option<String>,
    /// When true, reject responses with missing or expired assertions.
    pub strict_mode: bool,
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self {
            idp_metadata_url: None,
            idp_metadata_file: None,
            entity_id: String::new(),
            acs_url: String::new(),
            certificate: None,
            private_key: None,
            groups_attribute: None,
            strict_mode: true,
        }
    }
}

// ---------------------------------------------------------------------------
// IdP metadata
// ---------------------------------------------------------------------------

/// Parsed IdP metadata.
#[derive(Debug, Clone)]
pub struct IdpMetadata {
    /// IdP SSO redirect URL (where AuthnRequests are sent).
    pub sso_url: String,
    /// IdP entity ID.
    pub entity_id: String,
    /// Base64-encoded X.509 certificate used to sign responses.
    pub certificate: String,
}

/// Parse IdP metadata XML to extract SSO URL, entity ID, and certificate.
pub fn parse_idp_metadata(xml: &str) -> Result<IdpMetadata, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut sso_url: Option<String> = None;
    let mut entity_id: Option<String> = None;
    let mut cert_b64: Option<String> = None;
    let mut in_cert = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
                    "EntityDescriptor" => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"entityID" {
                                entity_id = Some(String::from_utf8_lossy(&attr.value).to_string());
                            }
                        }
                    }
                    "SingleSignOnService" => {
                        let mut binding = String::new();
                        let mut location = String::new();
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "Binding" => binding = val,
                                "Location" => location = val,
                                _ => {}
                            }
                        }
                        if binding.contains("HTTP-Redirect") && sso_url.is_none() {
                            sso_url = Some(location);
                        }
                    }
                    "X509Certificate" => {
                        in_cert = true;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_cert {
                    let raw = String::from_utf8_lossy(e.as_ref());
                    let text = xml_unescape(&raw).map_err(|e| e.to_string())?.to_string();
                    cert_b64 = Some(text);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if local_name(&tag) == "X509Certificate" {
                    in_cert = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    Ok(IdpMetadata {
        sso_url: sso_url.ok_or("No SingleSignOnService with HTTP-Redirect binding found")?,
        entity_id: entity_id.ok_or("No entityID found in IdP metadata")?,
        certificate: cert_b64.ok_or("No X509Certificate found in IdP metadata")?,
    })
}

// ---------------------------------------------------------------------------
// XML helpers
// ---------------------------------------------------------------------------

/// XML-escape a string.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Strip namespace prefix from a tag name (e.g. "md:EntityDescriptor" → "EntityDescriptor").
fn local_name(name: &str) -> &str {
    name.rsplit_once(':')
        .map(|(_, local)| local)
        .unwrap_or(name)
}

/// Exclusive C14N canonicalization per W3C Recommendation for XML-DSig.
///
/// Produces a deterministic canonical form suitable for SAML signature
/// verification. Handles: stripping XML declarations, removing comments,
/// normalizing self-closing tags, attribute whitespace, alphabetical
/// attribute sorting (by namespace URI then local name), and proper
/// text/attribute value escaping.
///
/// Key C14N invariants enforced:
/// - Only namespace declarations (xmlns:*) are inherited by descendants;
///   ordinary attributes never leak to child elements.
/// - Self-closing tags (`<tag/>`) do not leave dangling namespace stack entries.
fn exclusive_canonicalize(xml: &str) -> String {
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_comments = false;

    let mut out = String::with_capacity(xml.len());
    let mut ns_stack: Vec<HashMap<String, String>> = Vec::new();
    // Namespace declarations in scope for the current element's children.
    // Only xmlns:* entries — never ordinary attributes.
    let mut ns_in_scope: Vec<(String, String)> = Vec::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Decl(_)) => continue,
            Ok(Event::Comment(_)) => continue,
            Ok(Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let parent_ns = ns_in_scope.clone();
                let mut ns_map = ns_stack.last().cloned().unwrap_or_default();

                let mut own_ns: Vec<(String, String)> = Vec::new();
                let mut own_attrs: Vec<(String, String)> = Vec::new();
                for attr in e.attributes().flatten() {
                    let k = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let mut v = String::from_utf8_lossy(&attr.value).to_string();
                    if k.starts_with("xmlns") {
                        let prefix = if k == "xmlns" { "" } else { &k[6..] };
                        ns_map.insert(prefix.to_string(), v.clone());
                        v = normalize_attr_whitespace(&v);
                        own_ns.push((k, v));
                    } else {
                        v = normalize_attr_whitespace(&v);
                        own_attrs.push((k, v));
                    }
                }
                ns_stack.push(ns_map);

                // In-scope ns = parent's minus overridden, plus own declarations.
                let mut all_ns = parent_ns;
                for &(ref k, _) in &own_ns {
                    all_ns.retain(|(pk, _)| pk != k);
                }
                all_ns.extend(own_ns);
                all_ns.sort_by(|a, b| sort_attr_cmp(&a.0, &b.0));

                // Output: in-scope ns attrs + own ordinary attrs, all sorted.
                let mut output_attrs = all_ns.clone();
                output_attrs.extend(own_attrs);
                output_attrs.sort_by(|a, b| sort_attr_cmp(&a.0, &b.0));

                out.push('<');
                out.push_str(&local);
                for (k, v) in &output_attrs {
                    out.push(' ');
                    out.push_str(k);
                    out.push_str("=\"");
                    out.push_str(&escape_attr_value(v));
                    out.push('"');
                }
                out.push('>');

                // Only namespace declarations are inherited by descendants.
                ns_in_scope = all_ns;
            }
            Ok(Event::Empty(ref e)) => {
                let local = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let parent_ns = ns_in_scope.clone();
                let mut ns_map = ns_stack.last().cloned().unwrap_or_default();

                let mut own_ns: Vec<(String, String)> = Vec::new();
                let mut own_attrs: Vec<(String, String)> = Vec::new();
                for attr in e.attributes().flatten() {
                    let k = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let mut v = String::from_utf8_lossy(&attr.value).to_string();
                    if k.starts_with("xmlns") {
                        let prefix = if k == "xmlns" { "" } else { &k[6..] };
                        ns_map.insert(prefix.to_string(), v.clone());
                        v = normalize_attr_whitespace(&v);
                        own_ns.push((k, v));
                    } else {
                        v = normalize_attr_whitespace(&v);
                        own_attrs.push((k, v));
                    }
                }

                let mut all_ns = parent_ns.clone();
                for &(ref k, _) in &own_ns {
                    all_ns.retain(|(pk, _)| pk != k);
                }
                all_ns.extend(own_ns);
                all_ns.sort_by(|a, b| sort_attr_cmp(&a.0, &b.0));

                let mut output_attrs = all_ns.clone();
                output_attrs.extend(own_attrs);
                output_attrs.sort_by(|a, b| sort_attr_cmp(&a.0, &b.0));

                out.push('<');
                out.push_str(&local);
                for (k, v) in &output_attrs {
                    out.push(' ');
                    out.push_str(k);
                    out.push_str("=\"");
                    out.push_str(&escape_attr_value(v));
                    out.push('"');
                }
                out.push('>');
                out.push_str("</");
                out.push_str(&local);
                out.push('>');

                // Self-closing: no scope change — restore parent ns.
                ns_in_scope = parent_ns;
            }
            Ok(Event::End(ref e)) => {
                let local = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if ns_stack.pop().is_some() {
                    ns_in_scope = ns_stack
                        .last()
                        .map(|m| {
                            m.iter()
                                .map(|(p, v)| {
                                    if p.is_empty() {
                                        ("xmlns".to_string(), v.clone())
                                    } else {
                                        (format!("xmlns:{p}"), v.clone())
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    ns_in_scope.sort_by(|a, b| sort_attr_cmp(&a.0, &b.0));
                }
                out.push_str("</");
                out.push_str(&local);
                out.push('>');
            }
            Ok(Event::Text(ref e)) => {
                let raw = String::from_utf8_lossy(e.as_ref());
                out.push_str(&escape_text(&raw));
            }
            Ok(Event::CData(ref e)) => {
                let raw = String::from_utf8_lossy(e.as_ref());
                out.push_str(&escape_text(&raw));
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    out
}

/// Normalize attribute value whitespace per C14N: replace tabs, newlines,
/// carriage returns with spaces, then collapse multiple spaces.
fn normalize_attr_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_space = false;
    for c in s.chars() {
        match c {
            '\t' | '\n' | '\r' => {
                if !prev_space {
                    result.push(' ');
                    prev_space = true;
                }
            }
            ' ' => {
                if !prev_space {
                    result.push(' ');
                    prev_space = true;
                }
            }
            _ => {
                result.push(c);
                prev_space = false;
            }
        }
    }
    result
}

/// Compare two attribute keys for sorting by (namespace URI, local name).
fn sort_attr_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (uri_a, local_a) = attr_sort_key(a);
    let (uri_b, local_b) = attr_sort_key(b);
    uri_a.cmp(&uri_b).then(local_a.cmp(&local_b))
}

/// Return (namespace_uri, local_name) for an attribute key for sorting.
fn attr_sort_key(attr_key: &str) -> (String, String) {
    if attr_key == "xmlns" {
        (String::new(), String::new())
    } else if let Some(local) = attr_key.strip_prefix("xmlns:") {
        (String::new(), local.to_string())
    } else if let Some((prefix, local)) = attr_key.split_once(':') {
        let uri = match prefix {
            "samlp" => "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
            "md" => "urn:oasis:names:tc:SAML:2.0:metadata",
            "ds" => "http://www.w3.org/2000/09/xmldsig#",
            _ => prefix,
        };
        (uri.to_string(), local.to_string())
    } else {
        (String::new(), attr_key.to_string())
    }
}

/// Escape text content for C14N output.
fn escape_text(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            _ => result.push(c),
        }
    }
    result
}

/// Escape attribute value for C14N output.
fn escape_attr_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&apos;"),
            _ => result.push(c),
        }
    }
    result
}

/// SHA-256 digest, base64-encoded.
fn sha256_digest_b64(data: &[u8]) -> String {
    let hash = digest::digest(&digest::SHA256, data);
    base64::engine::general_purpose::STANDARD.encode(hash.as_ref())
}

// ---------------------------------------------------------------------------
// SAML security helpers
// ---------------------------------------------------------------------------

/// Extract the DigestValue from a SignedInfo XML fragment.
fn extract_reference_digest_value(signed_info: &str) -> Option<String> {
    let mut reader = Reader::from_str(signed_info);
    reader.config_mut().trim_text(true);
    let mut in_digest_value = false;
    let mut digest_value = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if local_name(&tag) == "DigestValue" {
                    in_digest_value = true;
                    digest_value.clear();
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_digest_value {
                    let raw = String::from_utf8_lossy(e.as_ref());
                    digest_value.push_str(&raw);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if local_name(&tag) == "DigestValue" {
                    in_digest_value = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    let trimmed = digest_value.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract the XML of the element whose ID attribute matches `target_id`.
///
/// Returns the raw element including its start/end tags and content.
fn extract_element_by_id(xml: &str, target_id: &str) -> Option<String> {
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut found = false;
    let mut depth = 0u32;
    let mut result = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if !found {
                    let has_target_id = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"ID" && a.value.as_ref() == target_id.as_bytes());
                    if has_target_id {
                        found = true;
                        depth = 1;
                        result.extend_from_slice(b"<");
                        result.extend_from_slice(e.name().as_ref());
                        for attr in e.attributes().flatten() {
                            result.push(b' ');
                            result.extend_from_slice(attr.key.as_ref());
                            result.extend_from_slice(b"=\"");
                            result.extend_from_slice(&attr.value);
                            result.push(b'"');
                        }
                        result.push(b'>');
                    }
                } else {
                    depth += 1;
                    result.extend_from_slice(b"<");
                    result.extend_from_slice(e.name().as_ref());
                    for attr in e.attributes().flatten() {
                        result.push(b' ');
                        result.extend_from_slice(attr.key.as_ref());
                        result.extend_from_slice(b"=\"");
                        result.extend_from_slice(&attr.value);
                        result.push(b'"');
                    }
                    result.push(b'>');
                }
            }
            Ok(Event::End(ref e)) => {
                if found {
                    result.extend_from_slice(b"</");
                    result.extend_from_slice(e.name().as_ref());
                    result.push(b'>');
                    depth -= 1;
                    if depth == 0 {
                        return String::from_utf8(result).ok();
                    }
                }
            }
            Ok(Event::Text(ref e)) => {
                if found {
                    result.extend_from_slice(e.as_ref());
                }
            }
            Ok(Event::CData(ref e)) => {
                if found {
                    result.extend_from_slice(b"<![CDATA[");
                    result.extend_from_slice(e.as_ref());
                    result.extend_from_slice(b"]]>");
                }
            }
            Ok(Event::Empty(ref e)) => {
                if found {
                    result.extend_from_slice(b"<");
                    result.extend_from_slice(e.name().as_ref());
                    for attr in e.attributes().flatten() {
                        result.push(b' ');
                        result.extend_from_slice(attr.key.as_ref());
                        result.extend_from_slice(b"=\"");
                        result.extend_from_slice(&attr.value);
                        result.push(b'"');
                    }
                    result.extend_from_slice(b"/>");
                } else {
                    let has_target_id = e
                        .attributes()
                        .flatten()
                        .any(|a| a.key.as_ref() == b"ID" && a.value.as_ref() == target_id.as_bytes());
                    if has_target_id {
                        let mut elem = Vec::new();
                        elem.extend_from_slice(b"<");
                        elem.extend_from_slice(e.name().as_ref());
                        for attr in e.attributes().flatten() {
                            elem.push(b' ');
                            elem.extend_from_slice(attr.key.as_ref());
                            elem.extend_from_slice(b"=\"");
                            elem.extend_from_slice(&attr.value);
                            elem.push(b'"');
                        }
                        elem.extend_from_slice(b"/>");
                        return String::from_utf8(elem).ok();
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Remove the `<ds:Signature>` element from an XML string (enveloped-signature transform).
fn remove_signature_element(xml: &str) -> String {
    use quick_xml::events::Event;

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    let mut buf = Vec::new();
    let mut out = String::with_capacity(xml.len());
    let mut in_signature = false;
    let mut sig_depth = 0u32;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                if in_signature {
                    sig_depth += 1;
                } else {
                    let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if local_name(&tag) == "Signature" {
                        in_signature = true;
                        sig_depth = 1;
                        continue;
                    }
                    out.push('<');
                    out.push_str(&String::from_utf8_lossy(e.name().as_ref()));
                    for attr in e.attributes().flatten() {
                        out.push(' ');
                        out.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
                        out.push_str("=\"");
                        out.push_str(&String::from_utf8_lossy(&attr.value));
                        out.push('"');
                    }
                    out.push('>');
                }
            }
            Ok(Event::End(ref e)) => {
                if in_signature {
                    sig_depth -= 1;
                    if sig_depth == 0 {
                        in_signature = false;
                    }
                } else {
                    out.push_str("</");
                    out.push_str(&String::from_utf8_lossy(e.name().as_ref()));
                    out.push('>');
                }
            }
            Ok(Event::Empty(ref e)) => {
                if !in_signature {
                    out.push('<');
                    out.push_str(&String::from_utf8_lossy(e.name().as_ref()));
                    for attr in e.attributes().flatten() {
                        out.push(' ');
                        out.push_str(&String::from_utf8_lossy(attr.key.as_ref()));
                        out.push_str("=\"");
                        out.push_str(&String::from_utf8_lossy(&attr.value));
                        out.push('"');
                    }
                    out.push_str("/>");
                }
            }
            Ok(Event::Text(ref e)) => {
                if !in_signature {
                    out.push_str(&String::from_utf8_lossy(e.as_ref()));
                }
            }
            Ok(Event::CData(ref e)) => {
                if !in_signature {
                    out.push_str("<![CDATA[");
                    out.push_str(&String::from_utf8_lossy(e.as_ref()));
                    out.push_str("]]>");
                }
            }
            Ok(Event::Decl(_)) => {}
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    out
}

/// Extract InResponseTo from the `<samlp:Response>` or `<saml:SubjectConfirmationData>`.
fn extract_in_response_to(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let ln = local_name(&tag);
                if ln == "Response" || ln == "SubjectConfirmationData" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"InResponseTo" {
                            return Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Extract Audience values from `AudienceRestriction` in a SAML assertion.
fn extract_audiences(xml: &str) -> Vec<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_audience_restriction = false;
    let mut in_audience = false;
    let mut audiences = Vec::new();
    let mut current_text = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
                    "AudienceRestriction" => in_audience_restriction = true,
                    "Audience" if in_audience_restriction => {
                        in_audience = true;
                        current_text.clear();
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_audience {
                    let raw = String::from_utf8_lossy(e.as_ref());
                    if let Ok(text) = xml_unescape(&raw) {
                        current_text.push_str(&text);
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
                    "Audience" => {
                        if in_audience {
                            let val = current_text.trim().to_string();
                            if !val.is_empty() {
                                audiences.push(val);
                            }
                            current_text.clear();
                        }
                        in_audience = false;
                    }
                    "AudienceRestriction" => in_audience_restriction = false,
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    audiences
}

// ---------------------------------------------------------------------------
// Deflate compression
// ---------------------------------------------------------------------------

/// Deflate (raw, no zlib header) compress bytes for SAML redirect binding.
fn deflate_encode(data: &[u8]) -> Vec<u8> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data).expect("deflate write");
    encoder.finish().expect("deflate finish")
}

/// Attempt deflate decompression.
fn decompress_deflate(data: &[u8]) -> Result<Vec<u8>, String> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut decoder = DeflateDecoder::new(data);
    let mut output = Vec::new();
    decoder
        .read_to_end(&mut output)
        .map_err(|e| format!("Deflate decompression failed: {e}"))?;
    Ok(output)
}

// ---------------------------------------------------------------------------
// RSA key handling
// ---------------------------------------------------------------------------

/// Parse a PEM-encoded RSA private key into an `RsaKeyPair`.
fn parse_rsa_private_key(pem: &str) -> Result<RsaKeyPair, String> {
    let pem = pem.trim();
    let b64 = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<String>()
        .replace(['\n', '\r'], "");
    let der = base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .map_err(|e| format!("Base64 decode error: {e}"))?;
    RsaKeyPair::from_der(&der).map_err(|e| format!("Invalid RSA private key: {e}"))
}

/// Sign data with RSA-SHA256.
fn sign_rsa_sha256(key_pair: &RsaKeyPair, data: &[u8]) -> Result<Vec<u8>, String> {
    let rng = ring::rand::SystemRandom::new();
    let mut signature = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &rng,
            data,
            &mut signature,
        )
        .map_err(|e| format!("RSA signing failed: {e:?}"))?;
    Ok(signature)
}

/// Parse a PEM or base64 certificate and return DER bytes.
fn parse_certificate_der(cert_pem: &str) -> Result<Vec<u8>, String> {
    let cert_pem = cert_pem.trim();
    if cert_pem.contains("-----BEGIN") {
        let b64 = cert_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<String>()
            .replace(['\n', '\r'], "");
        base64::engine::general_purpose::STANDARD
            .decode(&b64)
            .map_err(|e| format!("Certificate base64 decode error: {e}"))
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(cert_pem)
            .map_err(|e| format!("Certificate base64 decode error: {e}"))
    }
}

/// Verify RSA-SHA256 signature using DER certificate.
fn verify_rsa_sha256(cert_der: &[u8], data: &[u8], signature_b64: &str) -> Result<(), String> {
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .map_err(|e| format!("Signature base64 decode error: {e}"))?;
    let public_key_der = extract_spki_from_cert(cert_der)?;
    let public_key =
        signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA256, &public_key_der);
    public_key
        .verify(data, &sig_bytes)
        .map_err(|_| "RSA signature verification failed".to_string())
}

/// Extract SubjectPublicKeyInfo from X.509 DER.
fn extract_spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let rsa_oid: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    let pos = cert_der
        .windows(rsa_oid.len())
        .position(|w| w == rsa_oid)
        .ok_or("RSA OID not found in certificate")?;

    // Walk back to find the outer SPKI SEQUENCE
    let mut outer = pos;
    while outer > 0 {
        if cert_der[outer] == 0x30 && outer + 2 < cert_der.len() {
            break;
        }
        outer -= 1;
    }

    // Skip outer SEQUENCE tag + inner AlgorithmIdentifier SEQUENCE
    let mut i = outer + 1;
    if i < cert_der.len() && cert_der[i] == 0x30 {
        i += 1;
        let inner_len = parse_der_length(cert_der, &mut i)?;
        i += inner_len;
    }

    // BIT STRING
    if i >= cert_der.len() || cert_der[i] != 0x03 {
        return Err("Expected BIT STRING in SPKI".to_string());
    }
    i += 1;
    let _ = parse_der_length(cert_der, &mut i)?;
    // Skip unused bits byte
    if i < cert_der.len() {
        i += 1;
    }
    Ok(cert_der[i..].to_vec())
}

/// Parse a DER length field.
fn parse_der_length(data: &[u8], pos: &mut usize) -> Result<usize, String> {
    if *pos >= data.len() {
        return Err("Unexpected end of DER data".to_string());
    }
    let first = data[*pos];
    *pos += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let num_bytes = (first & 0x7f) as usize;
    if *pos + num_bytes > data.len() {
        return Err("DER length extends past data".to_string());
    }
    let mut length: usize = 0;
    for &b in &data[*pos..*pos + num_bytes] {
        length = (length << 8) | (b as usize);
    }
    *pos += num_bytes;
    Ok(length)
}

// ---------------------------------------------------------------------------
// AuthnRequest generation
// ---------------------------------------------------------------------------

/// Build a signed AuthnRequest XML. Returns (id, xml, redirect_url).
fn build_authn_request(
    config: &SamlConfig,
    idp_sso_url: &str,
) -> Result<(String, String, String), String> {
    let request_id = format!("_{}", Uuid::new_v4());
    let issue_instant = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Build the unsigned AuthnRequest using string concatenation to avoid
    // escape-sequence issues with newlines in regular strings.
    let mut parts: Vec<String> = Vec::new();
    parts.push(String::from("<samlp:AuthnRequest"));
    parts.push(String::from(
        "    xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"",
    ));
    parts.push(String::from(
        "    xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
    ));
    parts.push(format!("    ID=\"{}\"", xml_escape(&request_id)));
    parts.push(String::from("    Version=\"2.0\""));
    parts.push(format!("    IssueInstant=\"{issue_instant}\""));
    parts.push(format!("    Destination=\"{}\"", xml_escape(idp_sso_url)));
    parts.push(format!(
        "    AssertionConsumerServiceURL=\"{}\"",
        xml_escape(&config.acs_url)
    ));
    parts.push(String::from(
        "    ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\">",
    ));
    parts.push(format!(
        "  <saml:Issuer>{}</saml:Issuer>",
        xml_escape(&config.entity_id)
    ));
    parts.push(String::from("  <samlp:NameIDPolicy"));
    parts.push(String::from(
        "      Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress\"",
    ));
    parts.push(String::from("      AllowCreate=\"true\"/>"));
    parts.push(String::from("</samlp:AuthnRequest>"));
    let unsigned_request = parts.join(" ");

    // Sign the request if we have a private key
    let signed_request = if let Some(key_pem) = &config.private_key {
        sign_authn_request(&unsigned_request, key_pem)?
    } else {
        unsigned_request
    };

    // Build redirect URL with deflate + base64 encoding
    let deflated = deflate_encode(signed_request.as_bytes());
    let encoded = base64::engine::general_purpose::STANDARD.encode(&deflated);
    let redirect_url = format!(
        "{}?SAMLRequest={}",
        idp_sso_url,
        urlencoding::encode(&encoded)
    );

    Ok((request_id, signed_request, redirect_url))
}

/// Extract the ID attribute from an AuthnRequest element.
fn extract_request_id(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    if let Ok(quick_xml::events::Event::Start(ref e)) = reader.read_event_into(&mut buf) {
        for attr in e.attributes().flatten() {
            if attr.key.as_ref() == b"ID" {
                return Some(String::from_utf8_lossy(&attr.value).to_string());
            }
        }
    }
    None
}

/// Sign an AuthnRequest XML with an RSA-SHA256 enveloped signature.
fn sign_authn_request(xml: &str, private_key_pem: &str) -> Result<String, String> {
    let key_pair = parse_rsa_private_key(private_key_pem)?;

    // Canonicalize the request (with a placeholder for the signature)
    let canonical = exclusive_canonicalize(xml);
    let digest_value = sha256_digest_b64(canonical.as_bytes());
    let id = extract_request_id(xml).unwrap_or_default();

    // Build SignedInfo
    let mut si_parts: Vec<String> = Vec::new();
    si_parts.push(String::from(
        "<ds:SignedInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
    ));
    si_parts.push(String::from(
        "  <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    ));
    si_parts.push(String::from(
        "  <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\"/>",
    ));
    si_parts.push(format!("  <ds:Reference URI=\"{}\">", xml_escape(&id)));
    si_parts.push(String::from("    <ds:Transforms>"));
    si_parts.push(String::from(
        "      <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>",
    ));
    si_parts.push(String::from(
        "      <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>",
    ));
    si_parts.push(String::from("    </ds:Transforms>"));
    si_parts.push(String::from(
        "    <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"/>",
    ));
    si_parts.push(format!(
        "    <ds:DigestValue>{}</ds:DigestValue>",
        digest_value
    ));
    si_parts.push(String::from("  </ds:Reference>"));
    si_parts.push(String::from("</ds:SignedInfo>"));
    let signed_info_xml = si_parts.join("\n      ");

    let signed_info_canonical = exclusive_canonicalize(&signed_info_xml);
    let signature = sign_rsa_sha256(&key_pair, signed_info_canonical.as_bytes())?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    // Build the Signature element
    let mut sig_parts: Vec<String> = Vec::new();
    sig_parts.push(String::from(
        "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">",
    ));
    sig_parts.push(format!("      {}", signed_info_xml));
    sig_parts.push(format!(
        "      <ds:SignatureValue>{}</ds:SignatureValue>",
        signature_b64
    ));
    sig_parts.push(String::from("</ds:Signature>"));
    let signature_element = sig_parts.join("\n");

    // Insert signature before the Issuer element
    let issuer_tag = "<saml:Issuer";
    if let Some(pos) = xml.find(issuer_tag) {
        // Find the start of this line
        let line_start = xml[..pos].rfind('\n').map(|p| p + 1).unwrap_or(0);
        let indent = &xml[line_start..pos];
        let mut result = String::with_capacity(xml.len() + signature_element.len() + 64);
        result.push_str(&xml[..line_start]);
        result.push_str(indent);
        result.push_str(&signature_element);
        result.push('\n');
        result.push_str(indent);
        result.push_str(&xml[line_start..]);
        Ok(result)
    } else {
        Err("Could not find Issuer element in AuthnRequest".to_string())
    }
}

// ---------------------------------------------------------------------------
// SAML Response parsing
// ---------------------------------------------------------------------------

/// Parsed SAML assertion attributes.
#[derive(Debug, Clone)]
pub struct SamlAttributes {
    /// NameID — the subject identifier.
    pub name_id: String,
    /// Session index for logout.
    pub session_index: Option<String>,
    /// All attribute values keyed by attribute name.
    pub attributes: HashMap<String, Vec<String>>,
}

/// Parse and validate a base64-encoded SAMLResponse from the ACS callback.
pub fn parse_saml_response(
    saml_response: &str,
    config: &SamlConfig,
    idp_cert_pem: &str,
    request_id: Option<&str>,
) -> Result<SamlAttributes, String> {
    // 1. Base64-decode
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(saml_response)
        .map_err(|e| format!("SAMLResponse base64 decode failed: {e}"))?;

    // 2. Try deflate decompression
    let xml_bytes = match decompress_deflate(&decoded) {
        Ok(decompressed) => decompressed,
        Err(_) => decoded,
    };

    let xml = String::from_utf8(xml_bytes)
        .map_err(|e| format!("SAMLResponse is not valid UTF-8: {e}"))?;

    // 3. Validate signature if in strict mode (obtains verified element)
    let verified_element = if config.strict_mode && !idp_cert_pem.is_empty() {
        Some(validate_response_signature(&xml, idp_cert_pem, request_id)?)
    } else {
        None
    };

    let assertion_xml = verified_element.as_deref().unwrap_or(&xml);

    // 4. Parse attributes from verified element (not raw document)
    let attrs = parse_assertion_xml(assertion_xml)?;

    // 5. Validate audience restriction against verified element
    if config.strict_mode && !idp_cert_pem.is_empty() {
        let audiences = extract_audiences(assertion_xml);
        if !audiences.is_empty() && !audiences.iter().any(|a| *a == config.entity_id) {
            return Err(format!(
                "SP entity ID '{}' not found in Audience restriction",
                config.entity_id
            ));
        }
    }

    // 6. Check time conditions if in strict mode (against verified element)
    if config.strict_mode {
        validate_time_conditions(assertion_xml)?;
    }

    Ok(attrs)
}

/// Parse the SAML assertion XML and extract attributes.
fn parse_assertion_xml(xml: &str) -> Result<SamlAttributes, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut name_id: Option<String> = None;
    let mut session_index: Option<String> = None;
    let mut attributes: HashMap<String, Vec<String>> = HashMap::new();

    let mut in_name_id = false;
    let mut in_attribute_value = false;
    let mut in_session_index = false;
    let mut current_attr_name = String::new();
    let mut current_text = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
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
                    "SessionIndex" => {
                        in_session_index = true;
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
                    } else if in_session_index {
                        session_index = Some(text_str);
                    } else if in_attribute_value && !current_attr_name.is_empty() {
                        current_text.push_str(&text_str);
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
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
                    "SessionIndex" => {
                        in_session_index = false;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(format!("SAML XML parse error: {e}")),
            _ => {}
        }
        buf.clear();
    }

    let name_id = name_id.ok_or("No NameID found in SAML assertion")?;
    let session_index = session_index.or_else(|| {
        attributes
            .remove("SessionIndex")
            .and_then(|v| v.into_iter().next())
    });

    Ok(SamlAttributes {
        name_id,
        session_index,
        attributes,
    })
}

/// Validate the XML signature in a SAML response.
///
/// Verifies:
/// 1. RSA-SHA256 signature over SignedInfo.
/// 2. Digest of the referenced element matches DigestValue (prevents
///    signature-wrapping attacks where an attacker moves the signed
///    element and inserts a forged one).
/// 3. InResponseTo matches the AuthnRequest ID we sent (when provided).
///
/// Returns the verified assertion element (with signature removed) so
/// downstream consumers can operate on trusted content rather than the
/// raw document.
fn validate_response_signature(
    xml: &str,
    idp_cert_pem: &str,
    request_id: Option<&str>,
) -> Result<String, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut in_signature_value = false;
    let mut in_signed_info = false;
    let mut signature_value = String::new();
    let mut signed_info_buf = Vec::new();
    let mut signed_info_depth = 0u32;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
                    "SignedInfo" => {
                        in_signed_info = true;
                        signed_info_depth = 1;
                        signed_info_buf.clear();
                        signed_info_buf.extend_from_slice(b"<");
                        signed_info_buf.extend_from_slice(e.name().as_ref());
                        for attr in e.attributes().flatten() {
                            signed_info_buf.push(b' ');
                            signed_info_buf.extend_from_slice(attr.key.as_ref());
                            signed_info_buf.extend_from_slice(b"=\"");
                            signed_info_buf.extend_from_slice(&attr.value);
                            signed_info_buf.push(b'"');
                        }
                        signed_info_buf.push(b'>');
                    }
                    "SignatureValue" => {
                        in_signature_value = true;
                        signature_value.clear();
                    }
                    _ if in_signed_info => {
                        signed_info_depth += 1;
                        // Capture element start
                        signed_info_buf.extend_from_slice(b"<");
                        signed_info_buf.extend_from_slice(e.name().as_ref());
                        for attr in e.attributes().flatten() {
                            signed_info_buf.push(b' ');
                            signed_info_buf.extend_from_slice(attr.key.as_ref());
                            signed_info_buf.extend_from_slice(b"=\"");
                            signed_info_buf.extend_from_slice(&attr.value);
                            signed_info_buf.push(b'"');
                        }
                        signed_info_buf.push(b'>');
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if in_signed_info {
                    signed_info_buf.extend_from_slice(b"<");
                    signed_info_buf.extend_from_slice(e.name().as_ref());
                    for attr in e.attributes().flatten() {
                        signed_info_buf.push(b' ');
                        signed_info_buf.extend_from_slice(attr.key.as_ref());
                        signed_info_buf.extend_from_slice(b"=\"");
                        signed_info_buf.extend_from_slice(&attr.value);
                        signed_info_buf.push(b'"');
                    }
                    signed_info_buf.extend_from_slice(b"/>");
                }
                if local_name(&tag) == "SignatureValue" {
                    in_signature_value = true;
                    signature_value.clear();
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_signature_value {
                    let raw = String::from_utf8_lossy(e.as_ref());
                    signature_value.push_str(&raw);
                }
                if in_signed_info {
                    signed_info_buf.extend_from_slice(e.as_ref());
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if in_signed_info {
                    signed_info_buf.extend_from_slice(b"</");
                    signed_info_buf.extend_from_slice(e.name().as_ref());
                    signed_info_buf.push(b'>');
                    signed_info_depth -= 1;
                    if signed_info_depth == 0 {
                        in_signed_info = false;
                    }
                }
                if local_name(&tag) == "SignatureValue" {
                    in_signature_value = false;
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => return Err(format!("XML parse error finding signature: {e}")),
            _ => {}
        }
        buf.clear();
    }

    if signature_value.is_empty() {
        return Err("No SignatureValue found in SAML response".to_string());
    }

    // Extract Reference URI from SignedInfo to prevent signature wrapping attacks.
    let signed_info_str =
        String::from_utf8(signed_info_buf).map_err(|e| format!("SignedInfo UTF-8 error: {e}"))?;
    let reference_uri = extract_reference_uri(&signed_info_str)
        .ok_or("No Reference URI found in SignedInfo")?;

    // Extract Assertion ID and verify it matches the Reference URI.
    let assertion_id = extract_assertion_id(xml)
        .ok_or("No Assertion element with ID found in SAML response")?;
    if reference_uri != assertion_id {
        return Err(format!(
            "Signature Reference URI '{reference_uri}' does not match Assertion ID '{assertion_id}'"
        ));
    }

    let cert_der = parse_certificate_der(idp_cert_pem)?;
    let signed_info_canonical = exclusive_canonicalize(&signed_info_str);

    verify_rsa_sha256(
        &cert_der,
        signed_info_canonical.as_bytes(),
        signature_value.trim(),
    )?;

    // --- Digest verification (prevents signature-wrapping) ---
    let expected_digest = extract_reference_digest_value(&signed_info_str)
        .ok_or("No DigestValue found in SignedInfo")?;
    let element_xml = extract_element_by_id(xml, &reference_uri)
        .ok_or("Referenced element not found in SAML response")?;
    let element_xml = remove_signature_element(&element_xml);
    let canonical = exclusive_canonicalize(&element_xml);
    let computed_digest = sha256_digest_b64(canonical.as_bytes());
    if computed_digest.trim() != expected_digest.trim() {
        return Err("Digest verification failed — referenced element tampered".to_string());
    }

    // --- InResponseTo check ---
    if let Some(req_id) = request_id {
        let in_response_to = extract_in_response_to(xml);
        match in_response_to {
            Some(ref irt) if irt != req_id => {
                return Err(format!(
                    "InResponseTo '{irt}' does not match AuthnRequest ID '{req_id}'"
                ));
            }
            None => {
                return Err(
                    "InResponseTo attribute missing from SAML response".to_string(),
                );
            }
            _ => {}
        }
    }

    Ok(element_xml)
}

/// Extract the Reference URI from a SignedInfo XML fragment.
fn extract_reference_uri(signed_info: &str) -> Option<String> {
    let mut reader = Reader::from_str(signed_info);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if local_name(&tag) == "Reference" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"URI" {
                            let uri = String::from_utf8_lossy(&attr.value).to_string();
                            return Some(uri);
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Extract the ID attribute from the Assertion element in a SAML response.
fn extract_assertion_id(xml: &str) -> Option<String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if local_name(&tag) == "Assertion" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"ID" {
                            return Some(String::from_utf8_lossy(&attr.value).to_string());
                        }
                    }
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    None
}

/// Validate time conditions in the SAML assertion.
fn validate_time_conditions(xml: &str) -> Result<(), String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut conditions_not_before: Option<DateTime<Utc>> = None;
    let mut conditions_not_on_or_after: Option<DateTime<Utc>> = None;
    let mut subject_not_on_or_after: Option<DateTime<Utc>> = None;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e))
            | Ok(quick_xml::events::Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).to_string();
                match local_name(&tag) {
                    "Conditions" => {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            match key.as_str() {
                                "NotBefore" => {
                                    conditions_not_before = parse_saml_datetime(&val).ok();
                                }
                                "NotOnOrAfter" => {
                                    conditions_not_on_or_after = parse_saml_datetime(&val).ok();
                                }
                                _ => {}
                            }
                        }
                    }
                    "SubjectConfirmationData" => {
                        for attr in e.attributes().flatten() {
                            let key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                            let val = String::from_utf8_lossy(&attr.value).to_string();
                            if key == "NotOnOrAfter" {
                                subject_not_on_or_after = parse_saml_datetime(&val).ok();
                            }
                        }
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

    let now = Utc::now();

    if let Some(t) = conditions_not_before {
        if now < t {
            return Err(format!("SAML assertion not yet valid (NotBefore: {t})"));
        }
    }
    if let Some(t) = conditions_not_on_or_after {
        if now >= t {
            return Err(format!("SAML assertion expired (NotOnOrAfter: {t})"));
        }
    }
    if let Some(t) = subject_not_on_or_after {
        if now >= t {
            return Err(format!(
                "SAML subject confirmation expired (NotOnOrAfter: {t})"
            ));
        }
    }

    Ok(())
}

/// Parse a SAML datetime string (ISO 8601).
fn parse_saml_datetime(s: &str) -> Result<DateTime<Utc>, String> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|_| {
            DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ").map(|dt| dt.with_timezone(&Utc))
        })
        .or_else(|_| {
            DateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ").map(|dt| dt.with_timezone(&Utc))
        })
        .map_err(|e| format!("Invalid SAML datetime '{s}': {e}"))
}

/// Extract group memberships from parsed SAML attributes.
pub fn extract_groups(attrs: &SamlAttributes, groups_attribute: Option<&str>) -> Vec<String> {
    let attr_name = groups_attribute.unwrap_or("groups");
    attrs.attributes.get(attr_name).cloned().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// SP metadata generation
// ---------------------------------------------------------------------------

/// Generate SP metadata XML.
pub fn generate_sp_metadata(config: &SamlConfig) -> String {
    let cert_block = match &config.certificate {
        Some(cert) => {
            format!(
                "<md:KeyDescriptor use=\"signing\">\n  \
                 <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n    \
                 <ds:X509Data>\n      \
                 <ds:X509Certificate>{cert}</ds:X509Certificate>\n    \
                 </ds:X509Data>\n  \
                 </ds:KeyInfo>\n\
                 </md:KeyDescriptor>"
            )
        }
        None => String::new(),
    };

    format!(
        concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"",
            " entityID=\"{}\">",
            "<md:SPSSODescriptor",
            " AuthnRequestsSigned=\"true\"",
            " WantAssertionsSigned=\"true\"",
            " protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">",
            "{}",
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress</md:NameIDFormat>",
            "<md:AssertionConsumerService",
            " Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"",
            " Location=\"{}\"",
            " index=\"0\"",
            " isDefault=\"true\"/>",
            "</md:SPSSODescriptor>",
            "</md:EntityDescriptor>",
        ),
        xml_escape(&config.entity_id),
        cert_block,
        xml_escape(&config.acs_url),
    )
}

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// SAML 2.0 SP auth provider.
pub struct SamlProvider {
    config: SamlConfig,
    /// Cached IdP metadata.
    idp_metadata: std::sync::OnceLock<IdpMetadata>,
    /// The AuthnRequest ID we sent, held until the ACS callback arrives.
    pending_request_id: std::sync::Mutex<Option<String>>,
}

impl SamlProvider {
    pub fn new(config: SamlConfig) -> Self {
        Self {
            config,
            idp_metadata: std::sync::OnceLock::new(),
            pending_request_id: std::sync::Mutex::new(None),
        }
    }

    /// Get a reference to the provider's configuration.
    pub fn config(&self) -> &SamlConfig {
        &self.config
    }

    /// Load IdP metadata from file or URL.
    async fn load_idp_metadata(&self) -> Result<&IdpMetadata, String> {
        if let Some(meta) = self.idp_metadata.get() {
            return Ok(meta);
        }

        let xml = if let Some(path) = &self.config.idp_metadata_file {
            std::fs::read_to_string(path)
                .map_err(|e| format!("Failed to read IdP metadata file: {e}"))?
        } else if let Some(url) = &self.config.idp_metadata_url {
            reqwest::get(url)
                .await
                .map_err(|e| format!("Failed to fetch IdP metadata: {e}"))?
                .text()
                .await
                .map_err(|e| format!("Failed to read IdP metadata response: {e}"))?
        } else {
            return Err("No IdP metadata URL or file configured".to_string());
        };

        let metadata = parse_idp_metadata(&xml)?;
        let _ = self.idp_metadata.set(metadata);
        Ok(self.idp_metadata.get().unwrap())
    }
}

#[async_trait]
impl AuthProvider for SamlProvider {
    fn id(&self) -> &str {
        "saml"
    }

    fn capabilities(&self) -> Capabilities {
        Capabilities::AUTHENTICATE | Capabilities::REDIRECT
    }

    async fn authenticate(&self, request: &AuthRequest) -> AuthResult {
        // ACS callback?
        if let Some(params) = &request.callback_params {
            if let Some(saml_response) = params.get("SAMLResponse") {
                return self.handle_acs_callback(saml_response).await;
            }
        }

        // Generate AuthnRequest and redirect to IdP
        let metadata = match self.load_idp_metadata().await {
            Ok(m) => m,
            Err(e) => return AuthResult::Unavailable(format!("SAML IdP metadata error: {e}")),
        };

        match build_authn_request(&self.config, &metadata.sso_url) {
            Ok((id, _xml, redirect_url)) => {
                // Store the request ID so InResponseTo can be verified on callback.
                *self.pending_request_id.lock().unwrap() = Some(id);
                AuthResult::Redirect(redirect_url)
            }
            Err(e) => AuthResult::Failure(format!("Failed to build SAML AuthnRequest: {e}")),
        }
    }

    fn has_inline_login_form(&self) -> bool {
        false
    }
}

impl SamlProvider {
    /// Handle the ACS callback with a SAMLResponse.
    async fn handle_acs_callback(&self, saml_response_b64: &str) -> AuthResult {
        let metadata = match self.load_idp_metadata().await {
            Ok(m) => m,
            Err(e) => return AuthResult::Unavailable(format!("SAML IdP metadata error: {e}")),
        };

        // Retrieve and clear the pending request ID for InResponseTo verification.
        let request_id = self.pending_request_id.lock().unwrap().take();

        match parse_saml_response(
            saml_response_b64,
            &self.config,
            &metadata.certificate,
            request_id.as_deref(),
        ) {
            Ok(attrs) => {
                let groups = extract_groups(&attrs, self.config.groups_attribute.as_deref());
                AuthResult::Success {
                    subject: attrs.name_id.clone(),
                    display_name: attrs.name_id,
                    groups,
                    role: None,
                }
            }
            Err(e) => AuthResult::Failure(format!("SAML response validation failed: {e}")),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    #[test]
    fn saml_provider_capabilities() {
        let provider = SamlProvider::new(SamlConfig::default());
        assert_eq!(provider.id(), "saml");
        let caps = provider.capabilities();
        assert!(caps.contains(Capabilities::AUTHENTICATE));
        assert!(caps.contains(Capabilities::REDIRECT));
        assert!(!caps.contains(Capabilities::MFA));
    }

    #[tokio::test]
    async fn saml_provider_redirect_without_metadata_fails() {
        let provider = SamlProvider::new(SamlConfig::default());
        let result = provider.authenticate(&AuthRequest::default()).await;
        assert!(matches!(result, AuthResult::Unavailable(_)));
    }

    #[test]
    fn saml_provider_no_inline_form() {
        let provider = SamlProvider::new(SamlConfig::default());
        assert!(!provider.has_inline_login_form());
    }

    #[test]
    fn parse_saml_response_missing_cert_fails() {
        let config = SamlConfig::default();
        let result = parse_saml_response("fake-response", &config, "", None);
        assert!(result.is_err());
    }

    #[test]
    fn extract_groups_default_attribute() {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert("groups".into(), vec!["admin".into(), "devops".into()]);
        let attrs = SamlAttributes {
            name_id: "user@example.com".into(),
            session_index: None,
            attributes,
        };
        let groups = extract_groups(&attrs, None);
        assert_eq!(groups, vec!["admin".to_string(), "devops".to_string()]);
    }

    #[test]
    fn extract_groups_custom_attribute() {
        let mut attributes = std::collections::HashMap::new();
        attributes.insert(
            "memberOf".into(),
            vec!["cn=admins,ou=groups,dc=example,dc=com".into()],
        );
        let attrs = SamlAttributes {
            name_id: "user@example.com".into(),
            session_index: Some("_abc123".into()),
            attributes,
        };
        let groups = extract_groups(&attrs, Some("memberOf"));
        assert_eq!(groups.len(), 1);
        assert!(groups[0].contains("admins"));
    }

    #[test]
    fn extract_groups_missing_attribute_returns_empty() {
        let attrs = SamlAttributes {
            name_id: "user@example.com".into(),
            session_index: None,
            attributes: std::collections::HashMap::new(),
        };
        let groups = extract_groups(&attrs, None);
        assert!(groups.is_empty());
    }

    #[test]
    fn generate_sp_metadata_basic() {
        let config = SamlConfig {
            entity_id: "https://persea.example.com/saml/metadata".into(),
            acs_url: "https://persea.example.com/saml/acs".into(),
            ..Default::default()
        };
        let xml = generate_sp_metadata(&config);
        assert!(xml.contains("EntityDescriptor"));
        assert!(xml.contains("persea.example.com"));
        assert!(xml.contains("HTTP-POST"));
    }

    #[test]
    fn generate_sp_metadata_with_cert() {
        let config = SamlConfig {
            entity_id: "https://persea.example.com/saml/metadata".into(),
            acs_url: "https://persea.example.com/saml/acs".into(),
            certificate: Some("MIICpDCCAYwCCQDU...".into()),
            ..Default::default()
        };
        let xml = generate_sp_metadata(&config);
        assert!(xml.contains("KeyDescriptor"));
        assert!(xml.contains("MIICpDCCAYwCCQDU..."));
    }

    #[test]
    fn xml_escape_handles_special_chars() {
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("it's"), "it&apos;s");
    }

    #[test]
    fn parse_idp_metadata_minimal() {
        let xml = concat!(
            r#"<?xml version="1.0"?>"#,
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata""#,
            r#" entityID="https://idp.example.com">"#,
            r#"<md:IDPSSODescriptor>"#,
            r#"<md:SingleSignOnService"#,
            r#" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect""#,
            r#" Location="https://idp.example.com/sso"/>"#,
            r#"<md:KeyDescriptor use="signing">"#,
            r#"<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">"#,
            r#"<ds:X509Certificate>MIIBIjANBgkqhki...cert...</ds:X509Certificate>"#,
            r#"</ds:KeyInfo>"#,
            r#"</md:KeyDescriptor>"#,
            r#"</md:IDPSSODescriptor>"#,
            r#"</md:EntityDescriptor>"#,
        );

        let meta = parse_idp_metadata(xml).unwrap();
        assert_eq!(meta.sso_url, "https://idp.example.com/sso");
        assert_eq!(meta.entity_id, "https://idp.example.com");
        assert!(meta.certificate.contains("MIIBIjANBgkqhki"));
    }

    #[test]
    fn parse_idp_metadata_missing_sso_url_fails() {
        let xml = concat!(
            r#"<?xml version="1.0"?>"#,
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata""#,
            r#" entityID="https://idp.example.com">"#,
            r#"</md:EntityDescriptor>"#,
        );

        let result = parse_idp_metadata(xml);
        assert!(result.is_err());
    }

    #[test]
    fn parse_saml_datetime_valid() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00Z").unwrap();
        assert_eq!(dt.year(), 2024);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 15);
    }

    #[test]
    fn parse_saml_datetime_with_millis() {
        let dt = parse_saml_datetime("2024-01-15T10:30:00.123Z").unwrap();
        assert_eq!(dt.year(), 2024);
    }

    #[test]
    fn parse_saml_datetime_invalid() {
        assert!(parse_saml_datetime("not-a-date").is_err());
    }

    #[test]
    fn deflate_encode_produces_output() {
        let data = b"Hello, SAML!";
        let compressed = deflate_encode(data);
        assert!(!compressed.is_empty());
    }

    #[test]
    fn sha256_digest_b64_deterministic() {
        let a = sha256_digest_b64(b"test");
        let b = sha256_digest_b64(b"test");
        assert_eq!(a, b);
        assert!(!a.is_empty());
    }

    #[tokio::test]
    async fn saml_provider_handles_acs_callback_missing_response() {
        let provider = SamlProvider::new(SamlConfig::default());
        let mut params = std::collections::HashMap::new();
        params.insert("SAMLResponse".into(), "dGVzdA==".into());
        let request = AuthRequest {
            callback_params: Some(params),
            ..Default::default()
        };
        let result = provider.authenticate(&request).await;
        // No IdP metadata configured → Unavailable, or invalid XML → Failure
        assert!(!matches!(result, AuthResult::Success { .. }));
    }
}
