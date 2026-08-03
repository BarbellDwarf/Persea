# Research: SAML 2.0 Service Provider Integration

## Executive Summary

**Recommendation: `gamlastan` (pure-Rust) for production SAML SP.**

`gamlastan` is the clear winner — it's a comprehensive, pure-Rust SAML 2.0 library implementing the full spec with errata05 corrections. It passes 263/263 Italian SPID conformance checks, has 91.5% documentation coverage, includes a 32-check assertion validator, replay cache, attribute mapping, and all SAML profiles. Zero C dependencies. Released June 2026, actively maintained by Kushal Das (PyCA/GitPython maintainer).

`samael` is the older alternative but is marked "work in progress," requires C libs (xmlsec1/libxml2) via FFI, and docs.rs fails to build the latest version. Use only if you specifically need xmlsec1 compatibility.

---

## 1. SAML Crate Comparison

### `gamlastan` (v0.7.0) — RECOMMENDED

| Aspect | Detail |
|--------|--------|
| **Downloads** | New (June 2026), growing |
| **C deps** | None — pure Rust |
| **SP support** | Full: `profiles::sso::sp::create_authn_request`, ACS binding helpers |
| **Security** | 32-check `AssertionValidator`, replay cache, errata05 compliance |
| **Crypto** | XML-DSig + XML-Enc via `bergshamra` (pure Rust) |
| **Metadata** | Full `EntityDescriptor` parsing, caching, endpoint resolution |
| **Attribute mapping** | `attribute_map::AttributeConverterSet` with OID ↔ local name conversion |
| **Profiles** | Web Browser SSO (SP+IdP), SLO, ECP, Artifact Resolution, NameID Management |
| **Conformance** | 263/263 SPID checks passed |
| **Docs** | 91.5% documented |
| **License** | BSD-2-Clause |

**Why:** Full spec compliance, zero C deps, battle-tested via SPID conformance, comprehensive validation. The `bergshamra` crypto layer handles XML-DSig natively — no FFI needed.

### `samael` (v0.0.22) — FALLBACK

| Aspect | Detail |
|--------|--------|
| **Downloads** | ~579K (established) |
| **C deps** | `xmlsec1`, `libxml2`, `libxslt`, `libiconv`, `libclang`, `openssl` |
| **SP support** | `ServiceProviderBuilder`, `parse_base64_response`, `metadata()` |
| **Security** | Basic validation: destination, issuer, expiry, audience, bearer confirmation |
| **Crypto** | FFI bindings to `xmlsec1` via modified `rust-xmlsec` |
| **Metadata** | `EntityDescriptor` serde deserialization |
| **Status** | "Work in progress" — 108 stars, 63 forks |
| **License** | MIT |

**Why not first:** C dependency chain is heavy (especially `libclang` for bindgen). docs.rs fails to build latest versions. The `xmlsec` feature flag is the only path to signature validation, and it's FFI. Basic validation only — no replay cache, no errata checks.

### `gamlastan-actix` — Framework Adapter

`gamlastan` has an actix-web adapter crate. For axum, we'd implement the `bindings::HttpRequest`/`bindings::HttpResponseBuilder` traits or write thin axum handlers directly — the protocol logic lives in gamlastan, not the framework.

### Verdict

**Use `gamlastan`.** The pure-Rust stack, full spec coverage, and SPID conformance make it the production choice. `samael` is a reasonable fallback if gamlastan has issues, but the C deps are a significant deployment burden (especially in Docker — need `xmlsec1-dev`, `libxml2-dev`, `libxslt1-dev`, `libclang-dev`).

---

## 2. SP Metadata Generation

### What SP metadata looks like

```xml
<EntityDescriptor entityID="https://persea.example.com/saml/metadata"
                  validUntil="2026-08-01T00:00:00Z">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"
                   AuthnRequestsSigned="false"
                   WantAssertionsSigned="true">
    <KeyDescriptor use="signing">
      <KeyInfo>
        <X509Data>
          <X509Certificate>MIIC...</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo>...</KeyInfo>
      <EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        Location="https://persea.example.com/saml/slo"/>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                             Location="https://persea.example.com/saml/acs"
                             index="1" isDefault="true"/>
  </SPSSODescriptor>
  <ContactPerson contactType="technical">
    <SurName>persea</SurName>
  </ContactPerson>
</EntityDescriptor>
```

### With `gamlastan`

```rust
use gamlastan::xml::serialize::SamlSerialize;
use gamlastan::core::protocol::metadata::EntityDescriptor;
// Build SPSSODescriptor with KeyDescriptor, AssertionConsumerService, etc.
// Serialize via .to_xml_string()?
```

### With `samael` (if needed)

```rust
let sp = ServiceProviderBuilder::default()
    .entity_id("https://persea.example.com/saml/metadata".to_string())
    .key(private_key)
    .certificate(pub_key)
    .acs_url("https://persea.example.com/saml/acs".to_string())
    .slo_url("https://persea.example.com/saml/slo".to_string())
    .idp_metadata(idp_metadata)
    .build()?;

let metadata: EntityDescriptor = sp.metadata()?;
let metadata_xml = metadata.to_string()?;
```

### Config pattern (matching existing persea style)

```toml
[saml]
enabled = true
entity_id = "https://persea.example.com/saml/metadata"
acs_url = "https://persea.example.com/saml/acs"
slo_url = "https://persea.example.com/saml/slo"
idp_metadata_url = "https://idp.example.com/saml/metadata"
# Or load from file:
# idp_metadata_path = "/opt/persea/idp-metadata.xml"
certificate_path = "/opt/persea/sp-cert.pem"
private_key_path = "/opt/persea/sp-key.pem"
strict = true
groups_attribute = "groups"
default_role = "operator"
# Attribute mapping
username_attribute = "email"
email_attribute = "email"
# Role mapping from SAML groups
role_mapping = { "persea-admins" = "admin", "persea-operators" = "operator" }
```

---

## 3. ACS Handler

### POST endpoint to receive SAMLResponse

```rust
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize)]
pub struct SamlResponse {
    pub saml_response: String,   // base64-encoded SAMLResponse
    pub relay_state: Option<String>,
}

pub async fn acs_handler(
    State(state): State<SamlState>,
    Form(params): Form<HashMap<String, String>>,
) -> Result<impl IntoResponse, SamlError> {
    let encoded = params.get("SAMLResponse")
        .ok_or(SamlError::MissingResponse)?;
    let relay_state = params.get("RelayState").cloned().unwrap_or_default();

    // 1. Decode base64
    let xml_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)?;
    let xml = std::str::from_utf8(&xml_bytes)?;

    // 2. Parse and validate (gamlastan does all of this)
    let doc = gamlastan::xml::parse_secure(xml)?;  // XXE-safe parsing
    let response = gamlastan::xml::parse_saml::<ResponseRef>(&doc)?;

    // 3. Validate with AssertionValidator
    let config = gamlastan::security::SecurityConfig::new();  // or strict()
    let validator = AssertionValidator::new(&config)
        .with_replay_cache(&state.replay_cache);
    let result = validator.validate(&response, &validation_params)?;

    if !result.is_ok() {
        return Err(SamlError::ValidationFailed(result.errors()));
    }

    // 4. Extract attributes
    let attrs = extract_attributes(&response)?;

    // 5. Create session, redirect to relay_state or /
    let session_token = state.sessions.create(attrs).await?;
    Ok(Redirect::to(&relay_state))
}
```

### Security requirements

1. **XXE prevention** — `gamlastan::xml::parse_secure()` handles this (uses `uppsala` parser which disables external entities)
2. **Signature validation** — Handled by `AssertionValidator` + `bergshamra` crypto
3. **Audience restriction** — Checked by validator (SP entity ID must match)
4. **NotBefore/NotOnOrAfter** — Checked with configurable clock skew (default 180s)
5. **Destination** — Response destination must match ACS URL
6. **Issuer** — Response/Assertion issuer must match IdP entity ID
7. **Replay detection** — `InMemoryReplayCache` or custom `ReplayCache` impl
8. **RelayState sanitization** — gamlastan errata E90: length-limited, sanitized

---

## 4. Signature Validation

### Algorithms to support

Minimum required (per SAML spec and enterprise IdPs):
- **RSA-SHA256** — `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` (MUST)
- **RSA-SHA512** — `http://www.w3.org/2001/04/xmldsig-more#rsa-sha512` (common)

Optional (for modern IdPs):
- ECDSA-SHA256/384/512

### How gamlastan handles it

```rust
use gamlastan::crypto::{verify_signature, SignatureAlgorithm};
use gamlastan::security::SecurityConfig;

let mut config = SecurityConfig::new();
config.require_signed_assertions = true;
config.require_signed_responses = true;
// Algorithm restrictions are enforced at the crypto layer
```

### How to fetch IdP certificate

From IdP metadata XML:
```rust
use gamlastan::metadata::EntityDescriptor;

// Parse IdP metadata
let idp_meta_xml = reqwest::get(&config.idp_metadata_url).await?.text().await?;
let doc = gamlastan::xml::parse_secure(&idp_meta_xml)?;
let idp_meta = parse_saml::<EntityDescriptorRef>(&doc)?;

// Extract signing certificates from KeyDescriptor use="signing"
let signing_certs = idp_meta.signing_certificates()?;
```

Or from file: Load the PEM/DER certificate at startup.

---

## 5. Attribute Mapping

### Common SAML assertion attributes

| Attribute | Typical Name | OID |
|-----------|-------------|-----|
| Username/Email | `email`, `mail`, `urn:oid:0.9.2342.19200300.100.1.3` | email |
| Display Name | `displayName`, `cn` | `urn:oid:2.5.4.3` |
| Groups | `groups`, `memberOf`, `urn:oid:1.3.6.1.4.1.5923.1.5.1.1` | eduPersonAffiliation |
| First Name | `givenName` | `urn:oid:2.5.4.42` |
| Last Name | `sn`, `surname` | `urn:oid:2.5.4.4` |
| NameID | Subject NameID | Format-dependent |

### gamlastan attribute converter

```rust
use gamlastan::attribute_map::{AttributeConverterSet, LocalAttribute};
use gamlastan::core::constants::ATTRNAME_FORMAT_URI;

let converters = AttributeConverterSet::with_default_maps();

// Convert from SAML wire format (OIDs) to local names
let local_attrs = converters.to_local(saml_attributes);

// Or use configurable mapping
let email = local_attrs.get("mail").or_else(|| local_attrs.get("email"));
let groups = local_attrs.get("groups").or_else(|| local_attrs.get("memberOf"));
```

### Configurable mapping (persea config)

```toml
[saml.attribute_mapping]
username = ["email", "mail", "urn:oid:0.9.2342.19200300.100.1.3"]
email = ["email", "mail"]
display_name = ["displayName", "cn"]
groups = ["groups", "memberOf", "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"]
```

---

## 6. Group Extraction → Roles

### Multi-valued attributes

SAML group attributes are typically multi-valued:

```xml
<Attribute Name="groups" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
  <AttributeValue>persea-admins</AttributeValue>
  <AttributeValue>persea-operators</AttributeValue>
  <AttributeValue>engineering</AttributeValue>
</Attribute>
```

### Extraction code

```rust
fn extract_groups(assertion: &Assertion) -> Vec<String> {
    let mut groups = Vec::new();
    for attr_stmt in &assertion.attribute_statements {
        for attr in &attr_stmt.attributes {
            if GROUPS_ATTRIBUTE_NAMES.contains(&attr.name.as_str()) {
                for val in &attr.values {
                    groups.push(val.value.clone());
                }
            }
        }
    }
    groups
}

fn map_groups_to_role(groups: &[String], config: &SamlConfig) -> String {
    // Check role_mapping: group_name -> role
    for (group, role) in &config.role_mapping {
        if groups.contains(group) {
            return role.clone();
        }
    }
    // Fallback: check if any group matches role names directly
    for group in groups {
        if is_valid_role(group) {
            return group.clone();
        }
    }
    config.default_role.clone()
}
```

### Integration with `AuthIdentity`

```rust
// After SAML validation, create identity matching OIDC pattern
let identity = AuthIdentity::User {
    email: email_from_saml,
    role: mapped_role,
    groups: saml_groups,
};
```

---

## 7. Logout

### SLO (Single Logout) — NOT RECOMMENDED for v1

**Why skip SLO:**
- SAML SLO requires the SP to send LogoutRequest to the IdP, then handle LogoutResponse
- The IdP must then notify all other SPs — complex orchestration
- Browser-based SLO is unreliable (depends on browser keeping sessions alive)
- Most enterprise IdPs have broken SLO implementations
- Apache Guacamole's SAML extension doesn't implement SLO either
- The complexity/benefit ratio is terrible

**What to implement instead:**
- Local session termination (clear the session cookie/token)
- Optionally: generate a LogoutRequest and redirect to IdP SLO URL (best-effort)
- The IdP may or may not honor it

### Implementation (if needed later)

```rust
pub async fn slo_handler(State(state): State<SamlState>) -> impl IntoResponse {
    // 1. Destroy local session
    // 2. Generate LogoutRequest
    // 3. Redirect to IdP SLO URL via HTTP-POST binding
    let logout_request = gamlastan::profiles::slo::create_logout_request(...);
    // Build auto-submit form like AuthnRequest
}
```

---

## 8. IdP Metadata

### Loading strategy

```rust
pub struct IdpMetadataLoader {
    /// URL to fetch metadata from (e.g., https://idp.example.com/saml/metadata)
    url: Option<String>,
    /// Local file path (e.g., /opt/persea/idp-metadata.xml)
    path: Option<String>,
    /// Cached metadata with refresh time
    cache: Arc<RwLock<Option<(EntityDescriptor, Instant)>>>,
    /// Refresh interval (default: 1 hour)
    refresh_interval: Duration,
}
```

### Auto-refresh

```rust
impl IdpMetadataLoader {
    pub async fn get_metadata(&self) -> Result<EntityDescriptor, Error> {
        // Check cache freshness
        {
            let cache = self.cache.read().unwrap();
            if let Some((meta, fetched)) = cache.as_ref() {
                if fetched.elapsed() < self.refresh_interval {
                    return Ok(meta.clone());
                }
            }
        }

        // Fetch fresh metadata
        let xml = if let Some(url) = &self.url {
            reqwest::get(url).await?.text().await?
        } else if let Some(path) = &self.path {
            std::fs::read_to_string(path)?
        } else {
            return Err(Error::NoIdpMetadataSource);
        };

        let doc = gamlastan::xml::parse_secure(&xml)?;
        let meta = parse_saml::<EntityDescriptorRef>(&doc)?.to_owned();

        // Update cache
        *self.cache.write().unwrap() = Some((meta.clone(), Instant::now()));
        Ok(meta)
    }
}
```

### Rotation handling

- IdP metadata rotation = new signing certificates
- On refresh, reload certificates from metadata
- Old responses signed by previous cert should still validate during a grace period
- `gamlastan`'s metadata module handles `validUntil` and `cacheDuration`

---

## 9. Strict Mode

### Mandatory checks (always on)

| Check | Description |
|-------|-------------|
| Signature validation | Response or assertion must be signed |
| Issuer match | Response/Assertion issuer = IdP entity ID |
| Destination match | Response destination = SP ACS URL |
| Audience restriction | SP entity ID in AudienceRestriction |
| NotOnOrAfter | Assertion and SubjectConfirmation not expired |
| NotBefore | Assertion not used before validity |
| Bearer confirmation | SubjectConfirmation method = bearer |
| Recipient | SubjectConfirmationData.Recipient = ACS URL |
| Status success | StatusCode = Success |
| Replay detection | Assertion ID not seen before |

### Optional checks (configurable)

| Check | Default | Config |
|-------|---------|--------|
| Require signed assertions | true | `strict_sign_assertions` |
| Require signed responses | true | `strict_sign_responses` |
| Clock skew tolerance | 180s | `clock_skew_secs` |
| Max issue delay | 90s | `max_issue_delay_secs` |
| Allow IDP-initiated | false | `allow_idp_initiated` |
| Force authentication | false | `force_authn` |

### gamlastan SecurityConfig

```rust
// Production: strict mode
let config = SecurityConfig::strict();
// - require_signed_assertions: true
// - require_signed_responses: true
// - require_encrypted_assertions: true (if configured)
// - check_client_address: true
// - clock_skew_seconds: 180

// Development/testing: relaxed
let mut config = SecurityConfig::new();
config.require_signed_assertions = false;
config.clock_skew_seconds = 300;  // more tolerance
```

---

## 10. Apache Guacamole SAML Extension Reference

Guacamole's SAML extension config properties map to persea's needs:

| Guacamole Config | persea Equivalent |
|-----------------|---------------------|
| `saml-idp-metadata-url` | `idp_metadata_url` |
| `saml-entity-id` | `entity_id` |
| `saml-callback-url` | `acs_url` |
| `saml-strict` | `strict` |
| `saml-group-attribute` | `groups_attribute` |
| `saml-x509-cert-path` | `certificate_path` |
| `saml-private-key-path` | `private_key_path` |

Guacamole only supports POST binding for ACS. persea should match this — POST is the standard for SP.

---

## 11. Implementation Plan

### Files to create/modify

| File | Purpose |
|------|---------|
| `src/saml.rs` | SAML SP state, init, handlers (ACS, SLO, metadata) |
| `src/config.rs` | Add `SamlConfig` struct, add `saml: Option<SamlConfig>` to Config |
| `src/auth.rs` | Add `AuthIdentity::Saml` variant or reuse `User` variant |
| `src/api.rs` | Mount SAML routes |
| `src/main.rs` | Initialize SAML state at startup |
| `static/saml-login.html` | Login page with "Sign in with SAML" button (optional) |

### Dependencies to add

```toml
[dependencies]
gamlastan = "0.7"
```

### Route structure

```
GET  /saml/metadata     → SP metadata XML
POST /saml/acs          → Assertion Consumer Service
GET  /saml/login        → Redirect to IdP (SP-initiated SSO)
POST /saml/slo          → Single Logout (optional)
```

### Integration pattern (matches OIDC)

```rust
// In main.rs, after OIDC init:
let saml_state = if let Some(saml_config) = &config.saml {
    Some(saml::init_saml(saml_config, session_ttl).await?)
} else {
    None
};

// In router:
if let Some(saml) = saml_state {
    app = app
        .route("/saml/metadata", get(saml::metadata_handler))
        .route("/saml/acs", post(saml::acs_handler))
        .route("/saml/login", get(saml::login_handler))
        .layer(Extension(saml));
}
```

### Auth middleware integration

```rust
// In auth middleware, add SAML session check:
AuthIdentity::User { email, role, groups } => {
    // Already handles OIDC and SAML identically
    // SAML creates same AuthIdentity::User variant
}
```

---

## 12. Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| `gamlastan` is new (June 2026) | Medium — small community | SPID conformance (263/263) proves correctness. Active maintainer. |
| No axum adapter | Low — thin integration layer | Implement `bindings::HttpRequest` trait or write direct handlers |
| C deps if falling back to `saml` | High — Docker complexity | Avoid by using `gamlastan` |
| SLO complexity | Low — skip for v1 | Implement local session kill only |
| IdP metadata rotation | Medium | Auto-refresh with cache, graceful cert rollover |

---

## References

- `gamlastan` crate: https://crates.io/crates/gamlastan
- `gamlastan` docs: https://docs.rs/gamlastan/latest/gamlastan/
- `samael` crate: https://crates.io/crates/samael
- `samael` GitHub: https://github.com/njaremko/samael
- Apache Guacamole SAML docs: https://guacamole.apache.org/doc/gug/saml-auth.html
- SAML 2.0 spec: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- SAML 2.0 errata: https://docs.oasis-open.org/security/saml/v2.0/errata05/
