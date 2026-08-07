# Ticket: SAML XML-DSig canonicalization is a no-op

wayfinder:task
Priority: P0
Phase: Critical

## Finding

`src/auth_providers/saml.rs:170-172` — `exclusive_canonicalize` just returns `xml.to_string()`. This means the signature verification compares against the non-canonicalized form, creating the shape of an XML Signature Wrapping vulnerability when SAML SSO is enabled. An attacker could inject a second `Assertion` element and the verifier would match the signature against the wrong one.

## Fix

Implement real Exclusive C14N (W3C Recommendation) or adopt a vetted XML-DSig crate. The critical requirement is that the parsed assertion (`NameID`/`Attribute`) must correlate to the specific signed `Reference URI`, not just "first signature in the document."

Options:
1. Use `saml2-crate` or `xmlsec` which handle canonicalization properly
2. Implement `exclusive_canonicalize` per W3C Exclusive XML Canonicalization (sort attributes, normalize whitespace, handle `xmlns` properly)

Also add a check that the `Reference URI` in the `SignedInfo` matches the `Assertion ID` being consumed — currently the code just grabs the first assertion without checking.

## Files

- `src/auth_providers/saml.rs:170-172` — `exclusive_canonicalize`
- `src/auth_providers/saml.rs` — assertion consumption logic

## Deliverable

`exclusive_canonicalize` performs real Exclusive C14N. Signature verification correlates to the specific signed assertion. `cargo check` passes. SAML flow still works with a test IdP.
