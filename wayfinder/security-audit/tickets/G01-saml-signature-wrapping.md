# Ticket: C02 gap — SAML signature wrapping still exploitable

wayfinder:task
Priority: P0
Phase: Critical

## Gap

Prior fix replaced no-op canonicalization with a buggy hand-rolled one and never added digest verification.

### Problem 1 — `exclusive_canonicalize` (lines 176-307)

- Re-emits ordinary (non-namespace) attributes on every descendant instead of only in-scope namespace declarations ("attribute bleed", lines 213-226)
- Pushes `ns_stack` for `Event::Empty` self-closing tags without a matching pop (no `Event::End` fires), corrupting state so attributes leak onto sibling elements

### Problem 2 — `validate_response_signature` (lines 862-990)

- Verifies RSA signature over `SignedInfo` but never recomputes the Assertion's digest and compares to `DigestValue`
- Without that binding, attacker can alter Assertion `NameID`/`Attribute` values after signing (classic XSW)

### Missing from original finding, never implemented

- `InResponseTo` correlation check
- `Audience` restriction check

## Fix

1. Replace hand-rolled canonicalization with a vetted XML-C14N crate (e.g. `quick-xml` with proper Exclusive C14N, or `xmlsec`)
2. After signature verification: compute digest of referenced Assertion element, compare to `DigestValue`, reject on mismatch
3. Add `InResponseTo` check: assertion's `InResponseTo` must match the `ID` of the AuthnRequest we sent
4. Add `Audience` restriction: assertion's `Audience` must include our SP entity ID

## Files

- `src/auth_providers/saml.rs:176-307` — canonicalization
- `src/auth_providers/saml.rs:862-990` — signature validation

## Deliverable

Real Exclusive C14N. Digest verification. InResponseTo + Audience checks. `cargo check` passes. SAML flow works with test IdP.
