# Ticket: OIDC state fingerprint → HMAC-SHA256

wayfinder:task
Priority: P3

## Question

The OIDC state fingerprint at `oidc.rs:192-206` uses `DefaultHasher` (SipHash, non-cryptographic) to bind the state cookie to IP + User-Agent. An attacker who knows both could compute the fingerprint. Replace with HMAC-SHA256 using the CSRF secret (or a dedicated key) so the fingerprint can't be forged.

## Deliverable

Updated `oidc.rs` fingerprint computation. Test: state validation still works. Forgery with guessed fingerprint fails.
