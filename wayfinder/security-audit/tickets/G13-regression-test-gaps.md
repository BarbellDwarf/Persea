# Ticket: L04 gap — Regression tests missing Critical coverage

wayfinder:task
Priority: P3
Phase: Low

## Gap

Current tests cover M01/H11/H07/H10. Missing:

1. **C01** — Test `esc()` escapes `<script>` in user data (may need `pub(crate)` or test via HTML output)
2. **C02** — Test SAML assertion `NameID` tampering is rejected by digest check (requires test fixture)
3. **C03** — Test non-operator role gets 403 from `power_action`, `vm_id` with `/` or `..` rejected
4. **M02** — Test `delete_recording` with `identity=None` returns Forbidden

Also: refactor M01/H11 tests to call real functions (make `ldap_escape`/`csv_escape_field` `pub(crate)` if needed) instead of reimplementing logic.

## Files

- `tests/security_regression.rs`
- `src/auth_providers/ldap.rs` — may need `pub(crate)` on `ldap_escape`
- `src/db.rs` — may need `pub(crate)` on `csv_escape_field`

## Deliverable

All Critical findings have regression tests. Existing tests call real code. `cargo test` passes.
