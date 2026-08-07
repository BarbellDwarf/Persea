# Ticket: CSP nonce not inserted into header + no SRI on CDN scripts

wayfinder:task
Priority: P1
Phase: High

## Finding

`src/main.rs:719-747` — CSP header hardcodes `'unsafe-inline'` in `script-src` + 3 CDN origins, neutralizing CSP as an XSS mitigation. No SRI hashes on CDN `<script>` tags in `base.html`.

## Overlap

**Existing ticket S01** (`security-hardening/tickets/S01-csp-nonce-wiring.md`) claims this was fixed. Verify that S01 actually:
1. Removed `'unsafe-inline'` from the CSP header
2. Added `<script nonce>` to ALL inline scripts across ALL templates
3. Added SRI hashes to CDN `<script>` tags in `base.html`

If S01 is incomplete, fix the gaps. If S01 fully resolved this, mark this ticket as verified/duplicate.

## Files

- `src/main.rs:719-747` — CSP header construction
- `templates/layouts/base.html` — CDN script tags
- All `templates/**/*.html` — inline `<script>` tags

## Deliverable

CSP header uses nonce (no `'unsafe-inline'`). All inline scripts have `nonce` attribute. CDN scripts have SRI `integrity` + `crossorigin` attributes. `cargo check` passes. App loads without CSP violations in browser console.
