# Ticket: Wire CSP nonce into script-src header

wayfinder:task
Priority: P1

## Question

The CSP header at `main.rs:744` uses `'unsafe-inline'` in `script-src`, defeating XSS protection. A `CspNonce` is already generated per-request (`main.rs:719-728`) and stored as an extension, but the CSP header ignores it. Wire the nonce into the header and remove `'unsafe-inline'`.

Also audit every inline `<script>` tag across all templates to ensure they carry the nonce attribute, since `'unsafe-inline'` is being removed. If any scripts are loaded from CDNs (e.g., Tailwind, htmx), they need `'unsafe-inline'` replaced with `'self'` plus any CDN domains.

## Deliverable

Updated CSP header using nonce. All inline scripts annotated with the nonce attribute. `cargo check` passes. No JS errors in browser console after the change.
