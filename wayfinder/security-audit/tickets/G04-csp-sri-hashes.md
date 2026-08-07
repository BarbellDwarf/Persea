# Ticket: H04 gap — CSP SRI hashes missing on CDN scripts

wayfinder:task
Priority: P1
Phase: High

## Gap

Nonce wiring and `unsafe-inline` removal are done. Only remaining gap: no `integrity`/`crossorigin` on CDN scripts.

- `templates/base.html:17` — `https://cdn.tailwindcss.com` — no SRI
- `templates/base.html:45` — `https://unpkg.com/htmx.org@2.0.4` — no SRI

## Fix

Add SRI hashes for the pinned CDN versions. Compute from actual CDN responses (fetch once, `sha384sum`):

```html
<script src="https://cdn.tailwindcss.com"
  integrity="sha384-<hash>"
  crossorigin="anonymous"></script>
<script src="https://unpkg.com/htmx.org@2.0.4"
  integrity="sha384-<hash>"
  crossorigin="anonymous"></script>
```

## Files

- `templates/base.html:17,45`

## Deliverable

CDN scripts have SRI integrity hashes. CSP header allows the CDN origins. App loads without CSP violations.
