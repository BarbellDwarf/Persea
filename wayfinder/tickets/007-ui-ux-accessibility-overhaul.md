# Ticket: UI/UX Accessibility Overhaul

**Type:** grilling
**Labels:** ui-ux, wayfinder:grilling

## Question

What accessibility improvements should be made across all 9 HTML pages?

### Critical findings:
1. **Missing `<html lang="en">`** on all 9 HTML files — screen readers can't determine language
2. **Missing `<meta name="viewport">`** on all 9 files — mobile rendering broken
3. **Near-zero ARIA usage** — only `role="listbox"` exists in entire UI
4. **No focus trapping in modals** — Tab key escapes modal overlays
5. **No visible keyboard focus indicators** — `outline: none` without replacement
6. **`--text-dim: #666`** fails WCAG AA contrast on dark backgrounds (2.4:1 ratio)

### Pages affected:
- `client.html` — Guacamole terminal client
- `connections.html` — Vault-backed connections (4,258 lines)
- `sessions.html` — session management
- `recordings.html` — recording playback
- `admin.html` — admin panel
- `tokens.html` — API token management
- `reports.html` — session reports
- `docs.html` — documentation viewer
- `index.html` — landing page

### Missing ARIA patterns:
- `role="dialog"` + `aria-modal="true"` on modals
- `aria-label` on icon-only buttons
- `aria-live` regions for error/status messages
- `aria-expanded` on collapsible toggles
- `role="navigation"` on `<nav>` elements
- `aria-current="page"` on active nav links

### Decision needed:

1. Accessibility priority: critical fixes first (lang, viewport, ARIA), or comprehensive overhaul?
2. Focus trap library: custom implementation or lightweight library?
3. Color contrast: adjust `--text-dim` to meet WCAG AA, or add high-contrast mode?
4. Should accessibility be a gating criterion for all future PRs?
