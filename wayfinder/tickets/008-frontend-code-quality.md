# Ticket: Frontend Code Quality & Bundle Strategy

**Type:** grilling
**Labels:** ui-ux, wayfinder:grilling

## Question

Should the inline JS/CSS in HTML files be extracted to external files?

### Current state:
- All JavaScript is inline in `<script>` tags across 9 HTML files
- `connections.html` alone has ~3,000+ lines of inline JS
- `client.html` has ~1,670 lines of inline JS
- No external JS files for application logic
- CSP requires `'unsafe-inline'` for scripts because of this
- `applyThemeColors()`, `initTheme()`, `escapeHtml()`, `escapeAttr()`, `apiHeaders()` copy-pasted across all pages
- Theme description map duplicated in every page
- `client.html` duplicates CSS variables from `rustguac.css`

### Problems:
- Caching impossible (every page load re-downloads same code)
- Code review harder
- CSP weakened by `'unsafe-inline'`
- DRY violations across pages
- No tree-shaking or dead code elimination

### Options:
1. **Extract to shared JS files** — `static/js/theme.js`, `static/js/auth.js`, `static/js/utils.js`
2. **Keep inline but deduplicate** — use server-side includes or build step
3. **Full build pipeline** — add esbuild/vite for bundling, minification, tree-shaking
4. **Minimal extraction** — just extract shared utilities, keep page-specific code inline

### Decision needed:

1. Extraction scope: all JS, shared-only, or keep inline?
2. Build tool: esbuild, vite, or no build step?
3. Should CSP be tightened as part of this work?
4. Priority: extract now or defer until other work is done?
