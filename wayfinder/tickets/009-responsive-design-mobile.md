# Ticket: Responsive Design & Mobile Support

**Type:** grilling
**Labels:** ui-ux, wayfinder:grilling

## Question

Should the management pages (connections, sessions, recordings, admin) support mobile?

### Current state:
- **All 9 HTML files missing `<meta name="viewport">`** — mobile rendering is broken
- `connections.html` sidebar: fixed `min-width: 280px; max-width: 340px` — two-column layout with no breakpoint
- Nav bar: horizontal flex with no hamburger/overflow for small screens
- Modals: `min-width: 440px` — overflow on phones
- Tables in sessions/recordings: standard `<table>` with no responsive treatment
- `client.html` is inherently responsive (fullscreen display), but side panels eat phone screens

### Mobile use cases:
- Admin checking session status on phone
- Operator reviewing recordings on tablet
- User connecting to a session from mobile browser
- Support agent shadowing a session from field device

### Decision needed:

1. Mobile priority: admin/status pages first, or full mobile support?
2. Breakpoint strategy: stack columns at 768px, or fluid layout?
3. Should `client.html` side panels collapse on mobile?
4. Is this blocking other work, or can it be deferred?
