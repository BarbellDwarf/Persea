# Ticket: UI Redesign

wayfinder:research
Blocked by: 009 (User Identity Model), 002 (Auth Provider Architecture), 014 (RBAC Connection Perms)

## Question

How should persea redesign its UI to be professional and modern?

Current UI: 8 HTML pages with inline CSS, 8 themes, feels "childish and unprofessional." Target: expandable sidebar navigation, two sections (user + admin), professional design inspired by Grafana/Portainer/Cockpit.

Key decisions needed:

1. **Templating engine** — Askama (Jinja2-like, compile-time), maud (HTML macro), Leptos (full SPA), or htmx + server-rendered?
2. **CSS framework** — Tailwind CSS? Pico CSS? Custom? Something that produces clean, professional results without looking like every other Tailwind site.
3. **Layout structure** — Expandable sidebar with sections:
   - User section: Servers/Connections, Active Sessions, Quick Connect
   - Admin section (behind Settings → Admin): Users, Groups, Roles, Auth Settings, Audit Logs, Reports, System Config, Docs
   - Account section: Profile, API Keys, TOTP Enrollment, Session History
4. **Component patterns** — Data tables with sort/filter, status badges, card layouts, form patterns, modal dialogs.
5. **Dark/light theme** — System preference detection + manual toggle. Professional color palette.
6. **Guacamole client integration** — Keep existing `static/guac/` JS client for remote desktop. Embed in an iframe or separate route.
7. **Responsive design** — Mobile-friendly? Or desktop-focused (remote access tools are typically desktop)?
8. **Accessibility** — ARIA labels, keyboard navigation, screen reader support. Which level?
9. **Design references** — Grafana (dashboards), Portainer (container management), Cockpit (server admin), Tabby/Alacritty (terminal aesthetic).

## Research needed

- Askama vs maud vs Leptos vs htmx comparison for this use case
- Professional admin UI examples (Grafana, Portainer, Cockpit design language)
- How to embed Guacamole JS client in a modern layout
- Tailwind CSS vs alternatives for admin UIs
