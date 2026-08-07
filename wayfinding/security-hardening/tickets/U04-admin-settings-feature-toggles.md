# Ticket: Admin settings — feature toggles and professional redesign

wayfinder:task
Priority: P1

## Question

The admin settings page needs two things:
1. **Feature toggles** — per-protocol switches (RDP, Proxmox, VMware, SSH Tunnels, API Keys, Recordings, VDI, etc.). When disabled, the feature is hidden from the sidebar, entry types, and connection flows. Persisted in `system_settings` table.
2. **Professional iconography** — replace the childish emojis (⚡ Features, 💾 Storage) with simple SVG icons or remove them entirely. Session 🖥 and Server icons are acceptable; Features and Storage are not.

Redesign the Settings page into a clean card-based layout: "Session" section (max duration, concurrency), "Features" section (toggle list with clean labels), "Storage" section (DB vs Vault), "Security" section (TLS, password policies). Each toggle has a label and description. No emojis.

## Deliverable

Updated `templates/pages/admin/settings.html` with:
- Feature toggles wired to `system_settings` table (backend already has this table)
- Toggles for: RDP, Proxmox, VMware, SSH Tunnels, API Keys, Recordings, VDI, Web Sessions, SPICE
- Disabled features removed from sidebar nav and entry type dropdown
- Professional SVG icons or no icons
- `cargo check` passes, all settings save correctly

## Files to touch
- `templates/pages/admin/settings.html` (primary)
- `src/api/admin.rs` or `src/api/mod.rs` (settings CRUD if not already wired)
- `templates/partials/sidebar.html` (feature-flag conditional rendering)
