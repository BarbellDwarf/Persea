# Themes

This page covers how the persea web UI looks and how to change it. There are
two independent layers:

1. **Per-user appearance** — every user can pick a colour preset and a
   dark/light mode. Stored per browser.
2. **Deployment branding** — the site title, logo, and primary colour shown
   to everyone, set by an admin.

They combine: a user who hasn't picked anything sees the deployment's
branding; a user who picks a preset sees their own choice.

---

## Quick choices

- **Just want a different look for yourself?** Use the dark/light/auto toggle
  at the top-right of every page (it cycles **auto → dark → light**), and
  pick a colour preset under **My Profile → Appearance → Color Accent**. Your
  choices are stored in your browser and follow you across sessions on that
  machine — they don't affect anyone else.
- **Want to brand the whole deployment?** Use the admin **Branding** page
  (title, logo, colour) — see below — or the `[theme]` block in
  `config.toml` for full control.
- **Want a custom palette?** Drop a theme file into the themes directory —
  no recompiling, no patches.

---

## Built-in presets

| Name | Look |
|------|------|
| `aurora` | Default. Midnight-navy background with a soft blue/cyan glow. |
| `dark` | Classic dark mode (red primary, teal accent, navy backgrounds). |
| `light` | Clean white & blue. |
| `high-contrast` | Maximum legibility, accessibility-friendly. |
| `terminal` | Monospaced green-on-black aesthetic. |
| `nord` | Cool greys + cyan, based on the Nord palette. |
| `corporate` | Slate & steel blue with an orange accent. |
| `jaguar` | Racing green & gold on a deep green-black background. |

Plus any user-supplied themes you've added (see below).

---

## Per-user appearance

- **Mode** — the header toggle cycles **auto → dark → light** (auto follows
  your operating system's preference). The same choice is under **My Profile
  → Appearance → Mode**.
- **Color Accent** — **My Profile → Appearance → Color Accent** lists
  **default** plus every built-in and user-supplied preset.

Both choices persist in browser storage (localStorage), so they follow the
user across sessions on that browser but don't affect anyone else.

> **How presets and branding interact:** the frontend only applies a preset
> when the user has *explicitly chosen one*. A user on **default** (or who
> has never picked anything) sees the deployment's branding if the admin
> configured any — otherwise the app's original green look. The admin
> configured preset is **not** force-applied to users who haven't chosen it.

---

## Admin branding page

The **Admin → Branding** page (`/admin/branding.html`) is the quick way to
brand the deployment. It lets an admin set:

- **Site title** — shown in the sidebar and page titles.
- **Logo** — either a URL (`https://...` or a relative path like
  `/uploads/logo/logo.png`) or an uploaded file (PNG, SVG, JPG, or ICO,
  max 2 MB).
- **Primary colour** — used for the sidebar active state, buttons, and
  accents.

The page shows a live preview as you type. Saved values are stored in the
database and merged into the runtime config.

> **Restart required:** branding changes take effect for everyone **after a
> server restart** (settings are merged into the running config at startup).
> The admin who saves sees a preview immediately; other users pick the new
> title/logo/colour up on the next page load after persea restarts.

---

## Setting a default in `config.toml`

The `[theme]` block sets the admin-configured preset and lets you override
individual colours on top of it. (Values set on the Branding page are merged
over these at startup.)

```toml
[theme]
preset = "aurora"            # base preset; defaults to "aurora" if omitted
logo_url = "/logo.png"       # optional, replaces the persea logo
primary_color = "#003366"    # any of the per-field overrides below
```

### Per-field overrides

Every colour in a theme can be overridden individually; the override wins and
the preset provides the rest. All values are CSS colour strings (`"#003366"`,
`"rgb(0,51,102)"`, `"hsl(210 100% 20%)"` — anything CSS accepts).

| Key | What it colours |
|-----|-----------------|
| `primary_color` | Primary action colour (buttons, links) |
| `primary_hover` | Primary hover state |
| `accent_color` | Accent/secondary colour |
| `accent_hover` | Accent hover state |
| `bg_color` | Page background |
| `surface_color` | Card/panel backgrounds |
| `input_color` | Form input backgrounds |
| `text_color` | Primary text |
| `text_muted` | Secondary/muted text |
| `text_dim` | Tertiary/dim text |
| `text_on_primary` | Text on primary-coloured backgrounds |
| `border_color` | Borders and dividers |
| `btn_disabled` | Disabled button colour |
| `bg_pattern` | CSS background-image (gradient, pattern, or `"none"`) |
| `status_pending` / `status_active` / `status_completed` / `status_error` / `status_expired` | Session-state badge colours |
| `type_ssh_bg` / `type_ssh_fg` | SSH session-type badge |
| `type_rdp_bg` / `type_rdp_fg` | RDP session-type badge |
| `type_vnc_bg` / `type_vnc_fg` | VNC session-type badge |
| `type_web_bg` / `type_web_fg` | Web session-type badge |
| `type_vdi_bg` / `type_vdi_fg` | VDI session-type badge |
| `hop_bg` / `hop_fg` | Jump host badge |

### Example: corporate branding on top of a preset

```toml
site_title = "Acme Remote Console"

[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

---

## User-supplied themes

You can ship your own themes as standalone files, without touching the Rust
code: drop a `<name>.toml` file into `<static_path>/themes/` and restart
persea. The theme then appears in the **Color Accent** picker for every user
and can be selected as `preset = "<name>"` in `config.toml`.

### File format

A theme file is a flat TOML table with one entry per colour. The filename
(minus `.toml`) is the theme's id — there is **no** `name` field inside the
file. Field names match the per-field overrides above **without** the
`_color` suffix (`primary`, not `primary_color`); the sole exception is
`bg_pattern`, which defaults to `"none"` if omitted. All other fields are
required.

```toml
# /opt/persea/static/themes/acme-night.toml
primary          = "#003366"
primary_hover    = "#002244"
accent           = "#FF6600"
accent_hover     = "#CC4400"
bg               = "#0a0e1a"
surface          = "#141a2c"
input            = "#0f1422"
text             = "#e0e6f0"
text_muted       = "#a0a8b8"
border           = "#2a3045"
text_dim         = "#606878"
text_on_primary  = "#ffffff"
btn_disabled     = "#444a5c"
status_pending   = "#f0c040"
status_active    = "#22d3a0"
status_completed = "#888"
status_error     = "#ff5566"
status_expired   = "#666"
type_ssh_bg      = "#1b4332"
type_ssh_fg      = "#52b788"
type_rdp_bg      = "#3d1f00"
type_rdp_fg      = "#f0a050"
type_vnc_bg      = "#2d1b4e"
type_vnc_fg      = "#b07ff0"
type_web_bg      = "#1a1a4e"
type_web_fg      = "#7b8ff0"
type_vdi_bg      = "#0e2a2a"
type_vdi_fg      = "#2dd4bf"
hop_bg           = "#0d2818"
hop_fg           = "#34d399"
bg_pattern       = "none"
```

A complete example ships with persea at
`static/themes/catppuccin-macchiato.toml` — copy it and tweak.

### Naming rules

Theme filenames (and therefore theme ids) must match `[a-zA-Z0-9_-]{1,64}`.
Anything else (spaces, dots, non-ASCII, control characters) is rejected at
load time with a log warning and the file is ignored. This keeps theme ids
safe to render in the UI picker and in log lines, and rules out path-traversal
or lookalike-character tricks from crafted filenames.

### Overriding a built-in

A file named after a built-in (`aurora.toml`, `corporate.toml`, ...)
**replaces** the built-in in the picker and in `preset` resolution. This is
the supported way to re-brand a built-in without forking persea: edit your
own `aurora.toml` rather than patching the source.

### Loading rules

- Themes are loaded **once at startup** — restart persea after adding,
  editing, or removing a theme file.
- Only `.toml` files are loaded.
- Files missing required fields are skipped with a parse warning.
- Files with invalid TOML are skipped with a parse warning.
- Built-ins load first; user themes are appended, or override a built-in with
  the same name.

### Where the themes directory lives

The themes directory is `<static_path>/themes/`. `static_path` defaults to:

| Install method | Default static_path |
|----------------|---------------------|
| `.deb` (Debian) | `/opt/persea/static/` |
| Docker image | `/opt/persea/static/` |
| `install.sh` (bare metal) | `/opt/persea/static/` |
| Cargo run from source | `./static/` |

For Docker, mount your themes over the in-image path:

```bash
docker run -v /etc/persea/themes:/opt/persea/static/themes:ro ...
```
