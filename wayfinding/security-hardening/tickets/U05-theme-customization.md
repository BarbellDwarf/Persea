# Ticket: Theme customization — preset picker + dark/light/system mode

wayfinder:task
Priority: P2

## Question

Users need the ability to customize their UI appearance:
1. **Preset theme picker** — aurora, dark, light, high-contrast, terminal, nord, corporate, jaguar (8 presets already defined in config.rs). Exposed in the user menu dropdown.
2. **Dark/Light/System mode** — the existing header toggle (after U02 fixes it) should offer three states: dark, light, auto (follows OS preference via `prefers-color-scheme` media query).
3. The theme.js system already handles presets + localStorage. The header toggle just needs to call the right function and offer three-state switching.

## Deliverable

Updated `templates/partials/header.html`:
- Theme toggle cycles through: dark → light → auto (with a small indicator showing current mode)
- The user menu theme preset list (already in theme.js:18-48) renders correctly
- localStorage keys `persea_theme` (preset name), `persea_theme_colors` (applied colors), `theme` (dark/light/auto) all stay in sync

Updated `static/js/theme.js`:
- Extend `toggleTheme` to handle auto mode: listen to `prefers-color-scheme` media query and react to OS changes
- Store `"auto"` as the `theme` localStorage value and apply the OS preference

## Files to touch
- `templates/partials/header.html` (toggle UI)
- `static/js/theme.js` (auto mode logic)
- No conflict with U02 — they modify the same files but the work is additive (U02 fixes the basic toggle, U05 extends it with mode picker)
