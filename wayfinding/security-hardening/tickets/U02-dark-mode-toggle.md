# Ticket: Fix dark mode toggle

wayfinder:task
Priority: P1

## Question

The dark/light mode toggle button in the header (`header.html:21-26`) does nothing visible. It toggles the `dark`/`light` class on `<html>` and stores to localStorage, but the app uses CSS variables (set by theme.js) for all colors — the class toggle has no effect because no CSS rules depend on it.

Fix: the toggle should (a) call `applyThemeColors()` with the appropriate preset (dark or light) from the stored theme data, and (b) re-render the sidebar/header styles. The existing `toggleTheme` function in `theme.js` does this but the header toggle doesn't call it — it duplicates the logic incorrectly.

## Deliverable

Updated `templates/partials/header.html` click handler to call `toggleTheme()` (already defined in theme.js:62-68) instead of duplicating the logic. Theme.js handles the class toggle + localStorage correctly. Verify: toggle between dark and light modes on the Connections page — colors change.

## Files to touch
- `templates/partials/header.html` (sole file — no conflict)
