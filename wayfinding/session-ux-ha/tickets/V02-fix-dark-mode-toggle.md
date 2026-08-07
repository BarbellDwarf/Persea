# Ticket: Fix dark mode toggle (third attempt)

wayfinder:task
Priority: P1

## Question

The dark mode toggle still does nothing visible on the third attempt. The toggle calls `toggleTheme()` which cycles dark→light→auto and calls `applyClass()` + `applyThemeColors()`. The CSS variables are set by the theme, but the toggle only changes the html class.

Root cause analysis needed:
1. Does `applyClass()` actually change any visual state?
2. Does the light preset have different colors from the dark preset?
3. Is there a `.dark` vs `.light` CSS rule set in app.css that affects the appearance?
4. Does `applyThemeColors` get called when toggling?

## Deliverable

Dark mode toggle cycles between visually distinct dark and light modes. When the user clicks the toggle, the entire page appearance changes.
