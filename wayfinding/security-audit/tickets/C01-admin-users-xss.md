# Ticket: Stored/DOM XSS in admin Users page

wayfinder:task
Priority: P0
Phase: Critical

## Finding

`templates/pages/admin/users.html:189-204` — `renderUserRow` builds HTML via string concatenation with unescaped `user.name`, `user.email`, `user.auth_source`, `user.last_login_at`. The `email` and `role` values are interpolated directly into single-quoted `onclick` attributes without escaping, enabling injection.

## Fix

Use the same `esc()` / `escapeHtml()` helper already used by `admin/groups.html`, `admin/tunnels.html`, and `account/tokens.html`. Replace all string-concatenated HTML in `renderUserRow` with template literals using the escape helper. Also replace inline `onclick` handlers with `data-action`/`data-id` attributes + event delegation (matching the pattern already applied to groups.html in V05).

## Files

- `templates/pages/admin/users.html:189-204` — `renderUserRow` function

## Deliverable

All user-supplied values in `renderUserRow` are escaped. No inline `onclick` with user data. `cargo check` passes. Admin Users page renders correctly with special characters in names/emails.
