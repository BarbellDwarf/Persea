# Ticket: Fix Auth Providers, Groups, and Reports pages

wayfinder:task
Priority: P1

## Question

Three pages don't work properly:
1. **Auth Providers page** (`/admin/auth.html`): buttons do not function
2. **Groups page** (`/admin/groups.html`): buttons do not function
3. **Reports page**: bar graph not accurately displayed (chart bars may not have correct heights or labels)

## Deliverable

- Auth Providers page: verify all buttons (add, edit, delete providers) are wired with event listeners
- Groups page: verify all buttons (add group, add member, delete group) are wired
- Reports chart: verify bar heights are proportional to data and labels are readable
- Take Playwright screenshots of each page to confirm rendering

## Files to touch
- `templates/pages/admin/auth.html`
- `templates/pages/admin/groups.html`
- `templates/pages/admin/reports.html`
