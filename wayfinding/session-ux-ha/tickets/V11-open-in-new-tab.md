# Ticket: Open connections in new tab

wayfinder:task
Priority: P1

## Question

When clicking "Connect" on a connection entry, it should open a new browser tab with the session, not navigate away from the Connections page. Currently `window.location.href = url` navigates the current tab.

## Deliverable

Change all connection launches to use `window.open(url, '_blank')` instead of `window.location.href = url`. This applies to:
- `connectEntry()` in connections.html (entry connect button)
- `connectEntry()` in search results
- Any other connection trigger (recent connections section, sessions page reconnect)

The user keeps the Connections page open while the session opens in a new tab.

## Files to touch
- `templates/pages/connections.html` (connectEntry function + event handlers)
- `templates/pages/sessions.html` (reconnect links)
