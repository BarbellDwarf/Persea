# Ticket: Fix remote session toolbar — protocol badge, theme, disconnect

wayfinder:task
Priority: P1

## Question

Three bugs in the remote session toolbar (client.html):
1. **Protocol badge always shows SSH** — it should show the actual protocol (SSH/RDP/VNC/etc.) from the session metadata
2. **Toolbar theme does not match** — the toolbar uses hardcoded colors instead of CSS variables from the app theme
3. **Disconnect button** shows the confirmation prompt then immediately disconnects — the prompt should wait for user confirmation before disconnecting

## Deliverable

- Protocol badge reads from session metadata and shows the correct protocol
- Toolbar CSS variables align with the main app theme
- Disconnect: show confirmation → wait for click → then disconnect

## Files to touch
- `templates/pages/client.html` (toolbar section + JS)
