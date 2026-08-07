# Ticket: Session switching — connect to new server while connected

wayfinder:grilling
Priority: P2

## Question

Design the UX for switching between remote sessions without disconnecting first. The user wants to:
- Connect to a new server while an existing session is active
- Switch back to previous sessions
- Leave the current session open (not disconnect)

Design options to evaluate:
1. **Sidebar panel**: slide-out panel showing all active sessions with thumbnails
2. **Tab bar**: browser-like tabs at the top of the client page
3. **Server drawer**: collapsible drawer listing all connections (like the sessions page)
4. **Quick-switch overlay**: keyboard shortcut (Ctrl+K) to show a searchable list of sessions

Each option needs: where the data comes from, how to render thumbnails, how to switch (open new tab vs inline), memory/resource implications.

## Deliverable

A grilling session resolving which approach to use, with wireframe-level detail.
