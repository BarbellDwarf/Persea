# Ticket: Connection reason field (admin-toggleable)

wayfinder:task
Priority: P2

## Decision

Dropdown of common reasons + free-text field. Stored in `session_history.reason` column. Admin-toggleable: `[session] reason_required` setting.

## Design

### Common reasons (dropdown)
- Maintenance
- Password rotation
- Troubleshooting
- Incident response
- Configuration change
- Data migration
- Performance testing
- Security audit
- Other (free text)

### Fields
- **Reason select**: dropdown with the above options
- **Reason free text**: shown when "Other" is selected, or always available alongside the dropdown
- The prompt appears BEFORE the session starts (a modal before the WebSocket connects)
- Admin toggle: `[session] reason_required = false | optional | required`
  - `false`: no prompt shown (default)
  - `optional`: prompt shown but can be skipped
  - `required`: must provide a reason before session starts

### Storage
- New column: `session_history.connection_reason TEXT`
- Also stored in audit_events (the connect event gets the reason in details)

### UI
- Modal with dropdown + text field + Submit/Cancel buttons
- Shows when reason_required is enabled
- Cancel goes back to Connections page
- Submit proceeds with the session

## Files to touch
- `templates/pages/client.html` (reason modal + prompt logic)
- `src/session/types.rs` (add reason to SessionInfo)
- `src/session/create.rs` (store reason in session history)
- `src/api/admin.rs` or `src/api/settings.rs` (reason_required setting)
- `templates/pages/admin/settings.html` (admin toggle for reason_required)
- `templates/pages/sessions.html` (display reason column)
