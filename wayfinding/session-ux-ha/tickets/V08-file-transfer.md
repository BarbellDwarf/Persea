# Ticket: File transfer for SSH and RDP sessions

wayfinder:task
Priority: P1

## Question

Users need to transfer files to/from remote servers. File transfer should be supported for SSH (SFTP) and RDP (drive redirection) sessions, and any other protocols that support it.

The codebase already has:
- `[drive]` config section (config.example.toml lines 346-359) with drive_path, LUKS encryption
- `enable_drive` flag in CreateSessionRequest
- `allow_download`/`allow_upload` flags per-entry
- The Guacamole JS client supports `Guacamole.Client.createFileStream()` (RDP) and SFTP tunnels

## Deliverable

1. Add a file transfer button in the session toolbar (client.html)
2. For RDP: mount a per-session drive directory via guacd's drive redirection
3. For SSH: enable SFTP via guacd's SFTP support
4. File upload/download UI in the client page (a draggable drop zone or file picker)
5. Drive config wired: `enable_drive: true` in session creation when drive is configured
6. Admin toggle in settings (U04) for enabling/disabling file transfer globally

## Files to touch
- `templates/pages/client.html` (file transfer UI)
- `src/session/create.rs` (drive parameters in session creation)
- `src/config.rs` (drive config validation)
- `templates/pages/admin/settings.html` (file transfer toggle)
