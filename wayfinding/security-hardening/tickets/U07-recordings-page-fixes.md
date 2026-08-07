# Ticket: Fix recordings page — date format, protocol, duration

wayfinder:task
Priority: P2

## Question

Three problems on the Recordings page (visible in the user's screenshot):

1. **Date column** shows raw ISO 8601 with microseconds: `2026-08-07T01:53:24.765143884+00:00`. Should display as `YYYY-MM-DD HH:MM:SS`.

2. **Protocol column** is empty (shows checkbox-like icon). The backend returns `session_type` (from .meta sidecar) but the frontend reads `rec.protocol`. Field name mismatch.

3. **Duration column** shows `—` for every recording. The backend doesn't calculate or return duration. Need to parse the .guac file metadata or compute duration from frame timestamps.

## Deliverable

Updated `templates/pages/recordings.html`:
- Frontend reads `rec.session_type` for the protocol badge (not `rec.protocol`)
- Date formatted as `YYYY-MM-DD HH:MM:SS` (JS Date formatting)

Updated `src/api/reports.rs`:
- Add `duration_secs` field: parse the .meta sidecar (which stores `created_at`) and the recording's last timestamp instruction to compute duration. Or simpler: parse the .guac file's final instruction for timestamp data.
- Add `created_at` formatted as `YYYY-MM-DD HH:MM:SS` (or return raw and format in frontend)

## Files to touch
- `templates/pages/recordings.html` (date format + protocol field name)
- `src/api/reports.rs` (duration computation + date formatting)
