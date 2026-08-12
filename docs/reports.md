# Reports

This page explains the usage reports persea can produce: who used what, when,
and for how long, and how to export the data. Reports are for **powerusers
and admins**; operators and viewers get a 403 on every reports endpoint.

The Reports page lives at **Admin → Reports** (`/admin/reports.html`) and
pulls its data from the REST API below, so anything you can see in the UI you
can also script.

---

## Summary cards

The top of the page shows four numbers:

- **Total Sessions**: lifetime session count (within the retention window).
- **Total Hours**: cumulative session time.
- **Unique Users**: how many distinct users created sessions.
- **Active Now**: sessions currently in progress.

---

## Session history

A searchable, sortable table of every past and current session. Each row
shows the user who created it, the address book entry and folder (when
applicable), session type (SSH, RDP, VNC, SPICE, Proxmox, Web, VDI),
hostname, start time, duration, status, and a link to the recording if one
exists.

The table supports:

- **Text filter**: narrow results across all visible columns.
- **Column sorting**: click a column header to sort.
- **Pagination**: 100 rows at a time.

### CSV export

Click **Export CSV** next to the filter box to download the full matching
history as a CSV file. The export honours the same filters as the API (user,
entry, type, date range) and returns **all** matching rows, not just the
current page.

CSV columns: `Session ID, Type, Hostname, Username, User, Entry, Folder,
Started, Ended, Duration (secs), Status, Recording`.

Example, last month's SSH sessions via the API:

```bash
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "https://console.example.com/api/reports/sessions/csv?type=ssh&from=2025-02-01T00:00:00Z&to=2025-03-01T00:00:00Z" \
  -o ssh-sessions.csv
```

---

## Session activity chart

A bar chart of **sessions started per hour**, covering the last 24 hours by
default. The API's `hours` parameter extends the window to anything from
1–168 hours (a week).

---

## Leaderboards

Two side-by-side panels at the bottom of the page:

- **Top Connections**: the most-used connections, ranked by session count,
  with total hours.
- **Top Users**: the most active users, ranked by session count, with total
  hours and last session time.

---

## Recordings list

Recordings (`.guac` session recordings, or encrypted `.guac.enc` when
recording encryption is enabled) are browsed on the **Recordings** page
(`/recordings.html`), which lists every recording with its size, user, entry,
folder, session type, and duration. You can play a recording in the browser
or download the file.

- **poweruser and above**: list and play recordings.
- **admin**: delete recordings.
- Automatic cleanup is governed by the `[recording]` section (max count,
  disk-usage percentage), see [Configuration](configuration.md#recording-section).

---

## How long history is kept

Session history is retained for a configurable number of days; old entries
are cleaned up automatically once per hour:

```toml
session_history_retention_days = 90   # default: 90; set 0 to keep forever
```

---

## API endpoints

All require authentication (API key, user token, or session cookie) with the
**poweruser** role or higher.

| Method | Path | What it returns |
|--------|------|-----------------|
| `GET` | `/api/reports/summary` | Summary statistics (total sessions, hours, unique users, active now) |
| `GET` | `/api/reports/sessions` | Paginated session history with filters |
| `GET` | `/api/reports/sessions/csv` | Session history as a CSV download |
| `GET` | `/api/reports/activity` | Sessions started per hour (`hours` param, 1–168; default 24) |
| `GET` | `/api/reports/top-connections` | Most-used connections leaderboard |
| `GET` | `/api/reports/top-users` | Most active users leaderboard |
| `GET` | `/api/recordings` | Recording list with metadata |
| `GET` | `/api/recordings/{name}` | Play/download a recording (admin role to delete) |

### Query parameters for session endpoints

| Parameter | What it does |
|-----------|-------------|
| `user` | Filter by username (partial match) |
| `entry` | Filter by address book entry name (partial match) |
| `type` | Filter by session type (exact): `ssh`, `rdp`, `vnc`, `spice`, `proxmox`, `web`, `vdi` |
| `from` / `to` | Date range (ISO 8601, e.g. `2025-01-01T00:00:00Z`) |
| `limit` | Page size (default 100, max 1000; ignored for CSV export) |
| `offset` | Page offset (default 0; ignored for CSV export) |
