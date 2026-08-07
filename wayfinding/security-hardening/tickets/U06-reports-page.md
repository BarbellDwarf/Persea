# Ticket: Implement Reports page

wayfinder:task
Priority: P2

## Question

The Reports page (`/reports.html`) exists as a skeleton with summary cards and a "Charts coming soon" placeholder. It needs full implementation:

1. **Summary cards**: Total sessions, Active sessions, Total users, Uptime — pull from `session_history` table and server start time.
2. **Session activity chart**: Sessions per hour over the last 24h. Simple bar chart using CSS (no external charting library needed).
3. **Top connections**: Most-used connections by session count (from `session_history.address_book_entry`).
4. **Top users**: Most active users by session count (from `session_history.created_by`).
5. **Session history table**: Paginated list of past sessions with protocol, user, target, duration, start time, status. Filterable by user, protocol, date range.
6. **CSV export**: Download session history as CSV.

Backend already has `report_sessions` handler (`src/api/reports.rs:184-208`) and `list_recordings`. Extend with summary stats and chart data endpoints.

## Deliverable

Updated `templates/pages/admin/reports.html` with all sections wired to backend.
New API endpoints: `GET /api/reports/summary` (stats), `GET /api/reports/activity` (chart data).
`cargo check` passes. All report sections render with real data.

## Files to touch
- `templates/pages/admin/reports.html` (primary — sole template)
- `src/api/reports.rs` (new summary/activity endpoints)
- `src/main.rs` (new routes if needed)
