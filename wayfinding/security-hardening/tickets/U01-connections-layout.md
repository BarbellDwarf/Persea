# Ticket: Connections page layout — sidebar folders + button cleanup

wayfinder:task
Priority: P1

## Question

The Connections page layout is confusing. The folder tree sits inline above the entries, and the header has six buttons (Add Entry, Edit Entry, Delete Entry, Edit folder, Delete folder) that look the same — two say "Edit" and two say "Delete" with no visual distinction between folder and entry actions.

Redesign: move the folder tree to a **left sidebar** (persistent, like the app sidebar), with the entries taking the full content area. Consolidate folder actions into the folder header (edit icon + delete icon). Entry actions: "+ Add Entry" stays in the header row; Edit and Delete become row-level actions or a context menu when an entry is selected (not separate buttons that sit next to folder actions).

## Deliverable

Updated `templates/pages/connections.html`:
- Folder tree renders in a left sidebar panel (below the app sidebar, taking ~250px width)
- Folder actions are icon-only buttons (pencil icon, trash icon) in the folder header, only visible for the selected folder
- Entry actions: "+ Add Entry" (header), Edit/Delete only visible when an entry is selected (detail panel)
- No duplicate-labeled buttons visible simultaneously

## Files to touch
- `templates/pages/connections.html` (sole file — no conflict with other tickets)
