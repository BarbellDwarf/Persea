# Ticket: Fix connections page left-hand gap

wayfinder:task
Priority: P1

## Question

There is a visible gap between the left-hand nav sidebar and the Connections page folder pane. The main content area does not properly extend to fill the width up to the nav sidebar.

## Deliverable

Remove the gap so the connections content starts flush against the nav sidebar. Inspect CSS classes for both `.main-area` (app layout) and `.conn-sidebar`/`.conn-content` (connections page). The fix is likely in `static/css/app.css` (main-area margin-left vs width calculation) or `templates/layouts/app.html` (content wrapper).
