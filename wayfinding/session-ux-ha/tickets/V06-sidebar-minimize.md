# Ticket: Fix sidebar minimize button

wayfinder:task
Priority: P1

## Question

The sidebar collapse/minimize button does not work. The button exists in `templates/partials/sidebar.html` (id="sidebar-toggle") with JS wired in `templates/partials/header.html`. The CSS for `.sidebar.collapsed` is in `static/css/app.css`. The toggle should collapse the sidebar to 56px (icons only) and expand on hover.

Debug: check that the button element has the right id, the JS event listener is attached after DOM load, and the CSS class is being applied.

## Deliverable

Click the minimize button → sidebar collapses to icon-only mode → expand on hover. Works on all pages.
