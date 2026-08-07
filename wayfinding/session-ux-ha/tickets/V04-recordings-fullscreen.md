# Ticket: Recordings fullscreen / larger player

wayfinder:task
Priority: P2

## Question

The recordings player modal is too small to read session content. The current modal is `max-w-6xl` (1152px) with a display area of `min-height:400px`.

## Deliverable

- Add a fullscreen button to the player controls (uses the Fullscreen API: `element.requestFullscreen()`)
- Default the modal to `max-w-7xl` (1280px) instead of `max-w-6xl`
- In fullscreen mode, the player display fills the viewport with controls overlaid at the bottom
- ESC exits fullscreen and returns to modal

## Files to touch
- `templates/pages/recordings.html` (player modal)
