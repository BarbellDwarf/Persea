# Ticket: Sanitize error messages in API responses

wayfinder:task
Priority: P1

## Question

`AppError::into_response` (`error.rs:92-145`) returns the raw error message text to users for `Internal`, `Session`, `Guacd`, and `Vault` variants. This can leak internal hostnames, file paths, SQL statements, or stack traces.

For `AppError::Internal`, return a generic message (e.g., "An internal error occurred") to the client while logging the full error server-side. For `Session` and `Guacd` errors that are connection-specific (target not found, auth failed), keep the message but strip internal paths/hostnames — the user needs to know *what failed*, not *how the server saw it*.

## Deliverable

Updated `error.rs`. `AppError::Internal` returns generic text. `Session`/`Guacd` messages sanitized (hostnames redacted). Internal details logged. `cargo check` passes.
