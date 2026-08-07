# Ticket: Error responses leak raw library error text

wayfinder:task
Priority: P2
Phase: Medium

## Finding

`src/error.rs:216-233` — `rusqlite::Error`/`serde_json::Error`/`tokio::task::JoinError` wrapped via `format!("... {e}")` and returned verbatim in JSON error body (line ~140). Leaks SQL statements, file paths, internal details.

## Overlap

**Existing ticket S05** (`security-hardening/tickets/S05-error-message-sanitization.md`) claims this was fixed. Verify that S05 actually:
1. Returns generic messages for `AppError::Internal`
2. Sanitizes `Session`/`Guacd` errors (strips hostnames)
3. Logs full errors server-side

If S05 is incomplete, fix the gaps. The audit found this is still leaking raw text.

## Files

- `src/error.rs:216-233` — error wrapping
- `src/error.rs:~140` — `into_response`

## Deliverable

`AppError::Internal` returns generic text to client. Full error logged server-side. `Session`/`Guacd` errors sanitized. `cargo check` passes.
