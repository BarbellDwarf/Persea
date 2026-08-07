# Ticket: Always set CSRF cookie

wayfinder:task
Priority: P1

## Question

The CSRF middleware at `csrf.rs:151` only sets the `csrf_token` cookie when no other `Set-Cookie` header is present. This means login responses (which set `persea_session`) don't refresh the CSRF cookie, creating a window where CSRF attacks work right after login.

Remove the `if !resp.headers().contains_key(header::SET_COOKIE)` guard so the CSRF cookie is always appended to responses. The cookie value is regenerated on every response anyway, so overwriting is fine.

## Deliverable

Updated `csrf.rs` middleware. Test: login response now includes both `persea_session` and `csrf_token` Set-Cookie headers. CSRF protection works immediately after first login.
