# Ticket: Add always-on login rate limiter

wayfinder:task
Priority: P1

## Question

Rate limiting is disabled by default (`rate_limit: false` in config). Login brute-force is possible unless the operator explicitly enables the global rate limiter. The login endpoint (`/auth/login`) should have its own always-on rate limiter independent of the global setting.

Add a dedicated rate limiter for `/auth/login` that is always active (not gated by `rate_limit`). Use `tower_governor` with a tight burst (e.g., 5 per 10 seconds per IP) to block brute-force without blocking normal logins. The global `rate_limit` setting controls API endpoint limiting; the login limiter is separate.

## Deliverable

Updated `main.rs` route setup — login route gets its own governor layer. Test: rapid-fire login attempts are rate-limited even when global `rate_limit = false`. Normal logins still work.
