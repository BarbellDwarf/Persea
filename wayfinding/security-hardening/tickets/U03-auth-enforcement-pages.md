# Ticket: Enforce authentication on page routes

wayfinder:task
Priority: P1

## Question

All page routes (`html_routes` in `main.rs:1848-1893`) use `optional_auth` middleware (line 1891), meaning pages are accessible without login. The docs page (`/docs.html`, `/docs`) is intentionally public. All other pages should require authentication.

Change: split `html_routes` into two groups — public (login, docs, setup) and protected (everything else). Apply `require_auth` to protected routes. Leave `/`, `/docs`, `/docs.html`, `/setup` on `optional_auth`.

## Deliverable

Updated `main.rs` with split route groups. Test: `/connections.html` without cookie → redirect to `/`. `/docs.html` without cookie → page renders. `/admin/settings.html` without cookie → redirect to `/`.

## Files to touch
- `src/main.rs` (sole file — no conflict with S01/S03/H03 since those are different code paths in the same file, but this is a separate middleware change at line 1891)
