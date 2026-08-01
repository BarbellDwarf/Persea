# Ticket: Rust Code Quality Lints

**Type:** task
**Labels:** code-quality, wayfinder:task

## Question

What Rust linting and code quality tooling should be enabled?

### Current state:
- CI runs `cargo clippy` — catches some issues
- No `#![warn()]` or `#![deny()]` attributes in crate root
- No `#![deny(missing_docs)]` or `#![warn(clippy::pedantic)]`
- `#[allow(clippy::too_many_arguments)]` in 10+ places
- `tokio = { features = ["full"] }` — pulls in unnecessary features

### Missing:
- `#![warn(clippy::pedantic)]` for stricter linting
- `#![deny(missing_docs)]` for documentation coverage
- `#![warn(clippy::unwrap_used)]` to reduce panic surface
- Trim tokio features to what's actually needed
- Add `#[must_use]` to error types
- Add missing `Eq`/`PartialEq` derives where appropriate

### Decision needed:

1. Lint level: `warn` or `deny` for missing docs?
2. Clippy: pedantic or just default + selected extra lints?
3. Tokio features: trim to needed, or keep `full` for simplicity?
4. Should this be a single PR or incremental?
