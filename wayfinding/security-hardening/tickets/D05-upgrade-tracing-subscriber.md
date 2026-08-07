# Ticket: Upgrade tracing-subscriber

wayfinder:task
Priority: P3

## Question

tracing-subscriber 0.3.x has RUSTSEC-2025-0055: logging user input can poison logs with ANSI escape sequences. Upgrade to >= 0.3.19.

`cargo update -p tracing-subscriber`. Verify `cargo audit` clears. No functional changes expected.

## Deliverable

Updated Cargo.lock. Zero tracing-subscriber advisories.
