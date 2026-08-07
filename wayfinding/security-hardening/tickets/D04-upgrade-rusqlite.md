# Ticket: Upgrade rusqlite (3 versions behind)

wayfinder:task
Priority: P2

## Question

rusqlite 0.32 is 3 minor versions behind latest (0.35). The upgrade path is 0.32 → 0.33 → 0.34 → 0.35, with breaking changes in each step (API renames, feature flags, connection pool changes).

Upgrade rusqlite incrementally. Fix compilation errors at each step. Run `cargo test` after each upgrade. Document any breaking changes encountered.

## Deliverable

Updated Cargo.toml and Cargo.lock with rusqlite 0.35. All tests pass. Brief notes on breaking changes encountered.
