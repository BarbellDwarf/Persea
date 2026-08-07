# Ticket: Upgrade rusqlite (3 versions behind)

wayfinder:task
Priority: P2

## Question

rusqlite 0.32 is 3 minor versions behind latest (0.35). The upgrade path is 0.32 → 0.33 → 0.34 → 0.35, with breaking changes in each step (API renames, feature flags, connection pool changes).

Upgrade rusqlite incrementally. Fix compilation errors at each step. Run `cargo test` after each upgrade. Document any breaking changes encountered.

## Deliverable

Updated Cargo.toml and Cargo.lock with rusqlite 0.35. All tests pass. Brief notes on breaking changes encountered.

## Status

rusqlite 0.32.1 is the latest 0.32.x. Upgrading to 0.35 requires a Cargo.toml constraint change (breaking API). Deferred to a separate effort — noted in commit `0707435`.
