# Ticket: Testing Strategy — Security-Critical Modules

**Type:** research + task
**Labels:** testing, wayfinder:research

## Question

What testing approach should be used for the 6 untested security-critical modules?

### Current state:
- **`guacd.rs`** (647 lines, 0 tests) — constructs all guacamole protocol instructions for SSH/RDP/VNC/Web/VDI/SPICE. Trust boundary.
- **`tunnel.rs`** (497 lines, 0 tests) — SSH jump host tunneling. Handles key verification, multi-hop chains, TCP forwarding.
- **`drive.rs`** (303 lines, 0 tests) — file transfer + LUKS encryption.
- **`recording.rs`** (213 lines, 0 tests) — recording rotation, disk management. Uses unsafe `libc::statvfs`.
- **`migrate.rs`** (241 lines, 0 tests) — Vault migration logic.
- **`vdi/mod.rs`** (136 lines, 0 tests) — trait + type definitions (low risk).

### Testing approaches to evaluate:
1. **Mock TCP streams** for `guacd.rs` — verify instruction bytes match expected protocol
2. **Mock SSH server** for `tunnel.rs` — test tunnel construction without real SSH
3. **Temp directories** for `recording.rs` and `drive.rs` — test rotation/cleanup
4. **Trait-based mocking** for Docker/Vault — create `trait VaultBackend` with `MockVault`
5. **Property-based testing** for `protocol.rs` — `proptest` for round-trip invariants

### What's already working:
- `protocol.rs` has 33 tests including adversarial cases
- `db.rs` uses `:memory:` SQLite
- 5 Rust fuzz targets + 1 C fuzz target
- Load testing scripts (k6, Python)

### Decision needed:

1. Mock strategy: trait-based mocks, or test with real services in CI?
2. Priority order for adding tests: guacd.rs → tunnel.rs → api.rs handlers → ?
3. Should property-based testing (`proptest`) become a standard for parsers?
4. Integration test framework: `axum::test` or `tower::ServiceExt`?
