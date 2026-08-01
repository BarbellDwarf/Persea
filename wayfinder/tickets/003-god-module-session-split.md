# Ticket: God Module Split — session.rs (2,826 lines)

**Type:** grilling
**Labels:** architecture, wayfinder:grilling

## Question

How should the 2,826-line `session.rs` be拆分?

### Current state:
- `create_session()` is a ~1,089-line function (lines 626-1715) handling 7 session types
- `CreateSessionRequest` has 60+ optional fields — a "bag of everything"
- `Session` struct has 30+ fields mixing concerns: guacd, browser, VDI, drive, tunnel, recording, thumbnail
- 9-element tuple return from `create_session()`

### Candidate split:
- `session/types.rs` — `SessionType`, `SessionStatus`, `CreateSessionRequest`, `SessionInfo`
- `session/manager.rs` — `SessionManager` core (new, lookup, delete, reap)
- `session/create.rs` — session creation per type (SSH, RDP, VNC, Web, VDI, SPICE, Proxmox)
- `session/shadow.rs` — shadow tokens, share tokens
- `session/mod.rs` — re-exports

### Related decisions:
- `CreateSessionRequest` should be split into protocol-specific sub-structs (`SshParams`, `RdpParams`, etc.) using `#[serde(flatten)]`
- 9-element tuple return should become a named struct (`CreateSessionResult`)
- `create_session()` should dispatch to per-type builder functions

### Decision needed:

1. Split by concern (types, manager, creation) or by protocol (ssh, rdp, web)?
2. How to restructure `CreateSessionRequest` — sub-structs or keep flat?
3. Named struct for `create_session()` return type?
