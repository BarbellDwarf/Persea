# Ticket: Performance & Concurrency Improvements

**Type:** research + grilling
**Labels:** performance, wayfinder:research

## Question

What performance improvements should be prioritized?

### Findings:

**SQLite contention:**
- `Db = Arc<Mutex<Connection>>` — all DB calls serialized through one mutex
- `validate_api_key` scans ALL admin rows — O(N) per auth attempt
- `validate_user_token` same full-scan pattern
- `list_sessions` holds RwLock while acquiring Mutex per session

**Protocol parser allocation:**
- `InstructionParser::receive` at `protocol.rs:231`: `self.buffer = self.buffer[semi_pos + 1..].to_string()` — allocates new String per instruction
- 1 MiB buffer cap at `protocol.rs:222-225` silently drops data on large clipboard paste

**Blocking in async context:**
- `check_allowed_network` at `session.rs:434-482`: DNS resolution via `to_socket_addrs()` blocks tokio thread
- `WsTicketStore` uses `std::sync::Mutex` — blocks tokio thread under high connection rates

**Memory concerns:**
- CSV export at `api.rs:1079`: fetches up to 100,000 rows into memory as `serde_json::Value`
- `list_sessions` clones 30-field Session struct for each session

### Decision needed:

1. SQLite: migrate to `sqlx` async pool, or keep `rusqlite` with better indexing?
2. Auth query: add index on `api_key_hash`/`token_hash` for O(1) lookup?
3. Protocol parser: switch to `bytes::BytesMut` ring buffer?
4. DNS resolution: wrap in `spawn_blocking`?
5. CSV export: stream rows instead of loading all into memory?
