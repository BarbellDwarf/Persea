# Ticket: BytesMut carry buffer in proxy hot path

wayfinder:task
Priority: P2

## Question

The WebSocket proxy (`websocket.rs:517-528`) uses `Vec<u8>` for the carry buffer. On each guacd read, `carry.drain(..end).collect()` allocates a new `Vec<u8>`, then `String::from_utf8` allocates a second `Vec`. Under high frame rates (30+ fps RDP), this creates heap churn.

Replace the `Vec<u8>` carry buffer with `bytes::BytesMut`. Use `carry.split_to(end)` (O(1) slice) instead of `drain().collect()` (O(n) copy). The `String::from_utf8` step can also be optimized since `BytesMut` supports `TryInto<String>` in recent versions.

## Deliverable

Updated `websocket.rs` with `BytesMut` carry buffer. `cargo check` passes. Proxy behavior unchanged — same instruction boundary guarantees. All websocket tests pass.
