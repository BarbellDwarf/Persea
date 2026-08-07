# Ticket: Optimize carry buffer scan (last_instruction_boundary)

wayfinder:task
Priority: P2

## Question

`last_instruction_boundary()` in `protocol.rs` scans the entire carry buffer byte-by-byte on every TCP read from guacd to find the last complete instruction boundary. For large JPEG tiles (10-50KB each), the scan is O(n) in buffer size.

Add a fast-path heuristic: for buffers smaller than 1KB (the common case for SSH terminal output), skip the boundary scan if the buffer ends with a semicolon (`;`, the guac wire format instruction terminator). This avoids the scan for the overwhelmingly common case of small, complete instructions. Only run the full scan for larger buffers (RDP display data).

## Deliverable

Updated `protocol.rs` with fast-path in `last_instruction_boundary`. `cargo test` passes including the existing protocol tests. Manual verification: SSH and RDP sessions work correctly.
