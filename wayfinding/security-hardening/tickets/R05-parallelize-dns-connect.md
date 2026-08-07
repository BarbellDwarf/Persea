# Ticket: Parallelize DNS + guacd connect in session creation

wayfinder:task
Priority: P2

## Question

Session creation (`session/create.rs`) performs DNS resolution (`check_allowed_network`) and guacd handshake sequentially. Both operations touch the same hostname, and the DNS result (IP validation) doesn't block the guacd TCP connect (guacd does its own DNS resolution).

Parallelize: start the guacd connect in a spawned task while the DNS allowlist check runs concurrently. Use `tokio::join!` or `tokio::spawn` + `join`. If the DNS check fails, abort the guacd connect (cancellation token or drop the TCP stream). If guacd connect fails while DNS succeeds, return the guacd error.

Note: this is trickier for SSH/RDP/VNC branches where the hostname is an IP that doesn't need DNS resolution. Only worth parallelizing for hostname-based connections.

## Deliverable

Updated `create.rs` session creation with parallel DNS + guacd connect. Test: sessions with hostname targets connect faster. All session tests pass. Edge cases tested: DNS failure aborts guacd, guacd failure during DNS returns guacd error.
