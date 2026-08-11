//! Loopback TCP relay for RDP connections.
//!
//! Some hosts run per-process network filters (endpoint security agents)
//! that silently drop or corrupt outbound connections made by specific
//! processes, while byte-identical connections from other processes work
//! fine. Relaying guacd's RDP connection through a local loopback proxy
//! moves the outbound leg to a different process — the proven workaround
//! for such environments.
//!
//! The relay binds an ephemeral loopback-only listener and transparently
//! bridges every accepted connection to the configured target. guacd
//! retries its connection once on failure, so the accept loop serves
//! multiple connections.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Timeout for the relay's outbound connect to the target. A dead target
/// fails fast so guacd reports a clean error instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A loopback relay between guacd and the real RDP target.
///
/// Holds the accept task and the per-connection bridge tasks. Dropping the
/// handle aborts all of them — no orphaned listeners, tasks, or half-open
/// sockets survive.
pub struct RdpRelay {
    local: SocketAddr,
    task: JoinHandle<()>,
    connections: std::sync::Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
}

impl RdpRelay {
    /// The loopback address guacd should connect to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for RdpRelay {
    fn drop(&mut self) {
        self.task.abort();
        for handle in self.connections.lock().unwrap().iter() {
            handle.abort();
        }
    }
}

/// Spawn a relay that forwards loopback connections to `target_host:target_port`.
///
/// The listener binds `127.0.0.1:0` (loopback only, ephemeral port) and the
/// returned handle exposes the local address guacd should dial.
pub async fn spawn(target_host: &str, target_port: u16) -> io::Result<RdpRelay> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?;
    let target_host = target_host.to_string();

    let connections: std::sync::Arc<std::sync::Mutex<Vec<JoinHandle<()>>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let conn_list_task = connections.clone();

    let task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((inbound, _)) => {
                    // Prune finished bridge tasks so a long-lived session
                    // doesn't accumulate handles.
                    conn_list_task.lock().unwrap().retain(|h| !h.is_finished());
                    let target = target_host.clone();
                    let conns = conn_list_task.clone();
                    let bridge = tokio::spawn(async move {
                        if let Err(e) = bridge(inbound, &target, target_port).await {
                            tracing::debug!(
                                target = %target,
                                target_port,
                                error = %e,
                                "relay connection closed"
                            );
                        }
                    });
                    conns.lock().unwrap().push(bridge);
                }
                Err(e) => {
                    // Transient listener errors (e.g. fd exhaustion): back
                    // off briefly and keep serving. The handle's Drop aborts
                    // this task when the session ends.
                    tracing::warn!(error = %e, "RDP relay accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    });

    Ok(RdpRelay {
        local,
        task,
        connections,
    })
}

/// Bridge one accepted connection to the target until either side closes.
async fn bridge(mut inbound: TcpStream, target_host: &str, target_port: u16) -> io::Result<()> {
    let mut outbound = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((target_host, target_port)),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect to {}:{} timed out", target_host, target_port),
        )
    })??;

    let (mut inbound_read, mut inbound_write) = inbound.split();
    let (mut outbound_read, mut outbound_write) = outbound.split();

    tokio::try_join!(
        tokio::io::copy(&mut inbound_read, &mut outbound_write),
        tokio::io::copy(&mut outbound_read, &mut inbound_write),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_forwards_bidirectional_traffic() {
        // Echo server standing in for the RDP target.
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = target.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });

        let relay = spawn("127.0.0.1", target_addr.port()).await.unwrap();
        let mut client = TcpStream::connect(relay.local_addr()).await.unwrap();
        client.write_all(b"hello relay").await.unwrap();
        let mut buf = [0u8; 11];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello relay");

        // Closing the client lets the bridge tasks finish.
        drop(client);
        server.await.unwrap();
        drop(relay);
    }

    #[tokio::test]
    async fn relay_drop_closes_listener() {
        let relay = spawn("127.0.0.1", 1).await.unwrap();
        let addr = relay.local_addr();
        drop(relay);
        // Give the aborted accept task a moment to release the socket.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(TcpStream::connect(addr).await.is_err());
    }
}
