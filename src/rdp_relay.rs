//! Loopback TCP relay for RDP connections.
//!
//! Some hosts run per-process network filters (endpoint security agents)
//! that silently drop or corrupt outbound connections made by specific
//! processes, while byte-identical connections from other processes work
//! fine. Relaying guacd's RDP connection through a local loopback proxy
//! moves the outbound leg to a different process — the proven workaround
//! for such environments.
//!
//! The outbound leg is made by **socat** when it is available on PATH (a
//! common system binary that endpoint filters typically allow), falling
//! back to an in-process tokio bridge. The relay binds an ephemeral
//! loopback-only listener and transparently bridges every accepted
//! connection to the configured target. guacd retries its connection once
//! on failure, so the accept loop serves multiple connections.

use std::io;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

/// Timeout for the relay's outbound connect to the target. A dead target
/// fails fast so guacd reports a clean error instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Backend that actually performs the loopback→target forwarding.
enum RelayBackend {
    /// socat subprocess (`TCP-LISTEN … TCP:<target>`). Killed on drop.
    Socat {
        child: tokio::process::Child,
        target: String,
        target_port: u16,
    },
    /// In-process tokio accept loop + per-connection bridges.
    Tokio {
        task: JoinHandle<()>,
        connections: std::sync::Arc<std::sync::Mutex<Vec<JoinHandle<()>>>>,
    },
}

/// A loopback relay between guacd and the real RDP target.
///
/// Holds the backend. Dropping the handle kills the socat child or aborts
/// the tokio tasks — no orphaned listeners, tasks, or half-open sockets
/// survive.
pub struct RdpRelay {
    local: SocketAddr,
    backend: RelayBackend,
}

impl RdpRelay {
    /// The loopback address guacd should connect to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

impl Drop for RdpRelay {
    fn drop(&mut self) {
        match &mut self.backend {
            RelayBackend::Socat { child, .. } => {
                let _ = child.start_kill();
            }
            RelayBackend::Tokio { task, connections } => {
                task.abort();
                for handle in connections.lock().unwrap().iter() {
                    handle.abort();
                }
            }
        }
    }
}

/// Spawn a relay that forwards loopback connections to `target_host:target_port`.
///
/// The listener binds `127.0.0.1:0` (loopback only, ephemeral port) and the
/// returned handle exposes the local address guacd should dial. Prefers a
/// `socat` subprocess for the outbound leg (endpoint filters commonly
/// allowlist system binaries); falls back to an in-process tokio bridge.
pub async fn spawn(target_host: &str, target_port: u16) -> io::Result<RdpRelay> {
    match spawn_socat(target_host, target_port).await {
        Ok(Some(relay)) => Ok(relay),
        // socat not installed — fall back to the in-process bridge.
        Ok(None) => spawn_tokio(target_host, target_port).await,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            spawn_tokio(target_host, target_port).await
        }
        Err(e) => Err(e),
    }
}

/// Spawn `socat` as the relay backend, if socat is on PATH.
///
/// The port is reserved on the loopback first, then handed to socat (the
/// bind→release window is tiny; guacd's own connection retry covers it).
async fn spawn_socat(target_host: &str, target_port: u16) -> io::Result<Option<RdpRelay>> {
    let probe = TcpListener::bind("127.0.0.1:0").await?;
    let port = probe.local_addr()?.port();
    drop(probe);

    let child = tokio::process::Command::new("socat")
        .arg(format!("TCP-LISTEN:{port},reuseaddr,fork,bind=127.0.0.1"))
        .arg(format!("TCP:{target_host}:{target_port}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    tracing::info!(
        port,
        target = %target_host,
        target_port,
        "RDP relay: socat backend listening on loopback"
    );

    Ok(Some(RdpRelay {
        local: SocketAddr::from(([127, 0, 0, 1], port)),
        backend: RelayBackend::Socat {
            child,
            target: target_host.to_string(),
            target_port,
        },
    }))
}

/// Spawn the in-process tokio bridge relay.
async fn spawn_tokio(target_host: &str, target_port: u16) -> io::Result<RdpRelay> {
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
        backend: RelayBackend::Tokio { task, connections },
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
        // The socat backend binds the reserved port asynchronously — retry
        // briefly so the test doesn't race it (guacd's own retry covers
        // this in production).
        let mut client = None;
        for _ in 0..20 {
            if let Ok(c) = TcpStream::connect(relay.local_addr()).await {
                client = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let mut client = client.expect("relay listener did not come up in time");
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
