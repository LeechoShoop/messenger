// =============================================================================
// primus-net-opt/src/discovery.rs — UDP LAN Discovery
//
// MIGRATION: Moved from primus-core/src/discovery.rs.
//
// BREAKING CHANGE — PrimusNetwork<H> dependency removed:
//   The original code took `network_handle: PrimusNetwork` and called
//   `net.connect_to_peer()` directly. That created a compile-time dependency
//   on the full PrimusNetwork<H> generic, which forced callers to know H at
//   the call site and made the discovery module impossible to use standalone.
//
//   Fix: `start()` now accepts a `connect_fn: F` callback instead —
//   a plain async closure `Fn(String) -> Future<Output = ()>`.
//   The caller (main.rs) closes over whatever network handle it has.
//   PrimusDiscovery itself stays fully decoupled from the network type.
//
// BEACON FIX — port range now relative to my_port:
//   The original code hardcoded `9000..9016` as broadcast targets. Two nodes
//   on ports 9100 and 9200 would never discover each other.
//   Fix: broadcast to `(my_port..my_port + 16)` — relative to own port.
//
// PROTOCOL:
//   Beacon:   UDP broadcast "PRIMUS_PEER:<tcp_port>" every 10 s
//   Listener: receives beacons, reconstructs "ip:port", calls connect_fn
//   SO_REUSEPORT allows multiple nodes on the same host to each bind their
//   own discovery port without EADDRINUSE.
// =============================================================================

use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

const MAX_KNOWN_PEERS: usize = 10_000;
const EVICT_COUNT: usize = 1_000;

pub struct PrimusDiscovery {
    pub port: u16,
    pub bind_ip: String,
}

impl PrimusDiscovery {
    pub fn new(port: u16, bind_ip: Option<String>) -> Self {
        Self { port, bind_ip: bind_ip.unwrap_or_else(|| "0.0.0.0".to_string()) }
    }

    /// Start the UDP discovery service.
    ///
    /// # Arguments
    ///
    /// * `connect_fn` — Called whenever a new peer is found.
    ///   Receives the peer's `"ip:port"` string. The future is spawned
    ///   on the Tokio runtime — the callback must be `Send + 'static`.
    ///
    /// # Example (main.rs)
    ///
    /// ```rust,ignore
    /// let net = server_net.clone();
    /// let discovery = PrimusDiscovery::new(my_port);
    /// tokio::spawn(async move {
    ///     let _ = discovery.start(move |addr| {
    ///         let net = net.clone();
    ///         async move { let _ = net.connect_to_peer(&addr).await; }
    ///     }).await;
    /// });
    /// ```
    pub async fn start<F, Fut>(&self, connect_fn: F) -> Result<()>
    where
        F: Fn(String) -> Fut + Send + Sync + Clone + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let my_tcp_port = self.port;
        let listen_addr = format!("{}:{}", self.bind_ip, my_tcp_port);
        let socket = Self::bind_reuse(&listen_addr).await?;
        let socket = Arc::new(socket);
        let known_peers = Arc::new(Mutex::new(HashSet::<String>::new()));

        log::info!(
            "Discovery: UDP listener on {}, TCP port {}",
            socket.local_addr()?,
            my_tcp_port
        );

        // ── BEACON: broadcast our TCP port every 10 s ─────────────────────────
        //
        // Broadcast to a 16-port window relative to our own port so that nodes
        // on different port bases (9000, 9100, etc.) still find each other if
        // they're in the same window — and don't if they're not.
        let beacon_socket = socket.clone();
        tokio::spawn(async move {
            let msg = format!("PRIMUS_PEER:{}", my_tcp_port);
            // Broadcast to common ports (9000-9010) AND our own port window
            let mut ports: HashSet<u16> = (9000..=9010).collect();
            for p in my_tcp_port..my_tcp_port.saturating_add(16) {
                ports.insert(p);
            }

            let targets: Vec<String> = ports
                .into_iter()
                .map(|p| format!("255.255.255.255:{}", p))
                .collect();

            loop {
                for target in &targets {
                    if let Err(e) = beacon_socket.send_to(msg.as_bytes(), target).await {
                        // Only log errors that aren't "Permission denied" (broadcast can fail on some interfaces)
                        if e.kind() != std::io::ErrorKind::PermissionDenied {
                            log::debug!("Discovery beacon send error to {}: {}", target, e);
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });

        // ── LISTENER: receive beacons and connect to new peers ─────────────────
        let listener_socket = socket.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 256];
            loop {
                let (len, from_addr) = match listener_socket.recv_from(&mut buf).await {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("Discovery recv error: {}", e);
                        continue;
                    }
                };

                let data = String::from_utf8_lossy(&buf[..len]);

                let peer_tcp_port = match data
                    .strip_prefix("PRIMUS_PEER:")
                    .and_then(|p| p.trim().parse::<u16>().ok())
                {
                    Some(p) => p,
                    None => continue, // not our protocol
                };

                // Ignore our own beacon.
                if peer_tcp_port == my_tcp_port {
                    continue;
                }

                let target_addr = format!("{}:{}", from_addr.ip(), peer_tcp_port);

                let mut peers = known_peers.lock().await;
                if peers.contains(&target_addr) {
                    continue;
                }

                // Enforce cap with arbitrary eviction
                if peers.len() >= MAX_KNOWN_PEERS {
                    let to_remove: Vec<String> = peers.iter().take(EVICT_COUNT).cloned().collect();
                    for key in to_remove {
                        peers.remove(&key);
                    }
                }

                peers.insert(target_addr.clone());
                drop(peers);

                log::info!("Discovery: new peer at {}", target_addr);

                let connect = connect_fn.clone();
                tokio::spawn(async move {
                    // Brief delay so the remote node's TCP listener is ready.
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    connect(target_addr).await;
                });
            }
        });

        Ok(())
    }

    /// Bind a UDP socket with SO_REUSEPORT so multiple nodes on the same host
    /// can each own their discovery port without EADDRINUSE.
    async fn bind_reuse(addr: &str) -> Result<UdpSocket> {
        use std::net::SocketAddr;

        let sock_addr: SocketAddr = addr.parse()?;
        let domain = if sock_addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let raw = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;

        raw.set_reuse_address(true)?;
        #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        raw.set_reuse_port(true)?;
        raw.set_broadcast(true)?;
        raw.set_nonblocking(true)?;
        raw.bind(&sock_addr.into())?;

        let std_sock: std::net::UdpSocket = raw.into();
        Ok(UdpSocket::from_std(std_sock)?)
    }
}