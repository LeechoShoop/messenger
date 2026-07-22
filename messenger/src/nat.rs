use anyhow::{Result, anyhow};
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, SocketAddrV4};

pub struct NatService;

impl NatService {
    /// Attempts to open ports via UPnP to make the node accessible from the global internet.
    ///
    /// primus-net-opt no longer runs a TCP listener — all peer transport goes
    /// through QUIC (see network.rs's module comment) with an optional
    /// WebTransport path for browser/WASM leaf clients (server.rs's
    /// `wt_addr = addr.port() + 1` convention). Accordingly this maps two UDP
    /// ports:
    ///   - `port`     — the QUIC control/gossip port (Kademlia RPC + Noise
    ///                  gossip stream).
    ///   - `port + 1` — the WebTransport port, so browser/WASM leaf clients
    ///                  can reach this node from outside the LAN.
    ///
    /// Returns the external IP address on success.
    pub async fn open_world(port: u16) -> Result<IpAddr> {
        println!("🌐 NAT: Searching for gateway via [aio::tokio]...");

        let opts = SearchOptions::default();

        // High-performance asynchronous search using the explicit tokio path
        let gateway = igd_next::aio::tokio::search_gateway(opts)
            .await
            .map_err(|e| anyhow!("UPnP Discovery failed: {}", e))?;

        // Identify local IP address for port forwarding
        let local_ip = local_ip_address::local_ip()
            .map_err(|e| anyhow!("Failed to determine local IP: {}", e))?;

        let ipv4 = match local_ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(anyhow!(
                    "IPv6 mapping is not yet supported for Primus-Grade nodes"
                ));
            }
        };

        // 1. UDP Mapping — QUIC control/gossip port (Kademlia RPC + Noise
        // gossip stream all run over this single QUIC endpoint).
        let quic_addr = SocketAddrV4::new(ipv4, port);
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                port,
                quic_addr.into(),
                0, // Infinite lease duration
                "Primus-Node-QUIC",
            )
            .await
            .map_err(|e| anyhow!("QUIC UDP Port Mapping failed: {}", e))?;

        // 2. UDP Mapping — WebTransport port (port + 1), so browser/WASM leaf
        // clients can reach this node from outside the LAN.
        let wt_port = port + 1;
        let wt_addr = SocketAddrV4::new(ipv4, wt_port);
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                wt_port,
                wt_addr.into(),
                0,
                "Primus-Node-WebTransport",
            )
            .await
            .map_err(|e| anyhow!("WebTransport UDP Port Mapping failed: {}", e))?;

        let external_ip = gateway
            .get_external_ip()
            .await
            .map_err(|e| anyhow!("Failed to get external IP: {}", e))?;

        println!(
            "✅ NAT: UDP ports {} (QUIC) and {} (WebTransport) successfully opened. Global access enabled. External IP: {}",
            port, wt_port, external_ip
        );

        Ok(external_ip)
    }
}