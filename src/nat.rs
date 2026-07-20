use anyhow::{Result, anyhow};
use igd_next::{PortMappingProtocol, SearchOptions};
use std::net::{IpAddr, SocketAddrV4};

pub struct NatService;

impl NatService {
    /// Attempts to open ports via UPnP to make the node accessible from the global internet.
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

        let local_addr = SocketAddrV4::new(ipv4, port);

        // 1. TCP Mapping (peer sync and data exchange)
        gateway
            .add_port(
                PortMappingProtocol::TCP,
                port,
                local_addr.into(),
                0, // Infinite lease duration
                "Primus-Node-TCP",
            )
            .await
            .map_err(|e| anyhow!("TCP Port Mapping failed: {}", e))?;

        // 2. UDP Mapping (For Discovery v5 and high-speed Gossip)
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                port,
                local_addr.into(),
                0,
                "Primus-Node-UDP",
            )
            .await
            .map_err(|e| anyhow!("UDP Port Mapping failed: {}", e))?;

        let external_ip = gateway
            .get_external_ip()
            .await
            .map_err(|e| anyhow!("Failed to get external IP: {}", e))?;

        println!(
            "✅ NAT: Ports {} (TCP/UDP) successfully opened. Global access enabled. External IP: {}",
            port, external_ip
        );

        Ok(external_ip)
    }
}