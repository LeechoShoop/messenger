use crate::noise::NoiseStream;
use anyhow::Result;
use crate::peer::PrimusNR;
use tokio::io::{AsyncRead, AsyncWrite};

/// A unified stream that handles post-quantum security regardless of the
/// underlying transport (QUIC vs WebTransport).
pub struct PrimusTransportStream<S> {
    pub noise: NoiseStream<S>,
    pub is_leaf: bool,
}

/// Unified inbound handler (Part 7.5)
///
/// Abstracts away the underlying transport. Performs the mandatory Noise_XX
/// handshake with ML-DSA-87 identity binding.
pub async fn handle_inbound<S>(
    stream: S,
    is_wasm: bool,
    noise_static: &[u8],
    local_nr: &PrimusNR,
    ml_dsa_sk: &[u8],
) -> Result<(PrimusTransportStream<S>, PrimusNR)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Mandatory Noise handshake occurs INSIDE the transport stream.
    // handshake_responder already verifies the peer's Node Record and
    // hands it back — surfaced here instead of being discarded, so callers
    // (server.rs) can register the peer in the DHT right after the
    // handshake completes rather than only via a later Kademlia FIND_NODE.
    let (mut noise, peer_nr) =
        NoiseStream::handshake_responder(stream, noise_static, local_nr, ml_dsa_sk).await?;

    // Enable WASM padding if the client is a browser
    noise.is_wasm = is_wasm;

    Ok((
        PrimusTransportStream {
            noise,
            is_leaf: is_wasm, // Leaf nodes (WASM/Light Clients) don't route traffic
        },
        peer_nr,
    ))
}

/// Unified outbound handler — mirror of `handle_inbound` for the dialing
/// side of a connection.
///
/// Performs the mandatory Noise_XX handshake as the initiator with ML-DSA-87
/// identity binding. Used when we open a connection to a peer discovered via
/// LAN discovery (see discovery.rs) or a DHT bootstrap/lookup (see dht.rs),
/// as opposed to `handle_inbound`, which runs on the accept side.
pub async fn handle_outbound<S>(
    stream: S,
    is_wasm: bool,
    noise_static: &[u8],
    local_nr: &PrimusNR,
    ml_dsa_sk: &[u8],
) -> Result<(PrimusTransportStream<S>, PrimusNR)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Mandatory Noise handshake occurs INSIDE the transport stream. See the
    // matching comment in handle_inbound — same reasoning applies here for
    // the dialing side.
    let (mut noise, peer_nr) =
        NoiseStream::handshake_initiator(stream, noise_static, local_nr, ml_dsa_sk).await?;

    // Enable WASM padding if we are the browser/WASM side of this connection.
    noise.is_wasm = is_wasm;

    Ok((
        PrimusTransportStream {
            noise,
            is_leaf: is_wasm, // Leaf nodes (WASM/Light Clients) don't route traffic
        },
        peer_nr,
    ))
}

#[cfg(not(target_arch = "wasm32"))]
pub mod listeners {
    use super::*;
    use std::net::SocketAddr;
    use wtransport::Endpoint as WtEndpoint;
    use wtransport::ServerConfig as WtServerConfig;
    use wtransport::endpoint::endpoint_side::Server;

    pub struct WebTransportListener {
        endpoint: WtEndpoint<Server>,
    }

    impl WebTransportListener {
        pub async fn bind(addr: SocketAddr, identity: wtransport::Identity) -> Result<Self> {
            let config = WtServerConfig::builder()
                .with_bind_address(addr)
                .with_identity(&identity)
                .build();
            let endpoint = WtEndpoint::server(config)?;
            Ok(Self { endpoint })
        }

        pub async fn accept(&self) -> Result<wtransport::Connection> {
            let incoming = self.endpoint.accept().await;
            let session_request = incoming.await?;
            let connection = session_request.accept().await?;
            Ok(connection)
        }
    }
}