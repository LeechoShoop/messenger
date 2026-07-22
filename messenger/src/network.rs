// primus-net-opt/src/network.rs — Wire message types for the QUIC gossip path.
//
// DELETION PASS: The plaintext TCP network stack (PrimusNetwork<H>, the
// CoreHandle trait, connect_to_peer/send_to_peer/broadcast_message,
// start_listener, run_discovery_loop, and the handle_peer_logic TCP
// connection loop) has been removed. All peer-to-peer transport now goes
// through the QUIC/Noise path in server.rs.
//
// PrimusMessage is kept, but stripped down to the single variant the QUIC
// gossip path (server.rs) actually deserializes: `Envelope`. The TCP
// handshake-only variants (Ping, Pong, Handshake, GetPeers, PeersResponse,
// NodeError) existed solely to drive the now-deleted TCP peer loop and had
// no consumers on the QUIC path, so they were removed along with it.
//
// See lib.rs / server.rs for how this is used: server.rs deserializes
// incoming gossip-stream ciphertext into a `PrimusMessage` and matches on
// `Envelope` to hand the payload off to the application layer.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PrimusMessage {
    /// Generic application payload with TTL-decayed gossip relay.
    /// This is the single hook `messenger-core` plugs into — everything
    /// application-specific (message content, delivery receipts, presence)
    /// travels as an opaque envelope here. The network layer never inspects
    /// the bytes; they are ML-DSA/Noise-protected before they ever reach it.
    Envelope(Vec<u8>, u8), // data, ttl
}