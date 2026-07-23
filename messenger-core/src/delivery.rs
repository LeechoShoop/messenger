// =============================================================================
// messenger-core/src/delivery.rs — send_direct_message routing
//
// FREE FUNCTION, NOT A MessengerCore METHOD:
//   `PrimusNetworkServer<M, K>` holds ingress as `Arc<M>` — in main.rs's
//   wiring, `M = MessengerCore`. If `send_direct_message` were a method on
//   `MessengerCore` that itself held `Arc<PrimusNetworkServer<MessengerCore, K>>`,
//   that's a reference cycle (server -> ingress -> server -> ...), which
//   leaks both Arcs forever and is also circular in the type parameter
//   itself. So this follows the same shape as `bootstrap::bootstrap` /
//   `bootstrap::connect_seeds` in the messenger crate: a free function that
//   takes `&Arc<PrimusNetworkServer<M, K>>` explicitly, generic over M/K.
//   Callers (the future CLI/API layer, prompt 19) hold both the server Arc
//   and their MessengerCore handle side by side and pass the former in.
//
// REQUIRED UPSTREAM CHANGE (already applied, flagging it so it isn't
// missed on a clean rebuild): `PrimusNetworkServer::dht` was a private
// field. This module needs read access to `PrimusDHT::find_closest`, so a
// `pub fn dht(&self) -> &PrimusDHT` accessor was added to server.rs. See
// that file's diff.
//
// HONEST GAP — could not verify messenger's own lib.rs:
//   This crate needs `messenger::dht::{PrimusDHT, NodeID}` and
//   `messenger::network::PrimusMessage` to be reachable from outside the
//   `messenger` crate, i.e. `pub mod dht;` and `pub mod network;` in
//   primus-net-opt/src/lib.rs. That file was not available in this
//   session's context (both uploads named `lib.rs` — messenger-core's and
//   messenger's — landed at the same flat path and the second overwrote
//   the first on disk, so only messenger-core's lib.rs was actually
//   inspectable here). Every module this file needs *by name*
//   (`server`, `peer`, `dht`, `network`) already has other evidence of
//   being part of the public API (bootstrap.rs/server.rs/main.rs all
//   reference them, and `peer::PrimusNR::node_id()` returns
//   `dht::NodeID`, which is only useful to external callers if `dht` is
//   public) — but please double check `pub mod dht;` and
//   `pub mod network;` are actually present before assuming this builds.
//
// EXACT-MATCH LOOKUP VIA find_closest:
//   `PrimusDHT` has no "get by exact ID" method (see dht.rs) — only
//   `find_closest(target, k)`. That's sufficient for an exact check: if
//   `recipient_node_id` is in the table at all, its XOR distance to
//   itself is zero, so it IS the closest node to the target and a
//   `find_closest(target, 1)` call returns it as the sole (or first)
//   result. This function treats "closest result's node_id equals the
//   target" as "known", and anything else (empty result, or a closest
//   match that isn't exact) as "not known" — falling through to the
//   gossip-relay path rather than guessing at an approximate address.
//
// TTL SEMANTICS:
//   - Direct delivery (existing or freshly-dialed session): TTL 0. Per
//     the prompt, TTL 0 here means "no further relay" — the recipient's
//     own `handle_gossip_stream` sees `ttl == 0` and, per its existing
//     logic (server.rs), still calls `ingress.on_envelope` but never
//     calls `relay.relay(...)` on it. Exactly the "direct delivery, not
//     gossip flood" behavior asked for.
//   - Fallback flood: uses `GOSSIP_FALLBACK_TTL` below rather than
//     `GossipRelay::relay()` itself. `relay()` is written for the
//     *re*-broadcast case (a message we received from peer X, forwarded
//     to everyone except X) and unconditionally decrements TTL by one
//     hop before sending. Calling it to *originate* a message would
//     burn one hop before the message ever left this node and would
//     need a fake "from" address to avoid excluding a real peer. Cleaner
//     to build the `PrimusMessage::Envelope` directly here with the full
//     starting TTL and fan it out to every current session ourselves.
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;

use messenger::dht::NodeID;
use messenger::network::PrimusMessage;
use messenger::server::{KademliaHandler, MessageIngress, PeerSession, PrimusNetworkServer};

use crate::envelope::Envelope;

/// Starting TTL for the gossip-relay fallback path (step 4). No
/// project-wide default TTL constant existed to reuse — server.rs's own
/// tests use 32 as a representative "generous but bounded" value, so that
/// convention is followed here. Revisit if/when a real default is settled
/// on elsewhere in the stack.
const GOSSIP_FALLBACK_TTL: u8 = 32;

/// Outcome of a `send_direct_message` call, for the CLI/API layer
/// (prompt 19) to show delivery status to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeliveryResult {
    /// Sent directly to the recipient's own session (existing or
    /// freshly-dialed), TTL 0 — no relay involved.
    DirectDelivered,
    /// Recipient's address was not known locally; the envelope was
    /// flooded via TTL-decayed gossip relay as a last resort.
    RelayedViaGossip,
    /// Serialization, dial, or send failed with no remaining fallback.
    Failed,
}

/// Route `envelope` to `recipient_node_id`.
///
/// Order of attempts (per the routing strategy this implements):
///   1. Resolve `recipient_node_id` to an address via the local DHT.
///   2. If resolved and an active session already exists for that
///      address, send directly over it (TTL 0).
///   3. If resolved but no active session exists, dial the peer via
///      `connect_to_peer`, then send directly (TTL 0).
///   4. If not resolved at all (or the dial/send in step 3 failed), fall
///      back to TTL-decayed gossip relay so the network can route it via
///      flood.
pub async fn send_direct_message<M, K>(
    server: &Arc<PrimusNetworkServer<M, K>>,
    recipient_node_id: NodeID,
    envelope: Envelope,
) -> DeliveryResult
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let data = match bincode::serialize(&envelope) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::warn!(
                "send_direct_message: envelope serialization failed, cannot send: {}",
                e
            );
            return DeliveryResult::Failed;
        }
    };

    // ── Step 1: DHT lookup (doubles as the "exact node already known"
    // check — see the module doc comment on why find_closest(k=1) is
    // sufficient here). ────────────────────────────────────────────────
    let closest = server.dht().find_closest(&recipient_node_id, 1).await;
    let known_addr = closest
        .into_iter()
        .find(|nr| nr.node_id() == recipient_node_id)
        .map(|nr| nr.addr());

    let Some(addr) = known_addr else {
        // ── Step 4: not in the DHT at all — flood via gossip relay. ────
        log::info!(
            "send_direct_message: recipient not found in DHT, falling back to gossip relay"
        );
        return relay_fallback(server, &data).await;
    };

    // ── Step 2: active session already open for that address? ──────────
    if let Some(session) = server.sessions.get(&addr) {
        let session = session.value().clone();
        return send_over_session(&session, &data, addr).await;
    }

    // ── Step 3: known address, no session — dial, then send. ────────────
    log::info!(
        "send_direct_message: no active session for {}, dialing before send",
        addr
    );
    if let Err(e) = server.connect_to_peer(addr).await {
        log::warn!(
            "send_direct_message: connect_to_peer({}) failed, falling back to gossip relay: {}",
            addr,
            e
        );
        return relay_fallback(server, &data).await;
    }

    // `connect_to_peer` re-derives the actual remote address from the
    // established QUIC connection rather than assuming it matches `addr`
    // exactly (see its own comment in server.rs) — on the rare mismatch,
    // or if the session was already torn down again by the time we get
    // here, don't guess: fall back rather than silently dropping the
    // message.
    match server.sessions.get(&addr) {
        Some(session) => {
            let session = session.value().clone();
            send_over_session(&session, &data, addr).await
        }
        None => {
            log::warn!(
                "send_direct_message: connect_to_peer({}) returned Ok but no session is present, \
                 falling back to gossip relay",
                addr
            );
            relay_fallback(server, &data).await
        }
    }
}

/// Encrypt-and-send `data` over an already-open session with TTL 0 (direct
/// delivery, no further relay by the recipient).
async fn send_over_session(session: &Arc<PeerSession>, data: &[u8], addr: SocketAddr) -> DeliveryResult {
    let message = PrimusMessage::Envelope(data.to_vec(), 0);
    let payload = match bincode::serialize(&message) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::warn!(
                "send_direct_message: PrimusMessage serialization failed for {}: {}",
                addr,
                e
            );
            return DeliveryResult::Failed;
        }
    };

    match session.send_gossip(&payload).await {
        Ok(()) => DeliveryResult::DirectDelivered,
        Err(e) => {
            log::warn!(
                "send_direct_message: send_gossip to {} failed: {}",
                addr,
                e
            );
            DeliveryResult::Failed
        }
    }
}

/// Last-resort path: flood `data` to every currently-held session at
/// `GOSSIP_FALLBACK_TTL`, so the network can route it hop-by-hop even
/// though we don't know the recipient's address. See the module doc
/// comment for why this builds the message directly instead of going
/// through `GossipRelay::relay()`.
async fn relay_fallback<M, K>(
    server: &Arc<PrimusNetworkServer<M, K>>,
    data: &[u8],
) -> DeliveryResult
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let message = PrimusMessage::Envelope(data.to_vec(), GOSSIP_FALLBACK_TTL);
    let payload = match bincode::serialize(&message) {
        Ok(bytes) => bytes,
        Err(e) => {
            log::warn!(
                "send_direct_message: PrimusMessage serialization failed for gossip fallback: {}",
                e
            );
            return DeliveryResult::Failed;
        }
    };

    // Seed the shared dedup cache with this message before sending, so
    // that if it loops back to us through another peer's relay (a mesh
    // with more than one path back to us), handle_gossip_stream's
    // `relay.is_new()` check recognizes it as already-seen and drops it
    // instead of re-ingesting/re-relaying our own message. Not something
    // the prompt asked for explicitly, but a direct consequence of
    // reusing the same GossipRelay the receive path uses for dedup — flag
    // it here in case that surprises anyone reading this later.
    let _ = server.relay.is_new(data).await;

    let targets: Vec<Arc<PeerSession>> = server
        .sessions
        .iter()
        .map(|entry| entry.value().clone())
        .collect();

    if targets.is_empty() {
        log::warn!("send_direct_message: no active sessions to flood gossip fallback through");
        return DeliveryResult::Failed;
    }

    let mut any_sent = false;
    for session in targets {
        if session.send_gossip(&payload).await.is_ok() {
            any_sent = true;
        }
    }

    if any_sent {
        DeliveryResult::RelayedViaGossip
    } else {
        log::warn!("send_direct_message: gossip fallback failed on every current session");
        DeliveryResult::Failed
    }
}