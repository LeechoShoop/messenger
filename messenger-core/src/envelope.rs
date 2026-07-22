// =============================================================================
// messenger-core/src/envelope.rs — Application-level message schema
//
// HONEST GAP: prompt 12's `Envelope` definition wasn't in context for this
// prompt (only dht.rs, lib.rs, noise.rs, server.rs, bootstrap.rs, discovery.rs,
// main.rs, nat.rs, network.rs, peer.rs, transport.rs, Cargo.toml were
// available). What's below is a minimal, reasonable reconstruction —
// reconcile field-for-field against the actual prompt 12 output before
// relying on wire compatibility between nodes.
//
// SCOPE NOTE — two different "duplicate" checks, deliberately separate:
//   - server.rs's `relay.is_new(&data)` hashes the *raw opaque bytes* on the
//     gossip stream. That's transport-level relay-loop suppression: don't
//     re-relay/re-ingest identical ciphertext-adjacent bytes seen before.
//   - `MessageId` here is a field *inside* the deserialized Envelope,
//     assigned by the sender. This is an application-level idempotency
//     key: two envelopes with the same `id` are semantically "the same
//     message" even if their serialized bytes differ (e.g. re-sent with a
//     refreshed TTL). MessengerCore dedups on this, independent of and
//     downstream from the network layer's check.
// =============================================================================

use serde::{Deserialize, Serialize};

/// Application-level message identifier, assigned by the sender at
/// creation time. 32 bytes to line up with the NodeID / SHA3-256 sizing
/// used throughout primus-net-opt (dht.rs, peer.rs) — not itself a hash of
/// anything here, just a fixed-size opaque ID.
pub type MessageId = [u8; 32];

/// The application envelope carried inside `network::PrimusMessage::Envelope`'s
/// opaque `data` field. The network layer never inspects these bytes; this
/// is the first point in the stack that does.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    /// Sender-assigned idempotency key. See module doc comment.
    pub id: MessageId,

    /// Sender's Kademlia NodeID (`messenger::NodeID`, i.e. SHA3-256 of
    /// their ML-DSA-87 public key — see peer.rs). Kept as a raw
    /// `[u8; 32]` here rather than re-exporting `messenger::NodeID`
    /// directly, so this schema doesn't shift silently if that type's
    /// definition ever moves.
    pub sender: [u8; 32],

    /// Unix epoch milliseconds at creation. Not currently used for
    /// expiry/ordering by MessengerCore — stored for later use (e.g. a
    /// prompt-18 persistence layer wanting to prune or sort by age).
    pub timestamp: u64,

    /// Opaque message content. Whatever end-to-end encryption or plaintext
    /// framing applies above this layer is out of scope here — MessengerCore
    /// stores it as-is.
    pub payload: Vec<u8>,
}

/// What MessengerCore keeps per accepted message. Currently just the
/// Envelope itself; split out as its own type (rather than storing
/// `Envelope` directly) so bookkeeping fields (e.g. received_at, delivery
/// state) can be added later without changing the wire schema above.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub envelope: Envelope,
}