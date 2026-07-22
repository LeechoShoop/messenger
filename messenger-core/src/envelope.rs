// =============================================================================
// messenger-core/src/envelope.rs — Application-level message schema
//
// Deliberately minimal for now: no read receipts, no group messaging.
// Extend once 1:1 delivery works end to end.
// =============================================================================

use serde::{Deserialize, Serialize};

/// Sender-assigned idempotency key. 32 bytes to line up with NodeID sizing
/// used throughout primus-net-opt (dht.rs, peer.rs). May be random or
/// content-derived (e.g. hash of ciphertext + sender + sent_at) — callers
/// decide; this type doesn't enforce either.
pub type MessageId = [u8; 32];

/// Matches `messenger::dht::NodeID` / `PrimusNR::node_id()`'s output shape
/// (SHA3-256 of the peer's ML-DSA-87 public key). Kept as a raw `[u8; 32]`
/// rather than re-exporting `messenger::NodeID` directly, so this schema
/// doesn't shift silently if that type's definition ever moves.
pub type NodeId = [u8; 32];

/// What kind of application message this envelope carries. Presence and
/// delivery-receipt variants are declared now so the wire schema doesn't
/// need to change shape when those features land — their payload
/// conventions (what goes in `ciphertext` for each) aren't defined yet.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
    DirectMessage,
    DeliveryReceipt,
    PresenceUpdate,
}

/// The application envelope carried inside `network::PrimusMessage::Envelope`'s
/// opaque `data` field. The network layer never inspects these bytes; this
/// is the first point in the stack that does.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Envelope {
    /// Sender-assigned idempotency key. See type doc comment.
    pub message_id: MessageId,

    /// Sender's Kademlia NodeID.
    pub sender_node_id: NodeId,

    /// Intended recipient's Kademlia NodeID. Not used for routing at this
    /// layer — routing/relay is the network layer's job (gossip TTL in
    /// network.rs) — this is here so MessengerCore can filter "is this
    /// envelope addressed to me" once relay isn't purely broadcast.
    pub recipient_node_id: NodeId,

    /// End-to-end encrypted payload.
    ///
    /// TODO(e2e): the actual E2E encryption layer (key agreement, AEAD
    /// scheme, associated data) is out of scope for this prompt and not
    /// designed yet. For now this field is a stub: plaintext bytes wrapped
    /// as-is, with no encryption applied. Do NOT treat this as
    /// confidential until that layer exists — Noise_XX (noise.rs) protects
    /// the transport hop, not this field at rest or across relay hops.
    pub ciphertext: Vec<u8>,

    /// Unix epoch seconds at creation.
    pub sent_at: u64,

    /// What kind of message this is. See `MessageKind` doc comment.
    pub kind: MessageKind,
}

/// What MessengerCore keeps per accepted message. Currently just the
/// Envelope itself; split out as its own type (rather than storing
/// `Envelope` directly) so bookkeeping fields (e.g. received_at, delivery
/// state) can be added later without changing the wire schema above.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub envelope: Envelope,
}