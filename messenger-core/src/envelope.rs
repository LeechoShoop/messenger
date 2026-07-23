// =============================================================================
// messenger-core/src/envelope.rs — Application-level message schema
//
// Deliberately minimal for now: no read receipts beyond delivery
// acknowledgement, no group messaging. Extend once 1:1 delivery works end
// to end.
// =============================================================================

use serde::{Deserialize, Serialize};

/// Sender-assigned idempotency key. 32 bytes to line up with NodeID sizing
/// used throughout primus-net-opt (dht.rs, peer.rs). May be random or
/// content-derived (e.g. hash of ciphertext + sender + sent_at) — callers
/// decide; this type doesn't enforce either. `DeliveryReceipt` envelopes
/// (see `MessageKind`) derive theirs from the original message's ID plus
/// the receipt's own sender/timestamp — see `lib.rs::receipt_id`.
pub type MessageId = [u8; 32];

/// Matches `messenger::dht::NodeID` / `PrimusNR::node_id()`'s output shape
/// (SHA3-256 of the peer's ML-DSA-87 public key). Kept as a raw `[u8; 32]`
/// rather than re-exporting `messenger::dht::NodeID` directly, so this
/// schema doesn't shift silently if that type's definition ever moves.
/// The two are structurally identical (`[u8; 32]`) and interchangeable —
/// this is a naming distinction, not a real type boundary — so no
/// conversion is needed when passing one where the other is expected.
pub type NodeId = [u8; 32];

/// What kind of application message this envelope carries.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum MessageKind {
    DirectMessage,
    /// Sent automatically by the recipient's `MessengerCore` when it
    /// stores a new `DirectMessage` — see `lib.rs::on_envelope`. Never
    /// itself triggers another receipt (guarded structurally: receipts
    /// are handled on a separate path in `on_envelope` that never calls
    /// the receipt-queuing step).
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
    ///
    /// For `MessageKind::DeliveryReceipt` envelopes specifically, this
    /// holds a bincode-serialized `ReceiptPayload` rather than message
    /// content — reusing the generic opaque field instead of adding a
    /// dedicated wire-level receipt type, to keep the schema minimal per
    /// the original design note above.
    pub ciphertext: Vec<u8>,

    /// Unix epoch seconds at creation.
    pub sent_at: u64,

    /// What kind of message this is. See `MessageKind` doc comment.
    pub kind: MessageKind,
}

/// Structured content of a `MessageKind::DeliveryReceipt` envelope,
/// bincode-serialized into that envelope's `ciphertext` field. Not a
/// wire-level `Envelope` field of its own — see the note on `ciphertext`
/// above for why.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ReceiptPayload {
    /// The `message_id` of the original `DirectMessage` this receipt
    /// acknowledges.
    pub message_id: MessageId,
    /// Unix epoch seconds when the recipient's `MessengerCore` stored the
    /// original message (i.e. when it was received, not when the receipt
    /// was sent — the two are computed at the same instant here, but are
    /// conceptually different timestamps).
    pub received_at: u64,
}

/// Local delivery-tracking status for a message this node originated.
///
/// Only meaningful for `StoredMessage` entries created via
/// `MessengerCore::record_sent` (i.e. our own outbound `DirectMessage`s).
/// For inbound entries (messages received from a peer, stored by
/// `on_envelope`), this is set to `Delivered` unconditionally — "did this
/// arrive" is trivially true for something we just finished storing, but
/// the field's real purpose is tracking the sender-side lifecycle
/// (Sent -> Delivered upon receipt, or -> Failed if the send itself
/// failed at the transport level). See `lib.rs` for both write paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Handed off to `delivery::send_direct_message`; no confirmation yet.
    Sent,
    /// A matching `DeliveryReceipt` arrived from the recipient.
    Delivered,
    /// The send itself failed at the transport level (see
    /// `MessengerCore::mark_failed`). Distinct from "no receipt yet" —
    /// this means the attempt itself did not succeed, not that
    /// confirmation is merely pending.
    Failed,
}

/// What MessengerCore keeps per accepted or originated message.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub envelope: Envelope,
    pub status: DeliveryStatus,
}