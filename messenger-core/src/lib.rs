// =============================================================================
// messenger-core — application layer for the primus messenger
//
// `MessengerCore` implements `messenger::server::MessageIngress` so it can
// be handed to `PrimusNetworkServer::new()` in place of main.rs's
// `LoggingIngress` stand-in.
//
// STORE: Arc<Mutex<HashMap<MessageId, StoredMessage>>>, in-memory only.
// GAP (flagged, not silently guessed around): no persistence yet. Every
// restart loses the store, INCLUDING the Sent/Delivered/Failed status
// tracking added this prompt — a DeliveryReceipt arriving after a restart
// finds no matching entry and is logged and dropped (see
// `ingest_receipt`'s `None` arm). That's a real gap, not just a cosmetic
// one, now that delivery status is user-visible; persistence is still
// prompt 18's job, not fixed here.
//
// on_envelope CONTRACT (per server.rs's MessageIngress trait):
//   Ok(true)  — new information was recorded: either a new message was
//               stored, or a DeliveryReceipt updated a tracked message's
//               status to Delivered for the first time.
//   Ok(false) — no-op: a duplicate message, a duplicate/stale receipt, or
//               a receipt for a message this node has no record of
//               sending.
//   Err(_)    — bytes did not deserialize as `Envelope` (or, for a
//               DeliveryReceipt, its `ciphertext` did not deserialize as
//               `ReceiptPayload`). server.rs logs and drops on Err without
//               tearing down the session.
//
// DELIVERY RECEIPTS (this prompt):
//   - Inbound `DirectMessage`, newly stored -> `queue_receipt` builds a
//     `DeliveryReceipt` envelope and hands it to `outbound_tx`. See
//     outbound.rs for why this is a channel handoff rather than a direct
//     `send_direct_message` call, and for the loop that actually sends it.
//   - Inbound `DeliveryReceipt` -> `ingest_receipt` looks up the
//     original message by the ID carried in the receipt's payload and, if
//     found and not already `Delivered`, marks it so.
//   - LOOP GUARD: `on_envelope` dispatches `DeliveryReceipt` envelopes to
//     `ingest_receipt` on a separate branch that never calls
//     `queue_receipt`. This isn't a runtime check that could be forgotten
//     under some condition — receipts structurally never reach the code
//     path that queues a receipt, full stop.
// =============================================================================

pub mod delivery;
pub mod envelope;
pub mod outbound;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use sha3::{Digest, Sha3_256};
use tokio::sync::Mutex;

use messenger::server::MessageIngress;

pub use delivery::{send_direct_message, DeliveryResult};
pub use envelope::{
    DeliveryStatus, Envelope, MessageId, MessageKind, NodeId, ReceiptPayload, StoredMessage,
};
pub use outbound::{run_outbound_dispatch, send_tracked_message, OutboundReceiver, PendingSend};

/// Application core: owns the in-memory message store and implements
/// `MessageIngress` so it can be plugged into `PrimusNetworkServer`.
pub struct MessengerCore {
    store: Arc<Mutex<HashMap<MessageId, StoredMessage>>>,
    /// This node's own NodeID, needed to fill `sender_node_id` on the
    /// DeliveryReceipt envelopes this node originates. There was no
    /// existing place `MessengerCore` learned its own identity from
    /// before this prompt — construction now requires it explicitly.
    local_node_id: NodeId,
    outbound_tx: outbound::OutboundSender,
}

impl MessengerCore {
    /// Construct a new core for the node identified by `local_node_id`
    /// (the same value as `PrimusNR::node_id()` for this node's identity —
    /// see peer.rs).
    ///
    /// BREAKING CHANGE from the previous prompt: `new()` now takes
    /// `local_node_id` and returns `(Self, OutboundReceiver)` instead of
    /// just `Self` — the receiver must be handed to
    /// `outbound::run_outbound_dispatch` (spawned separately, alongside
    /// the server) for auto-sent DeliveryReceipts to actually go out. See
    /// outbound.rs's module doc comment for the full wiring. `Default` is
    /// removed accordingly — there's no sensible default `local_node_id`
    /// or a way to return a tuple from a zero-arg trait method.
    pub fn new(local_node_id: NodeId) -> (Self, OutboundReceiver) {
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
                local_node_id,
                outbound_tx,
            },
            outbound_rx,
        )
    }

    /// Look up a previously-ingested or self-originated message by ID.
    /// Exposed for whatever reads the store next (a CLI, a future API
    /// layer, tests) — not used internally by `on_envelope` itself.
    pub async fn get(&self, id: &MessageId) -> Option<StoredMessage> {
        self.store.lock().await.get(id).cloned()
    }

    /// Number of messages currently held (inbound + outbound-tracked).
    /// Mainly for logging/tests.
    pub async fn len(&self) -> usize {
        self.store.lock().await.len()
    }

    /// Record that `envelope` (expected to be `MessageKind::DirectMessage`)
    /// is being sent by this node, with status `Sent`, so a later
    /// `DeliveryReceipt` has something to update to `Delivered`.
    ///
    /// No-op for any other `MessageKind` — receipts and presence updates
    /// aren't tracked this way. Uses `entry(..).or_insert(..)` rather than
    /// unconditional overwrite so a retried send doesn't clobber a status
    /// that already advanced to `Delivered` (or `Failed`) in the meantime.
    ///
    /// Called by `outbound::send_tracked_message` — see that function for
    /// the intended single entry point for outbound `DirectMessage`s
    /// (prompt 19's future CLI/API layer). Exposed as its own public
    /// method too, in case a caller needs to record without immediately
    /// sending.
    pub async fn record_sent(&self, envelope: Envelope) {
        if envelope.kind != MessageKind::DirectMessage {
            return;
        }
        let id = envelope.message_id;
        let mut store = self.store.lock().await;
        store.entry(id).or_insert(StoredMessage {
            envelope,
            status: DeliveryStatus::Sent,
        });
    }

    /// Mark a previously `record_sent` message as `Failed` at the
    /// transport level — distinct from "no receipt has arrived yet",
    /// which just stays `Sent` indefinitely (no timeout logic exists to
    /// convert a stale `Sent` into `Failed` on its own).
    pub async fn mark_failed(&self, message_id: &MessageId) {
        let mut store = self.store.lock().await;
        if let Some(stored) = store.get_mut(message_id) {
            stored.status = DeliveryStatus::Failed;
        }
    }

    /// Store `envelope` if its `message_id` hasn't been seen before.
    /// Returns `true` if it was newly stored, `false` if it was already
    /// present (duplicate — see the module doc comment's `on_envelope`
    /// contract).
    ///
    /// Inbound entries are stored with status `Delivered` — see
    /// `DeliveryStatus`'s doc comment for why that's the right default
    /// for something this node just received, as opposed to `Sent`
    /// (which only applies to this node's own outbound messages via
    /// `record_sent`).
    async fn store_new(&self, envelope: Envelope) -> bool {
        let mut store = self.store.lock().await;
        if store.contains_key(&envelope.message_id) {
            log::debug!(
                "MessengerCore: duplicate message {} dropped (already stored)",
                hex_short(&envelope.message_id)
            );
            return false;
        }

        let id = envelope.message_id;
        store.insert(
            id,
            StoredMessage {
                envelope,
                status: DeliveryStatus::Delivered,
            },
        );
        log::info!("MessengerCore: stored new message {}", hex_short(&id));
        true
    }

    /// Build a `DeliveryReceipt` envelope for `original` and hand it to
    /// `outbound_tx`. Fire-and-forget from this method's point of view —
    /// see outbound.rs for what actually sends it and why this can't call
    /// `send_direct_message` directly.
    fn queue_receipt(&self, original: &Envelope) {
        let received_at = unix_now();
        let payload = ReceiptPayload {
            message_id: original.message_id,
            received_at,
        };

        let ciphertext = match bincode::serialize(&payload) {
            Ok(bytes) => bytes,
            Err(e) => {
                log::warn!(
                    "MessengerCore: failed to build delivery receipt payload for {}: {}",
                    hex_short(&original.message_id),
                    e
                );
                return;
            }
        };

        let receipt = Envelope {
            message_id: receipt_id(&original.message_id, &self.local_node_id, received_at),
            sender_node_id: self.local_node_id,
            recipient_node_id: original.sender_node_id,
            ciphertext,
            sent_at: received_at,
            kind: MessageKind::DeliveryReceipt,
        };

        let pending = PendingSend {
            // `messenger::dht::NodeID` and this crate's `NodeId` are the
            // same underlying `[u8; 32]` — see envelope.rs's doc comment
            // on `NodeId`.
            recipient_node_id: original.sender_node_id,
            envelope: receipt,
        };

        // Unbounded channel: `send` only fails if `run_outbound_dispatch`'s
        // receiver has been dropped (node shutting down) — nothing useful
        // to do but log.
        if let Err(e) = self.outbound_tx.send(pending) {
            log::warn!(
                "MessengerCore: failed to queue delivery receipt for {}: {}",
                hex_short(&original.message_id),
                e
            );
        }
    }

    /// Look up the original message by the ID carried in `receipt`'s
    /// payload and mark it `Delivered` if found and not already so.
    async fn ingest_receipt(&self, receipt: Envelope) -> Result<bool> {
        let payload: ReceiptPayload = bincode::deserialize(&receipt.ciphertext)
            .map_err(|e| anyhow::anyhow!("malformed delivery receipt: {}", e))?;

        let mut store = self.store.lock().await;
        match store.get_mut(&payload.message_id) {
            Some(stored) if stored.status != DeliveryStatus::Delivered => {
                stored.status = DeliveryStatus::Delivered;
                log::info!(
                    "MessengerCore: message {} marked Delivered (receipt from {})",
                    hex_short(&payload.message_id),
                    hex_short(&receipt.sender_node_id)
                );
                Ok(true)
            }
            Some(_) => {
                log::debug!(
                    "MessengerCore: duplicate delivery receipt for {} ignored",
                    hex_short(&payload.message_id)
                );
                Ok(false)
            }
            None => {
                // Receipt for a message this node has no record of
                // sending — could be a restart (store is in-memory only,
                // see the module doc comment's persistence GAP), or a
                // misdirected/unsolicited receipt. Not an error either
                // way: log and drop rather than fail the whole ingress
                // call over it.
                log::debug!(
                    "MessengerCore: delivery receipt for unknown message {} ignored",
                    hex_short(&payload.message_id)
                );
                Ok(false)
            }
        }
    }
}

#[async_trait::async_trait]
impl MessageIngress for MessengerCore {
    async fn on_envelope(&self, bytes: &[u8]) -> Result<bool> {
        // Malformed bytes -> Err, so server.rs's gossip handler can log and
        // drop without crashing (see server.rs's `.with_context(...)` call
        // around `ingress.on_envelope`).
        let envelope: Envelope = bincode::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("malformed envelope: {}", e))?;

        // LOOP GUARD: DeliveryReceipts are handled entirely on this branch
        // and never reach `queue_receipt` below — see the module doc
        // comment.
        if envelope.kind == MessageKind::DeliveryReceipt {
            return self.ingest_receipt(envelope).await;
        }

        let kind = envelope.kind.clone();
        let is_new = self.store_new(envelope.clone()).await;

        if is_new && kind == MessageKind::DirectMessage {
            self.queue_receipt(&envelope);
        }

        Ok(is_new)
    }
}

/// Content-derived ID for a DeliveryReceipt envelope: SHA3-256 of a
/// domain-separation tag, the original message's ID, this node's own
/// NodeID, and the receipt's timestamp. Avoids needing a `rand`
/// dependency (messenger-core doesn't currently have one) while still
/// being effectively unique per (message, sender, moment) — matches
/// `MessageId`'s own doc comment, which explicitly allows "random or
/// content-derived".
fn receipt_id(original_id: &MessageId, local_node_id: &NodeId, received_at: u64) -> MessageId {
    let mut hasher = Sha3_256::new();
    hasher.update(b"primus-messenger-core:delivery-receipt");
    hasher.update(original_id);
    hasher.update(local_node_id);
    hasher.update(received_at.to_be_bytes());
    hasher.finalize().into()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope(id: u8, kind: MessageKind) -> Envelope {
        Envelope {
            message_id: [id; 32],
            sender_node_id: [0xAB; 32],
            recipient_node_id: [0xCD; 32],
            ciphertext: vec![1, 2, 3], // TODO(e2e): plaintext stub, see envelope.rs
            sent_at: 0,
            kind,
        }
    }

    #[tokio::test]
    async fn new_direct_message_is_stored_and_returns_true() {
        let (core, _outbound_rx) = MessengerCore::new([0xEE; 32]);
        let bytes = bincode::serialize(&sample_envelope(1, MessageKind::DirectMessage)).unwrap();

        let result = core.on_envelope(&bytes).await.unwrap();

        assert!(result);
        assert_eq!(core.len().await, 1);
        let stored = core.get(&[1u8; 32]).await.unwrap();
        assert_eq!(stored.status, DeliveryStatus::Delivered);
    }

    #[tokio::test]
    async fn duplicate_direct_message_returns_false_and_does_not_overwrite() {
        let (core, _outbound_rx) = MessengerCore::new([0xEE; 32]);
        let first = bincode::serialize(&sample_envelope(2, MessageKind::DirectMessage)).unwrap();
        let mut second_env = sample_envelope(2, MessageKind::DirectMessage);
        second_env.ciphertext = vec![9, 9, 9]; // different content, same id
        let second = bincode::serialize(&second_env).unwrap();

        assert!(core.on_envelope(&first).await.unwrap());
        assert!(!core.on_envelope(&second).await.unwrap());

        assert_eq!(core.len().await, 1);
        let stored = core.get(&[2u8; 32]).await.unwrap();
        assert_eq!(stored.envelope.ciphertext, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn malformed_bytes_return_err_not_panic() {
        let (core, _outbound_rx) = MessengerCore::new([0xEE; 32]);
        let garbage = vec![0xFF, 0x00, 0x01, 0x02];

        let result = core.on_envelope(&garbage).await;

        assert!(result.is_err());
        assert_eq!(core.len().await, 0);
    }

    #[tokio::test]
    async fn new_direct_message_queues_exactly_one_receipt() {
        let (core, mut outbound_rx) = MessengerCore::new([0xEE; 32]);
        let bytes = bincode::serialize(&sample_envelope(3, MessageKind::DirectMessage)).unwrap();

        core.on_envelope(&bytes).await.unwrap();

        let pending = outbound_rx.try_recv().expect("a receipt should be queued");
        assert_eq!(pending.envelope.kind, MessageKind::DeliveryReceipt);
        // Receipt goes back to the original sender.
        assert_eq!(pending.recipient_node_id, [0xAB; 32]);
        let payload: ReceiptPayload = bincode::deserialize(&pending.envelope.ciphertext).unwrap();
        assert_eq!(payload.message_id, [3; 32]);

        // Exactly one — nothing else was queued behind it.
        assert!(outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn duplicate_direct_message_does_not_queue_a_second_receipt() {
        let (core, mut outbound_rx) = MessengerCore::new([0xEE; 32]);
        let bytes = bincode::serialize(&sample_envelope(4, MessageKind::DirectMessage)).unwrap();

        core.on_envelope(&bytes).await.unwrap();
        outbound_rx.try_recv().expect("first receipt should be queued");

        core.on_envelope(&bytes).await.unwrap(); // duplicate
        assert!(
            outbound_rx.try_recv().is_err(),
            "a duplicate message must not queue a second receipt"
        );
    }

    #[tokio::test]
    async fn presence_update_is_stored_but_does_not_queue_a_receipt() {
        let (core, mut outbound_rx) = MessengerCore::new([0xEE; 32]);
        let bytes = bincode::serialize(&sample_envelope(5, MessageKind::PresenceUpdate)).unwrap();

        let result = core.on_envelope(&bytes).await.unwrap();

        assert!(result);
        assert!(outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn delivery_receipt_marks_original_message_delivered() {
        let (core, mut outbound_rx) = MessengerCore::new([0xEE; 32]);

        // Simulate having sent a DirectMessage: record it as Sent.
        let original = sample_envelope(6, MessageKind::DirectMessage);
        core.record_sent(original.clone()).await;
        assert_eq!(
            core.get(&[6; 32]).await.unwrap().status,
            DeliveryStatus::Sent
        );

        // Build the receipt the recipient would have sent back and feed
        // it through on_envelope, as if it arrived over the network.
        let payload = ReceiptPayload {
            message_id: [6; 32],
            received_at: 12345,
        };
        let receipt = Envelope {
            message_id: [99; 32],
            sender_node_id: [0xCD; 32], // the original recipient
            recipient_node_id: [0xEE; 32], // us
            ciphertext: bincode::serialize(&payload).unwrap(),
            sent_at: 12345,
            kind: MessageKind::DeliveryReceipt,
        };
        let bytes = bincode::serialize(&receipt).unwrap();

        let result = core.on_envelope(&bytes).await.unwrap();

        assert!(result);
        assert_eq!(
            core.get(&[6; 32]).await.unwrap().status,
            DeliveryStatus::Delivered
        );
        // Receipt processing must never queue another receipt.
        assert!(outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn receipt_for_unknown_message_is_dropped_not_errored() {
        let (core, _outbound_rx) = MessengerCore::new([0xEE; 32]);

        let payload = ReceiptPayload {
            message_id: [123; 32], // never sent
            received_at: 1,
        };
        let receipt = Envelope {
            message_id: [200; 32],
            sender_node_id: [0xCD; 32],
            recipient_node_id: [0xEE; 32],
            ciphertext: bincode::serialize(&payload).unwrap(),
            sent_at: 1,
            kind: MessageKind::DeliveryReceipt,
        };
        let bytes = bincode::serialize(&receipt).unwrap();

        let result = core.on_envelope(&bytes).await.unwrap();

        assert!(!result);
        assert_eq!(core.len().await, 0);
    }

    #[tokio::test]
    async fn mark_failed_updates_status() {
        let (core, _outbound_rx) = MessengerCore::new([0xEE; 32]);
        let original = sample_envelope(7, MessageKind::DirectMessage);
        core.record_sent(original).await;

        core.mark_failed(&[7; 32]).await;

        assert_eq!(
            core.get(&[7; 32]).await.unwrap().status,
            DeliveryStatus::Failed
        );
    }
}