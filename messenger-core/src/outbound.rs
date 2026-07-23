// =============================================================================
// messenger-core/src/outbound.rs — outbound send queue + tracked sending
//
// WHY A CHANNEL, NOT A DIRECT CALL:
//   `MessageIngress::on_envelope(&self, bytes: &[u8]) -> Result<bool>` is a
//   fixed trait signature — it has no way to receive
//   `&Arc<PrimusNetworkServer<M, K>>`, and `MessengerCore` can't hold one
//   as a field either (that's the same Arc-cycle problem `delivery.rs`
//   already flagged: server -> ingress -> server -> ...). So when
//   `on_envelope` decides a DeliveryReceipt needs to go out (see
//   `lib.rs`), it can only *queue* that decision — it hands a `PendingSend`
//   to an unbounded channel and returns. `run_outbound_dispatch` below is
//   the other end of that channel: a loop, spawned separately by whoever
//   constructs the server (main.rs), that already holds the server Arc and
//   turns queued sends into real `delivery::send_direct_message` calls.
//
// WIRING (main.rs, or wherever `PrimusNetworkServer<MessengerCore, K>` is
// constructed):
//
//   let (core, outbound_rx) = MessengerCore::new(local_node_id);
//   let ingress = Arc::new(core);
//   let server = Arc::new(PrimusNetworkServer::new(..., ingress.clone(), ...).await?);
//   tokio::spawn(messenger_core::outbound::run_outbound_dispatch(
//       Arc::clone(&server),
//       outbound_rx,
//   ));
//
//   `ingress` and `server` can then be used as before — `run_outbound_dispatch`
//   just needs its own clone of the server Arc, same pattern as
//   `bootstrap::bootstrap` in the messenger crate.
// =============================================================================

use std::sync::Arc;

use tokio::sync::mpsc;

use messenger::dht::NodeID;
use messenger::server::{KademliaHandler, MessageIngress, PrimusNetworkServer};

use crate::delivery::{self, DeliveryResult};
use crate::envelope::{Envelope, MessageKind};
use crate::MessengerCore;

/// One outbound send `MessengerCore` couldn't perform itself — currently
/// only produced internally for `DeliveryReceipt`s (see
/// `lib.rs::queue_receipt`), but shaped generically in case a future
/// caller wants to queue other kinds through the same dispatch loop
/// instead of calling `send_tracked_message` synchronously.
pub struct PendingSend {
    pub recipient_node_id: NodeID,
    pub envelope: Envelope,
}

pub type OutboundReceiver = mpsc::UnboundedReceiver<PendingSend>;
pub type OutboundSender = mpsc::UnboundedSender<PendingSend>;

/// Drains `outbound_rx` for as long as the corresponding `MessengerCore`
/// (and its `OutboundSender`) is alive, routing each `PendingSend` through
/// `delivery::send_direct_message`. Runs until the channel closes — spawn
/// it as its own task and let it exit naturally on shutdown, no explicit
/// stop signal needed.
///
/// Receipts are fire-and-forget from `on_envelope`'s point of view: this
/// loop logs the outcome but there's no caller left to hand a
/// `DeliveryResult` back to. If a receipt's send fails, the sender simply
/// never sees their message move to `Delivered` — no retry is attempted
/// here (retries are a reasonable future addition, not built now).
pub async fn run_outbound_dispatch<M, K>(
    server: Arc<PrimusNetworkServer<M, K>>,
    mut outbound_rx: OutboundReceiver,
) where
    M: MessageIngress,
    K: KademliaHandler,
{
    log::info!("Outbound dispatch: started");
    while let Some(PendingSend {
                       recipient_node_id,
                       envelope,
                   }) = outbound_rx.recv().await
    {
        let kind = envelope.kind.clone();
        let message_id = envelope.message_id;
        let result = delivery::send_direct_message(&server, recipient_node_id, envelope).await;
        log::debug!(
            "Outbound dispatch: {:?} {} -> {:?}",
            kind,
            hex_short(&message_id),
            result
        );
    }
    log::info!("Outbound dispatch: channel closed, exiting");
}

/// Send a `DirectMessage`-kind envelope while tracking it in `core`'s
/// store, so a later `DeliveryReceipt` (processed by `on_envelope`) has
/// something to update.
///
/// For any other `MessageKind`, this is equivalent to calling
/// `delivery::send_direct_message` directly — no tracking happens, since
/// only `DirectMessage`s carry a delivery-status lifecycle (see
/// `DeliveryStatus`'s doc comment). `run_outbound_dispatch` above
/// deliberately does NOT use this helper for the receipts it sends, for
/// the same reason: a receipt is not a tracked `DirectMessage`.
///
/// Intended for the future CLI/API layer (prompt 19) — this prompt only
/// wires the receiving side (`on_envelope`) plus this ready-made sending
/// entry point; nothing yet calls it, since no message-composition layer
/// exists in messenger-core as of this prompt.
pub async fn send_tracked_message<M, K>(
    core: &MessengerCore,
    server: &Arc<PrimusNetworkServer<M, K>>,
    recipient_node_id: NodeID,
    envelope: Envelope,
) -> DeliveryResult
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let is_direct_message = envelope.kind == MessageKind::DirectMessage;
    if is_direct_message {
        core.record_sent(envelope.clone()).await;
    }

    let message_id = envelope.message_id;
    let result = delivery::send_direct_message(server, recipient_node_id, envelope).await;

    if is_direct_message && result == DeliveryResult::Failed {
        core.mark_failed(&message_id).await;
    }

    result
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{:02x}", b)).collect()
}