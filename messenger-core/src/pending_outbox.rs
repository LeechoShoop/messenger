// =============================================================================
// messenger-core/src/pending_outbox.rs — retry queue for failed sends
//
// WHAT THIS IS:
//   `delivery::send_direct_message` (prompt 13) can return
//   `DeliveryResult::Failed` — DHT lookup came back empty *and* the
//   gossip-flood fallback had no sessions to flood through, or every send
//   attempt on the resolved/fallback path errored. Before this prompt,
//   every caller of that function (`outbound::send_tracked_message`,
//   `outbound::run_outbound_dispatch`) just logged the failure and moved
//   on — a `Failed` outbound `DirectMessage` was gone for good the moment
//   the caller returned. `PendingOutbox` is the fix: a per-recipient
//   queue that `Failed` results land in instead of being dropped, plus a
//   background task (`run_retry_loop`) that periodically re-attempts
//   delivery.
//
// WHY GATE RETRIES ON THE DHT INSTEAD OF JUST RE-CALLING
// send_direct_message EVERY TICK:
//   `send_direct_message`'s own fallback, when a recipient isn't in the
//   DHT, is a full gossip-flood to every open session (see delivery.rs).
//   Calling that unconditionally every 30 s for a recipient nobody has
//   seen in days would spam every peer we're connected to with the same
//   stale envelope on a timer, for no better odds of delivery than the
//   first flood already had. Instead, each retry tick checks
//   `PrimusDHT::find_closest` for the recipient first (the same
//   exact-match check `delivery.rs` uses internally — see that file's
//   module doc comment) and only calls `send_direct_message` for
//   recipients the DHT currently resolves. A recipient who was
//   unreachable at send time reappearing *anywhere* in the network
//   should eventually populate our local DHT via the post-handshake
//   registration path (prompt 07) and/or `KademliaEngine`'s hourly
//   `start_maintenance` refresh (lib.rs, messenger crate) — this loop is
//   what turns "now resolvable" into an actual retried send instead of
//   requiring the original sender to notice and resend by hand.
//
//   One consequence worth flagging: a recipient who's only ever reachable
//   via gossip-flood (never resolves in our DHT, e.g. several NAT/relay
//   hops away with no direct path) will never get an outbox-driven retry
//   — it sits queued until it ages out. That's a real limitation of
//   gating on DHT visibility, not an oversight; the alternative
//   (unconditional periodic flooding) was judged worse for the reasons
//   above. The original send attempt's own gossip-flood fallback already
//   ran once at send time regardless.
//
// CAPS:
//   - MAX_PENDING_PER_RECIPIENT (1000): bounds worst-case memory if one
//     recipient never resolves and the sender keeps composing messages to
//     them. Enforced in `push()` by evicting the single oldest queued
//     envelope for that recipient (FIFO) — favors keeping the most recent
//     messages over the oldest, on the theory that a long-unreachable
//     recipient is more likely to care about recent context than a
//     message from a thousand sends ago. Each eviction is logged at
//     `warn` since it's a real, user-visible data loss, not routine
//     cache churn.
//   - MAX_RETRY_AGE (7 days): once an envelope has been sitting in the
//     outbox longer than this, it is removed and never retried again,
//     regardless of DHT state. "Notified" per this prompt's requirement
//     means routed through the same mechanism the rest of this crate
//     already uses for terminal send failure: `MessengerCore::mark_failed`,
//     which flips a tracked `DirectMessage`'s status to
//     `DeliveryStatus::Failed` (see envelope.rs / lib.rs). There is no
//     separate push-notification channel in this crate as of this
//     prompt — reusing `mark_failed` keeps aging-out consistent with how
//     an immediate (non-retried) failure is already surfaced to a caller
//     via `outbound::send_tracked_message`. For envelopes that never had
//     a `store` entry to begin with (e.g. a `DeliveryReceipt` queued by
//     `run_outbound_dispatch` — receipts are fire-and-forget and were
//     never `record_sent`), `mark_failed` is a documented no-op (see its
//     doc comment in lib.rs); the receipt simply stops being retried.
//
// LOCK DISCIPLINE:
//   The outbox's internal lock is never held across an `.await` on the
//   DHT or the network (`find_closest`, `send_direct_message`). Each
//   retry-loop tick snapshots the current recipient keys, then
//   re-acquires the lock per recipient only for the in-memory
//   partition/drain step (`drain_due`), releasing it before doing any
//   I/O for that recipient. A recipient added mid-tick (a fresh `push()`
//   from an unrelated `send_tracked_message` call racing the loop) simply
//   isn't in the snapshot and is picked up on the next tick — never lost,
//   just deferred by up to one interval.
// =============================================================================

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

use messenger::dht::NodeID;
use messenger::server::{KademliaHandler, MessageIngress, PrimusNetworkServer};

use crate::delivery::{self, DeliveryResult};
use crate::envelope::Envelope;
use crate::MessengerCore;

/// Per-recipient cap on queued envelopes. See module doc comment for the
/// eviction policy applied once a recipient's queue hits this.
pub const MAX_PENDING_PER_RECIPIENT: usize = 1000;

/// An envelope stops being retried once it has been queued longer than
/// this, regardless of DHT state, and is marked permanently `Failed`
/// instead (see module doc comment).
pub const MAX_RETRY_AGE: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// How often the background retry loop wakes up and re-checks the DHT for
/// every recipient currently holding queued envelopes.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(30);

struct PendingEntry {
    envelope: Envelope,
    /// Unix epoch seconds when this envelope was first queued (not
    /// re-queued — see `push`'s doc comment on why a re-queued entry
    /// keeps its original timestamp rather than resetting it).
    first_queued_at: u64,
}

/// Per-recipient queue of envelopes whose most recent `send_direct_message`
/// attempt returned `Failed`. Cheaply cloneable via `Arc` — constructed
/// once by `MessengerCore::new` and shared between whatever pushes into it
/// (`outbound::send_tracked_message`, `outbound::run_outbound_dispatch`)
/// and the background retry loop (`run_retry_loop`), same sharing pattern
/// as `outbound::OutboundSender`/`OutboundReceiver`.
pub struct PendingOutbox {
    entries: Mutex<HashMap<NodeID, VecDeque<PendingEntry>>>,
}

impl PendingOutbox {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Queue `envelope` for retry against `recipient_node_id`.
    ///
    /// If this is a fresh failure (the envelope wasn't already in the
    /// outbox), `first_queued_at` is stamped with the current time. If
    /// it's a re-queue after a retry attempt also came back `Failed` (see
    /// `run_retry_pass`), the caller is expected to have preserved and
    /// passed back the *original* `PendingEntry`'s timestamp semantics —
    /// in practice this is handled by `run_retry_pass` re-pushing the
    /// envelope it just pulled out via `drain_due`, so age accrues from
    /// the first failure, not from each retry. `push` itself only ever
    /// stamps "now"; callers doing a re-queue after a failed retry should
    /// prefer `push_with_timestamp` to preserve the original age. Plain
    /// `push` is what the two `outbound.rs` call sites use, since those
    /// are always first-time failures for that envelope.
    pub async fn push(&self, recipient_node_id: NodeID, envelope: Envelope) {
        self.push_with_timestamp(recipient_node_id, envelope, unix_now())
            .await;
    }

    /// Same as `push`, but with an explicit `first_queued_at` — used by
    /// the retry loop to re-queue an envelope that failed again without
    /// resetting its age, so `MAX_RETRY_AGE` is measured from the
    /// original failure rather than restarting on every retry attempt.
    pub async fn push_with_timestamp(
        &self,
        recipient_node_id: NodeID,
        envelope: Envelope,
        first_queued_at: u64,
    ) {
        let mut entries = self.entries.lock().await;
        let queue = entries.entry(recipient_node_id).or_default();

        if queue.len() >= MAX_PENDING_PER_RECIPIENT {
            if let Some(dropped) = queue.pop_front() {
                log::warn!(
                    "PendingOutbox: cap ({}) reached for recipient {}, dropping oldest queued message {}",
                    MAX_PENDING_PER_RECIPIENT,
                    hex_short(&recipient_node_id),
                    hex_short(&dropped.envelope.message_id),
                );
            }
        }

        queue.push_back(PendingEntry {
            envelope,
            first_queued_at,
        });
    }

    /// Total envelopes queued across every recipient. For logging/tests.
    pub async fn len(&self) -> usize {
        self.entries.lock().await.values().map(|q| q.len()).sum()
    }

    /// Recipients that currently have at least one queued envelope. Used
    /// by the retry loop to snapshot what to check this tick without
    /// holding the lock across any I/O — see the module doc comment's
    /// "LOCK DISCIPLINE" section.
    pub async fn recipients(&self) -> Vec<NodeID> {
        self.entries.lock().await.keys().copied().collect()
    }

    /// Partition `recipient`'s queue as of `now`/`is_known`, removing the
    /// partitioned entries from the outbox:
    ///   - Entries older than `MAX_RETRY_AGE` -> returned in `.0`
    ///     ("expired"), regardless of `is_known`.
    ///   - Remaining entries, only if `is_known` is true -> returned in
    ///     `.1` ("retryable").
    ///   - Everything else stays queued for a future call.
    ///
    /// `is_known` is computed by the caller (a DHT lookup — see
    /// `run_retry_pass`) rather than inside this method, so this method
    /// stays pure in-memory bookkeeping and is directly unit-testable
    /// without a live DHT/server.
    async fn drain_due(
        &self,
        recipient: NodeID,
        now: u64,
        is_known: bool,
    ) -> (Vec<(Envelope, u64)>, Vec<(Envelope, u64)>) {
        let mut entries = self.entries.lock().await;
        let Some(queue) = entries.get_mut(&recipient) else {
            return (Vec::new(), Vec::new());
        };

        let mut expired = Vec::new();
        let mut retryable = Vec::new();
        let mut keep = VecDeque::new();

        while let Some(entry) = queue.pop_front() {
            let age = now.saturating_sub(entry.first_queued_at);
            if age >= MAX_RETRY_AGE.as_secs() {
                expired.push((entry.envelope, entry.first_queued_at));
            } else if is_known {
                retryable.push((entry.envelope, entry.first_queued_at));
            } else {
                keep.push_back(entry);
            }
        }

        if keep.is_empty() {
            entries.remove(&recipient);
        } else {
            *queue = keep;
        }

        (expired, retryable)
    }
}

impl Default for PendingOutbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn this as its own task (alongside `outbound::run_outbound_dispatch`
/// — see that module's wiring comment) to periodically retry everything
/// sitting in `outbox`. Runs until the process exits; there's no shutdown
/// signal, matching `run_outbound_dispatch`'s "runs until the channel
/// closes" lifecycle (this loop just doesn't have an equivalent close
/// condition, since the outbox itself doesn't get dropped while `server`
/// and `core` are alive).
pub async fn run_retry_loop<M, K>(
    server: Arc<PrimusNetworkServer<M, K>>,
    core: Arc<MessengerCore>,
    outbox: Arc<PendingOutbox>,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<(crate::envelope::MessageId, DeliveryResult)>>,
) where
    M: MessageIngress,
    K: KademliaHandler,
{
    log::info!(
        "PendingOutbox: retry loop started (interval {:?}, max age {:?}, cap {}/recipient)",
        RETRY_INTERVAL,
        MAX_RETRY_AGE,
        MAX_PENDING_PER_RECIPIENT,
    );
    let mut ticker = tokio::time::interval(RETRY_INTERVAL);
    // First tick fires immediately; skip it so we don't hammer the DHT on
    // startup before anything has had a chance to fail and get queued.
    ticker.tick().await;

    loop {
        ticker.tick().await;
        run_retry_pass(&server, &core, &outbox, event_tx.clone()).await;
    }
}

/// One retry pass over every recipient currently in `outbox`. Split out
/// from `run_retry_loop` so a test (or a caller that wants a one-shot
/// retry instead of the interval loop) can drive a single pass directly.
pub async fn run_retry_pass<M, K>(
    server: &Arc<PrimusNetworkServer<M, K>>,
    core: &Arc<MessengerCore>,
    outbox: &Arc<PendingOutbox>,
    event_tx: Option<tokio::sync::mpsc::UnboundedSender<(crate::envelope::MessageId, DeliveryResult)>>,
) where
    M: MessageIngress,
    K: KademliaHandler,
{
    let recipients = outbox.recipients().await;
    if recipients.is_empty() {
        return;
    }

    let now = unix_now();

    for recipient in recipients {
        // Gate on DHT visibility — see module doc comment for why this
        // isn't just an unconditional send_direct_message call.
        let closest = server.dht().find_closest(&recipient, 1).await;
        let is_known = closest.into_iter().any(|nr| nr.node_id() == recipient);

        let (expired, retryable) = outbox.drain_due(recipient, now, is_known).await;

        for (envelope, first_queued_at) in expired {
            log::warn!(
                "PendingOutbox: message {} to {} exceeded max retry age ({:?}, queued {}s ago), \
                 marking Failed permanently and giving up",
                hex_short(&envelope.message_id),
                hex_short(&recipient),
                MAX_RETRY_AGE,
                now.saturating_sub(first_queued_at),
            );
            core.mark_failed(&envelope.message_id).await;
        }

        for (envelope, first_queued_at) in retryable {
            let message_id = envelope.message_id;
            let result = delivery::send_direct_message(server, recipient, envelope.clone()).await;
            if let Some(tx) = &event_tx {
                let _ = tx.send((message_id, result.clone()));
            }
            match result {
                DeliveryResult::Failed => {
                    log::debug!(
                        "PendingOutbox: retry still failing for {} to {}, re-queued",
                        hex_short(&message_id),
                        hex_short(&recipient),
                    );
                    // Preserve the original timestamp — age accrues from
                    // the first failure, not from this retry attempt.
                    outbox
                        .push_with_timestamp(recipient, envelope, first_queued_at)
                        .await;
                }
                result => {
                    log::info!(
                        "PendingOutbox: retry succeeded for {} to {} ({:?})",
                        hex_short(&message_id),
                        hex_short(&recipient),
                        result,
                    );
                }
            }
        }
    }
}

fn unix_now() -> u64 {
    crate::unix_now()
}

fn hex_short(id: &[u8; 32]) -> String {
    crate::hex_short(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope(id: u8) -> Envelope {
        Envelope {
            message_id: [id; 32],
            sender_node_id: [0xAA; 32],
            recipient_node_id: [0xBB; 32],
            ciphertext: vec![1, 2, 3],
            sent_at: 0,
            kind: crate::envelope::MessageKind::DirectMessage,
        }
    }

    #[tokio::test]
    async fn push_and_len() {
        let outbox = PendingOutbox::new();
        outbox.push([1; 32], sample_envelope(1)).await;
        outbox.push([1; 32], sample_envelope(2)).await;
        outbox.push([2; 32], sample_envelope(3)).await;

        assert_eq!(outbox.len().await, 3);
        let mut recipients = outbox.recipients().await;
        recipients.sort();
        assert_eq!(recipients, vec![[1u8; 32], [2u8; 32]]);
    }

    #[tokio::test]
    async fn cap_evicts_oldest_for_that_recipient() {
        let outbox = PendingOutbox::new();
        for i in 0..MAX_PENDING_PER_RECIPIENT {
            outbox
                .push([9; 32], sample_envelope((i % 256) as u8))
                .await;
        }
        assert_eq!(outbox.len().await, MAX_PENDING_PER_RECIPIENT);

        // One more push should evict the oldest (message_id [0;32]) rather
        // than growing past the cap or refusing the new message.
        outbox.push([9; 32], sample_envelope(200)).await;
        assert_eq!(outbox.len().await, MAX_PENDING_PER_RECIPIENT);

        let (expired, retryable) = outbox.drain_due([9; 32], unix_now(), true).await;
        assert!(expired.is_empty());
        assert_eq!(retryable.len(), MAX_PENDING_PER_RECIPIENT);
        // The very first envelope pushed (id 0) should have been evicted.
        assert!(!retryable
            .iter()
            .any(|(env, _)| env.message_id == [0u8; 32]));
    }

    #[tokio::test]
    async fn drain_due_holds_back_unknown_recipients() {
        let outbox = PendingOutbox::new();
        outbox.push([3; 32], sample_envelope(1)).await;

        let (expired, retryable) = outbox.drain_due([3; 32], unix_now(), false).await;
        assert!(expired.is_empty());
        assert!(retryable.is_empty());
        // Still queued for a future tick.
        assert_eq!(outbox.len().await, 1);
    }

    #[tokio::test]
    async fn drain_due_returns_retryable_when_known() {
        let outbox = PendingOutbox::new();
        outbox.push([4; 32], sample_envelope(1)).await;

        let (expired, retryable) = outbox.drain_due([4; 32], unix_now(), true).await;
        assert!(expired.is_empty());
        assert_eq!(retryable.len(), 1);
        // Drained out of the outbox — caller is responsible for re-queuing
        // on a further failure.
        assert_eq!(outbox.len().await, 0);
    }

    #[tokio::test]
    async fn drain_due_expires_stale_entries_regardless_of_known() {
        let outbox = PendingOutbox::new();
        let ancient = unix_now().saturating_sub(MAX_RETRY_AGE.as_secs() + 10);
        outbox
            .push_with_timestamp([5; 32], sample_envelope(1), ancient)
            .await;

        // Even though the recipient is "known" this tick, the entry is
        // past MAX_RETRY_AGE and must be expired, not retried.
        let (expired, retryable) = outbox.drain_due([5; 32], unix_now(), true).await;
        assert_eq!(expired.len(), 1);
        assert!(retryable.is_empty());
        assert_eq!(outbox.len().await, 0);
    }

    #[tokio::test]
    async fn push_with_timestamp_preserves_age_across_requeue() {
        let outbox = PendingOutbox::new();
        let original_ts = unix_now() - 1000;
        outbox
            .push_with_timestamp([6; 32], sample_envelope(1), original_ts)
            .await;

        // Simulate a failed retry re-queuing with the original timestamp.
        let (_, retryable) = outbox.drain_due([6; 32], unix_now(), true).await;
        let (envelope, ts) = retryable.into_iter().next().unwrap();
        assert_eq!(ts, original_ts);
        outbox
            .push_with_timestamp([6; 32], envelope, ts)
            .await;

        // Age is still measured from original_ts, not from the requeue.
        let (expired, _) = outbox
            .drain_due([6; 32], original_ts + MAX_RETRY_AGE.as_secs() + 1, true)
            .await;
        assert_eq!(expired.len(), 1);
    }
}