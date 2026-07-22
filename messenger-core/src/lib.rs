// =============================================================================
// messenger-core — application layer for the primus messenger
//
// This is the first slice of messenger-core: `MessengerCore` implements
// `messenger::server::MessageIngress` so it can be handed to
// `PrimusNetworkServer::new()` in place of main.rs's current
// `LoggingIngress` stand-in.
//
// STORE: Arc<Mutex<HashMap<MessageId, StoredMessage>>>, in-memory only.
// GAP (flagged, not silently guessed around): no persistence yet. Every
// restart loses the store. That's the plan per the prompt — persistence is
// prompt 18 — but it means this must not be treated as durable in the
// meantime; don't wire delivery guarantees on top of it yet.
//
// on_envelope CONTRACT (per server.rs's MessageIngress trait + this prompt):
//   Ok(true)  — new message, deserialized and stored.
//   Ok(false) — well-formed envelope, but its `id` was already in the
//               store (application-level duplicate — see envelope.rs's
//               module doc comment on how this differs from the network
//               layer's relay dedup).
//   Err(_)    — bytes did not deserialize as `Envelope`. server.rs wraps
//               this in `.with_context(...)` and logs it; the gossip
//               stream handler for *this* peer's message returns early on
//               error but does not tear down the session or crash the
//               node — a malformed envelope from one peer must not take
//               the node down.
// =============================================================================

pub mod envelope;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Mutex;

use messenger::server::MessageIngress;

pub use envelope::{Envelope, MessageId, StoredMessage};

/// Application core: owns the in-memory message store and implements
/// `MessageIngress` so it can be plugged into `PrimusNetworkServer`.
pub struct MessengerCore {
    store: Arc<Mutex<HashMap<MessageId, StoredMessage>>>,
}

impl MessengerCore {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Look up a previously-ingested message by ID. Exposed for whatever
    /// reads the store next (a CLI, a future API layer, tests) — not used
    /// internally by `on_envelope` itself.
    pub async fn get(&self, id: &MessageId) -> Option<StoredMessage> {
        self.store.lock().await.get(id).cloned()
    }

    /// Number of messages currently held. Mainly for logging/tests.
    pub async fn len(&self) -> usize {
        self.store.lock().await.len()
    }
}

impl Default for MessengerCore {
    fn default() -> Self {
        Self::new()
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

        let mut store = self.store.lock().await;

        if store.contains_key(&envelope.id) {
            log::debug!(
                "MessengerCore: duplicate message {} dropped (already stored)",
                hex_short(&envelope.id)
            );
            return Ok(false);
        }

        let id = envelope.id;
        store.insert(id, StoredMessage { envelope });

        log::info!("MessengerCore: stored new message {}", hex_short(&id));
        Ok(true)
    }
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope(id: u8) -> Envelope {
        Envelope {
            id: [id; 32],
            sender: [0xAB; 32],
            timestamp: 0,
            payload: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn new_envelope_is_stored_and_returns_true() {
        let core = MessengerCore::new();
        let bytes = bincode::serialize(&sample_envelope(1)).unwrap();

        let result = core.on_envelope(&bytes).await.unwrap();

        assert!(result);
        assert_eq!(core.len().await, 1);
        assert!(core.get(&[1u8; 32]).await.is_some());
    }

    #[tokio::test]
    async fn duplicate_id_returns_false_and_does_not_overwrite() {
        let core = MessengerCore::new();
        let first = bincode::serialize(&sample_envelope(2)).unwrap();
        let mut second_env = sample_envelope(2);
        second_env.payload = vec![9, 9, 9]; // different content, same id
        let second = bincode::serialize(&second_env).unwrap();

        assert!(core.on_envelope(&first).await.unwrap());
        assert!(!core.on_envelope(&second).await.unwrap());

        assert_eq!(core.len().await, 1);
        // Original payload preserved — duplicate does not overwrite.
        let stored = core.get(&[2u8; 32]).await.unwrap();
        assert_eq!(stored.envelope.payload, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn malformed_bytes_return_err_not_panic() {
        let core = MessengerCore::new();
        let garbage = vec![0xFF, 0x00, 0x01, 0x02];

        let result = core.on_envelope(&garbage).await;

        assert!(result.is_err());
        assert_eq!(core.len().await, 0);
    }
}