// =============================================================================
// primus-net-opt/src/lib.rs
//
// STACK OVERFLOW FIXES (Windows STATUS_STACK_OVERFLOW — exit code 0xc00000fd):
//
//  FIX 1 — Arc<Box<[u8]>> for ml_dsa_sk
//  FIX 2 — find_node: heap-allocated state machine (loop + VecDeque + Box::pin)
//  FIX 3 — Arc<PrimusNR> inside routing table
//
//  See previous revision header for full explanation.
//
// ROUTING TABLE UNIFICATION:
//   The old lib.rs defined its own RoutingTable + KBucket. dht.rs had a
//   separate implementation. Both are now replaced by dht::RoutingTable.
//   KademliaEngine uses dht::RoutingTable directly via Arc.
// =============================================================================

use anyhow::{Context, Result, anyhow};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_util::codec::LengthDelimitedCodec;

pub mod bootstrap;
pub mod dht;
pub mod discovery;
pub mod nat;
pub mod network;
pub mod noise;
pub mod peer;
pub mod server;
pub mod transport;

pub use dht::{K as BUCKET_SIZE, NodeID, PrimusDHT, RoutingTable, xor_distance};
pub use noise::{BiStream, NOISE_PATTERN, NoiseStream};
pub use peer::PrimusNR;

pub const ALPHA: usize = 3;

// ── Kademlia Messages ─────────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum KademliaMsg {
    FindNodeRequest(NodeID),
    FindNodeResponse(Vec<PrimusNR>),
}

// ── KademliaEngine ────────────────────────────────────────────────────────────

pub struct KademliaEngine {
    local_id: NodeID,
    routing_table: Arc<RoutingTable>, // shared with PrimusDHT if needed
    rpc: Arc<KademliaRpc>,
    local_nr: Arc<PrimusNR>,
    noise_static: [u8; 32],
    ml_dsa_sk: Arc<Box<[u8]>>, // FIX 1
    #[allow(dead_code)]
    tls_domain: String,
}

impl KademliaEngine {
    pub fn new(local_nr: PrimusNR, endpoint: quinn::Endpoint, ml_dsa_sk: Vec<u8>, tls_domain: String) -> Arc<Self> {
        let local_id = local_nr.node_id();

        // Derive X25519 Noise static key as SHA3-256(ml_dsa_sk).
        // Consistent with server.rs — do NOT use the first 32 bytes of
        // public_key (that was a bug: ML-DSA key bytes ≠ X25519 key).
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(&ml_dsa_sk);
        let noise_static: [u8; 32] = h.finalize().into();

        let sk: Arc<Box<[u8]>> = Arc::new(ml_dsa_sk.into_boxed_slice());
        let local_nr = Arc::new(local_nr);

        // RoutingTable from dht.rs — unified implementation.
        let routing_table = Arc::new(RoutingTable::new(local_id));

        Arc::new(Self {
            local_id,
            routing_table: Arc::clone(&routing_table),
            rpc: Arc::new(KademliaRpc::new(
                endpoint,
                Arc::clone(&local_nr),
                noise_static,
                Arc::clone(&sk),
                tls_domain.clone(),
            )),
            local_nr,
            noise_static,
            ml_dsa_sk: sk,
            tls_domain,
        })
    }

    // ── FIX 2: Iterative lookup — heap-allocated state machine ────────────────

    pub async fn find_node(self: Arc<Self>, target: NodeID) -> Vec<PrimusNR> {
        let seed = self
            .routing_table
            .get_closest_arc(target, BUCKET_SIZE)
            .await;

        let mut queue: VecDeque<Arc<PrimusNR>> = seed.into_iter().collect();
        let mut closest: Vec<Arc<PrimusNR>> = Vec::with_capacity(BUCKET_SIZE);
        let mut visited: HashSet<NodeID> = HashSet::new();
        visited.insert(self.local_id);

        loop {
            let mut batch: Vec<Arc<PrimusNR>> = Vec::with_capacity(ALPHA);
            for node in queue.iter() {
                if batch.len() >= ALPHA {
                    break;
                }
                let id = node.node_id();
                if !visited.contains(&id) {
                    batch.push(Arc::clone(node));
                }
            }

            if batch.is_empty() {
                break;
            }

            type PinnedFut =
            std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<PrimusNR>>> + Send>>;
            let mut futs: Vec<PinnedFut> = Vec::with_capacity(batch.len());

            for node in &batch {
                let node_id = node.node_id();
                let addr = node.addr();
                let self_c = Arc::clone(&self);
                visited.insert(node_id);

                // FIX 2: Box::pin moves the future state to the heap.
                futs.push(Box::pin(async move {
                    let res = self_c.rpc.send_find_node(addr, target).await;
                    if res.is_err() {
                        self_c.mark_failed(&node_id).await;
                    }
                    res
                }));
            }

            let results = futures::future::join_all(futs).await;
            let mut found = false;

            for nodes in results.into_iter().flatten() {
                for n in nodes {
                    let id = n.node_id();
                    // Register newly discovered peer in our routing table.
                    self.handle_new_peer(n.clone()).await;

                    if !visited.contains(&id) {
                        queue.push_back(Arc::new(n));
                        found = true;
                    }
                }
            }

            if !found {
                break;
            }

            closest.extend(queue.iter().cloned());
            closest.sort_unstable_by(|a, b| {
                xor_distance(&a.node_id(), &target).cmp(&xor_distance(&b.node_id(), &target))
            });
            closest.dedup_by_key(|n| n.node_id());
            closest.truncate(BUCKET_SIZE);

            queue = closest
                .iter()
                .filter(|n| !visited.contains(&n.node_id()))
                .cloned()
                .collect();

            if queue.is_empty() {
                break;
            }
        }

        // Single clone of key bytes — only at return time.
        closest.into_iter().map(|arc| (*arc).clone()).collect()
    }

    pub async fn handle_new_peer(&self, nr: PrimusNR) {
        // Hot path: called once per node returned from every find_node RPC
        // response inside the lookup loop. ML-DSA-87 verify is CPU-heavy and
        // stack-hungry, so it goes through spawn_blocking rather than running
        // inline on the async executor thread. The blocking-pool thread now
        // carries the enlarged stack from tokio::runtime::Builder's
        // thread_stack_size(16 MiB) config (see main.rs), so no per-call
        // std::thread::Builder is needed here.
        let nr_c = nr.clone();
        let verified = tokio::task::spawn_blocking(move || nr_c.verify())
            .await
            .unwrap_or(false);

        if verified {
            self.routing_table.insert(nr, self).await;
        }
    }

    pub async fn mark_failed(&self, id: &NodeID) {
        self.routing_table.remove(id).await;
    }

    pub fn start_maintenance(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let mut random_id = [0u8; 32];
                rand::thread_rng().fill(&mut random_id);
                let _ = self.clone().find_node(random_id).await;
            }
        });
    }

    pub async fn handle_rpc<S, R>(&self, send: S, recv: R) -> Result<()>
    where
        S: tokio::io::AsyncWrite + Unpin,
        R: tokio::io::AsyncRead + Unpin,
    {
        let bi = BiStream {
            reader: recv,
            writer: send,
        };
        // handshake_responder now also hands back the verified peer NR
        // (see noise.rs / transport.rs). Not consumed here: KademliaEngine
        // already registers peers via handle_new_peer() for every node
        // returned in a FindNodeResponse, so re-inserting the RPC caller's
        // own NR here would just be redundant work on this path.
        let (noise, _peer_nr) = NoiseStream::handshake_responder(
            bi,
            &self.noise_static,
            &self.local_nr,
            &self.ml_dsa_sk,
        )
            .await?;

        // Use LengthDelimitedCodec for bounded message framing (16 MiB limit).
        let mut framed = tokio_util::codec::FramedRead::new(
            noise,
            LengthDelimitedCodec::builder()
                .max_frame_length(16 * 1024 * 1024)
                .new_codec(),
        );

        let bytes = framed
            .next()
            .await
            .context("Kademlia RPC: stream closed")?
            .map_err(|e| anyhow!("Kademlia RPC: frame size limit exceeded or IO error: {}", e))?;

        let msg: KademliaMsg = bincode::deserialize(&bytes)
            .map_err(|e| anyhow!("KademliaMsg deserialization failed: {}", e))?;

        match msg {
            KademliaMsg::FindNodeRequest(target) => {
                let closest = self.routing_table.get_closest(target, BUCKET_SIZE).await;
                let resp = KademliaMsg::FindNodeResponse(closest);
                let resp_bytes = bincode::serialize(&resp)
                    .map_err(|e| anyhow!("KademliaMsg serialization failed: {}", e))?;

                let mut writer = tokio_util::codec::FramedWrite::new(
                    framed.into_inner(),
                    LengthDelimitedCodec::builder()
                        .max_frame_length(16 * 1024 * 1024)
                        .new_codec(),
                );

                writer
                    .send(resp_bytes.into())
                    .await
                    .context("Kademlia RPC: failed to send response")?;
                writer.flush().await?;
            }
            _ => return Err(anyhow!("Unexpected RPC message type")),
        }
        Ok(())
    }
}

// ── KademliaRpc ───────────────────────────────────────────────────────────────

pub struct KademliaRpc {
    endpoint: quinn::Endpoint,
    local_nr: Arc<PrimusNR>,
    noise_static: [u8; 32],
    ml_dsa_sk: Arc<Box<[u8]>>,
    tls_domain: String,
}

impl KademliaRpc {
    pub fn new(
        endpoint: quinn::Endpoint,
        local_nr: Arc<PrimusNR>,
        noise_static: [u8; 32],
        ml_dsa_sk: Arc<Box<[u8]>>,
        tls_domain: String,
    ) -> Self {
        Self {
            endpoint,
            local_nr,
            noise_static,
            ml_dsa_sk,
            tls_domain,
        }
    }

    pub async fn send_find_node(&self, addr: SocketAddr, target: NodeID) -> Result<Vec<PrimusNR>> {
        let connection = self.endpoint.connect(addr, &self.tls_domain)?.await?;
        let (send, recv) = connection.open_bi().await?;
        let bi = BiStream {
            reader: recv,
            writer: send,
        };

        // See the matching comment in handle_rpc above — peer NR discarded
        // here for the same reason.
        let (noise, _peer_nr) = NoiseStream::handshake_initiator(
            bi,
            &self.noise_static,
            &self.local_nr,
            &self.ml_dsa_sk,
        )
            .await?;

        let req = KademliaMsg::FindNodeRequest(target);
        let bytes = bincode::serialize(&req)
            .map_err(|e| anyhow!("KademliaMsg serialization failed: {}", e))?;

        let mut writer = tokio_util::codec::FramedWrite::new(
            noise,
            LengthDelimitedCodec::builder()
                .max_frame_length(16 * 1024 * 1024)
                .new_codec(),
        );

        writer
            .send(bytes.into())
            .await
            .context("Kademlia RPC: failed to send request")?;
        writer.flush().await?;

        let mut reader = tokio_util::codec::FramedRead::new(
            writer.into_inner(),
            LengthDelimitedCodec::builder()
                .max_frame_length(16 * 1024 * 1024)
                .new_codec(),
        );

        let resp_bytes = reader
            .next()
            .await
            .context("Kademlia RPC: no response")?
            .map_err(|e| anyhow!("Kademlia RPC: response too large or IO error: {}", e))?;

        match bincode::deserialize::<KademliaMsg>(&resp_bytes)
            .map_err(|e| anyhow!("KademliaMsg deserialization failed: {}", e))?
        {
            KademliaMsg::FindNodeResponse(nodes) => Ok(nodes),
            _ => Err(anyhow!("Unexpected response type")),
        }
    }
}

// ── KademliaHandler impl ─────────────────────────────────────────────────────
//
// Lives here (inside the `messenger` library crate) rather than in main.rs.
// main.rs is a *separate* crate from lib.rs even though they share one
// Cargo package — implementing a trait defined in `server` (foreign to a
// binary crate) for a type also foreign to that binary crate hits the
// orphan rule (E0117). Both KademliaHandler (server.rs) and KademliaEngine
// (this file) live inside the `messenger` crate, so the impl belongs here.
#[async_trait::async_trait]
impl crate::server::KademliaHandler for KademliaEngine {
    fn start_maintenance(self: Arc<Self>) {
        KademliaEngine::start_maintenance(self)
    }

    // CHANGED: server.rs's KademliaHandler trait now takes boxed dyn
    // AsyncWrite/AsyncRead instead of concrete quinn types — needed so the
    // bi-stream accept loop can peek a STREAM_TYPE_CONTROL discriminant
    // byte and still hand this a stream with that byte replayed
    // (PrefixedReader, in server.rs) rather than a real quinn::RecvStream.
    // KademliaEngine::handle_rpc below was already generic over
    // AsyncRead/AsyncWrite, so this is just a type change at the boundary.
    async fn handle_rpc(
        &self,
        send: Box<dyn tokio::io::AsyncWrite + Send + Unpin>,
        recv: Box<dyn tokio::io::AsyncRead + Send + Unpin>,
    ) -> Result<()> {
        KademliaEngine::handle_rpc(self, send, recv).await
    }
}

#[async_trait::async_trait]
impl crate::dht::NodePinger for KademliaEngine {
    async fn ping(&self, nr: &PrimusNR) -> bool {
        // Standard Kademlia ping: send a FIND_NODE(self_id).
        // INVARIANT: Use a strict 5s timeout to prevent blocking the maintenance loop.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.rpc.send_find_node(nr.addr(), self.local_id),
        )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false)
    }
}