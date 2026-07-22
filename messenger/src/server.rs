// =============================================================================
// primus-net-opt/src/server.rs — P2P Network Server
//
// MIGRATION: Moved from primus-core/src/net/mod.rs.
// primus-core has no business owning QUIC sockets, WebTransport listeners,
// or connection dispatch loops. This module owns all of that.
//
// ARCHITECTURE:
//   PrimusNetworkServer — binds QUIC + WebTransport, dispatches connections
//   PeerSession         — per-connection state: Noise stateless transport +
//                         per-direction recv nonce counter (fixes nonce=0 bug)
//   handle_native_connection  — QUIC connection handler
//   handle_web_connection     — WebTransport connection handler
//   handle_gossip_stream      — uni-stream gossip ingress → MessageIngress
//
// NONCE BUG FIX:
//   The original code called session.read_message(0, ...) with a hardcoded
//   nonce of 0 on every gossip uni-stream. In Noise stateless transport mode,
//   reusing nonce 0 on every message is a catastrophic security failure:
//   an attacker who captures two ciphertexts encrypted under the same
//   (key, nonce) pair can XOR them to cancel the keystream and recover
//   the XOR of the two plaintexts.
//
//   Fix: each PeerSession carries an Arc<AtomicU64> recv_nonce that is
//   incremented after every successfully decrypted message. The sender
//   must use a matching counter — convention: uni-stream N uses nonce N.
//   This is safe because QUIC stream IDs are monotonically increasing and
//   uni-streams are unidirectional, so there is no nonce collision between
//   send and receive directions.
//
// GOSSIP PAYLOAD LIMIT: 16 MiB per stream.
// QUIC / WebTransport TLS: self-signed cert for now. Production nodes should
//   supply a CA-signed cert via a config path passed to new().
// =============================================================================

use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use futures::StreamExt;
use quinn::{Connection, Endpoint, ServerConfig};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashSet, VecDeque};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::codec::LengthDelimitedCodec;
use wtransport::Identity;

use crate::peer::PrimusNR;

use crate::dht::{NodePinger, PrimusDHT};
use crate::noise::BiStream;
use crate::transport::{handle_inbound, handle_outbound, listeners::WebTransportListener};

// ── Protocol constants ────────────────────────────────────────────────────────

/// Default P2P QUIC port.
pub const P2P_PORT: u16 = 9000;

/// Gossip uni-stream type discriminant (first byte of the 8-byte header).
pub const STREAM_TYPE_GOSSIP: u8 = 0x01;

/// Control bi-stream type discriminant.
pub const STREAM_TYPE_CONTROL: u8 = 0x02;

/// Maximum gossip payload size in bytes. Payloads larger than this are
/// rejected before decryption to prevent memory exhaustion.
const MAX_GOSSIP_PAYLOAD: usize = 16 * 1024 * 1024; // 16 MiB

/// Maximum control payload size in bytes. Control messages (Ping/Pong,
/// GetPeers/PeersResponse) are small and bounded — a generous 64 KiB still
/// catches a malicious/broken peer trying to make us allocate something
/// huge before we've even deserialized the message.
const MAX_CONTROL_PAYLOAD: usize = 64 * 1024; // 64 KiB

// ── Control protocol ─────────────────────────────────────────────────────────

/// Messages exchanged over a `STREAM_TYPE_CONTROL` bi-stream.
///
/// Replaces the deleted TCP control messages (Ping/Pong/GetPeers/
/// PeersResponse — see network.rs's module header for what was removed).
/// One control RPC = one freshly-opened bi-stream: the initiator writes a
/// request and reads the response off the same stream, mirroring the
/// existing Kademlia RPC convention (`KademliaRpc::send_find_node` in
/// lib.rs) rather than keeping a long-lived control channel open. Simpler
/// to reason about at the cost of one extra QUIC stream-open per call.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ControlMsg {
    /// Liveness check. Expect a `Pong` back. Used by `SessionPinger`/
    /// `PrimusNetworkServer`'s `NodePinger` impl for `RoutingTable::insert`'s
    /// bucket-eviction check (dht.rs).
    Ping,
    Pong,
    /// Ask a peer for the addresses of the sessions it currently holds, to
    /// expand beyond configured seeds during bootstrap (see
    /// `PrimusNetworkServer::get_peers` below).
    GetPeers,
    PeersResponse(Vec<SocketAddr>),
}

// ── Application ingress abstraction ─────────────────────────────────────────

/// Trait abstracting the application layer so the server does not depend
/// directly on any concrete message store or state machine. `messenger-core`
/// implements this on whatever handle it wants (message store, delivery
/// queue, etc.) and passes it to `PrimusNetworkServer::new()`.
#[async_trait::async_trait]
pub trait MessageIngress: Send + Sync + 'static {
    /// Ingest a decrypted application envelope received over a gossip
    /// uni-stream. Returns `Ok(true)` if the envelope was new/accepted.
    async fn on_envelope(&self, bytes: &[u8]) -> anyhow::Result<bool>;
}

// ── KademliaEngine abstraction ────────────────────────────────────────────────

/// Trait abstracting the Kademlia RPC handler so primus-net-opt does not
/// hard-depend on a specific KademliaEngine implementation. primus-core
/// (or a future primus-net-opt Kademlia impl) provides a concrete type.
#[async_trait::async_trait]
pub trait KademliaHandler: Send + Sync + 'static {
    fn start_maintenance(self: Arc<Self>);

    /// `send`/`recv` are boxed rather than concrete `quinn::SendStream` /
    /// `quinn::RecvStream` — CHANGED from the original concrete-typed
    /// signature (see below) so that a bi-stream whose discriminant byte
    /// has already been peeked and re-prepended (`PrefixedReader`, added
    /// alongside the control protocol below) can still be handed off here.
    /// `KademliaEngine::handle_rpc` in lib.rs was already generic over
    /// `AsyncRead`/`AsyncWrite`; only this trait boundary was pinned to
    /// quinn's concrete types.
    async fn handle_rpc(
        &self,
        send: Box<dyn AsyncWrite + Send + Unpin>,
        recv: Box<dyn AsyncRead + Send + Unpin>,
    ) -> Result<()>;
}

pub enum PrimusConnection {
    Quic(quinn::Connection),
    Web(Arc<wtransport::Connection>),
}

/// Per-connection session state shared across stream handlers.
///
/// `recv_nonce` is incremented atomically after each successfully decrypted
/// gossip message. This fixes the nonce=0 bug — see module header.
pub struct PeerSession {
    pub conn: PrimusConnection,
    pub noise: snow::StatelessTransportState,
    pub recv_nonce: AtomicU64,
    pub send_nonce: AtomicU64,
    /// Limit concurrent streams from this peer to prevent task flooding.
    pub stream_semaphore: Arc<Semaphore>,
}

impl PeerSession {
    pub fn new(conn: PrimusConnection, noise: snow::StatelessTransportState) -> Self {
        Self {
            conn,
            noise,
            recv_nonce: AtomicU64::new(0),
            send_nonce: AtomicU64::new(0),
            // Max 100 concurrent streams per connection.
            stream_semaphore: Arc::new(Semaphore::new(100)),
        }
    }

    /// Decrypt `ciphertext` using the next available nonce.
    ///
    /// Returns the decrypted plaintext on success. The nonce counter is
    /// incremented even on failure (to stay in sync with the sender's
    /// counter) so callers should close the connection on error.
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.recv_nonce.fetch_add(1, Ordering::AcqRel);
        let mut plaintext = vec![0u8; ciphertext.len()];
        let n = self
            .noise
            .read_message(nonce, ciphertext, &mut plaintext)
            .map_err(|e| anyhow!("Noise decryption failed (nonce={}): {}", nonce, e))?;
        plaintext.truncate(n);
        Ok(plaintext)
    }

    /// Encrypt `payload` using the next available send nonce.
    ///
    /// Shared by `send_uni_framed` (gossip) and `send_control` (control
    /// request/response) — previously this logic was inlined only in
    /// `send_gossip`.
    ///
    /// NONCE-ORDERING CAVEAT (pre-existing, now shared by control traffic
    /// too): `send_nonce`/`recv_nonce` are single shared counters per
    /// session across every uni- and bi-stream this session sends/receives.
    /// The counter fixes the nonce=0 reuse bug (see module header), but it
    /// does NOT guarantee delivery order matches encryption order — QUIC
    /// only orders bytes *within* one stream, not across concurrently-open
    /// streams. If two frames from the same session (e.g. two gossip
    /// relays, or a gossip send racing a control request) are in flight at
    /// once and arrive out of the order they were encrypted in, the
    /// receiver's `decrypt()` will pull the wrong nonce for a given
    /// ciphertext and fail. Not introduced by the control protocol, but
    /// worth flagging now that a second traffic class shares the counter.
    fn encrypt(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.send_nonce.fetch_add(1, Ordering::AcqRel);
        let mut ciphertext = vec![0u8; payload.len() + 16]; // Poly1305 MAC adds 16 bytes
        let n = self
            .noise
            .write_message(nonce, payload, &mut ciphertext)
            .map_err(|e| anyhow!("Noise encryption failed (nonce={}): {}", nonce, e))?;
        ciphertext.truncate(n);
        Ok(ciphertext)
    }

    /// Build the shared 8-byte frame header: `[type][flags][len: u32 BE][pad × 2]`.
    fn build_header(stream_type: u8, len: usize) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[0] = stream_type;
        header[2..6].copy_from_slice(&(len as u32).to_be_bytes());
        header
    }

    /// Encrypt and send `payload` over a new uni-stream, tagged with
    /// `stream_type` in the frame header.
    ///
    /// GENERALIZED from the gossip-only version of this method (it took no
    /// stream-type parameter and hardcoded `STREAM_TYPE_GOSSIP`) so
    /// fire-and-forget control frames could reuse the same framing/
    /// encryption path — in practice `send_control` below needs a
    /// request/response round trip and uses a bi-stream instead, so this is
    /// currently gossip's only caller, but the parameter keeps the two
    /// paths from silently diverging if a future fire-and-forget control
    /// message shows up.
    pub async fn send_uni_framed(&self, stream_type: u8, payload: &[u8]) -> Result<()> {
        let ciphertext = self.encrypt(payload)?;
        let header = Self::build_header(stream_type, ciphertext.len());

        match &self.conn {
            PrimusConnection::Quic(conn) => {
                let mut send = conn.open_uni().await?;
                send.write_all(&header).await?;
                send.write_all(&ciphertext).await?;
                let _ = send.finish();
            }
            PrimusConnection::Web(conn) => {
                let mut send = conn.open_uni().await?.await?;
                send.write_all(&header).await?;
                send.write_all(&ciphertext).await?;
                send.finish().await?;
            }
        }
        Ok(())
    }

    /// Encrypt and send a gossip message over a new uni-stream.
    pub async fn send_gossip(&self, payload: &[u8]) -> Result<()> {
        // SECURITY: Encrypt outbound gossip to prevent plaintext exposure over QUIC
        // uni-streams. The Noise protocol is symmetric, but previously we only
        // decrypted inbound.
        self.send_uni_framed(STREAM_TYPE_GOSSIP, payload).await
    }

    /// Send a `ControlMsg` request over a fresh bi-stream and wait for the
    /// framed, encrypted response on the same stream.
    ///
    /// One call = one bi-stream (opened and torn down per request) — see
    /// the `ControlMsg` doc comment for why. The response is expected to
    /// arrive as a single frame; a peer that never answers is bounded by
    /// whatever timeout the caller wraps this in (`SessionPinger::ping`
    /// below uses a 5s timeout).
    pub async fn send_control(&self, msg: &ControlMsg) -> Result<ControlMsg> {
        let payload = bincode::serialize(msg)
            .map_err(|e| anyhow!("ControlMsg serialization failed: {}", e))?;
        let ciphertext = self.encrypt(&payload)?;
        let header = Self::build_header(STREAM_TYPE_CONTROL, ciphertext.len());

        let resp_ciphertext = match &self.conn {
            PrimusConnection::Quic(conn) => {
                let (mut send, recv) = conn
                    .open_bi()
                    .await
                    .context("Control: failed to open bi-stream")?;
                send.write_all(&header).await?;
                send.write_all(&ciphertext).await?;
                let _ = send.finish();
                read_control_response(recv).await?
            }
            PrimusConnection::Web(conn) => {
                let (mut send, recv) = conn
                    .open_bi()
                    .await
                    .context("Control: failed to open WebTransport bi-stream")?
                    .await
                    .context("Control: WebTransport bi-stream open failed")?;
                send.write_all(&header).await?;
                send.write_all(&ciphertext).await?;
                let _ = send.finish().await;
                read_control_response(recv).await?
            }
        };

        let plaintext = self.decrypt(&resp_ciphertext)?;
        bincode::deserialize(&plaintext)
            .map_err(|e| anyhow!("ControlMsg response deserialization failed: {}", e))
    }
}

/// Read a single `[type][flags][len: u32 BE][pad × 2]` + ciphertext frame
/// off a control bi-stream's response half and return the raw ciphertext
/// (header stripped). Shared by both `send_control` (initiator side, reads
/// the response) and `handle_control_stream` (accept side, reads the
/// request) — see the latter for the request-side counterpart.
async fn read_control_response<R>(mut recv: R) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    recv.read_exact(&mut header)
        .await
        .context("Control: stream closed before response header")?;

    if header[0] != STREAM_TYPE_CONTROL {
        return Err(anyhow!(
            "Control: response carried unexpected stream type 0x{:02x} (expected 0x{:02x})",
            header[0],
            STREAM_TYPE_CONTROL
        ));
    }

    let len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
    if len > MAX_CONTROL_PAYLOAD {
        return Err(anyhow!(
            "Control: response payload exceeds max size ({} > {})",
            len,
            MAX_CONTROL_PAYLOAD
        ));
    }

    let mut ciphertext = vec![0u8; len];
    recv.read_exact(&mut ciphertext)
        .await
        .context("Control: stream closed before response payload")?;
    Ok(ciphertext)
}

// ── DHT liveness pinger ───────────────────────────────────────────────────────

/// `NodePinger` backed by the session table, for `RoutingTable::insert`'s
/// bucket-eviction check (dht.rs) when a k-bucket is full.
///
/// `ping()` now does a real Ping/Pong round trip over a `STREAM_TYPE_CONTROL`
/// bi-stream instead of only inspecting the connection's own closed-state —
/// the previous version answered "do we still have an open connection to
/// this address", not "did this peer just answer a ping", so a session that
/// was open but wedged (peer vanished before the QUIC idle timeout fired)
/// was reported alive. A 5s timeout bounds how long an unresponsive peer
/// can hold up a bucket-eviction decision.
pub struct SessionPinger {
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
}

impl SessionPinger {
    pub fn new(sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>) -> Self {
        Self { sessions }
    }
}

#[async_trait::async_trait]
impl NodePinger for SessionPinger {
    async fn ping(&self, nr: &PrimusNR) -> bool {
        let Some(session) = self.sessions.get(&nr.addr()).map(|entry| entry.value().clone())
        else {
            // No open session for this address — nothing to vouch for it.
            return false;
        };

        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            session.send_control(&ControlMsg::Ping),
        )
            .await
        {
            Ok(Ok(ControlMsg::Pong)) => true,
            Ok(Ok(other)) => {
                log::warn!(
                    "Control: ping to {} got an unexpected response variant: {:?}",
                    nr.addr(),
                    other
                );
                false
            }
            Ok(Err(e)) => {
                log::debug!("Control: ping to {} failed: {}", nr.addr(), e);
                false
            }
            Err(_) => {
                log::debug!("Control: ping to {} timed out", nr.addr());
                false
            }
        }
    }
}

// ── Gossip Relay ───────────────────────────────────────────────────────────

/// Upper bound on the number of message ids the seen-set remembers.
/// Once the cap is hit, the oldest entry (by insertion order, tracked
/// separately in `SeenSet::order` — HashSet iteration order is arbitrary
/// and must never be used for eviction) is evicted to make room.
const MAX_SEEN_MESSAGES: usize = 10_000;

/// Bounded, insertion-ordered set of dedup ids. `ids` gives O(1) membership
/// checks; `order` is the FIFO queue that tells us which id to evict next.
/// The two are always kept in sync.
struct SeenSet {
    ids: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl SeenSet {
    fn new() -> Self {
        Self {
            ids: HashSet::with_capacity(MAX_SEEN_MESSAGES),
            order: VecDeque::with_capacity(MAX_SEEN_MESSAGES),
        }
    }

    /// Records `id` if it hasn't been seen before. Returns `true` if this
    /// was the first sighting (caller should process/relay), `false` if
    /// `id` is a duplicate (caller should drop it).
    fn insert_if_new(&mut self, id: [u8; 32]) -> bool {
        if !self.ids.insert(id) {
            return false;
        }

        // Evict oldest by insertion order, not HashSet iteration order.
        self.order.push_back(id);
        if self.order.len() > MAX_SEEN_MESSAGES {
            if let Some(oldest) = self.order.pop_front() {
                self.ids.remove(&oldest);
            }
        }

        true
    }
}

/// Dedup id for a gossip envelope: SHA3-256 of the payload data bytes
/// ONLY. The TTL field must never be part of this hash — TTL is
/// decremented on every hop, so hashing it in would make the same message
/// content compute a different id at each hop and defeat deduplication
/// entirely.
fn envelope_dedup_id(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Re-broadcasts received gossip envelopes to other currently-held peer
/// sessions, decrementing TTL by one hop. Relay is session-local: it only
/// fans out to peers we currently have an open QUIC/WebTransport session
/// with (the `sessions` table) — it does NOT consult the DHT for a wider
/// broadcast. Wiring it into both `handle_native_connection` and
/// `handle_web_connection` keeps QUIC and WebTransport peers on the same
/// relay path.
pub struct GossipRelay {
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    /// Bounded cache of recently-seen message ids, used to stop a gossip
    /// message from bouncing indefinitely between peers whose session sets
    /// overlap (previously bounded only by TTL reaching 0).
    seen: Mutex<SeenSet>,
}

impl GossipRelay {
    pub fn new(sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>) -> Self {
        Self {
            sessions,
            seen: Mutex::new(SeenSet::new()),
        }
    }

    /// Checks `data` against the seen-set and records it if new.
    ///
    /// Returns `true` the first time a given envelope's data is observed
    /// (caller should ingest and relay it), and `false` on every
    /// subsequent sighting of the same data, regardless of TTL (caller
    /// should drop it). Must be called — and its result respected — before
    /// both `ingress.on_envelope` and `relay()` for a given envelope.
    pub async fn is_new(&self, data: &[u8]) -> bool {
        let id = envelope_dedup_id(data);
        let mut seen = self.seen.lock().await;
        seen.insert_if_new(id)
    }

    /// Relay `data` to every session we currently hold except `from`, with
    /// `ttl` decremented by one hop. No-op if `ttl` is already 0 — that
    /// means this message arrived at its last hop and must not propagate
    /// further.
    pub async fn relay(&self, data: &[u8], ttl: u8, from: SocketAddr) {
        if ttl == 0 {
            return;
        }
        let new_ttl = ttl - 1;

        let message = crate::network::PrimusMessage::Envelope(data.to_vec(), new_ttl);
        let payload = match bincode::serialize(&message) {
            Ok(b) => b,
            Err(e) => {
                log::warn!("Gossip relay: envelope serialization failed: {}", e);
                return;
            }
        };

        // Snapshot the target set before spawning sends, so a peer that
        // disconnects mid-fan-out just fails its own send rather than
        // affecting the others.
        let targets: Vec<(SocketAddr, Arc<PeerSession>)> = self
            .sessions
            .iter()
            .filter(|entry| *entry.key() != from)
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();

        for (peer_addr, session) in targets {
            let payload = payload.clone();
            tokio::spawn(async move {
                if let Err(e) = session.send_gossip(&payload).await {
                    log::debug!("Gossip relay: send to {} failed: {}", peer_addr, e);
                }
            });
        }
    }
}

// ── PrimusNetworkServer ───────────────────────────────────────────────────────

/// The unified P2P network server for Obsidian Nexus.
///
/// Owns two transports:
///   - QUIC (`quinn`) for native node-to-node traffic
///   - WebTransport (`wtransport`) for browser/WASM leaf clients
///
/// Both transports perform a mandatory Noise_XX_25519_ChaChaPoly_SHA256
/// handshake with ML-DSA-87 identity binding before any application data
/// is exchanged.
pub struct PrimusNetworkServer<M, K> {
    endpoint: Endpoint,
    wt_listener: Option<WebTransportListener>,
    ingress: Arc<M>,
    kademlia: Arc<K>,
    dht: PrimusDHT,
    local_nr: PrimusNR,
    noise_static: [u8; 32],
    ml_dsa_sk: Vec<u8>,
    /// TLS SNI domain used both for our own self-signed cert and as the
    /// `server_name` argument when dialing out via `endpoint.connect()`.
    tls_domain: String,
    /// External (NAT-mapped) address reported by `nat::NatService::open_world`,
    /// if UPnP mapping has succeeded. Used by `connect_to_peer` for
    /// self-connection avoidance — a peer discovered (e.g. via LAN beacon
    /// relay or a DHT record populated before we knew our own external
    /// address) may report back our own mapped address.
    external_addr: Arc<Mutex<Option<SocketAddr>>>,
    /// Active session table: remote SocketAddr → PeerSession.
    /// DashMap gives lock-free concurrent reads across stream handlers.
    pub sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    pub frame_drops: Arc<AtomicU64>,
    pub relay: Arc<GossipRelay>,
}

impl<M, K> PrimusNetworkServer<M, K>
where
    M: MessageIngress,
    K: KademliaHandler,
{
    /// Construct and bind the server.
    ///
    /// # Arguments
    ///
    /// * `addr`       — QUIC listen address. WebTransport binds to `addr.port() + 1`.
    /// * `ingress`    — Shared ingress handle implementing `MessageIngress`.
    /// * `kademlia`   — Kademlia RPC handler.
    /// * `local_nr`   — This node's signed Node Record (used in Noise handshake).
    /// * `ml_dsa_sk`  — ML-DSA-87 signing key (4896 bytes). Used for handshake
    ///   identity binding AND to derive the Noise X25519 static key.
    ///
    /// # Noise static key derivation
    ///
    /// The X25519 static key is SHA3-256(ml_dsa_sk), giving a deterministic
    /// 32-byte value without requiring a separate key-management path.
    /// This is safe because SHA3-256 is a one-way function — the Noise key
    /// cannot be used to recover the ML-DSA signing key.
    pub async fn new(
        addr: SocketAddr,
        ingress: Arc<M>,
        kademlia: Arc<K>,
        local_nr: PrimusNR,
        ml_dsa_sk: Vec<u8>,
        tls_domain: String,
    ) -> Result<Self> {
        // ── QUIC endpoint ─────────────────────────────────────────────────────
        let (cert, key) = generate_self_signed_cert(&tls_domain)?;
        let server_config = ServerConfig::with_single_cert(vec![cert], key)
            .context("Failed to build QUIC ServerConfig")?;
        let endpoint =
            Endpoint::server(server_config, addr).context("Failed to bind QUIC endpoint")?;

        // ── Noise X25519 static key ───────────────────────────────────────────
        let mut hasher = Sha3_256::new();
        hasher.update(&ml_dsa_sk);
        let noise_static: [u8; 32] = hasher.finalize().into();

        // ── DHT (uses local peer::PrimusNR) ────────────────────────────────────
        let dht = PrimusDHT::new(&local_nr);

        // ── WebTransport listener ─────────────────────────────────────────────
        let wt_addr = SocketAddr::new(addr.ip(), addr.port() + 1);
        let wt_listener = match Identity::self_signed([tls_domain.clone()]) {
            Ok(identity) => WebTransportListener::bind(wt_addr, identity).await.ok(),
            Err(e) => {
                log::warn!(
                    "WebTransport identity creation failed, disabling WT listener: {}",
                    e
                );
                None
            }
        };

        let sessions = Arc::new(DashMap::new());
        let relay = Arc::new(GossipRelay::new(sessions.clone()));

        Ok(Self {
            endpoint,
            wt_listener,
            ingress,
            kademlia,
            dht,
            local_nr,
            noise_static,
            ml_dsa_sk,
            tls_domain,
            external_addr: Arc::new(Mutex::new(None)),
            sessions,
            frame_drops: Arc::new(AtomicU64::new(0)),
            relay,
        })
    }

    /// Record the external (NAT-mapped) address returned by
    /// `nat::NatService::open_world`, for use in `connect_to_peer`'s
    /// self-connection check. `open_world` only returns the external IP;
    /// callers should pass `SocketAddr::new(external_ip, bound_port)` since
    /// UPnP `add_port` maps the external port equal to the internal port
    /// (see nat.rs).
    pub async fn set_external_addr(&self, addr: SocketAddr) {
        *self.external_addr.lock().await = Some(addr);
    }

    /// Start serving. Spawns two accept loops (QUIC + WebTransport) and
    /// returns only on unrecoverable error.
    pub async fn run(self) -> Result<()> {
        log::info!(
            "P2P: QUIC listener active on {}",
            self.endpoint.local_addr()?
        );

        if self.wt_listener.is_some() {
            log::info!(
                "P2P: WebTransport listener active on port {}",
                self.endpoint.local_addr()?.port() + 1
            );
        }

        self.kademlia.clone().start_maintenance();

        // Move shared state into Arcs so both loops can hold a copy.
        let ingress = self.ingress.clone();
        let kademlia = self.kademlia.clone();
        let local_nr = self.local_nr.clone();
        let noise_static = self.noise_static;
        let ml_dsa_sk = self.ml_dsa_sk.clone();
        let sessions = self.sessions.clone();
        let frame_drops = self.frame_drops.clone();
        let dht = self.dht.clone();
        let relay = self.relay.clone();

        // ── QUIC accept loop ──────────────────────────────────────────────────
        let quic_endpoint = self.endpoint.clone();
        let quic_ingress = ingress.clone();
        let quic_kademlia = kademlia.clone();
        let quic_nr = local_nr.clone();
        let quic_sk = ml_dsa_sk.clone();
        let quic_sessions = sessions.clone();
        let quic_frame_drops = frame_drops.clone();
        let quic_dht = dht.clone();
        let quic_relay = relay.clone();

        tokio::spawn(async move {
            while let Some(incoming) = quic_endpoint.accept().await {
                let m = quic_ingress.clone();
                let _k = quic_kademlia.clone();
                let nr = quic_nr.clone();
                let sk = quic_sk.clone();
                let s = quic_sessions.clone();
                let fd = quic_frame_drops.clone();
                let d = quic_dht.clone();
                let r = quic_relay.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = handle_native_connection(
                                conn,
                                m,
                                _k,
                                nr,
                                noise_static,
                                sk,
                                s,
                                fd,
                                d,
                                r,
                            )
                                .await
                            {
                                log::warn!("QUIC connection error: {}", e);
                            }
                        }
                        Err(e) => log::warn!("QUIC incoming connection failed: {}", e),
                    }
                });
            }
        });

        // ── WebTransport accept loop ──────────────────────────────────────────
        if let Some(wt_listener) = self.wt_listener {
            tokio::spawn(async move {
                loop {
                    match wt_listener.accept().await {
                        Ok(conn) => {
                            let m = ingress.clone();
                            let _k = kademlia.clone();
                            let nr = local_nr.clone();
                            let sk = ml_dsa_sk.clone();
                            let s = sessions.clone();
                            let fd = frame_drops.clone();
                            let d = dht.clone();
                            let r = relay.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handle_web_connection(
                                    conn,
                                    m,
                                    _k,
                                    nr,
                                    noise_static,
                                    sk,
                                    s,
                                    fd,
                                    d,
                                    r,
                                )
                                    .await
                                {
                                    log::warn!("WebTransport connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("WebTransport accept failed: {}. Stopping WT loop.", e);
                            break;
                        }
                    }
                }
            });
        }

        // Park the calling task — both loops run on the Tokio runtime.
        futures::future::pending::<Result<()>>().await
    }

    /// Dial out to `target_addr` over QUIC and establish a peer session.
    ///
    /// Used for connecting to peers discovered via LAN discovery
    /// (discovery.rs's beacon listener) or a DHT bootstrap/lookup
    /// (dht.rs / lib.rs's `find_node`), as opposed to `handle_native_connection`,
    /// which handles the accept side of a connection.
    ///
    /// Self-connection avoidance compares `target_addr` (full IP + port) against
    /// both our own bound QUIC endpoint address and, if known, our NAT-mapped
    /// external address (see `set_external_addr`) — never by port alone, since
    /// two distinct peers can share a port on different hosts.
    ///
    /// If we already hold a session for `target_addr`, this is a no-op that
    /// returns `Ok(())` rather than opening a duplicate connection.
    pub async fn connect_to_peer(&self, target_addr: SocketAddr) -> Result<()> {
        let local_addr = self
            .endpoint
            .local_addr()
            .context("QUIC: failed to read local endpoint address")?;
        if target_addr == local_addr {
            log::debug!(
                "connect_to_peer: refusing to dial our own bound address {}",
                target_addr
            );
            return Ok(());
        }

        if let Some(external_addr) = *self.external_addr.lock().await {
            if target_addr == external_addr {
                log::debug!(
                    "connect_to_peer: refusing to dial our own external address {}",
                    target_addr
                );
                return Ok(());
            }
        }

        if self.sessions.contains_key(&target_addr) {
            log::debug!(
                "connect_to_peer: already have a session with {}, skipping",
                target_addr
            );
            return Ok(());
        }

        log::info!("P2P: dialing peer at {}", target_addr);

        let connecting = self
            .endpoint
            .connect(target_addr, &self.tls_domain)
            .with_context(|| format!("QUIC: failed to start connection to {}", target_addr))?;
        let connection = connecting
            .await
            .with_context(|| format!("QUIC: handshake failed connecting to {}", target_addr))?;

        // The address we actually ended up connected to (should equal
        // `target_addr` for QUIC, but re-derive it rather than assume, and
        // re-check under it in case a concurrent dial/inbound connection
        // from the same peer raced us here).
        let remote_addr = connection.remote_address();
        if self.sessions.contains_key(&remote_addr) {
            log::debug!(
                "connect_to_peer: session with {} appeared concurrently, dropping redundant connection",
                remote_addr
            );
            connection.close(0u32.into(), b"duplicate session");
            return Ok(());
        }

        // ── Mandatory Noise_XX handshake, initiator side, on a new bi-stream ───
        let (send, recv) = connection
            .open_bi()
            .await
            .with_context(|| format!("QUIC: failed to open handshake bi-stream to {}", target_addr))?;

        let (transport, peer_nr) = handle_outbound(
            BiStream {
                reader: recv,
                writer: send,
            },
            false, // native QUIC — no WASM padding
            &self.noise_static,
            &self.local_nr,
            &self.ml_dsa_sk,
        )
            .await
            .with_context(|| format!("Noise_XX handshake (outbound) failed with {}", target_addr))?;

        let (_, noise_state) = transport.noise.into_parts();
        let session = Arc::new(PeerSession::new(
            PrimusConnection::Quic(connection.clone()),
            noise_state,
        ));
        self.sessions.insert(remote_addr, session);

        log::info!(
            "QUIC: outbound Noise_XX handshake complete with {}",
            remote_addr
        );

        // Register in the DHT now that we have the peer's verified NR —
        // every successful handshake gets an entry, not just ones that
        // happen to also run a Kademlia FIND_NODE. `self` implements
        // NodePinger via SessionPinger, so bucket-eviction pings use this
        // same session table.
        self.dht.insert(peer_nr, self).await;

        // Service this connection's future gossip/Kademlia streams the same
        // way an inbound connection would, on its own task so
        // `connect_to_peer` can return once the session is registered.
        let ingress = self.ingress.clone();
        let kademlia = self.kademlia.clone();
        let sessions = self.sessions.clone();
        let frame_drops = self.frame_drops.clone();
        let relay = self.relay.clone();

        tokio::spawn(async move {
            if let Err(e) = run_native_stream_loop(
                connection,
                remote_addr,
                ingress,
                kademlia,
                sessions.clone(),
                frame_drops,
                relay,
            )
                .await
            {
                log::warn!("Outbound QUIC connection to {} ended: {}", remote_addr, e);
                sessions.remove(&remote_addr);
            }
        });

        Ok(())
    }

    /// Ask `target_addr` for the addresses of the peer sessions it
    /// currently holds, over a `ControlMsg::GetPeers` control-channel
    /// round trip. Requires an existing session with `target_addr` — call
    /// `connect_to_peer` first if one isn't already open.
    ///
    /// Intended for `bootstrap.rs` to expand beyond configured seeds once
    /// at least one seed connection succeeds, though wiring that in is left
    /// for a follow-up — this just exposes the primitive.
    pub async fn get_peers(&self, target_addr: SocketAddr) -> Result<Vec<SocketAddr>> {
        let session = self
            .sessions
            .get(&target_addr)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| anyhow!("get_peers: no open session with {}", target_addr))?;

        match session.send_control(&ControlMsg::GetPeers).await? {
            ControlMsg::PeersResponse(peers) => Ok(peers),
            other => Err(anyhow!(
                "get_peers: {} sent an unexpected response variant: {:?}",
                target_addr,
                other
            )),
        }
    }
}

#[async_trait::async_trait]
impl<M, K> NodePinger for PrimusNetworkServer<M, K>
where
    M: MessageIngress,
    K: KademliaHandler,
{
    async fn ping(&self, nr: &PrimusNR) -> bool {
        SessionPinger::new(self.sessions.clone()).ping(nr).await
    }
}

// ── Control stream demux ──────────────────────────────────────────────────────
//
// Both Control and Kademlia RPC traffic ride bi-streams accepted off the
// same `connection.accept_bi()` call — QUIC gives no way to have two
// `accept_bi()` futures each only fire for "their" kind of stream, so
// telling them apart means reading the first byte of whatever comes in.
// quinn's RecvStream has no peek, so `read_bi_stream_type` consumes that
// byte and hands back a reader (`PrefixedReader`) that replays it before
// falling through to the real stream — the receiver ends up seeing exactly
// the bytes the sender wrote, just via one extra layer of indirection.

/// Replays a single already-consumed byte before delegating to the
/// underlying reader, so peeking a stream's first byte doesn't lose it.
struct PrefixedReader<R> {
    prefix: Option<u8>,
    inner: R,
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(b) = self.prefix.take() {
            buf.put_slice(&[b]);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Peek the first byte of a freshly-accepted bi-stream to learn its frame
/// type, returning a reader that still yields that byte on its first read.
async fn read_bi_stream_type<R>(mut recv: R) -> Result<(u8, PrefixedReader<R>)>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    recv.read_exact(&mut byte)
        .await
        .context("Bi-stream: closed before type byte")?;
    Ok((
        byte[0],
        PrefixedReader {
            prefix: Some(byte[0]),
            inner: recv,
        },
    ))
}

/// Handle a single incoming `STREAM_TYPE_CONTROL` bi-stream request
/// (Ping/GetPeers) and write the encrypted, framed response back on the
/// same stream.
///
/// Frame format matches gossip's uni-stream header:
///   `[type: u8][flags: u8][length: u32 BE][padding: u8 × 2]`
/// followed by the Noise-encrypted, bincode-serialized `ControlMsg`.
async fn handle_control_stream<S, R>(
    mut send: S,
    mut recv: R,
    session: Arc<PeerSession>,
    remote_addr: SocketAddr,
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
) -> Result<()>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 8];
    recv.read_exact(&mut header)
        .await
        .context("Control: stream closed before header")?;

    if header[0] != STREAM_TYPE_CONTROL {
        return Err(anyhow!(
            "Control: unexpected stream type 0x{:02x} from {} (expected 0x{:02x})",
            header[0],
            remote_addr,
            STREAM_TYPE_CONTROL
        ));
    }

    let len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
    if len > MAX_CONTROL_PAYLOAD {
        return Err(anyhow!(
            "Control: payload from {} exceeds max size ({} > {})",
            remote_addr,
            len,
            MAX_CONTROL_PAYLOAD
        ));
    }

    let mut ciphertext = vec![0u8; len];
    recv.read_exact(&mut ciphertext)
        .await
        .context("Control: stream closed before payload")?;

    let plaintext = session.decrypt(&ciphertext)?;
    let msg: ControlMsg = bincode::deserialize(&plaintext)
        .map_err(|e| anyhow!("ControlMsg deserialization failed: {}", e))?;

    let response = match msg {
        ControlMsg::Ping => ControlMsg::Pong,
        ControlMsg::GetPeers => {
            // Every other session we currently hold, excluding the
            // requester itself — no point telling a peer about its own
            // address.
            let peers: Vec<SocketAddr> = sessions
                .iter()
                .map(|entry| *entry.key())
                .filter(|addr| *addr != remote_addr)
                .collect();
            ControlMsg::PeersResponse(peers)
        }
        // Pong/PeersResponse are response-only variants. A peer sending
        // one as a *request* is either confused or misbehaving; drop the
        // stream rather than guess at what it wanted.
        other => {
            return Err(anyhow!(
                "Control: {} sent a response variant ({:?}) as a request",
                remote_addr,
                other
            ));
        }
    };

    let resp_bytes = bincode::serialize(&response)
        .map_err(|e| anyhow!("ControlMsg response serialization failed: {}", e))?;
    let resp_ciphertext = session.encrypt(&resp_bytes)?;
    let resp_header = PeerSession::build_header(STREAM_TYPE_CONTROL, resp_ciphertext.len());

    send.write_all(&resp_header).await?;
    send.write_all(&resp_ciphertext).await?;

    Ok(())
}

// ── Connection handlers ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_native_connection<M, K>(
    connection: Connection,
    ingress: Arc<M>,
    kademlia: Arc<K>,
    local_nr: PrimusNR,
    noise_static: [u8; 32],
    ml_dsa_sk: Vec<u8>,
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    frame_drops: Arc<AtomicU64>,

    dht: PrimusDHT,
    relay: Arc<GossipRelay>,
) -> Result<()>
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let remote_addr = connection.remote_address();

    // ── Mandatory Noise_XX handshake on the first bi-stream ───────────────────
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("QUIC: failed to accept handshake bi-stream")?;

    let (transport, peer_nr) = handle_inbound(
        BiStream {
            reader: recv,
            writer: send,
        },
        false, // native QUIC — no WASM padding
        &noise_static,
        &local_nr,
        &ml_dsa_sk,
    )
        .await?;

    let (_, noise_state) = transport.noise.into_parts();
    let session = Arc::new(PeerSession::new(
        PrimusConnection::Quic(connection.clone()),
        noise_state,
    ));
    sessions.insert(remote_addr, session);

    log::info!("QUIC: Noise_XX handshake complete for {}", remote_addr);

    // Register the peer in the DHT now that we actually have its verified
    // PrimusNR (handle_inbound surfaces it — see transport.rs/noise.rs).
    // Previously this only happened indirectly, whenever the peer's NR
    // showed up in a Kademlia FIND_NODE response, so a peer that never
    // issued or answered one never made it into the routing table even
    // though its handshake had already been authenticated. Every
    // successful handshake now gets an entry.
    let pinger = SessionPinger::new(sessions.clone());
    dht.insert(peer_nr, &pinger).await;

    run_native_stream_loop(connection, remote_addr, ingress, kademlia, sessions, frame_drops, relay).await
}

/// Post-handshake stream dispatch loop for a native QUIC connection.
///
/// Shared by `handle_native_connection` (inbound, accept side) and
/// `PrimusNetworkServer::connect_to_peer` (outbound, dial side) — both sides
/// service gossip uni-streams and Kademlia RPC bi-streams identically once
/// the Noise_XX handshake and session registration are done.
async fn run_native_stream_loop<M, K>(
    connection: Connection,
    remote_addr: SocketAddr,
    ingress: Arc<M>,
    kademlia: Arc<K>,
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    frame_drops: Arc<AtomicU64>,
    relay: Arc<GossipRelay>,
) -> Result<()>
where
    M: MessageIngress,
    K: KademliaHandler,
{
    loop {
        tokio::select! {
            uni = connection.accept_uni() => {
                let recv = uni.context("QUIC: uni-stream accept failed")?;
                let m = ingress.clone();
                let s = sessions.clone();
                let session = s.get(&remote_addr).map(|r| r.value().clone());
                let connection_clone = connection.clone();
                let fd = frame_drops.clone();
                let r = relay.clone();
                tokio::spawn(async move {
                    if let Some(sess) = session {
                        let _permit = sess.stream_semaphore.acquire().await;
                        if let Err(e) = handle_gossip_stream(recv, m, s.clone(), remote_addr, fd, r).await {
                            log::warn!("Gossip stream error from {}: {} — closing connection", remote_addr, e);
                            // INVARIANT: Decrypt failures cause nonce desync. The connection must
                            // be closed immediately so the next message from this peer uses a new handshake.
                            s.remove(&remote_addr);
                            connection_clone.close(0u32.into(), b"nonce error");
                        }
                    }
                });
            }
            bi = connection.accept_bi() => {
                let (send, recv) = bi.context("QUIC: bi-stream accept failed")?;
                let k = kademlia.clone();
                let s = sessions.clone();
                tokio::spawn(async move {
                    let Some(sess) = s.get(&remote_addr).map(|r| r.value().clone()) else {
                        return;
                    };
                    // acquire_owned (not acquire) — acquire() returns a
                    // permit borrowed from `&sess.stream_semaphore`, which
                    // would keep `sess` borrowed for the permit's lifetime
                    // and block the move of `sess` into
                    // handle_control_stream below ("cannot move out of
                    // `sess` because it is borrowed"). Cloning the Arc first
                    // gives an owned permit with no lingering borrow on `sess`.
                    let _permit = sess.stream_semaphore.clone().acquire_owned().await;

                    // Demux by frame-type discriminant — see the
                    // "Control stream demux" section above for why this
                    // peek-and-replay is needed instead of a separate
                    // select arm.
                    match read_bi_stream_type(recv).await {
                        Ok((STREAM_TYPE_CONTROL, prefixed_recv)) => {
                            if let Err(e) = handle_control_stream(
                                send,
                                prefixed_recv,
                                sess,
                                remote_addr,
                                s,
                            )
                                .await
                            {
                                log::warn!("Control stream error from {}: {}", remote_addr, e);
                            }
                        }
                        Ok((_other, prefixed_recv)) => {
                            // Falls through to Kademlia unchanged from the
                            // original behavior. SAFE today only because
                            // KademliaRpc::send_find_node (lib.rs) never
                            // opens a second bi-stream on an *established*
                            // PeerSession connection — its request/response
                            // both ride the handshake bi-stream itself,
                            // which handle_inbound/handle_outbound fully
                            // consume before this loop ever starts. If
                            // Kademlia RPC is rewired to reuse a live
                            // PeerSession connection instead of dialing a
                            // fresh one per lookup, `send_find_node` will
                            // need to write a matching 8-byte header
                            // (e.g. a new STREAM_TYPE_KADEMLIA) before its
                            // request, or the two protocols will silently
                            // desync each other's framing here.
                            if let Err(e) = k
                                .handle_rpc(Box::new(send), Box::new(prefixed_recv))
                                .await
                            {
                                log::warn!("Kademlia RPC error from {}: {}", remote_addr, e);
                            }
                        }
                        Err(e) => {
                            log::warn!("Bi-stream type peek failed from {}: {}", remote_addr, e);
                        }
                    }
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_web_connection<M, K>(
    connection: wtransport::Connection,
    ingress: Arc<M>,
    _kademlia: Arc<K>,
    local_nr: PrimusNR,
    noise_static: [u8; 32],
    ml_dsa_sk: Vec<u8>,
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    frame_drops: Arc<AtomicU64>,

    dht: PrimusDHT,
    relay: Arc<GossipRelay>,
) -> Result<()>
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let remote_addr = connection.remote_address();

    // ── Mandatory Noise_XX handshake on the first bi-stream ───────────────────
    let (send, recv) = connection
        .accept_bi()
        .await
        .context("WebTransport: failed to accept handshake bi-stream")?;

    let (transport, peer_nr) = handle_inbound(
        BiStream {
            reader: recv,
            writer: send,
        },
        true, // WebTransport — enable WASM 6-byte padding
        &noise_static,
        &local_nr,
        &ml_dsa_sk,
    )
        .await?;

    let (_, noise_state) = transport.noise.into_parts();
    let arc_conn = Arc::new(connection);
    let session = Arc::new(PeerSession::new(
        PrimusConnection::Web(arc_conn.clone()),
        noise_state,
    ));
    sessions.insert(remote_addr, session);

    log::info!(
        "WebTransport: Noise_XX handshake complete for browser client {}",
        remote_addr
    );

    // Leaf nodes (WASM/browser) still don't run Kademlia RPC themselves,
    // but they now get a DHT entry like any other handshake — the routing
    // table needs to know they're reachable so other nodes' FIND_NODE
    // lookups can return them. BEHAVIOR CHANGE flagged: previously leaf
    // nodes were registered only when they sent a FIND_NODE request, which
    // they never do, so in practice they were never in the DHT at all.
    // Worth a second look if leaf nodes are meant to stay routing-invisible.
    let pinger = SessionPinger::new(sessions.clone());
    dht.insert(peer_nr, &pinger).await;

    // ── Stream dispatch loop ──────────────────────────────────────────────────
    //
    // NOTE: WebTransport leaf nodes (WASM/browser) do not participate in
    // Kademlia routing. Bi-streams from WT connections are used only for the
    // initial Noise handshake (handled above). Any subsequent bi-stream is
    // unexpected and is logged + dropped. Gossip arrives on uni-streams.
    loop {
        tokio::select! {
            uni = arc_conn.accept_uni() => {
                let recv = uni.context("WebTransport: uni-stream accept failed")?;
                let m = ingress.clone();
                let s = sessions.clone();
                let session = s.get(&remote_addr).map(|r| r.value().clone());
                let arc_conn_c = arc_conn.clone();
                let fd = frame_drops.clone();
                let r = relay.clone();
                tokio::spawn(async move {
                    if let Some(sess) = session {
                        let _permit = sess.stream_semaphore.acquire().await;
                        if let Err(e) = handle_gossip_stream(recv, m, s.clone(), remote_addr, fd, r).await {
                            log::warn!("WebTransport gossip error from {}: {} — closing connection", remote_addr, e);
                            s.remove(&remote_addr);
                            arc_conn_c.close(0u32.into(), b"nonce error");
                        }
                    }
                });
            }
            bi = arc_conn.accept_bi() => {
                // WT leaf nodes never run Kademlia RPC (different stream
                // types from quinn's, and they don't participate in
                // routing anyway — see the comment above this loop), so
                // unlike the native QUIC path there's nothing to demux:
                // any bi-stream here beyond the handshake is Control.
                let (send, recv) = bi.context("WebTransport: unexpected bi-stream")?;
                let s = sessions.clone();
                let sess = s.get(&remote_addr).map(|r| r.value().clone());
                tokio::spawn(async move {
                    let Some(sess) = sess else { return; };
                    // See the matching comment in the native QUIC bi-stream
                    // branch above — acquire_owned avoids a permit borrow
                    // on `sess` that would otherwise block moving it into
                    // handle_control_stream below.
                    let _permit = sess.stream_semaphore.clone().acquire_owned().await;
                    if let Err(e) = handle_control_stream(send, recv, sess, remote_addr, s).await {
                        log::warn!("WebTransport control stream error from {}: {}", remote_addr, e);
                    }
                });
            }
        }
    }
}

// ── Gossip stream handler ─────────────────────────────────────────────────────

/// Handle a single incoming gossip uni-stream.
///
/// Frame format (8-byte header):
///   [type: u8][flags: u8][length: u32 BE][padding: u8 × 2]
///
/// The payload is decrypted using the per-connection `PeerSession::decrypt()`
/// which uses a monotonically increasing nonce counter (fixes the nonce=0 bug).
async fn handle_gossip_stream<R, M>(
    recv: R,
    ingress: Arc<M>,
    sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>>,
    remote_addr: SocketAddr,
    frame_drops: Arc<AtomicU64>,
    relay: Arc<GossipRelay>,
) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin + Send,
    M: MessageIngress,
{
    // Use LengthDelimitedCodec to enforce 16 MiB limit and handle framing.
    // Protocol: [type: u8][flags: u8][length: u32 BE][padding: u8 × 2]
    // The length field (4 bytes) starts at offset 2.
    let codec = LengthDelimitedCodec::builder()
        .length_field_offset(2)
        .length_field_length(4)
        .length_adjustment(2) // 2 bytes of padding after length
        .max_frame_length(MAX_GOSSIP_PAYLOAD + 8)
        .new_codec();

    let mut framed = tokio_util::codec::FramedRead::new(recv, codec);

    let frame = framed
        .next()
        .await
        .context("Gossip: stream closed before header")?
        .map_err(|e| {
            frame_drops.fetch_add(1, Ordering::Relaxed);
            anyhow!(
                "Gossip: frame size limit exceeded or IO error from {}: {}",
                remote_addr,
                e
            )
        })?;

    if frame.len() < 8 {
        return Err(anyhow!("Gossip: frame too short from {}", remote_addr));
    }

    let stream_type = frame[0];
    let ciphertext = &frame[8..];

    if stream_type != STREAM_TYPE_GOSSIP {
        return Err(anyhow!(
            "Gossip: unexpected stream type 0x{:02x} from {} (expected 0x{:02x})",
            stream_type,
            remote_addr,
            STREAM_TYPE_GOSSIP
        ));
    }

    // ── Decrypt ───────────────────────────────────────────────────────────────
    let plaintext = match sessions.get(&remote_addr) {
        Some(session) => session.decrypt(ciphertext)?,
        None => {
            return Err(anyhow!(
                "Gossip: received data from {} before Noise handshake completed",
                remote_addr
            ));
        }
    };

    // ── Deserialize Envelope ─────────────────────────────────────────────────
    let message: crate::network::PrimusMessage =
        bincode::deserialize(&plaintext).context("Gossip: envelope deserialization failed")?;

    // ── Hand off to the application layer ─────────────────────────────────────
    match message {
        crate::network::PrimusMessage::Envelope(data, ttl) => {
            // Dedup check first: same content re-arriving via a different
            // relay path (or a loop within our overlapping session sets)
            // must not be re-ingested or re-relayed, no matter what TTL it
            // shows up with.
            if !relay.is_new(&data).await {
                log::debug!(
                    "Gossip: duplicate envelope from {} dropped (already seen)",
                    remote_addr
                );
                return Ok(());
            }

            ingress.on_envelope(&data).await.with_context(|| {
                format!(
                    "Gossip: envelope ingestion failed for payload from {}",
                    remote_addr
                )
            })?;

            // Relay to other currently-held peer sessions after successful
            // ingestion only — a peer whose payload failed application-level
            // ingestion shouldn't still get propagated further. Spawned so a
            // slow or stuck peer in the fan-out doesn't hold up this stream's
            // handler.
            let relay_data = data.clone();
            tokio::spawn(async move {
                relay.relay(&relay_data, ttl, remote_addr).await;
            });
        }
        _ => {
            log::debug!(
                "Gossip: received unsupported message type from {}",
                remote_addr
            );
        }
    }

    Ok(())
}

// ── TLS certificate generation ────────────────────────────────────────────────

/// Generate a self-signed TLS certificate for the QUIC endpoint.
///
/// For production deployment, replace this with a CA-signed certificate
/// loaded from a path supplied in the node configuration. Self-signed
/// certificates require peers to disable certificate validation, which
/// weakens the TLS layer. The Noise handshake provides the actual peer
/// authentication — TLS here is only for transport encryption.
fn generate_self_signed_cert(domain: &str) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert = rcgen::generate_simple_self_signed(vec![domain.into()])
        .context("rcgen: failed to generate self-signed certificate")?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    Ok((
        rustls::pki_types::CertificateDer::from(cert_der),
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key_der,
        )),
    ))
}

// ── Gossip dedup tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod gossip_dedup_tests {
    use super::*;

    /// The whole point of `envelope_dedup_id`: the same envelope data
    /// hopping through the network at different TTLs must produce the
    /// exact same dedup id. If TTL leaked into the hash, every hop would
    /// look like a brand-new message and dedup would never trigger.
    #[test]
    fn dedup_id_is_identical_across_different_ttls() {
        let data = b"same envelope payload, different hop count".to_vec();

        let hi_ttl_msg = crate::network::PrimusMessage::Envelope(data.clone(), 32);
        let lo_ttl_msg = crate::network::PrimusMessage::Envelope(data.clone(), 1);

        let id_hi = match &hi_ttl_msg {
            crate::network::PrimusMessage::Envelope(d, _) => envelope_dedup_id(d),
        };
        let id_lo = match &lo_ttl_msg {
            crate::network::PrimusMessage::Envelope(d, _) => envelope_dedup_id(d),
        };

        assert_eq!(
            id_hi, id_lo,
            "dedup id must depend only on envelope data, never on TTL"
        );
    }

    #[test]
    fn dedup_id_differs_for_different_data() {
        let id_a = envelope_dedup_id(b"payload a");
        let id_b = envelope_dedup_id(b"payload b");
        assert_ne!(id_a, id_b);
    }

    #[tokio::test]
    async fn seen_set_flags_first_sighting_new_and_repeat_as_duplicate() {
        let sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>> = Arc::new(DashMap::new());
        let relay = GossipRelay::new(sessions);

        let data = b"hello gossip network".to_vec();

        assert!(
            relay.is_new(&data).await,
            "first sighting of a message must be treated as new"
        );
        assert!(
            !relay.is_new(&data).await,
            "second sighting of the same data must be treated as a duplicate"
        );

        // A different TTL on the same underlying data is still a duplicate,
        // since dedup only looks at `data`.
        let same_data_again = data.clone();
        assert!(
            !relay.is_new(&same_data_again).await,
            "identical data must be recognized as duplicate regardless of TTL"
        );
    }

    #[tokio::test]
    async fn seen_set_evicts_oldest_on_overflow() {
        let sessions: Arc<DashMap<SocketAddr, Arc<PeerSession>>> = Arc::new(DashMap::new());
        let relay = GossipRelay::new(sessions);

        // Fill past capacity so the very first id gets evicted.
        for i in 0..(MAX_SEEN_MESSAGES + 1) {
            let data = format!("msg-{i}").into_bytes();
            assert!(relay.is_new(&data).await);
        }

        // The first message's id should have been evicted, so it is
        // treated as new again.
        let first_data = b"msg-0".to_vec();
        assert!(
            relay.is_new(&first_data).await,
            "oldest entry should have been evicted once the cap was exceeded"
        );

        // A recent message should still be remembered.
        let recent_data = format!("msg-{}", MAX_SEEN_MESSAGES).into_bytes();
        assert!(
            !relay.is_new(&recent_data).await,
            "recently inserted entries must still be remembered"
        );
    }
}