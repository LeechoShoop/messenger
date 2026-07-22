// =============================================================================
// primus-net-opt (crate name: `messenger`, per Cargo.toml) — src/main.rs
//
// This file did not exist in the uploaded project — everything below is new.
// It's a minimal but complete binary entry point: generate/load identity,
// implement the two abstraction traits server.rs expects (MessageIngress,
// KademliaHandler), stand up PrimusNetworkServer, and wire LAN discovery
// into it per the previous prompt.
//
// HONEST GAPS — flagged rather than silently guessed around:
//
//   1. Key persistence: keys are generated fresh on every run below. A real
//      node needs to persist (addr, ml_dsa_pk, ml_dsa_sk) to disk and only
//      generate once, or every restart gets a new NodeID and the DHT/routing
//      table churns. Not wired here — see `load_or_generate_identity()`.
//
//   2. KademliaEngine needs its own outbound quinn::Endpoint (client-mode)
//      for `KademliaRpc::send_find_node`, separate from the server's inbound
//      endpoint. Since QUIC connections here are secured by self-signed
//      certs (real auth is the Noise_XX/ML-DSA layer per server.rs's own
//      module comment), the client endpoint below disables TLS certificate
//      verification via a custom rustls verifier. This matches the existing
//      trust model but is worth a second look before shipping.
//
//   3. `impl KademliaHandler for KademliaEngine` now lives in lib.rs, not
//      here — main.rs and lib.rs are separate crates even in one Cargo
//      package, and implementing a foreign trait for a foreign type from
//      main.rs's perspective hits the orphan rule (E0117). See the bottom
//      of lib.rs for the impl.
//
//   4. `ml-dsa`'s `KeyGen`/`key_gen` require the crate's `rand_core`
//      feature, which Cargo.toml had disabled (`default-features = false`
//      with no features re-enabled). Cargo.toml needs
//      `features = ["rand_core"]` added or `key_gen` won't exist (E0599).
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use ml_dsa::signature::Keypair;
use ml_dsa::{KeyGen, MlDsa87};
use rand::rngs::OsRng;

use messenger::bootstrap;
use messenger::discovery::PrimusDiscovery;
use messenger::nat::NatService;
use messenger::peer::PrimusNR;
use messenger::server::{MessageIngress, PrimusNetworkServer};
use messenger::KademliaEngine;

// ── MessageIngress: minimal stand-in until messenger-core exists ────────────

struct LoggingIngress;

#[async_trait::async_trait]
impl MessageIngress for LoggingIngress {
    async fn on_envelope(&self, bytes: &[u8]) -> Result<bool> {
        log::info!("Ingress: received {}-byte envelope", bytes.len());
        Ok(true)
    }
}

// NOTE: `impl KademliaHandler for KademliaEngine` used to live here but was
// moved to lib.rs. main.rs (a binary) and lib.rs (the library) are two
// separate crates even inside one Cargo package — implementing a trait
// that's foreign to *this* crate (KademliaHandler, defined in
// messenger::server) for a type that's also foreign to this crate
// (KademliaEngine, defined in messenger) violates the orphan rule (E0117).
// The impl has to live inside the `messenger` crate itself.

// ── Identity ──────────────────────────────────────────────────────────────

struct Identity {
    local_nr: PrimusNR,
    ml_dsa_pk: Vec<u8>,
    ml_dsa_sk: Vec<u8>,
}

/// GAP (see module header, #1): generates a fresh keypair every run.
/// Replace with a load-from-disk-or-generate-once routine before this
/// leaves the "wiring it up to test discovery" stage — a churning NodeID
/// on every restart defeats the DHT's whole point.
fn generate_identity(addr: SocketAddr) -> Result<Identity> {
    let mut rng = OsRng;
    let kp = MlDsa87::key_gen(&mut rng);

    let ml_dsa_sk = kp.signing_key().encode().to_vec();
    let ml_dsa_pk = kp.verifying_key().encode().to_vec();

    let local_nr = PrimusNR::new(addr, &ml_dsa_pk, &ml_dsa_sk)
        .context("failed to build self-signed PrimusNR")?;

    Ok(Identity {
        local_nr,
        ml_dsa_pk,
        ml_dsa_sk,
    })
}

// ── Insecure client-side QUIC config for KademliaEngine's outbound endpoint ──
//
// GAP (see module header, #2): trusts any server certificate. Safe under
// this project's threat model only because Noise_XX + ML-DSA-87 is the
// actual peer-authentication layer (server.rs's own comment says as much
// re: self-signed certs) — but it's still worth a second pair of eyes.
mod insecure_client {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::sync::Arc;

    #[derive(Debug)]
    pub struct SkipVerification;

    impl ServerCertVerifier for SkipVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            // Self-signed certs from rcgen (server.rs::generate_self_signed_cert)
            // are ECDSA P-256 by default.
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    pub fn client_endpoint(bind_addr: std::net::SocketAddr) -> anyhow::Result<quinn::Endpoint> {
        let crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipVerification))
            .with_no_client_auth();

        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?,
        ));

        let mut endpoint = quinn::Endpoint::client(bind_addr)?;
        endpoint.set_default_client_config(client_config);
        Ok(endpoint)
    }
}

// ── main ──────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let my_port: u16 = std::env::var("PRIMUS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(messenger::server::P2P_PORT);

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", my_port).parse()?;
    let tls_domain = "primus.local".to_string();

    // ── Identity ─────────────────────────────────────────────────────────
    let identity = generate_identity(bind_addr)?;
    log::info!(
        "Node identity: {} (NodeID {})",
        identity.local_nr.addr(),
        hex_short(&identity.local_nr.node_id())
    );

    // ── Kademlia (needs its own outbound QUIC endpoint) ─────────────────────
    let kademlia_endpoint = insecure_client::client_endpoint("0.0.0.0:0".parse()?)
        .context("failed to build Kademlia client endpoint")?;
    let kademlia = KademliaEngine::new(
        identity.local_nr.clone(),
        kademlia_endpoint,
        identity.ml_dsa_sk.clone(),
        tls_domain.clone(),
    );

    // ── Application ingress ─────────────────────────────────────────────────
    let ingress = Arc::new(LoggingIngress);

    // ── Network server ───────────────────────────────────────────────────
    //
    // Pass a *clone* of the `kademlia` Arc here, not the binding itself —
    // `bootstrap::bootstrap` below needs `kademlia` again for the
    // post-seed-connect `find_node(local_id)` self-lookup, so the original
    // binding must survive this call rather than being moved into the server.
    let server = Arc::new(
        PrimusNetworkServer::new(
            bind_addr,
            ingress,
            Arc::clone(&kademlia),
            identity.local_nr.clone(),
            identity.ml_dsa_sk.clone(),
            tls_domain,
        )
            .await
            .context("failed to construct PrimusNetworkServer")?,
    );

    // ── NAT / UPnP (best-effort — don't fail startup if it doesn't work) ────
    match NatService::open_world(my_port).await {
        Ok(external_ip) => {
            let external_addr = SocketAddr::new(external_ip, my_port);
            server.set_external_addr(external_addr).await;
            log::info!("NAT: external address is {}", external_addr);
        }
        Err(e) => {
            log::warn!("NAT: UPnP mapping failed, staying LAN-only: {}", e);
        }
    }

    // ── LAN discovery, wired to server.connect_to_peer ───────────────────
    wire_discovery(Arc::clone(&server), my_port).await;

    // ── Internet bootstrap via configured seed nodes ─────────────────────
    //
    // Complementary to LAN discovery above, not redundant with it — see
    // README.md ("LAN discovery vs. internet bootstrap") for the split.
    // Seeds are dialed sequentially with a per-seed timeout inside
    // `bootstrap::bootstrap`; a dead seed is logged and skipped, it never
    // aborts startup. If at least one seed comes up, this also runs one
    // Kademlia self-lookup to populate the routing table immediately
    // rather than waiting for the first hourly maintenance tick.
    match bootstrap::load_seeds() {
        Ok(seeds) => {
            bootstrap::bootstrap(
                Arc::clone(&server),
                Arc::clone(&kademlia),
                seeds,
                identity.local_nr.node_id(),
            )
                .await;
        }
        Err(e) => {
            log::warn!("Bootstrap: failed to load seed configuration: {}", e);
        }
    }

    // ── Run ──────────────────────────────────────────────────────────────
    // `run(self)` takes ownership, so hand it the last owned copy. This is
    // fine because `wire_discovery` only needed a clone of the Arc, taken
    // above, and this is the last use of `server` in this function.
    Arc::try_unwrap(server)
        .unwrap_or_else(|arc| {
            panic!(
                "cannot start .run(): {} other Arc<PrimusNetworkServer> references still alive",
                Arc::strong_count(&arc)
            )
        })
        .run()
        .await
}

fn hex_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Discovery wiring (from the previous prompt) ──────────────────────────

async fn wire_discovery(
    server: Arc<PrimusNetworkServer<LoggingIngress, KademliaEngine>>,
    my_port: u16,
) {
    let discovery = PrimusDiscovery::new(my_port, None);

    // Only clone the Arc handle into the closure — never the server itself.
    // PrimusNetworkServer holds a quinn::Endpoint, DashMap sessions table,
    // etc.; cloning the Arc is O(1) and keeps every beacon-triggered dial
    // operating on the same session table as the rest of the node.
    let server_for_discovery = Arc::clone(&server);

    tokio::spawn(async move {
        if let Err(e) = discovery
            .start(move |addr_str: String| {
                let server = Arc::clone(&server_for_discovery);
                async move {
                    // discovery.rs hands back a plain "ip:port" string —
                    // parse defensively rather than trust it. A malformed
                    // beacon must never take the node down.
                    let target_addr: SocketAddr = match addr_str.parse() {
                        Ok(addr) => addr,
                        Err(e) => {
                            log::warn!(
                                "Discovery: dropping beacon with unparseable address '{}': {}",
                                addr_str,
                                e
                            );
                            return;
                        }
                    };

                    // connect_to_peer() itself no-ops on an existing session,
                    // but that check is only logged at debug level inside it.
                    // Checking here too lets LAN discovery activity show up
                    // at info level without cranking the whole node to debug.
                    if server.sessions.contains_key(&target_addr) {
                        log::info!("Discovery: {} already connected, skipping", target_addr);
                        return;
                    }

                    log::info!("Discovery: dialing new peer at {}", target_addr);

                    if let Err(e) = server.connect_to_peer(target_addr).await {
                        log::warn!(
                            "Discovery: connect_to_peer failed for {}: {}",
                            target_addr,
                            e
                        );
                    }
                }
            })
            .await
        {
            log::error!("Discovery service exited: {}", e);
        }
    });
}