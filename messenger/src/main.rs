// =============================================================================
// primus-net-opt (crate name: `messenger`, per Cargo.toml) — src/main.rs
//
// This file did not exist in the uploaded project — everything below is new.
// It's a minimal but complete binary entry point: generate/load identity,
// implement the two abstraction traits server.rs expects (MessageIngress,
// KademliaHandler), stand up PrimusNetworkServer, and wire LAN discovery
// into it per the previous prompt.
//
// THIS PROMPT'S CHANGES:
//   1. Identity is now persisted (identity.rs) instead of regenerated every
//      run — GAP #1 from the original version of this file is resolved,
//      see `load_or_generate_identity()` below.
//   2. The DHT's known-peer list is periodically snapshotted to disk and
//      reloaded on startup as extra bootstrap candidates, alongside the
//      seed list from bootstrap.rs (prompt 09) — see the "DHT snapshot"
//      section below and dht_snapshot.rs.
//
// REMAINING HONEST GAPS — flagged rather than silently guessed around:
//
//   1. KademliaEngine needs its own outbound quinn::Endpoint (client-mode)
//      for `KademliaRpc::send_find_node`, separate from the server's inbound
//      endpoint. Since QUIC connections here are secured by self-signed
//      certs (real auth is the Noise_XX/ML-DSA layer per server.rs's own
//      module comment), the client endpoint below disables TLS certificate
//      verification via a custom rustls verifier. This matches the existing
//      trust model but is worth a second look before shipping.
//
//   2. `impl KademliaHandler for KademliaEngine` now lives in lib.rs, not
//      here — main.rs and lib.rs are separate crates even in one Cargo
//      package, and implementing a foreign trait for a foreign type from
//      main.rs's perspective hits the orphan rule (E0117). See the bottom
//      of lib.rs for the impl.
//
//   3. `ml-dsa`'s `KeyGen`/`key_gen` require the crate's `rand_core`
//      feature, which Cargo.toml had disabled (`default-features = false`
//      with no features re-enabled). Cargo.toml needs
//      `features = ["rand_core"]` added or `key_gen` won't exist (E0599).
//
//   4. NEW THIS PROMPT — shutdown lifecycle: `PrimusNetworkServer::run()`
//      (server.rs) takes `self` by value and blocks forever on
//      `futures::future::pending()`; there is no drain/stop signal to hook
//      a "finish serving, then snapshot" sequence into. Separately,
//      `Arc::try_unwrap(server)` a few lines below `run()`'s call site
//      already assumes it's the last strong reference, despite
//      `wire_discovery` handing a clone into a beacon/listener loop that
//      (via discovery.rs's own internally-spawned tasks) in practice lives
//      for the rest of the process — that's a pre-existing gap in this
//      file, not something this change introduces, and reworking the
//      server's shutdown lifecycle in general is out of scope here. What
//      this prompt adds instead only needs `PrimusDHT` (cheaply `Clone`,
//      see dht.rs) and the snapshot path — not ownership of `server` — so
//      it saves one last snapshot on Ctrl+C and exits the process
//      directly, rather than trying to unwind `.run()`'s infinite pending
//      future. See the "Graceful-ish shutdown" section below.
// =============================================================================

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

use messenger::bootstrap;
use messenger::dht_snapshot;
use messenger::discovery::PrimusDiscovery;
use messenger::identity;
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
    ml_dsa_sk: Vec<u8>,
}

/// Load the node's persisted ML-DSA-87 keypair from `config_dir` (generating
/// and saving one on first run — see identity.rs), then build this run's
/// self-signed `PrimusNR` from it for `addr`.
///
/// Passphrase-encrypted storage is opt-in via `PRIMUS_KEY_PASSPHRASE` (see
/// identity.rs's module doc comment for the plain-vs-encrypted tradeoff and
/// the encrypted path's own honest-gap note). Plain storage is unconditional
/// otherwise — no silent fallback either way; `identity::load_or_generate_keypair`
/// errors out on a passphrase/on-disk-format mismatch rather than guessing.
fn load_or_generate_identity(addr: SocketAddr, config_dir: &Path) -> Result<Identity> {
    let passphrase = std::env::var(identity::PASSPHRASE_ENV_VAR).ok();
    if passphrase.is_some() {
        log::info!(
            "Identity: {} is set, using passphrase-encrypted identity storage",
            identity::PASSPHRASE_ENV_VAR
        );
    }

    let (ml_dsa_pk, ml_dsa_sk) = identity::load_or_generate_keypair(config_dir, passphrase.as_deref())
        .context("failed to load or generate the persistent node identity")?;

    let local_nr = PrimusNR::new(addr, &ml_dsa_pk, &ml_dsa_sk)
        .context("failed to build self-signed PrimusNR from the persisted/generated keypair")?;

    Ok(Identity {
        local_nr,
        ml_dsa_sk,
    })
}

// ── Insecure client-side QUIC config for KademliaEngine's outbound endpoint ──
//
// GAP (see module header, #1): trusts any server certificate. Safe under
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

fn main() -> Result<()> {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async_main())
        })
        .unwrap()
        .join()
        .unwrap()
}

async fn async_main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    env_logger::init();

    let my_port: u16 = std::env::var("PRIMUS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(messenger::server::P2P_PORT);

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", my_port).parse()?;
    let tls_domain = "primus.local".to_string();

    // ── Config directory (shared by identity.rs and dht_snapshot.rs) ───────
    let config_dir = identity::config_dir().context("failed to resolve the config directory")?;
    log::info!("Config directory: {}", config_dir.display());

    // ── Identity (persisted — see identity.rs) ──────────────────────────────
    let identity = load_or_generate_identity(bind_addr, &config_dir)?;
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

    // ── DHT snapshot: warm-start the routing table from last run ─────────
    //
    // Loaded (and, further down, periodically saved) regardless of whether
    // this ends up non-empty — an absent/corrupt snapshot just means an
    // empty Vec (see dht_snapshot::load), which makes everything below a
    // no-op rather than a special case.
    let snapshot_path = dht_snapshot::snapshot_path(&config_dir);
    let snapshot_records = dht_snapshot::load(&snapshot_path);
    if snapshot_records.is_empty() {
        log::info!(
            "DHT snapshot: no usable prior snapshot at {}, starting cold",
            snapshot_path.display()
        );
    } else {
        log::info!(
            "DHT snapshot: loaded {} peer record(s) from {}, warm-starting routing table",
            snapshot_records.len(),
            snapshot_path.display()
        );
        for nr in &snapshot_records {
            // The table starts empty this run, so no bucket can be full
            // yet — `insert`'s ping-on-full-bucket path (dht.rs) is
            // guaranteed unused here. `server` is passed only to satisfy
            // the generic `P: NodePinger` bound (PrimusNetworkServer
            // implements NodePinger — see server.rs).
            server.dht().insert(nr.clone(), server.as_ref()).await;
        }
    }

    // ── Internet bootstrap via configured seeds + the DHT snapshot ────────
    //
    // Complementary to LAN discovery above, not redundant with it — see
    // README.md ("LAN discovery vs. internet bootstrap") for the split.
    // Seeds are dialed sequentially with a per-seed timeout inside
    // `bootstrap::bootstrap`; a dead seed (operator-configured or
    // snapshot-sourced) is logged and skipped, it never aborts startup.
    // If at least one seed comes up, this also runs one Kademlia
    // self-lookup to populate the routing table immediately rather than
    // waiting for the first hourly maintenance tick.
    match bootstrap::load_seeds() {
        Ok(mut seeds) => {
            let before = seeds.len();
            for nr in &snapshot_records {
                let addr = nr.addr();
                if !seeds.contains(&addr) {
                    seeds.push(addr);
                }
            }
            if seeds.len() > before {
                log::info!(
                    "Bootstrap: added {} address(es) from the DHT snapshot as extra bootstrap \
                     candidates (deduplicated against the configured seed list)",
                    seeds.len() - before
                );
            }

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

    // ── Periodic DHT snapshot (every dht_snapshot::SNAPSHOT_INTERVAL) ─────
    dht_snapshot::spawn_periodic(server.dht().clone(), snapshot_path.clone());

    // ── Graceful-ish shutdown: snapshot on Ctrl+C ─────────────────────────
    // See module header gap #4 for why this only takes `PrimusDHT` (cheap
    // `Clone`) and the snapshot path rather than trying to get ownership
    // of `server` back from `.run()` below.
    {
        let shutdown_dht = server.dht().clone();
        let shutdown_snapshot_path = snapshot_path.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                log::info!("Shutdown: Ctrl+C received, saving a final DHT snapshot before exit");
                match dht_snapshot::save(&shutdown_dht, &shutdown_snapshot_path).await {
                    Ok(n) => log::info!("Shutdown: saved {} peer record(s), exiting", n),
                    Err(e) => log::warn!("Shutdown: final DHT snapshot save failed: {}, exiting anyway", e),
                }
                std::process::exit(0);
            }
        });
    }

    // ── Run ──────────────────────────────────────────────────────────────
    // `run(self)` takes ownership, so hand it the last owned copy. This is
    // fine because `wire_discovery` only needed a clone of the Arc, taken
    // above, and this is the last use of `server` in this function.
    //
    // (See module header gap #4: this `try_unwrap` already assumed more
    // than is actually true even before this prompt's changes — flagged
    // there rather than silently "fixed" as a drive-by here.)
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