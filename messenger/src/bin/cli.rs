// =============================================================================
// messenger-cli — minimal debug / demo CLI for the Primus P2P node
//
// WHAT THIS IS:
//   A single-binary debugging tool that spins up a full Primus network node
//   (identity, PrimusNetworkServer, LAN discovery, bootstrap, DHT snapshot)
//   and exposes a simple line-oriented REPL for interacting with it:
//
//   COMMANDS
//   ─────────────────────────────────────────────────────────────────────────
//   whoami
//       Print this node's NodeID (hex) and current listening address.
//
//   peers
//       List every peer currently known to the DHT routing table.
//       Format: <node_id_hex_short>…  <addr>
//
//   send <node_id_hex> <message...>
//       Look up <node_id_hex> in the DHT, connect if needed, then send the
//       remaining tokens as a UTF-8 gossip envelope (TTL=7).  The hex string
//       is matched as a prefix — you only need enough leading hex digits to
//       uniquely identify the target peer.
//
//   INCOMING MESSAGES
//   ─────────────────────────────────────────────────────────────────────────
//   Incoming DirectMessage envelopes are printed to stdout as they arrive:
//       [RECV ttl=N] <msg_id_hex_short>… (N bytes): <content>
//
// DESIGN NOTES
// ─────────────────────────────────────────────────────────────────────────────
//   • This is a debugging / demo tool, NOT the real client UI (that's
//     Cogitator's domain).  No TUI, no persistence, no message history.
//   • PrimusNetworkServer::run(self) takes ownership. We spawn it in a
//     background task after Arc::try_unwrap, then hold a second Arc for
//     the REPL commands. The server is kept alive by the background task;
//     the REPL Arc holds DHT + sessions state via the same server handles.
//     Because of this, wire_discovery() is called BEFORE the REPL Arc is
//     cloned away — see the startup sequence comments below.
//   • No clap / structopt — this stays dependency-minimal. Port and seeds
//     come from env vars (PRIMUS_PORT, PRIMUS_SEEDS, etc.) matching the
//     existing main.rs convention.
// =============================================================================

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::AsyncBufReadExt;

use messenger::bootstrap;
use messenger::dht_snapshot;
use messenger::discovery::PrimusDiscovery;
use messenger::dht::PrimusDHT;
use messenger::identity;
use messenger::nat::NatService;
use messenger::network::PrimusMessage;
use messenger::peer::PrimusNR;
use messenger::server::{MessageIngress, PrimusNetworkServer};
use messenger::KademliaEngine;

// ── CliIngress ────────────────────────────────────────────────────────────────

/// Prints each arriving gossip envelope to stdout.
///
/// Deserializes `PrimusMessage::Envelope(data, ttl)` from the raw bytes
/// handed to us by server.rs, then prints a one-line summary.  Non-envelope
/// variants (shouldn't exist on the QUIC path, but are handled gracefully)
/// are logged at warn level.
struct CliIngress;

#[async_trait::async_trait]
impl MessageIngress for CliIngress {
    async fn on_envelope(&self, bytes: &[u8]) -> Result<bool> {
        match bincode::deserialize::<PrimusMessage>(bytes) {
            Ok(PrimusMessage::Envelope(data, ttl)) => {
                let id = sha3_256_short(&data);
                let content = String::from_utf8_lossy(&data);
                println!("[RECV ttl={ttl}] {id}… ({} bytes): {content}", data.len());
                Ok(true)
            }
            Err(e) => {
                // Might be a raw non-PrimusMessage envelope from a future protocol
                // version.  Print the raw bytes as UTF-8 lossy so nothing is silently
                // swallowed.
                log::warn!("on_envelope: failed to deserialize PrimusMessage: {e}");
                let content = String::from_utf8_lossy(bytes);
                println!("[RECV raw] ({} bytes): {content}", bytes.len());
                Ok(true)
            }
        }
    }
}

// ── Identity ──────────────────────────────────────────────────────────────────

struct Identity {
    local_nr: PrimusNR,
    ml_dsa_sk: Vec<u8>,
}


fn load_or_generate_identity(addr: SocketAddr, config_dir: &Path) -> Result<Identity> {
    let passphrase = std::env::var(identity::PASSPHRASE_ENV_VAR).ok();
    if passphrase.is_some() {
        log::info!(
            "Identity: {} is set, using passphrase-encrypted storage",
            identity::PASSPHRASE_ENV_VAR
        );
    }
    let (ml_dsa_pk, ml_dsa_sk) =
        identity::load_or_generate_keypair(config_dir, passphrase.as_deref())
            .context("failed to load or generate the persistent node identity")?;

    let local_nr = PrimusNR::new(addr, &ml_dsa_pk, &ml_dsa_sk)
        .context("failed to build self-signed PrimusNR")?;

    Ok(Identity { local_nr, ml_dsa_sk })
}


// ── Insecure QUIC client for KademliaEngine's outbound endpoint ───────────────
//
// Same approach as main.rs — see that file's `insecure_client` mod comment
// for the full threat-model rationale (short version: TLS is bypassed because
// the actual peer authentication is the Noise_XX + ML-DSA layer in server.rs).

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
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
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

// ── LAN discovery wiring ──────────────────────────────────────────────────────

async fn wire_discovery(
    server: Arc<PrimusNetworkServer<CliIngress, KademliaEngine>>,
    my_port: u16,
) {
    let discovery = PrimusDiscovery::new(my_port, None);
    let server_for_discovery = Arc::clone(&server);

    tokio::spawn(async move {
        if let Err(e) = discovery
            .start(move |addr_str: String| {
                let server = Arc::clone(&server_for_discovery);
                async move {
                    let target_addr: SocketAddr = match addr_str.parse() {
                        Ok(a) => a,
                        Err(e) => {
                            log::warn!(
                                "Discovery: dropping beacon with unparseable address '{}': {}",
                                addr_str, e
                            );
                            return;
                        }
                    };
                    if server.sessions.contains_key(&target_addr) {
                        log::debug!("Discovery: {} already connected, skipping", target_addr);
                        return;
                    }
                    log::info!("Discovery: dialing new peer at {}", target_addr);
                    if let Err(e) = server.connect_to_peer(target_addr).await {
                        log::warn!("Discovery: connect_to_peer failed for {}: {}", target_addr, e);
                    }
                }
            })
            .await
        {
            log::error!("Discovery service exited: {}", e);
        }
    });
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// First 4 bytes of SHA3-256(data), formatted as 8 lowercase hex chars.
fn sha3_256_short(data: &[u8]) -> String {
    use sha3::{Digest, Sha3_256};
    let hash: [u8; 32] = Sha3_256::digest(data).into();
    hash[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// First 4 bytes of a node_id as 8 lowercase hex chars.
fn node_id_short(id: &[u8; 32]) -> String {
    id[..4].iter().map(|b| format!("{b:02x}")).collect()
}


// ── main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    println!("Future size: {}", std::mem::size_of_val(&async_main()));
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

    let bind_addr: SocketAddr = format!("0.0.0.0:{my_port}").parse()?;
    let tls_domain = std::env::var("PRIMUS_TLS_DOMAIN").unwrap_or_else(|_| "primus.local".to_string());

    // ── Config directory ────────────────────────────────────────────────────
    let config_dir = identity::config_dir().context("failed to resolve config directory")?;
    log::info!("Config directory: {}", config_dir.display());

    // ── Identity ────────────────────────────────────────────────────────────
    let identity_data = load_or_generate_identity(bind_addr, &config_dir)?;
    let node_id = identity_data.local_nr.node_id();
    println!(
        "[messenger-cli] NodeID: {}",
        hex::encode(node_id)
    );
    println!("[messenger-cli] Listening on: {bind_addr}");
    log::info!(
        "Identity loaded: NodeID {} at {}",
        &hex::encode(node_id)[..8],
        bind_addr
    );

    // ── Kademlia engine ─────────────────────────────────────────────────────
    let kademlia_endpoint = insecure_client::client_endpoint("0.0.0.0:0".parse()?)
        .context("failed to build Kademlia client endpoint")?;
    let kademlia = KademliaEngine::new(
        identity_data.local_nr.clone(),
        kademlia_endpoint,
        identity_data.ml_dsa_sk.clone(),
        tls_domain.clone(),
    );

    // ── Application ingress ─────────────────────────────────────────────────
    let ingress = Arc::new(CliIngress);

    // ── Network server ──────────────────────────────────────────────────────
    let server = Arc::new(
        PrimusNetworkServer::new(
            bind_addr,
            ingress,
            Arc::clone(&kademlia),
            identity_data.local_nr.clone(),
            identity_data.ml_dsa_sk.clone(),
            tls_domain,
        )
        .await
        .context("failed to construct PrimusNetworkServer")?,
    );

    // ── NAT / UPnP (best-effort) ────────────────────────────────────────────
    match NatService::open_world(my_port).await {
        Ok(external_ip) => {
            let ext = SocketAddr::new(external_ip, my_port);
            server.set_external_addr(ext).await;
            println!("[messenger-cli] NAT: external address {ext}");
        }
        Err(e) => log::warn!("NAT: UPnP failed (staying LAN-only): {e}"),
    }

    // ── LAN discovery ───────────────────────────────────────────────────────
    wire_discovery(Arc::clone(&server), my_port).await;

    // ── DHT snapshot warm-start ─────────────────────────────────────────────
    let snapshot_path = dht_snapshot::snapshot_path(&config_dir);
    let snapshot_records = dht_snapshot::load(&snapshot_path);
    if snapshot_records.is_empty() {
        log::info!("DHT snapshot: none at {}, starting cold", snapshot_path.display());
    } else {
        log::info!(
            "DHT snapshot: warm-starting with {} peer(s)",
            snapshot_records.len()
        );
        for nr in &snapshot_records {
            server.dht().insert(nr.clone(), server.as_ref()).await;
        }
    }

    // ── Internet bootstrap ──────────────────────────────────────────────────
    {
        let server_for_bootstrap = Arc::clone(&server);
        let kademlia_for_bootstrap = Arc::clone(&kademlia);
        let local_id = identity_data.local_nr.node_id();
        let mut seeds = bootstrap::load_seeds().unwrap_or_default();
        // Add snapshot addresses as extra bootstrap candidates.
        for nr in &snapshot_records {
            let addr = nr.addr();
            if !seeds.contains(&addr) {
                seeds.push(addr);
            }
        }
        tokio::spawn(async move {
            bootstrap::bootstrap(server_for_bootstrap, kademlia_for_bootstrap, seeds, local_id)
                .await;
        });
    }

    // ── Periodic DHT snapshot ───────────────────────────────────────────────
    dht_snapshot::spawn_periodic(server.dht().clone(), snapshot_path.clone());

    // ── Ctrl+C handler: final snapshot + exit ───────────────────────────────
    {
        let dht_for_shutdown = server.dht().clone();
        let path_for_shutdown = snapshot_path.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                log::info!("Ctrl+C — saving final DHT snapshot before exit");
                match dht_snapshot::save(&dht_for_shutdown, &path_for_shutdown).await {
                    Ok(n) => log::info!("Shutdown: saved {n} peer record(s)"),
                    Err(e) => log::warn!("Shutdown: snapshot save failed: {e}"),
                }
                std::process::exit(0);
            }
        });
    }

    // ── Spawn server.run_arc() in background; extract REPL handles ──────────
    //
    // run_arc(Arc<Self>) is the Arc-receiver variant of run(self) added to
    // server.rs for exactly this use-case: it clones all fields out of the
    // Arc at startup, then parks forever accepting connections.  Because it
    // takes Arc<Self> rather than consuming self, we can hold extra Arc clones
    // for REPL access without triggering try_unwrap failures.
    //
    // PrimusDHT is Clone and sessions is an Arc<DashMap> — both are cheap
    // to clone here before handing the server off to run_arc.
    let repl_dht      = server.dht().clone();
    let repl_sessions = Arc::clone(&server.sessions);
    let local_nr_for_repl = identity_data.local_nr.clone();


    // Spawn server accept loops via run_arc (QUIC + Kademlia maintenance).
    let server_for_run = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(e) = server_for_run.run_arc().await {
            log::error!("PrimusNetworkServer::run_arc exited with error: {e}");
        }
    });

    // Drop our own Arc — the spawned task's clone keeps the server alive.
    drop(server);


    // ── REPL ───────────────────────────────────────────────────────────────
    // Build a thin REPL context struct so we don't need the full server Arc.
    run_repl_direct(repl_dht, repl_sessions, local_nr_for_repl).await;

    Ok(())
}

// ── Direct REPL (uses pre-extracted DHT + sessions handles) ──────────────────
//
// This variant avoids needing to hold an Arc<PrimusNetworkServer> past the
// point where run_arc() takes its own Arc clone — we only need two things
// from the server for REPL commands:
//   • dht()  → PrimusDHT (cheaply Clone'd before server.run_arc())
//   • sessions → Arc<DashMap<…>> (Arc clone'd before server.run_arc())
// Plus connect_to_peer, which requires &self. Since we no longer have a
// full server ref, we can't call connect_to_peer from the REPL.
//
// Trade-off: `send` can only reach already-connected peers. If the target is
// not yet connected, we print a helpful message explaining how to add them
// (wait for discovery to pick them up, or run with --seed <addr>).
// This is acceptable for a debug tool; the real client UI (Cogitator) will
// handle session management properly.
async fn run_repl_direct(
    dht: PrimusDHT,
    sessions: Arc<dashmap::DashMap<SocketAddr, Arc<messenger::server::PeerSession>>>,
    local_nr: PrimusNR,
) {
    let stdin = tokio::io::stdin();
    let reader = tokio::io::BufReader::new(stdin);
    let mut lines = reader.lines();

    println!("\nmessenger-cli ready.");
    println!("Commands: whoami | peers | send <node_id_hex_prefix> <message...> | quit");
    print_prompt();

    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            Ok(None) => {
                println!("\n[EOF] REPL exiting.");
                break;
            }
            Err(e) => {
                log::error!("REPL stdin error: {e}");
                break;
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            print_prompt();
            continue;
        }

        let mut tokens = line.splitn(3, ' ');
        let cmd = tokens.next().unwrap_or("");
        let arg1 = tokens.next().unwrap_or("").trim();
        let rest = tokens.next().unwrap_or("").trim();

        match cmd {
            "quit" | "exit" | "q" => {
                println!("Goodbye.");
                std::process::exit(0);
            }

            "whoami" => {
                println!("NodeID : {}", hex::encode(local_nr.node_id()));
                println!("Listen : {}", local_nr.addr());
            }

            "peers" => {
                let peers = dht.get_all_records().await;
                if peers.is_empty() {
                    println!("(no peers in DHT yet — waiting for discovery/bootstrap)");
                } else {
                    println!("{:<18}  {}", "NodeID (prefix)", "Address");
                    println!("{}", "─".repeat(48));
                    for nr in &peers {
                        let id = nr.node_id();
                        let connected = if sessions.contains_key(&nr.addr()) { "✓" } else { " " };
                        println!("{}{:<18}  {}", connected, node_id_short(&id) + "…", nr.addr());
                    }
                    println!(
                        "({} peer(s); ✓ = active session)",
                        peers.len()
                    );
                }
            }

            "send" => {
                if arg1.is_empty() || rest.is_empty() {
                    println!("usage: send <node_id_hex_prefix> <message...>");
                    print_prompt();
                    continue;
                }

                // Resolve peer.
                let target_nr = match find_peer_by_hex_prefix_direct(&dht, arg1).await {
                    Some(nr) => nr,
                    None => {
                        println!("send: no peer with NodeID prefix '{arg1}' in DHT.");
                        println!("      Run 'peers' to see known nodes.");
                        print_prompt();
                        continue;
                    }
                };
                let target_addr = target_nr.addr();
                let target_id_short = node_id_short(&target_nr.node_id());

                // Check for open session.
                let session = sessions.get(&target_addr).map(|e| e.value().clone());
                match session {
                    None => {
                        println!(
                            "send: no active session with {target_id_short}… ({target_addr})."
                        );
                        println!(
                            "      Wait for discovery/bootstrap to connect, or restart with"
                        );
                        println!("      PRIMUS_SEEDS={target_addr} to seed that address.");
                    }
                    Some(s) => {
                        let data = rest.as_bytes().to_vec();
                        let envelope = PrimusMessage::Envelope(data.clone(), 7);
                        match bincode::serialize(&envelope) {
                            Err(e) => println!("send: serialization failed: {e}"),
                            Ok(payload) => match s.send_gossip(&payload).await {
                                Ok(()) => {
                                    let id = sha3_256_short(&data);
                                    println!(
                                        "[SENT ttl=7] {id}… ({} bytes) → {target_id_short}… ({target_addr}): {rest}",
                                        data.len()
                                    );
                                }
                                Err(e) => println!("send: send_gossip failed: {e}"),
                            },
                        }
                    }
                }
            }

            other => {
                println!(
                    "? unknown command '{other}'. Try: whoami | peers | send <id_hex> <msg> | quit"
                );
            }
        }

        print_prompt();
    }
}

/// Same as `find_peer_by_hex_prefix` but takes `&PrimusDHT` directly.
async fn find_peer_by_hex_prefix_direct(dht: &PrimusDHT, hex: &str) -> Option<PrimusNR> {
    // Normalise: strip any trailing "…" the user might have copy-pasted from
    // the peers output, then validate.
    let hex = hex.trim_end_matches('…').trim_end_matches("...");
    // Must be an even number of hex digits.
    if hex.is_empty() || hex.len() % 2 != 0 || hex.len() > 64 {
        return None;
    }
    let prefix: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect();
    if prefix.len() * 2 != hex.len() {
        // Some byte failed to parse.
        return None;
    }
    let all = dht.get_all_records().await;
    all.into_iter()
        .find(|nr| nr.node_id().starts_with(&prefix))
}

fn print_prompt() {
    use std::io::Write;
    print!("› ");
    let _ = std::io::stdout().flush();
}
