// =============================================================================
// messenger-tui — Primus P2P messenger with a ratatui terminal UI
//
// STARTUP SEQUENCE (mirrors cli.rs exactly):
//   1.  install_panic_hook() — terminal restore on crash, BEFORE Tui::init
//   2.  rustls crypto provider — ring, same as cli.rs
//   3.  identity::load_or_generate_keypair -> PrimusNR::new
//   4.  KademliaEngine::new
//   5.  PrimusNetworkServer::new (async)
//   6.  NatService::open_world (best-effort UPnP)
//   7.  wire_discovery(Arc::clone(&server), port)
//   8.  dht_snapshot::load -> warm-start DHT
//   9.  bootstrap::bootstrap (spawned)
//  10.  dht_snapshot::spawn_periodic
//  11.  server.run_arc() spawned in background (Arc::clone then drop local Arc)
//  12.  Tui::init() — enter alternate screen / raw mode
//  13.  Event loop (50 ms tick)
//
// EVENT LOOP:
//   • crossterm::event::poll(50ms) on each iteration.
//   • Keyboard events dispatched to handle_key().
//   • On each tick (whether or not a key was pressed) re-render via ui::render.
//   • App::should_quit = true → break → Tui dropped → terminal restored.
//
// PANE NAVIGATION:
//   Tab          — cycle focus (Input ↔ PeerList)
//   ↑ / ↓       — scroll peer list when PeerList focused; chat scroll otherwise
//   Enter        — send message when Input focused and a peer is selected
//   Esc / q      — quit
//   Ctrl+C       — quit (crossterm sends this as Event::Key)
// =============================================================================

mod anim;
mod app;
mod terminal;
mod theme;
mod ui;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

use messenger::bootstrap;
use messenger::discovery::PrimusDiscovery;
use messenger::dht::PrimusDHT;
use messenger::dht_snapshot;
use messenger::identity;
use messenger::nat::NatService;
use messenger::peer::PrimusNR;
use messenger::server::{MessageIngress, PrimusNetworkServer};
use messenger_core::MessengerCore;
use messenger::KademliaEngine;
use sha3::Digest;

use app::{App, Focus};
use terminal::Tui;

pub enum TuiEvent {
    IncomingEnvelope(Vec<u8>, u8), // data, ttl
    DeliveryUpdate(messenger_core::MessageId, messenger_core::DeliveryResult),
    BootstrapStarted,
    BootstrapCompleted,
}

pub struct TuiIngress {
    tx: tokio::sync::mpsc::UnboundedSender<TuiEvent>,
}

#[async_trait::async_trait]
impl MessageIngress for TuiIngress {
    async fn on_envelope(&self, bytes: &[u8]) -> Result<bool> {
        match bincode::deserialize::<messenger::network::PrimusMessage>(bytes) {
            Ok(messenger::network::PrimusMessage::Envelope(data, ttl)) => {
                let _ = self.tx.send(TuiEvent::IncomingEnvelope(data, ttl));
                Ok(true)
            }
            Err(e) => {
                log::warn!("TuiIngress: failed to deserialize PrimusMessage: {}", e);
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

// ── Insecure QUIC client (identical to cli.rs) ────────────────────────────────

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
            &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct,
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

// ── Discovery wiring ──────────────────────────────────────────────────────────

async fn wire_discovery(
    server: Arc<PrimusNetworkServer<TuiIngress, KademliaEngine>>,
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
                            log::warn!("Discovery: bad address '{}': {}", addr_str, e);
                            return;
                        }
                    };
                    if server.sessions.contains_key(&target_addr) {
                        return;
                    }
                    if let Err(e) = server.connect_to_peer(target_addr).await {
                        log::warn!("Discovery: connect failed for {}: {}", target_addr, e);
                    }
                }
            })
            .await
        {
            log::error!("Discovery service exited: {}", e);
        }
    });
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // Install panic hook FIRST so a crash during setup still restores terminal.
    terminal::install_panic_hook();

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
    // ── Crypto provider ──────────────────────────────────────────────────────
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── Logging (to a file so it doesn't clobber the TUI) ───────────────────
    // When RUST_LOG is set and the terminal is in raw mode, writing to stderr
    // garbles the display. Route logs to a file via the log filter.
    // The TUI is not yet initialized here, so env_logger to stderr is fine
    // for startup errors. Once the TUI starts, file logging is preferred.
    env_logger::init();

    // ── Networking config ────────────────────────────────────────────────────
    let my_port: u16 = std::env::var("PRIMUS_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(messenger::server::P2P_PORT);
    let bind_addr: SocketAddr = format!("0.0.0.0:{my_port}").parse()?;
    let tls_domain =
        std::env::var("PRIMUS_TLS_DOMAIN").unwrap_or_else(|_| "primus.local".to_string());

    // ── Config directory ─────────────────────────────────────────────────────
    let config_dir = identity::config_dir().context("failed to resolve config directory")?;

    // ── Identity ─────────────────────────────────────────────────────────────
    let id = load_or_generate_identity(bind_addr, &config_dir)?;
    let node_id = id.local_nr.node_id();

    // ── Kademlia engine ──────────────────────────────────────────────────────
    let kademlia_endpoint = insecure_client::client_endpoint("0.0.0.0:0".parse()?)
        .context("failed to build Kademlia client endpoint")?;
    let kademlia = KademliaEngine::new(
        id.local_nr.clone(),
        kademlia_endpoint,
        id.ml_dsa_sk.clone(),
        tls_domain.clone(),
    );

    // ── Ingress ──────────────────────────────────────────────────────────────
    let (core_val, outbound_rx) = MessengerCore::new(node_id);
    let core = Arc::new(core_val);
    let (tui_tx, tui_rx) = tokio::sync::mpsc::unbounded_channel();
    let ingress = Arc::new(TuiIngress { tx: tui_tx.clone() });

    // ── Network server ───────────────────────────────────────────────────────
    let server = Arc::new(
        PrimusNetworkServer::new(
            bind_addr,
            ingress,
            Arc::clone(&kademlia),
            id.local_nr.clone(),
            id.ml_dsa_sk.clone(),
            tls_domain,
        )
        .await
        .context("failed to construct PrimusNetworkServer")?,
    );

    let (core_tx, mut core_rx) = tokio::sync::mpsc::unbounded_channel();
    let tui_tx_for_core = tui_tx.clone();
    tokio::spawn(async move {
        while let Some((msg_id, res)) = core_rx.recv().await {
            let _ = tui_tx_for_core.send(TuiEvent::DeliveryUpdate(msg_id, res));
        }
    });

    tokio::spawn(messenger_core::outbound::run_outbound_dispatch(
        Arc::clone(&server),
        outbound_rx,
        core.outbox(),
        Some(core_tx.clone()),
    ));

    tokio::spawn(messenger_core::pending_outbox::run_retry_loop(
        Arc::clone(&server),
        Arc::clone(&core),
        core.outbox(),
        Some(core_tx.clone()),
    ));

    // ── NAT / UPnP (best-effort) ─────────────────────────────────────────────
    match NatService::open_world(my_port).await {
        Ok(external_ip) => {
            let ext = SocketAddr::new(external_ip, my_port);
            server.set_external_addr(ext).await;
            log::info!("NAT: external address {ext}");
        }
        Err(e) => log::warn!("NAT: UPnP failed (staying LAN-only): {e}"),
    }

    // ── LAN discovery ────────────────────────────────────────────────────────
    wire_discovery(Arc::clone(&server), my_port).await;

    // ── DHT snapshot warm-start ──────────────────────────────────────────────
    let snapshot_path = dht_snapshot::snapshot_path(&config_dir);
    let snapshot_records = dht_snapshot::load(&snapshot_path);
    for nr in &snapshot_records {
        server.dht().insert(nr.clone(), server.as_ref()).await;
    }
    log::info!("DHT snapshot: warm-started with {} record(s)", snapshot_records.len());

    // ── Internet bootstrap ───────────────────────────────────────────────────
    {
        let server_for_bootstrap = Arc::clone(&server);
        let kademlia_for_bootstrap = Arc::clone(&kademlia);
        let local_id = id.local_nr.node_id();
        let mut seeds = bootstrap::load_seeds().unwrap_or_default();
        for nr in &snapshot_records {
            let addr = nr.addr();
            if !seeds.contains(&addr) {
                seeds.push(addr);
            }
        }
        let bootstrap_tx = tui_tx.clone();
        tokio::spawn(async move {
            let _ = bootstrap_tx.send(TuiEvent::BootstrapStarted);
            bootstrap::bootstrap(server_for_bootstrap, kademlia_for_bootstrap, seeds, local_id)
                .await;
            let _ = bootstrap_tx.send(TuiEvent::BootstrapCompleted);
        });
    }

    // ── Periodic DHT snapshot ────────────────────────────────────────────────
    dht_snapshot::spawn_periodic(server.dht().clone(), snapshot_path.clone());

    // ── Extract REPL handles and spawn server ────────────────────────────────
    let repl_dht = server.dht().clone();
    let repl_sessions = Arc::clone(&server.sessions);

    let server_for_run = Arc::clone(&server);
    tokio::spawn(async move {
        if let Err(e) = server_for_run.run_arc().await {
            log::error!("PrimusNetworkServer::run_arc exited with error: {e}");
        }
    });

    // ── Initialize TUI ───────────────────────────────────────────────────────
    // Panic hook is already in place from the very start of main().
    let mut tui = Tui::init().context("failed to initialize terminal UI")?;

    // ── Application state ────────────────────────────────────────────────────
    let theme_path = config_dir.join("theme.json");
    let theme = theme::Theme::load_or_default(&theme_path);
    let mut app = App::new(node_id, theme);
    app.set_status(format!(
        "NodeID: {}… | Listening on {bind_addr}",
        hex::encode(&node_id[..4])
    ));

    // ── Event loop ───────────────────────────────────────────────────────────
    run_event_loop(&mut tui, &mut app, repl_dht, repl_sessions, core, Arc::clone(&server), tui_rx, tui_tx).await?;

    // ── Graceful Shutdown ────────────────────────────────────────────────────
    drop(tui); // ensure terminal is clean before we print anything
    log::info!("Saving final DHT snapshot before exit...");
    let _ = dht_snapshot::save(server.dht(), &snapshot_path).await;

    Ok(())
}

// ── Event loop ────────────────────────────────────────────────────────────────

const TICK_RATE: Duration = Duration::from_millis(50);

async fn run_event_loop(
    tui: &mut Tui,
    app: &mut App,
    dht: PrimusDHT,
    sessions: Arc<dashmap::DashMap<SocketAddr, Arc<messenger::server::PeerSession>>>,
    core: Arc<MessengerCore>,
    server: Arc<PrimusNetworkServer<TuiIngress, KademliaEngine>>,
    mut tui_rx: tokio::sync::mpsc::UnboundedReceiver<TuiEvent>,
    tui_tx: tokio::sync::mpsc::UnboundedSender<TuiEvent>,
) -> Result<()> {
    let mut tick_count: u64 = 0;
    let mut tick_interval = tokio::time::interval(TICK_RATE);

    loop {
        // ── Render ────────────────────────────────────────────────────────────
        tui.draw(|frame| ui::render(frame, app))?;

        tokio::select! {
            _ = tick_interval.tick() => {
                while event::poll(Duration::from_secs(0))? {
                    match event::read()? {
                        Event::Key(key) => {
                            let old_peer = app.selected_peer;
                            handle_key(app, key, &core, &server, &tui_tx);
                            if app.selected_peer != old_peer {
                                refresh_chat(app, &core).await;
                            }
                        }
                        Event::Resize(_, _) => { /* ratatui handles resize automatically */ }
                        _ => {}
                    }
                }

                tick_count += 1;
                for peer in &mut app.peers {
                    peer.connected = sessions.contains_key(&peer.addr);
                }
                
                if tick_count % 20 == 0 {
                    refresh_peer_list(app, &dht, &sessions).await;
                    app.refresh_status();
                }
            }
            Some(tui_event) = tui_rx.recv() => {
                match tui_event {
                    TuiEvent::IncomingEnvelope(data, _ttl) => {
                        if let Ok(env) = bincode::deserialize::<messenger_core::Envelope>(&data) {
                            if env.kind == messenger_core::MessageKind::DeliveryReceipt {
                                if let Ok(payload) = bincode::deserialize::<messenger_core::ReceiptPayload>(&env.ciphertext) {
                                    if let Some(msg) = app.messages.iter_mut().find(|m| m.message_id == payload.message_id) {
                                        msg.status = app::ChatStatus::Delivered;
                                    }
                                }
                            }
                        }
                        
                        let _ = core.on_envelope(&data).await;
                        
                        if let Ok(env) = bincode::deserialize::<messenger_core::Envelope>(&data) {
                            if env.kind == messenger_core::MessageKind::DirectMessage {
                                if let Some(peer) = app.selected_peer_entry() {
                                    if env.sender_node_id == peer.node_id || env.recipient_node_id == peer.node_id {
                                        refresh_chat(app, &core).await;
                                        // The newly added message should animate
                                        if let Some(last) = app.messages.last_mut() {
                                            last.anim = Some(crate::anim::AnimState::new(std::time::Duration::from_millis(300), crate::anim::ease_out_quad));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    TuiEvent::DeliveryUpdate(msg_id, result) => {
                        if let Some(msg) = app.messages.iter_mut().find(|m| m.message_id == msg_id) {
                            if result == messenger_core::DeliveryResult::Failed {
                                msg.status = app::ChatStatus::Failed;
                            } else if msg.status == app::ChatStatus::Failed {
                                msg.status = app::ChatStatus::Sent;
                            }
                        }
                    }
                    TuiEvent::BootstrapStarted => {
                        app.bootstrap_running = true;
                    }
                    TuiEvent::BootstrapCompleted => {
                        app.bootstrap_running = false;
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

// ── Key handling ──────────────────────────────────────────────────────────────

fn handle_key(
    app: &mut App,
    key: KeyEvent,
    core: &Arc<MessengerCore>,
    server: &Arc<PrimusNetworkServer<TuiIngress, KademliaEngine>>,
    tui_tx: &tokio::sync::mpsc::UnboundedSender<TuiEvent>,
) {
    if key.kind != crossterm::event::KeyEventKind::Press {
        return;
    }

    // Ctrl+C / Ctrl+Q — quit regardless of focus.
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => {
                app.should_quit = true;
                return;
            }
            _ => {}
        }
    }

    match key.code {
        // ── Global ────────────────────────────────────────────────────────────
        KeyCode::Esc => {
            app.should_quit = true;
        }
        KeyCode::Tab => {
            app.focus = match app.focus {
                Focus::Input    => Focus::PeerList,
                Focus::PeerList => Focus::Input,
            };
        }
        KeyCode::Char('?') => {
            app.help_open = !app.help_open;
        }
        KeyCode::Left if key.modifiers.contains(KeyModifiers::ALT) => {
            app.prev_tab();
        }
        KeyCode::Right if key.modifiers.contains(KeyModifiers::ALT) => {
            app.next_tab();
        }
        KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::ALT) => {
            app.close_tab();
        }
        KeyCode::Left if key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.sidebar_width = app.sidebar_width.saturating_sub(2).max(10);
        }
        KeyCode::Right if key.modifiers.contains(KeyModifiers::SHIFT) => {
            app.sidebar_width = app.sidebar_width.saturating_add(2).min(100);
        }

        // ── Focus-specific ────────────────────────────────────────────────────
        _ => match app.focus {
            Focus::Input    => handle_key_input(app, key, core, server, tui_tx),
            Focus::PeerList => handle_key_peer_list(app, key),
        },
    }
}

fn handle_key_input(
    app: &mut App,
    key: KeyEvent,
    core: &Arc<MessengerCore>,
    server: &Arc<PrimusNetworkServer<TuiIngress, KademliaEngine>>,
    tui_tx: &tokio::sync::mpsc::UnboundedSender<TuiEvent>,
) {
    match key.code {
        KeyCode::Char(c) => app.insert_char(c),
        KeyCode::Backspace => app.backspace(),
        KeyCode::Left  => app.cursor_left(),
        KeyCode::Right => app.cursor_right(),
        KeyCode::Enter => {
            let text = app.take_input();
            if text.trim().is_empty() {
                return;
            }
            if app.open_tabs.is_empty() {
                app.set_status("⚠  No active tab — Tab to Peers pane and pick one");
                return;
            }
            
            let peer_id = app.open_tabs[app.active_tab_index];

            let sent_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            
            let mut hasher = sha3::Sha3_256::new();
            sha3::Digest::update(&mut hasher, b"primus-messenger-tui:msg");
            sha3::Digest::update(&mut hasher, &app.local_node_id);
            sha3::Digest::update(&mut hasher, &peer_id);
            sha3::Digest::update(&mut hasher, &sent_at.to_be_bytes());
            sha3::Digest::update(&mut hasher, text.as_bytes());
            let message_id: [u8; 32] = hasher.finalize().into();

            let envelope = messenger_core::Envelope {
                message_id,
                sender_node_id: app.local_node_id,
                recipient_node_id: peer_id,
                ciphertext: text.as_bytes().to_vec(),
                sent_at,
                kind: messenger_core::MessageKind::DirectMessage,
            };

            let core_clone = Arc::clone(core);
            let server_clone = Arc::clone(server);
            let tx_clone = tui_tx.clone();
            
            tokio::spawn(async move {
                let res = messenger_core::outbound::send_tracked_message(&core_clone, &server_clone, peer_id, envelope).await;
                let _ = tx_clone.send(TuiEvent::DeliveryUpdate(message_id, res));
            });
            app.set_status("↗ Sending message...");
            
            app.messages.push(app::ChatLine {
                message_id,
                sender_id: app.local_node_id,
                text,
                sent_at,
                is_mine: true,
                status: app::ChatStatus::Sent,
                anim: Some(crate::anim::AnimState::new(std::time::Duration::from_millis(300), crate::anim::ease_out_quad)),
            });
            app.chat_scroll = 0;
        }
        KeyCode::Up   => { app.chat_scroll = app.chat_scroll.saturating_add(1); }
        KeyCode::Down => { app.chat_scroll = app.chat_scroll.saturating_sub(1); }
        _ => {}
    }
}

fn handle_key_peer_list(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.select_prev_peer(),
        KeyCode::Down | KeyCode::Char('j') => app.select_next_peer(),
        KeyCode::Enter => {
            if let Some(peer) = app.selected_peer_entry() {
                app.open_tab(peer.node_id);
                app.chat_scroll = 0; // reset scroll when opening/switching conversation
                app.focus = Focus::Input;
            }
        }
        _ => {}
    }
}

// ── Peer list refresh ─────────────────────────────────────────────────────────

async fn refresh_peer_list(
    app: &mut App,
    dht: &PrimusDHT,
    sessions: &dashmap::DashMap<SocketAddr, Arc<messenger::server::PeerSession>>,
) {
    let records = dht.get_all_records().await;
    app.peers = records
        .into_iter()
        .map(|nr| {
            let addr = nr.addr();
            let connected = sessions.contains_key(&addr);
            // Consider peer to be dialing if not connected and we have sent a tracked message to it recently.
            // Wait, an easier approach is to check if any message in app.messages to/from this peer is Sent (not Delivered/Failed).
            let dialing = !connected && app.messages.iter().any(|m| m.status == app::ChatStatus::Sent && (m.sender_id == nr.node_id() || m.is_mine)); // Actually we just check global pending state or something. Let's just track it via `core.outbox()` or simply say it's dialing if `!connected` and there's a pending message.
            app::PeerEntry {
                node_id: nr.node_id(),
                addr,
                connected,
                dialing,
            }
        })
        .collect();

    // Keep selection valid if peer list shrank.
    if let Some(i) = app.selected_peer {
        if i >= app.peers.len() {
            app.selected_peer = if app.peers.is_empty() { None } else { Some(app.peers.len() - 1) };
        }
    }
}


async fn refresh_chat(app: &mut App, core: &MessengerCore) {
    if let Some(&peer_id) = app.open_tabs.get(app.active_tab_index) {
        let stored_msgs = core.conversation(&peer_id).await;
        app.messages = stored_msgs
            .into_iter()
            .map(|msg| app::ChatLine {
                message_id: msg.envelope.message_id,
                sender_id: msg.envelope.sender_node_id,
                text: String::from_utf8_lossy(&msg.envelope.ciphertext).into_owned(),
                sent_at: msg.envelope.sent_at,
                is_mine: msg.envelope.sender_node_id == app.local_node_id,
                status: match msg.status {
                    messenger_core::DeliveryStatus::Sent => app::ChatStatus::Sent,
                    messenger_core::DeliveryStatus::Delivered => app::ChatStatus::Delivered,
                    messenger_core::DeliveryStatus::Failed => app::ChatStatus::Failed,
                },
                anim: None, // Historical messages don't animate on load
            })
            .collect();
    } else {
        app.messages.clear();
    }
}
