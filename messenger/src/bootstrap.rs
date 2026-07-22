// =============================================================================
// primus-net-opt/src/bootstrap.rs — Internet bootstrap via seed nodes
//
// WHAT THIS IS:
//   discovery.rs finds peers on the LAN with zero configuration (UDP
//   broadcast). That's necessary but not sufficient — broadcast doesn't
//   cross routers, so two nodes on different networks (a friend's machine
//   across town, a VPS you rent) will never see each other's beacons.
//   This module is the other half: a short, *configured* list of seed
//   addresses the operator supplies, dialed once at startup over the same
//   QUIC/Noise path as every other connection, purely to get the node's
//   first few DHT entries. See the README section at the bottom of this
//   file's companion doc comment (and README.md) for why both are kept.
//
// NO HARDCODED ADDRESSES:
//   `load_seeds()` never bakes an IP into the binary. It reads, in order
//   of precedence:
//     1. Repeated `--seed <ip:port>` CLI arguments
//     2. `--seeds-file <path>` — newline-separated `ip:port` list
//     3. `PRIMUS_SEEDS` env var — comma-separated `ip:port` list
//     4. `PRIMUS_SEEDS_FILE` env var — same file format as (2)
//   All four can be combined; results are deduplicated. An empty result
//   is not an error — a node with no configured seeds just relies on LAN
//   discovery alone, which is a legitimate configuration for a home LAN
//   swarm.
//
// FAILURE HANDLING:
//   Seeds are dialed sequentially (not concurrently — this is a one-time
//   startup cost against a short list, not a hot path, and sequential
//   dialing keeps the log output readable and avoids opening a burst of
//   simultaneous QUIC handshakes against unknown/possibly-down hosts).
//   Each dial is wrapped in a short per-attempt timeout. A failure or
//   timeout against any single seed is logged at `warn` and the loop
//   continues to the next seed — startup never aborts because one seed
//   in the list happens to be down.
//
// DHT POPULATION:
//   Once at least one seed connection succeeds, `connect_to_peer` has
//   already registered that peer in the DHT (see server.rs) — but a
//   single entry isn't a populated routing table. This module then runs
//   the same iterative `find_node` lookup that `KademliaEngine::
//   start_maintenance` runs every hour (lib.rs), except targeted at our
//   *own* NodeID and run once, immediately, at startup. That's the
//   standard Kademlia bootstrap procedure: looking up your own ID walks
//   the DHT outward from the seed and fills in the buckets closest to
//   you, which are the ones you'll actually use for routing.
//
//   If every seed dial fails, `find_node` is skipped — there is no
//   connected peer to query, and calling it anyway would just return
//   immediately with an empty result. LAN discovery (if any peers are on
//   the local network) remains free to populate the table on its own
//   independent path.
// =============================================================================

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use crate::dht::NodeID;
use crate::server::{KademliaHandler, MessageIngress, PrimusNetworkServer};
use crate::KademliaEngine;

/// Per-seed dial timeout. Generous enough for a slow WAN handshake
/// (QUIC connect + Noise_XX round trip), short enough that one dead seed
/// doesn't stall startup for long when the list has several entries.
const SEED_DIAL_TIMEOUT: Duration = Duration::from_secs(8);

/// Load seed addresses from CLI args, a seeds file, and/or environment
/// variables. See the module doc comment for precedence and format.
///
/// Malformed individual entries (a bad line in a seeds file, a bad
/// `--seed` value) are logged at `warn` and skipped — one typo in a
/// seeds file should not prevent the node from starting with the seeds
/// that *did* parse.
pub fn load_seeds() -> Result<Vec<SocketAddr>> {
    let mut seeds: Vec<SocketAddr> = Vec::new();

    // ── 1 & 2: CLI args ────────────────────────────────────────────────────
    let args: Vec<String> = std::env::args().collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seed" => {
                if let Some(val) = args.get(i + 1) {
                    push_parsed(&mut seeds, val, "--seed argument");
                    i += 1;
                } else {
                    log::warn!("Bootstrap: --seed given with no value, ignoring");
                }
            }
            "--seeds-file" => {
                if let Some(path) = args.get(i + 1) {
                    load_seeds_file(path, &mut seeds);
                    i += 1;
                } else {
                    log::warn!("Bootstrap: --seeds-file given with no path, ignoring");
                }
            }
            _ => {}
        }
        i += 1;
    }

    // ── 3: PRIMUS_SEEDS env var (comma-separated) ──────────────────────────
    if let Ok(val) = std::env::var("PRIMUS_SEEDS") {
        for entry in val.split(',') {
            let entry = entry.trim();
            if !entry.is_empty() {
                push_parsed(&mut seeds, entry, "PRIMUS_SEEDS env var");
            }
        }
    }

    // ── 4: PRIMUS_SEEDS_FILE env var ───────────────────────────────────────
    if let Ok(path) = std::env::var("PRIMUS_SEEDS_FILE") {
        load_seeds_file(&path, &mut seeds);
    }

    seeds.sort_by_key(|a| a.to_string());
    seeds.dedup();

    log::info!("Bootstrap: loaded {} seed address(es)", seeds.len());
    Ok(seeds)
}

fn load_seeds_file(path: &str, out: &mut Vec<SocketAddr>) {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Bootstrap: failed to read seeds file '{}': {}", path, e);
            return;
        }
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        push_parsed(out, line, path);
    }
}

fn push_parsed(out: &mut Vec<SocketAddr>, raw: &str, source: &str) {
    match raw.trim().parse::<SocketAddr>() {
        Ok(addr) => out.push(addr),
        Err(e) => log::warn!(
            "Bootstrap: skipping unparseable seed '{}' from {}: {}",
            raw,
            source,
            e
        ),
    }
}

/// Dial each seed sequentially with a per-attempt timeout, logging (and
/// continuing past) any failure. Returns the number of seeds we ended up
/// with an active session for.
///
/// A seed that's already connected (e.g. LAN discovery beat us to it) is
/// counted as a success without redialing — `connect_to_peer` itself is
/// a no-op in that case, this just reflects that in the return count.
pub async fn connect_seeds<M, K>(
    server: &Arc<PrimusNetworkServer<M, K>>,
    seeds: &[SocketAddr],
) -> usize
where
    M: MessageIngress,
    K: KademliaHandler,
{
    let mut connected = 0usize;

    for &seed in seeds {
        log::info!("Bootstrap: dialing seed {}", seed);

        match tokio::time::timeout(SEED_DIAL_TIMEOUT, server.connect_to_peer(seed)).await {
            Ok(Ok(())) => {
                connected += 1;
                log::info!("Bootstrap: seed {} reachable", seed);
            }
            Ok(Err(e)) => {
                log::warn!("Bootstrap: seed {} unreachable: {}", seed, e);
            }
            Err(_) => {
                log::warn!(
                    "Bootstrap: seed {} timed out after {:?}",
                    seed,
                    SEED_DIAL_TIMEOUT
                );
            }
        }
    }

    connected
}

/// Run the full startup bootstrap: dial configured seeds, and — if at
/// least one came up — run one Kademlia `find_node(local_id)` lookup to
/// seed the routing table via the standard "look up your own ID" bootstrap
/// procedure (the same lookup `KademliaEngine::start_maintenance` repeats
/// hourly in lib.rs, just triggered once immediately here instead of
/// waiting for the first maintenance tick).
///
/// Never fails startup: with zero seeds configured, or with every
/// configured seed unreachable, this simply logs and returns — LAN
/// discovery (discovery.rs) remains free to populate the table on its own.
pub async fn bootstrap<M, K>(
    server: Arc<PrimusNetworkServer<M, K>>,
    kademlia: Arc<KademliaEngine>,
    seeds: Vec<SocketAddr>,
    local_id: NodeID,
) where
    M: MessageIngress,
    K: KademliaHandler,
{
    if seeds.is_empty() {
        log::info!("Bootstrap: no seed addresses configured, relying on LAN discovery only");
        return;
    }

    let connected = connect_seeds(&server, &seeds).await;

    if connected == 0 {
        log::warn!(
            "Bootstrap: none of {} configured seed(s) were reachable; \
             routing table will only be populated via LAN discovery, if any",
            seeds.len()
        );
        return;
    }

    log::info!(
        "Bootstrap: {}/{} seed(s) reachable, running self-lookup to populate routing table",
        connected,
        seeds.len()
    );

    let found = kademlia.find_node(local_id).await;
    log::info!(
        "Bootstrap: self-lookup complete, {} node(s) known in routing table",
        found.len()
    );
}