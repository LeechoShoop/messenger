// =============================================================================
// primus-net-opt/src/dht_snapshot.rs — periodic DHT peer-list persistence
//
// WHAT THIS IS:
//   Without this, every restart starts `PrimusDHT`'s routing table
//   completely empty — the node has to rediscover its entire peer set from
//   scratch via LAN discovery (discovery.rs) and/or the configured seed
//   list (bootstrap.rs) every single time. This module periodically writes
//   `PrimusDHT::get_all_records()` (dht.rs) to disk, and on the next
//   startup, main.rs feeds that snapshot back in two ways:
//     1. A direct warm-start insert into the routing table (cheap — the
//        table starts empty, so no bucket can be full yet and the
//        liveness-ping path in `RoutingTable::insert` is never actually
//        exercised by this).
//     2. The snapshot's addresses are added to the seed list from
//        bootstrap.rs (prompt 09) before `bootstrap::bootstrap()` runs, so
//        they also get a real dial + Noise handshake — confirming
//        liveness rather than just trusting stale on-disk data forever.
//   See main.rs for exactly where both of those happen.
//
// WHY SNAPSHOT PrimusNR RECORDS, NOT JUST ADDRESSES:
//   `PrimusDHT::get_all_records()` returns full `PrimusNR` values (address
//   + public key + self-signature), not bare `SocketAddr`s. Keeping the
//   full record means the warm-start insert (use #1 above) can populate
//   the routing table with something that's already been through
//   `PrimusNR::verify()` once (by virtue of having been in the table
//   before), rather than just a bag of addresses with no identity
//   attached to route by NodeID against.
//
// STALENESS IS EXPECTED AND HANDLED, NOT SPECIAL-CASED HERE:
//   A snapshot can be arbitrarily old (node was off for a week; a
//   snapshotted peer has since changed address or gone away for good).
//   This module does not attempt to validate freshness — it just
//   round-trips whatever `get_all_records()` returned at snapshot time.
//   Staleness is handled downstream, by mechanisms that already exist for
//   other reasons: `RoutingTable::insert`'s ping-on-full-bucket eviction
//   (dht.rs) will bump any snapshot-sourced entry that's gone unresponsive
//   out of a bucket the next time something else wants that bucket slot,
//   and `bootstrap::connect_seeds`'s per-seed timeout (bootstrap.rs) means
//   a dead snapshot address just gets logged and skipped on the dial
//   attempt, same as a dead entry from the operator-configured seed list.
//
// ATOMICITY:
//   `save()` writes to a `.tmp` sibling file and renames over the real
//   path, so a crash mid-write (or the periodic-snapshot tick racing the
//   shutdown-time save — see main.rs) never leaves a half-written,
//   unparseable snapshot for the *next* startup to trip over. `load()`
//   treats a missing OR unparseable file the same way: log and return an
//   empty list, never fail startup over stale bootstrap-hint data.
// =============================================================================

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use crate::dht::PrimusDHT;
use crate::peer::PrimusNR;

const SNAPSHOT_FILENAME: &str = "dht_snapshot.bin";

/// How often `spawn_periodic` writes a snapshot. Five minutes per the
/// requirement — frequent enough that a crash (as opposed to a graceful
/// shutdown, which snapshots separately — see main.rs) loses at most a few
/// minutes of newly-discovered peers, infrequent enough that it's not
/// meaningfully disk I/O pressure for a routing table capped at
/// `dht::K * dht::NBUCKETS` entries (20 * 256 = 5120 max, realistically
/// far fewer).
pub const SNAPSHOT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Where the snapshot lives, given the shared config directory (see
/// `identity::config_dir()` — this module intentionally doesn't duplicate
/// that resolution logic, callers pass the same directory to both).
pub fn snapshot_path(config_dir: &Path) -> PathBuf {
    config_dir.join(SNAPSHOT_FILENAME)
}

/// Write the DHT's current set of known peer records to `path`.
/// Returns the number of records written.
pub async fn save(dht: &PrimusDHT, path: &Path) -> Result<usize> {
    let records = dht.get_all_records().await;
    let bytes = bincode::serialize(&records).context("failed to serialize DHT snapshot")?;

    let tmp_path = path.with_extension("tmp");
    std::fs::write(&tmp_path, &bytes)
        .with_context(|| format!("failed to write DHT snapshot temp file {}", tmp_path.display()))?;
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("failed to finalize DHT snapshot at {}", path.display()))?;

    Ok(records.len())
}

/// Load a previously-saved snapshot, if present. Absence (first run, or
/// the file was cleared by hand) is not an error — returns an empty Vec,
/// same as a corrupt/unparseable file (logged at `warn` rather than
/// failing startup — see module doc comment).
pub fn load(path: &Path) -> Vec<PrimusNR> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            log::warn!("DHT snapshot: failed to read {}: {}", path.display(), e);
            return Vec::new();
        }
    };

    match bincode::deserialize::<Vec<PrimusNR>>(&bytes) {
        Ok(records) => records,
        Err(e) => {
            log::warn!(
                "DHT snapshot: failed to parse {} ({}), ignoring stale/corrupt snapshot and \
                 starting cold instead of failing startup over it",
                path.display(),
                e
            );
            Vec::new()
        }
    }
}

/// Spawn a background task that saves a snapshot every `SNAPSHOT_INTERVAL`.
/// Runs until the process exits. `PrimusDHT` is cheaply `Clone` (see
/// dht.rs — it's an `Arc<RoutingTable>` plus an `Arc<RwLock<Vec<String>>>`
/// under the hood), so this doesn't need shared ownership of the whole
/// `PrimusNetworkServer` — just the DHT handle and the target path.
///
/// This loop's ticks alone don't cover a clean shutdown — "connected to
/// three new peers, then Ctrl+C ninety seconds later" would lose those
/// three without a *separate* save on shutdown. See main.rs's Ctrl+C
/// handler for that half.
pub fn spawn_periodic(dht: PrimusDHT, path: PathBuf) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(SNAPSHOT_INTERVAL);
        // The first tick fires immediately; skip it so we don't snapshot a
        // still-essentially-empty table one tick after startup, before the
        // warm-start insert and the bootstrap dials have had time to
        // actually populate it.
        interval.tick().await;
        loop {
            interval.tick().await;
            match save(&dht, &path).await {
                Ok(n) => log::info!(
                    "DHT snapshot: saved {} peer record(s) to {}",
                    n,
                    path.display()
                ),
                Err(e) => log::warn!("DHT snapshot: periodic save failed: {}", e),
            }
        }
    });
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_missing_file_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let records = load(&snapshot_path(dir.path()));
        assert!(records.is_empty());
    }

    #[test]
    fn load_corrupt_file_returns_empty_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = snapshot_path(dir.path());
        std::fs::write(&path, b"not a valid bincode snapshot").unwrap();
        let records = load(&path);
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn save_then_load_empty_table_round_trips_to_empty_vec() {
        // Build a PrimusDHT for a throwaway local_id — no real PrimusNR
        // needed for an empty-table round trip.
        let dir = tempfile::tempdir().unwrap();
        let path = snapshot_path(dir.path());

        // PrimusDHT::new() takes &PrimusNR just to seed `local_id`
        // (node_id() = SHA3-256(public_key)) — it never checks the
        // signature at construction time. Building it via struct literal
        // (all fields are `pub`, same pattern peer.rs's own tests use)
        // avoids exercising the real ML-DSA signing path, which is out of
        // scope for this narrow save/load-format test.
        let addr: std::net::SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let local_nr = crate::peer::PrimusNR {
            public_key: vec![7u8; crate::peer::PUBLIC_KEY_LEN],
            addr,
            signature: vec![],
        };
        let dht = PrimusDHT::new(&local_nr);

        let n = save(&dht, &path).await.unwrap();
        assert_eq!(n, 0);

        let loaded = load(&path);
        assert!(loaded.is_empty());
    }
}