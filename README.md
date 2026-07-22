# messenger
## Peer discovery: LAN discovery vs. internet bootstrap

primus-net-opt finds peers two ways. They solve different problems and are
both meant to run at the same time — neither one replaces the other.

### LAN discovery (`discovery.rs`)

- **Zero configuration.** A node broadcasts a UDP beacon (`PRIMUS_PEER:<port>`)
  every 10 seconds and listens for the same from others.
- **Scope: one broadcast domain.** UDP broadcast does not cross routers, so
  this only finds other nodes on the same LAN (or same Wi-Fi network, same
  Docker bridge network, etc.).
- **Use case:** two or more of your own nodes on one network find each other
  instantly with nothing to configure — useful for local testing, a home
  swarm, or a LAN party-style deployment.

### Internet bootstrap (`bootstrap.rs`)

- **Configured, not discovered.** You supply a short list of seed node
  addresses — via repeated `--seed <ip:port>` CLI flags, a `--seeds-file
  <path>` newline-separated list, or the `PRIMUS_SEEDS` /
  `PRIMUS_SEEDS_FILE` environment variables. Nothing is hardcoded into the
  binary.
- **Scope: anywhere on the internet.** A seed can be a friend's node across
  town or a VPS you rent specifically to act as a stable bootstrap point.
  There's no broadcast-domain limit.
- **What happens at startup:** each configured seed is dialed **sequentially**
  over the normal QUIC/Noise_XX path (the same `connect_to_peer` LAN
  discovery uses), with an 8-second timeout per attempt. An unreachable seed
  is logged at `warn` and skipped — one dead seed in the list never aborts
  startup. As soon as at least one seed connection succeeds, the node runs a
  single Kademlia `find_node` lookup against **its own NodeID**. That's the
  standard Kademlia bootstrap procedure: looking yourself up walks the DHT
  outward from the seed and fills in the routing-table buckets you'll
  actually use, instead of waiting for the first hourly maintenance refresh
  (`KademliaEngine::start_maintenance` in `lib.rs`) to do it.
- **Use case:** getting a node into the wider network the first time it
  runs, or when it has no LAN peers to bootstrap from at all (e.g. a
  freshly-provisioned VPS).

### Why both, not one or the other

- LAN discovery gives you peers with no configuration, but can't cross
  network boundaries.
- Internet bootstrap crosses network boundaries, but needs at least one
  known-good address to start from.
- Running both means a node on a LAN with no configured seeds still finds
  its LAN peers, a node with configured seeds but no LAN peers still joins
  the wider network, and a node with both gets the fastest, most complete
  picture of the network at startup. Neither path disables the other — they
  run concurrently and feed the same DHT / session table.

### Configuring seeds

```
# CLI flags (repeatable)
messenger --seed 203.0.113.10:9000 --seed 203.0.113.11:9000

# or a file, one "ip:port" per line, '#' comments allowed
messenger --seeds-file ./seeds.txt

# or environment variables (useful for containers)
PRIMUS_SEEDS=203.0.113.10:9000,203.0.113.11:9000 messenger
PRIMUS_SEEDS_FILE=/etc/primus/seeds.txt messenger
```

All sources can be combined; the resulting list is deduplicated. An empty
list is not an error — it just means the node relies on LAN discovery alone.