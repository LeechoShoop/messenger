# Primus Messenger

Primus is a highly decentralized, peer-to-peer (P2P) messaging network written in Rust. It aims to provide a robust, resilient communication layer that operates entirely without central servers. Emphasizing modern cryptography and network flexibility, Primus is built from the ground up to resist post-quantum computing threats.

## 🌟 Key Features

- **Decentralized Network (P2P):** Operates on a pure peer-to-peer topology using a custom **Kademlia DHT** (Distributed Hash Table) for routing and discovering nodes.
- **Post-Quantum Cryptography (PQC):** Utilizes **ML-DSA-87 (Dilithium)** for node identities and signatures, securing the network against quantum computing threats.
- **End-to-End Encryption (E2EE):** Incorporates the **Noise Protocol Framework** (using the `Noise_XX` handshake pattern). Connections use ML-DSA signatures for self-sovereign authentication—eliminating the need for centralized Certificate Authorities (CAs).
- **Modern Transports:** 
  - **QUIC** (via `quinn`) for high-performance, low-latency, and encrypted native P2P communication.
  - **WebTransport** (via `wtransport`) to eventually allow lightweight clients, such as browsers (WASM), to connect directly to the network.
- **Resilient Delivery:** Implements a robust Gossip protocol (`GossipRelay`) to broadcast messages across the network.
- **Auto-Discovery & NAT Traversal:** Built-in LAN discovery via UDP broadcasting and automatic port forwarding via UPnP.

## 🚀 Getting Started

### Prerequisites

You will need the Rust toolchain installed on your machine.
- [Install Rust](https://www.rust-lang.org/tools/install)

### Building and Running

The project consists of a core library (`messenger`) and three main binaries.

1. **Run the Messenger TUI (Terminal UI)**
   A rich, ratatui-based terminal application for chatting, featuring resizable panes, conversation tabs, themes, and animated message delivery.
   ```bash
   cargo run --bin messenger-tui
   ```
   *Features: Press `?` for keybindings, `Alt+Left/Right` to switch tabs, `Shift+Left/Right` to resize sidebar.*

2. **Run the Messenger CLI**
   A minimal, interactive REPL for interacting with the network, sending messages, and checking peers.
   ```bash
   cargo run --bin messenger-cli
   ```
   *Available commands in the CLI: `whoami`, `peers`, `send <node_id> <message>`, `quit`.*

3. **Run the Messenger Daemon**
   Runs the network node in the background without any interactive UI.
   ```bash
   cargo run --bin messenger
   ```

## 📡 Peer Discovery: LAN vs. Internet Bootstrap

Primus finds peers in two concurrent ways. They solve different problems and are both meant to run at the same time — neither one replaces the other.

### 1. LAN Discovery (`discovery.rs`)

- **Zero configuration:** A node broadcasts a UDP beacon (`PRIMUS_PEER:<port>`) every 10 seconds and listens for the same from others.
- **Scope:** Limited to one broadcast domain (e.g., local Wi-Fi, LAN).
- **Use case:** Automatic local swarm setups or LAN-party deployments.

### 2. Internet Bootstrap (`bootstrap.rs`)

- **Configured, not discovered:** You supply a short list of seed node addresses. Nothing is hardcoded into the binary.
- **Scope:** Anywhere on the internet.
- **What happens at startup:** Configured seeds are dialed sequentially over the QUIC/Noise_XX path. Upon the first successful connection, the node performs a Kademlia `find_node` lookup against its own NodeID to populate its routing table.
- **Use case:** Joining the wider global network for the first time or running a node on a VPS.

#### Configuring Seeds

You can configure internet seeds using environment variables (useful for Docker containers):

```bash
# Comma-separated list of IP:PORT
PRIMUS_SEEDS=203.0.113.10:9000,203.0.113.11:9000 cargo run --bin messenger-cli

# Or point to a file containing one "ip:port" per line
PRIMUS_SEEDS_FILE=/etc/primus/seeds.txt cargo run --bin messenger-cli
```

All sources are combined and deduplicated. An empty list is not an error — it just means the node will rely solely on LAN discovery.

## 🏗 Architecture Overview

- **Kademlia Engine (`dht.rs`, `lib.rs`):** Maintains buckets of known peers, calculates XOR distances for routing, and handles hourly maintenance refreshes.
- **Identity (`identity.rs`):** Manages the generation and persistence of the ML-DSA-87 keypair. Saves configuration and key data to the OS's local app data directory (e.g., `~/.config/primus/`).
- **Networking Server (`server.rs`):** The core asynchronous networking hub (`PrimusNetworkServer`). Binds both QUIC and WebTransport listeners, handling incoming connections concurrently.
- **Noise Handshake (`noise.rs`):** Encapsulates the Noise_XX handshake state machine to ensure both sides cryptographically prove their identity (Node Record) before application-layer data is exchanged.