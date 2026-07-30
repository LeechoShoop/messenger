#!/bin/bash
# Script for quickly starting a Primus seed node

# 1. Set the port (default is 9000 if no argument is passed)
export PRIMUS_PORT=${1:-9000}

# 2. Enable logging to see incoming connections
export RUST_LOG=info

# 3. Set the directory for keys and DHT so they are stored next to the script
export PRIMUS_CONFIG_DIR="./primus-seed-data"

# Check and create the folder if it doesn't exist
mkdir -p "$PRIMUS_CONFIG_DIR"

echo "=========================================================="
echo "🚀 Starting Primus Seed Node..."
echo "📡 Port: $PRIMUS_PORT (ensure UDP is open in your firewall)"
echo "📁 Data is saved in: $PRIMUS_CONFIG_DIR"
echo "=========================================================="

# 4. Build and run the daemon in release profile for maximum performance
cargo run --release --bin messenger
