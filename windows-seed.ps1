# Script for quickly starting a Primus seed node (Windows)

# 1. Set the port
$env:PRIMUS_PORT = if ($args.Length -gt 0) { $args[0] } else { "9000" }

# 2. Enable logging
$env:RUST_LOG = "info"

# 3. Set the directory for keys next to the script
$env:PRIMUS_CONFIG_DIR = ".\primus-seed-data"

# Check and create the folder if it doesn't exist
if (-Not (Test-Path -Path $env:PRIMUS_CONFIG_DIR)) {
    New-Item -ItemType Directory -Path $env:PRIMUS_CONFIG_DIR | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🚀 Starting Primus Seed Node..." -ForegroundColor Green
Write-Host "📡 Port: $env:PRIMUS_PORT (ensure UDP is open in your firewall)" -ForegroundColor Yellow
Write-Host "📁 Data is saved in: $env:PRIMUS_CONFIG_DIR" -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 4. Run
cargo run --release --bin messenger
