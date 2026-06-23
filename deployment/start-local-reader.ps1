# ============================================================================
# BlackBook L1 — Start Local Validator Node (syncs from Cherry Writer) — v1.0.2
# ============================================================================
# Usage:
#   .\deployment\start-local-reader.ps1 -WriterIP <CHERRY_IP>
#
# What it does:
#   - Builds the release binary (if needed)
#   - Starts a Validator node that mirrors the Cherry Writer's chain state
#   - Applies the same GENESIS_SEEDS so the initial state matches
#   - Streams all subsequent blocks in real-time via gRPC (port 50051)
#   - Participates in rotating leader schedule when it's this node's turn
#
# Prerequisites:
#   - Cherry port 50051 must be open from your local IP.
#     On the server run: ufw allow from <YOUR_IP> to any port 50051
#   - .env must exist in the repo root with GENESIS_SEEDS filled in
#   - config.toml must list this node's pubkey + stake
# ============================================================================
param(
    [Parameter(Mandatory=$true)]
    [string]$WriterIP,

    [string]$HttpPort  = "8080",
    [string]$RpcPort   = "8899",
    [string]$GrpcPort  = "50051",
    [switch]$Release
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path $PSScriptRoot -Parent
$EnvFile  = Join-Path $RepoRoot ".env"

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════╗"
Write-Host "║    BlackBook L1 — Local Reader Node                  ║"
Write-Host "╠═══════════════════════════════════════════════════════╣"
Write-Host "║  Writer : http://$WriterIP`:50051"
Write-Host "║  Local  : http://localhost:$HttpPort"
Write-Host "╚═══════════════════════════════════════════════════════╝"
Write-Host ""

# ── 1. Load local .env ────────────────────────────────────────
if (-Not (Test-Path $EnvFile)) {
    Write-Host "❌  .env not found at $EnvFile"
    Write-Host "    cp .env.template .env  →  fill in SERVER_MASTER_KEY + GENESIS_SEEDS"
    exit 1
}

# Parse .env into process environment
Get-Content $EnvFile | Where-Object { $_ -match "^\s*[^#]\w+=.+" } | ForEach-Object {
    $kv = $_ -split "=", 2
    $key = $kv[0].Trim()
    $val = $kv[1].Trim()
    [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
}
Write-Host "✅ Loaded .env"

# ── 2. Build binary if needed ─────────────────────────────────
Set-Location $RepoRoot
if ($Release) {
    $BinPath = Join-Path $RepoRoot "target\release\layer1.exe"
    if (-Not (Test-Path $BinPath)) {
        Write-Host "[1/2] Building release binary (this takes ~5 min)..."
        cargo build --release --bin layer1
    }
} else {
    $BinPath = Join-Path $RepoRoot "target\debug\layer1.exe"
    if (-Not (Test-Path $BinPath)) {
        Write-Host "[1/2] Building debug binary..."
        cargo build --bin layer1
    }
}
Write-Host "✅ Binary ready: $BinPath"

# ── 3. Start Reader node ──────────────────────────────────────
Write-Host "[2/2] Starting Reader node..."
Write-Host ""
Write-Host "  Syncing from: http://$WriterIP`:50051"
Write-Host "  API at:       http://localhost:$HttpPort"
Write-Host "  RPC at:       http://localhost:$RpcPort"
Write-Host ""
Write-Host "  Press Ctrl+C to stop."
Write-Host ""

# Use a separate DB for the Reader so it never touches the local Writer's blockchain.redb.
# Pass as a CLI flag (--redb-path) so it takes priority over any REDB_PATH in .env.
$ReaderDb = Join-Path $RepoRoot "blockchain_data\reader.redb"

& $BinPath `
    --mode reader `
    --writer-addr "http://$WriterIP`:50051" `
    --http-port $HttpPort `
    --rpc-port $RpcPort `
    --grpc-port $GrpcPort `
    --redb-path $ReaderDb
