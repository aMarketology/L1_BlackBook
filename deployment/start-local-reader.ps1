# ============================================================================
# BlackBook L1 — Start Local Reader Node (syncs from Hetzner Writer)
# ============================================================================
# Usage:
#   .\deployment\start-local-reader.ps1 -WriterIP <HETZNER_IP>
#
# What it does:
#   - Builds the release binary (if needed)
#   - Starts a Reader node that mirrors the Hetzner Writer's chain state
#   - Applies the same GENESIS_SEEDS so the initial state matches
#   - Streams all subsequent blocks in real-time via gRPC (port 50051)
#
# Prerequisites:
#   - HETZNER port 50051 must be open from your local IP.
#     On the server run: ufw allow from <YOUR_IP> to any port 50051
#   - .env must exist in the repo root with GENESIS_SEEDS filled in
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

# Set local port overrides so Reader doesn't clash with any other local process
$env:HTTP_PORT  = $HttpPort
$env:RPC_PORT   = $RpcPort
$env:GRPC_PORT  = $GrpcPort

# Use a separate local DB so the Reader doesn't clobber a local Writer DB
$env:REDB_PATH  = Join-Path $RepoRoot "blockchain_data\reader.redb"

& $BinPath --mode reader --writer-addr "http://$WriterIP`:50051"
