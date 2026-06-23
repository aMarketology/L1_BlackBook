# ============================================================================
# BlackBook L1 -- Local Dev Launcher (v1.0.2)
# ============================================================================
# Usage:
#   .\dev.ps1              (writer mode, dev.redb)
#   .\dev.ps1 reader       (reader mode, reader.redb, syncs from Hetzner)
#   .\dev.ps1 validator    (validator mode, consults LeaderSchedule)
#   .\dev.ps1 build        (build only, no run)
# ============================================================================

param(
    [string]$Mode = "writer"
)

# 1. Kill any stale layer1 / cargo / rustc processes holding file locks
Write-Host "Clearing stale processes..." -ForegroundColor Yellow
Get-Process -Name layer1, cargo, rustc -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 600

# 2. Set environment based on mode
$cliArgs = @()
if ($Mode -eq "reader") {
    $env:REDB_PATH       = "blockchain_data/reader.redb"
    $env:WRITER_HTTP_URL = "http://91.98.196.34:8080"
    $cliArgs = @("--mode", "reader", "--writer-addr", "http://91.98.196.34:50051")
    Write-Host "Mode: READER (syncing from 91.98.196.34)" -ForegroundColor Cyan
} elseif ($Mode -eq "validator") {
    $env:REDB_PATH  = "blockchain_data/dev.redb"
    $cliArgs = @("--mode", "validator", "--identity", "cherry-writer")
    Write-Host "Mode: VALIDATOR (rotating leader schedule)" -ForegroundColor Magenta
} else {
    $env:REDB_PATH  = "blockchain_data/dev.redb"
    $cliArgs = @("--mode", "writer")
    Write-Host "Mode: WRITER (dev.redb)" -ForegroundColor Green
}

$env:RUST_LOG       = "info,layer1=info,tower_http=warn"
$env:RUST_BACKTRACE = "1"

# 3. Build
Write-Host "Building (features: unsafe_admin)..." -ForegroundColor Yellow
cargo build --features unsafe_admin
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed" -ForegroundColor Red
    exit 1
}

if ($Mode -eq "build") {
    Write-Host "Build complete" -ForegroundColor Green
    exit 0
}

# 4. Run
Write-Host "Starting BlackBook L1 v1.0.2..." -ForegroundColor Green
& .\target\debug\layer1.exe @cliArgs
