# ============================================================================
# BlackBook L1 -- Local Dev Launcher
# ============================================================================
# Usage:
#   .\dev.ps1              (writer mode, dev.redb)
#   .\dev.ps1 reader       (reader mode, reader.redb, syncs from Hetzner)
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
if ($Mode -eq "reader") {
    $env:NODE_MODE       = "reader"
    $env:REDB_PATH       = "blockchain_data/reader.redb"
    $env:WRITER_ADDR     = "http://91.98.196.34:50051"
    $env:WRITER_HTTP_URL = "http://91.98.196.34:8080"
    Write-Host "Mode: READER (syncing from 91.98.196.34)" -ForegroundColor Cyan
} else {
    $env:NODE_MODE  = "writer"
    $env:REDB_PATH  = "blockchain_data/dev.redb"
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
Write-Host "Starting BlackBook L1..." -ForegroundColor Green
.\target\debug\layer1.exe
