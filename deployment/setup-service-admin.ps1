# ============================================================================
# BlackBook L1 — Elevation-Required Setup (run in an ADMIN PowerShell)
# ============================================================================
# This script does the parts that require Administrator rights:
#   1. Installs the NSSM service "BlackBookL1" pointing at the release binary,
#      with the repo root as the working directory (so .env / config.toml /
#      blockchain_data are found) and --mode writer.
#   2. (Optionally) registers a GitHub self-hosted runner as a Windows service.
#
# PREREQUISITES (already done for you):
#   - nssm installed           -> C:\...\NSSM.NSSM_...\win64\nssm.exe
#   - release binary built      -> target\release\layer1.exe
#
# USAGE (right-click PowerShell -> Run as Administrator):
#   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
#   & .\deployment\setup-service-admin.ps1
# ============================================================================

$ErrorActionPreference = "Stop"

$Repo = Split-Path -Parent $PSScriptRoot
$nssm = (Get-Command nssm -ErrorAction SilentlyContinue).Source
if (-not $nssm) {
    $nssm = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages" -Recurse -Filter nssm.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match 'win64' } | Select-Object -First 1 -ExpandProperty FullName
}
if (-not $nssm) { throw "nssm.exe not found. Install via: winget install NSSM.NSSM" }

$exe = Join-Path $Repo "target\release\layer1.exe"
if (-not (Test-Path $exe)) { throw "Release binary not found at $exe - run: cargo build --release" }

Write-Host "nssm   : $nssm"
Write-Host "binary : $exe"
Write-Host "workdir: $Repo"
Write-Host ""

# ── 1. Install the L1 node as a Windows service ─────────────────────────────
Write-Host "[1/2] Installing BlackBookL1 service..." -ForegroundColor Cyan

try { & $nssm stop BlackBookL1 } catch {}
try { & $nssm remove BlackBookL1 confirm } catch {}

& $nssm install BlackBookL1 $exe
# Arguments: run in writer mode (first mainnet node / block producer).
& $nssm set BlackBookL1 AppParameters "--mode writer"
# Working directory MUST be the repo root so .env is found next to the binary.
& $nssm set BlackBookL1 AppDirectory $Repo
# Auto-restart on crash, and start automatically at boot.
& $nssm set BlackBookL1 Start SERVICE_AUTO_START
& $nssm set BlackBookL1 AppExit Default Restart
& $nssm set BlackBookL1 AppRestartDelay 5000
# Display name + description
& $nssm set BlackBookL1 DisplayName "BlackBook L1 Node"
& $nssm set BlackBookL1 Description "BlackBook L1 permissioned settlement chain - first mainnet node"
# Rotate stdout/stderr to files under the repo so logs are inspectable.
& $nssm set BlackBookL1 AppStdout (Join-Path $Repo "blockchain_data\service-out.log")
& $nssm set BlackBookL1 AppStderr (Join-Path $Repo "blockchain_data\service-err.log")
& $nssm set BlackBookL1 AppRotateFiles 1
& $nssm set BlackBookL1 AppRotateBytes 10485760

# ── env vars the node reads from .env are NOT auto-injected by NSSM — the node
#    loads .env from its working directory itself. But REDB_PATH is a useful
#    explicit override to guarantee it uses the dev data file.
& $nssm set BlackBookL1 AppEnvironmentExtra "REDB_PATH=blockchain_data/dev.redb" "RUST_LOG=info,layer1=info,tower_http=warn" "RUST_BACKTRACE=1"

& $nssm start BlackBookL1
Write-Host "  Started BlackBookL1." -ForegroundColor Green

# ── 2. (Optional) GitHub self-hosted runner ─────────────────────────────────
Write-Host ""
Write-Host "[2/2] GitHub self-hosted runner" -ForegroundColor Cyan
Write-Host "  This step is INTERACTIVE and requires a runner registration token."
Write-Host "  Get it from: GitHub repo -> Settings -> Actions -> Runners -> New self-hosted runner."
Write-Host "  If you skip this, auto-update won't be wired (the service just runs forever)."
Write-Host ""
$skipRunner = Read-Host "  Register a GitHub self-hosted runner now? (y/N)"
if ($skipRunner -notmatch '^[yY]$') {
    Write-Host "  Skipped runner registration. You can re-run this section manually later." -ForegroundColor Yellow
} else {
    $RUNNER_DIR = "C:\actions-runner"
    New-Item -ItemType Directory -Path $RUNNER_DIR -Force | Out-Null
    Set-Location $RUNNER_DIR
    $token = Read-Host "  Paste the runner registration token"
    $url = Read-Host "  Repo URL (e.g. https://github.com/maxdeleonardis/L1_BlackBook)"
    $label = Read-Host "  Runner label (e.g. blackbook-local)"

    # Download the latest runner package and configure as a service.
    Invoke-WebRequest -Uri "https://github.com/actions/runner/releases/latest/download/actions-runner-win-x64-2.322.0.zip" -OutFile "runner.zip" -UseBasicParsing
    Expand-Archive -Path "runner.zip" -DestinationPath $RUNNER_DIR -Force
    .\config.cmd --url $url --token $token --name "blackbook-$env:COMPUTERNAME" --labels $label --runasservice --unattended
    Write-Host "  Runner configured as a service." -ForegroundColor Green
}

Write-Host ""
Write-Host "DONE. Verify with:" -ForegroundColor Green
Write-Host "  Get-Service BlackBookL1 | Select Name, Status"
Write-Host "  Invoke-RestMethod http://localhost:8080/health"