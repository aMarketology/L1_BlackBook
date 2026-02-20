# BlackBook L1 - TPS Benchmark Runner
#
# Quick start:
#   .\run-tps-benchmarks.ps1              # Real pipeline stress test (recommended)
#   .\run-tps-benchmarks.ps1 -K6          # HTTP load test (needs server running)
#   .\run-tps-benchmarks.ps1 -Criterion   # Criterion micro-benchmarks
#   .\run-tps-benchmarks.ps1 -All         # Everything
#
# Stress test flags passed through:
#   .\run-tps-benchmarks.ps1 -Accounts 200000 -Txs 100000 -Seconds 30

param(
    [switch]$Quick,           # Quick TPS discovery (cargo test find_max_tps)
    [switch]$K6,              # Run k6 HTTP load test against live server
    [switch]$Criterion,       # Full Criterion micro-benchmarks
    [switch]$All,             # Run everything
    [int]$Layer = 0,          # Stress test layer 1-4 (0 = all)
    [int]$Accounts = 100000,  # Number of accounts to pre-fund
    [int]$Txs = 50000,        # Transactions per batch
    [int]$Seconds = 10,       # Seconds for sustained load test
    [string]$BaseUrl = "http://localhost:8080"
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $PSScriptRoot

Write-Host ""
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         BlackBook L1 - TPS Benchmark Suite                      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Display system info
Write-Host "📊 System Information" -ForegroundColor Yellow
Write-Host "─────────────────────────────────────────────────────────────────"
$cpu = Get-WmiObject Win32_Processor | Select-Object -First 1
$ram = [math]::Round((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 2)
$cores = (Get-WmiObject Win32_Processor).NumberOfCores
$threads = (Get-WmiObject Win32_Processor).NumberOfLogicalProcessors

Write-Host "  CPU:     $($cpu.Name)"
Write-Host "  Cores:   $cores (Threads: $threads)"
Write-Host "  RAM:     ${ram} GB"
Write-Host ""

# ─────────────────────────────────────────────────────────────────────────────
# Function: Real pipeline stress test (the main test you want)
# ─────────────────────────────────────────────────────────────────────────────
function Run-StressTest {
    Write-Host "🔥 Running Real Pipeline Stress Test..." -ForegroundColor Magenta
    Write-Host "─────────────────────────────────────────────────────────────────"
    Write-Host "  Using: examples/stress_test.rs"
    Write-Host "  Tests: DashMap parallel, ReDB ACID, Sealevel scheduler, sustained load"
    Write-Host ""

    Push-Location $RootDir
    try {
        $layerArg = if ($Layer -gt 0) { "--layer $Layer" } else { "" }

        # Build the command string
        $cmd = "cargo run --release --example stress_test -- " +
               "--accounts $Accounts --txs $Txs --seconds $Seconds $layerArg"
        Write-Host "  Command: $cmd" -ForegroundColor DarkGray
        Write-Host ""
        Invoke-Expression $cmd
    } finally {
        Pop-Location
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Function: Quick TPS discovery (existing Rust test)
# ─────────────────────────────────────────────────────────────────────────────
function Run-QuickTPS {
    Write-Host "⚡ Running Quick TPS Discovery Test..." -ForegroundColor Magenta
    Write-Host "─────────────────────────────────────────────────────────────────"

    Push-Location $RootDir
    try {
        cargo test --release find_max_tps -- --ignored --nocapture
    } finally {
        Pop-Location
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Function: Criterion micro-benchmarks
# ─────────────────────────────────────────────────────────────────────────────
function Run-Criterion {
    Write-Host "📐 Running Criterion Micro-Benchmarks..." -ForegroundColor Magenta
    Write-Host "─────────────────────────────────────────────────────────────────"

    Push-Location $RootDir
    try {
        cargo bench --bench tps_benchmarks
    } finally {
        Pop-Location
    }

    Write-Host ""
    Write-Host "📁 HTML reports saved to: target/criterion/" -ForegroundColor Green
}

# ─────────────────────────────────────────────────────────────────────────────
# Function: k6 HTTP load test
# ─────────────────────────────────────────────────────────────────────────────
function Run-K6Tests {
    param([string]$Url)

    Write-Host "🌐 Running k6 HTTP Load Test..." -ForegroundColor Magenta
    Write-Host "─────────────────────────────────────────────────────────────────"
    Write-Host "  Target: $Url"
    Write-Host ""

    # Check k6 is installed
    $k6 = Get-Command k6 -ErrorAction SilentlyContinue
    if (-not $k6) {
        Write-Host "❌ k6 not found." -ForegroundColor Red
        Write-Host "   Install: winget install k6" -ForegroundColor Yellow
        Write-Host "   Or:      https://k6.io/docs/get-started/installation/" -ForegroundColor Yellow
        return
    }

    # Check server is running at /health (correct endpoint)
    try {
        $health = Invoke-RestMethod -Uri "$Url/health" -TimeoutSec 5
        Write-Host "✅ Server healthy: $($health.status)" -ForegroundColor Green
    } catch {
        Write-Host "❌ Server not responding at $Url/health" -ForegroundColor Red
        Write-Host "   Start the node in another terminal:" -ForegroundColor Yellow
        Write-Host "   cargo run --release" -ForegroundColor Yellow
        return
    }

    # Create results directory
    $resultsDir = Join-Path $RootDir "tests\load\results"
    if (-not (Test-Path $resultsDir)) {
        New-Item -ItemType Directory -Path $resultsDir | Out-Null
    }

    # Run k6 TPS benchmark (fixed endpoint version)
    Push-Location (Join-Path $RootDir "tests\load")
    try {
        k6 run k6-tps-benchmark.js `
            --env BASE_URL=$Url `
            --env TARGET_TPS=50000
    } finally {
        Pop-Location
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Main execution
# ─────────────────────────────────────────────────────────────────────────────
Write-Host ""

if ($All) {
    Run-StressTest
    Run-QuickTPS
    Run-Criterion
    Run-K6Tests -Url $BaseUrl
} elseif ($K6) {
    Run-K6Tests -Url $BaseUrl
} elseif ($Quick) {
    Run-QuickTPS
} elseif ($Criterion) {
    Run-Criterion
} else {
    # Default: real pipeline stress test
    Run-StressTest
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "✅ Benchmark complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Interpreting results:" -ForegroundColor Yellow
Write-Host "  Layer 1 (DashMap):    Raw scheduler speed. This is your headline TPS."
Write-Host "  Layer 2 (ReDB):       ACID persistence speed. Lower — this is durability cost."
Write-Host "  Layer 3 (Scheduler):  Realistic mix with conflict detection."
Write-Host "  Layer 4 (Sustained):  10s average — the number to publish."
Write-Host ""
Write-Host "To push higher TPS:" -ForegroundColor Yellow
Write-Host "  --accounts 500000    Larger account pool = fewer conflicts"
Write-Host "  --txs 200000         Bigger batches amortize scheduling overhead"
Write-Host ""
