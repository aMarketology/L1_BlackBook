# BlackBook L1 - TPS Benchmark Runner
# 
# Quick start script for running TPS benchmarks
# 
# Usage:
#   .\run-tps-benchmarks.ps1              # Run all benchmarks
#   .\run-tps-benchmarks.ps1 -Quick       # Quick TPS discovery only
#   .\run-tps-benchmarks.ps1 -K6          # Run k6 load test
#   .\run-tps-benchmarks.ps1 -Full        # Full benchmark suite

param(
    [switch]$Quick,      # Quick TPS discovery test
    [switch]$K6,         # Run k6 HTTP load test
    [switch]$Full,       # Full Criterion benchmarks
    [switch]$All,        # Run everything
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

# Function to run Rust benchmarks
function Run-RustBenchmarks {
    Write-Host "🦀 Running Rust Criterion Benchmarks..." -ForegroundColor Magenta
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

# Function to run quick TPS discovery
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

# Function to run k6 load tests
function Run-K6Tests {
    param([string]$Url)
    
    Write-Host "🌐 Running k6 HTTP Load Test..." -ForegroundColor Magenta
    Write-Host "─────────────────────────────────────────────────────────────────"
    Write-Host "  Target: $Url"
    Write-Host ""
    
    # Check k6 is installed
    $k6 = Get-Command k6 -ErrorAction SilentlyContinue
    if (-not $k6) {
        Write-Host "❌ k6 not found. Install with: winget install k6" -ForegroundColor Red
        return
    }
    
    # Check server is running
    try {
        $health = Invoke-RestMethod -Uri "$Url/mnemonic/health" -TimeoutSec 5
        Write-Host "✅ Server is healthy" -ForegroundColor Green
    } catch {
        Write-Host "❌ Server not responding at $Url" -ForegroundColor Red
        Write-Host "   Start the server first: cargo run --release" -ForegroundColor Yellow
        return
    }
    
    # Create results directory
    $resultsDir = Join-Path $RootDir "tests\load\results"
    if (-not (Test-Path $resultsDir)) {
        New-Item -ItemType Directory -Path $resultsDir | Out-Null
    }
    
    # Run k6 TPS benchmark
    Push-Location (Join-Path $RootDir "tests\load")
    try {
        k6 run k6-tps-benchmark.js --env BASE_URL=$Url
    } finally {
        Pop-Location
    }
}

# Main execution
Write-Host ""

if ($Quick -or (-not $K6 -and -not $Full -and -not $All)) {
    Run-QuickTPS
}

if ($Full -or $All) {
    Run-RustBenchmarks
}

if ($K6 -or $All) {
    Run-K6Tests -Url $BaseUrl
}

Write-Host ""
Write-Host "═════════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "✅ Benchmark complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Record baseline TPS numbers in docs/TPS_LOAD_TESTING_PLAN.md"
Write-Host "  2. Identify bottlenecks from benchmark results"
Write-Host "  3. Implement optimizations from the plan"
Write-Host "  4. Re-run benchmarks to measure improvement"
Write-Host ""
