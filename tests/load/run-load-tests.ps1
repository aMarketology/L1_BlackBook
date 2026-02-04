# BlackBook L1 - Production Load Testing Suite
# Run from: tests/load/
#
# Prerequisites:
#   - Install k6: winget install k6 (or https://k6.io/docs/getting-started/installation/)
#   - BlackBook L1 server running on localhost:3000

param(
    [string]$BaseUrl = "http://localhost:3000",
    [int]$MaxVUs = 10000,
    [string]$Duration = "15m",
    [switch]$QuickTest,
    [switch]$SmokeTest,
    [switch]$StressTest,
    [switch]$SpikeTest,
    [switch]$Full
)

$ErrorActionPreference = "Stop"

Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     BlackBook L1 - Production Load Testing Suite              ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check k6 installation
$k6 = Get-Command k6 -ErrorAction SilentlyContinue
if (-not $k6) {
    Write-Host "❌ k6 not found. Install with: winget install k6" -ForegroundColor Red
    Write-Host "   Or download from: https://k6.io/docs/getting-started/installation/" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ k6 found: $($k6.Source)" -ForegroundColor Green

# Check server health
Write-Host ""
Write-Host "Checking server health at $BaseUrl..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/mnemonic/health" -TimeoutSec 5
    Write-Host "✅ Server is healthy" -ForegroundColor Green
} catch {
    Write-Host "❌ Server not responding at $BaseUrl" -ForegroundColor Red
    Write-Host "   Make sure the BlackBook L1 server is running." -ForegroundColor Yellow
    exit 1
}

# Determine test type
$testScript = "k6-comprehensive-load-test.js"
$k6Options = @()

if ($SmokeTest) {
    Write-Host ""
    Write-Host "🔥 SMOKE TEST - Quick validation (50 VUs, 1 minute)" -ForegroundColor Cyan
    $k6Options += "--vus", "50"
    $k6Options += "--duration", "1m"
} 
elseif ($QuickTest) {
    Write-Host ""
    Write-Host "🏃 QUICK TEST - Fast stress test (500 VUs, 3 minutes)" -ForegroundColor Cyan
    $k6Options += "--vus", "500"
    $k6Options += "--duration", "3m"
}
elseif ($StressTest -or $Full) {
    Write-Host ""
    Write-Host "💪 STRESS TEST - Full 10K concurrent users" -ForegroundColor Magenta
    Write-Host "   This will ramp up to $MaxVUs virtual users over $Duration" -ForegroundColor Yellow
    # Use the scenario defined in the script
}
elseif ($SpikeTest) {
    Write-Host ""
    Write-Host "⚡ SPIKE TEST - Sudden burst to 10K users" -ForegroundColor Red
    $k6Options += "--vus", "10000"
    $k6Options += "--duration", "5m"
    $k6Options += "--rps", "50000"
}
else {
    # Default: Quick test
    Write-Host ""
    Write-Host "🏃 Running default quick test (use -StressTest for full 10K)" -ForegroundColor Yellow
    $k6Options += "--vus", "500"
    $k6Options += "--duration", "3m"
}

# Create results directory
$resultsDir = ".\results"
if (-not (Test-Path $resultsDir)) {
    New-Item -ItemType Directory -Path $resultsDir | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$resultFile = "$resultsDir\load_test_$timestamp.json"

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host "Starting k6 load test..." -ForegroundColor Green
Write-Host "  Test script: $testScript"
Write-Host "  Base URL:    $BaseUrl"
Write-Host "  Results:     $resultFile"
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray
Write-Host ""

# Build k6 command
$k6Args = @(
    "run",
    "--env", "BASE_URL=$BaseUrl",
    "--out", "json=$resultFile"
) + $k6Options + @($testScript)

# Run k6
try {
    & k6 @k6Args
    $exitCode = $LASTEXITCODE
} catch {
    Write-Host "❌ k6 execution failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor DarkGray

if ($exitCode -eq 0) {
    Write-Host "✅ LOAD TEST PASSED" -ForegroundColor Green
    Write-Host "   All thresholds met!" -ForegroundColor Green
} else {
    Write-Host "⚠️  LOAD TEST COMPLETED WITH THRESHOLD VIOLATIONS" -ForegroundColor Yellow
    Write-Host "   Check the results for details." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Results saved to: $resultFile" -ForegroundColor Cyan
Write-Host ""

# Summary
Write-Host "╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                     LOAD TEST SUMMARY                         ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "Production Readiness Targets:" -ForegroundColor White
Write-Host "  ✓ HTTP errors        < 5%     (reliability)" -ForegroundColor Gray
Write-Host "  ✓ p95 latency        < 1000ms (performance)" -ForegroundColor Gray
Write-Host "  ✓ Health checks      > 99%    (availability)" -ForegroundColor Gray
Write-Host "  ✓ Rate limiting      Working  (security)" -ForegroundColor Gray
Write-Host ""
Write-Host "Run with different test profiles:" -ForegroundColor Yellow
Write-Host "  .\run-load-tests.ps1 -SmokeTest    # 50 VUs, 1 min" -ForegroundColor DarkGray
Write-Host "  .\run-load-tests.ps1 -QuickTest    # 500 VUs, 3 min" -ForegroundColor DarkGray
Write-Host "  .\run-load-tests.ps1 -StressTest   # 10K VUs, 15 min" -ForegroundColor DarkGray
Write-Host "  .\run-load-tests.ps1 -SpikeTest    # 10K instant spike" -ForegroundColor DarkGray
Write-Host ""

exit $exitCode
