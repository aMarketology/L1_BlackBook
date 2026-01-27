# PowerShell Test Runner for BlackBook L1

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   BLACKBOOK L1 - WALLET & SECURITY TEST SUITE                         ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check if server is running
try {
    $health = Invoke-RestMethod -Uri "http://localhost:8080/health" -Method Get -TimeoutSec 5
    Write-Host "✓ Server is running" -ForegroundColor Green
} catch {
    Write-Host "✗ Server not reachable at http://localhost:8080" -ForegroundColor Red
    Write-Host "  Start the server with: cargo run" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# Define tests
$tests = @(
    @{ file = "test-01-server-health.js"; name = "Server Health" },
    @{ file = "test-02-wallet-creation.js"; name = "Wallet Creation" },
    @{ file = "test-03-wallet-funding.js"; name = "Wallet Funding" },
    @{ file = "test-04-secure-transfer.js"; name = "Secure Transfer" },
    @{ file = "test-05-secure-burn.js"; name = "Secure Burn" },
    @{ file = "test-06-sss-recovery.js"; name = "SSS Recovery" },
    @{ file = "test-07-wallet-security.js"; name = "Wallet Security" },
    @{ file = "test-08-full-lifecycle.js"; name = "Full Lifecycle" }
)

$passed = 0
$failed = 0

foreach ($test in $tests) {
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    Write-Host "  RUNNING: $($test.name)" -ForegroundColor Magenta
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Magenta
    
    $result = node $test.file
    
    if ($LASTEXITCODE -eq 0) {
        $passed++
    } else {
        $failed++
        Write-Host ""
        Write-Host "Test failed. Stopping." -ForegroundColor Red
        break
    }
}

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor White
Write-Host "  SUMMARY: Passed: $passed  |  Failed: $failed" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor White

if ($failed -eq 0) {
    Write-Host ""
    Write-Host "✨ ALL TESTS PASSED! ✨" -ForegroundColor Green
    Write-Host ""
} else {
    exit 1
}
