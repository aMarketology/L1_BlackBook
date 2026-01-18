# BlackBook L1 ↔ L2 Integration Test Suite Runner
# PowerShell script to run all tests sequentially

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║        BLACKBOOK L1 ↔ L2 INTEGRATION TEST SUITE          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$tests = @(
    "test-01-l1-health.js",
    "test-02-l1-balances.js",
    "test-03-l2-health.js",
    "test-04-l2-balances.js",
    "test-05-l1-transfer.js",
    "test-06-bridge-initiate.js",
    "test-07-l2-markets.js",
    "test-08-credit-line.js"
)

$results = @()

foreach ($test in $tests) {
    Write-Host ""
    Write-Host "🚀 Running: $test" -ForegroundColor Yellow
    Write-Host ""
    
    $output = & node $test
    $exitCode = $LASTEXITCODE
    
    Write-Output $output
    
    $results += [PSCustomObject]@{
        Test = $test
        Passed = ($exitCode -eq 0)
    }
    
    Write-Host ""
    Write-Host "─" * 60 -ForegroundColor Gray
}

# Final Summary
Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                    FINAL SUMMARY                          ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$passedCount = ($results | Where-Object { $_.Passed }).Count
$failedCount = ($results | Where-Object { -not $_.Passed }).Count

foreach ($result in $results) {
    if ($result.Passed) {
        Write-Host "   ✅ $($result.Test)" -ForegroundColor Green
    } else {
        Write-Host "   ❌ $($result.Test)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "   Total: $($results.Count) test files"
Write-Host "   ✅ Passed: $passedCount" -ForegroundColor Green
Write-Host "   ❌ Failed: $failedCount" -ForegroundColor Red
Write-Host ""

if ($failedCount -eq 0) {
    Write-Host "🎉 ALL TESTS PASSED!" -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host "⚠️  $failedCount test file(s) had failures." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}
