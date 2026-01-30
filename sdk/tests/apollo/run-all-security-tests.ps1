# APOLLO WALLET - COMPREHENSIVE SECURITY TEST RUNNER
# Runs all vulnerability tests in sequence

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║          APOLLO WALLET - COMPREHENSIVE SECURITY TEST SUITE           ║" -ForegroundColor Magenta
Write-Host "║                  Running All Vulnerability Tests                     ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

$startTime = Get-Date

# Change to the apollo directory
Set-Location "c:\Users\Allied Gaming\Documents\GitHub\L1_BlackBook\sdk\tests\apollo"

Write-Host "📍 Current directory: $(Get-Location)" -ForegroundColor Cyan
Write-Host ""

# Test 1: General Vulnerabilities
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "🔒 TEST SUITE 1: General Vulnerabilities" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

node test-apollo-vulnerabilities.js
$test1Status = $LASTEXITCODE

Write-Host ""
Write-Host "Press any key to continue to next test suite..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host ""

# Test 2: Cryptographic Attacks
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "🔐 TEST SUITE 2: Cryptographic Attacks" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

node test-apollo-crypto-attacks.js
$test2Status = $LASTEXITCODE

Write-Host ""
Write-Host "Press any key to continue to next test suite..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
Write-Host ""

# Test 3: Edge Cases & DoS
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "⚡ TEST SUITE 3: Edge Cases & DoS Attacks" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

node test-apollo-edge-cases.js
$test3Status = $LASTEXITCODE

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "╔══════════════════════════════════════════════════════════════════════╗" -ForegroundColor Magenta
Write-Host "║                    ALL TESTS COMPLETED                               ║" -ForegroundColor Magenta
Write-Host "╚══════════════════════════════════════════════════════════════════════╝" -ForegroundColor Magenta
Write-Host ""

Write-Host "📊 Test Suite Results:" -ForegroundColor Cyan
Write-Host "  Suite 1 (Vulnerabilities): " -NoNewline
if ($test1Status -eq 0) {
    Write-Host "✓ PASSED" -ForegroundColor Green
} else {
    Write-Host "✗ FAILED" -ForegroundColor Red
}

Write-Host "  Suite 2 (Crypto Attacks):  " -NoNewline
if ($test2Status -eq 0) {
    Write-Host "✓ PASSED" -ForegroundColor Green
} else {
    Write-Host "✗ FAILED" -ForegroundColor Red
}

Write-Host "  Suite 3 (Edge Cases):      " -NoNewline
if ($test3Status -eq 0) {
    Write-Host "✓ PASSED" -ForegroundColor Green
} else {
    Write-Host "✗ FAILED" -ForegroundColor Red
}

Write-Host ""
Write-Host "⏱️  Total Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Cyan
Write-Host ""

# Summary
$totalPassed = 0
if ($test1Status -eq 0) { $totalPassed++ }
if ($test2Status -eq 0) { $totalPassed++ }
if ($test3Status -eq 0) { $totalPassed++ }

Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
if ($totalPassed -eq 3) {
    Write-Host "✅ ALL TEST SUITES PASSED ($totalPassed/3)" -ForegroundColor Green
    Write-Host "   Apollo Wallet security is strong!" -ForegroundColor Green
} elseif ($totalPassed -gt 0) {
    Write-Host "⚠️  PARTIAL PASS ($totalPassed/3 suites)" -ForegroundColor Yellow
    Write-Host "   Some vulnerabilities detected. Review results." -ForegroundColor Yellow
} else {
    Write-Host "❌ ALL TEST SUITES FAILED (0/3)" -ForegroundColor Red
    Write-Host "   Critical security issues detected!" -ForegroundColor Red
}
Write-Host "═══════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

Write-Host "📄 Detailed report available in: SECURITY_REPORT.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
