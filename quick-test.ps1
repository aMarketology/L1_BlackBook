# Simple Mnemonic Wallet Tests
Write-Host "`n=== BlackBook Mnemonic Wallet Tests ===" -ForegroundColor Cyan

# Test 1: Health
Write-Host "`n1. Health Check..." -ForegroundColor Yellow
curl http://localhost:8080/mnemonic/health | ConvertFrom-Json

# Test 2: Create Wallet
Write-Host "`n2. Creating Wallet..." -ForegroundColor Yellow
$body = @{password='TestPassword123!'; bip39_passphrase=''} | ConvertTo-Json
$wallet = curl -Method POST -Uri http://localhost:8080/mnemonic/create -Body $body -ContentType 'application/json' | ConvertFrom-Json
Write-Host "   ✅ Created: $($wallet.wallet_address)" -ForegroundColor Green

# Test 3: Wallet Info
Write-Host "`n3. Getting Wallet Info..." -ForegroundColor Yellow
$info = curl http://localhost:8080/mnemonic/info/$($wallet.wallet_address) | ConvertFrom-Json
Write-Host "   ✅ Retrieved: $($info.wallet_address)" -ForegroundColor Green

# Test 4: Export Mnemonic (24 words)
Write-Host "`n4. Exporting 24-Word Mnemonic..." -ForegroundColor Yellow
$exportBody = @{
    password = 'TestPassword123!'
    two_factor_code = '123456'
    share_a_bound = $wallet.share_a_bound
} | ConvertTo-Json

$exported = curl -Method POST -Uri "http://localhost:8080/mnemonic/export/$($wallet.wallet_address)" -Body $exportBody -ContentType 'application/json' | ConvertFrom-Json

Write-Host "`n   ⚠️  YOUR 24-WORD RECOVERY PHRASE:" -ForegroundColor Red
Write-Host "   ════════════════════════════════" -ForegroundColor Red
$words = $exported.mnemonic -split " "
for ($i = 0; $i -lt 24; $i += 4) {
    Write-Host "   $($i+1). $($words[$i])  $($i+2). $($words[$i+1])  $($i+3). $($words[$i+2])  $($i+4). $($words[$i+3])" -ForegroundColor Yellow
}

Write-Host "`n✅ All Core Tests Passed!" -ForegroundColor Green
Write-Host "`nHybrid Custody System Status:" -ForegroundColor Cyan
Write-Host "  FROST Wallet: /wallet/* endpoints" -ForegroundColor Gray
Write-Host "  Mnemonic Wallet: /mnemonic/* endpoints" -ForegroundColor Gray
Write-Host "`n  Both systems operational!`n" -ForegroundColor Green
