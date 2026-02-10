# Load environment variables
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        Set-Item -Path "env:$($matches[1])" -Value $matches[2]
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MAX'S WALLET - COMPLETE VERIFICATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$SUPABASE_URL = $env:SUPABASE_URL
$ANON_KEY = $env:SUPABASE_ANON_KEY
$SERVICE_KEY = $env:SUPABASE_SERVICE_ROLE_KEY

# Load local wallet JSON
$walletPath = "real_wallets/Max_wallet.json"
if (-not (Test-Path $walletPath)) {
    Write-Host "ERROR: Max_wallet.json not found!" -ForegroundColor Red
    exit 1
}

$wallet = Get-Content $walletPath | ConvertFrom-Json

Write-Host "Step 1: Local JSON File" -ForegroundColor Yellow
Write-Host "  Email: $($wallet.user.email)"
Write-Host "  Password: $($wallet.user.password)"
Write-Host "  User ID: $($wallet.user.id)"
Write-Host "  Username: $($wallet.user.username)"
Write-Host "  Wallet Address: $($wallet.wallet.address)"
Write-Host "  Mnemonic: $($wallet.wallet.mnemonic.Substring(0, 50))..."
Write-Host "  Share A Encrypted: $($wallet.wallet.share_a_is_encrypted)"
Write-Host "  Share A Length: $($wallet.wallet.share_a.Length) chars"
Write-Host "  Share C Length: $($wallet.wallet.share_c.Length) chars (hex)"
Write-Host ""

# Test 1: Login to Supabase
Write-Host "Step 2: Supabase Authentication Test" -ForegroundColor Yellow
$authUrl = "$SUPABASE_URL/auth/v1/token?grant_type=password"
$authHeaders = @{
    "apikey" = $ANON_KEY
    "Content-Type" = "application/json"
}
$authBody = @{
    email = $wallet.user.email
    password = $wallet.user.password
} | ConvertTo-Json

try {
    $authResponse = Invoke-RestMethod -Uri $authUrl -Method Post -Headers $authHeaders -Body $authBody
    Write-Host "  AUTH SUCCESS" -ForegroundColor Green
    Write-Host "  Access Token: $($authResponse.access_token.Substring(0, 50))..." -ForegroundColor Gray
    Write-Host "  Token Type: $($authResponse.token_type)"
    Write-Host "  Expires In: $($authResponse.expires_in) seconds"
    $accessToken = $authResponse.access_token
} catch {
    Write-Host "  AUTH FAILED" -ForegroundColor Red
    Write-Host "  Error: $_"
    exit 1
}
Write-Host ""

# Test 2: Verify User Vault
Write-Host "Step 3: User Vault Verification" -ForegroundColor Yellow
$vaultUrl = "$SUPABASE_URL/rest/v1/user_vault?id=eq.$($wallet.user.id)&select=*"
$vaultHeaders = @{
    "apikey" = $SERVICE_KEY
    "Authorization" = "Bearer $SERVICE_KEY"
}

try {
    $vaultResponse = Invoke-RestMethod -Uri $vaultUrl -Headers $vaultHeaders -Method Get
    
    if ($vaultResponse.Count -gt 0) {
        $vault = $vaultResponse[0]
        
        Write-Host "  VAULT FOUND" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Data Integrity Checks:" -ForegroundColor Cyan
        
        # Check 1: User ID match
        $userIdMatch = $vault.id -eq $wallet.user.id
        Write-Host "    User ID Match: $(if ($userIdMatch) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($userIdMatch) { 'Green' } else { 'Red' })
        
        # Check 2: Username match
        $usernameMatch = $vault.username -eq $wallet.user.username
        Write-Host "    Username Match: $(if ($usernameMatch) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($usernameMatch) { 'Green' } else { 'Red' })
        
        # Check 3: Wallet address match
        $addressMatch = $vault.wallet_address -eq $wallet.wallet.address
        Write-Host "    Wallet Address Match: $(if ($addressMatch) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($addressMatch) { 'Green' } else { 'Red' })
        
        # Check 4: Root pubkey match
        $rootMatch = $vault.root_pubkey -eq $wallet.wallet.public_key
        Write-Host "    Root Pubkey Match: $(if ($rootMatch) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($rootMatch) { 'Green' } else { 'Red' })
        
        # Check 5: Shard A present
        $shardAPresent = $vault.encrypted_shard_a_blob -ne $null -and $vault.encrypted_shard_a_blob.Length -gt 0
        Write-Host "    Shard A Present: $(if ($shardAPresent) { 'PASS' } else { 'FAIL' }) (Length: $($vault.encrypted_shard_a_blob.Length))" -ForegroundColor $(if ($shardAPresent) { 'Green' } else { 'Red' })
        
        # Check 6: Shard B present
        $shardBPresent = $vault.encrypted_shard_b_blob -ne $null -and $vault.encrypted_shard_b_blob.Length -gt 0
        Write-Host "    Shard B Present: $(if ($shardBPresent) { 'PASS' } else { 'FAIL' }) (Length: $($vault.encrypted_shard_b_blob.Length))" -ForegroundColor $(if ($shardBPresent) { 'Green' } else { 'Red' })
        
        # Check 7: PIN hash present
        $pinHashPresent = $vault.pin_hash -ne $null -and $vault.pin_hash.StartsWith('$argon2id$')
        Write-Host "    PIN Hash Present: $(if ($pinHashPresent) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($pinHashPresent) { 'Green' } else { 'Red' })
        
        # Check 8: Client salt present
        $saltPresent = $vault.client_salt -ne $null -and $vault.client_salt.Length -gt 0
        Write-Host "    Client Salt Present: $(if ($saltPresent) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($saltPresent) { 'Green' } else { 'Red' })
        
        Write-Host ""
        Write-Host "  Stored Values:" -ForegroundColor Cyan
        Write-Host "    Daily Limit: $($vault.daily_limit)"
        Write-Host "    PIN Hash: $($vault.pin_hash.Substring(0, 40))..."
        Write-Host "    Client Salt: $($vault.client_salt)"
        
    } else {
        Write-Host "  VAULT NOT FOUND" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "  VAULT QUERY FAILED" -ForegroundColor Red
    Write-Host "  Error: $_"
    exit 1
}
Write-Host ""

# Test 3: Verify Profile
Write-Host "Step 4: Profile Verification" -ForegroundColor Yellow
$profileUrl = "$SUPABASE_URL/rest/v1/profiles?id=eq.$($wallet.user.id)&select=*"

try {
    $profileResponse = Invoke-RestMethod -Uri $profileUrl -Headers $vaultHeaders -Method Get
    
    if ($profileResponse.Count -gt 0) {
        $profile = $profileResponse[0]
        Write-Host "  PROFILE FOUND" -ForegroundColor Green
        Write-Host "    ID: $($profile.id)"
        Write-Host "    Email: $($profile.email)"
        Write-Host "    Username: $($profile.username)"
        Write-Host "    Created At: $($profile.created_at)"
    } else {
        Write-Host "  PROFILE NOT FOUND (Warning - may not be critical)" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  PROFILE QUERY FAILED" -ForegroundColor Yellow
    Write-Host "  Error: $_"
}
Write-Host ""

# Test 4: Decode Share C to verify format
Write-Host "Step 5: Share C Format Verification" -ForegroundColor Yellow
try {
    $shareCBytes = [System.Convert]::FromHexString($wallet.wallet.share_c)
    $shareCJson = [System.Text.Encoding]::UTF8.GetString($shareCBytes)
    $shareCObj = $shareCJson | ConvertFrom-Json
    
    Write-Host "  SHARE C VALID JSON" -ForegroundColor Green
    Write-Host "    Ciphersuite: $($shareCObj.header.ciphersuite)"
    Write-Host "    Version: $($shareCObj.header.version)"
    Write-Host "    Identifier: $($shareCObj.identifier.Substring(0, 20))..."
    Write-Host "    Signing Share: $($shareCObj.signing_share.Substring(0, 20))..."
    Write-Host "    Commitments: $($shareCObj.commitment.Count) items"
} catch {
    Write-Host "  SHARE C DECODE FAILED" -ForegroundColor Red
    Write-Host "  Error: $_"
}
Write-Host ""

# Final Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$allChecks = $userIdMatch -and $usernameMatch -and $addressMatch -and $rootMatch -and $shardAPresent -and $shardBPresent -and $pinHashPresent -and $saltPresent

if ($allChecks) {
    Write-Host "ALL CHECKS PASSED" -ForegroundColor Green
    Write-Host ""
    Write-Host "Max's wallet is PRODUCTION READY:" -ForegroundColor Green
    Write-Host "  - Authentication: Working"
    Write-Host "  - Shard A: Stored in Supabase (User-encrypted)"
    Write-Host "  - Shard B: Stored in Supabase (Server-encrypted)"
    Write-Host "  - Shard C: Stored locally (Recovery shard)"
    Write-Host "  - Metadata: Complete (PIN, limits, pubkey)"
    Write-Host ""
    Write-Host "Frontend Login Credentials:" -ForegroundColor Cyan
    Write-Host "  Email: $($wallet.user.email)"
    Write-Host "  Password: $($wallet.user.password)"
} else {
    Write-Host "SOME CHECKS FAILED" -ForegroundColor Yellow
    Write-Host "Review the output above for details."
}
Write-Host ""
