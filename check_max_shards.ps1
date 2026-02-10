# Load environment variables
Get-Content .env | ForEach-Object {
    if ($_ -match '^([^=]+)=(.*)$') {
        Set-Item -Path "env:$($matches[1])" -Value $matches[2]
    }
}

$SUPABASE_URL = $env:SUPABASE_URL
$SERVICE_KEY = $env:SUPABASE_SERVICE_ROLE_KEY
$USER_ID = "4dc896ac-f9cf-4954-9ae1-3df6cda0c0b0"

Write-Host ""
Write-Host "Checking Max Shard Storage in Supabase..." -ForegroundColor Cyan
Write-Host ""

# Query user_vault table
$url = "$SUPABASE_URL/rest/v1/user_vault?id=eq.$USER_ID&select=*"
$headers = @{
    "apikey" = $SERVICE_KEY
    "Authorization" = "Bearer $SERVICE_KEY"
}

try {
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    
    if ($response.Count -gt 0) {
        $vault = $response[0]
        
        Write-Host "User Vault Record Found" -ForegroundColor Green
        Write-Host ""
        Write-Host "Shard Storage Status:" -ForegroundColor Yellow
        Write-Host "  User ID: $($vault.id)"
        Write-Host "  Username: $($vault.username)"
        Write-Host "  Wallet Address: $($vault.wallet_address)"
        
        $rootDisplay = if ($vault.root_pubkey) { $vault.root_pubkey.Substring(0, 20) + "..." } else { "NULL" }
        Write-Host "  Root Pubkey: $rootDisplay"
        Write-Host "  Daily Limit: $($vault.daily_limit)"
        
        $pinDisplay = if ($vault.pin_hash) { $vault.pin_hash.Substring(0, 30) + "..." } else { "NULL" }
        Write-Host "  PIN Hash: $pinDisplay"
        Write-Host ""
        
        Write-Host "Encrypted Shards:" -ForegroundColor Yellow
        $shardALen = if ($vault.encrypted_shard_a_blob) { $vault.encrypted_shard_a_blob.Length } else { 0 }
        $shardBLen = if ($vault.encrypted_shard_b_blob) { $vault.encrypted_shard_b_blob.Length } else { 0 }
        
        Write-Host "  Shard A: $(if ($shardALen -gt 0) { "Stored (Length: $shardALen)" } else { "MISSING" })"
        Write-Host "  Shard B: $(if ($shardBLen -gt 0) { "Stored (Length: $shardBLen)" } else { "MISSING" })"
        Write-Host "  Client Salt: $($vault.client_salt)"
        Write-Host ""
        
        # Summary
        $shardsOk = ($vault.encrypted_shard_a_blob -and $vault.encrypted_shard_b_blob)
        $metadataOk = ($vault.root_pubkey -and $vault.pin_hash -and $vault.username)
        
        if ($shardsOk -and $metadataOk) {
            Write-Host "ALL SHARDS AND METADATA STORED SUCCESSFULLY" -ForegroundColor Green
        } else {
            Write-Host "INCOMPLETE STORAGE DETECTED" -ForegroundColor Yellow
            if (-not $shardsOk) {
                Write-Host "  Missing encrypted shards" -ForegroundColor Red
            }
            if (-not $metadataOk) {
                Write-Host "  Missing metadata fields" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "No vault record found for user ID" -ForegroundColor Red
    }
} catch {
    Write-Host "Error querying Supabase: $_" -ForegroundColor Red
}
