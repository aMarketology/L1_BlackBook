# BlackBook L1 - Vault Development Setup Script (PowerShell)
# Configures HashiCorp Vault for local development with AppRole authentication

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "=========================================="
Write-Host "BlackBook L1 - Vault Development Setup"
Write-Host "=========================================="
Write-Host ""

# Set Vault address
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"

Write-Host "Vault Address: $env:VAULT_ADDR"
Write-Host "Using Root Token: root"
Write-Host ""

# Check if Vault server is running
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:8200/v1/sys/health" -Method Get -TimeoutSec 2 -UseBasicParsing 2>$null
    Write-Host "[OK] Vault server is running"
} catch {
    Write-Host "[ERROR] Vault server is not running!"
    Write-Host ""
    Write-Host "Start the Vault dev server first:"
    Write-Host "  vault server -dev -dev-root-token-id=root"
    exit 1
}

Write-Host ""

# Step 1: Enable KV v2 secrets engine
Write-Host "Step 1: Enabling KV v2 secrets engine at blackbook/..."
& "$env:USERPROFILE\vault\vault.exe" secrets enable -path=blackbook kv-v2 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   [OK] KV v2 enabled"
} else {
    Write-Host "   [OK] Already enabled"
}
Write-Host ""

# Step 2: Store the pepper
Write-Host "Step 2: Storing pepper secret..."
$timestamp = Get-Date -Format "yyyyMMddHHmmss"
$pepper = "BlackBook_L1_Pepper_${timestamp}_StrongKey_2026"
& "$env:USERPROFILE\vault\vault.exe" kv put blackbook/pepper value="$pepper"
Write-Host "   [OK] Pepper stored: $pepper"
Write-Host ""

# Step 3: Create policy file
Write-Host "Step 3: Creating access policy..."
$policyContent = @'
# BlackBook L1 - Vault Access Policy
path "blackbook/data/pepper" {
  capabilities = ["read"]
}
path "blackbook/metadata/pepper" {
  capabilities = ["read"]
}
'@

$policyFile = "$env:TEMP\blackbook-policy.hcl"
Set-Content -Path $policyFile -Value $policyContent -Encoding UTF8
& "$env:USERPROFILE\vault\vault.exe" policy write blackbook-policy $policyFile
Remove-Item $policyFile -ErrorAction SilentlyContinue
Write-Host "   [OK] Policy blackbook-policy created"
Write-Host ""

# Step 4: Enable AppRole authentication
Write-Host "Step 4: Enabling AppRole authentication..."
& "$env:USERPROFILE\vault\vault.exe" auth enable approle 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "   [OK] AppRole enabled"
} else {
    Write-Host "   [OK] Already enabled"
}
Write-Host ""

# Step 5: Create AppRole for wallet server
Write-Host "Step 5: Creating AppRole wallet-server..."
& "$env:USERPROFILE\vault\vault.exe" write auth/approle/role/wallet-server secret_id_ttl=24h token_num_uses=0 token_ttl=1h token_max_ttl=4h secret_id_num_uses=0 policies=blackbook-policy
Write-Host "   [OK] AppRole created"
Write-Host ""

# Step 6: Generate credentials
Write-Host "Step 6: Generating credentials..."
$roleId = & "$env:USERPROFILE\vault\vault.exe" read -field=role_id auth/approle/role/wallet-server/role-id
$secretId = & "$env:USERPROFILE\vault\vault.exe" write -field=secret_id -f auth/approle/role/wallet-server/secret-id

Write-Host ""
Write-Host "=========================================="
Write-Host "[SUCCESS] Vault Setup Complete!"
Write-Host "=========================================="
Write-Host ""
Write-Host "Add these to your .env file:"
Write-Host ""
Write-Host "VAULT_ADDR=http://127.0.0.1:8200"
Write-Host "VAULT_ROLE_ID=$roleId"
Write-Host "VAULT_SECRET_ID=$secretId"
Write-Host ""
Write-Host "Pepper value: $pepper"
Write-Host ""
Write-Host "Vault UI: http://127.0.0.1:8200 (Token: root)"
Write-Host ""
Write-Host "Test with: vault kv get blackbook/pepper"
Write-Host "=========================================="
