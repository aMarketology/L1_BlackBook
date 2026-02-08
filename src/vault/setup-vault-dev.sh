#!/bin/bash
# BlackBook L1 - Vault Development Setup Script
# Configures HashiCorp Vault for local development with AppRole authentication

set -e

echo "=========================================="
echo "BlackBook L1 - Vault Development Setup"
echo "=========================================="
echo ""

# Check if Vault is installed
if ! command -v vault &> /dev/null; then
    echo "❌ Vault is not installed!"
    echo ""
    echo "Install with:"
    echo "  macOS:   brew tap hashicorp/tap && brew install hashicorp/tap/vault"
    echo "  Linux:   wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg"
    echo "  Windows: choco install vault"
    echo ""
    exit 1
fi

echo "✅ Vault binary found: $(vault --version)"
echo ""

# Set Vault address
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

echo "📍 Vault Address: $VAULT_ADDR"
echo "🔑 Using Root Token: $VAULT_TOKEN"
echo ""

# Check if Vault server is running
if ! curl -s http://127.0.0.1:8200/v1/sys/health > /dev/null 2>&1; then
    echo "⚠️  Vault server is not running!"
    echo ""
    echo "Start the Vault dev server in another terminal:"
    echo "  vault server -dev -dev-root-token-id=\"root\""
    echo ""
    echo "Then run this script again."
    exit 1
fi

echo "✅ Vault server is running"
echo ""

# Step 1: Enable KV v2 secrets engine
echo "🔧 Step 1: Enabling KV v2 secrets engine at 'blackbook/'..."
vault secrets enable -path=blackbook kv-v2 2>/dev/null || echo "   (already enabled)"
echo ""

# Step 2: Store the pepper
echo "🌶️  Step 2: Storing pepper secret..."
PEPPER="BlackBook_L1_Pepper_$(date +%s)_StrongKey_2026!"
vault kv put blackbook/pepper value="$PEPPER"
echo "   ✅ Pepper stored securely"
echo ""

# Step 3: Create policy
echo "📜 Step 3: Creating access policy..."
cat > /tmp/blackbook-policy.hcl << 'EOF'
# BlackBook L1 - Vault Access Policy
path "blackbook/data/pepper" {
  capabilities = ["read"]
}
path "blackbook/metadata/pepper" {
  capabilities = ["read"]
}
path "*" {
  capabilities = ["deny"]
}
EOF

vault policy write blackbook-policy /tmp/blackbook-policy.hcl
rm /tmp/blackbook-policy.hcl
echo "   ✅ Policy 'blackbook-policy' created"
echo ""

# Step 4: Enable AppRole authentication
echo "🔐 Step 4: Enabling AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "   (already enabled)"
echo ""

# Step 5: Create AppRole for wallet server
echo "🤖 Step 5: Creating AppRole 'wallet-server'..."
vault write auth/approle/role/wallet-server \
    secret_id_ttl=24h \
    token_num_uses=0 \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_num_uses=0 \
    policies="blackbook-policy"
echo "   ✅ AppRole created"
echo ""

# Step 6: Generate credentials
echo "🎫 Step 6: Generating credentials..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/wallet-server/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wallet-server/secret-id)

echo ""
echo "=========================================="
echo "✅ Vault Setup Complete!"
echo "=========================================="
echo ""
echo "📋 Credentials for your .env file:"
echo ""
echo "VAULT_ADDR=http://127.0.0.1:8200"
echo "VAULT_ROLE_ID=$ROLE_ID"
echo "VAULT_SECRET_ID=$SECRET_ID"
echo ""
echo "🔥 Pepper value (for reference):"
echo "$PEPPER"
echo ""
echo "🌐 Vault UI: http://127.0.0.1:8200"
echo "   Token: root"
echo ""
echo "🧪 Test pepper retrieval:"
echo "   vault kv get blackbook/pepper"
echo ""
echo "=========================================="
