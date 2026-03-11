#!/bin/sh
# ============================================================================
# BlackBook L1 - Vault Initialization Script
# ============================================================================
# Runs inside the vault-init container to configure Vault for production use.
# ============================================================================

set -e

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-blackbook-dev-root-token}"

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  BlackBook L1 - Vault Production Initialization                   ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""

export VAULT_ADDR
export VAULT_TOKEN

# Wait for Vault to be ready
echo "⏳ Waiting for Vault to be ready..."
until vault status > /dev/null 2>&1; do
    sleep 1
done
echo "✅ Vault is ready!"
echo ""

# ============================================================================
# Step 1: Enable KV v2 Secrets Engine
# ============================================================================
echo "📦 Step 1: Enabling KV v2 secrets engine..."
vault secrets enable -path=blackbook kv-v2 2>/dev/null || echo "   (Already enabled)"
echo "   ✓ KV v2 enabled at blackbook/"
echo ""

# ============================================================================
# Step 2: Store BlackBook Pepper Secret
# ============================================================================
echo "🔐 Step 2: Storing pepper secret..."

# Generate cryptographically strong pepper (32 bytes = 256 bits)
PEPPER=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n 1)

vault kv put blackbook/pepper \
    value="$PEPPER" \
    description="BlackBook L1 SSS Share C encryption pepper" \
    created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    rotation_policy="quarterly"

echo "   ✓ Pepper stored (64-char random string)"
echo ""

# ============================================================================
# Step 3: Create Security Policies
# ============================================================================
echo "📋 Step 3: Creating security policies..."

# Wallet server policy (read-only pepper access)
cat > /tmp/wallet-server-policy.hcl <<'EOF'
# BlackBook L1 - Wallet Server Policy
# Read-only access to pepper for Share C operations

# Read pepper secret
path "blackbook/data/pepper" {
  capabilities = ["read"]
}

# Read pepper metadata (for rotation tracking)
path "blackbook/metadata/pepper" {
  capabilities = ["read"]
}
EOF
vault policy write wallet-server /tmp/wallet-server-policy.hcl
echo "   ✓ wallet-server policy created"

# Admin policy (full access for recovery operations)
cat > /tmp/admin-policy.hcl <<'EOF'
# BlackBook L1 - Admin Policy
# Full access for privileged operations

# Full pepper access
path "blackbook/data/pepper" {
  capabilities = ["create", "read", "update", "delete"]
}

path "blackbook/metadata/pepper" {
  capabilities = ["read", "delete"]
}

# Admin keys management
path "blackbook/data/admin/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "blackbook/metadata/admin/*" {
  capabilities = ["read", "delete", "list"]
}

# Audit log access
path "sys/audit/*" {
  capabilities = ["read", "list"]
}
EOF
vault policy write admin /tmp/admin-policy.hcl
echo "   ✓ admin policy created"
echo ""

# ============================================================================
# Step 4: Enable AppRole Authentication
# ============================================================================
echo "🔑 Step 4: Enabling AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "   (Already enabled)"
echo "   ✓ AppRole auth enabled"
echo ""

# ============================================================================
# Step 5: Create AppRoles
# ============================================================================
echo "👤 Step 5: Creating AppRoles..."

# Wallet server AppRole (for production servers)
vault write auth/approle/role/wallet-server \
    secret_id_ttl=0 \
    token_num_uses=0 \
    token_ttl=1h \
    token_max_ttl=4h \
    secret_id_num_uses=0 \
    token_policies=wallet-server
echo "   ✓ wallet-server AppRole created (1h TTL, auto-renew)"

# Admin AppRole (for privileged operations)
vault write auth/approle/role/admin \
    secret_id_ttl=1h \
    token_num_uses=10 \
    token_ttl=30m \
    token_max_ttl=1h \
    secret_id_num_uses=1 \
    token_policies=admin
echo "   ✓ admin AppRole created (30m TTL, single-use secret)"
echo ""

# ============================================================================
# Step 6: Generate Credentials
# ============================================================================
echo "🎫 Step 6: Generating credentials..."

ROLE_ID=$(vault read -field=role_id auth/approle/role/wallet-server/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/wallet-server/secret-id)

echo ""
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║  ✅ VAULT INITIALIZATION COMPLETE                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo ""
echo "Add these to your .env file:"
echo ""
echo "  VAULT_ADDR=http://localhost:8200"
echo "  VAULT_ROLE_ID=$ROLE_ID"
echo "  VAULT_SECRET_ID=$SECRET_ID"
echo ""
echo "For Kubernetes, create a secret:"
echo ""
echo "  kubectl create secret generic blackbook-vault \\"
echo "    --from-literal=role-id=$ROLE_ID \\"
echo "    --from-literal=secret-id=$SECRET_ID"
echo ""
echo "⚠️  SECURITY REMINDER:"
echo "  • Rotate SECRET_ID regularly (recommended: monthly)"
echo "  • Use Kubernetes/cloud IAM for production secret injection"
echo "  • Enable Vault audit logging for compliance"
echo ""

# ============================================================================
# Step 7: Enable Audit Logging
# ============================================================================
echo "📊 Step 7: Enabling audit logging..."
vault audit enable file file_path=/vault/logs/audit.log 2>/dev/null || echo "   (Already enabled)"
echo "   ✓ Audit logging enabled at /vault/logs/audit.log"
echo ""

echo "🎉 Vault is ready for BlackBook L1 production!"
