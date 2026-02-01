# 🔐 HashiCorp Vault Integration Plan
## BlackBook L1 - Secure Pepper Management Implementation

---

## Executive Summary

This document outlines the complete implementation plan for integrating HashiCorp Vault into BlackBook L1's wallet system. The goal is to eliminate storing the encryption pepper in environment variables and instead fetch it securely from Vault using AppRole authentication with short-lived tokens.

**Timeline:** 3-5 hours  
**Complexity:** Medium  
**Impact:** High Security Enhancement  

---

## Table of Contents

1. [Current State vs Target State](#current-state-vs-target-state)
2. [Implementation Phases](#implementation-phases)
3. [Phase 1: Local Development Setup](#phase-1-local-development-setup)
4. [Phase 2: Code Integration](#phase-2-code-integration)
5. [Phase 3: Testing & Validation](#phase-3-testing--validation)
6. [Phase 4: Production Deployment](#phase-4-production-deployment)
7. [Rollback Plan](#rollback-plan)
8. [Success Metrics](#success-metrics)

---

## Current State vs Target State

### Current State (❌ Security Risk)

```
┌─────────────────────────────────────┐
│         .env File                   │
│                                     │
│  SHARE_C_PEPPER=MySecretPepper123   │ ← Stored on filesystem
│                                     │ ← Visible to anyone with access
└─────────────────────────────────────┘ ← No audit trail
                │
                ↓
┌─────────────────────────────────────┐
│      BlackBook L1 Server            │
│  process.env.SHARE_C_PEPPER         │
│  → Used directly for encryption     │
└─────────────────────────────────────┘
```

**Problems:**
- Pepper stored in plaintext in `.env` file
- Accessible if server is compromised
- No rotation mechanism
- No audit logging
- Committed to git accidentally (common mistake)

### Target State (✅ Secure)

```
┌─────────────────────────────────────┐
│         .env File                   │
│                                     │
│  VAULT_ADDR=http://vault:8200       │ ← Only connection info
│  VAULT_ROLE_ID=abc-123              │ ← Not the secret itself
│  VAULT_SECRET_ID=xyz-789            │ ← Short-lived credentials
└─────────────────────────────────────┘
                │
                ↓
┌─────────────────────────────────────┐
│      BlackBook L1 Server            │
│  1. Auth with AppRole               │
│  2. Get token (1h TTL)              │
│  3. Fetch pepper on-demand          │
│  4. Cache 5 min in memory           │
│  5. Never write to disk             │
└─────────────────────────────────────┘
                │
                ↓
┌─────────────────────────────────────┐
│       HashiCorp Vault               │
│  • Pepper encrypted at rest         │
│  • All access audited               │
│  • Token-based auth                 │
│  • Network-isolated                 │
│  • Versioned secrets                │
└─────────────────────────────────────┘
```

**Benefits:**
- ✅ Pepper never on filesystem
- ✅ Tokens expire automatically
- ✅ Full audit trail
- ✅ Easy rotation without downtime
- ✅ Zero-trust architecture

---

## Implementation Phases

```
Phase 1: Local Dev Setup (30 min)
├── Install Vault
├── Run dev server
├── Configure secrets engine
├── Create AppRole
└── Test connection

Phase 2: Code Integration (2 hours)
├── Add Vault module to Rust
├── Add Vault client to Node.js
├── Update wallet creation flow
├── Update wallet login flow
└── Update recovery flow

Phase 3: Testing (1 hour)
├── Unit tests
├── Integration tests
├── End-to-end wallet tests
├── Security validation
└── Performance benchmarks

Phase 4: Production (1 hour)
├── HCP Vault setup
├── TLS configuration
├── Monitoring & alerts
├── Deploy to staging
└── Deploy to production
```

---

## Phase 1: Local Development Setup

### Step 1.1: Install HashiCorp Vault

**macOS:**
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
vault --version  # Should show v1.x.x
```

**Windows:**
```powershell
# Using Chocolatey
choco install vault

# Or download binary from https://www.vaultproject.io/downloads
# Add to PATH manually
```

**Linux:**
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
```

**✅ Validation:**
```bash
vault --version
# Expected: Vault v1.15.0 or higher
```

### Step 1.2: Start Vault Dev Server

Open a dedicated terminal (keep it running):

```bash
vault server -dev -dev-root-token-id="root"
```

**Expected Output:**
```
==> Vault server configuration:
             Api Address: http://127.0.0.1:8200
                     Cgo: disabled
         Cluster Address: https://127.0.0.1:8201
              Dev Mode: true
...
Root Token: root
```

**✅ Validation:**
```bash
curl http://127.0.0.1:8200/v1/sys/health
# Expected: {"initialized":true,"sealed":false,...}
```

### Step 1.3: Run Setup Script

**macOS/Linux:**
```bash
cd vault
chmod +x setup-vault-dev.sh
./setup-vault-dev.sh
```

**Windows:**
```powershell
cd vault
.\setup-vault-dev.ps1
```

**What the script does:**
1. Enables KV v2 secrets engine at `blackbook/`
2. Stores pepper: `blackbook/pepper`
3. Creates policy: `blackbook-policy` (read-only)
4. Enables AppRole authentication
5. Creates role: `wallet-server`
6. Generates ROLE_ID and SECRET_ID

**✅ Validation:**
The script outputs credentials:
```
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=abc-123-def-456
VAULT_SECRET_ID=xyz-789-uvw-012
```

### Step 1.4: Update .env File

Add to `.env` (create if doesn't exist):

```bash
# HashiCorp Vault Configuration
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<paste-from-setup-script>
VAULT_SECRET_ID=<paste-from-setup-script>

# Remove or comment out old pepper
# SHARE_C_PEPPER=old_insecure_pepper
```

**✅ Validation:**
```bash
# Check env vars are set
grep VAULT .env
# Should show 3 lines
```

### Step 1.5: Test Vault Access

```bash
# Set environment
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Read the pepper
vault kv get blackbook/pepper

# Expected output:
# ====== Data ======
# Key      Value
# ---      -----
# value    BlackBook_L1_Pepper_...
```

**✅ Phase 1 Complete:** Vault is running and configured

---

## Phase 2: Code Integration

### Step 2.1: Add Vault Module to Rust src/lib.rs

**File:** `src/lib.rs`

Add the vault module declaration:

```rust
// Add to module declarations
pub mod vault;
```

**✅ Validation:**
```bash
cargo check
# Should compile without errors
```

### Step 2.2: Update Wallet Creation to Use Vault

**File:** `src/routes_v2/wallet.rs` (or wherever wallet creation is)

**Before:**
```rust
let pepper = std::env::var("SHARE_C_PEPPER")
    .unwrap_or_else(|_| "default_pepper".to_string());
```

**After:**
```rust
use crate::vault::get_pepper;

let pepper = get_pepper().await
    .map_err(|e| {
        tracing::error!("Failed to get pepper from Vault: {}", e);
        warp::reject::custom(InternalError)
    })?;
```

**✅ Validation:**
```bash
cargo build
# Should compile successfully
```

### Step 2.3: Update Node.js SDK to Use Vault

**File:** `sdk/zkp-wallet-sdk.js`

**Before:**
```javascript
const TEST_PEPPER = process.env.SHARE_C_PEPPER || 'TEST_PEPPER_SECRET';
```

**After:**
```javascript
const { getPepper } = require('./vault-client');

// In async functions:
const pepper = await getPepper();
```

**✅ Validation:**
```bash
cd sdk
node -e "require('./vault-client').getPepper().then(p => console.log('✅ Pepper:', p.substring(0,10)+'...'))"
```

### Step 2.4: Update All Wallet Functions

Search for all uses of the pepper and update them:

**Search pattern:**
```bash
grep -r "SHARE_C_PEPPER\|pepper" --include="*.rs" --include="*.js"
```

**Files to update:**
- `src/routes_v2/wallet.rs` - Wallet creation
- `src/routes_v2/auth.rs` - Authentication
- `sdk/tests/create-zkp-wallets.js` - Test wallets
- `sdk/tests/migrate-to-zkp.js` - Migration script

**Template for updates:**

Rust:
```rust
// Replace
let pepper = env::var("SHARE_C_PEPPER")?;

// With
let pepper = crate::vault::get_pepper().await?;
```

Node.js:
```javascript
// Replace
const pepper = process.env.SHARE_C_PEPPER;

// With
const { getPepper } = require('./vault-client');
const pepper = await getPepper();
```

**✅ Validation:**
```bash
# Check no hardcoded peppers remain
grep -r "SHARE_C_PEPPER" src/ sdk/ | grep -v "vault"
# Should return no results (or only comments)
```

### Step 2.5: Add Error Handling

Ensure all Vault calls have proper error handling:

**Rust:**
```rust
match get_pepper().await {
    Ok(pepper) => {
        // Use pepper
    },
    Err(e) => {
        tracing::error!("Vault error: {:?}", e);
        return Err(VaultError::ClientError(e.to_string()));
    }
}
```

**Node.js:**
```javascript
try {
    const pepper = await getPepper();
    // Use pepper
} catch (error) {
    console.error('Vault error:', error.message);
    throw new Error('Failed to retrieve encryption pepper');
}
```

**✅ Phase 2 Complete:** Code integrated with Vault

---

## Phase 3: Testing & Validation

### Step 3.1: Unit Tests

**Rust Unit Test:**

Add to `src/vault/mod.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore] // Run only when Vault is available
    async fn test_vault_auth() {
        let config = VaultConfig::from_env().expect("Vault config");
        let client = VaultClient::new(config);
        
        client.initialize().await.expect("Init failed");
        assert!(client.is_token_valid().await);
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_pepper() {
        let pepper = get_pepper().await.expect("Failed to get pepper");
        assert!(!pepper.is_empty());
        assert!(pepper.len() > 20); // Should be a strong pepper
    }
}
```

**Run tests:**
```bash
cargo test --lib vault -- --ignored
```

**✅ Expected:** Both tests pass

### Step 3.2: Integration Test - Wallet Creation

**File:** `tests/vault_wallet_integration.rs`

```rust
#[tokio::test]
#[ignore]
async fn test_create_wallet_with_vault_pepper() {
    // Initialize Vault
    let pepper = crate::vault::get_pepper().await
        .expect("Failed to get pepper from Vault");
    
    // Create wallet using the pepper
    let wallet = create_zkp_wallet("test_user", "TestPass123!", &pepper)
        .await
        .expect("Wallet creation failed");
    
    assert!(wallet.address.starts_with("L1_"));
    assert!(wallet.shareCEncrypted.encrypted.len() > 0);
}
```

**Run test:**
```bash
cargo test --test vault_wallet_integration -- --ignored
```

**✅ Expected:** Test passes, wallet created successfully

### Step 3.3: End-to-End Test - Full Wallet Flow

**File:** `sdk/tests/test-vault-e2e.js`

```javascript
const { getPepper } = require('../vault-client');
const { ZKPWallet } = require('../zkp-wallet-sdk');

async function testFullFlow() {
    console.log('🧪 Testing full wallet flow with Vault...\n');
    
    // 1. Get pepper from Vault
    console.log('1. Fetching pepper from Vault...');
    const pepper = await getPepper();
    console.log('   ✅ Pepper retrieved\n');
    
    // 2. Create wallet
    console.log('2. Creating wallet...');
    const wallet = await ZKPWallet.create('alice', 'AlicePass123!', pepper);
    console.log('   ✅ Wallet created:', wallet.wallet.address, '\n');
    
    // 3. Login
    console.log('3. Testing login...');
    const session = await ZKPWallet.login(
        wallet.wallet,
        wallet.shareB,
        'AlicePass123!'
    );
    console.log('   ✅ Login successful\n');
    
    // 4. Sign transaction
    console.log('4. Signing transaction...');
    const tx = session.signTransaction({
        to: 'L1_TEST_ADDRESS',
        amount: 100
    });
    console.log('   ✅ Transaction signed:', tx.signature.substring(0, 16) + '...\n');
    
    console.log('✅ All tests passed!');
}

testFullFlow().catch(console.error);
```

**Run test:**
```bash
node sdk/tests/test-vault-e2e.js
```

**✅ Expected:** All 4 steps pass

### Step 3.4: Security Validation

**Test 1: Token Expiry**
```bash
# In vault client, set token TTL to 10 seconds for testing
# Wait 15 seconds
# Try to get pepper
# Expected: Auto-refresh and succeed
```

**Test 2: Invalid Credentials**
```bash
# Set VAULT_SECRET_ID to invalid value
# Try to get pepper
# Expected: Authentication error
```

**Test 3: Vault Unavailable**
```bash
# Stop Vault server
# Try to get pepper
# Expected: Connection error, graceful failure
```

**✅ Expected:** All security tests behave correctly

### Step 3.5: Performance Benchmark

**File:** `tests/bench_vault_pepper.rs`

```rust
#[tokio::test]
async fn bench_pepper_retrieval() {
    let start = std::time::Instant::now();
    
    // First call (no cache)
    let pepper1 = get_pepper().await.unwrap();
    let first_call = start.elapsed();
    
    // Second call (cached)
    let start2 = std::time::Instant::now();
    let pepper2 = get_pepper().await.unwrap();
    let cached_call = start2.elapsed();
    
    assert_eq!(pepper1, pepper2);
    
    println!("First call (no cache): {:?}", first_call);
    println!("Cached call: {:?}", cached_call);
    
    // Cached should be < 1ms
    assert!(cached_call < std::time::Duration::from_millis(1));
}
```

**✅ Expected:**
- First call: 10-50ms (network call to Vault)
- Cached call: <1ms (in-memory)

**✅ Phase 3 Complete:** All tests passing

---

## Phase 4: Production Deployment

### Step 4.1: Choose Vault Deployment

**Option A: HashiCorp Cloud Platform (HCP) - Recommended**
- Fully managed
- Auto-scaling
- Built-in HA
- $0.25/hour (~$180/month)

**Option B: Self-Hosted on AWS/GCP**
- More control
- Lower cost
- Requires ops expertise

**Option C: Self-Hosted Single Node (Not for Production)**
- Development only
- No HA

**Recommendation:** Start with HCP for simplicity

### Step 4.2: HCP Vault Setup

```bash
# Install Terraform
brew install terraform  # macOS
# or download from terraform.io

# Configure HCP
export HCP_CLIENT_ID="your-client-id"
export HCP_CLIENT_SECRET="your-client-secret"

# Deploy Vault cluster
cd vault/terraform
terraform init
terraform plan
terraform apply
```

**Terraform config:** `vault/terraform/main.tf`
```hcl
terraform {
  required_providers {
    hcp = {
      source  = "hashicorp/hcp"
      version = "~> 0.78.0"
    }
  }
}

provider "hcp" {}

resource "hcp_hvn" "blackbook" {
  hvn_id         = "blackbook-vault-network"
  cloud_provider = "aws"
  region         = "us-east-1"
}

resource "hcp_vault_cluster" "blackbook" {
  cluster_id      = "blackbook-vault"
  hvn_id          = hcp_hvn.blackbook.hvn_id
  tier            = "starter_small"
  public_endpoint = true
}
```

**✅ Validation:**
```bash
export VAULT_ADDR=$(terraform output -raw vault_public_url)
vault status
# Expected: initialized and unsealed
```

### Step 4.3: Configure Production Secrets

```bash
# Login to HCP Vault
vault login -method=userpass username=admin

# Enable secrets engine
vault secrets enable -path=blackbook kv-v2

# Store PRODUCTION pepper (STRONG!)
vault kv put blackbook/pepper \
    value="$(openssl rand -base64 48)"

# Create production policy
vault policy write blackbook-prod-policy vault/blackbook-policy.hcl

# Create AppRole
vault write auth/approle/role/wallet-server-prod \
    secret_id_ttl=720h \
    token_ttl=4h \
    token_max_ttl=24h \
    policies="blackbook-prod-policy"

# Get credentials for production .env
vault read auth/approle/role/wallet-server-prod/role-id
vault write -f auth/approle/role/wallet-server-prod/secret-id
```

### Step 4.4: Enable TLS

**Generate certificates:**
```bash
# Using Let's Encrypt
certbot certonly --standalone -d vault.blackbook.finance

# Configure Vault to use TLS
vault write pki/root/generate/internal \
    common_name="BlackBook Vault CA" \
    ttl=87600h
```

**Update production .env:**
```bash
VAULT_ADDR=https://vault.blackbook.finance:8200  # Note: HTTPS
VAULT_ROLE_ID=<prod-role-id>
VAULT_SECRET_ID=<prod-secret-id>
```

### Step 4.5: Enable Audit Logging

```bash
# Enable file audit log
vault audit enable file file_path=/var/log/vault/audit.log

# Enable syslog for centralized logging
vault audit enable syslog tag="vault" facility="AUTH"

# Test audit log
vault kv get blackbook/pepper
tail -f /var/log/vault/audit.log | jq '.'
```

**✅ Expected:** See audit entry for pepper access

### Step 4.6: Deploy to Staging

**Update staging environment:**
```bash
# SSH to staging server
ssh blackbook-staging

# Update .env with staging Vault credentials
nano /opt/blackbook/.env

# Restart services
systemctl restart blackbook-l1
systemctl restart blackbook-sdk

# Verify Vault connectivity
curl https://staging-vault.blackbook.finance/v1/sys/health
```

**✅ Validation:**
```bash
# Create test wallet on staging
curl -X POST https://staging.blackbook.finance/api/wallet/create \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"TestPass123!"}'

# Expected: Wallet created successfully
```

### Step 4.7: Monitor & Alert

**Setup Prometheus metrics:**

Add to `src/vault/mod.rs`:
```rust
// Track Vault metrics
metrics::counter!("vault.pepper.requests_total").increment(1);
metrics::histogram!("vault.pepper.latency_ms").record(latency_ms);
metrics::gauge!("vault.token.ttl_seconds").set(ttl_seconds);
```

**Grafana Dashboard:**
```json
{
  "dashboard": {
    "title": "BlackBook Vault Metrics",
    "panels": [
      {
        "title": "Pepper Requests/sec",
        "targets": ["rate(vault_pepper_requests_total[5m])"]
      },
      {
        "title": "Cache Hit Rate",
        "targets": ["vault_pepper_cache_hits / vault_pepper_requests_total"]
      },
      {
        "title": "Token TTL",
        "targets": ["vault_token_ttl_seconds"]
      }
    ]
  }
}
```

**Alerts:**
```yaml
# alerts.yml
- alert: VaultUnreachable
  expr: up{job="vault"} == 0
  for: 1m
  annotations:
    summary: "Vault is unreachable"
  
- alert: VaultTokenExpiringSoon
  expr: vault_token_ttl_seconds < 600
  for: 5m
  annotations:
    summary: "Vault token expiring in < 10 minutes"

- alert: HighPepperLatency
  expr: vault_pepper_latency_ms > 100
  for: 5m
  annotations:
    summary: "Pepper retrieval slow (>100ms)"
```

### Step 4.8: Deploy to Production

**Pre-deployment checklist:**
- [ ] All tests passing
- [ ] Staging validated for 24+ hours
- [ ] Backup plan ready
- [ ] Monitoring configured
- [ ] Team notified
- [ ] Maintenance window scheduled

**Deployment steps:**
```bash
# 1. Create backup of current config
cp .env .env.backup.$(date +%s)

# 2. Update .env with production Vault
VAULT_ADDR=https://vault.blackbook.finance:8200
VAULT_ROLE_ID=<prod-role-id>
VAULT_SECRET_ID=<prod-secret-id>

# 3. Deploy new code
git pull origin main
cargo build --release
npm install

# 4. Restart services with zero-downtime
systemctl reload blackbook-l1  # Graceful reload

# 5. Verify
curl https://api.blackbook.finance/health
```

**✅ Validation:**
```bash
# Check logs for Vault initialization
journalctl -u blackbook-l1 -f | grep Vault
# Expected: "✅ Vault authentication successful"

# Test wallet creation
# Create a real wallet and verify it works
```

**✅ Phase 4 Complete:** Production deployment successful

---

## Rollback Plan

If something goes wrong, follow these steps:

### Emergency Rollback (5 minutes)

```bash
# 1. Restore old .env
cp .env.backup.<timestamp> .env

# 2. Add pepper back to .env
echo "SHARE_C_PEPPER=<old-pepper>" >> .env

# 3. Restart services
systemctl restart blackbook-l1

# 4. Verify
curl https://api.blackbook.finance/health
```

### Gradual Rollback (20 minutes)

```bash
# 1. Checkout previous commit
git checkout <previous-commit-hash>

# 2. Rebuild
cargo build --release

# 3. Restart
systemctl restart blackbook-l1

# 4. Monitor for 10 minutes
journalctl -u blackbook-l1 -f
```

---

## Success Metrics

Track these metrics to validate the implementation:

### Security Metrics
- ✅ Zero peppers in `.env` or config files
- ✅ All Vault access audited (100% coverage)
- ✅ Token TTL < 4 hours
- ✅ No plaintext peppers in logs

### Performance Metrics
- ✅ Pepper retrieval < 50ms (uncached)
- ✅ Pepper retrieval < 1ms (cached)
- ✅ Cache hit rate > 95%
- ✅ No impact on wallet creation time

### Reliability Metrics
- ✅ Vault uptime > 99.9%
- ✅ Token refresh success rate > 99.99%
- ✅ Zero failed wallet operations due to Vault
- ✅ Graceful degradation if Vault temporarily unavailable

### Operational Metrics
- ✅ Pepper rotation < 5 minutes downtime
- ✅ Audit logs retained for 90 days
- ✅ Alert response time < 5 minutes
- ✅ Team trained on Vault operations

---

## Post-Implementation Tasks

### Week 1
- [ ] Monitor all metrics daily
- [ ] Review audit logs
- [ ] Test pepper rotation
- [ ] Update runbooks

### Month 1
- [ ] Rotate pepper for first time
- [ ] Analyze performance data
- [ ] Optimize cache TTL if needed
- [ ] Security audit

### Ongoing
- [ ] Quarterly pepper rotation
- [ ] Annual security review
- [ ] Keep Vault updated
- [ ] Review audit logs monthly

---

## Appendix

### A. Common Issues & Solutions

**Issue:** "Vault credentials not provided"
```bash
# Solution: Check .env file
cat .env | grep VAULT
# Ensure all 3 vars are set
```

**Issue:** "Token expired"
```bash
# Solution: Client auto-refreshes, but if it fails:
# Generate new SECRET_ID
vault write -f auth/approle/role/wallet-server/secret-id
```

**Issue:** "Permission denied"
```bash
# Solution: Check policy
vault policy read blackbook-policy
# Ensure path "blackbook/data/pepper" has "read" capability
```

### B. Useful Commands

```bash
# Check Vault status
vault status

# List secrets
vault kv list blackbook/

# Read pepper
vault kv get blackbook/pepper

# View audit log
tail -f /var/log/vault/audit.log | jq '.request.path'

# Token info
vault token lookup

# Revoke token
vault token revoke <token>
```

### C. References

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AppRole Auth Method](https://www.vaultproject.io/docs/auth/approle)
- [KV Secrets Engine v2](https://www.vaultproject.io/docs/secrets/kv/kv-v2)
- [Production Hardening](https://learn.hashicorp.com/tutorials/vault/production-hardening)

---

**Document Version:** 1.0  
**Last Updated:** January 31, 2026  
**Author:** BlackBook L1 Core Team  
**Status:** 🚧 Implementation in Progress
