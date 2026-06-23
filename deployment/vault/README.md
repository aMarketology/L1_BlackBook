# 🔐 HashiCorp Vault Integration - BlackBook L1

## Overview

BlackBook L1 uses **HashiCorp Vault** for secure, on-demand pepper retrieval. Instead of storing the encryption pepper in environment variables or configuration files, we fetch it from Vault at runtime using AppRole authentication.

### Why Vault?

| Traditional Approach (❌) | Vault Approach (✅) |
|---------------------------|---------------------|
| Pepper in `.env` file | Pepper in encrypted Vault |
| Accessible if server compromised | Requires authentication token |
| No audit trail | Full audit logging |
| Manual rotation | Versioned secrets |
| Single point of failure | Distributed, HA-capable |

---

## Quick Start (Development)

### 1. Install Vault

#### macOS
```bash
brew tap hashicorp/tap
brew install hashicorp/tap/vault
vault --version
```

#### Windows
```powershell
choco install vault
# Or download from https://www.vaultproject.io/downloads
vault --version
```

#### Linux
```bash
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt update && sudo apt install vault
```

### 2. Start Vault Dev Server

Open a dedicated terminal and run:

```bash
vault server -dev -dev-root-token-id="root"
```

**Keep this terminal open!** This is your active Vault server.

### 3. Run Setup Script

#### macOS/Linux
```bash
cd vault
chmod +x setup-vault-dev.sh
./setup-vault-dev.sh
```

#### Windows PowerShell
```powershell
cd vault
.\setup-vault-dev.ps1
```

The script will output your credentials:

```
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=abc-123-def-456
VAULT_SECRET_ID=xyz-789-uvw-012
```

### 4. Add to Your `.env`

Create or update `.env` in the project root:

```bash
# HashiCorp Vault Configuration
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=<your-role-id>
VAULT_SECRET_ID=<your-secret-id>
```

### 5. Test the Integration

#### Node.js SDK
```javascript
const { getPepper } = require('./sdk/vault-client');

(async () => {
  const pepper = await getPepper();
  console.log('✅ Pepper retrieved:', pepper.substring(0, 10) + '...');
})();
```

#### Rust Server
```rust
use layer1::vault::get_pepper;

#[tokio::main]
async fn main() {
    let pepper = get_pepper().await.expect("Failed to get pepper");
    println!("✅ Pepper retrieved: {}...", &pepper[..10]);
}
```

---

## Architecture

### Authentication Flow

```
┌─────────────────────────────────────────────────────────┐
│                   BLACKBOOK L1 SERVER                   │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 1. Load VAULT_ROLE_ID & VAULT_SECRET_ID from env│  │
│  └──────────────────────────────────────────────────┘  │
│                         │                               │
│                         ↓                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 2. POST /v1/auth/approle/login                   │  │
│  │    {                                              │  │
│  │      "role_id": "abc-123",                        │  │
│  │      "secret_id": "xyz-789"                       │  │
│  │    }                                              │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────┐
│                   HASHICORP VAULT                       │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 3. Verify AppRole credentials                    │  │
│  │ 4. Check policy: "blackbook-policy"              │  │
│  │ 5. Issue token (TTL: 1-4 hours)                  │  │
│  └──────────────────────────────────────────────────┘  │
│                         │                               │
│                         ↓                               │
│  ┌──────────────────────────────────────────────────┐  │
│  │ RESPONSE:                                         │  │
│  │ {                                                 │  │
│  │   "auth": {                                       │  │
│  │     "client_token": "hvs.CAESIX...",             │  │
│  │     "lease_duration": 3600                        │  │
│  │   }                                               │  │
│  │ }                                                 │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
                         ↓
┌─────────────────────────────────────────────────────────┐
│                   BLACKBOOK L1 SERVER                   │
│  ┌──────────────────────────────────────────────────┐  │
│  │ 6. Store token in memory (expires in 1 hour)    │  │
│  │ 7. Cache pepper for 5 minutes                    │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Pepper Retrieval Flow

```
User requests wallet operation
        │
        ↓
Server needs to decrypt Share C
        │
        ↓
Check pepper cache (5 min TTL)
        │
        ├─> Cache HIT → Return pepper
        │
        └─> Cache MISS
                │
                ↓
        Check token validity
                │
                ├─> Valid → Use existing token
                │
                └─> Expired → Re-authenticate
                        │
                        ↓
                GET /v1/blackbook/data/pepper
                Header: X-Vault-Token: hvs.CAESIX...
                        │
                        ↓
                Vault checks policy
                        │
                        ├─> ALLOWED → Return pepper
                        │
                        └─> DENIED → 403 Forbidden
                                │
                                ↓
                        Log & alert security team
```

---

## Security Model

### What Vault Stores

```
blackbook/
└── pepper (KV v2)
    └── value: "BlackBook_L1_Pepper_2026_StrongKey!"
        ├─ Version 1 (current)
        ├─ Version 2 (rotated)
        └─ Version 3 (rotated)
```

### Access Control Policy

```hcl
# blackbook-policy.hcl

# ALLOW: Read pepper data
path "blackbook/data/pepper" {
  capabilities = ["read"]
}

# ALLOW: Read pepper metadata
path "blackbook/metadata/pepper" {
  capabilities = ["read"]
}

# DENY: Everything else
path "*" {
  capabilities = ["deny"]
}
```

### Attack Scenarios

| Attack | Impact |
|--------|--------|
| **Steal .env file** | Attacker gets ROLE_ID and SECRET_ID, but:<br>• Still needs network access to Vault<br>• All access is audited<br>• Token expires in 1-4 hours<br>• Can revoke credentials immediately |
| **Compromise server** | Attacker may find token in memory, but:<br>• Token expires quickly<br>• Limited to read-only pepper access<br>• Audit logs capture all access<br>• Can rotate pepper to invalidate stolen copies |
| **Insider threat** | Admin with Vault access can:<br>• See audit logs of who accessed pepper<br>• Rotate pepper (old Share Cs become invalid)<br>• Revoke suspicious AppRole credentials |
| **Network sniffing** | HTTPS/TLS encrypts all Vault traffic<br>• Use production Vault with TLS certificates |

---

## Production Setup

### 1. Deploy Vault Cluster

Use HashiCorp Cloud Platform (HCP) or self-host:

```bash
# Example: HCP Vault
terraform apply -var="hvn_id=blackbook-vault" \
                -var="cluster_id=blackbook-prod" \
                -var="tier=standard"
```

### 2. Configure TLS

```bash
vault write pki/root/generate/internal \
    common_name="BlackBook Vault CA" \
    ttl=87600h

vault write pki/config/urls \
    issuing_certificates="https://vault.blackbook.finance/v1/pki/ca" \
    crl_distribution_points="https://vault.blackbook.finance/v1/pki/crl"
```

### 3. Rotate Pepper

```bash
# Create new version
vault kv put blackbook/pepper value="NewPepper_2026_v2"

# Old Share Cs can still be decrypted using version 1
vault kv get -version=1 blackbook/pepper
```

### 4. Enable Audit Logging

```bash
vault audit enable file file_path=/var/log/vault/audit.log

# View audit logs
tail -f /var/log/vault/audit.log | jq '.request.path'
```

---

## Monitoring

### Health Check Endpoint

```bash
curl http://127.0.0.1:8200/v1/sys/health
```

Response:
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false
}
```

### Token TTL Check

```bash
vault token lookup
```

### Pepper Access Audit

```bash
vault audit enable syslog
```

Every pepper retrieval generates an audit entry:
```json
{
  "time": "2026-01-31T10:30:00Z",
  "type": "request",
  "auth": {
    "token_policies": ["blackbook-policy"]
  },
  "request": {
    "operation": "read",
    "path": "blackbook/data/pepper",
    "client_token": "hmac-sha256:abc123...",
    "remote_address": "10.0.1.42"
  }
}
```

---

## Troubleshooting

### Issue: "Vault credentials not provided"

```bash
# Check env vars are set
echo $VAULT_ADDR
echo $VAULT_ROLE_ID
echo $VAULT_SECRET_ID

# If not set, add to .env
cat >> .env << EOF
VAULT_ADDR=http://127.0.0.1:8200
VAULT_ROLE_ID=your-role-id
VAULT_SECRET_ID=your-secret-id
EOF
```

### Issue: "Vault server not running"

```bash
# Start dev server in separate terminal
vault server -dev -dev-root-token-id="root"
```

### Issue: "Permission denied"

```bash
# Re-run setup script to recreate policy
cd vault
./setup-vault-dev.sh  # macOS/Linux
# or
.\setup-vault-dev.ps1  # Windows
```

### Issue: "Token expired"

The client auto-refreshes tokens. If it fails:

```bash
# Check Vault is accessible
curl http://127.0.0.1:8200/v1/sys/health

# Restart your application to re-authenticate
```

---

## Vault UI

Access the web interface at **http://127.0.0.1:8200/ui**

Login with token: `root` (dev mode)

Navigate to: **Secrets > blackbook > pepper**

---

## Further Reading

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [AppRole Authentication](https://www.vaultproject.io/docs/auth/approle)
- [KV Secrets Engine v2](https://www.vaultproject.io/docs/secrets/kv/kv-v2)
- [Production Hardening](https://learn.hashicorp.com/collections/vault/day-one-raft)

---

**Version:** 1.0.2  
**Last Updated:** January 31, 2026  
**Author:** BlackBook L1 Core Team
