# Back From Turkey — Execution Plan
> **Written:** April 6, 2026  
> **Status as of departure:** L1 v5.0.0 compiles cleanly, all Phase 1 & Phase 2 critical items done.  
> **Goal:** Lightweight blockchain, maximum security — two major workstreams below.

---

## Where We Left Off

### What Was Completed This Session (April 6)

| Item | File(s) Changed | Status |
|------|----------------|--------|
| **Float Removal** | `src/storage/mod.rs`, `src/main.rs` | ✅ Done |
| **Persistence Guarantee** | `src/contracts/global_escrow/mod.rs`, `src/contracts/deposit_gateway/mod.rs`, `src/contracts/withdrawal_gateway/mod.rs`, `src/storage/mod.rs` | ✅ Done |
| **L2 State Root Monotonicity** | `src/contracts/global_escrow/mod.rs` | ✅ Done |

**Cargo check result:** `Finished dev profile` — zero errors, only cosmetic warnings about unused imports.

### The Two Remaining Big Bets

1. **Workstream A — Maximum Security:** HashiCorp Vault Integration  
   The L1's private keys (`DEALER_PRIVATE_KEY`, `SERVER_MASTER_KEY`, `L2_SEQUENCER_PUBKEY`) currently live in a plaintext `.env` file on every Hetzner server. SSH breach = all funds compromised. Vault fixes this permanently.

2. **Workstream B — Incredibly Lightweight:** Binary Serialization & Wire the UDP TPU  
   The current REST HTTP/JSON stack is *already functional* — but it's the wrong tool for a high-throughput L1. The UDP TPU and bincode serialization are already fully scaffolded in `runtime/tpu.rs`. This workstream wires it end-to-end and benchmarks the result.

---

## Workstream A: HashiCorp Vault — Get Keys Off Disk

### Why This Matters
`DEALER_PRIVATE_KEY` signs every mint and burn on the chain. It is currently read at startup via `std::env::var("DEALER_PRIVATE_KEY")` in three places:
- `src/main.rs` line 2325 — dealer address derivation
- `src/watcher/mod.rs` line 213 — startup balance sync
- `src/contracts/withdrawal_gateway/mod.rs` line 144 — withdrawal signing

Any actor with SSH access to the server can `cat /opt/blackbook/.env` and steal the key in under 3 seconds. This is a single point of catastrophic failure.

**Vault replaces the static `.env` file with a runtime secret fetch.** The plaintext key never touches disk on the application server. Vault Agent renders a short-lived `.env` file (TTL = 1 hour) into memory, and the Docker container picks it up. On expiry it re-fetches. The key is gone from disk between TTL windows.

---

### Step-by-Step Implementation

#### Step 1 — Stand Up Vault (choose one)

**Option A: HCP Vault (Managed, easiest)**  
Go to https://portal.cloud.hashicorp.com → Create HCP Vault Dedicated cluster → Choose smallest tier (~$50/mo). No server to manage, automatic HA, no unseal ceremony needed.

**Option B: Self-hosted on a separate Hetzner CX11 (€4/mo)**  
```bash
# On a SEPARATE Hetzner server (NOT your L1 node)
docker run -d \
  --cap-add=IPC_LOCK \
  --name vault \
  -p 8200:8200 \
  -v /vault/data:/vault/data \
  -e VAULT_LOCAL_CONFIG='{"storage":{"file":{"path":"/vault/data"}},"listener":[{"tcp":{"address":"0.0.0.0:8200","tls_disable":true}}],"ui":true}' \
  hashicorp/vault server

# Initialise (save these keys in 1Password — never commit them)
vault operator init
vault operator unseal   # Paste unseal key 1
vault operator unseal   # Paste unseal key 2
vault operator unseal   # Paste unseal key 3
vault login             # Paste root token
```

---

#### Step 2 — Write BlackBook Secrets into Vault

Run this **from your laptop** after first deployment:
```bash
# Enable KV v2
vault secrets enable -path=blackbook kv-v2

# Write all BlackBook production secrets
vault kv put blackbook/node \
  DEALER_PRIVATE_KEY="your_64_char_hex_key_here" \
  L2_SEQUENCER_PUBKEY="your_64_char_hex_pubkey_here" \
  SERVER_MASTER_KEY="your_master_key_hex_here" \
  SOLANA_RPC_URL="https://your-paid-rpc.helius.xyz/..." \
  BSC_RPC_URL="https://bsc-dataseed.binance.org/" \
  BSC_CUSTODY_WALLET="0xYourBscCustodyWallet"
```

To verify: `vault kv get blackbook/node` — you should see all 6 keys echoed back.

---

#### Step 3 — Create a Minimal Read-Only Policy

Create file `blackbook-node-policy.hcl`:
```hcl
path "blackbook/data/node" {
  capabilities = ["read"]
}
```

Apply it:
```bash
vault policy write blackbook-node blackbook-node-policy.hcl
```

This is the blast-radius limiter. Even if the node's Vault token is stolen, the attacker can only read `/blackbook/data/node`. They cannot write, delete, or read any other path.

---

#### Step 4 — AppRole Auth (Machine-to-Machine)

```bash
vault auth enable approle

vault write auth/approle/role/blackbook-node \
  token_policies="blackbook-node" \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=24h

# Get RoleID (this is NOT secret — can live in docker-compose.prod.yml)
vault read auth/approle/role/blackbook-node/role-id

# Get SecretID (treat like a password — rotate daily via cron on YOUR laptop)
vault write -f auth/approle/role/blackbook-node/secret-id
```

---

#### Step 5 — Install Vault Agent on Each Hetzner Node

Vault Agent is a tiny sidecar that handles token renewal and file re-rendering.

```bash
# On the Hetzner node
apt-get install -y vault
mkdir -p /etc/vault-agent
```

Create `/etc/vault-agent/config.hcl`:
```hcl
vault {
  address = "https://YOUR_VAULT_SERVER_IP:8200"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "/etc/vault-agent/role-id"
      secret_id_file_path = "/etc/vault-agent/secret-id"
    }
  }

  sink "file" {
    config = {
      path = "/tmp/vault-token"
    }
  }
}

template {
  source      = "/etc/vault-agent/blackbook.env.tpl"
  destination = "/opt/blackbook/.env"
  perms       = "0600"
}
```

Create `/etc/vault-agent/blackbook.env.tpl`:
```
{{ with secret "blackbook/data/node" }}
DEALER_PRIVATE_KEY={{ .Data.data.DEALER_PRIVATE_KEY }}
L2_SEQUENCER_PUBKEY={{ .Data.data.L2_SEQUENCER_PUBKEY }}
SERVER_MASTER_KEY={{ .Data.data.SERVER_MASTER_KEY }}
SOLANA_RPC_URL={{ .Data.data.SOLANA_RPC_URL }}
BSC_RPC_URL={{ .Data.data.BSC_RPC_URL }}
BSC_CUSTODY_WALLET={{ .Data.data.BSC_CUSTODY_WALLET }}
{{ end }}
```

```bash
# Put the non-secret RoleID directly on disk
echo "YOUR_ROLE_ID" > /etc/vault-agent/role-id
# SecretID is rotated daily (see Step 6)
echo "YOUR_SECRET_ID" > /etc/vault-agent/secret-id
chmod 600 /etc/vault-agent/secret-id

# Start vault agent as systemd service
vault agent -config=/etc/vault-agent/config.hcl &
```

When Vault Agent starts it authenticates, fetches the secrets, and writes `/opt/blackbook/.env`. The existing `docker-compose.prod.yml` already reads it via `env_file: - .env`. Nothing in the Rust code changes.

---

#### Step 6 — Rotate SecretID Daily (cron on YOUR laptop)

```bash
# Add to your laptop's crontab (runs at 03:00 UTC every day)
# crontab -e
0 3 * * * vault write -f auth/approle/role/blackbook-node/secret-id \
  | grep secret_id \
  | awk '{print $2}' \
  | ssh root@YOUR_NODE_IP "cat > /etc/vault-agent/secret-id && pkill -HUP vault"
```

The node never gets write access. The key material lives only in Vault. You rotate from your machine.

---

#### Step 7 — Update `deployment/setup-hetzner.sh`

Find the line:
```bash
ufw allow 50051/tcp comment 'gRPC Validator Relay'
```

Replace with the IP-restricted version (fill in your actual L2 server IPs):
```bash
L2_ROLLUP2_IP="${L2_ROLLUP2_IP:?Set L2_ROLLUP2_IP before running setup}"
L2_ROLLUP3_IP="${L2_ROLLUP3_IP:?Set L2_ROLLUP3_IP before running setup}"
ufw allow from "$L2_ROLLUP2_IP" to any port 50051 proto tcp comment 'gRPC relay — Rollup 2'
ufw allow from "$L2_ROLLUP2_IP" to any port 50052 proto tcp comment 'gRPC settlement — Rollup 2'
ufw allow from "$L2_ROLLUP3_IP" to any port 50051 proto tcp comment 'gRPC relay — Rollup 3'
ufw allow from "$L2_ROLLUP3_IP" to any port 50052 proto tcp comment 'gRPC settlement — Rollup 3'
```

Also update `deployment/docker-compose.prod.yml` to prevent Docker from bypassing UFW:
```yaml
# Before:
ports:
  - "50051:50051"
# After:
ports:
  - "127.0.0.1:50051:50051"
  - "127.0.0.1:50052:50052"
```

---

#### Checklist After Vault Is Live

- [ ] HCP or self-hosted Vault cluster is up and unsealed
- [ ] All 6 secrets written to `blackbook/node`
- [ ] `blackbook-node` AppRole created with read-only policy
- [ ] Vault Agent installed and running on each Hetzner node
- [ ] `/opt/blackbook/.env` is now rendered from Vault, not manually `scp`'d
- [ ] SecretID rotation cron job running on your laptop
- [ ] `.env` removed from the git history (run `git-secrets` scan)
- [ ] `deployment/setup-hetzner.sh` updated with IP-restricted UFW rules
- [ ] `deployment/docker-compose.prod.yml` updated with `127.0.0.1` bindings
- [ ] Mark `security_step_by_step.md` Phase 1 "Vault Integration" as `[x]` ✅

---

## Workstream B: Incredible Lightweight — Wire the UDP TPU

### Context: What's Already Built vs What Needs Wiring

The good news: **the hard work is already done.**

`runtime/tpu.rs` contains a production-ready UDP TPU implementation:
- Binds `0.0.0.0:8003` UDP socket
- Spins up **8 parallel Tokio worker tasks** sharing the socket (no thundering herd)
- Deserializes incoming packets via **`bincode`** (not JSON — ~70 bytes vs ~200 bytes)
- Applies **per-IP QoS rate limiting** (5,000 packets/sec/IP, resets every 1 second)
- Verifies **Ed25519 signatures** with canonical message format
- Enforces **chain_id = 1** — cross-chain replay impossible
- Checks **TTL** — transactions older than 60 seconds are silently dropped
- Uses **atomic DashMap nonce check** — no TOCTOU race
- Dispatches to **GulfStreamService** → **Sealevel Parallel Execution**

The TPU service is even launched at startup in `src/main.rs` (line 3053–3066).

**The remaining work is the last-mile issues:**

---

### Issue 1: `TpuPacket.amount` is still `f64`

**File:** `runtime/tpu.rs` line 54
**Current:**
```rust
pub struct TpuPacket {
    pub amount: f64,  // <-- must be u64 lamports now
```

Since we removed `f64` from the entire ledger layer this session, the TPU packet and its downstream handlers need to match. The field must become `u64` representing lamports (raw, no division). Example: `500` = 0.000005 BB.

**Fix:**
```rust
// In TpuPacket struct
pub amount: u64,  // lamports (1 BB = 100_000 lamports)

// Downstream check (line 169) -- change from:
if pkt.from.is_empty() || pkt.to.is_empty() || pkt.amount <= 0.0 {
// to:
if pkt.from.is_empty() || pkt.to.is_empty() || pkt.amount == 0 {

// Balance check (line 244) -- change from:
let balance = bc.get_balance(&pkt.from);
if balance < pkt.amount {
// to:
let balance_lamports = bc.get_balance_lamports(&pkt.from);
if balance_lamports < pkt.amount {

// Dispatch (line 254) -- change from:
let mut tx = RuntimeTx::new(pkt.from.clone(), pkt.to.clone(), pkt.amount, tx_type);
// to:
let amount_bb = pkt.amount as f64 / 100_000.0;  // only at dispatch boundary
let mut tx = RuntimeTx::new(pkt.from.clone(), pkt.to.clone(), amount_bb, tx_type);
```

---

### Issue 2: Signature Message Format Uses JSON String

**File:** `runtime/tpu.rs` lines 186–199  
The signature verification reconstructs a JSON string to verify against. This defeats the purpose of binary serialization — you are paying JSON encoding cost inside the verification path.

The fix is to make the canonical signed message fully binary:
```
chain_id (1 byte) || from_bytes (32 bytes) || to_bytes (32 bytes) || amount.to_le_bytes() (8 bytes) || timestamp.to_le_bytes() (8 bytes) || nonce.to_le_bytes() (8 bytes)
= 89 bytes total (vs ~150 byte JSON string today)
```

**Important:** This change to the canonical message format must be reflected in the L2 `dealer.sdk.ts` (`sdk/dealer.sdk.ts`) as well. The SDK's `signTpuPacket()` method must produce the same 89-byte message before signing. Update both together so they stay in lock-step.

---

### Issue 3: `runtime/core.rs` Transaction Still Uses `f64`

The `RuntimeTx::new()` still takes `f64` amount. When the TPU dispatches to GulfStream it converts back from lamports to `f64`. This is a temporary bridge — the right fix is to update `runtime/core.rs` Transaction to use `u64` lamports natively and update GulfStream + Sealevel to pass lamports through.

This is the deepest float removal pass. Do it last.

---

### Issue 4: UDP Port 8003 Not Open in UFW

`deployment/setup-hetzner.sh` does not open UDP port 8003. Add this line:
```bash
ufw allow 8003/udp comment 'BlackBook TPU (binary transaction ingestion)'
```

---

### Issue 5: Bincode Canonical Format Must Match SDK

The L2 `dealer.sdk.ts` currently submits via HTTP/JSON to the REST API. For the TPU path, the TypeScript SDK must build a `TpuPacket` serialized exactly the way `bincode` expects. Bincode is positional — fields must be serialized in exact struct field declaration order.

The struct field order is:
```
from (string) | to (string) | amount (u64) | public_key (string) | signature (string) | timestamp (u64) | nonce (string) | chain_id (u8) | priority (u64) | tx_type (Option<string>)
```

In JavaScript, bincode serializes strings as a `u64` length prefix followed by UTF-8 bytes. Note that the npm package `@napi-rs/bincode` or the custom implementation in `sdk/dealer.sdk.ts` must match this exactly.

A simpler approach: define a fixed-width wire format (no variable-length strings) and use `DataView` in TypeScript. The Rust side then uses a custom deserializer.

---

### Issue 6: Load Test to Confirm 100k TPS Target

Once the above fixes are applied, run the existing load test at:
```
examples/udp_tpu_load_test.rs
```

```bash
cargo run --example udp_tpu_load_test -- --tps 50000 --duration 30
```

Expected outputs to verify:
- No packet loss at 50k TPS
- CPU stays below 60% on a Hetzner CX21
- Memory stays flat (no DashMap nonce table bloat — nonces must be pruned after TTL)
- Zero failed signature verifications with valid packets

**Note:** The nonce table (`used_nonces: DashMap<String, u64>`) currently grows forever. Add a background pruner that drops nonces older than 120 seconds:
```rust
// In TpuService::run, spawn a cleanup task
tokio::spawn(async move {
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(120);
        nonces_clone.retain(|_, inserted_at| *inserted_at > cutoff);
    }
});
```

---

### TPU Work Checklist

- [ ] Fix `TpuPacket.amount: f64` → `u64` lamports in `runtime/tpu.rs`
- [ ] Fix sanity check `<= 0.0` → `== 0` in `runtime/tpu.rs`
- [ ] Fix balance check to use `get_balance_lamports()` in `runtime/tpu.rs`
- [ ] Replace JSON canonical message with 89-byte binary message in `runtime/tpu.rs`
- [ ] Update `sdk/dealer.sdk.ts` `signTpuPacket()` to match binary message format
- [ ] Add UDP 8003 to `deployment/setup-hetzner.sh` UFW rules
- [ ] Add nonce pruning background task in `runtime/tpu.rs`
- [ ] Update `runtime/core.rs` Transaction to use `u64` lamports natively (deepest change)
- [ ] Run `cargo run --example udp_tpu_load_test` and confirm TPS metrics
- [ ] Mark `security_step_by_step.md` Phase 3 items `[x]` ✅

---

## Execution Order When You Get Back

**Day 1 (Security First):**
1. Stand up Vault (HCP is fastest — 20 minutes)
2. Write all secrets in
3. Install Vault Agent on node
4. Verify `.env` is no longer `scp`'d manually
5. Tighten UFW gRPC rules + docker-compose bindings

**Day 2 (Lightweight Layer):**
1. Fix `TpuPacket.amount` to `u64`
2. Fix binary canonical message format
3. Update `dealer.sdk.ts` to match
4. Add nonce pruner
5. Run load test
6. Fix `runtime/core.rs` float (deepest)

**Day 3 (Validate & Ship):**
1. Full `cargo check` + `cargo test`
2. Deploy to Hetzner
3. Run live load test against the production node
4. Update `security_step_by_step.md` checklist

---

## Current State of the Checklist

```
Phase 1: Security & Core Stability
  [x] Fix Panics
  [x] Atomic Replay Protection
  [x] Sealevel Deadlock Prevention
  [x] Token Swap Ed25519 Enforcement
  [ ] Vault Integration            ← Day 1

Phase 2: Financial Integrity
  [x] Float Removal                ← Done this session
  [x] Persistence Guarantee        ← Done this session
  [ ] Circuit Breakers & Rate Limits

Phase 3: High-Throughput Networking
  [ ] UDP TPU (wire it)            ← Day 2
  [ ] Binary Serialization         ← Day 2
  [ ] Stake-Weighted QoS           ← Day 2 (partially done in tpu.rs)
  [ ] Dedicated RPC Meatshield     ← Later

Phase 4: Multi-Node Global Network
  [ ] Wire gRPC Relay
  [ ] Firewall Lockdown            ← Day 1 (partial)
  [ ] Reader Node Deployment

Phase 5: L2 / L3 Settlement
  [x] L2 State Root Monotonicity   ← Done this session
  [ ] L2 Sequencer Allowlist
  [ ] settle_market_and_generate_root()
  [ ] L3 Anchoring Interface
  [ ] End-to-End Load Test         ← Day 3
```

---

## Key Files for Reference

| What | Where |
|------|-------|
| UDP TPU full implementation | `runtime/tpu.rs` |
| TPU service launch | `src/main.rs` line 3053 |
| Global escrow (monotonicity fix) | `src/contracts/global_escrow/mod.rs` |
| Withdrawal gateway | `src/contracts/withdrawal_gateway/mod.rs` |
| Deposit gateway | `src/contracts/deposit_gateway/mod.rs` |
| Storage / persistence layer | `src/storage/mod.rs` |
| Dealer SDK (L2 integration) | `sdk/dealer.sdk.ts` |
| Hetzner deployment script | `deployment/setup-hetzner.sh` |
| Docker compose | `deployment/docker-compose.prod.yml` |
| This checklist | `security_step_by_step.md` |

---

*Enjoy Turkey. Come back ready to ship.*
