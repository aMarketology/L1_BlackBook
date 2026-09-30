# BlackBook L1 — Production Deployment Guide

**Version:** 5.0.2-mainnet-beta  
**Date:** 2026-09-29  
**Future Target:** OVH Cloud (Bare Metal / VPS) — Ubuntu 24.04  
**Current Mode:** Local development — L1 runs constantly on dev machine; L2 prediction market runs on top  
**Status:** Local dev active; production deployment deferred

---

## 📋 Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Key Design Decisions](#key-design-decisions)
3. [Contracts Deployed on L1](#contracts-deployed-on-l1)
4. [Local Development (Current)](#local-development-current)
5. [Critical Gaps for Production](#critical-gaps-for-production)
6. [What's Solid (No Changes Needed)](#whats-solid-no-changes-needed)
7. [Deployment Readiness Assessment](#deployment-readiness-assessment)
8. [Pre-Deployment Checklist](#pre-deployment-checklist)
9. [Post-Deploy Verification](#post-deploy-verification)
10. [Troubleshooting](#troubleshooting)

---

## 🏗️ Architecture Overview

### Core Stack (Production-Ready)

| Layer | Module | Status | Key Features |
|---|---|---|---|
| **Consensus** | `runtime/consensus.rs` | ✅ | Tower BFT + PoH + Gulf Stream, rotating 4-slot leader tenures, stake-weighted schedule |
| **Execution** | `runtime/sealevel.rs` | ✅ | Parallel execution with account-level read/write locks, rayon thread pool |
| **PoH Clock** | `runtime/poh_service.rs` | ✅ | 400ms slots, 4-stage pipeline (fetch→verify→execute→commit), 16 sigverify workers |
| **Networking** | `runtime/turbine.rs` + `validator_registry.rs` | ✅ | Permissioned VIP mesh, UDP tick shreds on port 8004, IP + pubkey + Ed25519 + PoH verification |
| **Storage** | `src/storage/mod.rs` | ✅ | ReDB (persistent) + SVM AccountsDB (hot, u64 lamports), DashMap f64 mirror for legacy APIs |
| **SVM** | `src/svm/` | ✅ | SPL Token engine, PDA derivation, system transfers, swap pool, escrow vaults |
| **Contracts** | `src/contracts/` | ✅ | Global escrow, token swap, deposit/withdrawal gateways, oracle, rollup hub, NFT bridge, DA |

### Node Modes

| Mode | CLI Flag | Behavior |
|------|----------|----------|
| **Writer** | `--mode writer` | Single writer: always produces blocks (legacy/dev) |
| **Reader** | `--mode reader` | Always syncs from a writer via gRPC (legacy/dev) |
| **Validator** | `--mode validator` | **Production mode.** Consults `LeaderSchedule` at every slot. Produces blocks when scheduled, syncs as reader otherwise. Dynamic role switching. |

In Validator mode, `--identity` must match a `label` in `config.toml` `[[validators]]`.  
The `LeaderSchedule` is populated from all validators' `stake_lamports` in the registry.  
Leaders rotate in contiguous 4-slot tenures (`LEADER_TENURE_SLOTS = 4`, 1.6s each).

---

## 🔑 Key Design Decisions

| Decision | Implementation | Why It Matters |
|---|---|---|
| **Integer-only financial math** | All balances = `u64` lamports; `f64` only at API boundary | No floating-point drift, exact accounting |
| **SVM = single source of truth** | `SvmAccountsDB` hot state + ReDB flush | Lock-free reads, ACID writes, no dual-state bugs |
| **Permissioned validator mesh** | Static registry from `config.toml` / `APPROVED_VALIDATORS` env | No dynamic peer discovery attack surface |
| **Rotating leader schedule** | `LEADER_TENURE_SLOTS = 4` (1.6s), stake-proportional | Deterministic, no leader thrashing |
| **Turbine tick streaming** | Signed `TickShred` over UDP, 4-layer verification | Real-time PoH sync for readers, no gRPC bottleneck |
| **Replay protection** | DashMap `entry()` atomic nonce check + 60s timestamp window | TOCTOU-free, no double-spend |
| **90-day data retention** | Nightly prune job, blocks + txs older than 90 days removed | Chain stays lean, transparent audit window |

---

## 📋 Contracts Deployed on L1

| Contract | Purpose | Key Endpoints |
|---|---|---|
| **Global Escrow** | L2 prediction market settlement | `/escrow/deposit`, `/escrow/submit-state-root`, `/escrow/withdraw` |
| **Token Swap** | BB ↔ wUSDT fixed 10:1 rate | `/swap/bb-to-usdc`, `/swap/usdc-to-bb`, `/swap/pool/balances` |
| **Deposit Gateway** | Solana/BSC USDC → BB mint | `/deposit/request`, `/deposit/claim`, webhooks |
| **Withdrawal Gateway** | BB burn → real USDC release | `/withdraw/request`, `/withdraw/release`, `/withdraw/since/:seq` |
| **Oracle** | Optimistic oracle + disputes | `/oracle/register`, `/oracle/submit-pending-root`, `/oracle/vote` |
| **Rollup Hub** | Universal L2/L3/L5 bridge | `/rollup/:id/lock_bb`, `/rollup/:id/submit_root`, `/rollup/:id/exit` |
| **NFT Bridge** | L3 NFT anchoring on L1 | `/nft/:col/:id`, `/nft/transfer` |
| **DA Layer** | Data availability for settlements | `/da/:market_id`, `/da/claim` |

---

## 💻 Local Development (Current)

**The L1 runs constantly on the dev machine. The L2 prediction market sequencer runs on top of it.**

### L1 — Start the Node

```powershell
# Windows (PowerShell) — writer mode with unsafe_admin for dev
.\dev.ps1 writer

# Or manually:
$env:REDB_PATH = "blockchain_data/dev.redb"
$env:RUST_LOG = "info,layer1=info,tower_http=warn"
$env:RUST_BACKTRACE = "1"
cargo build --features unsafe_admin
.\target\debug\layer1.exe --mode writer
```

The L1 starts on:
| Port | Protocol | Purpose |
|------|----------|---------|
| `:8080` | HTTP | REST API (wallet, escrow, swap, rollup) |
| `:8899` | HTTP | Solana JSON-RPC (Phantom, OneKey) |
| `:8003` | UDP | TPU binary transaction ingestion |
| `:8004` | UDP | Turbine tick shred broadcast |
| `:50051` | gRPC | Validator relay (writer → reader) |
| `:50052` | gRPC | Settlement (L2 → L1) |

### L1 — What's Already Configured

Your `.env` already has all the critical secrets:
- ✅ `SERVER_MASTER_KEY` — set
- ✅ `L2_SEQUENCER_PUBKEY` — `ca9225e3...` (matches L2 sequencer key)
- ✅ `DEALER_PRIVATE_KEY` — set (same key as L2 sequencer — shared Oracle identity)
- ✅ `L3_SEQUENCER_PUBKEY` — set
- ✅ `GENESIS_SEEDS` — dealer wallet seeded with 1M BB
- ⚠️ `USDC_MINT_AUTHORITY` — empty (wUSDT minting disabled until wallet created)

### L2 Prediction Market Sequencer — Start

```powershell
cd sequencer

# Install deps (first time only)
npm install

# Build shared library first
npm run build --workspace=shared

# Start L2 sequencer in dev mode
npm run dev:l2
```

The L2 sequencer:
- Listens on `:7072`
- Connects to L1 via WebSocket (`ws://localhost:8080/ws`) for PoH slot ticks
- Seals Merkle batches every 25 slots (~10 seconds)
- Submits state roots to L1 via `POST /rollup/L2/submit_root`
- Manages prediction markets: create, bet (YES/NO), lock, resolve
- Tracks off-chain balances in SQLite (`sequencer/l2/data/l2.sqlite`)

### L2 — Required `.env`

The L2 sequencer needs `sequencer/l2/.env` (or reads from `sequencer/.env.l2`):

```env
L2_SEQUENCER_PRIVKEY=88c428ea60ec00ef8e2aa7af19384a7732efa0a43cd325ef976036197836c7f9
L2_SEQUENCER_PUBKEY=ca9225e31a668c0540062c1be1f36a70593ef6f3dac10dcc771e65f96f13b9dc
L1_HTTP_URL=http://localhost:8080
L1_WS_URL=ws://localhost:8080/ws
DB_PATH=./data/l2.sqlite
PORT=7072
SLOTS_PER_BATCH=25
```

### L1 + L2 — Full Local Stack Verification

```powershell
# 1. L1 health
curl http://localhost:8080/health

# 2. L1 balance (dealer wallet)
curl http://localhost:8080/balance/EdkcKbgiYRVWMGXKbehfDrAuWUcgd7A6UoJzVg7CYQCT

# 3. L2 sequencer health
curl http://localhost:7072/health

# 4. Create a prediction market on L2
curl -X POST http://localhost:7072/markets \
  -H "Content-Type: application/json" \
  -d '{"question": "Will BTC hit $100k by December?"}'

# 5. Place a bet
curl -X POST http://localhost:7072/markets/<market_id>/bet \
  -H "Content-Type: application/json" \
  -d '{"wallet_address": "EdkcKbgiYRVWMGXKbehfDrAuWUcgd7A6UoJzVg7CYQCT", "side": "YES", "amount_lamports": 10000000}'

# 6. Lock market, resolve, and seal
curl -X POST http://localhost:7072/markets/<market_id>/lock
curl -X POST http://localhost:7072/markets/<market_id>/resolve \
  -H "Content-Type: application/json" \
  -d '{"outcome": "YES"}'
```

### Blockers to Spinning Up Locally

| # | Blocker | Status | Fix |
|---|---|---|---|
| **1** | L1 builds and runs | ✅ Working | `.\dev.ps1 writer` |
| **2** | `.env` secrets configured | ✅ Working | All keys present |
| **3** | L2 sequencer `.env` points to localhost | ✅ Working | `sequencer/l2/.env` already has `L1_HTTP_URL=http://localhost:8080` |
| **4** | `sequencer/shared` needs build | ⚠️ First run | `npm run build --workspace=shared` |
| **5** | L2 SQLite DB directory | ⚠️ First run | `mkdir sequencer\l2\data` if missing |
| **6** | `USDC_MINT_AUTHORITY` empty | 🟡 Optional | Only needed for wUSDT minting; prediction market uses $BB |

### Quick-Start Checklist (Local)

```powershell
# Terminal 1 — L1
.\dev.ps1 writer

# Terminal 2 — L2 Sequencer
cd sequencer
npm install
npm run build --workspace=shared
# Ensure sequencer/l2/.env has L1_HTTP_URL=http://localhost:8080
npm run dev:l2

# Terminal 3 — Smoke test
curl http://localhost:8080/health
curl http://localhost:7072/health
```

---

## ⚠️ Critical Gaps for Production (OVH Cloud)

| # | Gap | Severity | Status (Local) | Fix for OVH |
|---|---|---|---|---|
| **1** | `DEALER_PRIVATE_KEY` in `.env` | 🔴 **BLOCKER** | ✅ Set locally | Already in `.env` — just SCP to OVH |
| **2** | Vault runs in dev mode (`server -dev`) | 🔴 **BLOCKER** | N/A (no Vault locally) | Need production config with auto-unseal |
| **3** | `L2_ORACLE_ADDRESS` not set in seed script | 🟡 High | ✅ Dealer wallet seeded via `GENESIS_SEEDS` | Set in `seed_hetzner.sh` |
| **4** | gRPC port 50051 requires `READER_NODE_IP` | 🟡 High | N/A (single node) | Configure UFW on OVH |
| **5** | `USDC_MINT_AUTHORITY` empty | 🟡 High | ⚠️ Empty locally | Create mint authority wallet, set address |
| **6** | `CUSTODY_WALLET_ADDRESS` empty | 🟡 Medium | N/A (no cross-chain) | Set Solana custody wallet for deposit gateway |
| **7** | L2 sequencer `.env` points to production IP | 🟡 Medium | ✅ Already `localhost:8080` |

---

## ✅ What's Solid (No Changes Needed)

- **Consensus**: Tower BFT + PoH + Gulf Stream + rotating leaders — all integer math, no f64
- **Execution**: Sealevel parallel scheduler with conflict detection, auto-tuning batch sizes
- **Networking**: Permissioned Turbine mesh with 4-layer packet verification
- **Storage**: ReDB + SVM AccountsDB architecture is clean, type-safe table definitions
- **Contracts**: All 8 contract modules implemented with proper auth (Ed25519 via `auth.rs`)
- **Deployment**: Multi-stage Dockerfile, docker-compose.prod.yml, Hetzner bootstrap script, Nginx TLS config
- **Observability**: `/health`, `/ready`, `/metrics` (Prometheus), `/stats`, `/chain/volume`, `/supply/audit`
- **Recovery**: Startup slot recovery, block hash chain restoration, genesis seeding idempotent

---

## 🎯 Deployment Readiness Assessment

**Overall Status: Local dev active — OVH production deployment deferred**

### Local Dev (Current) — ✅ Working

The L1 runs on this machine in writer mode. The L2 prediction market sequencer runs alongside it. All critical secrets are configured in `.env`. The main blocker for the full L1+L2 local stack is ensuring the L2 sequencer's `.env` points to `localhost:8080` instead of the production IP.

### Blockers for OVH Production Deploy (When Ready)

1. **Provision OVH Cloud instance** — bare metal or VPS, Ubuntu 24.04
2. **SCP `.env` to OVH** — all secrets are already populated locally
3. **Run bootstrap** — adapt `setup-cherry.sh` for OVH (same Ubuntu 24.04 base)
4. **Switch Vault to Production Mode** — HA cluster with auto-unseal
5. **Set `USDC_MINT_AUTHORITY`** — create mint authority wallet, set address
6. **Set `CUSTODY_WALLET_ADDRESS`** — for cross-chain deposit gateway
7. **Configure DNS** — point `layer1.blackbook.id` and `layer2.blackbook.id` to OVH IP
8. **Provision TLS certs** — Let's Encrypt via Certbot + Nginx

---

## 📝 Pre-Deployment Checklist (OVH Cloud)

### On LOCAL Machine

```bash
# 1. .env is already populated — verify all values
cat .env | grep -E "SERVER_MASTER_KEY|L2_SEQUENCER|DEALER_PRIVATE_KEY|GENESIS_SEEDS"

# 2. Copy .env to OVH server BEFORE running bootstrap
scp .env root@<OVH_IP>:/opt/blackbook-env.tmp

# 3. Verify Docker build locally (optional but recommended)
docker compose -f deployment/docker-compose.prod.yml build
```

### On Server (OVH Cloud)

```bash
# 1. SSH into server
ssh root@<OVH_IP>

# 2. Run bootstrap script (adapt setup-cherry.sh for OVH — same Ubuntu 24.04 base)
bash deployment/setup-cherry.sh

# 3. Wait for node to be healthy (~60s)
docker logs -f blackbook-l1

# 4. Seed genesis balances
export HETZNER_HOST=<OVH_IP>
bash deployment/seed_hetzner.sh

# 5. Verify all endpoints
curl https://layer1.blackbook.id/health
curl https://layer1.blackbook.id/balance/EdkcKbgiYRVWMGXKbehfDrAuWUcgd7A6UoJzVg7CYQCT
curl https://layer1.blackbook.id/dealer/balances
```

---

## ✅ Post-Deploy Verification

| Endpoint | Expected | Notes |
|---|---|---|
| `GET /health` | `{"status":"healthy",...}` | Block age < 10s |
| `GET /ready` | `{"status":"ready",...}` | Block age < 30s |
| `GET /balance/<personal>` | ~10,000 BB | From GENESIS_SEEDS |
| `GET /balance/<house>` | ~50,000 BB | Treasury PDA |
| `GET /balance/<oracle>` | ~10,000 BB | L2 oracle wallet |
| `GET /dealer/balances` | BB + wUSDT balances | **Confirms DEALER_PRIVATE_KEY works** |
| `GET /validators` | `cherry-writer` + `local-reader` | Leader schedule populated |
| `GET /consensus/tower` | `validator_count: 2` | Tower BFT active |
| `GET /turbine/status` | `validator_count: 2` | Permissioned mesh |
| `GET /poh/block/latest` | Slot incrementing | Block production live |
| `GET /chain/volume` | `total_volume_bb`, `total_tx_count` | Volume tracking active |
| `GET /supply/audit` | `invariant_ok: true` | 10:1 BB↔wUSDT backing verified |

---

## 🔧 Troubleshooting

### Block Production Stalled

**Symptom:** `/health` returns `{"status":"degraded"}` or `{"status":"not_ready"}`

**Diagnosis:**
```bash
# Check block age
curl https://layer1.blackbook.id/health | jq '.block_production.latest_block_age_s'

# Check leader schedule
curl https://layer1.blackbook.id/validators | jq '.current_leader'

# Check PoH status
curl https://layer1.blackbook.id/poh/status | jq '.current_slot'
```

**Fix:**
- Ensure `--mode validator` is set (not `writer` or `reader`)
- Verify `--identity` matches a label in `config.toml` `[[validators]]`
- Check that `APPROVED_VALIDATORS` env var or `config.toml` has at least one validator

### Dealer Endpoints Return 503

**Symptom:** `GET /dealer/balances` returns HTTP 503

**Diagnosis:**
```bash
# Check if DEALER_PRIVATE_KEY is set
docker exec blackbook-l1 printenv | grep DEALER_PRIVATE_KEY

# Check logs
docker logs blackbook-l1 | grep -i dealer
```

**Fix:**
- Add `DEALER_PRIVATE_KEY=e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae` to `.env`
- Restart container: `docker compose restart blackbook-l1`

### Turbine Tick Streaming Not Working

**Symptom:** Reader nodes can't receive PoH ticks

**Diagnosis:**
```bash
# Check if APPROVED_VALIDATORS is set
docker exec blackbook-l1 printenv | grep APPROVED_VALIDATORS

# Check if port 8004 is listening
docker exec blackbook-l1 netstat -tuln | grep 8004

# Check validator registry
curl https://layer1.blackbook.id/turbine/status | jq '.validator_count'
```

**Fix:**
- Set `APPROVED_VALIDATORS` env var or create `config.toml` with `[[validators]]` entries
- Ensure `READER_NODE_IP` is set if you have reader nodes
- Re-run `setup-hetzner.sh` to apply UFW rules

### Genesis Seeding Not Applied

**Symptom:** Genesis addresses have 0 balance after restart

**Diagnosis:**
```bash
# Check if GENESIS_SEEDS is set
docker exec blackbook-l1 printenv | grep GENESIS_SEEDS

# Check if addresses already have balance
curl https://layer1.blackbook.id/balance/EJYsHB4zZ5J5fmtk61Ge9BYDuA1QMtC8j9Dm7q8jWbmo
```

**Fix:**
- Run `bash deployment/seed_hetzner.sh <HETZNER_IP>` to append `GENESIS_SEEDS` to `.env`
- Restart container: `docker compose restart blackbook-l1`
- Wait ~5 seconds for node to boot and apply seeds

### Vault Not Starting

**Symptom:** Vault container fails to start

**Diagnosis:**
```bash
docker logs blackbook-vault
```

**Fix:**
- Switch Vault to production mode (see Vault section below)
- Ensure volume permissions are correct: `chown -R blackbook:blackbook /opt/blackbook/vault-data`

---

## 🔐 Vault Production Configuration

### Current State (Dev Mode)

```yaml
# deployment/vault/docker-compose.yml
vault:
  command: server -dev  # ❌ Dev mode — unsealed on restart
  environment:
    VAULT_DEV_ROOT_TOKEN_ID: "blackbook-dev-root-token"  # ❌ Not secure
```

### Production Configuration

```yaml
# deployment/vault/docker-compose.prod.yml
vault:
  image: hashicorp/vault:1.15
  command: server -config=/vault/config/vault.hcl  # ✅ Production mode
  environment:
    VAULT_ADDR: "https://vault.blackbook.io:8200"
    VAULT_CACERT: "/vault/tls/ca.crt"
    VAULT_CLIENT_CERT: "/vault/tls/client.crt"
    VAULT_CLIENT_KEY: "/vault/tls/client.key"
  cap_add:
    - IPC_LOCK
  volumes:
    - vault-data:/vault/data
    - vault-logs:/vault/logs
    - ./config:/vault/config:ro
    - ./policies:/vault/policies:ro
    - ./tls:/vault/tls:ro
  networks:
    - blackbook-network
  restart: unless-stopped
```

### Vault Config File (`deployment/vault/config/vault.hcl`)

```hcl
ui = true

listener "tcp" {
  address     = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file = "/vault/tls/ca.crt"
  tls_key_file   = "/vault/tls/client.key"
  tls_client_ca_file = "/vault/tls/ca.crt"
}

storage "consul" {
  address = "consul.blackbook.io:8500"
  path    = "blackbook"
}

seal "awskms" {
  region     = "us-east-1"
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
}

disable_mlock = false
```

### Setup Steps

```bash
# 1. Generate TLS certificates
cd deployment/vault
openssl req -x509 -newkey rsa:4096 -keyout tls/client.key -out tls/client.crt -days 365 -nodes -subj "/CN=vault.blackbook.io"
openssl req -x509 -newkey rsa:4096 -keyout tls/ca.key -out tls/ca.crt -days 365 -nodes -subj "/CN=BlackBook CA"

# 2. Create Vault policies
cat > policies/blackbook-policy.hcl <<EOF
path "blackbook/data/*" {
  capabilities = ["read", "list"]
}
EOF

# 3. Start Vault in production mode
docker compose -f docker-compose.prod.yml up -d

# 4. Initialize and unseal
docker exec blackbook-vault vault operator init -key-shares=5 -key-threshold=3
docker exec blackbook-vault vault operator unseal <key1>
docker exec blackbook-vault vault operator unseal <key2>
docker exec blackbook-vault vault operator unseal <key3>
```

---

## 📊 Monitoring & Observability

### Health Endpoints

| Endpoint | Purpose | Expected Response |
|---|---|---|
| `GET /health` | Liveness probe | `{"status":"healthy",...}` |
| `GET /ready` | Readiness probe | `{"status":"ready",...}` |
| `GET /metrics` | Prometheus metrics | Text exposition format |
| `GET /stats` | Detailed statistics | JSON with all subsystem stats |
| `GET /chain/volume` | On-chain volume metrics | JSON with deposits, withdrawals, swaps, transfers |
| `GET /supply/audit` | BB↔wUSDT backing invariant | JSON with `invariant_ok: true` |

### Key Metrics (Prometheus)

```promql
# Block production
bb_block_height
bb_total_tx_count
bb_avg_tps

# Consensus
bb_tower_root
bb_confirmed_slots
bb_current_leader

# Token economy
bb_total_supply_lamports
bb_account_count
wusdt_supply_micro
escrow_balance_lamports

# Security
circuit_breaker_tripped
withdrawal_window_total_micro
```

### Log Levels

```bash
# Set log format
export RUST_LOG=info,layer1=info,tower_http=warn

# JSON format (recommended for production)
export RUST_LOG=info,layer1=info,tower_http=warn
export LOG_FORMAT=json

# Debug mode (development only)
export RUST_LOG=debug,layer1=debug,tower_http=debug
```

---

## 🚀 Deployment Commands

### Quick Deploy (All-in-One)

```bash
# On LOCAL machine
scp .env root@<HETZNER_IP>:/opt/blackbook-env.tmp
scp deployment/setup-hetzner.sh root@<HETZNER_IP>:/opt/

# On server
ssh root@<HETZNER_IP>
bash /opt/setup-hetzner.sh

# After node is healthy
export HETZNER_HOST=<HETZNER_IP>
bash deployment/seed_hetzner.sh
```

### Manual Deploy (Step-by-Step)

```bash
# 1. Clone repo
git clone --branch master https://github.com/aMarketology/L1_BlackBook.git /opt/blackbook
cd /opt/blackbook

# 2. Copy .env
scp .env root@<HETZNER_IP>:/opt/blackbook-env.tmp
mv /opt/blackbook-env.tmp /opt/blackbook/.env
chmod 600 /opt/blackbook/.env

# 3. Build and start
docker compose -f deployment/docker-compose.prod.yml up -d --build

# 4. Wait for health check
sleep 60
curl https://layer1.blackbook.id/health

# 5. Seed genesis
export HETZNER_HOST=<HETZNER_IP>
bash deployment/seed_hetzner.sh

# 6. Verify
curl https://layer1.blackbook.id/balance/EJYsHB4zZ5J5fmtk61Ge9BYDuA1QMtC8j9Dm7q8jWbmo
curl https://layer1.blackbook.id/dealer/balances
```

### Update Deployment

```bash
# On server
cd /opt/blackbook
git pull origin master

# Rebuild and restart
docker compose -f deployment/docker-compose.prod.yml up -d --build

# Check logs
docker logs -f blackbook-l1
```

### Backup Database

```bash
# On server
docker exec blackbook-l1 /app/layer1 --mode reader --backup

# Or manually
cp blockchain_data/blockchain.redb blockchain_data/blockchain.redb.bak.$(date +%Y%m%d_%H%M%S)
```

---

## 📚 References

- **Main Manifesto:** [MANIFESTO.md](../MANIFESTO.md)
- **Architecture Docs:** [docs/](../docs/)
- **L2 Integration Guide:** [L2_INTEGRATION_GUIDE.md](../../L2_BlackBook/L2_INTEGRATION_GUIDE.md)
- **Dealer/Oracle Docs:** [docs/dealer_oracle.md](../../L2_BlackBook/docs/dealer_oracle.md)
- **Wallet SDK:** [wallet.sdk.ts](../sdk/wallet.sdk.ts)
- **Sequencer SDK:** [sequencer.sdk.ts](../sdk/sequencer.sdk.ts)

---

## 📞 Support

- **GitHub Issues:** https://github.com/aMarketology/L1_BlackBook/issues
- **Discord:** [BlackBook Discord](https://discord.gg/blackbook)
- **Email:** support@blackbook.id

---

**Last Updated:** 2026-06-25  
**Next Review:** After production deployment (30 days)