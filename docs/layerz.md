# BlackBook — Layer Stack: End-to-End Testing & Deployment Plan

> **Date:** June 2026  
> **Status:** Local E2E testing phase — all four layers wired together for the first time.  
> **Goal:** Get L0 → L1 → L2 → L3 running cleanly on localhost, then ship to bare-metal.

---

## The Full Stack at a Glance

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 0  —  Relay & Consensus Foundation                       │
│  Tower BFT validators · PoH clock · Turbine shred mesh         │
│  Cross-chain IBC message routing (future expansion)            │
└─────────────────────────┬───────────────────────────────────────┘
                          │ anchors finality
┌─────────────────────────▼───────────────────────────────────────┐
│  LAYER 1  —  BlackBook Settlement Chain  (this repo)           │
│  Rust · Axum :8080 · UDP TPU :8003 · ReDB · DashMap           │
│  $BB + wUSDT · Universal Rollup Hub · NFT Bridge               │
│  Global Escrow · SPL Token Engine · Ed25519 auth               │
└────────┬──────────────────────┬──────────────────────────────   ┘
         │  lock_bb / submit_root / exit          │
         ▼                                        ▼
┌────────────────────┐                  ┌──────────────────────┐
│  LAYER 2           │                  │  LAYER 3             │
│  Prediction Market │                  │  NFT Minting System  │
│  TypeScript/Node   │                  │  TypeScript/Node     │
│  sequencer/l2/     │                  │  sequencer/l3/       │
│  SQLite WAL        │                  │  SQLite WAL          │
│  :7072             │                  │  :7073               │
└────────────────────┘                  └──────────────────────┘
```

---

## Layer 0 — Context & Role

Layer 0 is **not a separate service today** — it lives inside L1 as the consensus and
networking substrate. Understanding it conceptually matters because we will extract it
when we want to connect external chains.

### What L0 Does Today (embedded in L1)

| Component | File | Responsibility |
|---|---|---|
| PoH clock | `runtime/poh_service.rs` | Cryptographic timestamping — orders all events globally |
| Tower BFT | `runtime/consensus.rs` | Supermajority voting — finalizes blocks |
| Gulf Stream | `runtime/consensus.rs` | Mempool forwarding — routes txs to the leader |
| Turbine mesh | `runtime/turbine.rs` | Shred gossip — propagates blocks to whitelisted validators |
| Validator registry | `runtime/validator_registry.rs` | Tracks approved consortium nodes |

### What L0 Becomes (future)

When BlackBook expands to connect partner chains (gaming L1s, DeFi L1s, etc.), the
Tower BFT consensus and Turbine propagation layer gets extracted into a standalone
`l0-core` Rust binary. It will speak a strict **Inter-Blockchain Communication (IBC)**
packet format:

```rust
pub struct CrossChainPacket {
    pub sequence: u64,
    pub source_chain_id: String,      // e.g. "BLACKBOOK_L1"
    pub dest_chain_id: String,        // e.g. "PARTNER_GAME_L1"
    pub payload: Vec<u8>,             // encrypted action
    pub source_merkle_proof: String,  // proof the action happened
}
```

The current modular architecture (isolated ReDB, decoupled TS sequencers, strict
Ed25519 auth at every boundary) was designed so that extraction is **surgical**, not
a rewrite. We are L0-ready when we need it.

### Current L0 Validators (consortium)

| Label | Pubkey (first 16) | Role |
|---|---|---|
| cherry-writer | `61e5b4a8d2cd192…` | Block producer — signs tick-shreds |
| local-reader | `7b6b3abf0e8e7a1…` | Reader node — receives and verifies shreds |

---

## Layer 1 — BlackBook Settlement Chain

**Repo:** `L1_BlackBook/` (this repo)  
**Language:** Rust 2026 edition, v5.0.0 engine  
**Process:** single binary `layer1.exe` / `layer1`

### What L1 Does

- Holds every user's `$BB` and `wUSDT` balance against their Ed25519 public key
- Executes signed transactions after verifying signature, nonce, and timestamp freshness
- Runs the **Universal Rollup Hub** — the single bridge API all upper layers use
- Anchors Merkle state roots submitted by L2 and L3 sequencers
- Enforces exit proofs — releases `$BB` or mints NFTs on successful exit

### L1 Token Economy

| Token | Decimals | 1 unit | Purpose |
|---|---|---|---|
| `$BB` | 5 | `100_000 lamports` | Gas, collateral, oracle staking |
| `wUSDT` | 6 | `1_000_000 micro-units` | Stablecoin reserve, swap pool |

Fixed swap rate: **10 BB = 1 wUSDT**

### Key L1 Endpoints for E2E Testing

```
GET  /health                                    — PoH clock + node status
GET  /balance/:addr                             — wallet balance
POST /faucet                                    — seed test wallets
POST /transfer                                  — user→user BB transfer
POST /swap/bb-to-usdc                           — swap BB for wUSDT
POST /rollup/L2/lock_bb                         — user locks BB into L2 vault
POST /rollup/L2/submit_root                     — L2 sequencer anchors root
POST /rollup/L2/exit                            — user exits BB back from L2
POST /rollup/L3/lock_bb                         — user locks BB into L3 vault
POST /rollup/L3/submit_root                     — L3 sequencer anchors root
POST /rollup/L3/exit                            — user exits NFT from L3
GET  /nft/:collection_id/:token_id              — fetch anchored NFT
GET  /nft/:collection_id/:token_id/owner        — NFT owner lookup
```

### Starting L1 Locally

```powershell
# Dev mode — admin mint endpoints enabled
cargo build --features unsafe_admin
$env:L2_SEQUENCER_PUBKEY = "<64-char hex from sequencer/l2/.env>"
$env:L3_SEQUENCER_PUBKEY = "<64-char hex from sequencer/l3/.env>"
.\target\debug\layer1.exe
```

---

## Layer 2 — Prediction Market

**Location:** `sequencer/l2/`  
**Language:** TypeScript / Node.js  
**Port:** `:7072`  
**Storage:** SQLite WAL (`sequencer/l2/data/`)

### What L2 Does

- Users place bets denominated in `$BB` on binary prediction markets
- L2 holds its own SQLite state (markets, positions, payouts)
- When a market resolves, the L2 sequencer:
  1. Computes winner balances
  2. Builds a SHA-256 sorted-pair Merkle tree over all balances
  3. Submits the 32-byte root to L1 via `POST /rollup/L2/submit_root`
- Users exit winnings back to L1 via `POST /rollup/L2/exit` with a Merkle proof

### L2 Internals

| File | Purpose |
|---|---|
| `src/index.ts` | Startup, env validation, service wiring |
| `src/server.ts` | HTTP API for frontend and L2 clients |
| `src/markets.ts` | Market create / bet / resolve logic |
| `src/db.ts` | SQLite schema and query helpers |
| `src/lockIngest.ts` | Polls L1 for new `lock_bb` records, credits L2 balance |
| `src/batchSealer.ts` | Periodic: computes Merkle root, submits to L1 |
| `src/pohLoop.ts` | Local PoH-derived clock for L2 ordering |

### Merkle Leaf Format (L2)

```
SHA-256( "L2:BB:{address}:{balance_lamports}" )
```

### Starting L2 Locally

```bash
cd sequencer/l2
cp .env.example .env    # fill in L1_URL, SEQUENCER_PRIVKEY
npm install
npm start
```

---

## Layer 3 — NFT Minting System

**Location:** `sequencer/l3/`  
**Language:** TypeScript / Node.js  
**Port:** `:7073`  
**Storage:** SQLite WAL (`sequencer/l3/data/`)

### What L3 Does

- Creators and collectors lock `$BB` on L1 to mint NFTs on L3
- L3 manages a collection registry, token metadata, and ownership records in SQLite
- On each batch seal, L3 sequencer:
  1. Hashes all NFT records into Merkle leaves
  2. Submits the root to L1 via `POST /rollup/L3/submit_root`
- NFT exit calls `POST /rollup/L3/exit` with `asset_type: "NFT"` — L1 calls
  `nft_bridge::put_nft()` to anchor the NFT on-chain permanently

### L3 Internals

| File | Purpose |
|---|---|
| `src/index.ts` | Startup and service wiring |
| `src/server.ts` | HTTP API — mint, transfer, list collections |
| `src/nftEngine.ts` | Core: mint, burn, transfer, metadata management |
| `src/db.ts` | SQLite: collections, tokens, owners, metadata |
| `src/batchSealer.ts` | Periodic: build NFT Merkle root, submit to L1 |
| `src/pohLoop.ts` | Local PoH-derived clock for L3 ordering |

### Merkle Leaf Format (L3)

```
SHA-256( "L3:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}" )
```

Where `metadata_hash = SHA-256( JSON.stringify(metadata) )`.

### Starting L3 Locally

```bash
cd sequencer/l3
cp .env.example .env    # fill in L1_URL, SEQUENCER_PRIVKEY
npm install
npm start
```

---

## End-to-End Testing Plan

### Pre-Flight Checklist

- [ ] L1 builds cleanly: `cargo build --features unsafe_admin`
- [ ] `L2_SEQUENCER_PUBKEY` env var set (matches `sequencer/l2/.env SEQUENCER_PUBKEY`)
- [ ] `L3_SEQUENCER_PUBKEY` env var set (matches `sequencer/l3/.env SEQUENCER_PUBKEY`)
- [ ] L1 `GET /health` returns `{ "status": "healthy" }`
- [ ] L2 starts and connects to L1 (check lock ingest polling logs)
- [ ] L3 starts and connects to L1 (check sequencer startup logs)

---

### Phase 1 — L1 Baseline

**Goal:** Confirm the settlement chain is clean before layering anything on top.

| # | Test | Expected |
|---|---|---|
| 1.1 | `GET /health` | `status: healthy`, PoH hashes/sec > 1M |
| 1.2 | `POST /faucet` → seed two test wallets (Alice, Bob) | Both show `$BB` balance |
| 1.3 | `POST /transfer` Alice → Bob | Bob balance increases, nonce consumed |
| 1.4 | Replay same nonce | HTTP 400 replay rejected |
| 1.5 | `POST /swap/bb-to-usdc` | Alice wUSDT balance credited |
| 1.6 | `GET /escrow/status` | Pool balances non-zero |

**Run:** `node tests/full_flow_test.mjs` — all 43 tests should pass.

---

### Phase 2 — L2 Prediction Market Lock/Exit Flow

**Goal:** Full round-trip of BB through the L2 prediction market.

| # | Test | Expected |
|---|---|---|
| 2.1 | L2 starts, `lockIngest` polls L1 successfully | No errors in logs |
| 2.2 | Alice calls `POST /rollup/L2/lock_bb` with 1000 lamports | L1 returns lock UUID |
| 2.3 | L2 `lockIngest` detects the lock, credits Alice on L2 | L2 balance = 1000 lamports |
| 2.4 | Alice places bet via L2 API | Market position recorded in SQLite |
| 2.5 | Resolve market with Alice as winner | Alice L2 balance updated to payout |
| 2.6 | `batchSealer` fires — submits Merkle root to `POST /rollup/L2/submit_root` | L1 returns `{ "batch_id": 1, "root": "..." }` |
| 2.7 | Alice calls `POST /rollup/L2/exit` with Merkle proof | L1 releases lamports to Alice, exit sealed |
| 2.8 | Replay same exit proof | HTTP 403 — double-spend blocked |
| 2.9 | Alice re-deposits and exits increment only | Only the new delta is released |

---

### Phase 3 — L3 NFT Minting & Anchor Flow

**Goal:** Creator mints an NFT on L3, it exits and is permanently anchored on L1.

| # | Test | Expected |
|---|---|---|
| 3.1 | L3 starts, connects to L1 | No errors in logs |
| 3.2 | Creator locks `$BB` via `POST /rollup/L3/lock_bb` | Lock UUID returned |
| 3.3 | L3 mints an NFT for the creator via L3 API | Token record in SQLite, owner set |
| 3.4 | `batchSealer` fires — submits NFT Merkle root to `POST /rollup/L3/submit_root` | L1 anchors root |
| 3.5 | Creator calls `POST /rollup/L3/exit` with `asset_type: "NFT"` + Merkle proof | L1 calls `nft_bridge::put_nft()`, NFT anchored |
| 3.6 | `GET /nft/:collection_id/:token_id` | NFT record returned with metadata |
| 3.7 | `GET /nft/:collection_id/:token_id/owner` | Owner matches creator address |
| 3.8 | Replay the same NFT exit | HTTP 403 — already sealed |
| 3.9 | Collector buys NFT on L3, new root submitted, collector exits | NFT owner updated on L1 |

---

### Phase 4 — Cross-Layer Smoke Test

**Goal:** One user moves value across all three layers in a single session.

```
Alice faucet ($BB on L1)
  → lock_bb into L2
  → win prediction market bet
  → L2 root submitted
  → exit BB winnings back to L1
  → lock_bb into L3 (using winnings)
  → mint NFT on L3
  → L3 root submitted
  → exit NFT to L1
  → verify L1 balance + NFT ownership
```

All steps scripted in: `tests/full_flow_test.mjs` (extend with L2/L3 steps).

---

### Phase 5 — Merkle Integrity Audit

**Goal:** Prove the Merkle math is identical on both ends.

| # | Check |
|---|---|
| 5.1 | Independently recompute BB leaf from known inputs — matches what L1 stored |
| 5.2 | Independently recompute NFT leaf — matches |
| 5.3 | Submit a tampered proof to `exit` — L1 rejects with HTTP 400 |
| 5.4 | Submit a proof against a non-existent batch_id — HTTP 404 |
| 5.5 | Submit a proof against an old (superseded) root — HTTP 403 |

Use: `sequencer/shared/src/merkle.ts` helpers for client-side proof generation.

---

## Deployment Plan (Post-Local Validation)

> We are moving off Hetzner (flagged blockchain workloads) to **Cherry bare-metal** for
> its blockchain-friendly policy, NVMe throughput, and European colocation.

### Target Infrastructure

| Service | Host | Spec |
|---|---|---|
| **L1 BlackBook node** | Cherry bare-metal (writer) | 32-core · 64 GB RAM · NVMe · 1 Gbps unmetered |
| **Local reader node** | Dev machine / secondary VPS | Syncs from Cherry writer via Turbine |
| **L2 sequencer** | Cherry (same host or lightweight VPS) | Node.js process, minimal RAM |
| **L3 sequencer** | Cherry (same host or lightweight VPS) | Node.js process, minimal RAM |
| **Nginx reverse proxy** | Cherry | TLS termination, routes `:443` → `:8080` / `:7072` / `:7073` |

### Deployment Steps

#### Step 1 — Provision Cherry Server

- [ ] Order: 32-core, 64 GB RAM, NVMe SSD, 1 Gbps unmetered, EU colo
- [ ] Note public IPv4 — needed in `config.toml` and DNS
- [ ] Open firewall:
  - `TCP 8080` — L1 HTTP RPC (public)
  - `TCP 7072` — L2 sequencer API (public or behind Nginx)
  - `TCP 7073` — L3 sequencer API (public or behind Nginx)
  - `TCP 50051` — gRPC relay (public)
  - `UDP 8003` — TPU ingest (public)
  - `UDP 8004` — Turbine shreds (**whitelist only**)

#### Step 2 — Configure L1

```bash
# On Cherry server
cp config.toml.example config.toml
# Edit config.toml: replace placeholder IPs with Cherry public IP
# [[validators]] addr = "CHERRY_IP:8004"

export VALIDATOR_KEYPAIR_PATH=keys/writer.key
export L2_SEQUENCER_PUBKEY=<from sequencer/l2/.env>
export L3_SEQUENCER_PUBKEY=<from sequencer/l3/.env>
```

#### Step 3 — Deploy via Docker Compose

```bash
# From deployment/
docker compose -f docker-compose.prod.yml up -d

# Or manual setup via script
bash deployment/setup-cherry.sh
```

#### Step 4 — Deploy Sequencers

```bash
# L2
cd sequencer/l2
cp .env.example .env
# Set L1_URL=http://CHERRY_IP:8080, SEQUENCER_PRIVKEY=<key>
npm ci --omit=dev
pm2 start dist/index.js --name l2-sequencer

# L3
cd sequencer/l3
cp .env.example .env
# Set L1_URL=http://CHERRY_IP:8080, SEQUENCER_PRIVKEY=<key>
npm ci --omit=dev
pm2 start dist/index.js --name l3-sequencer
```

#### Step 5 — Nginx TLS

Config already scaffolded at `deployment/nginx-blackbook.conf`.

```nginx
# Route example — extend for L2/L3
upstream l1     { server 127.0.0.1:8080; }
upstream l2     { server 127.0.0.1:7072; }
upstream l3     { server 127.0.0.1:7073; }

server {
    listen 443 ssl;
    server_name blackbook.io;

    location /api/l1/ { proxy_pass http://l1/; }
    location /api/l2/ { proxy_pass http://l2/; }
    location /api/l3/ { proxy_pass http://l3/; }
}
```

#### Step 6 — Smoke Test on Cherry

Run `tests/smoke.ps1` or `tests/l1_smoke.ps1` pointed at the Cherry IP.
Then run the full cross-layer Phase 4 scenario above against the live host.

#### Step 7 — Repoint DNS & Wallet

- Update `blackbook-wallet` `L1_URL` env to `https://blackbook.io/api/l1`
- Update L2 and L3 sequencer `L1_URL` to Cherry address
- Confirm `GET /health` from the public domain

---

### Post-Deploy Monitoring

| Check | Tool |
|---|---|
| L1 PoH health | `GET /health` — watch `hashes_per_sec` |
| L2 lock ingest lag | L2 logs — `lockIngest` poll interval |
| L3 batch seal frequency | L3 logs — `batchSealer` fires |
| Turbine mesh | L1 logs — `turbine shred sent to cherry-writer` |
| ReDB file size | `du -sh blockchain_data/blockchain.redb` |
| TPU queue depth | `GET /health` → `tpu_queue_depth` |

---

## Outstanding Items Before Full Production

| Priority | Item | Layer |
|---|---|---|
| P0 | Cherry provisioning + L1 migration | L1 infra |
| P1 | Turbine Phase 7D — round-robin shreds + mesh + FEC reassembly | L0/L1 |
| P2 | Rollup trust-minimization — challenge window, sequencer bond, forced exit | L1/L2/L3 |
| P3 | L2 frontend wired to live prediction market API | L2 |
| P4 | L3 creator/collector frontend (NFT gallery, mint UI) | L3 |
| P5 | L5 Creator Economy sequencer (`sequencer/l5/`) — spec and build | L5 |
| P6 | ZK validity proofs (risc0) — replaces optimistic fraud window | L1+ |

---

*Last updated: June 2026 — local E2E testing phase initiated.*
