# First 100 Users & 5-Node Launch Plan

> BlackBook L1 — Go-to-Market Infrastructure Playbook

---

## 1. The Goal

Get **100 real users on-chain** with funded SVM wallets, transacting on a **5-node cluster** (4 US + 1 Australia) — proving that BlackBook L1 is a live, multi-region blockchain with real read scalability and sub-second finality.

---

## 2. The 5-Node Cluster

### 2.1 Node Topology

```
                   ┌─────────────────────────────────────┐
                   │       WRITER (us-east)               │
                   │  Virginia — Primary block producer   │
                   │  gRPC :50051 / RPC :8899 / HTTP :8080│
                   └──────────┬──────────────────────────┘
                              │
          gRPC SubscribeBlocks (streaming)
                              │
      ┌───────────┬───────────┼───────────┬──────────────┐
      │           │           │           │              │
┌─────▼─────┐┌────▼─────┐┌────▼─────┐┌────▼──────┐      │
│ READER #1 ││ READER #2││ READER #3││ READER #4 │      │
│ us-east   ││ us-west  ││ us-central│ au-syd    │      │
│ Virginia  ││ Oregon   ││ Dallas   ││ Sydney    │      │
│ RPC :8899 ││ RPC :8899││ RPC :8899││ RPC :8899 │      │
└───────────┘└──────────┘└──────────┘└───────────┘      
```

### 2.2 Node Assignments

| # | Role | Region | Provider | Purpose |
|---|------|--------|----------|---------|
| 1 | **Writer** | us-east (Virginia) | Railway / AWS | Block production, tx execution, gRPC relay |
| 2 | Reader #1 | us-east (Virginia) | Railway / AWS | Same-region read replica, lowest latency to Writer |
| 3 | Reader #2 | us-west (Oregon) | Railway / AWS | West coast users, ~60 ms from Writer |
| 4 | Reader #3 | us-central (Dallas) | Railway / AWS | Central US, load distribution |
| 5 | Reader #4 | au-southeast (Sydney) | Railway / AWS | International presence, ~180 ms from Writer |

### 2.3 Why This Layout

- **Writer in Virginia**: Major cloud hub, lowest latency to the most US data centers. Backbone connectivity to Sydney via undersea cable (~180 ms RTT).
- **3 US Readers**: Cover east/west/central time zones. Users are geo-routed to the nearest Reader for RPC queries.
- **1 Sydney Reader**: Proves multi-continent block propagation works. At 600 ms slots and ~180 ms round-trip, blocks arrive well within the slot window. Also seeds future APAC expansion.
- **Reader #1 co-located with Writer**: Handles overflow read traffic that would otherwise hit the Writer. Zero network latency for block subscription.

### 2.4 Launch Commands

Each node runs the same Docker image or binary. Only the CLI flags differ:

**Writer (Virginia)**:
```bash
docker run -d --name bb-writer \
  -p 8080:8080 -p 8899:8899 -p 50051:50051 \
  -v bb-data:/data \
  blackbook/layer1:latest \
  /app/layer1 --mode writer --identity writer_us_east \
    --grpc-port 50051 --http-port 8080 --rpc-port 8899
```

**Reader #1 (Virginia)**:
```bash
docker run -d --name bb-reader-1 \
  -p 8080:8080 -p 8899:8899 \
  -v bb-data-r1:/data \
  blackbook/layer1:latest \
  /app/layer1 --mode reader --identity reader_us_east \
    --writer-addr http://bb-writer:50051 \
    --http-port 8080 --rpc-port 8899
```

**Reader #2 (Oregon)**:
```bash
docker run -d --name bb-reader-2 \
  -p 8080:8080 -p 8899:8899 \
  -v bb-data-r2:/data \
  blackbook/layer1:latest \
  /app/layer1 --mode reader --identity reader_us_west \
    --writer-addr http://writer.blackbook.io:50051 \
    --http-port 8080 --rpc-port 8899
```

**Reader #3 (Dallas)**:
```bash
docker run -d --name bb-reader-3 \
  -p 8080:8080 -p 8899:8899 \
  -v bb-data-r3:/data \
  blackbook/layer1:latest \
  /app/layer1 --mode reader --identity reader_us_central \
    --writer-addr http://writer.blackbook.io:50051 \
    --http-port 8080 --rpc-port 8899
```

**Reader #4 (Sydney)**:
```bash
docker run -d --name bb-reader-4 \
  -p 8080:8080 -p 8899:8899 \
  -v bb-data-r4:/data \
  blackbook/layer1:latest \
  /app/layer1 --mode reader --identity reader_au_syd \
    --writer-addr http://writer.blackbook.io:50051 \
    --http-port 8080 --rpc-port 8899
```

### 2.5 DNS & Routing

| Domain | Points To | Purpose |
|--------|-----------|---------|
| `writer.blackbook.io` | Writer (Virginia) | Internal: Reader → Writer gRPC |
| `rpc.blackbook.io` | Geo-load-balanced across all 4 Readers | Public: SDK/wallet JSON-RPC endpoint |
| `api.blackbook.io` | Geo-load-balanced across all 4 Readers | Public: HTTP API (wallet create, faucet, etc.) |
| `explorer.blackbook.io` | Any Reader | Block explorer frontend |

Users never hit the Writer directly. All public traffic routes to Readers via geo-DNS (Cloudflare, Route 53, or similar). The Writer's gRPC port (50051) is only exposed to the Reader nodes over a private network / WireGuard tunnel.

---

## 3. Getting 100 Users On-Chain

### 3.1 The Wallet Stack

Every user gets a **Solana-compatible SVM wallet** with 2-of-3 Shamir Secret Sharing:

| Component | What It Does |
|-----------|-------------|
| **BIP-39 mnemonic** | 24-word seed phrase (shown once at creation) |
| **Ed25519 keypair** | Solana-native `Pubkey` — the on-chain address |
| **Shard A** | User's shard (AES-256-GCM encrypted with their password) |
| **Shard B** | Server shard (encrypted with `SERVER_MASTER_KEY`, stored in Supabase) |
| **Shard C** | Cold shard (raw hex — user stores offline, backed up to HashiCorp Vault) |

Any 2-of-3 shards reconstruct the full key. Users sign transactions with shards A+B (password + server). If they lose their password, B+C (server + cold) recovers the wallet.

**SDK call to create a wallet**:
```javascript
const bb = new BlackBookSDK('https://rpc.blackbook.io:8899');

const wallet = await bb.createWallet('alice', {
  password: 'her-secret-password',
  pin: '4821',
  dailyLimit: 500,
});

console.log(wallet.address);    // "EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk"
console.log(wallet.mnemonic);   // 24 words — show ONCE, user writes down
console.log(wallet.shardC);     // Hex — show ONCE, user stores offline
```

### 3.2 Onboarding Flow (Per User)

```
┌──────────────────────────────────────────────────────────────────┐
│ Step 1: SIGN UP                                                  │
│   User visits wallet.blackbook.io or opens the mobile app        │
│   → Creates account (email + password)                           │
│   → Supabase auth issues JWT                                     │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 2: CREATE WALLET                                            │
│   SDK.createWallet(username, { password, pin })                  │
│   → Server generates Ed25519 keypair from BIP-39                 │
│   → Splits secret into 3 Shamir shards                          │
│   → Encrypts Shard A with user's password (Argon2id → AES-256)  │
│   → Encrypts Shard B with SERVER_MASTER_KEY                      │
│   → Returns: address, mnemonic, shardA (encrypted), shardC (raw)│
│   → User shown mnemonic + shardC ONE TIME → must write down     │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 3: FUND WALLET                                              │
│   Faucet: SDK.faucet(wallet.address, 100)                        │
│   → Dealer account mints up to 99,999 BB to the new address     │
│   → Transaction executes on Writer → appears in next block       │
│   → User sees balance within 600 ms (1 slot)                    │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│ Step 4: FIRST TRANSACTION                                        │
│   User sends BB to another address via the wallet UI             │
│   SDK.transfer({ from, to, amount, password })                   │
│   → SSS reconstruct key from Shard A (user) + Shard B (server)  │
│   → Sign transaction with Ed25519                                │
│   → sendTransaction → Writer executes → confirmed in 600 ms     │
│   → User sees updated balance on their Reader's RPC             │
└──────────────────────────────────────────────────────────────────┘
```

### 3.3 The 100-User Rollout Plan

| Wave | Users | Timeline | Method | Initial Balance |
|------|-------|----------|--------|-----------------|
| **Wave 0: Genesis** | 5 | Day 1 | Existing accounts (Max, Alice, Bob, Apollo, Dealer) | 10K–99K BB |
| **Wave 1: Team** | 10 | Week 1 | Internal team creates wallets via SDK | 1,000 BB each (faucet) |
| **Wave 2: Alpha** | 25 | Week 2–3 | Invite-only: friends, advisors, early supporters | 500 BB each (faucet) |
| **Wave 3: Beta** | 60 | Week 4–6 | Public beta signup → wallet.blackbook.io | 100 BB each (faucet) |
| **Total** | **100** | 6 weeks | | |

### 3.4 What "On-Chain" Means

Each of the 100 users has:

- A **real Solana-compatible `Pubkey`** stored in `SvmAccountsDB` (DashMap + ReDB)
- A **non-zero lamport balance** (funded via faucet transactions recorded in blocks)
- A **transaction history** queryable via `getSignaturesForAddress`
- A **balance** queryable via `getBalance` from any of the 5 nodes
- A **token account** (SPL-USDC) queryable via `getTokenAccountsByOwner`
- An entry in every Reader's local ReDB — replicated from the Writer's block stream

Proof of liveness: anyone can `curl` any Reader's RPC and verify:
```bash
# Check balance from Sydney Reader
curl -s https://rpc-au.blackbook.io:8899 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk"]}' \
  | jq .result.value
# → 500000000000  (500 BB in lamports)
```

---

## 4. Infrastructure Checklist

### 4.1 Before Launch

| # | Task | Owner | Status |
|---|------|-------|--------|
| 1 | Build Docker image (`docker build -t blackbook/layer1:latest .`) | DevOps | ☐ |
| 2 | Push image to private registry (ECR / GHCR) | DevOps | ☐ |
| 3 | Provision Writer instance (Virginia) — 4 vCPU, 8 GB RAM, 100 GB SSD | DevOps | ☐ |
| 4 | Provision Reader #1 (Virginia) — 2 vCPU, 4 GB RAM, 50 GB SSD | DevOps | ☐ |
| 5 | Provision Reader #2 (Oregon) — 2 vCPU, 4 GB RAM, 50 GB SSD | DevOps | ☐ |
| 6 | Provision Reader #3 (Dallas) — 2 vCPU, 4 GB RAM, 50 GB SSD | DevOps | ☐ |
| 7 | Provision Reader #4 (Sydney) — 2 vCPU, 4 GB RAM, 50 GB SSD | DevOps | ☐ |
| 8 | Set up WireGuard / private network between Writer ↔ Readers (gRPC :50051) | DevOps | ☐ |
| 9 | Configure geo-DNS: `rpc.blackbook.io` → nearest Reader | DevOps | ☐ |
| 10 | Deploy Writer, verify block production (`getSlot` incrementing) | DevOps | ☐ |
| 11 | Deploy Readers, verify catchup + subscribe (`getBlockHeight` matches Writer) | DevOps | ☐ |
| 12 | Deploy Supabase (auth + Shard B storage) | Backend | ☐ |
| 13 | Deploy HashiCorp Vault (Shard C backup) | Backend | ☐ |
| 14 | Deploy wallet frontend (`wallet.blackbook.io`) | Frontend | ☐ |
| 15 | Publish `@blackbook/sdk` to npm | SDK | ☐ |
| 16 | Load genesis accounts (Max, Alice, Bob, Apollo, Dealer) | Chain | ☐ |
| 17 | Smoke test: create wallet → faucet → transfer → check balance on each Reader | QA | ☐ |

### 4.2 Hardware Sizing

| Node | vCPU | RAM | Disk | Bandwidth | Justification |
|------|------|-----|------|-----------|---------------|
| Writer | 4 | 8 GB | 100 GB SSD | 1 Gbps | PoH hashing, SVM execution, gRPC broadcast to 4 readers |
| Reader | 2 | 4 GB | 50 GB SSD | 500 Mbps | Block verification, ReDB storage, RPC serving |

At 100 users and moderate tx volume (~100 TPS), these specs have headroom. The Writer's gRPC broadcast is the bottleneck — 4 readers at 600 ms slots is trivial. Scale to 100 readers by adding bandwidth, not CPU.

### 4.3 Monitoring

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| Slot height (Writer) | `getSlot` | Stale > 5 seconds |
| Slot height (Readers) | `getSlot` on each Reader | Behind Writer by > 10 slots |
| Block verification failures | Reader logs (`blocks_failed`) | Any > 0 |
| Connected readers | `GetStatus` gRPC | < 4 |
| RPC latency (p99) | Cloudflare / ALB | > 200 ms |
| Disk usage (ReDB) | Host metrics | > 80% |
| Faucet balance (Dealer) | `getBalance(Dealer)` | < 1,000,000 BB |

---

## 5. User Acquisition Strategy

### 5.1 Wave 0 — Genesis (5 Users, Day 1)

The 5 genesis accounts are already on-chain:

| Name | Role | Address | Balance |
|------|------|---------|---------|
| Max | Admin | `GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV` | 10,000 BB |
| Alice | User | `EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk` | 1,325 BB |
| Bob | User | `mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd` | 1,650 BB |
| Apollo | User | `EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb` | 775 BB |
| Dealer | Treasury | `3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp` | 98,750 BB |

These accounts validate the full pipeline: wallet creation, funding, transfers, block production, and multi-node replication. Day 1 is about proving the cluster works, not onboarding strangers.

### 5.2 Wave 1 — Team (10 Users, Week 1)

Internal team members create wallets using the SDK or wallet UI:
- Each receives 1,000 BB from the faucet
- Required to send at least 3 transactions (test the full tx flow)
- Report bugs, UX friction, latency observations from different US regions
- Verify that their balance shows correctly on Readers in Virginia, Oregon, Dallas, and Sydney

### 5.3 Wave 2 — Alpha (25 Users, Week 2–3)

Invite-only cohort:
- Friends, advisors, crypto-native early supporters
- Each receives 500 BB from the faucet
- Given access to the wallet UI + SDK docs
- Assigned a "buddy" from Wave 1 to send their first transaction to
- Feedback collected via Discord or direct chat

Acceptance criteria before Wave 3:
- [ ] All 25 wallets created without errors
- [ ] All 25 funded via faucet in < 1 second
- [ ] 50+ peer-to-peer transfers completed
- [ ] Balance queries return correct values from all 5 nodes
- [ ] No block verification failures on any Reader
- [ ] Sydney Reader latency < 400 ms for `getBalance`

### 5.4 Wave 3 — Beta (60 Users, Week 4–6)

Public beta via `wallet.blackbook.io`:
- Sign up with email → create wallet → receive 100 BB
- Onboarding tutorial: "Send 10 BB to a friend"
- Referral mechanism: each existing user can invite 3 friends
- Channels: Twitter/X announcement, Discord community, direct outreach

### 5.5 Milestone: 100 Users On-Chain

When we hit 100 wallets with non-zero balances:
- [ ] 100 unique `Pubkey` entries in `SvmAccountsDB`
- [ ] 100+ faucet transactions in the block history
- [ ] 200+ total transactions (faucets + peer-to-peer)
- [ ] All 5 nodes in sync (`getSlot` within 2 slots of each other)
- [ ] Sydney reader verified independently (query balance of any US-created wallet from AU)
- [ ] Publish a "State of the Chain" snapshot: total blocks, total txs, total BB supply, active wallets

---

## 6. Security Posture at Launch

| Concern | Mitigation |
|---------|-----------|
| Writer is a single point of failure for writes | Readers continue serving reads if Writer is down. Writer auto-restarts via Docker healthcheck. Writer backup via `restore_chain_state()` from ReDB. |
| Shard B compromise (server breach) | Shard B alone cannot reconstruct the key. Attacker needs Shard A (user's password) or Shard C (cold storage). |
| Shard C compromise (user loses cold shard) | Shard C backed up in HashiCorp Vault, accessible only with AAL2 (2FA-authenticated JWT). |
| gRPC relay intercepted | Writer → Reader gRPC runs over WireGuard encrypted tunnel. Readers also verify every block independently — a MITM cannot inject invalid blocks. |
| Faucet abuse | Faucet capped at 99,999 BB per address per epoch. Rate-limited at the HTTP layer. Dealer balance monitored. |
| Reader serves stale data | Monitoring alerts if any Reader falls > 10 slots behind. Readers auto-catchup via `CatchupBlocks` gRPC. |

---

## 7. Success Metrics

| Metric | Target | How to Measure |
|--------|--------|----------------|
| Wallets created | 100 | `SELECT COUNT(*) FROM svm_accounts WHERE lamports > 0` |
| Total transactions | 200+ | `getEpochInfo` → `transactionCount` |
| Blocks produced | 1,000+ | `getBlockHeight` on Writer |
| Node sync | All 5 within 2 slots | Compare `getSlot` across all nodes |
| Cross-region latency | Sydney `getBalance` < 400 ms | Timed RPC call from AU reader |
| Uptime | 99%+ | Writer healthcheck logs over 6 weeks |
| Zero verification failures | 0 `blocks_failed` | Reader logs |
| User satisfaction | 80%+ positive | Survey after Wave 2 |

---

## 8. Timeline

```
Week 0    │ Infrastructure
          │ ├─ Build + push Docker image
          │ ├─ Provision 5 nodes (4 US + 1 AU)
          │ ├─ Deploy Writer → verify block production
          │ ├─ Deploy 4 Readers → verify sync
          │ └─ Set up geo-DNS, monitoring, alerting
          │
Week 1    │ Wave 0 + Wave 1
          │ ├─ Genesis accounts verified on all 5 nodes
          │ ├─ 10 team members onboarded
          │ └─ Internal tx load test (~100 TPS burst)
          │
Week 2-3  │ Wave 2 (Alpha)
          │ ├─ 25 invite-only users onboarded
          │ ├─ Wallet UI polished based on feedback
          │ └─ Acceptance criteria validated
          │
Week 4-6  │ Wave 3 (Beta)
          │ ├─ Public signup at wallet.blackbook.io
          │ ├─ 60 users onboarded via referral
          │ └─ 100-user milestone reached
          │
Week 6    │ Milestone
          │ ├─ "State of the Chain" snapshot published
          │ ├─ 5 nodes running, fully synced
          │ └─ 100+ wallets, 200+ txs, zero block failures
```

---

## 9. What Comes After 100

| Next Step | Description |
|-----------|-------------|
| **10 → 50 Readers** | Add Reader nodes in EU (Frankfurt, London), Asia (Tokyo, Singapore). Geo-DNS auto-routes. |
| **Fee model v1** | Introduce micro-fees (< 0.001 BB per tx) to prevent spam. Writers earn fees. |
| **USDC on-ramp** | Fiat → USDC → BB swap via the SPL Token engine. Real money on-chain. |
| **Mobile wallet** | React Native app wrapping `@blackbook/sdk`. Push notifications for incoming txs. |
| **rBPF programs** | Activate `solana_rbpf 0.8` for custom on-chain programs. Opens DeFi, NFTs, governance. |
| **Multi-Writer** | Promote top-staked Readers to Writers via leader schedule. True decentralization. |
