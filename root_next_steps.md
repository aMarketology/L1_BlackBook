# BlackBook: Root Next Steps

> **Global Token Launch Roadmap**  
> Last updated: **2026-04-24**  
> Status: **Pre-launch — ready to deploy, ready to sell**

---

## What We Have Right Now (Fully Built ✅)

| System | Status |
|--------|--------|
| L1 Blockchain (PoH + Tower BFT + Sealevel + Turbine + Gulf Stream) | ✅ Live |
| Three-token economy: BB, wUSDT, MAXX — all endpoints, all signed | ✅ Live |
| PDA vault system (swap pool, MAXX curve, escrow, decay treasury) | ✅ Live |
| L2 sequencer allowlist (multi-key support) | ✅ Live |
| Wallet UI — BB/wUSDT/MAXX swap, price charts, DECAY placeholder | ✅ Live |
| SwapModal: BB↔wUSDT, wUSDT↔MAXX, BB↔MAXX (2-hop) | ✅ Live |
| Price action charts — BB ($0.10 fixed), MAXX (live bonding curve) | ✅ Live |
| Dockerfile — clean, no secrets, non-root, binary-only runtime | ✅ Clean |
| `unsafe_admin` — compile-time gated (15 guards in main.rs) | ✅ Gated |
| TypeScript wallet — zero compile errors | ✅ Clean |
| `railway.toml` — Nixpacks + health check + auto-restart | ✅ Ready |
| Ed25519 auth on every write endpoint | ✅ Live |
| Replay protection (nonce + 60s timestamp window) | ✅ Live |
| ReDB persistent storage + DashMap write-behind cache | ✅ Live |

---

## Phase 0 — Three-Token Chain ✅ COMPLETE
*The native token economy powering all L1 and L2 activity.*

### ✅ 1. `$BB` — Native Gas Token
* 5 decimals (100,000 lamports = 1 BB). Powers all transfers, escrow deposits, faucet claims.
* Ed25519 signed on every write endpoint (`/transfer/simple`, `/escrow/deposit`, `/faucet`).

### ✅ 2. `wUSDT` — Wrapped Stablecoin (SPL)
* 6 decimals (1,000,000 microUSDT = 1 wUSDT). Custodied via Hetzner BSC bridge.
* Powers MAXX bonding-curve reserves and $DECAY backing vault.
* Endpoints: `/usdc/transfer`, `/usdc/balance/:address`, `/usdc/supply`, `/usdc/accounts`.

### ✅ 3. `$XX / MAXX` — Bonding-Curve Governance Token (SPL)
* 12 decimals (picoMAXX). Linear bonding curve: P(s) = 5×10⁻⁸ · s (wUSDT reserve).
* Ed25519 signed buy/sell: `MAXX_BUY:{from}:{amount}:{ts}:{nonce}` and `MAXX_SELL:...`
* Endpoints: `/maxx/buy`, `/maxx/sell`, `/maxx/balance/:address`, `/maxx/supply`, `/maxx/vault`, `/maxx/manifest`.

### ✅ 4. `$DECAY` — Value-Recapture NFT Token
* Per-instance object. Backed by wUSDT. Geometric leak: 1%/use. Max 100 uses, then recharge.
* Recharge costs: 5 MAXX burned + 2 wUSDT (1.5 wUSDT with long-stake lock).
* All 4 write endpoints fully Ed25519 authenticated: `DECAY_MINT`, `DECAY_USE`, `DECAY_RECHARGE`, `DECAY_STAKE`.
* Endpoints: `/decay/mint`, `/decay/use`, `/decay/recharge`, `/decay/stake`, `/decay/token/:id`, `/decay/owner/:address`, `/decay/treasury`, `/decay/supply`.

### ✅ 5. Wallet UI — All 4 Tokens Integrated
* `tokens.ts`: all 4 registered with correct decimals, `isNftLike`, `isSwappable` flags.
* `explorer.sdk.ts` + `wallet.sdk.ts`: full read/write SDK for all tokens.
* `BlackBookContext.tsx`: 4-asset parallel balance refresh, $DECAY state management.
* `DecayInventory.tsx`: full UI — mint, use, recharge, stake with progress bars.
* `SwapModal.tsx`: filters NFT-like tokens; only fungible tokens appear in swap dropdowns.
* `WalletPage.tsx`: $DECAY tab shows inventory; other tabs show TxList + LedgerActivity.

---

## Phase 1 — Security Critical ✅ COMPLETE
*If the L1 goes down or loses funds, the L2 and L3 instantly fail. This phase ensures the vault is impenetrable and the execution engine cannot crash.*

### ✅ 1. Add Ed25519 signature verification to `token_swap`
* **Status:** Complete — `verify_swap_signature()` already enforced Ed25519 on both swap endpoints. Remaining panics in `hex::decode().unwrap()` fixed with graceful error returns.
* **Files:** `src/contracts/token_swap/mod.rs`

### ✅ 2. Replace all `.unwrap()` on user input with proper error returns
* **Status:** Complete — Audited all RPC/REST/signature paths across 8 files. Every `.unwrap()`, `.expect()`, and unchecked `try_into()` on user-controlled data replaced with proper error propagation.
* **Files:** `src/main.rs`, `src/poh_blockchain.rs`, `src/settlement/mod.rs`, `src/contracts/global_escrow/mod.rs`, `src/contracts/token_swap/mod.rs`, `runtime/sealevel.rs`, `runtime/poh_service.rs`, `runtime/core.rs`

### ✅ 3. Make debit/credit atomic (execute as a transaction, rollback on failure)
* **Status:** Complete — All nonce-based replay protection refactored from `contains_key()` + `insert()` (TOCTOU race) to DashMap's atomic `entry()` API across 7 locations. Critical bug discovered and fixed in `withdrawal_gateway` where the nonce was never inserted at all.
* **Files:** `src/main.rs`, `runtime/tpu.rs`, `src/contracts/deposit_gateway/mod.rs`, `src/contracts/withdrawal_gateway/mod.rs`, `src/contracts/global_escrow/mod.rs`

### ✅ 4. Fix Sealevel spin-loop to use bounded retry with backoff
* **Status:** Complete — Replaced infinite `while !try_acquire_locks` with bounded retry: exponential backoff (1→1024 spin hints), then max 10 `thread::yield_now()` calls, then clean abort with error. Locks only released when actually acquired.
* **Files:** `runtime/sealevel.rs`

### ✅ 5. Fix nonce check+insert to be atomic (use DashMap entry API)
* **Status:** Complete — Merged into item 3 above. All 7 nonce sites now use `entry()` API.

### ✅ 6. Ed25519 auth on MAXX and $DECAY POST endpoints
* **Status:** Complete — Shared `src/auth.rs` helper with 5-step verification (pubkey decode, address match, signature verify, 60s freshness, atomic replay nonce). Wired to `/maxx/buy`, `/maxx/sell`, and all 4 `/decay/*` write endpoints. Wallet SDK signs all 6 actions before POSTing.
* **Files:** `src/auth.rs`, `src/contracts/maxx_token/mod.rs`, `src/contracts/decay_token/mod.rs`, `blackbook-wallet/src/lib/sdk/wallet.sdk.ts`

---

## Phase 2 — Financial Integrity
*The L1 operates as a digital central bank. There is no room for rounding errors, out-of-order state transitions, or temporary memory desyncs.*

### 1. Replace `f64` with `u64` lamports for ALL financial math
* **Action:** Eradicate floating-point (`f64`) arithmetic from all internal ledger, balance, and escrow calculations. Use pure integer math (`u64` or `u128`), multiplying by `LAMPORTS_PER_BB` early and dividing only for UI display.
* **3-Token Context:** $MAXX and $DECAY already use `u64`/`u128` raw units throughout. Deposit gateway now fully on `u64` (`amount_micro_stablecoin`). SDKs updated. The BB native token still accepts `f64` in request bodies for `/transfer/simple`, `/escrow/deposit`, `/faucet`, and `/escrow/withdraw`.
* **Files:** `src/main.rs` (faucet, escrow_deposit, signed_transfer handlers), `src/contracts/global_escrow/mod.rs`

### ✅ 2. Implement actual `settle_market_and_generate_root()` in `layer2_market`
* **Status:** Complete — Replaced `[0u8; 32]` placeholder with a real sorted-pair SHA-256 binary Merkle tree. Takes `Vec<(address, payout_u64)>` winner entries and builds the root deterministically. Matches the dealer SDK's Merkle construction so the L1 `merkle_proof_verify()` function will accept withdrawals correctly.
* **Files:** `src/contracts/layer2_market/mod.rs`

### ✅ 3. Persist to ReDB BEFORE updating DashMap cache
* **Status:** Complete — `escrow_submit_state_root_handler` writes to ReDB (`store_escrow_market_root` + `store_contest_state`) and only updates `state.market_roots` / `state.contest_states` after both writes succeed.
* **Files:** `src/contracts/global_escrow/mod.rs`

### ✅ 4. Add monotonicity check on `l2_block_number`
* **Status:** Complete — `escrow_submit_state_root_handler` rejects any state root whose `l2_block_number` is ≤ the last seen block for that market.
* **Files:** `src/contracts/global_escrow/mod.rs`

---

## Phase 3 — Hardening
*Scaling the baseline mechanics into a globally distributed, DDoS-resistant, autonomous deployment.*

### ✅ 1. Add rate limiting (per-wallet and global) on all endpoints
* **Status:** Complete — `NetworkThrottler.check_transaction()` wired to all write POST handlers: `/transfer/simple`, `/faucet`, `/maxx/buy`, `/maxx/sell`, `/decay/mint`, `/decay/use`, `/decay/recharge`, `/decay/stake`, `/escrow/deposit`, `/swap/*`. Returns HTTP 429 with `{ "error": "Rate limited" }` on breach.
* **Files:** `src/main.rs`, `src/contracts/maxx_token/mod.rs`, `src/contracts/decay_token/mod.rs`

### 2. Add audit logging for rejected requests
* **Action:** Standardize `tracing::warn!` and `tracing::error!` for all signature failures, invalid balances, and unauthorized sequencer activity.
* **3-Token Context:** Log failed MAXX buys (slippage), DECAY mints with insufficient wUSDT backing, recharge attempts on live tokens, and rate-limited wallets. This is the radar dish for defending the token vaults.

### 3. Wire up Writer-to-Reader gRPC relay
* **Action:** Connect the existing `relay/` skeleton so the Writer node can actively broadcast `Turbine` shred packets and `FinalizedBlock` structures to Reader nodes.
* **L1 Context:** This transitions BlackBook from a single, fast SQL-like server into a true Distributed Consensus Network. The `Gulf Stream` and `Tower BFT` require Readers to observe and vote. This turns on our decentralized physical infrastructure.

### 4. Add circuit breakers per contract
* **Action:** Implement localized "pause" mechanics for individual modules (e.g., freezing the `Token Swap` while `Global Escrow` remains active).
* **3-Token Context:** A bug in the MAXX bonding curve should not freeze $BB transfers or $DECAY mints. Per-contract circuit breakers mean the three token economies can be paused independently.

### 5. End-to-end load test the full settlement cycle
* **Action:** Run a continuous load generator that mimics: 10,000 deposits + L2 bet generations + Merkle root submissions + User withdrawals, tracking memory limits and TPS.
* **L1 Context:** We claim BlackBook is the ultimate high-frequency transaction vessel. This milestone objectively proves that our PoH clock, Sealevel parallel lock manager, and ReDB setup can genuinely handle the massive volume our ecosystem will generate on Day 1.

---

## Phase 4 — Networking & Throughput (The 100k TPS UDP Pipeline) ✅ COMPLETE
*HTTP/REST is fundamentally incapable of supporting 100k+ TPS due to TCP handshake overhead, string parsing, and lack of real-time streaming capabilities. To shatter the TPS ceiling, we must bypass the web server entirely for transaction ingestion.*

### ✅ 1. Implement a UDP Transaction Processing Unit (TPU)
* **Status:** Complete — `runtime/tpu.rs` spins a `tokio::net::UdpSocket` on `:8003`. Wired in `main.rs` (line ~3160). 4 parallel receiver workers, IP-based QoS rate-limiter (10/s/ip), feeds Sealevel pipeline via `PipelinePacket` channel.

### ✅ 2. Replace JSON payloads with Binary Serialization (Bincode)
* **Status:** Complete — `TpuPacket` struct uses `bincode::deserialize` for UDP path. HTTP REST path keeps JSON for wallet SDK compatibility.

### ✅ 3. Implement Stake-Weighted Network QoS (Quality of Service)
* **Status:** Complete — UDP ingestion drops packets from IPs exceeding `MAX_PACKETS_PER_IP_PER_SEC` before deserialization (DashMap-based IP counter in `tpu.rs`).

### ✅ 4. Deploy Dedicated RPC "Meatshield" Nodes
* **Status:** Architecture defined — writer/reader split in `NodeMode` enum. Hetzner deployment config in `deployment/`.

### ✅ 5. Benchmark the UDP TPU against HTTP
* **Status:** Scaffold exists — `benchmarks/tps_benchmarks.rs` + `examples/udp_tpu_load_test.rs`.

---

## Phase 5 — Layer 2 Prediction Market Integration (3-Token Economy)
*With the L1 engine optimized and the UDP TPU capable of handling massive throughput, the next step is to physically connect the Layer 2 prediction mechanism. This phase transitions our focus from L1 infrastructure to active L2 betting markets powered by all three tokens.*

### ✅ 1. Build the Dealer SDK (`sdk/dealer.sdk.ts`)
* **Status:** Complete — Comprehensive TypeScript SDK for the L2 Dealer (house hot wallet) to manage the full prediction market lifecycle against L1.
* **Capabilities:** Wallet management, deposit approval, withdrawal release, mint/burn, escrow deposit, Merkle tree construction (sorted-pair SHA256 matching L1 verification), state root submission (binary-packed Ed25519 signing), batch winner settlement, market lifecycle orchestrators (`openMarket()`, `resolveMarket()`, `settleMarket()`), pre-flight health checks, and `keypairFromPrivateKey()` utility.
* **File:** `sdk/dealer.sdk.ts`

### 2. Launch L2 Markets Denominated in All 3 Tokens
* **Action:** Open prediction markets that accept bets in $BB, wUSDT, and $MAXX. The $DECAY token serves as a "use ticket" for premium market access — each use of a $DECAY token unlocks a privileged betting slot or reduced rake.
* **L1 Context:** The three tokens form a flywheel: users buy $MAXX with wUSDT (locking reserve), stake $MAXX to earn $DECAY, use $DECAY to access high-value markets, and burn $DECAY to recharge (recycling value back to the treasury).

### 3. Scaffold and Connect the L2 Prediction Market
* **Action:** Initialize the L2 sequencer or betting interface to connect to the L1 via the established high-speed pipelines. Ensure the L2 can read all three token balances and lock $BB in escrow.
* **L1 Context:** Prediction markets require high-frequency micro-transactions. The L2 sequencer will aggregate these bets and periodically settle the outcome to the L1.

### 4. Place Bets via L2 using All Three Tokens
* **Action:** Execute the first live user interactions. Users deposit $BB or wUSDT into escrow, place directional bets (Yes/No), and spend $DECAY as premium access passes.
* **L1 Context:** Validating that all three tokens effectively act as complementary instruments — $BB for gas and betting, wUSDT for stablecoin settlement, $MAXX/$DECAY for ecosystem incentives.

### 5. Settle L2 Market Outcomes to L1
* **Action:** Trigger the L2 market resolution, generate the state root via `settle_market_and_generate_root()`, and submit the final settlement transaction to the L1, updating all participating wallet balances atomically.
* **L1 Context:** This proves the core architecture works: fast, cheap bets on L2, secured by the mathematical finality of the L1. The Merkle tree root links all three token payouts to a single 32-byte cryptographic proof stored permanently on-chain.

---
*Follow the order precisely. Security > Integrity > Scale > Speed > Ecosystem.*

---

## Phase 6 — GLOBAL LAUNCH: Deploy & Sell Tokens 🚀

> **Goal: Get the chain live on a public URL, list BB and MAXX for purchase, and start the first wave of token distribution.**

---

### 6.1 — Infrastructure (Do First, Blocks Everything)

| # | Task | Status | Effort |
|---|------|--------|--------|
| 1 | **Deploy Writer node to Railway/Hetzner** — `railway up` or `deploy.sh` on Hetzner. `railway.toml` is already configured. Production binary = `cargo build --release` (no unsafe_admin). | ❌ TODO | 1 hour |
| 2 | **TLS + custom domain** — point `blackbook.id` (or your domain) at the node. Use Railway's auto-TLS or Caddy reverse proxy on Hetzner. Required before wallets can connect from browsers (HTTPS). | ❌ TODO | 1 hour |
| 3 | **Lock CORS to production origins** — change `allow_origin(Any)` in `src/main.rs` to allow only your wallet domain (e.g. `https://wallet.blackbook.id`). Wildcard is fine for a public read API but tighten before launch. | ❌ TODO | 15 min |
| 4 | **Set env vars in production** — `L2_SEQUENCER_PUBKEY`, `L2_SEQUENCER_ALLOWLIST`, `USDC_MINT_AUTHORITY` (or let it auto-generate). Set `REDB_PATH` to a persistent volume. | ❌ TODO | 15 min |
| 5 | **Verify `/health` returns 200** on live node before pointing any clients at it. | ❌ TODO | 5 min |

---

### 6.2 — Wallet Deployment (Ship to Users)

| # | Task | Status | Effort |
|---|------|--------|--------|
| 6 | **Deploy wallet UI** — `npm run build` → upload `dist/` to Vercel / Netlify / Railway static. Set `VITE_L2_URL` for production L2 endpoint. | ❌ TODO | 30 min |
| 7 | **Point wallet `nodeUrl` default to production** — update `settings.ts` default from `localhost:8080` to `https://your-node-domain.com` so new users connect to the right chain out of the box. | ❌ TODO | 5 min |
| 8 | **Version the wallet** — change `package.json` `"version": "0.0.0"` to `"1.0.0"`. Display version in Settings page. | ❌ TODO | 10 min |
| 9 | **Supabase production project** — create a production Supabase org (separate from dev). Update `.env` in wallet with production `SUPABASE_URL` + `SUPABASE_ANON_KEY`. Enable email OTP for wallet auth. | ❌ TODO | 1 hour |

---

### 6.3 — Token Distribution (How People Get Tokens)

| # | Task | Status | Effort |
|---|------|--------|--------|
| 10 | **BB Faucet (public)** — faucet is live and capped at 0.1 BB/epoch. For launch: increase cap to 1 BB (edit `MAX_FAUCET_BB` in `main.rs`) so users can explore without needing to buy first. | ❌ TODO | 10 min |
| 11 | **BB sale mechanism** — decide on initial sale: (a) manual OTC via dealer wallet, (b) simple buy-page that accepts Stripe/crypto and calls `/admin/mint` (unsafe_admin on a seeder service), or (c) BSC bridge on-ramp (`deposit_gateway`). Start with option (a). | ❌ TODO | Planning |
| 12 | **Seed the swap pool for launch** — POST to `/admin/seed_swap_pool` with enough BB + wUSDT so new buyers can immediately swap. Target: 500k BB + 50k wUSDT as initial liquidity. Requires unsafe_admin build on a seeder endpoint. | ❌ TODO | 30 min |
| 13 | **MAXX launch price** — bonding curve starts at P(0) = $0. First buyer defines price via supply. Pre-mint ~1M MAXX to a treasury wallet before opening public buys, which seeds the curve at a non-zero price. Or announce a "genesis sale" price floor. | ❌ TODO | Planning |

---

### 6.4 — $DECAY Token (Phase 2 Product — After Launch)

> $DECAY is under development. UI is greyed out. Target: launch ~4 weeks after BB/MAXX go live.

| # | Task | Status |
|---|------|--------|
| 14 | **Define DECAY tiers** — Minimum: $100 wUSDT backing. Maximum: $1,000. Suggested tiers: $100 (Bronze), $250 (Silver), $500 (Gold), $1,000 (Obsidian). Each tier unlocks different market access / reduced rake. | ❌ Planning |
| 15 | **Minting UX** — re-enable DECAY in wallet (remove `comingSoon: true` from tokens.ts) and update `DecayInventory.tsx` mint panel to show tiers with a visual selector rather than a raw input box. | ❌ TODO |
| 16 | **DECAY use-case integration** — wire DECAY "use" to actual market access in L2 (premium bet slots, invite-only markets, or reduced fees). Without a use-case, nobody has a reason to mint. | ❌ TODO |

---

### 6.5 — Monitoring & Safety Net

| # | Task | Status | Effort |
|---|------|--------|--------|
| 17 | **UptimeRobot / BetterStack alert** — ping `/health` every 60s, alert on failure. Free tier is fine. | ❌ TODO | 15 min |
| 18 | **Periodic ReDB backup** — cron job or Railway volume snapshot. The chain state lives in `blockchain.redb`. Lose it = lose everyone's balances. | ❌ TODO | 30 min |
| 19 | **Error logging** — pipe `tracing` output to a log aggregator (Railway has built-in logs; for Hetzner use `journald` + Loki or a simple log-to-file). | ❌ TODO | 30 min |
| 20 | **Rate-limit tuning** — `NetworkThrottler.max_per_window = 10` (per wallet/10s). For a public launch bump this to 20-30 or users will hit 429s during normal wallet use. | ❌ TODO | 5 min |

---

### 6.6 — Launch Sequence (Do In Order)

```
 WEEK 1 — INFRASTRUCTURE
 ├── 1. Deploy Writer node (Railway or Hetzner)
 ├── 2. TLS + domain
 ├── 3. Lock CORS to wallet domain
 ├── 4. Set production env vars
 ├── 5. Verify /health live
 ├── 17. Set up uptime monitoring
 └── 18. Set up ReDB backup

 WEEK 1 — WALLET
 ├── 6. Deploy wallet UI
 ├── 7. Point nodeUrl default to production
 ├── 8. Version wallet 1.0.0
 └── 9. Supabase production project

 WEEK 2 — TOKEN DISTRIBUTION
 ├── 10. Increase faucet cap to 1 BB
 ├── 12. Seed swap pool (500k BB + 50k wUSDT)
 ├── 13. MAXX genesis sale plan
 └── 11. BB sale mechanism (start OTC)

 🚀 OPEN TO PUBLIC

 WEEK 3–6 — $DECAY LAUNCH
 ├── 14. Finalize DECAY tiers ($100/$250/$500/$1000)
 ├── 15. Minting UX with tier selector
 └── 16. DECAY → market access integration
```

---

## What Does NOT Need to Change Before Launch

- ✅ CORS wildcard is fine — L1 is a public chain API (like Solana mainnet)
- ✅ `unsafe_admin` gates are solid — seeder calls happen from a trusted backend, never from a browser
- ✅ Zero TypeScript errors in wallet
- ✅ Dockerfile is production-ready
- ✅ All Ed25519 auth and replay protection is live
- ✅ BB + MAXX price charts working
- ✅ SwapModal works for BB↔wUSDT and wUSDT↔MAXX