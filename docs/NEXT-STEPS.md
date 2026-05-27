# BlackBook — Next Steps

> **What to do right now, in priority order.**
> Last updated: May 2026 — Post full-infrastructure audit. gRPC reconnect fix deployed. Dual L2 system documented.

---

## Current Status Snapshot

| Layer | L1 Bridge | Sequencer | SDK |
|---|---|---|---|
| **L2 Prediction Markets** | ✅ System A (legacy) + ✅ System B (Rollup Hub) | ✅ Running | ⚠️ Needs `buildRollupMerkleTree` + `submitRollupRoot` |
| **L3 NFT Bridge** | ✅ L1 side complete | ❌ Not built | ❌ Not built |
| **L5 Creator Economy** | ✅ L1 side complete | ❌ Not built | ⚠️ `TokenFactory.ts` calls wrong endpoint |
| **Reader/Writer CQRS** | ✅ Fixed gRPC reconnect anchor bug | — | — |

---

## P0 — Step 1: Expand `dealer.sdk.ts` (System B SDK)

**File:** `sdk/dealer.sdk.ts`

The existing SDK only speaks System A (legacy escrow). The Rollup Hub (System B) needs two new methods.

### `buildRollupMerkleTree(rollupId, entries)`
Build the SHA-256 Merkle tree using the **Rollup Hub canonical leaf format**.

```
BB leaf: SHA-256( "{rollupId}:BB:{address}:{balance_lamports}" )
```

- `address` — lowercase L1 wallet address (plain string, no bs58 decoding)
- `balance_lamports` — `u64` as decimal string
- Tree combination: `SHA256(min(a,b) || max(a,b))` — same sorted-pair helper as existing `merkleHash()`
- Returns: `MerkleTreeResult` (same type as existing `buildMerkleTree()`)

**Critical difference from System A:** No base58 decoding. No SPL unit conversion. Pure UTF-8 string hashing.

### `submitRollupRoot(rollupId, batchId, tree)`
Post the state root to the Rollup Hub with sequencer signature.

```
Sig message (UTF-8): "ROLLUP_SUBMIT_ROOT:{rollupId}:{batchId}:{root_hex}:{timestamp}"
```

- Uses `signMessage()` (UTF-8) — NOT `signBinaryMessage()` (which is System A only)
- POST body: `{ batch_id, merkle_root_hex, sequencer_public_key, signature, timestamp }`
- Endpoint: `POST /rollup/{rollupId}/submit_root`
- Dealer wallet must be the registered sequencer for the rollup (set via `L2_SEQUENCER_PUBKEY` env var on L1)

---

## P0 — Step 2: TypeScript L2 Sequencer

Build a standalone Node.js sequencer that runs the prediction market lifecycle using System B.

**Responsibilities:**
1. Watch for `lock_bb` events (poll `GET /rollup/L2/locks/:lock_id`)
2. Accept user bets off-chain with local DB
3. On market resolution: build Rollup Merkle tree with `buildRollupMerkleTree()`
4. Submit to L1 via `submitRollupRoot()`
5. Store proofs for user withdrawal requests

**Signed messages the sequencer sends:**
| Action | Format |
|---|---|
| Consume lock | `"CONSUME_LOCK:L2:{lock_id}:{ts}"` |
| Submit root | `"ROLLUP_SUBMIT_ROOT:L2:{batch_id}:{root_hex}:{ts}"` |

**Key rule:** Sequencer must keep `batch_id` strictly monotonic. L1 rejects anything <= the last accepted root.

---

## P0 — Step 3: Freeze System A New Entries

**Do NOT shut down System A endpoints.** Existing users have funds locked in the global PDA. They have a 30-day claim window.

**Action required:**
- Stop routing new market deposits to `/escrow/deposit`
- Route all new markets through `/rollup/L2/lock_bb`
- Keep `/escrow/submit-state-root` and `/escrow/withdraw` permanently available

**Dead code note:** `src/contracts/layer2_market/mod.rs` has `#![allow(dead_code)]` — it is called from nowhere. The real Merkle tree for System A is built in `dealer.sdk.ts::buildMerkleTree()`. Do not delete either until all claim windows expire.

---

## P1 — Fix `TokenFactory.ts` Endpoint

**File:** `sdk/TokenFactory.ts`

Currently calls `POST /l5/launch-coin` which does **not exist on L1**.

**Correct two-step flow:**
1. User calls `POST /rollup/L5/lock_bb` on L1 with initial liquidity amount
2. L1 returns a `lock_id`
3. User sends `lock_id` + coin config to the **TypeScript L5 sequencer**
4. Sequencer consumes the lock (`POST /rollup/L5/locks/:lock_id/consume`)
5. Sequencer manages coin state off-chain, anchors roots via `POST /rollup/L5/submit_root`

**L5 exit golden rule:** Creator Coins **cannot** be exited to L1 directly. Users must swap Creator Coins back to $BB on L5 first (via L5 bonding curve / vAMM), then exit via the standard BB Merkle proof path.

---

## P1 — Fix Wrong Comment in `token_swap/mod.rs`

**File:** `src/contracts/token_swap/mod.rs` line 18

Current (wrong): `// 1 BB = 1 wUSDT ($BB is a 1:1 USD stablecoin)`

Correct: `// 1 BB = 0.10 wUSDT — 10 BB buys 1 wUSDT. BB is a $0.10 token, NOT a stablecoin.`

The constants `BB_TO_USDC_RATE = 10` and `BB_PER_USDT = 10` in `src/svm/types.rs` are correct. Only the comment is wrong.

---

## P2 — L3 NFT Bridge Sequencer

L1 is ready. The sequencer and execution engine must be built.

**L3 Merkle leaf format:**
```
NFT leaf: SHA-256( "L3:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}" )
```

**Build order:**
1. L3 execution engine (NFT trading environment, off-chain)
2. L3 sequencer: builds NFT Merkle tree, calls `POST /rollup/L3/submit_root`
3. Set `L3_SEQUENCER_PUBKEY` env var on L1

---

## P2 — Infrastructure

- [ ] **Prometheus metrics** — `GET /metrics`: slot height, TPS, escrow TVL, rollup lock count
- [ ] **Multi-validator** — second Hetzner CX42 as a Reader node (gRPC `SubscribeBlocks` on port 50051)
- [ ] **UptimeRobot** — ping `/health` every 60s (free tier)
- [ ] **ReDB backup** — daily cron snapshot of `blockchain_data/blockchain.redb`

---

## Ongoing: Code Health

| Item | File | Priority |
|------|------|----------|
| Fix wrong comment (1 BB = 1 wUSDT) | `src/contracts/token_swap/mod.rs` line 18 | P1 |
| Replace `credit(f64)` with `credit_svm_lamports(u64)` | `src/main.rs` ~lines 1176, 1256, 1480, 1797 | P1 |
| Strip MAXX/DECAY/$oz UI from wallet | `blackbook-wallet/src/` | P1 |
| Add unit test for Rollup Hub exit (BB + NFT) | `tests/` | P2 |
| Delete `layer2_market/mod.rs` after System A claim windows expire | `src/contracts/layer2_market/mod.rs` | P3 |

---

## Token Economy Reference

| Token | Symbol | Decimals | 1 unit = | Role |
|---|---|---|---|---|
| BlackBook | `$BB` | 5 | $0.10 USD | Gas, bets, oracle bond |
| Wrapped Stablecoin | `wUSDT` | 6 | $1.00 USD | Swap reserve |

**Fixed rate:** 10 BB = 1 wUSDT. No AMM. No oracle. Dealer market-maker only.

**Removed (archived in `archive/contracts/`):** MAXX, DECAY, OZ. Do NOT restore.

---

## Quick Reference: Canonical Signed Message Formats

| Action | Signer | Format |
|---|---|---|
| Transfer | User | `"TRANSFER:{from}:{to}:{amount}:{ts}:{nonce}"` |
| Faucet | User | `"FAUCET:{addr}:{amount}:{ts}:{nonce}"` |
| Swap BB->wUSDT | User | `"SWAP_BB_USDC:{wallet}:{bb_amount}:{ts}:{nonce}"` |
| Lock BB in rollup | User | `"ROLLUP_LOCK_BB:{rollup_id}:{wallet}:{lamports}:{symbol_hint}:{ts}:{nonce}"` |
| Consume lock | Sequencer | `"CONSUME_LOCK:{rollup_id}:{lock_id}:{ts}"` |
| Submit root | Sequencer | `"ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{root_hex}:{ts}"` |
| Exit BB | User | `"ROLLUP_EXIT:{rollup_id}:BB:{address}:{batch_id}:{ts}:{nonce}"` |
| Exit NFT | User | `"ROLLUP_EXIT:{rollup_id}:NFT:{address}:{batch_id}:{ts}:{nonce}"` |
| Legacy escrow root | L2 sequencer | Binary packed: `contest_id_bytes || block_num_le64 || root32` |