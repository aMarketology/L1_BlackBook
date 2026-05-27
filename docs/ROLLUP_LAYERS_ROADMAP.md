# BlackBook — Rollup Layers 2–5 Roadmap

> **L1 is the settlement layer. Layers 2–5 are rollup execution environments that post state roots back to L1.**
> Last updated: May 2026 — Full infrastructure audit complete. Dual L2 system documented. L5 golden rule established.

---

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    BLACKBOOK L1 (Settlement)                 │
│  PoH Clock · Tower BFT · Sealevel · Gulf Stream · Turbine   │
│  Global Escrow · Universal Rollup Hub · NFT Bridge          │
│  Two-token economy: BB · wUSDT                              │
│                                                              │
│  POST /rollup/:rollup_id/lock_bb                            │
│  POST /rollup/:rollup_id/submit_root                        │
│  POST /rollup/:rollup_id/exit         ← BB or NFT           │
└────────┬────────────┬────────────┬────────────┬─────────────┘
         │            │            │            │
    ┌────▼────┐  ┌────▼────┐  ┌───▼───┐  ┌────▼────┐
    │  L2     │  │  L3     │  │  L4   │  │  L5     │
    │ Predict │  │  NFT    │  │ Yield │  │ Creator │
    │ Market  │  │ Bridge  │  │ Vault │  │ Economy │
    │ rollup  │  │ rollup  │  │       │  │ rollup  │
    └─────────┘  └─────────┘  └───────┘  └─────────┘
```

**How every layer talks to L1 via the Universal Rollup Hub:**
1. Users lock $BB in the per-rollup vault PDA via `POST /rollup/:rollup_id/lock_bb`
2. Layer runs autonomously (own DB, own execution engine)
3. On settlement: sequencer submits a SHA-256 Merkle root via `POST /rollup/:rollup_id/submit_root`
4. L1 enforces: registered sequencer signature, monotonically increasing batch_id
5. Users exit via `POST /rollup/:rollup_id/exit` with a Merkle proof — L1 releases BB or mints NFT

---

## Universal Rollup Hub — L1 Bridge API ✅ LIVE

All five routes are implemented and building cleanly at `src/contracts/rollup/mod.rs`.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /rollup/:rollup_id/lock_bb` | User Ed25519 | Lock $BB into rollup vault PDA |
| `GET  /rollup/:rollup_id/locks/:lock_id` | Public | Sequencer reads lock record |
| `POST /rollup/:rollup_id/locks/:lock_id/consume` | Sequencer Ed25519 | Mark lock as spent |
| `POST /rollup/:rollup_id/submit_root` | Sequencer Ed25519 | Anchor Merkle state root on L1 |
| `POST /rollup/:rollup_id/exit` | User Ed25519 | Exit BB or NFT back to L1 |

**rollup_id values:** `"L2"` (Prediction Markets), `"L3"` (NFTs), `"L5"` (Creator Economy)

### Sequencer Registration
Each rollup's sequencer is registered via env var at startup:
```
L2_SEQUENCER_PUBKEY=<64-char hex Ed25519 pubkey>
L3_SEQUENCER_PUBKEY=<64-char hex Ed25519 pubkey>
L5_SEQUENCER_PUBKEY=<64-char hex Ed25519 pubkey>
```
If an env var is absent, that rollup's `submit_root` and `consume_lock` return HTTP 503.
`lock_bb` and `exit` are always open.

### Signed Message Formats (canonical — must match exactly)
| Action | Message Format |
|---|---|
| lock_bb | `ROLLUP_LOCK_BB:{rollup_id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}` |
| consume lock | `CONSUME_LOCK:{rollup_id}:{lock_id}:{ts}` |
| submit_root | `ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{ts}` |
| exit BB | `ROLLUP_EXIT:{rollup_id}:BB:{address}:{batch_id}:{ts}:{nonce}` |
| exit NFT | `ROLLUP_EXIT:{rollup_id}:NFT:{address}:{batch_id}:{ts}:{nonce}` |

### Canonical Merkle Leaf Encoding
Sequencers MUST produce leaves using these exact formats (colon-separated strings, no JSON):

```
BB leaf:   SHA-256( "{rollup_id}:BB:{address}:{balance_lamports}" )
NFT leaf:  SHA-256( "{rollup_id}:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}" )
```
- `address` — lowercase L1 wallet address
- `balance_lamports` — $BB amount as decimal integer (no decimals)
- `metadata_hash` — SHA-256 hex of the NFT metadata JSON

### ReDB Storage
| Table | Key format | Value |
|---|---|---|
| `ROLLUP_STATE_ROOTS` | `"{rollup_id}:{batch_id:020}"` (zero-padded) | 32-byte root |
| `ROLLUP_CONSUMED_EXITS` | `SHA256("{rollup_id}:{batch_id}:{asset_type}:{identity}")` | timestamp u64 |
| `ROLLUP_LOCKS` | lock UUID | `RollupLockRecord` JSON |

### Double-Spend Protection
Every exit is permanently sealed in `ROLLUP_CONSUMED_EXITS` **after** the asset transfer succeeds.
On BB exits the vault debit+credit are rolled back if the seal write conflicts (concurrent exit attempt).
On NFT exits the `nft_bridge::get_nft` pre-check rejects if the token already exists on L1.

---

## Layer 2 — Prediction Market ⭐ IN PRODUCTION

**Status:** Running at `:1234`. Frontend wallet integrated. Rollup Hub bridge ready.

### What L1 Provides
| Feature | L1 Endpoint | Status |
|---|---|---|
| BB lock-in (new hub path) | `POST /rollup/L2/lock_bb` | ✅ Live |
| State root anchoring | `POST /rollup/L2/submit_root` | ✅ Live |
| BB exit with Merkle proof | `POST /rollup/L2/exit` | ✅ Live |
| Legacy escrow deposit | `POST /escrow/deposit` | ✅ Working |
| Legacy state root | `POST /escrow/submit-state-root` | ✅ Working |
| Legacy withdrawal | `POST /escrow/withdraw` | ✅ Working |
| Monotonicity enforcement | Auto-reject stale batch_id | ✅ Implemented |
| Claim window (30 days) | 6,480,000 slots from settlement | ✅ Implemented |
| Double-claim prevention | ROLLUP_CONSUMED_EXITS (permanent seal) | ✅ Implemented |

### L2 ← L1 Integration Contract (What L2 Must Send)

**Deposit verification:**
The L2 receives a `deposit_tx` UUID from the L1 escrow response. The L2 must:
1. Trust the deposit_tx ref only after validating via `GET /deposit/status/:tx_hash`
2. Lock user into the market entry only once `status == "approved"`

**State root submission** (after market resolution):
```json
POST /escrow/submit-state-root
{
  "market_id": "MLS-W8-LAFC",
  "merkle_root": "<64 hex chars — 32 bytes>",
  "signature": "<Ed25519 signature over: market_id_bytes ++ l2_block_number.to_le_bytes(8) ++ merkle_root[32]>",
  "l2_block_number": 101,          // strictly > last submitted
  "total_deposited": 5000000,       // SPL units (6 dec) — sum of all deposits
  "total_payout": 4750000,          // SPL units — sum of winner payouts
  "house_rake": 250000,             // SPL units — must equal deposited - payout
  "winner_count": 3
}
```

**Merkle leaf format** (must match L1 verify logic exactly):
```
leaf = SHA256( pubkey_raw_32_bytes || payout_spl_u64_le_bytes )
```
- `pubkey_raw_32_bytes` = bs58-decoded user wallet address (32 bytes)
- `payout_spl_u64_le_bytes` = `(payout_bb * 1_000_000).round() as u64` in little-endian

**Claim proof format** (returned by L2 to user frontend):
```json
{
  "market_id": "MLS-W8-LAFC",
  "wallet": "<base58 address>",
  "proof": ["<32-byte hex node>", "<32-byte hex node>", ...],
  "payout_spl": 1500000,
  "payout_bb": 1.5,
  "claim_deadline_slot": 7012345
}
```

### The Dual L2 System — Critical Architecture Note

There are two **incompatible** L2 settlement paths in the codebase. This is intentional during migration.

| | System A — Legacy Global Escrow | System B — Rollup Hub |
|---|---|---|
| Endpoints | `/escrow/deposit`, `/escrow/submit-state-root`, `/escrow/withdraw` | `/rollup/L2/lock_bb`, `/rollup/L2/submit_root`, `/rollup/L2/exit` |
| Merkle leaf | `SHA256(bs58_decode(wallet)[32] ∥ amount_spl_u64_le[8])` — **binary** | `SHA256("L2:BB:{address}:{lamports}")` — **UTF-8 string** |
| Amount units | SPL units (6 dec, lamports × 10) | Lamports (5 dec) |
| Sig format | Binary packed: `id_bytes ∥ block_num_le64 ∥ root32` | UTF-8: `"ROLLUP_SUBMIT_ROOT:L2:{batch_id}:{root_hex}:{ts}"` |
| Vault | Single global PDA | Per-rollup PDA: `rollup_vault_address("L2")` |
| Who funds vault | **Dealer** pre-funds prize pool | **Each user** locks their own BB |
| Zero-sum check | Enforced at root submission | Not needed — vault balance is ground truth |
| Claim deadline | 30 days (6.48M slots) | No deadline |
| SDK | `dealer.sdk.ts` — `buildMerkleTree()`, `submitStateRoot()` | Not yet built |

**Deprecation plan:**
1. ✅ No new System A markets — stop calling `/escrow/deposit` for new contests
2. 🔒 Keep `/escrow/*` endpoints permanently live — existing funds are locked, users must be able to claim
3. 🔲 Add `buildRollupMerkleTree()` and `submitRollupRoot()` to `dealer.sdk.ts`
4. 🔲 Build the TypeScript L2 sequencer against System B
5. 🔲 Delete `src/contracts/layer2_market/mod.rs` only after all System A claim windows expire (30+ days after last settlement)

> **Note:** `src/contracts/layer2_market/mod.rs` is already `#![allow(dead_code)]` — it is called from nowhere. The actual Merkle tree for System A is built entirely in `dealer.sdk.ts::buildMerkleTree()`. The Rust file is a reference spec only.

---

## Layer 3 — NFT Bridge ✅ L1 SIDE COMPLETE

**Status:** L1 anchor + rollup hub exit wired. L3 sequencer and execution engine not yet built.

### Purpose
L3 is the NFT layer. Users lock $BB on L1, play / trade NFTs in the L3 environment,
then exit their NFTs back to L1 where they are permanently anchored via `nft_bridge::put_nft()`.

### What L1 Provides (all live)
| Feature | L1 Endpoint | Status |
|---|---|---|
| $BB lock into L3 vault | `POST /rollup/L3/lock_bb` | ✅ Live |
| State root anchoring | `POST /rollup/L3/submit_root` | ✅ Live |
| NFT exit with Merkle proof | `POST /rollup/L3/exit` (asset_type="NFT") | ✅ Live |
| NFT read | `GET /nft/:collection_id/:token_id` | ✅ Live |
| BB exit from L3 | `POST /rollup/L3/exit` (asset_type="BB") | ✅ Live |

### NFT Exit Flow
```
L3 user wants to bring their NFT to L1
  1. L3 sequencer builds Merkle tree of NFT ownerships:
     leaf = SHA-256("{rollup_id}:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}")
  2. L3 submits root → POST /rollup/L3/submit_root
  3. User calls POST /rollup/L3/exit with:
     { asset_type: "NFT", collection_id, nft_token_id, metadata_uri, metadata_hash,
       batch_id, proof_siblings, sibling_is_right, public_key, signature, timestamp, nonce }
  4. L1 verifies Merkle proof → double-spend check → calls nft_bridge::put_nft()
  5. NFT is now permanently anchored on L1 (can be read via GET /nft/...)
```

### What Still Needs to Be Built
- [ ] **L3 execution engine** — NFT trading environment (off-chain, Rust or Node)
- [ ] **L3 sequencer** — builds NFT Merkle tree, signs roots, calls L1
- [ ] **L3 SDK** — TypeScript client for minting, trading, exiting NFTs
- [ ] **L3_SEQUENCER_PUBKEY** env var — must be set in production

---

## Layer 4 — Yield Vault 📋 PLANNED

**Status:** Not started.

### Purpose
Auto-compounding yield vaults. Users lock $BB, vault allocates to L2/L3 strategies, profits
settle back via Merkle proof claims on L1.

### How It Uses L1
- Lock funds: `POST /rollup/L4/lock_bb` (once rollup_id `"L4"` is added to the registry)
- Settlement: `POST /rollup/L4/submit_root`
- Withdrawals: `POST /rollup/L4/exit`

### L1 Changes Required
- [ ] Add `"L4"` to rollup registry + `L4_SEQUENCER_PUBKEY` env var
- [ ] **Partial claims** — yield vaults claim yield without closing principal

---

## Layer 5 — Creator Economy Rollup 📋 PLANNED

**Status:** L1 bridge fully wired (`rollup_id = "L5"`). L5 execution engine not built.

### Purpose
Creator token launchpad — like pump.fun but settlement-backed. Creators lock $BB on L1 to
seed their L5 token's initial reserve. The L5 sequencer credits rollup-$BB and runs the
bonding curve. When a creator or holder wants to exit back to L1, they supply a Merkle proof.

### What L1 Provides (all live)
| Feature | L1 Endpoint | Status |
|---|---|---|
| Creator seed lock | `POST /rollup/L5/lock_bb` | ✅ Live |
| State root anchoring | `POST /rollup/L5/submit_root` | ✅ Live |
| BB exit back to L1 | `POST /rollup/L5/exit` (asset_type="BB") | ✅ Live |
| Lock consumed? | `POST /rollup/L5/locks/:id/consume` | ✅ Live |
| Legacy L5 roots migrated | Startup migration L5_STATE_ROOTS → ROLLUP_STATE_ROOTS | ✅ Done |

### What Still Needs to Be Built
- [ ] **L5 bonding curve engine** — price formula, token accounting, off-chain
- [ ] **L5 sequencer** — builds Merkle tree of balances, signs roots, calls L1
- [ ] **L5 SDK** — TypeScript client for lock, trade, exit
- [ ] **`L5_SEQUENCER_PUBKEY`** env var — must be set in production

---

## L1 Shared Infrastructure Status

These items are needed by ALL rollup layers.

| Feature | Status | Notes |
|---|---|---|
| Universal Rollup Hub | ✅ Done | `/rollup/:rollup_id/lock_bb\|submit_root\|exit` |
| Per-rollup vault PDA | ✅ Done | `rollup_vault_address(rollup_id)` — unique per rollup |
| Multi-asset exit (BB + NFT) | ✅ Done | `asset_type` field in ExitRequest |
| Permanent double-spend seal | ✅ Done | `ROLLUP_CONSUMED_EXITS` ReDB table |
| Sequencer registry | ✅ Done | `authorized_sequencers` DashMap, loaded from env vars |
| NFT anchor (L3 exit) | ✅ Done | `nft_bridge::put_nft()` called from exit handler |
| Legacy L5 root migration | ✅ Done | `L5_STATE_ROOTS` → `ROLLUP_STATE_ROOTS` at startup |
| Global Escrow deposit | ✅ Done | `POST /escrow/deposit` (legacy L2 path) |
| Merkle root verification | ✅ Done | SHA-256 sorted-pair, 32-byte nodes |
| Monotonicity enforcement | ✅ Done | Zero-padded batch_id rejects stale roots |
| ReDB-first persistence | ✅ Done | Disk before DashMap cache |
| Rollup lock consumed guard | ✅ Done | `consumed` field + `consume_lock_handler` |
| WebSocket balance push | ✅ Done | Real-time balance updates post-exit |
| `simulateTransaction` | ❌ Needed | RPC pre-flight for wallets |
| Partial claims (L4) | ❌ Needed | Yield vaults need claim-without-close |
| Balance snapshots (governance) | ❌ Needed | `GET /balance/snapshot/:addr/:slot` |

---

## Implementation Priority

```
IMMEDIATE (sequencer integration):
  1. Update L2 sequencer to use /rollup/L2/ paths with new leaf format
     BB leaf: SHA-256("{rollup_id}:BB:{address}:{balance_lamports}")
  2. Set L2_SEQUENCER_PUBKEY in Hetzner .env
  3. Run end-to-end exit test: lock_bb → play → submit_root → exit

NEXT (L3 NFT layer):
  4. Build L3 execution engine (NFT minting/trading, off-chain)
  5. L3 sequencer: builds NFT Merkle tree with correct leaf format
     NFT leaf: SHA-256("{rollup_id}:NFT:{col}:{tok}:{owner}:{meta_hash}")
  6. Set L3_SEQUENCER_PUBKEY in production
  7. SDK: TypeScript client for lock_bb/submit_root/exit (asset_type=NFT)

NEXT (L5 Creator Economy):
  8. Build L5 bonding curve engine (off-chain)
  9. L5 sequencer: builds BB balance Merkle tree
  10. Set L5_SEQUENCER_PUBKEY in production

LONG TERM:
  11. L4 Yield Vaults (add "L4" rollup_id, partial claims)
  12. simulateTransaction RPC
  13. Balance snapshot endpoint
```


## LI.FI Integration & $XX Token Strategy

### LI.FI Widget (Track A — Live)
Embedded in the wallet `DepositModal`. No signup required. Bridges any source token on any chain to **native Solana USDT** in our custody wallet. The existing `CustodyWatcher` picks it up unchanged.

```tsx
// Lock destination: native Solana USDT into our custody wallet
const config: WidgetConfig = {
  integrator: 'BlackBook',
  toChain: 1151111081099710,   // Solana chainId in LI.FI
  toToken: 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  toAddress: import.meta.env.VITE_CUSTODY_WALLET,
  hiddenUI: ['toAddress', 'toToken', 'toChain'],
};
```

### Native Chain Listing (Track B — 3–6 months)
Sequence: stable Railway RPC → apply to Mayan Finance → LI.FI partner portal → get BB chain ID → update widget config.

Requirements: high-uptime JSON-RPC, chain ID registration, bridge partner, block explorer, token list JSON.

### $XX / MAXXCOIN — Legal Framework

**$XX is a utility token, not a security, if:**
- It provides on-chain utility (governance votes, fee discounts, $DECAY redemption)
- Price is algorithmic (bonding curve `P(s) = 5×10⁻⁸ × s`) — not issuer-set
- No promises of profits or returns

**Key rules:**
- Describe as: *"utility token for platform governance and fee access"*
- Do NOT promise returns, profits, or yield in fiat
- Do NOT market to US persons without Reg D/S exemption
- Keep KYC/AML for purchases > $10,000
- First buyer sets the curve — no pre-mine, no team allocation

**Full swap path:**
```
Any chain → LI.FI → native Solana USDT → custody wallet
  → watcher mints wUSDT 1:1 → BB at 10:1 dealer rate
  → POST /sealevel/submit SwapBbForUsdc  (BB → wUSDT)
  → POST /maxx/buy                       (wUSDT → $XX at curve)
```

---

## Reference Documents

| Doc | What It Covers |
|---|---|
| [L2_INTEGRATION.md](L2_INTEGRATION.md) | Full L2 protocol spec: gRPC, HTTP, crypto, error codes, test guide |
| [ENDPOINT_GUIDE.md](ENDPOINT_GUIDE.md) | Full L1 API reference (76 endpoints) |
| [CHAIN_REFERENCE.md](CHAIN_REFERENCE.md) | Technical spec: tokens, crypto, PoH, SVM, storage |
| [IMPLEMENTATION_ROADMAP.md](IMPLEMENTATION_ROADMAP.md) | 14 milestones + onramp hardening phases |
