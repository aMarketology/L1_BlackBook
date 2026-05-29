# BlackBook — Rollup Architecture & L1 Interaction Reference

> **Ground truth documentation.** Describes the actual deployed codebase as of May 2026,
> not a proposal. All file paths, endpoint names, and data types are verified against source.

---

## 1. The Real Stack

```
┌────────────────────────────────────────────────────────────────────┐
│  Next.js / React Front-End  (blackbook-wallet/src/)                │
│  TypeScript — HTTP REST + WebSocket to L1 on :8080                │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
                               ▼  REST / WS
┌────────────────────────────────────────────────────────────────────┐
│  LAYER 1 — BlackBook Settlement Chain                              │
│  Pure Rust · Tokio · Axum 0.7 · ReDB · DashMap                   │
│  HTTP :8080   UDP TPU :8003                                        │
│                                                                    │
│  Proof of History · Tower BFT · Sealevel · Gulf Stream            │
│  Universal Rollup Hub · Global Escrow · NFT Bridge                │
│  Two-token: $BB (5 dec) · wUSDT (6 dec)                          │
└──────┬──────────────────┬──────────────────┬────────────────────  ┘
       │                  │                  │
       ▼                  ▼                  ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  LAYER 2     │  │  LAYER 3     │  │  LAYER 5     │
│  Prediction  │  │  NFT Engine  │  │  Creator     │
│  Markets     │  │              │  │  Economy     │
│              │  │              │  │              │
│  TypeScript  │  │  TypeScript  │  │  TypeScript  │
│  Node.js     │  │  Node.js     │  │  Node.js     │
│  SQLite WAL  │  │  SQLite WAL  │  │  (planned)   │
│  :7072       │  │  :7073       │  │  :7075       │
└──────────────┘  └──────────────┘  └──────────────┘
```

**Important:** L2, L3, and L5 sequencers are TypeScript/Node.js processes today.
The "Rust execution" for L2 and L3 lives on **L1** — the rollup hub, NFT bridge, and
signature verification are all Rust. The sequencers are lightweight orchestrators.

---

## 2. Token Economics

| Token | Decimals | Raw Unit | Constant |
|-------|----------|----------|----------|
| `$BB` | 5 | 1 lamport = 0.00001 BB | `LAMPORTS_PER_BB = 100_000` |
| `wUSDT` | 6 | 1 micro-USDT | `USDC_UNIT = 1_000_000` |

**Immutable protocol invariant** (`src/svm/types.rs`):
```rust
pub const BB_USD_CENTS: u64 = 10;       // 1 BB = $0.10 internal compute value — NEVER changes
pub const LAMPORTS_PER_BB: u64 = 100_000; // 5 decimal places — NEVER changes
const _: () = assert!(BB_USD_CENTS == 10, "$BB internal ledger value is exactly 10 US cents");
const _: () = assert!(LAMPORTS_PER_BB == 100_000, "BB always has exactly 5 decimal places");
```

**External exchange rate** (`BB_PER_USDT`) is dynamic — stored in the `swap_rates` ReDB table,
readable/writable via `POST /admin/swap/set_rate` (unsafe_admin feature only).
Default = 10 (10 BB per 1 wUSDT). Zero-guard prevents divide-by-zero if DB is tampered.

**All financial math uses integer types.** `f64` is only used at the final display/API boundary.

---

## 3. Layer 1 — Universal Rollup Hub

Every rollup layer (L2, L3, L5) communicates with L1 through a single set of endpoints.
The `:rollup_id` path parameter is `"L2"`, `"L3"`, or `"L5"`.

Source: `src/contracts/rollup/mod.rs`

### 3.1 Full Lifecycle

```
User on L2/L3                L1 Rollup Hub                L2/L3 Sequencer
     │                            │                              │
     │── POST /rollup/L2/lock_bb ─►│                              │
     │     (signed, Ed25519)       │── store ROLLUP_LOCKS ──────► │
     │                            │                              │── GET /rollup/L2/locks/:id
     │                            │                              │── creditBalance() in SQLite
     │── [bet / transfer / mint] ──────────────────────────────► │
     │                            │                   executes in SQLite <1ms
     │                            │                              │
     │                            │◄── POST /rollup/L2/submit_root
     │                            │     (signed by sequencer,    │
     │                            │      Merkle root, batch_id)  │
     │                            │── store ROLLUP_STATE_ROOTS   │
     │                            │   enforce batch_id monoton.  │
     │                            │                              │
     │── POST /rollup/L2/exit ───► │                              │
     │     (Merkle proof)          │── verify proof against root  │
     │                            │── release BB from vault PDA  │
     │◄───────────── BB credited ──│                              │
```

### 3.2 Endpoint Reference

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/rollup/:id/lock_bb` | User Ed25519 | Lock $BB into the rollup vault PDA |
| `GET`  | `/rollup/:id/locks/:lock_id` | — | Sequencer reads a lock record |
| `POST` | `/rollup/:id/locks/:lock_id/consume` | Sequencer Ed25519 | Mark lock as spent |
| `POST` | `/rollup/:id/submit_root` | Sequencer Ed25519 | Anchor a Merkle state root on L1 |
| `POST` | `/rollup/:id/exit` | User Ed25519 | Exit assets back to L1 with Merkle proof |

### 3.3 Signed Message Formats (canonical — must match exactly)

```
lock_bb:       "ROLLUP_LOCK_BB:{rollup_id}:{wallet}:{bb_lamports}:{symbol_hint}:{ts}:{nonce}"
consume_lock:  "CONSUME_LOCK:{rollup_id}:{lock_id}:{ts}"
submit_root:   "ROLLUP_SUBMIT_ROOT:{rollup_id}:{batch_id}:{merkle_root_hex}:{ts}"
exit BB:       "ROLLUP_EXIT:{rollup_id}:BB:{address}:{batch_id}:{ts}:{nonce}"
exit NFT:      "ROLLUP_EXIT:{rollup_id}:NFT:{address}:{batch_id}:{ts}:{nonce}"
```

### 3.4 Merkle Leaf Encoding (sequencers must match exactly)

```
BB leaf:   SHA-256( "{rollup_id}:BB:{address}:{balance_lamports}" )
NFT leaf:  SHA-256( "{rollup_id}:NFT:{collection_id}:{token_id}:{owner}:{metadata_hash}" )
```

Merkle combination: `SHA-256( min(a,b) || max(a,b) )` — sorted pair, deterministic.

### 3.5 Monotonicity Enforcement (L1-side, `src/storage/mod.rs`)

```rust
pub fn store_rollup_state_root(&self, rollup_id: &str, batch_id: u64, root: [u8; 32])
    -> Result<(), String>
{
    if let Some(latest) = self.latest_rollup_batch_id(rollup_id) {
        if batch_id <= latest {
            return Err(format!(
                "{} batch_id {} is not greater than latest {} (monotonicity violation)",
                rollup_id, batch_id, latest
            ));
        }
    }
    // ... ReDB write
}
```

All three rollup IDs share this function — L2, L3, and L5 each get independent monotonic
sequences stored under zero-padded keys `"{rollup_id}:{batch_id:020}"`.

### 3.6 Double-Exit Prevention

Every successful exit burns a permanent seal into ReDB:

```
ROLLUP_CONSUMED_EXITS: key = SHA-256("{rollup_id}:{batch_id}:{asset_type}:{address|collection:token}")
```

A second exit attempt with the same proof returns `409 CONFLICT` before any state changes.

---

## 4. Layer 1 — Deposit Gateway (Bridge-In)

Source: `src/contracts/deposit_gateway/mod.rs`

Converts external stablecoins (Solana/BSC tx hash) into minted $BB on L1.

### 4.1 Two-Phase Commit (double-mint safe)

```
POST /deposit/request   ──► validate sig + nonce
                             atomic entry() on deposit_requests DashMap
                             store DepositRecord to ReDB (status=pending)

POST /admin/deposit/approve (unsafe_admin) ──►
    is_bridge_tx_processed()  check (ReDB, hot DashMap)
    reserve_bridge_tx()       atomic DashMap entry() ← actual TOCTOU-free guard
    credit_lamports()         mint BB to wallet
    commit_bridge_tx()        persist seal to ReDB
    [on failure] cancel_bridge_tx() removes reservation
```

The `reserve_bridge_tx()` call uses DashMap's `entry()` API — atomic check-and-insert
with no window between check and write. A second approve call on the same tx_hash always fails.

---

## 5. Layer 2 — Prediction Markets Sequencer

Source: `sequencer/l2/src/`

### 5.1 Architecture

```
Axum/Express HTTP :7072
    │
    ├── POST /markets          createMarket()
    ├── POST /markets/:id/bet  placeBet()          ← SQLite transaction, <1ms
    ├── POST /markets/:id/resolve  resolveMarket() ← pro-rata BigInt payout
    └── GET  /markets/:id
    │
    └── setInterval (SLOTS_PER_BATCH × 400ms)
            └── batchSealer.ts
                    ├── snapshot all balances
                    ├── build SHA-256 Merkle tree
                    ├── POST /rollup/L2/submit_root  ← L1 anchor FIRST
                    └── sealBatch() in SQLite        ← local write AFTER
```

### 5.2 State Machine: placeBet()

```typescript
// Everything inside a single SQLite transaction — atomic
db.transaction(() => {
    getBalance()            // read from balances table
    creditBalance(-amount)  // debit immediately (BigInt lamports)
    INSERT INTO l2_positions ... run(marketId, walletAddress, side, amountLamports)  // BigInt, not Number
    UPDATE l2_markets SET pool = pool + ?  run(amountLamports, marketId)             // BigInt, not Number
})
```

`amountLamports` is passed as JavaScript `BigInt` to all SQLite calls.
`node:sqlite` maps BigInt → SQLite INTEGER (exact). `Number()` would map to REAL, losing
precision above 2^53 lamports (~90B BB). Both `.run()` calls use raw BigInt.

### 5.3 Schema

```sql
-- All monetary values: INTEGER lamports, never REAL/FLOAT
balances(rollup_id, address, asset_type, bb_lamports INTEGER)
l2_markets(market_id, question, status, total_yes_pool INTEGER, total_no_pool INTEGER)
l2_positions(market_id, wallet_address, bet_side, amount_lamports INTEGER)
batches(batch_id, rollup_id, merkle_root, entry_count, sealed_at_slot)
locks(lock_id, rollup_id, wallet_address, bb_lamports INTEGER, consumed INTEGER)
```

### 5.4 SQLite Connection Profile (shared/src/db.ts — applied to L2 AND L3)

```typescript
db.pragma('journal_mode = WAL');      // readers never block writers
db.pragma('synchronous = NORMAL');    // fsync at checkpoint only (~3x faster than FULL)
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');     // retry 5 s on SQLITE_BUSY (multi-process safe)
db.pragma('cache_size = -32768');     // 32 MB page cache (default = ~2 MB)
db.pragma('mmap_size = 134217728');   // 128 MB memory-mapped reads (bypasses syscalls)
db.pragma('temp_store = MEMORY');     // ORDER BY / GROUP BY sort buffers in RAM
```

**Performance ceiling (single Node.js process, current setup):**
~800–1,200 SQLite writes/sec before the event queue becomes the bottleneck.
Suitable for current prediction market volumes. A Rust migration (Tokio + rusqlite)
would lift this to ~50,000+ TPS but is not required until that ceiling is approached.

---

## 6. Layer 3 — NFT Engine Sequencer

Source: `sequencer/l3/src/`

### 6.1 Architecture

```
HTTP :7073
    │
    ├── POST /nft/mint       insert l3_nfts row
    ├── POST /nft/transfer   UPDATE l3_nfts SET owner = ?
    └── GET  /nft/:collection/:token
    │
    └── setInterval (SLOTS_PER_BATCH × 400ms)
            └── batchSealer.ts
                    ├── SELECT * FROM l3_nfts (full snapshot)
                    ├── build Merkle tree with NFT leaves
                    │     leaf = SHA-256("L3:NFT:{collId}:{tokId}:{owner}:{metaHash}")
                    ├── POST /rollup/L3/submit_root  ← L1 anchor FIRST
                    └── sealBatch() in SQLite        ← local write AFTER
```

**Crash safety:** if the process dies between `submit_root` and `sealBatch`, the next
timer fires, re-snapshots the same NFT state, builds the same root, and re-submits.
L1 rejects a duplicate batch_id with 409 — the sequencer increments and continues.

### 6.2 Schema

```sql
-- All TEXT or INTEGER, no REAL/FLOAT anywhere
l3_nfts(
    collection_id  TEXT,
    token_id       TEXT,
    owner_address  TEXT,
    metadata_hash  TEXT,   -- anchored in Merkle leaf
    metadata_uri   TEXT,   -- L3-local only, not hashed
    minted_at_ts   INTEGER,
    updated_at_ts  INTEGER,
    PRIMARY KEY (collection_id, token_id)
)
```

### 6.3 L1-Side NFT Bridge

When a user calls `POST /rollup/L3/exit` with an NFT proof, L1 executes:

```rust
// src/contracts/nft_bridge/mod.rs
nft_bridge::put_nft(state, collection_id, token_id, owner, metadata_hash)
```

This mints the NFT as a permanent record on L1 ReDB — no TypeScript involved at that point.

---

## 7. State Sovereignty Rule

**L2 and L3 never talk to each other directly.**

```
                     ┌──────────┐
L2 SQLite ──────────►│          │◄────────── L3 SQLite
                     │   L1     │
                     │  ReDB    │
                     │          │
L2 exit ────────────►│ Rollup   │◄────────── L3 lock
(BB released)        │  Hub     │  (BB locked into L3 vault)
                     └──────────┘

Cross-layer user flow:
  L2 → POST /rollup/L2/exit  →  BB credited on L1
  L1 → POST /rollup/L3/lock_bb  →  BB locked into L3 vault
  L3 sequencer credits balance  →  user operates in L3
```

A bug on L2 (bad payout, corrupted pool total) cannot corrupt L3 state. The only shared
surface is the L1 vault and Rollup Hub endpoints, which are protected by Ed25519 signatures
and the double-exit seal.

---

## 8. Security Model Summary

| Protection | Mechanism | Source |
|---|---|---|
| Replay attacks | Nonce stored in `used_nonces: DashMap<String, u64>`; 60-second timestamp window | `src/auth.rs` |
| Double-mint (bridge) | `reserve_bridge_tx()` atomic DashMap `entry()` + ReDB seal | `src/contracts/deposit_gateway/mod.rs` |
| Double-exit (rollup) | SHA-256 keyed `ROLLUP_CONSUMED_EXITS` ReDB table | `src/contracts/rollup/mod.rs` |
| Root regression | `store_rollup_state_root()` enforces strict `batch_id > latest` | `src/storage/mod.rs` |
| Unauthorized root | Ed25519 sig checked against `authorized_sequencers[rollup_id]` | `src/contracts/rollup/mod.rs` |
| Rate limiting | `NetworkThrottler`: 10 tx/window per wallet | `runtime/core.rs` |
| Divide-by-zero (swap) | `get_swap_rate()` returns `BB_PER_USDT_DEFAULT` if rate is 0 | `src/storage/mod.rs` |
| SQLite TOCTOU (deposit) | `deposit_requests.entry()` is atomic check-and-insert | `src/contracts/deposit_gateway/mod.rs` |
| BigInt precision (L2) | `amountLamports` passed as BigInt (not Number) to SQLite | `sequencer/l2/src/markets.ts` |

---

## 9. Environment Variables

### L1 (Rust)
| Variable | Purpose |
|---|---|
| `L2_SEQUENCER_PUBKEY` | 64-char hex Ed25519 pubkey — authorizes L2 `submit_root` |
| `L3_SEQUENCER_PUBKEY` | 64-char hex Ed25519 pubkey — authorizes L3 `submit_root` |
| `L5_SEQUENCER_PUBKEY` | 64-char hex Ed25519 pubkey — authorizes L5 `submit_root` |
| `USDC_MINT_AUTHORITY` | wUSDT mint authority privkey (auto-generated if unset) |

If a sequencer pubkey env var is not set, `submit_root` and `consume_lock` return `503`;
`lock_bb` and `exit` still work for that rollup.

### L2 Sequencer (TypeScript)
| Variable | Purpose |
|---|---|
| `L2_SEQUENCER_PRIVKEY` | 32-byte hex Ed25519 privkey for signing root submissions |
| `L2_SEQUENCER_PUBKEY` | Corresponding pubkey (must match `L2_SEQUENCER_PUBKEY` on L1) |
| `L1_HTTP_URL` | L1 base URL e.g. `http://localhost:8080` |
| `DB_PATH` | SQLite file path e.g. `./data/l2.sqlite` |
| `PORT` | HTTP port e.g. `7072` |
| `SLOTS_PER_BATCH` | Slots between batch seals e.g. `25` |

### L3 Sequencer (TypeScript)
Same shape as L2, using `L3_SEQUENCER_PRIVKEY` / `L3_SEQUENCER_PUBKEY`, `PORT=7073`.

---

## 10. Build & Start Reference

```powershell
# L1 — development (admin endpoints enabled)
cargo build --features unsafe_admin
.\target\debug\layer1.exe

# L1 — production
cargo build --release
.\target\release\layer1.exe

# L2 sequencer
cd sequencer
$env:L2_SEQUENCER_PRIVKEY = "..."
$env:L2_SEQUENCER_PUBKEY  = "..."
$env:L1_HTTP_URL = "http://localhost:8080"
$env:DB_PATH = "./data/l2.sqlite"
$env:PORT = "7072"
$env:SLOTS_PER_BATCH = "25"
npm run dev   # or: npm start

# L3 sequencer (same pattern, PORT=7073, L3_* keys)
```

---

## 11. What a Rust L2 Migration Would Require

The Node.js sequencer ceiling is ~800–1,200 SQLite writes/sec (single process, WAL mode).
If that ceiling is approached, migrating L2 to Rust yields ~50,000+ TPS via Tokio parallelism.

**Scope of migration:**

| Current | Target |
|---|---|
| `sequencer/l2/src/` TypeScript | New Rust crate e.g. `sequencer-l2/` |
| `node:sqlite` DatabaseSync | `rusqlite` or `redb` |
| `markets.ts` (placeBet, resolveMarket) | Rust structs + Tokio handlers |
| `lockIngest.ts` (poll L1 locks) | Tokio `interval` task |
| `batchSealer.ts` (Merkle + submit) | Already has a Rust equivalent pattern on L1 |
| HTTP server (implicit) | `axum` (already used on L1) |

The L1 endpoints, Merkle leaf format, and Ed25519 signing protocol **do not change**.
Only the sequencer process is replaced. L1 has no awareness of what language the sequencer is written in.

For L3 hybrid (Napi-rs), the TypeScript HTTP layer stays; a `napi-rs` native addon handles
Merkle tree construction and Ed25519 signing at C speed.
