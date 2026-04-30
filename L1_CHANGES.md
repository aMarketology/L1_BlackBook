# BlackBook L1 — Session 1 Change Spec

> **Created:** 2026-04-26  
> **Target repo:** L1 Rust (`C:\Users\maxd1\Documents\GitHub\L1_BlackBook\` — outside the wallet repo)  
> **Mission:** Kill the 4 P0 onramp bugs so the wallet is safe to take real money.  
> **Estimated scope:** Single focused session, no feature work.

---

## Status

| Bug | Description | Status |
|-----|-------------|--------|
| #1 | f64 → u64 integer math | ✅ **DONE** |
| #2 | Atomic reserve_bridge_tx | ✅ **DONE** |
| #3 | Silent deposit drops | ✅ **DONE** |
| #4 | BSC decode_transfer panic | ✅ **DONE** |

**Build:** `cargo check --features unsafe_admin` — 0 errors, warnings only ✅

---

## What Was Implemented

### Bug #1 + #2 — Integer math + atomic reserve (implemented together)

**Files changed:** `src/storage/mod.rs`, `src/contracts/deposit_gateway/mod.rs`, `src/watcher/mod.rs`, `src/watcher/bsc_watcher.rs`

`DepositRecord` struct updated:
- `amount_stablecoin: f64` → `amount_micro_stablecoin: u64` (6-decimal micro-units)
- `bb_to_mint: f64` → `bb_lamports: u64` (5-decimal lamports)

New methods on `ConcurrentBlockchain`:
- `reserve_bridge_tx(tx_hash)` — atomic DashMap `Entry::Vacant` claim, Err if already reserved/committed
- `commit_bridge_tx(tx_hash, mint_id)` — write to ReDB then update DashMap
- `cancel_bridge_tx(tx_hash)` — remove reservation on mint failure
- `credit_lamports(address, lamports)` — integer path into existing `credit()`
- `is_bridge_tx_processed()` updated to filter out `"reserved"` sentinel

All callers updated to use `reserve → credit_lamports → commit/cancel` pattern.  
f64 inputs from HTTP request body are converted at the API boundary only.

### Bug #3 — Silent deposit drops

**Files changed:** `src/storage/mod.rs`, `src/watcher/mod.rs`, `src/contracts/deposit_gateway/mod.rs`, `src/main.rs`

**Problem:** Users who sent stablecoin to the custody wallet without first calling `/deposit/request` had their deposits silently ignored.

**Solution — three-tier deposit detection in `scan_new_deposits`:**
- **Tier 1:** Known request (`deposit_requests.contains_key`) → existing `verify_and_approve()` path (unchanged)
- **Tier 2:** Unknown tx, valid `BB:<base58>` memo → auto-create `DepositRecord`, call `verify_and_approve()` immediately
- **Tier 3:** Unknown tx, no valid memo → queue as `UnattributedDeposit` in ReDB for user to claim later

**New storage in `src/storage/mod.rs`:**
- `UNATTRIBUTED_DEPOSITS: TableDefinition<&str, &[u8]>` — ReDB table (initialized at startup)
- `UnattributedDeposit` struct: `external_tx_hash`, `asset`, `amount_micro_stablecoin: u64`, `observed_at: u64`, `claimed_by: Option<String>`
- `write_unattributed_deposit()`, `get_unattributed_deposit()`, `mark_unattributed_claimed()` methods

**New `extract_wallet_from_memo(memo: Option<&str>) -> Option<String>`** — validates `BB:` prefix, bs58-decodes to verify 32-byte pubkey.

**New endpoint `POST /deposit/claim`:**
- Ed25519 auth with message `"CLAIM_DEPOSIT:{wallet}:{tx_hash}:{ts}:{nonce}"`
- Looks up `UNATTRIBUTED_DEPOSITS` by tx hash
- Returns 404 if not found, 409 if already claimed
- Mints BB via `reserve → credit_lamports → commit` atomic pattern
- Calls `mark_unattributed_claimed` in ReDB

### Bug #4 — BSC decode_transfer safety`decode_transfer()` updated to use `hex::decode()` for proper bounds-checked binary decode instead of string slicing. `verify_receipt()` inner log decode also updated to `hex::decode`.

---

## Bug #1 — `f64` → `u64` Integer Math (DO THIS FIRST)

### File: `storage/mod.rs`

**Current (broken):**
```rust
pub struct DepositRecord {
    pub tx_hash: String,
    pub source_chain: String,
    pub source_address: String,
    pub destination_wallet: String,
    pub amount_stablecoin: f64,   // ❌ float
    pub bb_to_mint: f64,           // ❌ float
    pub status: DepositStatus,
    pub created_at: i64,
    pub credited_at: Option<i64>,
}
```

**Replace with:**
```rust
pub struct DepositRecord {
    pub tx_hash: String,
    pub source_chain: String,
    pub source_address: String,
    pub destination_wallet: String,
    pub stablecoin_symbol: String,        // "USDT" | "USDC" | "BUSD"
    pub stablecoin_decimals: u8,          // 6 for Solana USDT/USDC, 18 for BSC USDT
    pub amount_micro: u64,                // raw on-chain units (no conversion!)
    pub bb_to_mint_lamports: u64,         // 9 dec — final BB amount
    pub status: DepositStatus,
    pub created_at: i64,
    pub credited_at: Option<i64>,
    pub error: Option<String>,            // for failed deposits
}
```

### New file: `storage/conversions.rs`
```rust
/// Convert any stablecoin micro-units → wUSDT-equivalent (always 6 dec internally)
pub fn normalize_to_wusdt_micro(amount_micro: u64, source_decimals: u8) -> u64 {
    const TARGET_DECIMALS: u8 = 6;
    if source_decimals == TARGET_DECIMALS {
        amount_micro
    } else if source_decimals > TARGET_DECIMALS {
        let divisor = 10u64.pow((source_decimals - TARGET_DECIMALS) as u32);
        amount_micro / divisor
    } else {
        let multiplier = 10u64.pow((TARGET_DECIMALS - source_decimals) as u32);
        amount_micro
            .checked_mul(multiplier)
            .expect("overflow normalizing micro units")
    }
}

/// Fixed dealer rate: 1 wUSDT = 10 BB
/// wUSDT has 6 dec, BB has 9 dec → multiplier is 10 * 10^3 = 10_000
pub fn wusdt_to_bb_lamports(wusdt_micro: u64) -> u64 {
    wusdt_micro
        .checked_mul(10_000)
        .expect("overflow wusdt→bb")
}
```

### Migration
- Add a one-time migration that reads old `f64` records, converts them, and writes new format
- Or: drop the table if you have no production data yet (probably the case)

### Audit checklist (search and fix every site)
- [ ] Every `as f64` and `as u64` cast in deposit code
- [ ] Every `* 10.0` or `/ 1_000_000.0` — replace with integer ops
- [ ] All HTTP responses serializing `f64` — switch to `u64` + `decimals` field
- [ ] Frontend will receive `{ amount_micro: u64, decimals: u8 }` and format on display

---

## Bug #2 — Atomic `reserve_bridge_tx` (Race Fix)

### File: `watcher/mod.rs` (or wherever `mark_bridge_tx_processed` lives)

**Current (broken pattern):**
```rust
// ❌ Two threads can both pass this check before either calls credit()
if storage.is_bridge_tx_processed(&tx_hash)? {
    return Ok(());
}
credit(wallet, amount).await?;
storage.mark_bridge_tx_processed(&tx_hash)?;
```

**Replace with reserve → credit → commit pattern:**
```rust
use dashmap::mapref::entry::Entry;

#[derive(Clone, Debug)]
enum ReservationState {
    Reserved { reserved_at: i64 },
    Committed,
}

pub struct BridgeTxRegistry {
    // Hot cache for in-flight reservations (DashMap = lock-free per-key)
    cache: DashMap<String, ReservationState>,
    // Persistent committed set (ReDB)
    storage: Arc<Storage>,
}

impl BridgeTxRegistry {
    /// Atomically claim a tx_hash. Returns true if WE won the race.
    /// Returns false if already reserved OR already committed.
    pub fn reserve(&self, tx_hash: &str) -> Result<bool> {
        // Fast path: persistent storage check (committed = done forever)
        if self.storage.is_bridge_tx_processed(tx_hash)? {
            return Ok(false);
        }
        // Atomic claim via DashMap entry API
        match self.cache.entry(tx_hash.to_string()) {
            Entry::Occupied(_) => Ok(false),  // someone else has it
            Entry::Vacant(slot) => {
                slot.insert(ReservationState::Reserved {
                    reserved_at: chrono::Utc::now().timestamp(),
                });
                Ok(true)
            }
        }
    }

    /// Promote a reservation to committed (call AFTER credit succeeds).
    pub fn commit(&self, tx_hash: &str) -> Result<()> {
        self.storage.mark_bridge_tx_processed(tx_hash)?;
        self.cache.insert(tx_hash.to_string(), ReservationState::Committed);
        Ok(())
    }

    /// Release a reservation (call if credit fails).
    pub fn cancel(&self, tx_hash: &str) {
        self.cache.remove(tx_hash);
    }

    /// Background sweep: drop reservations older than 5 min that never committed.
    pub fn sweep_stale(&self) {
        let cutoff = chrono::Utc::now().timestamp() - 300;
        self.cache.retain(|_, state| match state {
            ReservationState::Reserved { reserved_at } => *reserved_at > cutoff,
            ReservationState::Committed => true,
        });
    }
}
```

**Updated watcher flow (replaces the broken check-then-act):**
```rust
async fn process_deposit(&self, tx: BridgeDeposit) -> Result<()> {
    // 1. Atomic reservation
    if !self.registry.reserve(&tx.tx_hash)? {
        debug!("tx {} already reserved/committed, skipping", tx.tx_hash);
        return Ok(());
    }

    // 2. Try to credit (with rollback on failure)
    match self.credit_deposit(&tx).await {
        Ok(record) => {
            self.registry.commit(&tx.tx_hash)?;
            self.storage.write_deposit_record(record)?;
            info!("✓ credited tx {}", tx.tx_hash);
            Ok(())
        }
        Err(e) => {
            self.registry.cancel(&tx.tx_hash);
            warn!("✗ credit failed for tx {}: {}", tx.tx_hash, e);
            Err(e)
        }
    }
}
```

### Test (REQUIRED before merging)
```rust
#[tokio::test]
async fn race_condition_only_one_winner() {
    let registry = Arc::new(BridgeTxRegistry::new(test_storage()));
    let tx_hash = "0xdeadbeef".to_string();

    let mut handles = vec![];
    for _ in 0..100 {
        let r = Arc::clone(&registry);
        let h = tx_hash.clone();
        handles.push(tokio::spawn(async move {
            r.reserve(&h).unwrap()
        }));
    }

    let winners: usize = futures::future::join_all(handles)
        .await
        .into_iter()
        .filter(|r| *r.as_ref().unwrap())
        .count();

    assert_eq!(winners, 1, "exactly one thread must win the race");
}
```

---

## Bug #3 — Silent Deposit Drops

### File: `watcher/mod.rs:scan_new_deposits`

**Current (broken):**
```rust
// ❌ If user just sends USDT without calling /deposit/request first, drops it
for transfer in new_transfers {
    let req = storage.get_deposit_request(&transfer.tx_hash)?;
    if req.is_none() {
        continue;  // silent fund loss!
    }
    process_deposit(transfer, req.unwrap()).await?;
}
```

**Replace with three-tier attribution:**
```rust
for transfer in new_transfers {
    // Tier 1: explicit /deposit/request — use it
    if let Some(req) = self.storage.get_deposit_request(&transfer.tx_hash)? {
        self.process_deposit_with_request(transfer, req).await?;
        continue;
    }

    // Tier 2: memo-based attribution (Solana memo program)
    if let Some(wallet) = self.extract_wallet_from_memo(&transfer) {
        self.process_attributed_deposit(transfer, wallet).await?;
        continue;
    }

    // Tier 3: queue as unattributed — user can claim later via signed /deposit/claim
    self.storage.write_unattributed_deposit(UnattributedDeposit {
        tx_hash: transfer.tx_hash.clone(),
        source_chain: transfer.source_chain.clone(),
        source_address: transfer.source_address.clone(),
        amount_micro: transfer.amount_micro,
        stablecoin_decimals: transfer.decimals,
        observed_at: chrono::Utc::now().timestamp(),
    })?;
    info!(
        "queued unattributed deposit {} from {}",
        transfer.tx_hash, transfer.source_address
    );
}
```

### New endpoint: `POST /deposit/claim`
- Body: `{ wallet, tx_hash, sig, ts, nonce }`
- `sig` = Ed25519 over `CLAIM_DEPOSIT:<wallet>:<tx_hash>:<ts>:<nonce>`
- Looks up unattributed deposit → if exists and not yet claimed → credits to `wallet`
- Uses same `reserve_bridge_tx` atomic pattern from Bug #2

### Memo extraction helper
```rust
/// Solana memo program logs the memo as an inner instruction.
/// We expect: "BB:<base58_wallet_address>"
fn extract_wallet_from_memo(&self, transfer: &SolanaTransfer) -> Option<String> {
    transfer.memo.as_ref()
        .and_then(|m| m.strip_prefix("BB:"))
        .filter(|w| {
            bs58::decode(w)
                .into_vec()
                .map(|v| v.len() == 32)
                .unwrap_or(false)
        })
        .map(String::from)
}
```

---

## Bug #4 — BSC `decode_transfer` Panic on Short Hex

### File: `bsc_watcher.rs`

**Current (broken):**
```rust
// ❌ Panics or returns garbage if hex_data is < 64 chars
fn decode_transfer(log: &EthLog) -> Result<TransferEvent> {
    let hex_data = log.data.strip_prefix("0x").unwrap_or(&log.data);
    let amount_bytes = &hex_data[hex_data.len() - 32..];  // panic if len < 32
    let amount = u128::from_str_radix(amount_bytes, 16)?;
    // ...
}
```

**Replace with bounds-checked `ethabi` decode:**
```rust
use ethabi::{decode, ParamType, Token};

fn decode_transfer(log: &EthLog) -> Result<TransferEvent> {
    // ERC-20 Transfer: indexed from, indexed to, uint256 value
    // - topics[0] = event sig
    // - topics[1] = from (32 bytes)
    // - topics[2] = to (32 bytes)
    // - data       = abi-encoded uint256 value (32 bytes)

    if log.topics.len() < 3 {
        anyhow::bail!(
            "transfer log missing topics: got {}, expected 3",
            log.topics.len()
        );
    }

    let hex_data = log.data.strip_prefix("0x").unwrap_or(&log.data);
    let data_bytes = hex::decode(hex_data)
        .map_err(|e| anyhow!("bad hex in log data: {}", e))?;

    if data_bytes.len() < 32 {
        anyhow::bail!(
            "transfer data too short: {} bytes, expected ≥32",
            data_bytes.len()
        );
    }

    let tokens = decode(&[ParamType::Uint(256)], &data_bytes)
        .map_err(|e| anyhow!("abi decode failed: {}", e))?;

    let amount = match tokens.first() {
        Some(Token::Uint(v)) => *v,
        _ => anyhow::bail!("expected Uint256 in transfer data"),
    };

    let from = h256_to_address(&log.topics[1])?;
    let to   = h256_to_address(&log.topics[2])?;

    Ok(TransferEvent {
        from,
        to,
        amount_micro: amount.as_u128(),  // BSC USDT is 18 dec — handle in normalization
        tx_hash: log.transaction_hash.clone(),
    })
}

fn h256_to_address(topic: &str) -> Result<String> {
    let hex = topic.strip_prefix("0x").unwrap_or(topic);
    if hex.len() != 64 {
        anyhow::bail!("address topic wrong length: {}", hex.len());
    }
    // address is the last 20 bytes (40 hex chars) of the 32-byte topic
    Ok(format!("0x{}", &hex[24..]))
}
```

### Tests
```rust
#[test]
fn decode_short_data_does_not_panic() {
    let log = EthLog {
        topics: vec![
            "0x...".into(),
            format!("0x{}", "00".repeat(32)),
            format!("0x{}", "00".repeat(32)),
        ],
        data: "0x1234".to_string(),  // way too short
        transaction_hash: "0xabc".to_string(),
    };
    assert!(decode_transfer(&log).is_err());  // must error, not panic
}

#[test]
fn decode_missing_topics_does_not_panic() {
    let log = EthLog {
        topics: vec![],
        data: "0x".into(),
        transaction_hash: "0xabc".into(),
    };
    assert!(decode_transfer(&log).is_err());
}
```

---

## Cleanup (per the ONRAMP_HARDENING_PLAN's -30% LOC goal)

After the above lands, **delete**:
- `is_bridge_tx_processed` callers in the watcher loop (replaced by `reserve`)
- Any `f64`-based amount conversion helpers
- Old `mark_bridge_tx_processed` direct callers (now goes through `commit`)
- Dead error paths that assumed `f64` precision

---

## Definition of Done — Session 1

- [ ] All 4 bugs fixed
- [ ] Race-condition test passes (100 threads → exactly 1 winner)
- [ ] BSC short-hex test passes (no panics)
- [ ] Integer math: `grep -r 'f64' src/storage src/watcher` returns zero hits in deposit paths
- [ ] No `unwrap()` on user-input bytes/strings in `bsc_watcher.rs`
- [ ] `cargo build` clean, all tests green
- [ ] Watcher LOC reduced (track before/after with `tokei`)

---

## What NOT to Do in Session 1 (Scope Discipline)

These are tempting but belong to later sessions — **don't scope-creep**:
- ❌ Adding `/wrapped/swap` (Session 3)
- ❌ Adding `/deposit/status` (Session 3)
- ❌ Lightning gateway changes (deferred)
- ❌ Frontend changes (Session 2)

Stay laser-focused on the 4 bugs. Ship safety first; features come after.

---

## After Session 1

When all 4 bugs are fixed and tests are green, return to the wallet repo and we'll start
**Session 2 — Frontend Deposit Loop + Toast System**.
