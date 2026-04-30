# $DECAY Token — Value-Recapture Plan

> **Token name:** `DECAY` | **Ticker:** `$DECAY` | **Module:** `decay_token`
>
> Per-token NFT-style asset. Each $DECAY is a unique on-chain object with its own backing value (locked wUSDT) and a `uses_count`. Every "use" leaks 1% of the **current** backing into the central Treasury. After 100 uses the token is dead and must be **recharged** by burning `$XX` and paying a wUSDT maintenance fee. Long-stake locks (1 year) give a 25% recharge discount.

---

## Economics

- **Leak per use:** `leak = backing_value / 100` (1% of current backing → geometric decay)
- **Max uses before recharge:** `100`
- **Recharge cost:** burn `5 MAXX` ($XX) **+** transfer `2 wUSDT` to treasury
- **Long-stake discount:** if `lock_until_slot > current_slot`, recharge wUSDT fee is `1.5 wUSDT` (25% off)
- **Mint:** user pays N wUSDT → moves into the **decay vault** SVM account → new $DECAY issued with `backing_value = N`
- **Treasury:** all leaked + recharge wUSDT fees accumulate in a separate **treasury** SVM account

After 100 uses ~36.6% of nominal backing is left in the vault and stays there permanently (it does not refund — the user pays to recharge, not to redeem). Treasury captures the value flow.

---

## State

### ReDB tables ([src/storage/mod.rs](src/storage/mod.rs))

```rust
pub const DECAY_TOKENS:       TableDefinition<u64, &[u8]>  = TableDefinition::new("decay_tokens");
pub const DECAY_OWNER_INDEX:  TableDefinition<&str, &[u8]> = TableDefinition::new("decay_owner_index");
pub const DECAY_META:         TableDefinition<&str, u64>   = TableDefinition::new("decay_meta"); // "next_id"
```

### Per-token struct

```rust
pub struct DecayToken {
    pub id: u64,
    pub owner: String,            // base58 pubkey
    pub backing_value: u128,      // microUSDT held in vault for this token
    pub uses_count: u32,          // 0..=100
    pub minted_slot: u64,
    pub last_use_slot: u64,
    pub lock_until_slot: u64,     // 0 = unlocked
    pub recharge_count: u32,      // lifetime
}
```

### SVM accounts ([src/svm/spl_token.rs](src/svm/spl_token.rs))

- `DECAY_VAULT_SEED = "BlackBook_DECAY_Vault_v1"` — holds wUSDT backing for live tokens
- `DECAY_TREASURY_SEED = "BlackBook_DECAY_Treasury_v1"` — holds recaptured wUSDT (the profit center)

Both are wUSDT token accounts; lazy-init on first transfer.

---

## Endpoints

| Route | Verb | Body | Purpose |
|---|---|---|---|
| `/decay/mint` | POST | `{ from, backing_amount }` | Lock `backing_amount` wUSDT → issue new $DECAY |
| `/decay/use` | POST | `{ from, token_id }` | Increment uses, leak 1% of backing → treasury |
| `/decay/recharge` | POST | `{ from, token_id }` | Burn 5 MAXX + pay 2 (or 1.5) wUSDT → reset uses |
| `/decay/stake` | POST | `{ from, token_id, lock_slots }` | Long-lock for recharge discount |
| `/decay/token/:id` | GET | — | One token's state |
| `/decay/owner/:address` | GET | — | All token IDs owned by address |
| `/decay/treasury` | GET | — | Treasury wUSDT balance + lifetime stats |
| `/decay/supply` | GET | — | Total minted, total active, total dead |

**Auth note:** v1 ships unauthenticated (matching current `/maxx/buy` and `/transfer/simple` patterns). Ed25519 signature verification is tracked in [clean_blockchain.md](clean_blockchain.md) as airtightness gap #1 and applies to **all** trade endpoints (`/maxx/*`, `/decay/*`) before mainnet.

---

## Implementation Phases

### Phase 1 — Core contract + reads ✅ this commit
1. Add three ReDB tables.
2. Add SVM seed constants + `decay_vault_address()` / `decay_treasury_address()` helpers + re-exports.
3. Create [src/contracts/decay_token/mod.rs](src/contracts/decay_token/mod.rs) with:
   - `DecayToken` struct + ReDB get/put/owner-index helpers
   - `mint_decay_handler` (lock wUSDT → issue token)
   - `use_decay_handler` (geometric leak → treasury)
   - `recharge_decay_handler` (burn MAXX + wUSDT fee → reset uses)
   - `stake_decay_handler` (set lock_until_slot)
   - `decay_token_handler`, `decay_owner_handler`, `decay_treasury_handler`, `decay_supply_handler`
4. Register module in [src/contracts/mod.rs](src/contracts/mod.rs).
5. Wire 8 routes in [src/main.rs](src/main.rs).
6. `cargo check` clean.

### Phase 2 — Auth + Audit (deferred, see clean_blockchain.md)
- Ed25519 signature on `mint`, `use`, `recharge`, `stake`.
- Extend `/supply/audit` with `decay_vault_solvent` invariant: `vault_balance == sum(token.backing_value for live tokens)`.

### Phase 3 — Wallet SDK + UI (separate commit)
- `getDecayTokens(address)`, `mintDecay`, `useDecay`, `rechargeDecay` in `wallet.sdk.ts`.
- Inventory page showing each $DECAY card with backing/uses/recharge button.

### Phase 4 — Long-stake yield routing (out of scope here)
- Off-chain bot moves the unlocked treasury portion into a yield protocol (Aave / T-Bill fund), keeping the principal liquid for unlock requests.

---

## Verification (Phase 1)

```bash
# 1. Mint a $DECAY backed by 10 wUSDT
curl -X POST localhost:8080/decay/mint \
  -d '{"from":"<addr>","backing_amount":10000000}'

# 2. Use it 5 times — each leaks 1% of current backing into treasury
for i in 1..5: curl -X POST localhost:8080/decay/use -d '{"from":"<addr>","token_id":1}'

# 3. After 5 uses backing ≈ 9_509_900 microUSDT, treasury ≈ 490_100
curl localhost:8080/decay/token/1
curl localhost:8080/decay/treasury
```
