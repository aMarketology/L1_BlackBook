# USDC-Backed Token System: Zero-Leak 1:1 Guarantee

## The Core Invariant

**Every $BC token in existence is backed by exactly 1 USDC in our vault.**

```
INVARIANT (must ALWAYS hold):

  total_bc_supply = usdc_in_vault

  WHERE:
    total_bc_supply = sum(all_balances) + sum(all_locked_for_l2)
    usdc_in_vault   = sum(all_deposits) - sum(all_withdrawals)
```

This is not a goal. This is a **mathematical guarantee** enforced by our protocol.

---

## How Tokens Enter the System (The ONLY Way)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     TOKEN CREATION: DEPOSIT FLOW                        │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   User sends 100 USDC ──────► USDC Vault (on Base/Ethereum)            │
│                                      │                                  │
│                                      │ Oracle confirms deposit          │
│                                      │ (12+ block confirmations)        │
│                                      ▼                                  │
│                              BlackBook L1 verifies:                     │
│                              ├─ tx_hash not already processed          │
│                              ├─ amount matches USDC received            │
│                              ├─ vault balance increased                 │
│                              └─ signature valid                         │
│                                      │                                  │
│                                      ▼                                  │
│                              MINT 100 $BC to user                       │
│                              Record: deposit_id, tx_hash, amount        │
│                                                                         │
│   RESULT:                                                               │
│   ├─ usdc_in_vault:    +100 USDC                                       │
│   ├─ total_bc_supply:  +100 $BC                                        │
│   └─ INVARIANT:        MAINTAINED ✓                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

NO OTHER WAY TO CREATE TOKENS EXISTS.
- No admin mint
- No treasury
- No genesis allocation
- No inflation
- No rewards that create new tokens

```

---

## How Tokens Exit the System (The ONLY Way)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     TOKEN DESTRUCTION: WITHDRAWAL FLOW                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   User requests withdrawal of 50 $BC                                   │
│                     │                                                   │
│                     ▼                                                   │
│   BlackBook L1 verifies:                                               │
│   ├─ User has 50 $BC available (not locked)                            │
│   ├─ User signed the withdrawal request                                │
│   └─ Destination address is valid                                      │
│                     │                                                   │
│                     ▼                                                   │
│   BURN 50 $BC from user's balance                                      │
│   Generate withdrawal_proof (signed by L1)                             │
│                     │                                                   │
│                     ▼                                                   │
│   USDC Vault receives proof ──────► Release 50 USDC to user           │
│   (Multi-sig validates proof)                                          │
│                                                                         │
│   RESULT:                                                               │
│   ├─ usdc_in_vault:    -50 USDC                                        │
│   ├─ total_bc_supply:  -50 $BC                                         │
│   └─ INVARIANT:        MAINTAINED ✓                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘

NO OTHER WAY TO DESTROY TOKENS EXISTS.
Tokens cannot disappear - only be burned for USDC withdrawal.
```

---

## Layer 2 ($BB): Credit System, Not Token Creation

**Critical: L2 does NOT create tokens. L2 operates on CREDIT backed by LOCKED L1 tokens.**

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     L1 → L2 BRIDGE: LOCK, NOT CREATE                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   User wants to play on L2 with 1000 $BC                               │
│                                                                         │
│   STEP 1: Lock on L1                                                   │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  User: 1000 $BC                                                 │  │
│   │                    │                                            │  │
│   │                    ▼                                            │  │
│   │  lock_tokens(user, 1000, "L2_GAMING")                          │  │
│   │                    │                                            │  │
│   │  User: 0 $BC spendable, 1000 $BC locked                        │  │
│   │  Lock Record: { lock_id, owner, amount: 1000, purpose: L2 }    │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   STEP 2: L2 receives signed lock proof                                │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  L2 verifies:                                                   │  │
│   │  ├─ L1 signature on lock_proof                                  │  │
│   │  ├─ lock_id exists on L1                                        │  │
│   │  └─ amount matches                                              │  │
│   │                                                                 │  │
│   │  L2 creates CREDIT LINE (not tokens):                          │  │
│   │  { session_id, user, credit_limit: 1000, backed_by: lock_id }  │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   INVARIANT CHECK:                                                     │
│   ├─ L1 total_bc_supply: UNCHANGED (tokens locked, not destroyed)     │
│   ├─ L1 sum(locked): +1000                                            │
│   ├─ L1 sum(spendable): -1000                                         │
│   ├─ L2 credit_issued: 1000 (backed by lock_id)                       │
│   └─ L2 credit_issued <= L1 locked: ALWAYS TRUE ✓                     │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Gaming on L2: Zero-Sum Redistribution

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     L2 GAMING: REDISTRIBUTION ONLY                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   BEFORE GAME:                                                         │
│   ├─ Alice credit: 1000 (backed by L1 lock_alice)                     │
│   ├─ Bob credit:   1000 (backed by L1 lock_bob)                       │
│   ├─ Dealer credit: 10000 (backed by L1 lock_dealer)                  │
│   └─ TOTAL: 12000 (all backed by 12000 $BC locked on L1)             │
│                                                                         │
│   GAME PLAYS OUT:                                                      │
│   ├─ Alice bets 100, wins → +200                                      │
│   ├─ Bob bets 100, loses → -100                                       │
│   ├─ Dealer pays winner, collects from loser                          │
│                                                                         │
│   AFTER GAME:                                                          │
│   ├─ Alice credit: 1100                                               │
│   ├─ Bob credit:   900                                                │
│   ├─ Dealer credit: 10000 (break even this round)                     │
│   └─ TOTAL: 12000 (UNCHANGED - zero-sum)                              │
│                                                                         │
│   KEY: L2 can only REDISTRIBUTE credit.                                │
│        L2 can NEVER create new credit beyond what L1 locked.          │
│        sum(L2_credits) == sum(L1_locked_for_L2) ALWAYS                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## L2 → L1 Settlement: Release Locked Tokens

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     L2 → L1 SETTLEMENT: UNLOCK WITH P&L                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   Alice cashes out from L2 (started with 1000, now has 1100)          │
│                                                                         │
│   STEP 1: L2 calculates P&L                                            │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  original_credit: 1000                                          │  │
│   │  final_balance:   1100                                          │  │
│   │  pnl:             +100 (profit)                                 │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   STEP 2: L2 sends settlement to L1 (signed by L2 + Alice)            │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  settlement_request: {                                          │  │
│   │    lock_id: "lock_alice",                                       │  │
│   │    pnl: +100,                                                   │  │
│   │    l2_signature: "...",                                         │  │
│   │    wallet_signature: "..." (Alice approves)                     │  │
│   │  }                                                              │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   STEP 3: L1 processes settlement                                      │
│   ┌─────────────────────────────────────────────────────────────────┐  │
│   │  L1 verifies:                                                   │  │
│   │  ├─ lock_id exists and belongs to Alice                         │  │
│   │  ├─ L2 signature valid                                          │  │
│   │  ├─ Alice signature valid                                       │  │
│   │  └─ pnl came from Dealer's locked balance                       │  │
│   │                                                                 │  │
│   │  L1 executes:                                                   │  │
│   │  ├─ Unlock Alice's 1000 $BC                                     │  │
│   │  ├─ Transfer 100 $BC from Dealer to Alice                       │  │
│   │  └─ Alice now has: 1100 $BC spendable                          │  │
│   └─────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│   INVARIANT CHECK:                                                     │
│   ├─ L1 total_bc_supply: UNCHANGED                                    │
│   ├─ L1 sum(locked): -1000 (Alice's lock released)                    │
│   ├─ L1 sum(spendable): +1000 (Alice's tokens unlocked)               │
│   ├─ Dealer balance: -100 (paid to winner)                            │
│   ├─ Alice balance: +100 (won from Dealer)                            │
│   └─ Zero-sum: MAINTAINED ✓                                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## The Conservation Equations

### Equation 1: USDC Backing
```
usdc_in_vault = total_bc_minted - total_bc_burned

WHERE:
  total_bc_minted = sum(all_usdc_deposits_processed)
  total_bc_burned = sum(all_usdc_withdrawals_completed)
```

### Equation 2: Token Accounting
```
total_bc_supply = sum(all_spendable_balances) + sum(all_locked_balances)

This must equal usdc_in_vault at ALL times.
```

### Equation 3: L2 Credit Backing
```
sum(all_l2_credit_balances) <= sum(all_l1_locked_for_l2)

L2 can NEVER issue more credit than L1 has locked.
The Dealer on L2 also has credit backed by locked L1 tokens.
```

### Equation 4: Zero-Sum Gaming
```
sum(l2_credits_at_start) = sum(l2_credits_at_end)

Winners gain what losers lose.
House edge comes from Dealer's credit line.
```

---

## Validation System: Real-Time Proof

### Every Block Validates:
```rust
struct BlockValidation {
    // USDC backing check
    usdc_vault_balance: u64,        // From oracle
    total_bc_supply: u64,           // sum(balances) + sum(locked)
    backing_valid: bool,            // vault >= supply
    
    // L2 credit check  
    total_l1_locked_for_l2: u64,    // All locks with purpose = L2
    total_l2_credit_issued: u64,    // From L2 state root
    l2_backing_valid: bool,         // locked >= credit
    
    // Zero-sum check
    total_deposits_processed: u64,
    total_withdrawals_completed: u64,
    expected_supply: u64,           // deposits - withdrawals
    supply_matches: bool,           // expected == actual
}
```

### Public Proof Endpoint:
```
GET /validate/supply

Response:
{
  "valid": true,
  "usdc_in_vault": 1234567.89,
  "total_bc_supply": 1234567.89,
  "total_bc_spendable": 734567.89,
  "total_bc_locked": 500000.00,
  "l2_credit_issued": 500000.00,
  "backing_ratio": 1.0,
  "last_deposit_processed": "tx_abc123",
  "last_withdrawal_completed": "tx_xyz789",
  "state_root": "0x...",
  "block_height": 12345
}
```

---

## Leak Prevention: Every Possible Attack Vector

### Attack 1: Admin creates tokens without USDC
**Prevention:** No admin mint function exists. `mint()` ONLY accepts a verified deposit tx_hash from USDC vault. Code enforces this - there is no bypass.

### Attack 2: L2 creates more credit than L1 locked
**Prevention:** L2 credit issuance requires L1 signed lock_proof. L1 only signs proofs for actual locks. L2 cannot forge L1 signatures.

### Attack 3: Double-spend a deposit
**Prevention:** Every deposit tx_hash is recorded in `processed_deposits` set. Same tx_hash cannot be processed twice.

### Attack 4: Withdraw more USDC than burned
**Prevention:** USDC vault only releases funds with a valid burn_proof signed by L1. L1 only signs after burning tokens from user's balance.

### Attack 5: L2 sends fake settlement
**Prevention:** Settlement requires BOTH L2 signature AND user wallet signature. User must approve the P&L. L1 verifies both signatures.

### Attack 6: Phantom tokens appear
**Prevention:** Every token has a traceable origin (deposit tx_hash). If `sum(balances) + sum(locked) != expected_from_deposits`, system HALTS and alerts.

### Attack 7: L2 manipulates P&L to steal
**Prevention:** P&L transfers happen on L1 between locked balances. Dealer's loss = User's gain. Zero-sum enforced at L1 level.

---

## System States

### Healthy State
```
✅ usdc_in_vault == total_bc_supply
✅ sum(l2_credit) <= sum(l1_locked)
✅ all deposits have matching mints
✅ all withdrawals have matching burns
```

### Warning State
```
⚠️ Oracle temporarily unavailable
⚠️ L2 state root not yet anchored
→ System continues but flags for review
```

### Critical State (System Halts)
```
❌ usdc_in_vault < total_bc_supply
❌ sum(l2_credit) > sum(l1_locked)
❌ unexplained token balance detected
→ All operations HALT
→ Alert sent to operators
→ Manual investigation required
```

---

## Summary: The Guarantees

1. **No token without USDC** - Tokens only created when USDC deposited
2. **No USDC without burn** - USDC only released when tokens burned
3. **L2 is credit, not tokens** - L2 operates on locked L1 backing
4. **Gaming is zero-sum** - Winners get losers' credit
5. **Every token traceable** - deposit_tx_hash → mint → transfers → burn → withdrawal_tx_hash
6. **Real-time validation** - Every block checks invariants
7. **System halts on discrepancy** - No silent failures

**Result: 1:1 backing is mathematically guaranteed, not promised.**
