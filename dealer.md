# THE DEALER: Layer 2 Authority & Market Maker
> "The House Always Has Liquidity"

The **Dealer** is a specialized system account that exists natively on Layer 2. Unlike users (Alice/Bob) who must bridge funds from Layer 1, the Dealer represents the platform's operational liquidity and authority.

---

## 🔐 CRITICAL SECURITY MODEL

### Alice & Bob (Test Accounts)
- ✅ Private keys stored in codebase (for testing)
- ✅ Deterministic - same keys every time
- ⚠️ NEVER use in production - keys are public!

### Dealer (Production Oracle)
- ❌ Private key **NEVER** in codebase
- ✅ Only PUBLIC KEY stored in code
- ✅ Private key stored offline by operator
- ✅ Loaded from `DEALER_PRIVATE_KEY` env var when signing

---

## Account Credentials

```
ADDRESS:        L2DEALER00000001
PUBLIC KEY:     f19717a1860761b4e1b64101941c2115a416a07c57ff4fa3a91df7024b413d69
PRIVATE KEY:    [STORED LOCALLY BY OPERATOR - NEVER IN CODE]
```

The public key is stored in `src/integration/unified_auth.rs`:
- `DEALER_ADDRESS` - The L2 native address
- `DEALER_PUBLIC_KEY` - For signature verification

---

## 1. Core Identity: "The God Key"

Technically, the Dealer is a standard Ed25519 Keypair, but the L2 Runtime treats it as the **Superuser**.

*   **Lives on:** Layer 2 (Native Ledger)
*   **Backed by:** The L1 Vault Contract (The "House Bankroll")
*   **Role:** Market Maker, Oracle, and Settlement Engine

### Permissions
| Permission | Description |
|------------|-------------|
| **Infinite Liquidity** | Can mint "House Shares" to seed new markets (backed by L1 Vault). |
| **Resolution Authority** | The *only* account authorized to call `/resolve` on a market. |
| **Forced Settlement** | Can push funds from Market Pools directly to User Accounts. |
| **Fee Collection** | Receives the trading fees from every bet. |

---

## 2. The Workflow: The Dealer's Lifecycle

The Dealer manages the entire lifecycle of a prediction market event.

### Phase A: The Setup (The House)
*The Dealer opens the table.*

1.  **Action:** Dealer calls `createMarket(id, "Will BTC hit 100k?", [YES, NO])`.
2.  **Liquidity Injection:** The Dealer automatically mints/locks **1,000 BB** into the market's liquidity pool.
3.  **Result:** The market opens with deep liquidity. Alice can bet immediately without waiting for a counterparty.

### Phase B: The Action (The Bank)
*The Dealer manages risk.*

1.  **Action:** Users place bets. They are technically trading against the Dealer's pool.
2.  **Hedging (Optional):** If the book becomes too unbalanced (e.g., 90% YES), the Dealer can programmatically place a bet on NO to rebalance the odds and reduce platform risk.

### Phase C: The Judgment (The Oracle)
*The Dealer decides the truth.*

1.  **Trigger:** The event deadline passes.
2.  **Action:** Dealer calls `resolveMarket(market_id, "YES")`.
3.  **Effect:**
    *   Market state freezes (no new bets).
    *   Winning Share Price set to **$1.00**.
    *   Losing Share Price set to **$0.00**.

### Phase D: The Payout (The Distributor)
*The Dealer pays the winners.*

Instead of users claiming funds (Pull), the Dealer sends them (Push).

1.  **Action:** Dealer runs the `distribute_winnings` process.
2.  **Logic:**
    ```python
    for bet in winning_bets:
        payout = bet.amount / avg_price
        transfer(from=Market_Pool, to=User_L2_Balance, amount=payout)
    ```
3.  **Result:** Alice checks her phone and the money is already there.

---

## 3. Technical Implementation

### L2 Initialization (God Mode)
When the L2 Node boots up, it initializes the Dealer with operational capital. This capital is virtual on L2 but backed by the real assets locked in the L1 Bridge Contract.

```rust
// src/l2_node/main.rs

fn initialize_ledger() {
    // 1. Load User Accounts (Start at 0 until bridged)
    
    // 2. Initialize Dealer (God Mode)
    let dealer_address = "L2DEALER00000001";
    ledger.set_balance(dealer_address, 1_000_000.00); // 1M BB Liquidity
    
    println!("🏛️ Dealer initialized. House Bankroll: 1,000,000 BB");
}
```

### Signing Market Operations

The Dealer signs operations using the private key loaded from environment:

```rust
// Server-side only - private key from env
let dealer_private_key = std::env::var("DEALER_PRIVATE_KEY")
    .expect("DEALER_PRIVATE_KEY must be set");

// Sign a market resolution
let message = format!("resolve:{}:{}", market_id, outcome);
let signature = sign_message(&dealer_private_key, &message);
```

---

## 4. Security Model

### Key Storage
| Environment | Private Key Location |
|-------------|---------------------|
| Development | Local file on operator's machine |
| Staging | Encrypted env var in Railway/Vercel |
| Production | Hardware Security Module (HSM) |

### Never Commit
```gitignore
# .gitignore
DEALER_PRIVATE_KEY
dealer_private.txt
*.key
```

### L1 Solvency
The Dealer must never mint more L2 tokens than exist in the L1 Vault. A "Proof of Reserves" check should run periodically.

---

## 5. Usage Examples

### Verify Dealer Signature (Anyone can do this)
```rust
use layer1::integration::unified_auth::{verify_dealer_signature, is_dealer_address};

// Verify a market resolution was signed by the Dealer
let is_valid = verify_dealer_signature(&message, &signature)?;
assert!(is_valid, "Invalid dealer signature!");

// Check if an address is the Dealer
if is_dealer_address(sender_address) {
    // This is an authorized dealer operation
}
```

### Create Signed Request (Dealer operator only)
```bash
# Set the private key in environment (DO NOT COMMIT THIS!)
export DEALER_PRIVATE_KEY="your_private_key_here"

# Now the server can sign dealer operations
```
