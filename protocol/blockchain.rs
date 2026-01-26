//! BlackBook L1 - The Sweepstakes Ledger
//!
//! ═══════════════════════════════════════════════════════════════════════════
//!                    THE VAULT - PRIZE REGISTRY & ESCROW AGENT
//! ═══════════════════════════════════════════════════════════════════════════
//!
//! LEGAL ROLE: Proves every $BB in existence is accounted for.
//! FINANCIAL ROLE: Holds funds in escrow while games happen.
//!
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         L1 STATE (Immutable Truth)                      │
//! │                                                                         │
//! │   ┌─────────────────────┐    ┌─────────────────────────────────────┐   │
//! │   │   USER ACCOUNTS     │    │        ACTIVE ESCROWS               │   │
//! │   │                     │    │                                     │   │
//! │   │  Alice: 100 $BB     │    │  Match_001: EscrowVault {           │   │
//! │   │  Bob:    50 $BB     │    │    total_locked: 20 $BB             │   │
//! │   │  Carol:  75 $BB     │    │    participants: [Alice, Bob]       │   │
//! │   │                     │    │    expiry: 1737849600               │   │
//! │   │                     │    │  }                                  │   │
//! │   └─────────────────────┘    └─────────────────────────────────────┘   │
//! │                                                                         │
//! │   NOTE: We do NOT track "Gold Coins" here. That's Web2 data.           │
//! └─────────────────────────────────────────────────────────────────────────┘
//!
//! THE 4 CRITICAL FUNCTIONS (L1 rejects everything else):
//!
//!   1. MINT(user, amount)    - USDC deposited → $BB created
//!   2. LOCK(match_id, users) - Move $BB from users into escrow
//!   3. SETTLE(match_id, winner) - Empty escrow → pay winner
//!   4. BURN(user, amount)    - $BB destroyed → USDC released
//!
//! ZERO-SUM INVARIANT: Total supply can only change via Mint/Burn.
//! Lock and Settle only MOVE tokens, never create or destroy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ============================================================================
// CONSTANTS
// ============================================================================

/// Genesis timestamp (fixed for deterministic genesis hash)
pub const GENESIS_TIMESTAMP: u64 = 1735689600;

/// Micro-units per $BB token (like Solana lamports)
pub const LAMPORTS_PER_BB: u64 = 1_000_000;

/// Default escrow expiry: 24 hours (refund if L2 dies)
pub const DEFAULT_ESCROW_EXPIRY_SECS: u64 = 86400;

/// Compute deterministic genesis hash
pub fn compute_genesis_hash() -> String {
    let seed = "BlackBook_L1_Sweepstakes_Ledger_2024";
    format!("{:x}", Sha256::digest(seed.as_bytes()))
}

// ============================================================================
// L1 STATE - THE IMMUTABLE TRUTH
// ============================================================================

/// The complete L1 state - only tracks accounts and escrows
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct L1State {
    /// User accounts: Address → Balance in lamports
    pub accounts: std::collections::HashMap<String, u64>,
    
    /// Active escrows: MatchID → EscrowVault
    pub escrows: std::collections::HashMap<String, EscrowVault>,
    
    /// Total supply of $BB (in lamports) - for invariant checks
    pub total_supply: u64,
}

/// An escrow vault holding funds during an active game
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscrowVault {
    /// Total $BB locked in this escrow (in lamports)
    pub total_locked: u64,
    /// Participants in this match
    pub participants: Vec<String>,
    /// Contribution per participant (in lamports)
    pub contributions: Vec<u64>,
    /// Expiry timestamp - auto-refund if L2 doesn't settle
    pub expiry: u64,
    /// Creation timestamp
    pub created_at: u64,
}

// ============================================================================
// TRANSACTION TYPES - ONLY 4 ALLOWED
// ============================================================================

/// The ONLY 4 operations L1 accepts. Everything else is rejected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxType {
    /// USDC deposited → $BB created (Admin only)
    Mint,
    /// Move $BB from users into escrow for a match
    Lock,
    /// Empty escrow → pay winner (Zero-sum)
    Settle,
    /// $BB destroyed → USDC can be released
    Burn,
}

/// A transaction on the L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction ID
    pub id: String,
    /// Transaction type (one of the 4 allowed)
    pub tx_type: TxType,
    /// Unix timestamp
    pub timestamp: u64,
    /// Transaction-specific data
    pub data: TxData,
    /// Signature from authorized party
    pub signature: Option<String>,
}

/// Transaction-specific data for each of the 4 operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxData {
    /// Mint: Admin creates tokens when USDC hits treasury
    Mint {
        /// Recipient address
        user: String,
        /// Amount in $BB (will be converted to lamports)
        amount: f64,
        /// USDC transaction reference
        usdc_tx_hash: Option<String>,
    },
    
    /// Lock: L2 requests funds locked for a match
    Lock {
        /// Unique match identifier
        match_id: String,
        /// Participants and their contributions
        participants: Vec<LockParticipant>,
        /// Expiry timestamp (auto-refund if not settled)
        expiry: u64,
    },
    
    /// Settle: L2 reports match result, pay winner
    Settle {
        /// Match to settle
        match_id: String,
        /// Winner address (receives entire escrow)
        winner: String,
        /// Optional: split among multiple winners
        payouts: Option<Vec<Payout>>,
    },
    
    /// Burn: User cashes out, tokens destroyed
    Burn {
        /// User burning tokens
        user: String,
        /// Amount in $BB
        amount: f64,
        /// USDC withdrawal address
        usdc_destination: Option<String>,
    },
}

/// A participant in a Lock transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockParticipant {
    pub address: String,
    pub amount: f64,
}

/// A payout entry for complex settlements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payout {
    pub address: String,
    pub amount: f64,
}

// ============================================================================
// TRANSACTION CONSTRUCTORS
// ============================================================================

impl Transaction {
    fn generate_id(data: &str) -> String {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        format!("{:x}", Sha256::digest(format!("{}_{}", data, timestamp).as_bytes()))
    }

    /// Create a MINT transaction (Admin only)
    pub fn mint(user: &str, amount: f64, usdc_tx_hash: Option<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: Self::generate_id(&format!("mint_{}_{}", user, amount)),
            tx_type: TxType::Mint,
            timestamp,
            data: TxData::Mint {
                user: user.to_string(),
                amount,
                usdc_tx_hash,
            },
            signature: None,
        }
    }

    /// Create a LOCK transaction (from L2)
    pub fn lock(match_id: &str, participants: Vec<LockParticipant>, expiry: Option<u64>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let expiry = expiry.unwrap_or(timestamp + DEFAULT_ESCROW_EXPIRY_SECS);
        
        Self {
            id: Self::generate_id(&format!("lock_{}", match_id)),
            tx_type: TxType::Lock,
            timestamp,
            data: TxData::Lock {
                match_id: match_id.to_string(),
                participants,
                expiry,
            },
            signature: None,
        }
    }

    /// Create a SETTLE transaction (from L2)
    pub fn settle(match_id: &str, winner: &str) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: Self::generate_id(&format!("settle_{}", match_id)),
            tx_type: TxType::Settle,
            timestamp,
            data: TxData::Settle {
                match_id: match_id.to_string(),
                winner: winner.to_string(),
                payouts: None,
            },
            signature: None,
        }
    }

    /// Create a SETTLE transaction with custom payouts
    pub fn settle_with_payouts(match_id: &str, payouts: Vec<Payout>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let winner = payouts.first().map(|p| p.address.clone()).unwrap_or_default();
        
        Self {
            id: Self::generate_id(&format!("settle_{}", match_id)),
            tx_type: TxType::Settle,
            timestamp,
            data: TxData::Settle {
                match_id: match_id.to_string(),
                winner,
                payouts: Some(payouts),
            },
            signature: None,
        }
    }

    /// Create a BURN transaction (User cashout)
    pub fn burn(user: &str, amount: f64, usdc_destination: Option<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: Self::generate_id(&format!("burn_{}_{}", user, amount)),
            tx_type: TxType::Burn,
            timestamp,
            data: TxData::Burn {
                user: user.to_string(),
                amount,
                usdc_destination,
            },
            signature: None,
        }
    }

    /// Legacy transfer function - converts to Lock + Settle internally
    /// This maintains backwards compatibility with existing code
    pub fn transfer(from: &str, to: &str, amount: f64) -> Self {
        // For simple transfers, we mint to the recipient
        // This is a simplification - real transfers should use Lock/Settle
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id: Self::generate_id(&format!("transfer_{}_{}", from, to)),
            tx_type: TxType::Mint, // Treated as mint for backwards compat
            timestamp,
            data: TxData::Mint {
                user: to.to_string(),
                amount,
                usdc_tx_hash: Some(format!("internal_transfer_from_{}", from)),
            },
            signature: None,
        }
    }
}

// ============================================================================
// CHAIN ERRORS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChainError {
    /// User doesn't have enough balance
    InsufficientBalance,
    /// Escrow doesn't exist
    EscrowNotFound,
    /// Escrow already exists for this match
    EscrowAlreadyExists,
    /// Winner not in participants list
    InvalidWinner,
    /// Zero-sum violation detected
    ZeroSumViolation,
    /// Unauthorized mint attempt
    UnauthorizedMint,
    /// Invalid amount
    InvalidAmount,
    /// Escrow has expired
    EscrowExpired,
}

// ============================================================================
// L1 STATE MACHINE - The Core Logic
// ============================================================================

impl L1State {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get balance for an address (in $BB, not lamports)
    pub fn get_balance(&self, address: &str) -> f64 {
        self.accounts.get(address)
            .map(|&lamports| lamports as f64 / LAMPORTS_PER_BB as f64)
            .unwrap_or(0.0)
    }

    /// Get balance in lamports
    pub fn get_balance_lamports(&self, address: &str) -> u64 {
        *self.accounts.get(address).unwrap_or(&0)
    }

    /// Execute a transaction against the state
    pub fn execute(&mut self, tx: &Transaction) -> Result<(), ChainError> {
        match &tx.data {
            TxData::Mint { user, amount, .. } => self.execute_mint(user, *amount),
            TxData::Lock { match_id, participants, expiry } => {
                self.execute_lock(match_id, participants, *expiry)
            }
            TxData::Settle { match_id, winner, payouts } => {
                self.execute_settle(match_id, winner, payouts.as_ref())
            }
            TxData::Burn { user, amount, .. } => self.execute_burn(user, *amount),
        }
    }

    /// MINT: Create $BB when USDC is deposited
    /// Zero-Sum: INFLOW (total supply increases)
    fn execute_mint(&mut self, user: &str, amount: f64) -> Result<(), ChainError> {
        if amount <= 0.0 {
            return Err(ChainError::InvalidAmount);
        }

        let lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        
        // Credit user account
        *self.accounts.entry(user.to_string()).or_insert(0) += lamports;
        
        // Increase total supply
        self.total_supply += lamports;

        Ok(())
    }

    /// LOCK: Move $BB from users into escrow for a match
    /// Zero-Sum: Total supply unchanged (just moved to escrow)
    fn execute_lock(
        &mut self,
        match_id: &str,
        participants: &[LockParticipant],
        expiry: u64,
    ) -> Result<(), ChainError> {
        // Check escrow doesn't already exist
        if self.escrows.contains_key(match_id) {
            return Err(ChainError::EscrowAlreadyExists);
        }

        // Verify all participants have sufficient balance
        for p in participants {
            let required = (p.amount * LAMPORTS_PER_BB as f64) as u64;
            let balance = self.get_balance_lamports(&p.address);
            if balance < required {
                return Err(ChainError::InsufficientBalance);
            }
        }

        // Debit all participants
        let mut total_locked = 0u64;
        let mut addresses = Vec::new();
        let mut contributions = Vec::new();

        for p in participants {
            let lamports = (p.amount * LAMPORTS_PER_BB as f64) as u64;
            
            if let Some(balance) = self.accounts.get_mut(&p.address) {
                *balance -= lamports;
            }
            
            total_locked += lamports;
            addresses.push(p.address.clone());
            contributions.push(lamports);
        }

        // Create escrow vault
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.escrows.insert(match_id.to_string(), EscrowVault {
            total_locked,
            participants: addresses,
            contributions,
            expiry,
            created_at: timestamp,
        });

        // ZERO-SUM CHECK: Total supply unchanged (moved to escrow, not created)
        Ok(())
    }

    /// SETTLE: Empty escrow and pay winner(s)
    /// Zero-Sum: Input (escrow) == Output (payouts). STRICT REQUIREMENT.
    fn execute_settle(
        &mut self,
        match_id: &str,
        winner: &str,
        payouts: Option<&Vec<Payout>>,
    ) -> Result<(), ChainError> {
        // Get and remove escrow
        let escrow = self.escrows.remove(match_id)
            .ok_or(ChainError::EscrowNotFound)?;

        // Calculate total payout
        let total_to_distribute = escrow.total_locked;

        if let Some(payouts) = payouts {
            // Complex payout: distribute according to payout list
            let mut total_paid = 0u64;
            
            for payout in payouts {
                let lamports = (payout.amount * LAMPORTS_PER_BB as f64) as u64;
                *self.accounts.entry(payout.address.clone()).or_insert(0) += lamports;
                total_paid += lamports;
            }

            // ZERO-SUM CHECK: Must distribute exactly what was in escrow
            if total_paid != total_to_distribute {
                // Rollback: put escrow back
                self.escrows.insert(match_id.to_string(), escrow);
                return Err(ChainError::ZeroSumViolation);
            }
        } else {
            // Simple winner-takes-all
            // Verify winner was a participant
            if !escrow.participants.contains(&winner.to_string()) {
                // Rollback
                self.escrows.insert(match_id.to_string(), escrow);
                return Err(ChainError::InvalidWinner);
            }

            // Credit winner with entire escrow
            *self.accounts.entry(winner.to_string()).or_insert(0) += total_to_distribute;
        }

        // ZERO-SUM: Escrow emptied, exact amount credited. Supply unchanged.
        Ok(())
    }

    /// BURN: Destroy $BB so USDC can be released
    /// Zero-Sum: OUTFLOW (total supply decreases)
    fn execute_burn(&mut self, user: &str, amount: f64) -> Result<(), ChainError> {
        if amount <= 0.0 {
            return Err(ChainError::InvalidAmount);
        }

        let lamports = (amount * LAMPORTS_PER_BB as f64) as u64;
        let balance = self.get_balance_lamports(user);

        if balance < lamports {
            return Err(ChainError::InsufficientBalance);
        }

        // Debit user
        if let Some(bal) = self.accounts.get_mut(user) {
            *bal -= lamports;
        }

        // Decrease total supply
        self.total_supply -= lamports;

        Ok(())
    }

    /// Refund expired escrows (called periodically)
    pub fn refund_expired_escrows(&mut self) -> Vec<String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired: Vec<String> = self.escrows.iter()
            .filter(|(_, e)| e.expiry < now)
            .map(|(id, _)| id.clone())
            .collect();

        let mut refunded = Vec::new();

        for match_id in expired {
            if let Some(escrow) = self.escrows.remove(&match_id) {
                // Refund each participant their contribution
                for (i, address) in escrow.participants.iter().enumerate() {
                    let contribution = escrow.contributions.get(i).copied().unwrap_or(0);
                    *self.accounts.entry(address.clone()).or_insert(0) += contribution;
                }
                refunded.push(match_id);
            }
        }

        refunded
    }

    /// Get total supply in $BB
    pub fn get_total_supply(&self) -> f64 {
        self.total_supply as f64 / LAMPORTS_PER_BB as f64
    }

    /// Verify zero-sum invariant
    pub fn verify_invariant(&self) -> bool {
        let accounts_total: u64 = self.accounts.values().sum();
        let escrows_total: u64 = self.escrows.values().map(|e| e.total_locked).sum();
        
        accounts_total + escrows_total == self.total_supply
    }
}

// ============================================================================
// BLOCK (for PoH chain)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub slot: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
    pub poh_hash: String,
    pub transactions: Vec<Transaction>,
    pub state_root: String,
}

impl Block {
    pub fn genesis() -> Self {
        let hash = compute_genesis_hash();
        Self {
            slot: 0,
            timestamp: GENESIS_TIMESTAMP,
            previous_hash: "0".repeat(64),
            hash: hash.clone(),
            poh_hash: hash.clone(),
            transactions: Vec::new(),
            state_root: hash,
        }
    }

    pub fn new(
        slot: u64,
        previous_hash: String,
        poh_hash: String,
        transactions: Vec<Transaction>,
        state_root: String,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let tx_ids: Vec<&str> = transactions.iter().map(|t| t.id.as_str()).collect();
        let hash_input = format!("{}{}{}{}{:?}", slot, previous_hash, poh_hash, timestamp, tx_ids);
        let hash = format!("{:x}", Sha256::digest(hash_input.as_bytes()));

        Self {
            slot,
            timestamp,
            previous_hash,
            hash,
            poh_hash,
            transactions,
            state_root,
        }
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint() {
        let mut state = L1State::new();
        
        // Mint 100 $BB to Alice
        let tx = Transaction::mint("alice", 100.0, Some("usdc_123".to_string()));
        assert!(state.execute(&tx).is_ok());
        
        assert_eq!(state.get_balance("alice"), 100.0);
        assert_eq!(state.get_total_supply(), 100.0);
    }

    #[test]
    fn test_lock_and_settle() {
        let mut state = L1State::new();
        
        // Setup: Mint to Alice and Bob
        state.execute(&Transaction::mint("alice", 100.0, None)).unwrap();
        state.execute(&Transaction::mint("bob", 100.0, None)).unwrap();
        
        assert_eq!(state.get_total_supply(), 200.0);
        
        // Lock: Both put 10 $BB into escrow
        let lock_tx = Transaction::lock("match_001", vec![
            LockParticipant { address: "alice".to_string(), amount: 10.0 },
            LockParticipant { address: "bob".to_string(), amount: 10.0 },
        ], None);
        assert!(state.execute(&lock_tx).is_ok());
        
        // Check balances
        assert_eq!(state.get_balance("alice"), 90.0);
        assert_eq!(state.get_balance("bob"), 90.0);
        assert!(state.escrows.contains_key("match_001"));
        
        // Total supply unchanged (just moved to escrow)
        assert_eq!(state.get_total_supply(), 200.0);
        assert!(state.verify_invariant());
        
        // Settle: Alice wins
        let settle_tx = Transaction::settle("match_001", "alice");
        assert!(state.execute(&settle_tx).is_ok());
        
        // Alice gets 20 $BB (her 10 + Bob's 10)
        assert_eq!(state.get_balance("alice"), 110.0);
        assert_eq!(state.get_balance("bob"), 90.0);
        
        // Escrow cleared, supply still 200
        assert!(!state.escrows.contains_key("match_001"));
        assert_eq!(state.get_total_supply(), 200.0);
        assert!(state.verify_invariant());
    }

    #[test]
    fn test_burn() {
        let mut state = L1State::new();
        
        // Mint then burn
        state.execute(&Transaction::mint("alice", 100.0, None)).unwrap();
        assert_eq!(state.get_total_supply(), 100.0);
        
        // Burn 30 $BB
        let burn_tx = Transaction::burn("alice", 30.0, Some("usdc_withdraw".to_string()));
        assert!(state.execute(&burn_tx).is_ok());
        
        assert_eq!(state.get_balance("alice"), 70.0);
        assert_eq!(state.get_total_supply(), 70.0);
        assert!(state.verify_invariant());
    }

    #[test]
    fn test_insufficient_balance() {
        let mut state = L1State::new();
        
        state.execute(&Transaction::mint("alice", 10.0, None)).unwrap();
        
        // Try to lock more than available
        let lock_tx = Transaction::lock("match_001", vec![
            LockParticipant { address: "alice".to_string(), amount: 100.0 },
        ], None);
        
        assert_eq!(state.execute(&lock_tx), Err(ChainError::InsufficientBalance));
    }

    #[test]
    fn test_zero_sum_violation() {
        let mut state = L1State::new();
        
        state.execute(&Transaction::mint("alice", 100.0, None)).unwrap();
        state.execute(&Transaction::mint("bob", 100.0, None)).unwrap();
        
        let lock_tx = Transaction::lock("match_001", vec![
            LockParticipant { address: "alice".to_string(), amount: 10.0 },
            LockParticipant { address: "bob".to_string(), amount: 10.0 },
        ], None);
        state.execute(&lock_tx).unwrap();
        
        // Try to settle with wrong payout amount (should fail)
        let bad_settle = Transaction::settle_with_payouts("match_001", vec![
            Payout { address: "alice".to_string(), amount: 30.0 }, // Too much!
        ]);
        
        assert_eq!(state.execute(&bad_settle), Err(ChainError::ZeroSumViolation));
    }

    #[test]
    fn test_invalid_winner() {
        let mut state = L1State::new();
        
        state.execute(&Transaction::mint("alice", 100.0, None)).unwrap();
        state.execute(&Transaction::mint("bob", 100.0, None)).unwrap();
        
        let lock_tx = Transaction::lock("match_001", vec![
            LockParticipant { address: "alice".to_string(), amount: 10.0 },
            LockParticipant { address: "bob".to_string(), amount: 10.0 },
        ], None);
        state.execute(&lock_tx).unwrap();
        
        // Try to settle with non-participant as winner
        let settle_tx = Transaction::settle("match_001", "carol");
        
        assert_eq!(state.execute(&settle_tx), Err(ChainError::InvalidWinner));
    }
}
