// ============================================================================
// BlackBook L1 Protocol - Digital Central Bank & Vault
// ============================================================================
//
// Three Core Jobs:
//   1. GATEKEEPER (Tier 1): USDT → $BB at 1:10 ratio
//   2. TIME MACHINE (Tier 2): $BB → $DIME with vintage stamps (inflation protection)
//   3. SSS WALLET: Shamir Secret Sharing (handled in wallet_mnemonic module)
//
// Invariants:
//   - Tier 1: vault_usdt * 10 = total_bb_supply (always!)
//   - Tier 2: sum(vintage_bb_locked) = total_bb_in_vault
//
// ============================================================================

use serde::{Deserialize, Serialize};

// NOTE: Token ledgers, Tier1/Tier2 vault structs, AccountSecurity, and their
// impl blocks were removed — they were dead code (never constructed outside
// the protocol tests). The canonical vault logic lives in storage/mod.rs.

// ============================================================================
// TRANSACTIONS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub timestamp: u64,
    pub data: TxData,
    pub signature: String,
    pub signer_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TxData {
    // ========== Account Operations ==========
    CreateAccount {
        root_pubkey: String,
        initial_op_pubkey: String,
        kdf_params_hash: String,
    },
    
    RotateOpKey {
        new_op_pubkey: String,
        kdf_params_hash: String,
    },
    
    // ========== Tier 1: USDT → $BB ==========
    
    /// Deposit USDT, mint $BB at 1:10 ratio
    DepositUsdt {
        usdt_amount: u64,
        external_tx_hash: Option<String>,
    },
    
    /// Redeem $BB for USDT
    RedeemBbForUsdt {
        bb_amount: u64,
    },
    
    // ========== Tier 2: $BB → $DIME ==========
    
    /// Lock $BB, mint $DIME with vintage stamp
    LockBbForDime {
        bb_amount: u64,
    },
    
    /// Redeem vintage for exact original $BB
    RedeemDimeVintage {
        vintage_id: String,
    },
    
    // ========== Oracle ==========
    
    /// Update CPI index (oracle only)
    UpdateCpi {
        new_cpi_index: f64,
    },
    
    // ========== Token Operations ==========
    
    /// Transfer $BB between accounts
    TransferBb {
        to: String,
        amount: u64,
    },
    
    /// Transfer $DIME between accounts
    TransferDime {
        to: String,
        amount: u64,
    },
}
