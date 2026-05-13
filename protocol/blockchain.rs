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
use borsh::{BorshSerialize, BorshDeserialize};

// NOTE: Token ledgers, Tier1/Tier2 vault structs, AccountSecurity, and their
// impl blocks were removed — they were dead code (never constructed outside
// the protocol tests). The canonical vault logic lives in storage/mod.rs.

// ============================================================================
// TRANSACTIONS
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Transaction {
    pub hash: String,
    pub from: String,
    pub timestamp: u64,
    pub data: TxData,
    pub signature: String,
    pub signer_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum TxData {
    // ========== Tier 1: USDT → $BB Gateway ==========

    /// Deposit USDT, mint $BB at 1:10 ratio
    DepositUsdt {
        usdt_amount: u64,
        external_tx_hash: Option<String>,
    },

    // ========== Token Operations ==========

    /// Transfer $BB between accounts
    TransferBb {
        to: String,
        amount: u64,
    },

    // ========== Global Escrow Smart Contract ==========

    /// User deposits tokens into the global escrow vault
    EscrowDeposit {
        amount: u64,
        escrow_address: String,
    },

    /// L2 sequencer submits a per-market merkle root for settlement
    EscrowStateRoot {
        market_id: String,
        merkle_root: String,
    },

    /// User withdraws from escrow using a merkle proof against a settled market
    EscrowWithdraw {
        market_id: String,
        amount: u64,
        escrow_address: String,
    },

    // ========== Vault Gateway — Cross-Chain Bridge ==========

    /// User burns $BB (supply ↓) and receives wUSDT (supply ↑) in equal measure.
    /// This is the first step of the outbound bridge.
    /// INVARIANT: wusdt_credited == bb_burned (1:1 at micro/lamport scale).
    VaultBurn {
        /// Lamports of $BB destroyed — removed from total supply permanently.
        bb_burned: u64,
        /// Micro-units of wUSDT created — exactly equal to bb_burned.
        wusdt_credited: u64,
        /// PoH slot used as the BurnRecord primary key.
        poh_slot: u64,
    },

    /// Expired contest house rake swept to the house treasury PDA.
    /// Fires once per contest after claim_deadline_slot elapses and
    /// house_rake_swept_tx is None. Only the platform cut (house_rake)
    /// is moved — unclaimed winner payouts are left accessible.
    EscrowSweep {
        /// Contest whose rake is being recovered.
        contest_id: String,
        /// Lamports of house_rake transferred to house treasury.
        rake_lamports: u64,
        /// Base58 address of the house treasury PDA that received the funds.
        treasury_address: String,
    },
}

