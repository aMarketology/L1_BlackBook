use anchor_lang::prelude::*;

// ============================================================================
// BLACKBOOK BRIDGE — EVENTS
// ============================================================================
//
// Events are logged to the Solana transaction log as CPI-compatible
// borsh-serialized data. The L1 CustodyWatcher subscribes to these via
// `getSignaturesForAddress` + transaction parsing to auto-mint BB on L1.
//
// ============================================================================

/// Fired every time a user locks USDC into the bridge vault.
///
/// L1 watcher listens for this event, then calls `POST /deposit/request`
/// automatically using `depositor` as the wallet identity and `l1_wallet`
/// as the target BB address.
#[event]
pub struct UsdcDepositedEvent {
    /// Who sent the USDC.
    pub depositor: Pubkey,
    /// The L1 BlackBook wallet address (base58).
    pub l1_wallet: String,
    /// Amount in USDC smallest units (6 decimals).
    pub usdc_amount: u64,
    /// Sequential deposit index (matches DepositReceipt::deposit_index).
    pub deposit_index: u64,
    /// Solana slot at time of deposit.
    pub solana_slot: u64,
}

/// Fired by the operator after BB has been minted on L1 for a deposit.
///
/// Allows off-chain observers (audit tooling, block explorers) to correlate
/// an on-chain Solana deposit with its corresponding L1 mint operation.
#[event]
pub struct DepositAcknowledgedEvent {
    /// The DepositReceipt PDA that was acknowledged.
    pub deposit_receipt: Pubkey,
    /// L1 slot at which BB was minted.
    pub l1_mint_slot: u64,
    /// BB amount that was minted (= usdc_amount / 1_000_000 * 10, i.e. 10:1 ratio).
    pub bb_minted: u64,
}

/// Fired when the operator releases USDC to a user completing an offboard.
///
/// Maps to a L1-side burn/withdrawal operation.  The `l1_withdrawal_id` is
/// the UUID from the L1 `WITHDRAWAL_REQUESTS` table, providing a full
/// cross-chain audit trail.
#[event]
pub struct UsdcReleasedEvent {
    /// Solana wallet that received the USDC.
    pub recipient: Pubkey,
    /// Amount released in USDC smallest units.
    pub usdc_amount: u64,
    /// L1 withdrawal request UUID (for cross-chain correlation).
    pub l1_withdrawal_id: String,
    /// Solana slot at release.
    pub solana_slot: u64,
}
