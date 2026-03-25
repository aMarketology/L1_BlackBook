use anchor_lang::prelude::*;

// ============================================================================
// BLACKBOOK BRIDGE — ON-CHAIN STATE
// ============================================================================
//
// Two account types live on-chain:
//
//   BridgeVault  — singleton PDA holding program config + USDC reserve totals.
//                  Seeds: ["bridge_vault"]
//
//   DepositReceipt — one PDA per deposit, storing the deposit details so the
//                    L1 watcher can confirm finality before minting BB.
//                    Seeds: ["deposit", payer.key(), nonce.to_le_bytes()]
//
// ============================================================================

/// Singleton PDA: program configuration and treasury accounting.
///
/// Holds:
///  - The authorized operator pubkey (can approve withdrawals)
///  - Lifetime deposit / withdrawal counters
///  - The USDC mint address we accept
#[account]
pub struct BridgeVault {
    /// Pubkey that can execute `release_withdrawal` (the L1 relayer hot key).
    pub operator: Pubkey,
    /// Real USDC SPL mint we accept (Solana mainnet-beta USDC).
    pub usdc_mint: Pubkey,
    /// Bump seed so we can sign CPIs without a private key.
    pub bump: u8,
    /// Cumulative USDC (in smallest units, 6 decimals) ever deposited.
    pub total_deposited: u64,
    /// Cumulative USDC ever released to withdrawers.
    pub total_withdrawn: u64,
    /// Running count of deposit operations (used as nonce for DepositReceipt PDAs).
    pub deposit_count: u64,
    /// Running count of completed withdrawals.
    pub withdrawal_count: u64,
}

impl BridgeVault {
    /// Discriminator (8) + all fields.
    pub const LEN: usize = 8 + 32 + 32 + 1 + 8 + 8 + 8 + 8;
}

/// Per-deposit PDA: proof that a specific deposit happened on-chain.
///
/// The L1 watcher queries `getProgramAccounts` filtering by `depositor` to
/// find uninitiated deposits it hasn't minted BB for yet.  Once BB is minted
/// it calls `ack_deposit` which flips `bb_minted = true` and records the L1
/// slot, creating an auditable trail.
///
/// Seeds: ["deposit", depositor.key, deposit_index.to_le_bytes(8)]
#[account]
pub struct DepositReceipt {
    /// The Solana wallet that sent USDC.
    pub depositor: Pubkey,
    /// The L1 BlackBook wallet address (base58 string, 44 bytes max).
    /// Stored as a fixed-length byte array padded with zeros.
    pub l1_wallet_bytes: [u8; 44],
    /// Actual byte length of l1_wallet_bytes (the address can be shorter).
    pub l1_wallet_len: u8,
    /// Amount deposited in USDC smallest units (6 decimals).
    pub usdc_amount: u64,
    /// Sequential deposit index, matches `BridgeVault::deposit_count - 1` when created.
    pub deposit_index: u64,
    /// Solana slot when this deposit was confirmed on-chain.
    pub solana_slot: u64,
    /// Unix timestamp at deposit time.
    pub created_at: i64,
    /// Set to true by the L1 relayer after BB has been minted to l1_wallet.
    pub bb_minted: bool,
    /// L1 BlackBook slot when BB was minted (set by `ack_deposit`).
    pub l1_mint_slot: u64,
    /// Bump seed of this PDA.
    pub bump: u8,
}

impl DepositReceipt {
    /// Space: discriminator + all fields.
    pub const LEN: usize = 8 + 32 + 44 + 1 + 8 + 8 + 8 + 8 + 1 + 8 + 1;
}
