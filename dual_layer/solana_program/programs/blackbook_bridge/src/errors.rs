use anchor_lang::prelude::*;

// ============================================================================
// BLACKBOOK BRIDGE — CUSTOM ERRORS
// ============================================================================

#[error_code]
pub enum BridgeError {
    /// Deposited amount is zero or below minimum (1 USDC = 1_000_000 units).
    #[msg("Deposit amount must be at least 1 USDC (1_000_000 units)")]
    AmountTooSmall,

    /// Deposit amount exceeds the per-transaction ceiling (100,000 USDC).
    #[msg("Deposit amount exceeds per-transaction maximum (100,000 USDC)")]
    AmountTooLarge,

    /// The USDC mint passed by the caller does not match the vault's registered mint.
    #[msg("Invalid USDC mint — must use the mint registered in BridgeVault")]
    InvalidMint,

    /// The caller is not the authorized operator.
    #[msg("Only the authorized operator can call this instruction")]
    Unauthorized,

    /// Withdrawal would exceed the available USDC balance in the vault token account.
    #[msg("Insufficient USDC balance in bridge vault for this withdrawal")]
    InsufficientVaultBalance,

    /// The L1 wallet address string is empty or exceeds 44 characters.
    #[msg("l1_wallet must be a non-empty base58 address of at most 44 characters")]
    InvalidL1Wallet,

    /// The DepositReceipt has already been acknowledged (bb_minted = true).
    #[msg("This deposit has already been acknowledged — BB already minted")]
    AlreadyAcknowledged,

    /// Withdrawal amount is zero.
    #[msg("Withdrawal amount must be greater than zero")]
    WithdrawalAmountZero,

    /// The operator provided a withdrawal amount that doesn't match the authorized payload.
    #[msg("Withdrawal amount mismatch — check signed payload")]
    WithdrawalAmountMismatch,
}
