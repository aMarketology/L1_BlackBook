// ============================================================================
// BLACKBOOK BRIDGE — ANCHOR PROGRAM
// ============================================================================
//
// Non-custodial USDC ↔ BB bridge between Solana and the BlackBook L1.
//
// DEPOSIT FLOW (onboarding)
// ─────────────────────────
//   1. User calls `deposit_usdc(amount, l1_wallet)` from their Solana wallet.
//   2. Program transfers `amount` USDC from user's ATA → bridge vault ATA.
//   3. A `DepositReceipt` PDA is written on-chain (auditable proof).
//   4. `UsdcDepositedEvent` is emitted.
//   5. L1 CustodyWatcher detects the event → auto-calls `/deposit/request` →
//      mints `amount / 1_000_000 * 10 BB` to `l1_wallet` on BlackBook L1.
//   6. Operator calls `ack_deposit` to mark the receipt as fulfilled.
//
// WITHDRAWAL FLOW (offboarding)
// ──────────────────────────────
//   1. User calls `POST /withdraw/request` on L1, burns wUSDC.
//   2. L1 records a `WithdrawalRecord` with status "pending".
//   3. Operator's relayer calls `release_withdrawal(amount, recipient, l1_id)`.
//   4. Program verifies operator authority + sufficient vault balance.
//   5. Program transfers USDC from vault ATA → recipient's Solana ATA.
//   6. `UsdcReleasedEvent` emitted → L1 relayer marks withdrawal "released".
//
// SECURITY INVARIANTS
// ────────────────────
//   • Only the registered operator can call `release_withdrawal` and `ack_deposit`.
//   • All deposits go to a PDA-owned token account — no private key holds funds.
//   • Per-tx limits: min 1 USDC, max 100,000 USDC.
//   • Replay protection: each deposit gets a unique PDA seeded by (depositor, index).
//   • No reentrancy possible (Solana program model, single-threaded execution).
//
// ============================================================================

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};

pub mod errors;
pub mod events;
pub mod state;

use errors::BridgeError;
use events::*;
use state::{BridgeVault, DepositReceipt};

declare_id!("BBRDGEXXxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

/// Minimum deposit: 1 USDC (6 decimals).
pub const MIN_DEPOSIT_USDC: u64 = 1_000_000;
/// Maximum deposit per transaction: 100,000 USDC.
pub const MAX_DEPOSIT_USDC: u64 = 100_000_000_000;
/// Seeds for the BridgeVault PDA.
pub const VAULT_SEED: &[u8] = b"bridge_vault";
/// Seeds prefix for DepositReceipt PDAs.
pub const DEPOSIT_SEED: &[u8] = b"deposit";

#[program]
pub mod blackbook_bridge {
    use super::*;

    // =========================================================================
    // INSTRUCTION: initialize
    //
    // Called once by the deployer to create the BridgeVault singleton PDA.
    // =========================================================================

    /// Initialize the bridge vault singleton.
    ///
    /// # Arguments
    /// * `operator`  — Pubkey of the L1 relayer hot key.
    /// * `usdc_mint` — Real USDC SPL mint on Solana.
    pub fn initialize(
        ctx: Context<Initialize>,
        operator: Pubkey,
    ) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.operator    = operator;
        vault.usdc_mint   = ctx.accounts.usdc_mint.key();
        vault.bump        = ctx.bumps.vault;
        vault.total_deposited  = 0;
        vault.total_withdrawn  = 0;
        vault.deposit_count    = 0;
        vault.withdrawal_count = 0;

        msg!("BlackBook Bridge initialized. Operator: {}", operator);
        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: deposit_usdc
    //
    // Non-custodial onboarding: user locks USDC into the bridge vault.
    // The L1 watcher will auto-mint BB to `l1_wallet` after detecting the event.
    // =========================================================================

    /// Deposit USDC into the bridge and request BB on BlackBook L1.
    ///
    /// # Arguments
    /// * `amount`     — USDC amount in smallest units (6 decimals). Min 1_000_000.
    /// * `l1_wallet`  — The BlackBook L1 base58 address to receive BB tokens.
    pub fn deposit_usdc(
        ctx: Context<DepositUsdc>,
        amount: u64,
        l1_wallet: String,
    ) -> Result<()> {
        // ── Validate inputs ──────────────────────────────────────────────────
        require!(amount >= MIN_DEPOSIT_USDC, BridgeError::AmountTooSmall);
        require!(amount <= MAX_DEPOSIT_USDC, BridgeError::AmountTooLarge);
        require!(!l1_wallet.is_empty() && l1_wallet.len() <= 44, BridgeError::InvalidL1Wallet);
        require_keys_eq!(
            ctx.accounts.usdc_mint.key(),
            ctx.accounts.vault.usdc_mint,
            BridgeError::InvalidMint
        );

        let clock = Clock::get()?;
        let vault = &mut ctx.accounts.vault;

        // ── CPI: transfer USDC from user → vault ATA ─────────────────────────
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from:      ctx.accounts.user_usdc_account.to_account_info(),
                to:        ctx.accounts.vault_usdc_account.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;

        // ── Write DepositReceipt PDA ─────────────────────────────────────────
        let receipt = &mut ctx.accounts.deposit_receipt;
        receipt.depositor    = ctx.accounts.user.key();
        receipt.usdc_amount  = amount;
        receipt.deposit_index = vault.deposit_count;
        receipt.solana_slot  = clock.slot;
        receipt.created_at   = clock.unix_timestamp;
        receipt.bb_minted    = false;
        receipt.l1_mint_slot = 0;
        receipt.bump         = ctx.bumps.deposit_receipt;

        // Store l1_wallet as fixed-length byte array
        let l1_bytes = l1_wallet.as_bytes();
        receipt.l1_wallet_len = l1_bytes.len() as u8;
        receipt.l1_wallet_bytes[..l1_bytes.len()].copy_from_slice(l1_bytes);

        // ── Update vault accounting ──────────────────────────────────────────
        vault.total_deposited = vault.total_deposited.saturating_add(amount);
        vault.deposit_count   = vault.deposit_count.saturating_add(1);

        // ── Emit event for L1 watcher ────────────────────────────────────────
        emit!(UsdcDepositedEvent {
            depositor:    ctx.accounts.user.key(),
            l1_wallet:    l1_wallet.clone(),
            usdc_amount:  amount,
            deposit_index: receipt.deposit_index,
            solana_slot:   clock.slot,
        });

        msg!(
            "Deposit: {} USDC ({} units) → L1 wallet {} | index {}",
            amount / 1_000_000,
            amount,
            l1_wallet,
            receipt.deposit_index
        );

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: ack_deposit
    //
    // Called by the operator after BB has been minted on L1 for a deposit.
    // Marks the DepositReceipt as fulfilled and records the L1 slot.
    // =========================================================================

    /// Acknowledge a deposit after BB has been minted on L1.
    ///
    /// # Arguments
    /// * `l1_mint_slot` — BlackBook L1 slot at which BB was minted.
    pub fn ack_deposit(
        ctx: Context<AckDeposit>,
        l1_mint_slot: u64,
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.operator.key(),
            ctx.accounts.vault.operator,
            BridgeError::Unauthorized
        );

        let receipt = &mut ctx.accounts.deposit_receipt;
        require!(!receipt.bb_minted, BridgeError::AlreadyAcknowledged);

        receipt.bb_minted    = true;
        receipt.l1_mint_slot = l1_mint_slot;

        // BB minted = usdc_amount / 1_000_000 * 10 (10:1 ratio, 0 decimals)
        let bb_minted = (receipt.usdc_amount / 1_000_000) * 10;

        emit!(DepositAcknowledgedEvent {
            deposit_receipt: ctx.accounts.deposit_receipt.key(),
            l1_mint_slot,
            bb_minted,
        });

        msg!("Deposit {} acknowledged — {} BB minted at L1 slot {}",
            receipt.deposit_index, bb_minted, l1_mint_slot);

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: release_withdrawal
    //
    // Called by the operator to release USDC to a user completing an offboard.
    // The operator must provide the L1 withdrawal UUID for cross-chain auditing.
    // =========================================================================

    /// Release USDC from the vault to a withdrawing user.
    ///
    /// # Arguments
    /// * `amount`          — USDC amount in smallest units (6 decimals).
    /// * `l1_withdrawal_id` — UUID string from the L1 WithdrawalRecord (audit trail).
    pub fn release_withdrawal(
        ctx: Context<ReleaseWithdrawal>,
        amount: u64,
        l1_withdrawal_id: String,
    ) -> Result<()> {
        require!(amount > 0, BridgeError::WithdrawalAmountZero);
        require_keys_eq!(
            ctx.accounts.operator.key(),
            ctx.accounts.vault.operator,
            BridgeError::Unauthorized
        );
        require!(
            ctx.accounts.vault_usdc_account.amount >= amount,
            BridgeError::InsufficientVaultBalance
        );

        let clock = Clock::get()?;
        let vault = &mut ctx.accounts.vault;
        let bump = vault.bump;

        // ── CPI: transfer USDC from vault ATA → recipient ATA ────────────────
        // The vault PDA is the authority over the vault token account.
        // We sign the CPI with the PDA's seeds.
        let vault_seeds: &[&[u8]] = &[VAULT_SEED, &[bump]];
        let signer_seeds = &[vault_seeds];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from:      ctx.accounts.vault_usdc_account.to_account_info(),
                to:        ctx.accounts.recipient_usdc_account.to_account_info(),
                authority: ctx.accounts.vault.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;

        // ── Update vault accounting ──────────────────────────────────────────
        vault.total_withdrawn  = vault.total_withdrawn.saturating_add(amount);
        vault.withdrawal_count = vault.withdrawal_count.saturating_add(1);

        // ── Emit event ───────────────────────────────────────────────────────
        emit!(UsdcReleasedEvent {
            recipient:        ctx.accounts.recipient.key(),
            usdc_amount:      amount,
            l1_withdrawal_id: l1_withdrawal_id.clone(),
            solana_slot:      clock.slot,
        });

        msg!(
            "Withdrawal: {} USDC released to {} | L1 id {}",
            amount / 1_000_000,
            ctx.accounts.recipient.key(),
            l1_withdrawal_id
        );

        Ok(())
    }

    // =========================================================================
    // INSTRUCTION: update_operator
    //
    // Allows the current operator to rotate the hot key without redeploying.
    // =========================================================================

    /// Rotate the operator authority.
    pub fn update_operator(
        ctx: Context<UpdateOperator>,
        new_operator: Pubkey,
    ) -> Result<()> {
        require_keys_eq!(
            ctx.accounts.operator.key(),
            ctx.accounts.vault.operator,
            BridgeError::Unauthorized
        );
        ctx.accounts.vault.operator = new_operator;
        msg!("Operator updated to {}", new_operator);
        Ok(())
    }
}

// ============================================================================
// ACCOUNT CONTEXTS
// ============================================================================

#[derive(Accounts)]
pub struct Initialize<'info> {
    /// The deployer pays for the vault PDA rent.
    #[account(mut)]
    pub deployer: Signer<'info>,

    /// BridgeVault singleton PDA. Initialized once.
    #[account(
        init,
        payer  = deployer,
        space  = BridgeVault::LEN,
        seeds  = [VAULT_SEED],
        bump,
    )]
    pub vault: Account<'info, BridgeVault>,

    /// The USDC mint we'll accept. Stored in BridgeVault for later validation.
    pub usdc_mint: Account<'info, Mint>,

    /// The vault's USDC token account. PDA-owned, holds all deposited USDC.
    #[account(
        init,
        payer   = deployer,
        token::mint      = usdc_mint,
        token::authority = vault,  // PDA is the authority — no private key
    )]
    pub vault_usdc_account: Account<'info, TokenAccount>,

    pub token_program:  Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent:           Sysvar<'info, Rent>,
}

#[derive(Accounts)]
#[instruction(amount: u64, l1_wallet: String)]
pub struct DepositUsdc<'info> {
    /// The user making the deposit. Pays rent for the DepositReceipt PDA.
    #[account(mut)]
    pub user: Signer<'info>,

    /// BridgeVault singleton — mutated to update accounting.
    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump  = vault.bump,
    )]
    pub vault: Account<'info, BridgeVault>,

    /// User's USDC token account (source of funds).
    #[account(
        mut,
        constraint = user_usdc_account.mint == vault.usdc_mint @ BridgeError::InvalidMint,
        constraint = user_usdc_account.owner == user.key(),
    )]
    pub user_usdc_account: Account<'info, TokenAccount>,

    /// The vault's USDC token account (destination of funds).
    #[account(
        mut,
        constraint = vault_usdc_account.mint  == vault.usdc_mint @ BridgeError::InvalidMint,
        constraint = vault_usdc_account.owner == vault.key(),
    )]
    pub vault_usdc_account: Account<'info, TokenAccount>,

    /// DepositReceipt PDA — one per deposit, seeds include index for uniqueness.
    #[account(
        init,
        payer = user,
        space = DepositReceipt::LEN,
        seeds = [DEPOSIT_SEED, user.key().as_ref(), &vault.deposit_count.to_le_bytes()],
        bump,
    )]
    pub deposit_receipt: Account<'info, DepositReceipt>,

    /// CHECK: read-only, used only for constraint validation.
    pub usdc_mint: Account<'info, Mint>,

    pub token_program:  Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AckDeposit<'info> {
    /// The operator (L1 relayer) must sign.
    pub operator: Signer<'info>,

    /// BridgeVault to verify operator authority.
    #[account(
        seeds = [VAULT_SEED],
        bump  = vault.bump,
    )]
    pub vault: Account<'info, BridgeVault>,

    /// The DepositReceipt PDA to mark as fulfilled.
    #[account(mut)]
    pub deposit_receipt: Account<'info, DepositReceipt>,
}

#[derive(Accounts)]
pub struct ReleaseWithdrawal<'info> {
    /// The operator must sign to authorize the payout.
    pub operator: Signer<'info>,

    /// BridgeVault — authority over vault token account + accounting.
    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump  = vault.bump,
    )]
    pub vault: Account<'info, BridgeVault>,

    /// Vault USDC token account — source of payout funds.
    #[account(
        mut,
        constraint = vault_usdc_account.owner == vault.key() @ BridgeError::Unauthorized,
    )]
    pub vault_usdc_account: Account<'info, TokenAccount>,

    /// Recipient's Solana wallet (the user who burnt BB on L1).
    /// CHECK: we don't need to validate this is a system account — just that
    /// the ATA below belongs to it.
    pub recipient: UncheckedAccount<'info>,

    /// Recipient's USDC ATA.
    #[account(
        mut,
        constraint = recipient_usdc_account.owner == recipient.key(),
    )]
    pub recipient_usdc_account: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct UpdateOperator<'info> {
    /// Current operator must sign.
    pub operator: Signer<'info>,

    #[account(
        mut,
        seeds = [VAULT_SEED],
        bump  = vault.bump,
    )]
    pub vault: Account<'info, BridgeVault>,
}
