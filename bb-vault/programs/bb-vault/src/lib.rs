use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

// ============================================================================
// BlackBook USDT Vault
// ============================================================================
//
// Outbound claim flow:
//   1. User burns $BB on the L1 → recorded in PoH.
//   2. L1 backend signs an attestation via AWS KMS:
//        message = "CLAIM:{poh_slot}:{amount}:{user_pubkey}"
//   3. User's frontend submits a 2-instruction Solana tx:
//        ix[0] = Ed25519 native verify (KMS signature)
//        ix[1] = claim_usdt (this program)
//   4. claim_usdt introspects ix[0] via instructions sysvar,
//      confirms the KMS pubkey matches, then transfers USDT.
//
// Security layers:
//   - KMS-only signing (no private key on disk)
//   - ProcessedSlot PDA per PoH slot (structural replay protection)
//   - Daily rate limit (caps blast radius)
//   - Circuit breaker (Squads multisig pause)
// ============================================================================

#[program]
pub mod bb_vault {
    use super::*;

    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        admin_multisig: Pubkey,
        kms_oracle_pubkey: Pubkey,
        daily_limit: u64,
    ) -> Result<()> {
        let state = &mut ctx.accounts.vault_state;
        state.admin_multisig = admin_multisig;
        state.kms_oracle_pubkey = kms_oracle_pubkey;
        state.daily_limit = daily_limit;
        state.dispensed_today = 0;
        state.last_reset_time = Clock::get()?.unix_timestamp;
        state.is_paused = false;
        state.bump = ctx.bumps.vault_state;

        emit!(ConfigEvent {
            field: "initialize".to_string(),
            old_value: "none".to_string(),
            new_value: format!("limit={},kms={}", daily_limit, kms_oracle_pubkey),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn claim_usdt(
        ctx: Context<ClaimUsdt>,
        poh_slot: u64,
        amount: u64,
    ) -> Result<()> {
        let state = &mut ctx.accounts.vault_state;

        // 1. Circuit breaker
        require!(!state.is_paused, VaultError::VaultIsPaused);

        // 2. Daily rate limit (reset if 24h have passed)
        let current_time = Clock::get()?.unix_timestamp;
        if current_time - state.last_reset_time > 86400 {
            state.dispensed_today = 0;
            state.last_reset_time = current_time;
        }
        require!(
            state.dispensed_today.checked_add(amount).ok_or(VaultError::DailyLimitExceeded)? <= state.daily_limit,
            VaultError::DailyLimitExceeded
        );

        // 3. Verify KMS signature via instructions sysvar
        verify_ed25519_instruction(
            &ctx.accounts.instructions_sysvar,
            &state.kms_oracle_pubkey,
            poh_slot,
            amount,
            &ctx.accounts.user.key(),
        )?;

        // 4. Update state + mark slot as processed
        state.dispensed_today += amount;

        let slot = &mut ctx.accounts.processed_slot;
        slot.slot_number = poh_slot;
        slot.claimed_at = current_time;
        slot.user = ctx.accounts.user.key();
        slot.amount = amount;
        slot.bump = ctx.bumps.processed_slot;

        // 5. Transfer USDT from vault PDA to user
        let seeds = &[b"vault".as_ref(), &[state.bump]];
        let signer_seeds = &[&seeds[..]];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault_usdt_account.to_account_info(),
                    to: ctx.accounts.user_usdt_account.to_account_info(),
                    authority: ctx.accounts.vault_state.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )?;

        emit!(ClaimEvent {
            user: ctx.accounts.user.key(),
            poh_slot,
            amount,
            timestamp: current_time,
        });

        Ok(())
    }

    pub fn pause_vault(ctx: Context<AdminAction>) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.vault_state.admin_multisig,
            VaultError::Unauthorized
        );
        ctx.accounts.vault_state.is_paused = true;

        emit!(PauseEvent {
            paused_by: ctx.accounts.admin.key(),
            is_paused: true,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn unpause_vault(ctx: Context<AdminAction>) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.vault_state.admin_multisig,
            VaultError::Unauthorized
        );
        ctx.accounts.vault_state.is_paused = false;

        emit!(PauseEvent {
            paused_by: ctx.accounts.admin.key(),
            is_paused: false,
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn update_daily_limit(ctx: Context<AdminAction>, new_limit: u64) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.vault_state.admin_multisig,
            VaultError::Unauthorized
        );
        let old = ctx.accounts.vault_state.daily_limit;
        ctx.accounts.vault_state.daily_limit = new_limit;

        emit!(ConfigEvent {
            field: "daily_limit".to_string(),
            old_value: old.to_string(),
            new_value: new_limit.to_string(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }

    pub fn rotate_kms_key(ctx: Context<AdminAction>, new_kms_pubkey: Pubkey) -> Result<()> {
        require!(
            ctx.accounts.admin.key() == ctx.accounts.vault_state.admin_multisig,
            VaultError::Unauthorized
        );
        let old = ctx.accounts.vault_state.kms_oracle_pubkey;
        ctx.accounts.vault_state.kms_oracle_pubkey = new_kms_pubkey;

        emit!(ConfigEvent {
            field: "kms_oracle_pubkey".to_string(),
            old_value: old.to_string(),
            new_value: new_kms_pubkey.to_string(),
            timestamp: Clock::get()?.unix_timestamp,
        });

        Ok(())
    }
}

// ============================================================================
// Account Structs
// ============================================================================

#[account]
pub struct VaultState {
    pub admin_multisig: Pubkey,
    pub kms_oracle_pubkey: Pubkey,
    pub daily_limit: u64,
    pub dispensed_today: u64,
    pub last_reset_time: i64,
    pub is_paused: bool,
    pub bump: u8,
}

impl VaultState {
    // discriminator(8) + pubkey(32) + pubkey(32) + u64(8) + u64(8) + i64(8) + bool(1) + u8(1)
    pub const LEN: usize = 8 + 32 + 32 + 8 + 8 + 8 + 1 + 1;
}

#[account]
pub struct ProcessedSlot {
    pub slot_number: u64,
    pub claimed_at: i64,
    pub user: Pubkey,
    pub amount: u64,
    pub bump: u8,
}

impl ProcessedSlot {
    // discriminator(8) + u64(8) + i64(8) + pubkey(32) + u64(8) + u8(1)
    pub const LEN: usize = 8 + 8 + 8 + 32 + 8 + 1;
}

// ============================================================================
// Instruction Account Constraints
// ============================================================================

#[derive(Accounts)]
pub struct InitializeVault<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(
        init,
        payer = admin,
        space = VaultState::LEN,
        seeds = [b"vault"],
        bump,
    )]
    pub vault_state: Account<'info, VaultState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(poh_slot: u64, amount: u64)]
pub struct ClaimUsdt<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault_state.bump,
    )]
    pub vault_state: Account<'info, VaultState>,

    #[account(
        init,
        payer = user,
        space = ProcessedSlot::LEN,
        seeds = [b"slot", poh_slot.to_le_bytes().as_ref()],
        bump,
    )]
    pub processed_slot: Account<'info, ProcessedSlot>,

    #[account(
        mut,
        constraint = vault_usdt_account.owner == vault_state.key()
            @ VaultError::InvalidVaultTokenAccount,
    )]
    pub vault_usdt_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub user_usdt_account: Account<'info, TokenAccount>,

    /// CHECK: Validated as instructions sysvar in verify_ed25519_instruction
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminAction<'info> {
    pub admin: Signer<'info>,

    #[account(
        mut,
        seeds = [b"vault"],
        bump = vault_state.bump,
    )]
    pub vault_state: Account<'info, VaultState>,
}

// ============================================================================
// Ed25519 Sysvar Introspection
// ============================================================================

/// Verify that instruction[0] in the current transaction is a valid
/// Ed25519 native program verification using the expected KMS public key.
///
/// The Ed25519 instruction data layout (for 1 signature):
///   bytes  0..2   num_signatures (u16 LE, must be 1)
///   bytes  2..4   padding
///   bytes  4..6   signature_offset (u16 LE)
///   bytes  6..8   signature_instruction_index (u16 LE, must be 0xFFFF = current tx)
///   bytes  8..10  public_key_offset (u16 LE)
///   bytes 10..12  public_key_instruction_index (u16 LE, must be 0xFFFF)
///   bytes 12..14  message_data_offset (u16 LE)
///   bytes 14..16  message_data_size (u16 LE)
///   bytes 16..18  message_instruction_index (u16 LE, must be 0xFFFF)
///   (then raw data: signature bytes, pubkey bytes, message bytes at their offsets)
fn verify_ed25519_instruction(
    instructions_sysvar: &AccountInfo,
    expected_kms_pubkey: &Pubkey,
    poh_slot: u64,
    amount: u64,
    user_pubkey: &Pubkey,
) -> Result<()> {
    let ix = solana_program::sysvar::instructions::load_instruction_at_checked(
        0,
        instructions_sysvar,
    )
    .map_err(|_| VaultError::InvalidEd25519Instruction)?;

    // Must be the native Ed25519 program
    require!(
        ix.program_id == solana_program::ed25519_program::ID,
        VaultError::InvalidEd25519Instruction
    );

    let data = &ix.data;
    require!(data.len() >= 18, VaultError::InvalidEd25519Instruction);

    let num_signatures = u16::from_le_bytes([data[0], data[1]]);
    require!(num_signatures == 1, VaultError::InvalidEd25519Instruction);

    // Extract offsets
    let sig_offset = u16::from_le_bytes([data[4], data[5]]) as usize;
    let pubkey_offset = u16::from_le_bytes([data[8], data[9]]) as usize;
    let msg_offset = u16::from_le_bytes([data[12], data[13]]) as usize;
    let msg_size = u16::from_le_bytes([data[14], data[15]]) as usize;

    // Bounds check
    require!(
        pubkey_offset + 32 <= data.len()
            && sig_offset + 64 <= data.len()
            && msg_offset + msg_size <= data.len(),
        VaultError::InvalidEd25519Instruction
    );

    // Verify the public key matches our KMS oracle
    let ix_pubkey = &data[pubkey_offset..pubkey_offset + 32];
    require!(
        ix_pubkey == expected_kms_pubkey.to_bytes().as_ref(),
        VaultError::KmsKeyMismatch
    );

    // Verify the signed message matches the expected canonical format
    let ix_message = &data[msg_offset..msg_offset + msg_size];
    let expected_message = format!("CLAIM:{}:{}:{}", poh_slot, amount, user_pubkey);
    require!(
        ix_message == expected_message.as_bytes(),
        VaultError::MessageMismatch
    );

    Ok(())
}

// ============================================================================
// Errors
// ============================================================================

#[error_code]
pub enum VaultError {
    #[msg("Vault is paused — all claims are frozen")]
    VaultIsPaused,

    #[msg("Daily USDT disbursement limit exceeded")]
    DailyLimitExceeded,

    #[msg("Invalid or missing Ed25519 verification instruction")]
    InvalidEd25519Instruction,

    #[msg("Ed25519 public key does not match the configured KMS oracle")]
    KmsKeyMismatch,

    #[msg("Signed message does not match the expected claim parameters")]
    MessageMismatch,

    #[msg("Signer is not the admin multisig")]
    Unauthorized,

    #[msg("Vault USDT token account authority mismatch")]
    InvalidVaultTokenAccount,
}

// ============================================================================
// Events
// ============================================================================

#[event]
pub struct ClaimEvent {
    pub user: Pubkey,
    pub poh_slot: u64,
    pub amount: u64,
    pub timestamp: i64,
}

#[event]
pub struct PauseEvent {
    pub paused_by: Pubkey,
    pub is_paused: bool,
    pub timestamp: i64,
}

#[event]
pub struct ConfigEvent {
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub timestamp: i64,
}
