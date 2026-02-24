// ============================================================================
// BLACKBOOK SVM — SPL TOKEN (Native Implementation)
// ============================================================================
//
// Implements the Solana Program Library (SPL) Token standard natively in Rust
// without the rBPF VM. This gives BlackBook L1 full SPL Token compatibility:
//   - Mint accounts (token definitions with supply, decimals, authority)
//   - Token accounts (per-wallet token balances)
//   - getTokenAccountsByOwner RPC returns real data
//   - Any SVM wallet (Nightly, svmseek, Phantom) can display token balances
//
// USDC on BlackBook L1:
//   - Mint address is deterministic (derived from "USDC" seed at genesis)
//   - 6 decimals (matches Solana mainnet USDC)
//   - Mint authority = Dealer wallet (can mint wrapped USDC when bridge deposits arrive)
//
// Data layouts match Solana's SPL Token exactly so that any client library
// (@solana/spl-token, Anchor, etc.) can deserialize them without modification.
//
// ============================================================================

use serde::Serialize;
use sha2::{Sha256, Digest};
use solana_sdk::{
    account::{AccountSharedData, Account, ReadableAccount},
    pubkey::Pubkey,
};

use crate::svm::accounts_db::SvmAccountsDB;
use crate::svm::types::{RENT_EPOCH_EXEMPT, SvmError};

// ============================================================================
// WELL-KNOWN PROGRAM IDS
// ============================================================================

/// SPL Token Program ID (same as Solana mainnet)
/// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
];

/// Associated Token Account Program ID (same as Solana mainnet)
/// ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL
pub const ASSOCIATED_TOKEN_PROGRAM_ID: [u8; 32] = [
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
    11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
];

// ============================================================================
// SPL TOKEN ACCOUNT LAYOUTS (binary-compatible with Solana)
// ============================================================================

/// SPL Token Mint layout — 82 bytes on Solana.
///
/// This is the exact byte layout that @solana/spl-token expects when
/// deserializing a Mint account's data field.
#[derive(Debug, Clone)]
pub struct MintLayout {
    /// Optional authority who can mint new tokens (36 bytes: 4-byte COption + 32-byte pubkey)
    pub mint_authority_option: u32,       // 0 = None, 1 = Some
    pub mint_authority: [u8; 32],         // authority pubkey (zeroed if None)
    /// Total supply of this token (in smallest units)
    pub supply: u64,
    /// Number of decimal places (USDC = 6, BB could = 9)
    pub decimals: u8,
    /// Is this mint initialized?
    pub is_initialized: bool,
    /// Optional freeze authority (36 bytes: COption + pubkey)
    pub freeze_authority_option: u32,     // 0 = None, 1 = Some
    pub freeze_authority: [u8; 32],       // freeze authority pubkey
}

impl MintLayout {
    /// Serialize to 82 bytes (Solana SPL Token Mint layout)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(82);
        buf.extend_from_slice(&self.mint_authority_option.to_le_bytes());   // 4
        buf.extend_from_slice(&self.mint_authority);                        // 32
        buf.extend_from_slice(&self.supply.to_le_bytes());                  // 8
        buf.push(self.decimals);                                            // 1
        buf.push(if self.is_initialized { 1 } else { 0 });                 // 1
        buf.extend_from_slice(&self.freeze_authority_option.to_le_bytes()); // 4
        buf.extend_from_slice(&self.freeze_authority);                      // 32
        buf                                                                 // = 82
    }

    /// Deserialize from 82 bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 82 {
            return Err(format!("Mint data too short: {} bytes (need 82)", data.len()));
        }
        Ok(Self {
            mint_authority_option: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            mint_authority: data[4..36].try_into().unwrap(),
            supply: u64::from_le_bytes(data[36..44].try_into().unwrap()),
            decimals: data[44],
            is_initialized: data[45] != 0,
            freeze_authority_option: u32::from_le_bytes(data[46..50].try_into().unwrap()),
            freeze_authority: data[50..82].try_into().unwrap(),
        })
    }
}

/// SPL Token Account layout — 165 bytes on Solana.
///
/// This is the exact byte layout for an Associated Token Account (ATA).
/// Any wallet or dApp using @solana/spl-token can deserialize this directly.
#[derive(Debug, Clone)]
pub struct TokenAccountLayout {
    /// The mint this account holds tokens of (32 bytes)
    pub mint: [u8; 32],
    /// The owner of this token account (32 bytes)
    pub owner: [u8; 32],
    /// Token balance (in smallest units, e.g. micro-USDC for 6 decimals)
    pub amount: u64,
    /// Delegate option (36 bytes: COption + pubkey)
    pub delegate_option: u32,
    pub delegate: [u8; 32],
    /// Account state: 0 = Uninitialized, 1 = Initialized, 2 = Frozen
    pub state: u8,
    /// Is this a native SOL/BB token account? (12 bytes: COption + u64)
    pub is_native_option: u32,
    pub is_native: u64,
    /// Delegated amount
    pub delegated_amount: u64,
    /// Close authority option (36 bytes: COption + pubkey)
    pub close_authority_option: u32,
    pub close_authority: [u8; 32],
}

impl TokenAccountLayout {
    /// Serialize to 165 bytes (Solana SPL Token Account layout)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(165);
        buf.extend_from_slice(&self.mint);                                  // 32
        buf.extend_from_slice(&self.owner);                                 // 32
        buf.extend_from_slice(&self.amount.to_le_bytes());                  // 8
        buf.extend_from_slice(&self.delegate_option.to_le_bytes());         // 4
        buf.extend_from_slice(&self.delegate);                              // 32
        buf.push(self.state);                                               // 1
        buf.extend_from_slice(&self.is_native_option.to_le_bytes());        // 4
        buf.extend_from_slice(&self.is_native.to_le_bytes());               // 8
        buf.extend_from_slice(&self.delegated_amount.to_le_bytes());        // 8
        buf.extend_from_slice(&self.close_authority_option.to_le_bytes());  // 4
        buf.extend_from_slice(&self.close_authority);                       // 32
        buf                                                                 // = 165
    }

    /// Deserialize from 165 bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 165 {
            return Err(format!("Token account data too short: {} bytes (need 165)", data.len()));
        }
        Ok(Self {
            mint: data[0..32].try_into().unwrap(),
            owner: data[32..64].try_into().unwrap(),
            amount: u64::from_le_bytes(data[64..72].try_into().unwrap()),
            delegate_option: u32::from_le_bytes(data[72..76].try_into().unwrap()),
            delegate: data[76..108].try_into().unwrap(),
            state: data[108],
            is_native_option: u32::from_le_bytes(data[109..113].try_into().unwrap()),
            is_native: u64::from_le_bytes(data[113..121].try_into().unwrap()),
            delegated_amount: u64::from_le_bytes(data[121..129].try_into().unwrap()),
            close_authority_option: u32::from_le_bytes(data[129..133].try_into().unwrap()),
            close_authority: data[133..165].try_into().unwrap(),
        })
    }
}

// ============================================================================
// DETERMINISTIC MINT ADDRESS DERIVATION
// ============================================================================

/// Derive a deterministic mint address from a seed string.
///
/// This uses SHA-256(seed) → first 32 bytes as the Pubkey, ensuring the
/// USDC mint address is consistent across restarts without storing it.
///
/// Example: `derive_mint_address("BlackBook_USDC_Mint_v1")` → always the same Pubkey
pub fn derive_mint_address(seed: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    let result = hasher.finalize();
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&result[..32]);
    addr
}

/// Derive an Associated Token Account (ATA) address for a given wallet + mint.
///
/// Uses the same PDA derivation as Solana's ATA Program:
///   PDA = SHA-256(wallet_pubkey || spl_token_program_id || mint_pubkey || ata_program_id)[..32]
///
/// Note: Real Solana uses find_program_address with bump, but since we control
/// the entire chain, SHA-256 gives us deterministic, collision-resistant addresses.
pub fn derive_ata_address(wallet: &[u8; 32], mint: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(wallet);
    hasher.update(&SPL_TOKEN_PROGRAM_ID);
    hasher.update(mint);
    hasher.update(&ASSOCIATED_TOKEN_PROGRAM_ID);
    let result = hasher.finalize();
    let mut addr = [0u8; 32];
    addr.copy_from_slice(&result[..32]);
    addr
}

// ============================================================================
// USDC MINT CONSTANTS
// ============================================================================

/// The seed used to derive the USDC mint address on BlackBook L1.
/// Changing this would change the mint address — NEVER change after deployment.
pub const USDC_MINT_SEED: &str = "BlackBook_USDC_Mint_v1";

/// USDC has 6 decimal places (same as Solana mainnet USDC).
/// 1 USDC = 1,000,000 smallest units.
pub const USDC_DECIMALS: u8 = 6;

/// 1 USDC in smallest units
pub const USDC_UNIT: u64 = 1_000_000;

/// Get the deterministic USDC mint address bytes
pub fn usdc_mint_bytes() -> [u8; 32] {
    derive_mint_address(USDC_MINT_SEED)
}

/// Get the USDC mint address as a base58 string
pub fn usdc_mint_address() -> String {
    bs58::encode(usdc_mint_bytes()).into_string()
}

// ============================================================================
// SPL TOKEN ENGINE — operates on SvmAccountsDB
// ============================================================================

/// The SPL Token Engine provides mint, transfer, and query operations
/// for SPL tokens on BlackBook L1. It operates directly on SvmAccountsDB
/// accounts using the exact same binary layouts as Solana's SPL Token program.
pub struct SplTokenEngine;

impl SplTokenEngine {
    // ────────────────────────────────────────────────────────────────────────
    // BOOTSTRAP — Called once at genesis to create the USDC mint
    // ────────────────────────────────────────────────────────────────────────

    /// Bootstrap the USDC mint account into the SVM accounts database.
    ///
    /// This creates:
    ///   1. The SPL Token Program account (executable marker)
    ///   2. The USDC Mint account (82-byte Mint layout, 6 decimals, 0 initial supply)
    ///
    /// The `mint_authority` is the address that can mint new USDC tokens
    /// (typically the Dealer wallet for bridge deposits).
    ///
    /// IDEMPOTENT: If the mint already exists, this is a no-op.
    pub fn bootstrap_usdc_mint(
        accounts_db: &SvmAccountsDB,
        mint_authority: &Pubkey,
    ) -> Result<String, SvmError> {
        let mint_bytes = usdc_mint_bytes();
        let mint_pubkey = Pubkey::new_from_array(mint_bytes);

        // Check if mint already exists (idempotent)
        if accounts_db.account_exists(&mint_pubkey) {
            let existing = accounts_db.get_account(&mint_pubkey).unwrap();
            if existing.data().len() == 82 {
                tracing::info!(
                    mint = %bs58::encode(&mint_bytes).into_string(),
                    "USDC mint already exists — skipping bootstrap"
                );
                return Ok(bs58::encode(&mint_bytes).into_string());
            }
        }

        // 1. Create SPL Token Program account (executable marker)
        let token_program_pubkey = Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID);
        if !accounts_db.account_exists(&token_program_pubkey) {
            let program_account = AccountSharedData::from(Account {
                lamports: 1,
                data: vec![],  // Native program — no ELF
                owner: Pubkey::default(), // Native loader
                executable: true,
                rent_epoch: RENT_EPOCH_EXEMPT,
            });
            accounts_db.store_account(&token_program_pubkey, program_account);
            tracing::info!("Created SPL Token Program account");
        }

        // 2. Create the USDC Mint account (82 bytes, SPL Token format)
        let mint_layout = MintLayout {
            mint_authority_option: 1, // Some
            mint_authority: mint_authority.to_bytes(),
            supply: 0,
            decimals: USDC_DECIMALS,
            is_initialized: true,
            freeze_authority_option: 0, // None — no freeze authority
            freeze_authority: [0u8; 32],
        };

        let mint_account = AccountSharedData::from(Account {
            lamports: 1_000_000_000, // rent-exempt minimum (not spent, just SOL-compat marker)
            data: mint_layout.to_bytes(),
            owner: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
            executable: false,
            rent_epoch: RENT_EPOCH_EXEMPT,
        });

        accounts_db.store_account(&mint_pubkey, mint_account);

        let mint_address = bs58::encode(&mint_bytes).into_string();
        tracing::info!(
            mint = %mint_address,
            decimals = USDC_DECIMALS,
            authority = %mint_authority,
            "✅ USDC SPL Token Mint bootstrapped on BlackBook L1"
        );

        Ok(mint_address)
    }

    // ────────────────────────────────────────────────────────────────────────
    // MINT TOKENS — Create or credit an ATA with tokens
    // ────────────────────────────────────────────────────────────────────────

    /// Mint USDC tokens to a wallet's Associated Token Account.
    ///
    /// Creates the ATA if it doesn't exist. Updates the Mint's total supply.
    ///
    /// `amount` is in smallest units (1 USDC = 1_000_000).
    pub fn mint_to(
        accounts_db: &SvmAccountsDB,
        mint_bytes: &[u8; 32],
        wallet_pubkey: &Pubkey,
        amount: u64,
    ) -> Result<MintResult, SvmError> {
        if amount == 0 {
            return Err(SvmError::InvalidTransaction("Mint amount must be > 0".into()));
        }

        let mint_pubkey = Pubkey::new_from_array(*mint_bytes);

        // 1. Load and validate the Mint account
        let mut mint_account = accounts_db
            .get_account(&mint_pubkey)
            .ok_or_else(|| SvmError::AccountNotFound(format!("Mint {} not found", bs58::encode(mint_bytes).into_string())))?;

        let mut mint_layout = MintLayout::from_bytes(mint_account.data())
            .map_err(|e| SvmError::SerializationError(e))?;

        if !mint_layout.is_initialized {
            return Err(SvmError::InvalidTransaction("Mint not initialized".into()));
        }

        // 2. Update supply
        mint_layout.supply = mint_layout.supply
            .checked_add(amount)
            .ok_or(SvmError::LamportOverflow)?;

        // Write updated mint data back
        let new_mint_data = mint_layout.to_bytes();
        mint_account.set_data_from_slice(&new_mint_data);
        accounts_db.store_account(&mint_pubkey, mint_account);

        // 3. Get or create the ATA for this wallet
        let ata_bytes = derive_ata_address(&wallet_pubkey.to_bytes(), mint_bytes);
        let ata_pubkey = Pubkey::new_from_array(ata_bytes);

        let ata_account = if let Some(existing) = accounts_db.get_account(&ata_pubkey) {
            existing
        } else {
            // Create new ATA
            let token_account = TokenAccountLayout {
                mint: *mint_bytes,
                owner: wallet_pubkey.to_bytes(),
                amount: 0,
                delegate_option: 0,
                delegate: [0u8; 32],
                state: 1, // Initialized
                is_native_option: 0,
                is_native: 0,
                delegated_amount: 0,
                close_authority_option: 0,
                close_authority: [0u8; 32],
            };

            AccountSharedData::from(Account {
                lamports: 1_000_000_000, // rent-exempt
                data: token_account.to_bytes(),
                owner: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
                executable: false,
                rent_epoch: RENT_EPOCH_EXEMPT,
            })
        };

        // 4. Credit the ATA
        let mut token_layout = TokenAccountLayout::from_bytes(ata_account.data())
            .map_err(|e| SvmError::SerializationError(e))?;

        token_layout.amount = token_layout.amount
            .checked_add(amount)
            .ok_or(SvmError::LamportOverflow)?;

        let mut updated_ata = ata_account;
        updated_ata.set_data_from_slice(&token_layout.to_bytes());
        accounts_db.store_account(&ata_pubkey, updated_ata);

        let ata_address = bs58::encode(&ata_bytes).into_string();
        Ok(MintResult {
            mint: bs58::encode(mint_bytes).into_string(),
            ata: ata_address,
            amount,
            new_supply: mint_layout.supply,
        })
    }

    // ────────────────────────────────────────────────────────────────────────
    // TRANSFER TOKENS — move tokens between two ATAs
    // ────────────────────────────────────────────────────────────────────────

    /// Transfer tokens between two wallet's ATAs.
    ///
    /// Both ATAs must exist (the recipient ATA is created if necessary).
    pub fn transfer_tokens(
        accounts_db: &SvmAccountsDB,
        mint_bytes: &[u8; 32],
        from_wallet: &Pubkey,
        to_wallet: &Pubkey,
        amount: u64,
    ) -> Result<TransferTokenResult, SvmError> {
        if amount == 0 {
            return Err(SvmError::InvalidTransaction("Transfer amount must be > 0".into()));
        }

        // 1. Load sender's ATA
        let from_ata_bytes = derive_ata_address(&from_wallet.to_bytes(), mint_bytes);
        let from_ata_pubkey = Pubkey::new_from_array(from_ata_bytes);

        let from_account = accounts_db
            .get_account(&from_ata_pubkey)
            .ok_or_else(|| SvmError::AccountNotFound(
                format!("Sender token account not found: {}", bs58::encode(&from_ata_bytes).into_string())
            ))?;

        let mut from_layout = TokenAccountLayout::from_bytes(from_account.data())
            .map_err(|e| SvmError::SerializationError(e))?;

        if from_layout.amount < amount {
            return Err(SvmError::InsufficientFunds {
                available: from_layout.amount,
                required: amount,
            });
        }

        // 2. Load or create recipient's ATA
        let to_ata_bytes = derive_ata_address(&to_wallet.to_bytes(), mint_bytes);
        let to_ata_pubkey = Pubkey::new_from_array(to_ata_bytes);

        let to_account = if let Some(existing) = accounts_db.get_account(&to_ata_pubkey) {
            existing
        } else {
            let new_token_account = TokenAccountLayout {
                mint: *mint_bytes,
                owner: to_wallet.to_bytes(),
                amount: 0,
                delegate_option: 0,
                delegate: [0u8; 32],
                state: 1,
                is_native_option: 0,
                is_native: 0,
                delegated_amount: 0,
                close_authority_option: 0,
                close_authority: [0u8; 32],
            };
            AccountSharedData::from(Account {
                lamports: 1_000_000_000,
                data: new_token_account.to_bytes(),
                owner: Pubkey::new_from_array(SPL_TOKEN_PROGRAM_ID),
                executable: false,
                rent_epoch: RENT_EPOCH_EXEMPT,
            })
        };

        let mut to_layout = TokenAccountLayout::from_bytes(to_account.data())
            .map_err(|e| SvmError::SerializationError(e))?;

        // 3. Debit sender, credit recipient
        from_layout.amount = from_layout.amount.checked_sub(amount)
            .ok_or(SvmError::InsufficientFunds { available: from_layout.amount, required: amount })?;
        to_layout.amount = to_layout.amount.checked_add(amount)
            .ok_or(SvmError::LamportOverflow)?;

        // 4. Write both accounts back
        let mut updated_from = from_account;
        updated_from.set_data_from_slice(&from_layout.to_bytes());
        accounts_db.store_account(&from_ata_pubkey, updated_from);

        let mut updated_to = to_account;
        updated_to.set_data_from_slice(&to_layout.to_bytes());
        accounts_db.store_account(&to_ata_pubkey, updated_to);

        Ok(TransferTokenResult {
            from_ata: bs58::encode(&from_ata_bytes).into_string(),
            to_ata: bs58::encode(&to_ata_bytes).into_string(),
            amount,
            from_balance: from_layout.amount,
            to_balance: to_layout.amount,
        })
    }

    // ────────────────────────────────────────────────────────────────────────
    // QUERY — get token balance, supply, all token accounts for owner
    // ────────────────────────────────────────────────────────────────────────

    /// Get the token balance for a wallet's ATA.
    pub fn get_token_balance(
        accounts_db: &SvmAccountsDB,
        mint_bytes: &[u8; 32],
        wallet_pubkey: &Pubkey,
    ) -> u64 {
        let ata_bytes = derive_ata_address(&wallet_pubkey.to_bytes(), mint_bytes);
        let ata_pubkey = Pubkey::new_from_array(ata_bytes);

        accounts_db.get_account(&ata_pubkey)
            .and_then(|acct| {
                TokenAccountLayout::from_bytes(acct.data()).ok()
            })
            .map(|layout| layout.amount)
            .unwrap_or(0)
    }

    /// Get the current total supply of a mint.
    pub fn get_mint_supply(
        accounts_db: &SvmAccountsDB,
        mint_bytes: &[u8; 32],
    ) -> Result<u64, SvmError> {
        let mint_pubkey = Pubkey::new_from_array(*mint_bytes);
        let mint_account = accounts_db
            .get_account(&mint_pubkey)
            .ok_or_else(|| SvmError::AccountNotFound("Mint not found".into()))?;

        let layout = MintLayout::from_bytes(mint_account.data())
            .map_err(|e| SvmError::SerializationError(e))?;

        Ok(layout.supply)
    }

    /// Get all token accounts owned by a wallet for a specific mint.
    ///
    /// Returns the ATA address and balance. Used by `getTokenAccountsByOwner`.
    pub fn get_token_accounts_for_owner(
        accounts_db: &SvmAccountsDB,
        mint_bytes: &[u8; 32],
        wallet_pubkey: &Pubkey,
    ) -> Vec<TokenAccountInfo> {
        let ata_bytes = derive_ata_address(&wallet_pubkey.to_bytes(), mint_bytes);
        let ata_pubkey = Pubkey::new_from_array(ata_bytes);

        match accounts_db.get_account(&ata_pubkey) {
            Some(acct) if acct.data().len() == 165 => {
                if let Ok(layout) = TokenAccountLayout::from_bytes(acct.data()) {
                    vec![TokenAccountInfo {
                        address: bs58::encode(&ata_bytes).into_string(),
                        mint: bs58::encode(&layout.mint).into_string(),
                        owner: bs58::encode(&layout.owner).into_string(),
                        amount: layout.amount,
                        decimals: USDC_DECIMALS,
                        raw_data: acct.data().to_vec(),
                    }]
                } else {
                    vec![]
                }
            }
            _ => vec![],
        }
    }
}

// ============================================================================
// RESULT TYPES
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub struct MintResult {
    pub mint: String,
    pub ata: String,
    pub amount: u64,
    pub new_supply: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransferTokenResult {
    pub from_ata: String,
    pub to_ata: String,
    pub amount: u64,
    pub from_balance: u64,
    pub to_balance: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenAccountInfo {
    pub address: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
    pub decimals: u8,
    #[serde(skip)]
    pub raw_data: Vec<u8>,
}
