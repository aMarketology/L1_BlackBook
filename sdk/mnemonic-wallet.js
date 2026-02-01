/**
 * BlackBook L1 - Mnemonic Wallet Module
 * 
 * Implements the "Hidden Mnemonic" architecture:
 * - BIP-39 mnemonic generation (24 words / 256-bit entropy)
 * - Shamir's Secret Sharing (2-of-3 threshold)
 * - Password-bound Share A
 * - BIP-44 HD wallet derivation
 * 
 * The mnemonic is NEVER shown to users during normal operation.
 * It can only be exported via the "Export Recovery Phrase" feature.
 * 
 * 24 words provides maximum security (256-bit) and is industry standard
 * for hardware wallets like Ledger and Trezor.
 */

const bip39 = require('bip39');
const hdkey = require('hdkey');
const crypto = require('crypto');
const argon2 = require('argon2');
const secrets = require('secrets.js-grempe');
const nacl = require('tweetnacl');

// ============================================================================
// ENTROPY GENERATION & BIP-39 ENCODING
// ============================================================================

/**
 * Generate 256 bits (32 bytes) of cryptographically secure entropy
 * This will become a 24-word BIP-39 mnemonic (industry standard for hardware wallets)
 * @returns {Buffer} 32 bytes of entropy
 */
function generateEntropy() {
    return crypto.randomBytes(32);
}

/**
 * Convert entropy bytes to 24-word mnemonic
 * @param {Buffer} entropy - 32 bytes of entropy
 * @returns {string} 24 space-separated words
 */
function entropyToMnemonic(entropy) {
    if (entropy.length !== 32) {
        throw new Error('Entropy must be exactly 32 bytes for 24-word mnemonic');
    }
    return bip39.entropyToMnemonic(entropy.toString('hex'));
}

/**
 * Convert 24-word mnemonic back to entropy bytes
 * @param {string} mnemonic - 24 space-separated words
 * @returns {Buffer} 32 bytes of entropy
 */
function mnemonicToEntropy(mnemonic) {
    if (!bip39.validateMnemonic(mnemonic)) {
        throw new Error('Invalid mnemonic phrase');
    }
    const hex = bip39.mnemonicToEntropy(mnemonic);
    return Buffer.from(hex, 'hex');
}

/**
 * Validate that a mnemonic is valid BIP-39
 * @param {string} mnemonic - Words to validate
 * @returns {boolean} True if valid
 */
function validateMnemonic(mnemonic) {
    return bip39.validateMnemonic(mnemonic);
}

// ============================================================================
// SHAMIR'S SECRET SHARING (2-of-3)
// ============================================================================

/**
 * Split entropy into 3 shares using Shamir's Secret Sharing
 * Threshold is 2 - any 2 shares can reconstruct the entropy
 * 
 * @param {Buffer} entropy - 32 bytes of entropy to split (256-bit for 24-word mnemonic)
 * @returns {Object} { shareA, shareB, shareC } - hex strings
 */
function splitEntropy(entropy) {
    // Convert to hex for secrets.js
    const entropyHex = entropy.toString('hex');
    
    // Split into 3 shares with threshold of 2
    // secrets.js uses a different format, we need to pad properly
    const shares = secrets.share(entropyHex, 3, 2);
    
    return {
        shareA: shares[0],  // Will be XOR'd with password hash
        shareB: shares[1],  // Stored on L1 blockchain (ZK-gated)
        shareC: shares[2],  // Encrypted with Vault pepper → Supabase
    };
}

/**
 * Reconstruct entropy from any 2 shares
 * @param {string} share1 - First share (hex string)
 * @param {string} share2 - Second share (hex string)
 * @returns {Buffer} Original 32-byte entropy (256-bit)
 */
function reconstructEntropy(share1, share2) {
    const entropyHex = secrets.combine([share1, share2]);
    return Buffer.from(entropyHex, 'hex');
}

// ============================================================================
// PASSWORD-BOUND SHARE A
// ============================================================================

/**
 * Derive Share A by combining the raw share with password hash
 * This binds Share A to the user's password - can't use it without knowing password
 * 
 * @param {string} password - User's password
 * @param {string} shareARaw - Raw Share A from SSS split (hex)
 * @param {Buffer|string} salt - 32-byte salt for Argon2
 * @returns {Promise<string>} Password-bound Share A (hex)
 */
async function deriveShareA(password, shareARaw, salt) {
    // Ensure salt is a buffer
    const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
    
    // Hash password with Argon2id (memory-hard, GPU-resistant)
    const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 65536,  // 64 MB
        timeCost: 3,        // 3 iterations
        parallelism: 4,     // 4 threads
        raw: true,          // Return raw buffer
        salt: saltBuf,
        hashLength: 32,
    });
    
    // XOR the raw share with password hash
    const shareRawBuf = Buffer.from(shareARaw, 'hex');
    const boundShare = Buffer.alloc(shareRawBuf.length);
    
    for (let i = 0; i < shareRawBuf.length; i++) {
        boundShare[i] = shareRawBuf[i] ^ passwordHash[i % passwordHash.length];
    }
    
    return boundShare.toString('hex');
}

/**
 * Recover raw Share A from password-bound version
 * (Same operation as deriveShareA - XOR is its own inverse)
 * 
 * @param {string} password - User's password
 * @param {string} boundShareA - Password-bound Share A (hex)
 * @param {Buffer|string} salt - 32-byte salt
 * @returns {Promise<string>} Raw Share A (hex)
 */
async function recoverShareA(password, boundShareA, salt) {
    // XOR is its own inverse, so same operation recovers the raw share
    return deriveShareA(password, boundShareA, salt);
}

// ============================================================================
// HD WALLET DERIVATION (BIP-32/44)
// ============================================================================

/**
 * Derive wallet address and keys from mnemonic
 * Uses BIP-44 path: m/44'/60'/0'/0/0 (Ethereum-compatible)
 * 
 * @param {string} mnemonic - 24-word mnemonic
 * @param {string} path - Derivation path (default: Ethereum)
 * @returns {Object} { address, publicKey, privateKey }
 */
function deriveAddressFromMnemonic(mnemonic, path = "m/44'/60'/0'/0/0") {
    // Convert mnemonic to seed (512-bit)
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    
    // Create HD wallet from seed
    const hdWallet = hdkey.fromMasterSeed(seed);
    
    // Derive key at BIP-44 path
    const derivedKey = hdWallet.derive(path);
    
    // Get keys
    const privateKey = derivedKey.privateKey;
    const publicKey = derivedKey.publicKey;
    
    // Create BlackBook L1 address format
    // SHA256 hash of public key, take first 20 bytes, prefix with L1_
    const hash = crypto.createHash('sha256').update(publicKey).digest();
    const address = 'L1_' + hash.slice(0, 20).toString('hex').toUpperCase();
    
    return {
        address,
        publicKey: publicKey.toString('hex'),
        privateKey: privateKey.toString('hex'),
    };
}

/**
 * Derive an Ed25519 keypair from mnemonic (for BlackBook L1 native signing)
 * @param {string} mnemonic - 24-word mnemonic
 * @returns {Object} { address, publicKey, secretKey }
 */
function deriveEd25519FromMnemonic(mnemonic) {
    // Convert mnemonic to seed
    const seed = bip39.mnemonicToSeedSync(mnemonic);
    
    // Use first 32 bytes of seed for Ed25519
    const ed25519Seed = seed.slice(0, 32);
    
    // Generate Ed25519 keypair
    const keypair = nacl.sign.keyPair.fromSeed(ed25519Seed);
    
    // Create address from public key
    const hash = crypto.createHash('sha256').update(Buffer.from(keypair.publicKey)).digest();
    const address = 'L1_' + hash.slice(0, 20).toString('hex').toUpperCase();
    
    return {
        address,
        publicKey: Buffer.from(keypair.publicKey).toString('hex'),
        secretKey: Buffer.from(keypair.secretKey).toString('hex'),
    };
}

// ============================================================================
// WALLET GENERATION (Full Pipeline)
// ============================================================================

/**
 * Generate a complete wallet with hidden mnemonic
 * 
 * The mnemonic is generated but NOT returned to the caller.
 * It can only be recovered later via reconstructMnemonic().
 * 
 * @param {string} password - User's password
 * @returns {Promise<Object>} Wallet data (WITHOUT mnemonic)
 */
async function generateWallet(password) {
    // 1. Generate 256-bit entropy
    const entropy = generateEntropy();
    
    // 2. Convert to 24-word mnemonic (internal only!)
    const mnemonic = entropyToMnemonic(entropy);
    
    // 3. Split entropy into 3 shares
    const { shareA: shareARaw, shareB, shareC } = splitEntropy(entropy);
    
    // 4. Generate salt for password hashing
    const salt = crypto.randomBytes(32);
    
    // 5. Bind Share A to password
    const shareABound = await deriveShareA(password, shareARaw, salt);
    
    // 6. Derive wallet address from mnemonic
    const { address, publicKey } = deriveEd25519FromMnemonic(mnemonic);
    
    // 7. CRITICAL: Clear entropy and mnemonic from memory
    entropy.fill(0);
    // Note: Can't truly clear JS strings, but we don't return mnemonic
    
    return {
        // Public info
        address,
        publicKey,
        
        // Share storage info
        shareARaw,      // Store encrypted or in memory
        shareABound,    // Password-bound version (alternative)
        shareB,         // Store on L1 blockchain (ZK-gated)
        shareC,         // Encrypt with Vault pepper → Supabase
        salt: salt.toString('hex'),
        
        // Metadata
        createdAt: new Date().toISOString(),
        version: '2.0-mnemonic',
    };
}

/**
 * Reconstruct mnemonic from shares (for signing or export)
 * 
 * @param {string} password - User's password
 * @param {string} shareARaw - Raw Share A (or bound share)
 * @param {string} shareB - Share B from L1 blockchain
 * @param {string} salt - Salt for Argon2 (hex)
 * @param {boolean} isShareABound - Whether shareA is password-bound
 * @returns {Promise<string>} 24-word mnemonic
 */
async function reconstructMnemonic(password, shareARaw, shareB, salt, isShareABound = false) {
    let shareA = shareARaw;
    
    // If Share A is password-bound, recover the raw version
    if (isShareABound) {
        shareA = await recoverShareA(password, shareARaw, salt);
    }
    
    // Reconstruct entropy from Share A + Share B
    const entropy = reconstructEntropy(shareA, shareB);
    
    // Convert entropy back to mnemonic
    const mnemonic = entropyToMnemonic(entropy);
    
    return mnemonic;
}

/**
 * Sign a transaction using reconstructed mnemonic
 * 
 * @param {string} password - User's password
 * @param {Object} walletData - { shareARaw, shareB, salt }
 * @param {Object} transaction - { to, amount, nonce }
 * @returns {Promise<Object>} Signed transaction
 */
async function signTransaction(password, walletData, transaction) {
    // 1. Reconstruct mnemonic
    const mnemonic = await reconstructMnemonic(
        password,
        walletData.shareARaw,
        walletData.shareB,
        walletData.salt,
        false
    );
    
    // 2. Derive signing key
    const { address, secretKey } = deriveEd25519FromMnemonic(mnemonic);
    
    // 3. Create transaction message
    const txMessage = JSON.stringify({
        from: address,
        to: transaction.to,
        amount: transaction.amount,
        nonce: transaction.nonce || Date.now(),
        timestamp: Date.now(),
    });
    
    // 4. Sign with Ed25519
    const messageBytes = Buffer.from(txMessage);
    const secretKeyBytes = Buffer.from(secretKey, 'hex');
    const signature = nacl.sign.detached(messageBytes, secretKeyBytes);
    
    // 5. CRITICAL: Clear sensitive data
    secretKeyBytes.fill(0);
    
    return {
        transaction: txMessage,
        signature: Buffer.from(signature).toString('hex'),
        from: address,
    };
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
    // Entropy & Mnemonic
    generateEntropy,
    entropyToMnemonic,
    mnemonicToEntropy,
    validateMnemonic,
    
    // Shamir's Secret Sharing
    splitEntropy,
    reconstructEntropy,
    
    // Password binding
    deriveShareA,
    recoverShareA,
    
    // HD Wallet derivation
    deriveAddressFromMnemonic,
    deriveEd25519FromMnemonic,
    
    // Full wallet operations
    generateWallet,
    reconstructMnemonic,
    signTransaction,
};
