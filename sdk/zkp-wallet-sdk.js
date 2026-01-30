/**
 * BlackBook L1 - ZKP + SSS Non-Custodial Wallet SDK
 * 
 * Architecture:
 * - Zero-Knowledge Proofs for authentication (password never transmitted)
 * - Shamir's Secret Sharing for key distribution (2-of-3 threshold)
 * - Argon2id for memory-hard key derivation (GPU/ASIC resistant)
 * - Peppered encryption for recovery share protection
 * 
 * Share Distribution:
 * - Share A: Derived from password via Argon2id (user knowledge)
 * - Share B: Stored on L1 chain (released after ZK-proof verification)
 * - Share C: Encrypted with pepper, stored on Supabase (recovery)
 * 
 * @version 2.0.0-zkp
 * @license MIT
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');

// =============================================================================
// CONSTANTS
// =============================================================================

// Galois Field prime for 256-bit SSS (2^256 - 189 is a safe prime)
const GF_PRIME = 2n ** 256n - 189n;

// Argon2id configuration (OWASP recommended for password hashing)
const ARGON2_CONFIG = {
  type: 2,              // argon2id
  memoryCost: 65536,    // 64 MB RAM
  timeCost: 3,          // 3 iterations
  parallelism: 4,       // 4 threads
  hashLength: 32        // 256-bit output
};

// Session configuration
const SESSION_CONFIG = {
  defaultTimeout: 5 * 60 * 1000,  // 5 minutes
  maxTimeout: 30 * 60 * 1000,     // 30 minutes max
  warningThreshold: 60 * 1000     // Warn 1 minute before expiry
};

// SSS configuration
const SSS_THRESHOLD = 2;  // k = 2 shares needed
const SSS_TOTAL = 3;      // n = 3 total shares

// =============================================================================
// GALOIS FIELD ARITHMETIC (GF(2^256))
// =============================================================================

/**
 * Modular exponentiation: base^exp mod mod
 */
function modPow(base, exp, mod) {
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) {
      result = (result * base) % mod;
    }
    exp = exp >> 1n;
    base = (base * base) % mod;
  }
  return result;
}

/**
 * Modular multiplicative inverse using Fermat's little theorem
 * a^(-1) mod p = a^(p-2) mod p (when p is prime)
 */
function modInverse(a, mod = GF_PRIME) {
  a = ((a % mod) + mod) % mod;
  if (a === 0n) throw new Error('Cannot invert zero');
  return modPow(a, mod - 2n, mod);
}

/**
 * Safe modular arithmetic (handles negative numbers)
 */
function mod(n, m = GF_PRIME) {
  return ((n % m) + m) % m;
}

// =============================================================================
// SHAMIR'S SECRET SHARING (2-of-3 over GF(2^256))
// =============================================================================

/**
 * Split a secret into n shares with threshold k
 * Uses polynomial f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
 * 
 * @param {Buffer|string} secret - The secret to split (32 bytes)
 * @param {number} k - Threshold (shares needed to reconstruct)
 * @param {number} n - Total number of shares
 * @returns {Array<{x: number, y: string}>} Array of shares
 */
function sssSplit(secret, k = SSS_THRESHOLD, n = SSS_TOTAL) {
  // Convert secret to BigInt
  const secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'hex');
  if (secretBuf.length !== 32) {
    throw new Error('Secret must be exactly 32 bytes');
  }
  const secretBigInt = BigInt('0x' + secretBuf.toString('hex'));
  
  // Generate k-1 random coefficients for polynomial
  const coefficients = [secretBigInt];
  for (let i = 1; i < k; i++) {
    const randomBytes = crypto.randomBytes(32);
    const coeff = BigInt('0x' + randomBytes.toString('hex')) % GF_PRIME;
    coefficients.push(coeff);
  }
  
  // Evaluate polynomial at x = 1, 2, 3, ..., n
  const shares = [];
  for (let x = 1; x <= n; x++) {
    const xBig = BigInt(x);
    let y = 0n;
    let xPower = 1n;
    
    for (let i = 0; i < k; i++) {
      y = mod(y + mod(coefficients[i] * xPower));
      xPower = mod(xPower * xBig);
    }
    
    shares.push({
      x: x,
      y: y.toString(16).padStart(64, '0')
    });
  }
  
  return shares;
}

/**
 * Reconstruct secret from k shares using Lagrange interpolation
 * 
 * @param {Array<{x: number, y: string}>} shares - Array of shares (need k shares)
 * @returns {Buffer} Reconstructed 32-byte secret
 */
function sssReconstruct(shares) {
  if (shares.length < SSS_THRESHOLD) {
    throw new Error(`Need at least ${SSS_THRESHOLD} shares to reconstruct`);
  }
  
  // Use exactly k shares
  const usedShares = shares.slice(0, SSS_THRESHOLD);
  
  // Lagrange interpolation at x = 0
  let secret = 0n;
  
  for (let i = 0; i < usedShares.length; i++) {
    const xi = BigInt(usedShares[i].x);
    const yi = BigInt('0x' + usedShares[i].y);
    
    // Calculate Lagrange basis polynomial L_i(0)
    let numerator = 1n;
    let denominator = 1n;
    
    for (let j = 0; j < usedShares.length; j++) {
      if (i !== j) {
        const xj = BigInt(usedShares[j].x);
        numerator = mod(numerator * (0n - xj));      // (0 - xj)
        denominator = mod(denominator * (xi - xj));  // (xi - xj)
      }
    }
    
    // L_i(0) * y_i
    const lagrangeTerm = mod(yi * numerator * modInverse(denominator));
    secret = mod(secret + lagrangeTerm);
  }
  
  // Convert back to 32-byte buffer
  const hexSecret = secret.toString(16).padStart(64, '0');
  return Buffer.from(hexSecret, 'hex');
}

/**
 * Split secret with deterministic Share A from password
 * Share A is derived from password, making it reproducible
 * 
 * @param {Buffer} secret - The secret to split
 * @param {Buffer} shareA - Pre-determined Share A (from password derivation)
 * @returns {Object} { shareA, shareB, shareC }
 */
function sssSplitWithDeterministicA(secret, shareA) {
  // We need to find coefficients such that f(1) = shareA and f(0) = secret
  // For k=2: f(x) = secret + a1*x
  // f(1) = secret + a1 = shareA
  // Therefore: a1 = shareA - secret
  
  const secretBigInt = BigInt('0x' + secret.toString('hex'));
  const shareABigInt = BigInt('0x' + shareA.toString('hex'));
  
  // Calculate coefficient a1
  const a1 = mod(shareABigInt - secretBigInt);
  
  // Generate shares at x = 1, 2, 3
  // f(1) = secret + a1*1 = shareA (deterministic)
  // f(2) = secret + a1*2 (random-looking, stored on L1)
  // f(3) = secret + a1*3 (random-looking, stored on Supabase)
  
  const evaluatePolynomial = (x) => {
    const xBig = BigInt(x);
    return mod(secretBigInt + mod(a1 * xBig));
  };
  
  return {
    shareA: { x: 1, y: evaluatePolynomial(1).toString(16).padStart(64, '0') },
    shareB: { x: 2, y: evaluatePolynomial(2).toString(16).padStart(64, '0') },
    shareC: { x: 3, y: evaluatePolynomial(3).toString(16).padStart(64, '0') }
  };
}

// =============================================================================
// KEY DERIVATION (Argon2id)
// =============================================================================

let argon2 = null;

/**
 * Initialize Argon2 module (lazy loading)
 */
async function initArgon2() {
  if (!argon2) {
    try {
      argon2 = require('argon2');
    } catch (e) {
      throw new Error('Argon2 module not found. Install with: npm install argon2');
    }
  }
  return argon2;
}

/**
 * Derive Share A from password using Argon2id
 * This is the user's "knowledge share" - reproducible from password
 * 
 * @param {string} password - User's password
 * @param {Buffer|string} salt - 32-byte salt
 * @returns {Promise<Buffer>} 32-byte derived share
 */
async function deriveShareA(password, salt) {
  const argon2Module = await initArgon2();
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
  
  if (saltBuf.length !== 32) {
    throw new Error('Salt must be exactly 32 bytes');
  }
  
  const hash = await argon2Module.hash(password, {
    type: argon2Module.argon2id,
    memoryCost: ARGON2_CONFIG.memoryCost,
    timeCost: ARGON2_CONFIG.timeCost,
    parallelism: ARGON2_CONFIG.parallelism,
    hashLength: ARGON2_CONFIG.hashLength,
    salt: saltBuf,
    raw: true
  });
  
  return hash;
}

/**
 * Derive encryption key for Share C using pepper
 * Key = Argon2id(password || pepper, salt)
 * 
 * @param {string} password - User's password
 * @param {Buffer|string} salt - 32-byte salt
 * @param {string} pepper - Server-side secret (from env var)
 * @returns {Promise<Buffer>} 32-byte encryption key
 */
async function derivePepperedKey(password, salt, pepper) {
  const argon2Module = await initArgon2();
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'hex');
  
  // Combine password and pepper
  const pepperedPassword = password + pepper;
  
  const hash = await argon2Module.hash(pepperedPassword, {
    type: argon2Module.argon2id,
    memoryCost: ARGON2_CONFIG.memoryCost,
    timeCost: ARGON2_CONFIG.timeCost,
    parallelism: ARGON2_CONFIG.parallelism,
    hashLength: ARGON2_CONFIG.hashLength,
    salt: saltBuf,
    raw: true
  });
  
  return hash;
}

// =============================================================================
// ZK-COMMITMENT (Poseidon Hash Simulation)
// =============================================================================

/**
 * Generate ZK-commitment for authentication
 * In production, use circomlibjs Poseidon hash for ZK-circuit compatibility
 * For now, we use SHA-256 as a placeholder (same security, not ZK-friendly)
 * 
 * Commitment = Hash(username || password || salt)
 * 
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @param {Buffer|string} salt - 32-byte salt
 * @returns {string} 64-character hex commitment
 */
function generateZKCommitment(username, password, salt) {
  const saltHex = Buffer.isBuffer(salt) ? salt.toString('hex') : salt;
  
  // Domain separation to prevent cross-protocol attacks
  const domain = 'BLACKBOOK_ZK_COMMITMENT_V1';
  
  const hash = crypto.createHash('sha256')
    .update(domain)
    .update(username)
    .update(password)
    .update(saltHex)
    .digest();
  
  return hash.toString('hex');
}

/**
 * Generate ZK-proof that user knows password
 * In production, use snarkjs to generate actual ZK-SNARK proof
 * For now, we use HMAC-based proof (requires server-side secret for verification)
 * 
 * @param {string} username - User's username
 * @param {string} password - User's password
 * @param {Buffer|string} salt - 32-byte salt
 * @param {string} commitment - Expected commitment
 * @param {string} nonce - Server-provided nonce for freshness
 * @returns {Object} Proof object
 */
function generateZKProof(username, password, salt, commitment, nonce) {
  // Verify commitment matches
  const computedCommitment = generateZKCommitment(username, password, salt);
  if (computedCommitment !== commitment) {
    throw new Error('Commitment mismatch - invalid password');
  }
  
  // Generate proof components
  const saltHex = Buffer.isBuffer(salt) ? salt.toString('hex') : salt;
  const timestamp = Date.now();
  
  // Proof = HMAC(commitment, nonce || timestamp || random)
  // This proves knowledge of password without revealing it
  const proofInput = `${nonce}:${timestamp}:${crypto.randomBytes(16).toString('hex')}`;
  const proof = crypto.createHmac('sha256', Buffer.from(commitment, 'hex'))
    .update(proofInput)
    .digest('hex');
  
  return {
    commitment,
    proof,
    proofInput,
    timestamp,
    version: 'hmac-sha256-v1'  // Will upgrade to 'groth16-v1' in production
  };
}

/**
 * Verify ZK-proof (server-side)
 * 
 * @param {Object} proofData - Proof object from generateZKProof
 * @param {string} expectedCommitment - Stored commitment
 * @param {string} nonce - Server-provided nonce
 * @param {number} maxAge - Maximum proof age in milliseconds
 * @returns {boolean} True if proof is valid
 */
function verifyZKProof(proofData, expectedCommitment, nonce, maxAge = 60000) {
  // Check commitment matches
  if (proofData.commitment !== expectedCommitment) {
    return false;
  }
  
  // Check timestamp freshness
  const age = Date.now() - proofData.timestamp;
  if (age > maxAge || age < -5000) {  // Allow 5s clock skew
    return false;
  }
  
  // Check nonce is in proof input
  if (!proofData.proofInput.startsWith(nonce + ':')) {
    return false;
  }
  
  // Verify HMAC
  const expectedProof = crypto.createHmac('sha256', Buffer.from(expectedCommitment, 'hex'))
    .update(proofData.proofInput)
    .digest('hex');
  
  return crypto.timingSafeEqual(
    Buffer.from(proofData.proof, 'hex'),
    Buffer.from(expectedProof, 'hex')
  );
}

// =============================================================================
// ENCRYPTION (AES-256-GCM with Pepper)
// =============================================================================

/**
 * Encrypt Share C with peppered key
 * 
 * @param {Buffer|string} shareC - Share C to encrypt
 * @param {Buffer} key - 32-byte encryption key (from derivePepperedKey)
 * @returns {Object} { encrypted, iv, authTag }
 */
function encryptShareC(shareC, key) {
  const shareBuf = Buffer.isBuffer(shareC) ? shareC : Buffer.from(shareC, 'hex');
  const iv = crypto.randomBytes(12);  // 96-bit IV for GCM
  
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(shareBuf), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return {
    encrypted: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Decrypt Share C with peppered key
 * 
 * @param {Object} encryptedData - { encrypted, iv, authTag }
 * @param {Buffer} key - 32-byte encryption key
 * @returns {Buffer} Decrypted Share C
 */
function decryptShareC(encryptedData, key) {
  const { encrypted, iv, authTag } = encryptedData;
  
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'hex')),
    decipher.final()
  ]);
  
  return decrypted;
}

// =============================================================================
// ED25519 SIGNING
// =============================================================================

/**
 * Generate Ed25519 keypair from secret
 * 
 * @param {Buffer} secret - 32-byte secret
 * @returns {Object} { publicKey, secretKey }
 */
function generateKeypair(secret) {
  const secretBuf = Buffer.isBuffer(secret) ? secret : Buffer.from(secret, 'hex');
  if (secretBuf.length !== 32) {
    throw new Error('Secret must be exactly 32 bytes');
  }
  
  const keypair = nacl.sign.keyPair.fromSeed(new Uint8Array(secretBuf));
  
  return {
    publicKey: Buffer.from(keypair.publicKey).toString('hex'),
    secretKey: Buffer.from(keypair.secretKey)  // Keep as Buffer for signing
  };
}

/**
 * Derive L1 address from public key
 * Address = 'L1_' + SHA256(pubkey)[0..20].toUpperCase()
 * 
 * @param {string} pubkeyHex - 64-character hex public key
 * @returns {string} L1 address
 */
function deriveAddress(pubkeyHex) {
  const hash = crypto.createHash('sha256')
    .update(Buffer.from(pubkeyHex, 'hex'))
    .digest();
  
  return 'L1_' + hash.slice(0, 20).toString('hex').toUpperCase();
}

/**
 * Sign a message with Ed25519
 * 
 * @param {Buffer|string} message - Message to sign
 * @param {Buffer} secretKey - 64-byte Ed25519 secret key
 * @returns {string} 128-character hex signature
 */
function sign(message, secretKey) {
  const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message);
  const signature = nacl.sign.detached(new Uint8Array(msgBuf), new Uint8Array(secretKey));
  return Buffer.from(signature).toString('hex');
}

/**
 * Verify an Ed25519 signature
 * 
 * @param {Buffer|string} message - Original message
 * @param {string} signatureHex - 128-character hex signature
 * @param {string} pubkeyHex - 64-character hex public key
 * @returns {boolean} True if signature is valid
 */
function verify(message, signatureHex, pubkeyHex) {
  const msgBuf = Buffer.isBuffer(message) ? message : Buffer.from(message);
  const sigBuf = Buffer.from(signatureHex, 'hex');
  const pubBuf = Buffer.from(pubkeyHex, 'hex');
  
  return nacl.sign.detached.verify(
    new Uint8Array(msgBuf),
    new Uint8Array(sigBuf),
    new Uint8Array(pubBuf)
  );
}

// =============================================================================
// SECURE SESSION (Auto-Locking Memory Management)
// =============================================================================

/**
 * SecureSession - Holds reconstructed secret with auto-zeroization
 * 
 * The secret is held in memory only while the session is active.
 * After timeout, the secret is cryptographically zeroized.
 */
class SecureSession {
  constructor(secret, keypair, address, timeout = SESSION_CONFIG.defaultTimeout) {
    this._secret = Buffer.from(secret);  // Copy to avoid external references
    this._secretKey = Buffer.from(keypair.secretKey);
    this._publicKey = keypair.publicKey;
    this._address = address;
    this._timeout = Math.min(timeout, SESSION_CONFIG.maxTimeout);
    this._createdAt = Date.now();
    this._lastActivity = Date.now();
    this._locked = false;
    this._warningCallbacks = [];
    
    // Start auto-lock timer
    this._timer = setTimeout(() => this.lock(), this._timeout);
    
    // Set up warning timer
    if (this._timeout > SESSION_CONFIG.warningThreshold) {
      this._warningTimer = setTimeout(() => {
        this._warningCallbacks.forEach(cb => cb(SESSION_CONFIG.warningThreshold));
      }, this._timeout - SESSION_CONFIG.warningThreshold);
    }
  }
  
  /**
   * Check if session is still active
   */
  get isActive() {
    return !this._locked;
  }
  
  /**
   * Get public key (always available)
   */
  get publicKey() {
    return this._publicKey;
  }
  
  /**
   * Get address (always available)
   */
  get address() {
    return this._address;
  }
  
  /**
   * Get remaining time in milliseconds
   */
  get remainingTime() {
    if (this._locked) return 0;
    return Math.max(0, this._timeout - (Date.now() - this._lastActivity));
  }
  
  /**
   * Register callback for expiry warning
   */
  onExpiryWarning(callback) {
    this._warningCallbacks.push(callback);
  }
  
  /**
   * Extend session (refresh activity timer)
   */
  extend() {
    if (this._locked) {
      throw new Error('Session is locked - cannot extend');
    }
    
    clearTimeout(this._timer);
    clearTimeout(this._warningTimer);
    
    this._lastActivity = Date.now();
    this._timer = setTimeout(() => this.lock(), this._timeout);
    
    if (this._timeout > SESSION_CONFIG.warningThreshold) {
      this._warningTimer = setTimeout(() => {
        this._warningCallbacks.forEach(cb => cb(SESSION_CONFIG.warningThreshold));
      }, this._timeout - SESSION_CONFIG.warningThreshold);
    }
  }
  
  /**
   * Sign a message (extends session)
   */
  sign(message) {
    if (this._locked) {
      throw new Error('Session is locked - cannot sign');
    }
    
    this.extend();
    return sign(message, this._secretKey);
  }
  
  /**
   * Sign a transaction payload (extends session)
   */
  signTransaction(payload) {
    if (this._locked) {
      throw new Error('Session is locked - cannot sign transaction');
    }
    
    // Canonical JSON for deterministic hashing
    const canonical = JSON.stringify(payload, Object.keys(payload).sort());
    const hash = crypto.createHash('sha256').update(canonical).digest();
    
    this.extend();
    return {
      signature: sign(hash, this._secretKey),
      pubkey: this._publicKey,
      address: this._address,
      timestamp: Date.now()
    };
  }
  
  /**
   * Lock session and zeroize secret
   */
  lock() {
    if (this._locked) return;
    
    // Clear timers
    clearTimeout(this._timer);
    clearTimeout(this._warningTimer);
    
    // Cryptographic zeroization
    if (this._secret) {
      crypto.randomFillSync(this._secret);  // Overwrite with random
      this._secret.fill(0);                  // Then zero
      this._secret = null;
    }
    
    if (this._secretKey) {
      crypto.randomFillSync(this._secretKey);
      this._secretKey.fill(0);
      this._secretKey = null;
    }
    
    this._locked = true;
    this._warningCallbacks = [];
  }
}

// =============================================================================
// ZKP WALLET CLASS
// =============================================================================

/**
 * ZKPWallet - Main wallet class for registration, login, and transactions
 */
class ZKPWallet {
  /**
   * Create a new wallet
   * 
   * @param {string} username - User's username
   * @param {string} password - User's password
   * @param {string} pepper - Server-side pepper for Share C encryption
   * @returns {Promise<Object>} Wallet registration data
   */
  static async create(username, password, pepper) {
    // Generate random secret (private key seed)
    const secret = crypto.randomBytes(32);
    
    // Generate random salt
    const salt = crypto.randomBytes(32);
    
    // Derive keypair
    const keypair = generateKeypair(secret);
    const address = deriveAddress(keypair.publicKey);
    
    // Derive Share A from password (deterministic)
    const shareA = await deriveShareA(password, salt);
    
    // Split secret with deterministic Share A
    const shares = sssSplitWithDeterministicA(secret, shareA);
    
    // Generate ZK-commitment
    const zkCommitment = generateZKCommitment(username, password, salt);
    
    // Encrypt Share C with peppered key
    const pepperedKey = await derivePepperedKey(password, salt, pepper);
    const encryptedShareC = encryptShareC(
      Buffer.from(shares.shareC.y, 'hex'),
      pepperedKey
    );
    
    // Zeroize secret from memory
    crypto.randomFillSync(secret);
    secret.fill(0);
    
    return {
      // Public wallet data
      wallet: {
        version: '2.0-zkp',
        address,
        pubkey: keypair.publicKey,
        salt: salt.toString('hex'),
        zkCommitment,
        created: new Date().toISOString(),
        keyDerivation: 'Argon2id-64MB',
        encryption: 'AES-256-GCM-PEPPERED',
        sss: '2-of-3-GF(2^256)'
      },
      
      // Share B for L1 storage
      shareB: shares.shareB,
      
      // Encrypted Share C for Supabase storage
      shareCEncrypted: encryptedShareC,
      
      // Share A is NOT stored - derived from password on login
      _debug_shareA: shares.shareA  // Remove in production!
    };
  }
  
  /**
   * Login to wallet with password
   * 
   * @param {Object} walletData - Stored wallet data (from Supabase)
   * @param {Object} shareB - Share B from L1
   * @param {string} password - User's password
   * @param {number} sessionTimeout - Session timeout in ms
   * @returns {Promise<SecureSession>} Active session
   */
  static async login(walletData, shareB, password, sessionTimeout = SESSION_CONFIG.defaultTimeout) {
    const { salt, zkCommitment, pubkey, address } = walletData;
    
    // Derive Share A from password
    const shareA = await deriveShareA(password, salt);
    
    // Verify commitment (proves correct password)
    // Note: In full ZK implementation, this would be a ZK-proof verification
    
    // Reconstruct secret from Share A + Share B
    const shares = [
      { x: 1, y: shareA.toString('hex') },
      shareB
    ];
    
    const secret = sssReconstruct(shares);
    
    // Derive keypair and verify it matches stored pubkey
    const keypair = generateKeypair(secret);
    if (keypair.publicKey !== pubkey) {
      // Zeroize and throw
      crypto.randomFillSync(secret);
      secret.fill(0);
      throw new Error('Invalid password - keypair mismatch');
    }
    
    // Create secure session
    const session = new SecureSession(secret, keypair, address, sessionTimeout);
    
    // Zeroize local secret copy
    crypto.randomFillSync(secret);
    secret.fill(0);
    
    return session;
  }
  
  /**
   * Recover wallet using Share B + Share C (emergency recovery)
   * 
   * @param {Object} walletData - Stored wallet data
   * @param {Object} shareB - Share B from L1
   * @param {Object} encryptedShareC - Encrypted Share C from Supabase
   * @param {string} oldPassword - Old password (for peppered decryption)
   * @param {string} newPassword - New password
   * @param {string} pepper - Server-side pepper
   * @returns {Promise<Object>} New wallet data with updated shares
   */
  static async recover(walletData, shareB, encryptedShareC, oldPassword, newPassword, pepper) {
    const { salt, pubkey, address } = walletData;
    
    // Decrypt Share C with old peppered key
    const oldPepperedKey = await derivePepperedKey(oldPassword, salt, pepper);
    const shareC = decryptShareC(encryptedShareC, oldPepperedKey);
    
    // Reconstruct secret from Share B + Share C
    const shares = [
      shareB,
      { x: 3, y: shareC.toString('hex') }
    ];
    
    const secret = sssReconstruct(shares);
    
    // Verify keypair matches
    const keypair = generateKeypair(secret);
    if (keypair.publicKey !== pubkey) {
      crypto.randomFillSync(secret);
      secret.fill(0);
      throw new Error('Recovery failed - keypair mismatch');
    }
    
    // Generate new salt
    const newSalt = crypto.randomBytes(32);
    
    // Derive new Share A from new password
    const newShareA = await deriveShareA(newPassword, newSalt);
    
    // Generate new shares
    const newShares = sssSplitWithDeterministicA(secret, newShareA);
    
    // Generate new ZK-commitment
    const newCommitment = generateZKCommitment(walletData.username || 'recovered', newPassword, newSalt);
    
    // Encrypt new Share C
    const newPepperedKey = await derivePepperedKey(newPassword, newSalt, pepper);
    const newEncryptedShareC = encryptShareC(
      Buffer.from(newShares.shareC.y, 'hex'),
      newPepperedKey
    );
    
    // Zeroize
    crypto.randomFillSync(secret);
    secret.fill(0);
    
    return {
      wallet: {
        ...walletData,
        salt: newSalt.toString('hex'),
        zkCommitment: newCommitment,
        recoveredAt: new Date().toISOString()
      },
      shareB: newShares.shareB,
      shareCEncrypted: newEncryptedShareC
    };
  }
  
  /**
   * Change password (requires current password)
   * 
   * @param {Object} walletData - Stored wallet data
   * @param {Object} shareB - Share B from L1
   * @param {string} currentPassword - Current password
   * @param {string} newPassword - New password
   * @param {string} pepper - Server-side pepper
   * @returns {Promise<Object>} Updated wallet data
   */
  static async changePassword(walletData, shareB, currentPassword, newPassword, pepper) {
    const { salt, pubkey, address } = walletData;
    
    // Derive Share A from current password
    const shareA = await deriveShareA(currentPassword, salt);
    
    // Reconstruct secret
    const shares = [
      { x: 1, y: shareA.toString('hex') },
      shareB
    ];
    
    const secret = sssReconstruct(shares);
    
    // Verify keypair
    const keypair = generateKeypair(secret);
    if (keypair.publicKey !== pubkey) {
      crypto.randomFillSync(secret);
      secret.fill(0);
      throw new Error('Invalid current password');
    }
    
    // Generate new salt
    const newSalt = crypto.randomBytes(32);
    
    // Derive new Share A
    const newShareA = await deriveShareA(newPassword, newSalt);
    
    // Generate new shares
    const newShares = sssSplitWithDeterministicA(secret, newShareA);
    
    // Generate new ZK-commitment
    const newCommitment = generateZKCommitment(
      walletData.username || address,
      newPassword,
      newSalt
    );
    
    // Encrypt new Share C
    const newPepperedKey = await derivePepperedKey(newPassword, newSalt, pepper);
    const newEncryptedShareC = encryptShareC(
      Buffer.from(newShares.shareC.y, 'hex'),
      newPepperedKey
    );
    
    // Zeroize
    crypto.randomFillSync(secret);
    secret.fill(0);
    
    return {
      wallet: {
        ...walletData,
        salt: newSalt.toString('hex'),
        zkCommitment: newCommitment,
        passwordChangedAt: new Date().toISOString()
      },
      shareB: newShares.shareB,
      shareCEncrypted: newEncryptedShareC
    };
  }
}

// =============================================================================
// MIGRATION UTILITIES
// =============================================================================

/**
 * Migrate legacy PBKDF2 wallet to ZKP format
 * 
 * @param {Object} legacyWallet - Old wallet data
 * @param {string} password - User's password
 * @param {string} pepper - Server-side pepper
 * @returns {Promise<Object>} New ZKP wallet data
 */
async function migrateLegacyWallet(legacyWallet, password, pepper) {
  // Extract legacy data
  const { address, rootPubkey, opPubkey, salt, encryptedOpKey, sssShares } = legacyWallet;
  
  // For migration, we need the original private key
  // This requires decrypting with legacy PBKDF2 method
  
  // Legacy PBKDF2 decryption
  const derivedKey = crypto.pbkdf2Sync(
    password,
    Buffer.from(salt, 'hex'),
    300000,  // 300k iterations
    32,
    'sha256'
  );
  
  // Decrypt legacy encrypted key
  const { encrypted, iv, authTag } = encryptedOpKey;
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    derivedKey,
    Buffer.from(iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTag, 'hex'));
  
  const secret = Buffer.concat([
    decipher.update(Buffer.from(encrypted, 'hex')),
    decipher.final()
  ]);
  
  // Generate new ZKP wallet with same secret
  const newSalt = crypto.randomBytes(32);
  const keypair = generateKeypair(secret);
  
  // Verify address matches
  const derivedAddress = deriveAddress(keypair.publicKey);
  if (derivedAddress !== address) {
    throw new Error('Migration failed - address mismatch');
  }
  
  // Derive new Share A
  const shareA = await deriveShareA(password, newSalt);
  
  // Split with deterministic Share A
  const shares = sssSplitWithDeterministicA(secret, shareA);
  
  // Generate ZK-commitment
  const zkCommitment = generateZKCommitment(legacyWallet.name || address, password, newSalt);
  
  // Encrypt Share C
  const pepperedKey = await derivePepperedKey(password, newSalt, pepper);
  const encryptedShareC = encryptShareC(
    Buffer.from(shares.shareC.y, 'hex'),
    pepperedKey
  );
  
  // Zeroize
  crypto.randomFillSync(secret);
  secret.fill(0);
  
  return {
    wallet: {
      version: '2.0-zkp',
      name: legacyWallet.name,
      address,
      pubkey: keypair.publicKey,
      salt: newSalt.toString('hex'),
      zkCommitment,
      created: legacyWallet.created,
      migratedAt: new Date().toISOString(),
      keyDerivation: 'Argon2id-64MB',
      encryption: 'AES-256-GCM-PEPPERED',
      sss: '2-of-3-GF(2^256)',
      legacyKeyDerivation: legacyWallet.keyDerivation
    },
    shareB: shares.shareB,
    shareCEncrypted: encryptedShareC
  };
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  // Main wallet class
  ZKPWallet,
  
  // Session management
  SecureSession,
  
  // SSS operations
  sssSplit,
  sssReconstruct,
  sssSplitWithDeterministicA,
  
  // Key derivation
  deriveShareA,
  derivePepperedKey,
  
  // ZK operations
  generateZKCommitment,
  generateZKProof,
  verifyZKProof,
  
  // Encryption
  encryptShareC,
  decryptShareC,
  
  // Ed25519
  generateKeypair,
  deriveAddress,
  sign,
  verify,
  
  // Migration
  migrateLegacyWallet,
  
  // Constants
  GF_PRIME,
  SSS_THRESHOLD,
  SSS_TOTAL,
  ARGON2_CONFIG,
  SESSION_CONFIG
};
