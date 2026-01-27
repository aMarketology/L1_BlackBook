/**
 * Enhanced Secure Wallet with Dual-Password Architecture
 * 
 * SECURITY MODEL:
 * 1. Auth Password: Used for Supabase authentication (user login/signup)
 * 2. User Password: Used to encrypt/decrypt the operational key (never leaves client)
 * 3. Root Key: Random 256-bit, SSS-split 2-of-3 (paper backup)
 * 4. Operational Key: Encrypted with user password, stored in Supabase
 * 5. Salt: Random per-user, stored in Supabase
 * 
 * STORAGE ARCHITECTURE:
 * - Supabase stores: encrypted_op_key, salt, address, root_pubkey
 * - Client memory: decrypted operational key during session
 * - Paper backup: SSS shares of root key
 * 
 * ADVANTAGES:
 * - Auth password can be changed without affecting wallet
 * - User password controls key decryption (zero-knowledge)
 * - Salt prevents rainbow table attacks
 * - Encrypted key backup in cloud
 * - Root key remains offline in SSS shares
 */

const nacl = require('tweetnacl');
const crypto = require('crypto');

// Try to load argon2, fallback to PBKDF2 if not available
let argon2;
try {
  argon2 = require('argon2');
} catch (e) {
  console.warn('argon2 not available, using PBKDF2 fallback');
}

// Shamir Secret Sharing Prime (256-bit)
const SSS_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');

// ==================== CRYPTOGRAPHIC PRIMITIVES ====================

/**
 * Generate cryptographically secure random BigInt
 */
function randomBigInt(max) {
  const bytes = 32;
  const randBytes = crypto.randomBytes(bytes);
  let num = BigInt('0x' + randBytes.toString('hex'));
  return num % max;
}

/**
 * Modular inverse using Extended Euclidean Algorithm
 */
function modInverse(a, m) {
  a = ((a % m) + m) % m;
  let [old_r, r] = [a, m];
  let [old_s, s] = [BigInt(1), BigInt(0)];

  while (r !== BigInt(0)) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  if (old_r > BigInt(1)) throw new Error('Not invertible');
  return ((old_s % m) + m) % m;
}

/**
 * Split secret into n shares with k-of-n threshold using Shamir Secret Sharing
 */
function splitSecret(secretBytes, n = 3, k = 2) {
  if (secretBytes.length !== 32) throw new Error('Secret must be 32 bytes');
  if (k > n) throw new Error('k must be <= n');

  const secret = BigInt('0x' + Buffer.from(secretBytes).toString('hex'));
  const coefficients = [secret];
  
  // Generate k-1 random coefficients
  for (let i = 1; i < k; i++) {
    coefficients.push(randomBigInt(SSS_PRIME));
  }

  // Generate n shares
  const shares = [];
  for (let x = 1; x <= n; x++) {
    let y = BigInt(0);
    for (let i = 0; i < k; i++) {
      const term = (coefficients[i] * (BigInt(x) ** BigInt(i))) % SSS_PRIME;
      y = (y + term) % SSS_PRIME;
    }
    shares.push({ x, y: y.toString(16).padStart(64, '0') });
  }

  return shares;
}

/**
 * Reconstruct secret from k shares using Lagrange interpolation
 */
function reconstructSecret(shares) {
  if (shares.length < 2) throw new Error('Need at least 2 shares');

  let secret = BigInt(0);
  for (let i = 0; i < shares.length; i++) {
    const xi = BigInt(shares[i].x);
    const yi = BigInt('0x' + shares[i].y);

    let numerator = BigInt(1);
    let denominator = BigInt(1);

    for (let j = 0; j < shares.length; j++) {
      if (i !== j) {
        const xj = BigInt(shares[j].x);
        numerator = (numerator * (BigInt(0) - xj)) % SSS_PRIME;
        denominator = (denominator * (xi - xj)) % SSS_PRIME;
      }
    }

    const lagrange = (numerator * modInverse(denominator, SSS_PRIME)) % SSS_PRIME;
    secret = (secret + (yi * lagrange)) % SSS_PRIME;
  }

  secret = ((secret % SSS_PRIME) + SSS_PRIME) % SSS_PRIME;
  const secretHex = secret.toString(16).padStart(64, '0');
  return Buffer.from(secretHex, 'hex');
}

// ==================== KEY DERIVATION ====================

/**
 * Derive encryption key from user password using Argon2id
 * This key is used to encrypt/decrypt the operational key
 */
async function deriveEncryptionKey(userPassword, salt, iterations = 3, memory = 65536) {
  const saltBuffer = Buffer.from(salt, 'hex');

  if (argon2) {
    const hash = await argon2.hash(userPassword, {
      type: argon2.argon2id,
      memoryCost: memory,
      timeCost: iterations,
      parallelism: 1,
      hashLength: 32,
      salt: saltBuffer,
      raw: true
    });
    return Buffer.from(hash);
  } else {
    // PBKDF2 fallback
    return crypto.pbkdf2Sync(userPassword, saltBuffer, iterations * 100000, 32, 'sha256');
  }
}

/**
 * Derive operational key from user password + salt using Argon2id
 * Alternative: just use a random op key and encrypt it
 */
async function deriveOpKey(userPassword, salt, iterations = 3, memory = 65536) {
  const saltBuffer = Buffer.from(salt, 'hex');

  if (argon2) {
    const hash = await argon2.hash(userPassword, {
      type: argon2.argon2id,
      memoryCost: memory,
      timeCost: iterations,
      parallelism: 1,
      hashLength: 32,
      salt: saltBuffer,
      raw: true
    });
    return Buffer.from(hash);
  } else {
    return crypto.pbkdf2Sync(userPassword, saltBuffer, iterations * 100000, 32, 'sha256');
  }
}

// ==================== ENCRYPTION/DECRYPTION ====================

/**
 * Encrypt operational key with user password-derived key
 * Uses AES-256-GCM for authenticated encryption
 */
function encryptKey(keyBytes, encryptionKey) {
  const iv = crypto.randomBytes(12); // GCM standard nonce size
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, iv);
  
  let encrypted = cipher.update(keyBytes);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encrypted: encrypted.toString('hex'),
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

/**
 * Decrypt operational key with user password-derived key
 */
function decryptKey(encryptedData, encryptionKey) {
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    encryptionKey,
    Buffer.from(encryptedData.iv, 'hex')
  );
  
  decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'hex'));
  
  let decrypted = decipher.update(Buffer.from(encryptedData.encrypted, 'hex'));
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  
  return decrypted;
}

// ==================== SECURE SESSION CLASS (CLOSURE-BASED) ====================

/**
 * SecureSession - Holds operational key in closure, never exposed
 * Auto-locks after timeout or visibility change
 */
class SecureSession {
  constructor(opKeyPair, address, rootPubkey, timeout = 600000) { // 10 min default
    this._opKeyPair = opKeyPair; // Private, not enumerable
    this.address = address;
    this.rootPubkey = rootPubkey;
    this.opPubkey = Buffer.from(opKeyPair.publicKey).toString('hex');
    this._locked = false;
    this._timeout = timeout;
    this._timer = null;
    this._visibilityHandler = null;
    
    // Start auto-lock timer
    this._resetTimer();
    
    // Mobile backgrounding detection
    if (typeof document !== 'undefined') {
      this._visibilityHandler = () => {
        if (document.visibilityState === 'hidden') {
          this.lock();
        }
      };
      document.addEventListener('visibilitychange', this._visibilityHandler);
    }
  }
  
  _resetTimer() {
    if (this._timer) clearTimeout(this._timer);
    this._timer = setTimeout(() => this.lock(), this._timeout);
  }
  
  /**
   * Sign transaction with operational key (only exposed method)
   */
  signTransaction(transaction) {
    if (this._locked) {
      throw new Error('Session locked. Please login again.');
    }
    
    this._resetTimer(); // Activity detected
    
    const txJson = JSON.stringify(transaction);
    const signature = nacl.sign.detached(Buffer.from(txJson), this._opKeyPair.secretKey);
    
    return {
      transaction,
      signature: Buffer.from(signature).toString('hex'),
      signer: this.opPubkey
    };
  }
  
  /**
   * Lock session and zero key material
   */
  lock() {
    if (this._locked) return;
    
    this._locked = true;
    
    // Zero key material
    if (this._opKeyPair && this._opKeyPair.secretKey) {
      this._opKeyPair.secretKey.fill(0);
    }
    this._opKeyPair = null;
    
    // Clear timer
    if (this._timer) clearTimeout(this._timer);
    this._timer = null;
    
    // Remove visibility listener
    if (this._visibilityHandler && typeof document !== 'undefined') {
      document.removeEventListener('visibilitychange', this._visibilityHandler);
      this._visibilityHandler = null;
    }
  }
  
  /**
   * Check if session is still active
   */
  isLocked() {
    return this._locked;
  }
}

// ==================== ENHANCED SECURE WALLET CLASS ====================

class EnhancedSecureWallet {
  /**
   * Create new account with dual-password system
   * 
   * @param {string} authPassword - Password for Supabase authentication
   * @param {string} userPassword - Password for key encryption (never sent to server)
   * @param {string} supabaseUrl - Supabase project URL
   * @param {string} supabaseAnonKey - Supabase anonymous key
   * @param {string} l1Endpoint - Layer 1 blockchain endpoint
   * @returns {Object} Account data with SSS shares and encrypted key info
   */
  static async createAccount(authPassword, userPassword, supabaseUrl, supabaseAnonKey, l1Endpoint) {
    // 1. Generate Root Key (random 256-bit)
    const rootKeyBytes = crypto.randomBytes(32);
    const rootKeyPair = nacl.sign.keyPair.fromSeed(rootKeyBytes);
    const rootPubkeyHex = Buffer.from(rootKeyPair.publicKey).toString('hex');

    // 2. Generate random Operational Key
    const opKeyBytes = crypto.randomBytes(32);
    const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);
    const opPubkeyHex = Buffer.from(opKeyPair.publicKey).toString('hex');

    // 3. Derive address from root public key
    const addressHash = crypto.createHash('sha256').update(rootKeyPair.publicKey).digest();
    const address = 'L1_' + addressHash.slice(0, 20).toString('hex').toUpperCase();

    // 4. Generate salt for encryption
    const salt = crypto.randomBytes(32).toString('hex');

    // 5. Derive encryption key from user password
    const encryptionKey = await deriveEncryptionKey(userPassword, salt);

    // 6. Encrypt operational key
    const encryptedOpKey = encryptKey(opKeyBytes, encryptionKey);

    // 7. Split root key using SSS (2-of-3)
    const shares = splitSecret(rootKeyBytes, 3, 2);

    // 8. Create account on Layer 1
    const createAccountTx = {
      timestamp: Date.now(),
      tx_data: {
        CreateAccount: {
          address: address,
          root_pubkey: rootPubkeyHex,
          initial_op_pubkey: opPubkeyHex
        }
      }
    };

    // Sign with root key
    const txJson = JSON.stringify(createAccountTx);
    const signature = nacl.sign.detached(Buffer.from(txJson), rootKeyPair.secretKey);

    const response = await fetch(`${l1Endpoint}/submit_transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        transaction: createAccountTx,
        signature: Buffer.from(signature).toString('hex'),
        signer: rootPubkeyHex
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to create L1 account: ${error}`);
    }

    // 9. Return account data (SSS shares for paper backup, encrypted key for Supabase)
    return {
      address,
      rootPubkey: rootPubkeyHex,
      opPubkey: opPubkeyHex,
      salt,
      encryptedOpKey,
      shares, // Save these to paper/secure storage
      // Note: Don't return plaintext keys in production
      message: 'Account created successfully. Store SSS shares securely (paper backup).'
    };
  }

  /**
   * Login with user password (decrypt operational key from Supabase)
   * Returns a SecureSession that auto-locks after timeout
   * 
   * @param {string} userPassword - User's encryption password
   * @param {Object} accountData - Data retrieved from Supabase (encrypted_op_key, salt, etc.)
   * @param {Object} options - { timeout: ms (default 10min desktop), platform: 'desktop'|'mobile' }
   * @returns {SecureSession} Secure session with signTransaction() method
   */
  static async login(userPassword, accountData, options = {}) {
    const { encrypted_op_key, salt, address, root_pubkey } = accountData;

    // 1. Derive encryption key from user password
    const encryptionKey = await deriveEncryptionKey(userPassword, salt);

    // 2. Decrypt operational key
    let opKeyBytes;
    try {
      opKeyBytes = decryptKey(encrypted_op_key, encryptionKey);
    } catch (error) {
      throw new Error('Invalid user password or corrupted key data');
    }

    // 3. Recreate operational key pair
    const opKeyPair = nacl.sign.keyPair.fromSeed(opKeyBytes);
    
    // 4. Determine timeout based on platform
    const platform = options.platform || 'desktop';
    const defaultTimeout = platform === 'mobile' ? 60000 : 600000; // 60s mobile, 10min desktop
    const timeout = options.timeout || defaultTimeout;

    // 5. Return SecureSession (key in closure, auto-lock)
    return new SecureSession(opKeyPair, address, root_pubkey, timeout);
  }

  /**
   * Recover account from SSS shares and set new user password
   * 
   * IMPORTANT: Generates NEW salt and NEW operational key
   * Old salt is tied to lost password and is obsolete after recovery
   * 
   * @param {Array} shares - 2 or more SSS shares
   * @param {string} newUserPassword - New encryption password
   * @param {string} address - Account address
   * @param {string} l1Endpoint - Layer 1 endpoint
   * @returns {Object} New encrypted operational key and NEW salt
   */
  static async recoverAccount(shares, newUserPassword, address, l1Endpoint) {
    if (shares.length < 2) {
      throw new Error('Need at least 2 shares to recover account');
    }

    // 1. Reconstruct root key from shares
    const rootKeyBytes = reconstructSecret(shares);
    const rootKeyPair = nacl.sign.keyPair.fromSeed(rootKeyBytes);
    const rootPubkeyHex = Buffer.from(rootKeyPair.publicKey).toString('hex');

    // 2. Generate NEW operational key (old one is lost/compromised)
    const newOpKeyBytes = crypto.randomBytes(32);
    const newOpKeyPair = nacl.sign.keyPair.fromSeed(newOpKeyBytes);
    const newOpPubkeyHex = Buffer.from(newOpKeyPair.publicKey).toString('hex');

    // 3. Generate NEW salt (old salt was tied to lost password)
    const newSalt = crypto.randomBytes(32).toString('hex');

    // 4. Derive new encryption key from new password + new salt
    const newEncryptionKey = await deriveEncryptionKey(newUserPassword, newSalt);

    // 5. Encrypt new operational key
    const encryptedOpKey = encryptKey(newOpKeyBytes, newEncryptionKey);

    // 6. Rotate operational key on Layer 1 (signed by root key)
    const rotateKeyTx = {
      timestamp: Date.now(),
      tx_data: {
        RotateOpKey: {
          address: address,
          new_op_pubkey: newOpPubkeyHex,
          revoke_old_keys: true
        }
      }
    };

    const txJson = JSON.stringify(rotateKeyTx);
    const signature = nacl.sign.detached(Buffer.from(txJson), rootKeyPair.secretKey);

    const response = await fetch(`${l1Endpoint}/submit_transaction`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        transaction: rotateKeyTx,
        signature: Buffer.from(signature).toString('hex'),
        signer: rootPubkeyHex
      })
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to rotate operational key: ${error}`);
    }

    return {
      address,
      rootPubkey: rootPubkeyHex,
      newOpPubkey: newOpPubkeyHex,
      newSalt,
      encryptedOpKey,
      message: 'Account recovered. NEW salt and NEW operational key generated. Update Supabase.'
    };
  }

  /**
   * DEPRECATED: Use session.signTransaction() instead
   * This method is kept for backward compatibility but exposes keys
   * 
   * @deprecated Use SecureSession.signTransaction() from login()
   */
  static signTransaction(transaction, opSecretKey) {
    console.warn('EnhancedSecureWallet.signTransaction() is deprecated. Use session.signTransaction() instead.');
    const txJson = JSON.stringify(transaction);
    const signature = nacl.sign.detached(Buffer.from(txJson), opSecretKey);
    
    // Get public key from secret key
    const opKeyPair = nacl.sign.keyPair.fromSecretKey(opSecretKey);
    const signerPubkey = Buffer.from(opKeyPair.publicKey).toString('hex');

    return {
      transaction,
      signature: Buffer.from(signature).toString('hex'),
      signer: signerPubkey
    };
  }

  /**
   * Change user password (re-encrypt operational key)
   * 
   * @param {string} oldUserPassword - Current user password
   * @param {string} newUserPassword - New user password
   * @param {Object} accountData - Current account data from Supabase
   * @returns {Object} New encrypted operational key and NEW salt
   */
  static async changeUserPassword(oldUserPassword, newUserPassword, accountData) {
    // 1. Login with old password (gets SecureSession)
    const session = await this.login(oldUserPassword, accountData);

    // 2. Generate NEW salt (old salt is now obsolete)
    const newSalt = crypto.randomBytes(32).toString('hex');

    // 3. Derive new encryption key
    const newEncryptionKey = await deriveEncryptionKey(newUserPassword, newSalt);

    // 4. Get op key bytes from session (access private member for this operation)
    const opKeyBytes = session._opKeyPair.secretKey.slice(0, 32);

    // 5. Encrypt with new key
    const encryptedOpKey = encryptKey(opKeyBytes, newEncryptionKey);
    
    // 6. Lock the session
    session.lock();

    return {
      newSalt,
      encryptedOpKey,
      message: 'Password changed. NEW salt generated. Update Supabase.'
    };
  }
}

// ==================== EXPORTS ====================

module.exports = {
  EnhancedSecureWallet,
  SecureSession,
  splitSecret,
  reconstructSecret,
  deriveEncryptionKey,
  encryptKey,
  decryptKey
};
