// ============================================================================
// BLACKBOOK UNIFIED WALLET SDK - Full Security Implementation
// ============================================================================
//
// This SDK provides:
// 1. Client-side encrypted wallet vault (AES-256-GCM)
// 2. Argon2id key derivation from password + salt
// 3. Ed25519 signature-based authentication (NO JWT)
// 4. Shamir's Secret Sharing (SSS) for MPC wallets (optional)
// 5. L1/L2 address derivation (SHA256 of public key)
// 6. Domain separation (prevents L1/L2 replay attacks)
// 7. Path binding (prevents cross-endpoint replay attacks)
//
// Security Model:
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  PASSWORD → ARGON2id → ENCRYPTION KEY → AES-GCM → ENCRYPTED BLOB       │
// │                                                                         │
// │  ENCRYPTED BLOB + PASSWORD → PRIVATE KEY → Ed25519 SIGNATURE           │
// │                                                                         │
// │  L1 ADDRESS = "L1_" + SHA256(public_key).slice(0, 40)                  │
// │  L2 ADDRESS = "L2_" + SHA256(public_key).slice(0, 40)                  │
// │                                                                         │
// │  SIGNATURE = sign(chain_id + path + payload + timestamp + nonce)       │
// └─────────────────────────────────────────────────────────────────────────┘

import nacl from 'tweetnacl';
import naclUtil from 'tweetnacl-util';
import { createHash, randomBytes } from 'crypto';

// ============================================================================
// ARGON2 IMPORT - Use argon2-browser for browser compatibility
// ============================================================================

// Try to import argon2 (Node.js) or argon2-browser (browser)
let argon2Module = null;
try {
  // For Node.js environments
  argon2Module = await import('argon2');
} catch {
  try {
    // For browser environments
    argon2Module = await import('argon2-browser');
  } catch {
    console.warn('⚠️ Argon2 not available, falling back to PBKDF2 (LESS SECURE)');
  }
}

// ============================================================================
// CONSTANTS
// ============================================================================

export const CHAIN_ID_L1 = 0x01;  // Layer 1 (Bank/Vault) - Real money
export const CHAIN_ID_L2 = 0x02;  // Layer 2 (Gaming) - Fast bets

export const SALT_LENGTH = 32;    // 32 bytes (256 bits)
export const NONCE_LENGTH = 12;   // 12 bytes for AES-GCM
export const KEY_LENGTH = 32;     // 32 bytes (256 bits)
export const VAULT_VERSION = 1;   // Current vault format version

export const AUTH_CONSTANT = "BLACKBOOK_AUTH_V1";
export const WALLET_CONSTANT = "BLACKBOOK_WALLET_V1";

export const REQUEST_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes

// Argon2 parameters (MUST match server: unified_auth.rs)
export const ARGON2_MEMORY_KIB = 65536;   // 64 MB
export const ARGON2_ITERATIONS = 3;        // Time cost
export const ARGON2_PARALLELISM = 4;       // Lanes

// ============================================================================
// TEST ACCOUNTS (Development Only)
// ============================================================================

export const ACCOUNTS = {
  alice: {
    username: "alice_test",
    email: "alice@blackbook.test",
    publicKey: "c0e349153cbc75e9529b5f1963205cab20253db573ec65e8ff31155dc131bd05",
    privateKey: "37b5e0e7f8a456d3b70ff2c4c5ea8f9e3c2c89c0f0a91e27e4d6f8c3e1a2b4d0",
    address: "L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
    l1_address: "L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
    l2_address: "L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
    l1_balance: 10000,
    l2_balance: 0
  },
  bob: {
    username: "bob_test",
    email: "bob@blackbook.test",
    publicKey: "582420216093fcff65b0eec2ca2c82279db682b076526c341b80d5e2dc5c32b7",
    privateKey: "9f3c7e5a2b8d1f6e4c9a0d7e3b2f8c5e1a4d6f9c2b7e5a1d3f8c6e9b4a7d2f5e",
    address: "L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9",
    l1_address: "L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9",
    l2_address: "L2_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9",
    l1_balance: 5000,
    l2_balance: 0
  },
  dealer: {
    username: "dealer_house",
    email: "dealer@blackbook.internal",
    publicKey: "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a",
    privateKey: "e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae",
    address: "L2_F5C46483E8A28394F5E8687DEADF6BD4E924CED3",
    l1_address: "L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3",
    l2_address: "L2_F5C46483E8A28394F5E8687DEADF6BD4E924CED3",
    l1_balance: 100000,
    l2_balance: 0
  }
};

// ============================================================================
// KEY DERIVATION - Argon2id (Password → Encryption Key)
// ============================================================================

/**
 * Derive encryption key from password using Argon2id
 * This is intentionally slow to prevent brute force attacks
 * 
 * CRITICAL: Parameters MUST match server (unified_auth.rs):
 * - Algorithm: Argon2id
 * - Memory: 65536 KiB (64 MB)
 * - Iterations: 3
 * - Parallelism: 4
 * - Output length: 32 bytes
 * 
 * @param {string} password - User's password
 * @param {Buffer|string} salt - 32-byte salt (hex string or Buffer)
 * @param {string} domain - Domain constant (AUTH_CONSTANT or WALLET_CONSTANT)
 * @returns {Promise<Buffer>} - 32-byte encryption key
 */
export async function deriveKey(password, salt, domain = WALLET_CONSTANT) {
  const saltBuffer = typeof salt === 'string' ? Buffer.from(salt, 'hex') : salt;
  const domainedPassword = domain + password;
  
  // Use Argon2id if available (matches server implementation)
  if (argon2Module) {
    try {
      let result;
      
      // Handle different argon2 module interfaces
      if (argon2Module.hash) {
        // Node.js argon2 module
        result = await argon2Module.hash(domainedPassword, {
          salt: saltBuffer,
          type: argon2Module.argon2id || 2,  // Argon2id
          memoryCost: ARGON2_MEMORY_KIB,
          timeCost: ARGON2_ITERATIONS,
          parallelism: ARGON2_PARALLELISM,
          hashLength: KEY_LENGTH,
          raw: true
        });
        return Buffer.from(result);
      } else if (argon2Module.default?.hash) {
        // argon2-browser module
        result = await argon2Module.default.hash({
          pass: domainedPassword,
          salt: saltBuffer,
          type: argon2Module.default.ArgonType.Argon2id,
          mem: ARGON2_MEMORY_KIB,
          time: ARGON2_ITERATIONS,
          parallelism: ARGON2_PARALLELISM,
          hashLen: KEY_LENGTH
        });
        return Buffer.from(result.hash);
      }
    } catch (err) {
      console.warn('⚠️ Argon2 failed, falling back to PBKDF2:', err.message);
    }
  }
  
  // Fallback to PBKDF2 if Argon2 is not available
  // WARNING: This is less secure than Argon2id
  console.warn('⚠️ Using PBKDF2 fallback - install argon2 for better security');
  const crypto = await import('crypto');
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(domainedPassword, saltBuffer, 100000, KEY_LENGTH, 'sha256', (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

/**
 * Generate a random salt for key derivation
 * @returns {string} - 64 hex characters (32 bytes)
 */
export function generateSalt() {
  return randomBytes(SALT_LENGTH).toString('hex');
}

// ============================================================================
// ENCRYPTED BLOB - Wallet Vault (AES-256-GCM)
// ============================================================================

/**
 * Encrypted wallet vault structure
 * Stored in Supabase, decrypted client-side with password
 * 
 * @typedef {Object} EncryptedBlob
 * @property {number} version - Vault format version (currently 1)
 * @property {string} salt - 64 hex chars (32 bytes)
 * @property {string} nonce - 24 hex chars (12 bytes) for AES-GCM
 * @property {string} ciphertext - Base64 encoded encrypted data
 */

/**
 * Create an encrypted wallet vault
 * 
 * @param {string} privateKeyHex - Ed25519 private key (64 hex chars)
 * @param {string} password - User's password
 * @param {string} [saltHex] - Optional salt (generated if not provided)
 * @returns {Promise<EncryptedBlob>} - Encrypted vault
 */
export async function createEncryptedBlob(privateKeyHex, password, saltHex = null) {
  const salt = saltHex || generateSalt();
  
  // Derive encryption key from password
  const encryptionKey = await deriveKey(password, salt, WALLET_CONSTANT);
  
  // Generate random nonce for AES-GCM
  const nonceBuffer = randomBytes(NONCE_LENGTH);
  
  // Encrypt private key
  const crypto = await import('crypto');
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey, nonceBuffer);
  
  let ciphertext = cipher.update(privateKeyHex, 'utf8', 'base64');
  ciphertext += cipher.final('base64');
  const authTag = cipher.getAuthTag();
  
  // Combine ciphertext + auth tag
  const combined = Buffer.concat([
    Buffer.from(ciphertext, 'base64'),
    authTag
  ]).toString('base64');
  
  return {
    version: VAULT_VERSION,
    salt: salt,
    nonce: nonceBuffer.toString('hex'),
    ciphertext: combined
  };
}

/**
 * Decrypt wallet vault to recover private key
 * 
 * @param {EncryptedBlob} blob - Encrypted vault
 * @param {string} password - User's password
 * @returns {Promise<string>} - Ed25519 private key (64 hex chars)
 */
export async function unlockEncryptedBlob(blob, password) {
  // Derive decryption key
  const decryptionKey = await deriveKey(password, blob.salt, WALLET_CONSTANT);
  
  // Decode ciphertext
  const combinedBuffer = Buffer.from(blob.ciphertext, 'base64');
  const authTag = combinedBuffer.slice(-16);
  const ciphertext = combinedBuffer.slice(0, -16);
  
  // Decrypt
  const crypto = await import('crypto');
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    decryptionKey,
    Buffer.from(blob.nonce, 'hex')
  );
  decipher.setAuthTag(authTag);
  
  let privateKey = decipher.update(ciphertext, null, 'utf8');
  privateKey += decipher.final('utf8');
  
  return privateKey;
}

// ============================================================================
// ADDRESS DERIVATION - SHA256(public_key)
// ============================================================================

/**
 * Derive L1 address from public key
 * Format: "L1_" + SHA256(public_key).slice(0, 40)
 * Total: 43 characters
 * 
 * @param {string} publicKeyHex - Ed25519 public key (64 hex chars)
 * @returns {string} - L1 address
 */
export function deriveL1Address(publicKeyHex) {
  const hash = createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest('hex');
  
  return 'L1_' + hash.slice(0, 40).toUpperCase();
}

/**
 * Derive L2 address from public key
 * Format: "L2_" + SHA256(public_key).slice(0, 40)
 * Total: 43 characters
 * 
 * @param {string} publicKeyHex - Ed25519 public key (64 hex chars)
 * @returns {string} - L2 address
 */
export function deriveL2Address(publicKeyHex) {
  const hash = createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest('hex');
  
  return 'L2_' + hash.slice(0, 40).toUpperCase();
}

/**
 * Strip L1_/L2_ prefix to get base hash
 * @param {string} address - Full address with prefix
 * @returns {string} - Base hash (40 hex chars)
 */
export function stripPrefix(address) {
  if (address.startsWith('L1_') || address.startsWith('L2_')) {
    return address.slice(3);
  }
  return address;
}

// ============================================================================
// SHAMIR'S SECRET SHARING (SSS) - MPC Wallet Support
// ============================================================================

/**
 * Split a secret into N shares where K shares are needed to reconstruct
 * This is a simplified implementation - use 'secrets.js-grempe' in production
 * 
 * @param {string} secretHex - Secret to split (private key)
 * @param {number} totalShares - Total number of shares (N)
 * @param {number} threshold - Minimum shares needed (K)
 * @returns {Array<string>} - Array of share hex strings
 */
export function shamirSplit(secretHex, totalShares = 2, threshold = 2) {
  // TODO: Implement proper Shamir's Secret Sharing
  // For now, return a simple 2-of-2 split (XOR-based)
  
  if (totalShares !== 2 || threshold !== 2) {
    throw new Error('Only 2-of-2 split supported in this demo');
  }
  
  const secretBuffer = Buffer.from(secretHex, 'hex');
  const share1 = randomBytes(secretBuffer.length);
  const share2 = Buffer.alloc(secretBuffer.length);
  
  // share2 = secret XOR share1
  for (let i = 0; i < secretBuffer.length; i++) {
    share2[i] = secretBuffer[i] ^ share1[i];
  }
  
  return [
    share1.toString('hex'),
    share2.toString('hex')
  ];
}

/**
 * Reconstruct secret from K shares
 * 
 * @param {Array<string>} sharesHex - Array of share hex strings
 * @returns {string} - Reconstructed secret (private key)
 */
export function shamirCombine(sharesHex) {
  if (sharesHex.length !== 2) {
    throw new Error('Exactly 2 shares required for reconstruction');
  }
  
  const share1 = Buffer.from(sharesHex[0], 'hex');
  const share2 = Buffer.from(sharesHex[1], 'hex');
  const secret = Buffer.alloc(share1.length);
  
  // secret = share1 XOR share2
  for (let i = 0; i < share1.length; i++) {
    secret[i] = share1[i] ^ share2[i];
  }
  
  return secret.toString('hex');
}

// ============================================================================
// ED25519 SIGNATURES - Zero-Knowledge Authentication
// ============================================================================

/**
 * Generate a new Ed25519 keypair
 * @returns {{publicKey: string, privateKey: string, l1Address: string, l2Address: string}}
 */
export function generateKeypair() {
  const keypair = nacl.sign.keyPair();
  const publicKey = Buffer.from(keypair.publicKey).toString('hex');
  const privateKey = Buffer.from(keypair.secretKey.slice(0, 32)).toString('hex');
  
  return {
    publicKey,
    privateKey,
    l1Address: deriveL1Address(publicKey),
    l2Address: deriveL2Address(publicKey)
  };
}

/**
 * Sign a message with domain separation (prevents L1/L2 replay attacks)
 * 
 * @param {string} privateKeyHex - Ed25519 private key (64 hex chars)
 * @param {string} message - Message to sign
 * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
 * @returns {string} - Signature (128 hex chars)
 */
export function signMessage(privateKeyHex, message, chainId = CHAIN_ID_L1) {
  // Domain separation: prepend chain ID
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  // Sign with Ed25519
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey, 0);
  
  // Derive public key from private key
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  secretKey.set(keypair.publicKey, 32);
  
  const signature = nacl.sign.detached(domainSeparated, secretKey);
  return Buffer.from(signature).toString('hex');
}

/**
 * Verify a signature
 * 
 * @param {string} publicKeyHex - Ed25519 public key (64 hex chars)
 * @param {string} message - Original message
 * @param {string} signatureHex - Signature (128 hex chars)
 * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
 * @returns {boolean} - True if signature is valid
 */
export function verifySignature(publicKeyHex, message, signatureHex, chainId = CHAIN_ID_L1) {
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  const publicKey = new Uint8Array(Buffer.from(publicKeyHex, 'hex'));
  const signature = new Uint8Array(Buffer.from(signatureHex, 'hex'));
  
  return nacl.sign.detached.verify(domainSeparated, signature, publicKey);
}

// ============================================================================
// UNIFIED WALLET CLASS
// ============================================================================

export class UnifiedWallet {
  constructor(privateKeyHex, publicKeyHex = null) {
    this.privateKey = privateKeyHex;
    
    // Derive public key if not provided
    if (!publicKeyHex) {
      const keypair = nacl.sign.keyPair.fromSeed(Buffer.from(privateKeyHex, 'hex'));
      this.publicKey = Buffer.from(keypair.publicKey).toString('hex');
    } else {
      this.publicKey = publicKeyHex;
    }
    
    // Derive addresses
    this.l1Address = deriveL1Address(this.publicKey);
    this.l2Address = deriveL2Address(this.publicKey);
    
    // Balances (populated by refresh())
    this.l1Balance = 0;
    this.l2Balance = 0;
    this.totalBalance = 0;
    
    // Nonce counter for replay protection
    this.nonce = Date.now();
  }
  
  /**
   * Create wallet from encrypted blob + password
   * @param {EncryptedBlob} blob - Encrypted vault
   * @param {string} password - User's password
   * @returns {Promise<UnifiedWallet>}
   */
  static async fromEncryptedBlob(blob, password) {
    const privateKey = await unlockEncryptedBlob(blob, password);
    return new UnifiedWallet(privateKey);
  }
  
  /**
   * Create wallet from test account
   * @param {string} name - 'alice', 'bob', or 'dealer'
   * @returns {UnifiedWallet}
   */
  static fromTestAccount(name) {
    const account = ACCOUNTS[name];
    if (!account) throw new Error(`Unknown test account: ${name}`);
    return new UnifiedWallet(account.privateKey, account.publicKey);
  }
  
  /**
   * Sign a request with domain separation AND path binding
   * @param {object} payload - Request payload
   * @param {number} chainId - CHAIN_ID_L1 or CHAIN_ID_L2
   * @param {string} requestPath - API endpoint path (e.g., "/transfer", "/wallet/balance")
   * @returns {object} - Signed request
   */
  signRequest(payload, chainId = CHAIN_ID_L1, requestPath = null) {
    const timestamp = Date.now();
    this.nonce++;
    
    const payloadStr = JSON.stringify(payload);
    
    // Build message with path binding (if provided)
    // Format: [path\n]payload\ntimestamp\nnonce
    let message;
    if (requestPath) {
      message = `${requestPath}\n${payloadStr}\n${timestamp}\n${this.nonce}`;
    } else {
      // Backward compatibility: no path
      message = `${payloadStr}\n${timestamp}\n${this.nonce}`;
    }
    
    const signature = signMessage(this.privateKey, message, chainId);
    
    const result = {
      public_key: this.publicKey,
      wallet_address: chainId === CHAIN_ID_L1 ? this.l1Address : this.l2Address,
      nonce: this.nonce.toString(),
      timestamp,
      chain_id: chainId,
      payload: payloadStr,
      signature
    };
    
    // Include request_path if provided (recommended for security)
    if (requestPath) {
      result.request_path = requestPath;
    }
    
    return result;
  }
  
  /**
   * Refresh balances from L1
   * @param {string} l1Url - L1 server URL
   * @returns {Promise<void>}
   */
  async refresh(l1Url = 'http://localhost:8080') {
    try {
      // Query L1 balance
      const l1Response = await fetch(`${l1Url}/balance/${this.l1Address}`);
      const l1Data = await l1Response.json();
      this.l1Balance = l1Data.balance || 0;
      
      // Query L2 balance
      const l2Response = await fetch(`${l1Url}/balance/${this.l2Address}`);
      const l2Data = await l2Response.json();
      this.l2Balance = l2Data.balance || 0;
      
      // Combined balance
      const combinedResponse = await fetch(`${l1Url}/balance/${stripPrefix(this.l1Address)}`);
      const combinedData = await combinedResponse.json();
      this.totalBalance = combinedData.balance || 0;
      
    } catch (error) {
      console.error('Failed to refresh balances:', error);
    }
  }
  
  /**
   * Transfer tokens to another address
   * @param {string} toAddress - Recipient address
   * @param {number} amount - Amount to transfer
   * @param {string} l1Url - L1 server URL
   * @returns {Promise<object>} - Transfer result
   */
  async transfer(toAddress, amount, l1Url = 'http://localhost:8080') {
    const payload = {
      to: toAddress,
      amount: amount
    };
    
    // Sign with path binding for security
    const signedRequest = this.signRequest(payload, CHAIN_ID_L1, '/transfer');
    
    const response = await fetch(`${l1Url}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    return response.json();
  }
  
  /**
   * Register this wallet on the server
   * @param {string} username - Username for registration
   * @param {string} password - Password (used to encrypt vault)
   * @param {string} email - Optional email
   * @param {string} l1Url - L1 server URL
   * @returns {Promise<object>} - Registration result
   */
  async register(username, password, email = null, l1Url = 'http://localhost:8080') {
    // Create encrypted vault
    const vault = await this.createVault(password);
    vault.address = this.l1Address;
    
    const requestBody = {
      username,
      email: email || username,
      encrypted_vault: vault,
      public_key: this.publicKey
    };
    
    const response = await fetch(`${l1Url}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody)
    });
    
    return response.json();
  }
  
  /**
   * Load wallet from server using username and password
   * @param {string} username - Username
   * @param {string} password - Password to decrypt vault
   * @param {string} l1Url - L1 server URL
   * @returns {Promise<UnifiedWallet>} - Loaded wallet
   */
  static async fromServer(username, password, l1Url = 'http://localhost:8080') {
    // 1. Fetch encrypted vault
    const vaultResponse = await fetch(`${l1Url}/auth/vault/fetch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    const vaultData = await vaultResponse.json();
    if (!vaultData.success) {
      throw new Error(vaultData.error || 'Failed to fetch vault');
    }
    
    // 2. Decrypt vault to get private key
    const privateKey = await unlockEncryptedBlob(vaultData.encrypted_vault, password);
    
    return new UnifiedWallet(privateKey);
  }
  
  /**
   * Create encrypted vault for this wallet
   * @param {string} password - User's password
   * @returns {Promise<EncryptedBlob>}
   */
  async createVault(password) {
    return createEncryptedBlob(this.privateKey, password);
  }
  
  /**
   * Split wallet into MPC shares (2-of-2)
   * @returns {Array<string>} - [clientShard, serverShard]
   */
  splitMPC() {
    return shamirSplit(this.privateKey, 2, 2);
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Constants
  CHAIN_ID_L1,
  CHAIN_ID_L2,
  ACCOUNTS,
  
  // Key derivation
  deriveKey,
  generateSalt,
  
  // Encrypted vault
  createEncryptedBlob,
  unlockEncryptedBlob,
  
  // Address derivation
  deriveL1Address,
  deriveL2Address,
  stripPrefix,
  
  // Shamir's Secret Sharing
  shamirSplit,
  shamirCombine,
  
  // Ed25519
  generateKeypair,
  signMessage,
  verifySignature,
  
  // Wallet class
  UnifiedWallet
};
