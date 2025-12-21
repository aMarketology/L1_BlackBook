// ============================================================================
// BLACKBOOK UNIFIED WALLET SDK
// ============================================================================
//
// Single wallet experience for L1 (vault) and L2 (gaming/betting)
// 
// SECURITY: Domain separation prevents L1↔L2 signature replay attacks
// - Same keypair works on both layers
// - Signatures include chain_id prefix (0x01 for L1, 0x02 for L2)
// - L1 signature CANNOT be replayed on L2 (and vice versa)
//
// THE FLOW:
// ┌──────────────┐      "Bridge"      ┌──────────────┐      "Bet"       
// │ L1 Wallet    │ ─────────────────▶ │ L2 Session   │ ──────────────▶ WIN/LOSE
// │ 10,000 BB    │   Lock funds       │ 5,000 BB     │   Fast betting   
// └──────────────┘                    └──────────────┘                  
//        ▲                                                    │
//        └────────────────────────────────────────────────────┘
//                            "Withdraw" (profit returned!)
//
// USAGE:
//   import { UnifiedWallet, CHAIN_ID_L1, CHAIN_ID_L2 } from './unified-wallet-sdk.js';
//   
//   // Connect to Alice or Bob (real accounts on L1/L2)
//   const alice = await UnifiedWallet.connect('alice');
//   const bob = await UnifiedWallet.connect('bob');
//   
//   // Or connect with custom credentials
//   const wallet = await UnifiedWallet.connect({
//     private_key: '...',
//     address: '...'
//   });
//   
//   console.log(alice.balance); // 10000 BB
//   
//   // Bridge to L2 for betting
//   await alice.bridgeToL2(5000);
//   
//   // Place bet on L2 (signed with CHAIN_ID_L2)
//   await alice.placeBet('btc_100k_2025', 'yes', 1000);
//   
//   // Withdraw winnings back to L1
//   await alice.withdraw();
//
// RUN DEMO:
//   bun unified-wallet-sdk.js
//   node unified-wallet-sdk.js
//
// ============================================================================

import nacl from 'tweetnacl';
import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import CryptoJS from 'crypto-js';
import { createClient } from '@supabase/supabase-js';

// SSS Recovery Module (optional - gracefully fallback if not available)
let walletRecovery = null;
try {
  // Dynamic import for Node.js compatibility
  if (typeof require !== 'undefined') {
    walletRecovery = require('./wallet-recovery.js');
  } else {
    // ES6 import for browser
    walletRecovery = await import('./wallet-recovery.js');
  }
  console.log('✅ SSS wallet recovery module loaded');
} catch (e) {
  console.warn('⚠️  wallet-recovery.js not loaded - SSS recovery features disabled');
  console.warn('   To enable: Install secrets.js-grempe with: npm install secrets.js-grempe');
}

// ============================================================================
// DOMAIN SEPARATION CONSTANTS
// ============================================================================
// These MUST match the Rust constants in identity.rs
// Signatures include chain_id as first byte to prevent L1↔L2 replay attacks

/** Layer 1 Chain ID - Bank/Vault operations (withdrawals, deposits, settlements) */
export const CHAIN_ID_L1 = 0x01;

/** Layer 2 Chain ID - Casino/Gaming operations (bets, trades) */
export const CHAIN_ID_L2 = 0x02;

// ============================================================================
// CONFIGURATION - Change these if your servers are on different ports
// ============================================================================

// Detect if we're running in browser dev mode (Vite)
const isBrowser = typeof window !== 'undefined';
const isDev = isBrowser && (import.meta?.env?.DEV || window.location.hostname === 'localhost');

const CONFIG = {
  // Use Vite proxy in development to avoid CORS, direct URLs in production/Node
  L1_URL: isDev ? '/api/l1' : (process.env.L1_URL || 'http://localhost:8080'),
  L2_URL: isDev ? '/api/l2' : (process.env.L2_URL || 'http://localhost:1234'),
  SUPABASE_URL: import.meta?.env?.VITE_SUPABASE_URL || '',
  SUPABASE_KEY: import.meta?.env?.VITE_SUPABASE_ANON_KEY || '',
};

// BIP-44 Derivation Path for BlackBook (SLIP-0010 compatible)
const L1_DERIVATION_PATH = "m/44'/1337'/0'/0'/0'";

// Password Fork Constants (must match backend)
const AUTH_CONSTANT = 'BLACKBOOK_AUTH_V1';
const WALLET_CONSTANT = 'BLACKBOOK_WALLET_V1';

// ============================================================================
// BUILT-IN ACCOUNTS - Alice & Bob (real BIP-39 derived accounts)
// ============================================================================
// Generated using: npm run generate-accounts
// These are REAL cryptographic keys derived from BIP-39 mnemonics
// Address format: L1_/L2_ + 40 hex chars (43 chars total, 160-bit security)

const ACCOUNTS = {
  alice: {
    name: 'Alice',
    username: 'alice_test',
    email: 'alice@blackbook.test',
    address: 'L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD',
    public_key: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
    private_key: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    mnemonic: 'machine sword cause scrub simple damage program together spoon lock ball banana',
    derivation_path: "m/44'/1337'/0'/0'/0'"
  },
  bob: {
    name: 'Bob', 
    username: 'bob_test',
    email: 'bob@blackbook.test',
    address: 'L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9',
    public_key: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
    private_key: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    mnemonic: 'base echo grape penalty hawk resemble obscure unusual throw paddle carpet elder',
    derivation_path: "m/44'/1337'/0'/0'/0'"
  },
  // DEALER/ORACLE/HOUSE - L2 Native Account (Private key in .env)
  dealer: {
    name: 'Dealer',
    role: 'Oracle/House',
    layer: 'L2',
    address: 'L2_F5C46483E8A28394F5E8687DEADF6BD4E924CED3',
    public_key: '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a',
    // ⚠️ Private key loaded from environment variable DEALER_PRIVATE_KEY
    private_key: null,
    derivation_path: "m/44'/1337'/0'/0'/0'"
  }
};

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function generateNonce() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return bytesToHex(array);
}

/**
 * Generate cryptographically secure salt (32 bytes)
 * @returns {string} 64-character hex string
 */
function generateSalt() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return bytesToHex(array);
}

// ============================================================================
// PASSWORD FORK - Split Password into Login + Wallet Secrets
// ============================================================================
//
// User Password + Salt
//         ↓
//    ┌────┴────┐
//    ↓         ↓
// Path A      Path B  
// (Fast)      (Slow)
//    ↓         ↓
// Login      Wallet
// Password   Key
//    ↓         ↓
// Supabase   Encrypt
// Auth       Mnemonic
//
// ============================================================================

/**
 * Derive Login Password (Path A) - sent to Supabase for authentication
 * Formula: SHA256(password + salt + AUTH_CONSTANT)
 * @param {string} password - User's plaintext password
 * @param {string} salt - User's unique salt (64 hex chars)
 * @returns {string} 64-character hex hash
 */
function deriveLoginPassword(password, salt) {
  const input = password + salt + AUTH_CONSTANT;
  return CryptoJS.SHA256(input).toString(CryptoJS.enc.Hex);
}

/**
 * Derive Wallet Key (Path B) - NEVER sent to server
 * Uses PBKDF2 with 600k iterations for security (OWASP 2024)
 * @param {string} password - User's plaintext password
 * @param {string} salt - User's unique salt (64 hex chars)
 * @returns {string} 64-character hex key
 */
function deriveWalletKey(password, salt) {
  const input = password + salt + WALLET_CONSTANT;
  const key = CryptoJS.PBKDF2(input, salt, {
    keySize: 256 / 32,
    iterations: 600000,  // OWASP 2024: 600k+ for PBKDF2-SHA256
    hasher: CryptoJS.algo.SHA256
  });
  return key.toString(CryptoJS.enc.Hex);
}

/**
 * Fork password into two separate secrets
 * @param {string} password - User's plaintext password
 * @param {string} [existingSalt] - Optional existing salt (for login)
 * @returns {Object} { loginPassword, walletKey, salt }
 */
function forkPassword(password, existingSalt = null) {
  const salt = existingSalt || generateSalt();
  return {
    loginPassword: deriveLoginPassword(password, salt),
    walletKey: deriveWalletKey(password, salt),
    salt
  };
}

// ============================================================================
// VAULT ENCRYPTION - AES-256-GCM (Authenticated Encryption)
// ============================================================================

/**
 * Encrypt vault contents with Wallet Key using AES-256-GCM
 * Uses Web Crypto API for authenticated encryption (prevents bit-flipping attacks)
 * @param {Object} contents - Vault data to encrypt (e.g., { mnemonic })
 * @param {string} walletKey - 64 hex char key from password fork
 * @returns {Promise<Object>} { encrypted_blob, nonce, auth_tag }
 */
async function encryptVault(contents, walletKey) {
  const plaintext = new TextEncoder().encode(JSON.stringify(contents));
  
  // Generate 12-byte nonce (96 bits - recommended for GCM)
  const nonce = new Uint8Array(12);
  if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
    throw new Error('Secure random not available. Use a modern browser with Web Crypto API.');
  }
  crypto.getRandomValues(nonce);
  
  // Import key for AES-GCM
  const keyBytes = hexToBytes(walletKey.slice(0, 64));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  // Encrypt with AES-GCM (includes authentication tag)
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    cryptoKey,
    plaintext
  );
  
  return {
    encrypted_blob: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    nonce: bytesToHex(nonce)
  };
}

/**
 * Decrypt vault contents with Wallet Key using AES-256-GCM
 * Uses Web Crypto API for authenticated decryption
 * @param {string} encryptedBlob - Base64 encoded ciphertext (includes auth tag)
 * @param {string} nonce - 24 hex char nonce
 * @param {string} walletKey - 64 hex char key
 * @returns {Promise<Object>} Decrypted vault contents
 */
async function decryptVault(encryptedBlob, nonce, walletKey) {
  // Decode ciphertext from base64
  const ciphertext = Uint8Array.from(atob(encryptedBlob), c => c.charCodeAt(0));
  const nonceBytes = hexToBytes(nonce);
  
  // Import key for AES-GCM
  const keyBytes = hexToBytes(walletKey.slice(0, 64));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  
  try {
    // Decrypt with AES-GCM (verifies authentication tag)
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonceBytes, tagLength: 128 },
      cryptoKey,
      ciphertext
    );
    
    const decoded = new TextDecoder().decode(plaintext);
    return JSON.parse(decoded);
  } catch (e) {
    throw new Error('Decryption failed - wrong password, corrupted vault, or tampered data');
  }
}

// ============================================================================
// BIP-39 MNEMONIC - Human-readable wallet backup
// ============================================================================

/**
 * Generate a new BIP-39 mnemonic phrase
 * @param {number} wordCount - 12 or 24 words
 * @returns {string} Space-separated mnemonic words
 */
function generateMnemonic(wordCount = 12) {
  const strength = wordCount === 24 ? 256 : 128;
  return bip39.generateMnemonic(strength);
}

/**
 * Validate a mnemonic phrase
 * @param {string} mnemonic
 * @returns {boolean}
 */
function validateMnemonic(mnemonic) {
  return bip39.validateMnemonic(mnemonic);
}

/**
 * Derive ed25519 keypair from mnemonic using SLIP-0010
 * @param {string} mnemonic - BIP-39 mnemonic phrase
 * @param {string} [derivationPath] - BIP-44 path (default: L1_DERIVATION_PATH)
 * @returns {Object} { publicKey, privateKey, publicKeyHex, privateKeyHex }
 */
function deriveKeypairFromMnemonic(mnemonic, derivationPath = L1_DERIVATION_PATH) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const seedHex = seed.toString('hex');
  const { key } = derivePath(derivationPath, seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(key);
  
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
    publicKeyHex: bytesToHex(keypair.publicKey),
    privateKeyHex: bytesToHex(keypair.secretKey)
  };
}

/**
 * Generate L1 address from Ed25519 public key
 * Format: L1_ + 40 hex chars (e.g., L1_48F582A1BC8976D3E45F6789AB...)
 * Algorithm: L1_ + SHA256(pubkey).slice(0, 20 bytes) = 160-bit security (same as Bitcoin RIPEMD160)
 * @param {string} publicKeyHex - 64-character hex public key
 * @returns {string} L1 address (43 characters: L1_ + 40 hex)
 */
function generateL1Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const addressHash = hash.slice(0, 40).toUpperCase(); // 160 bits = collision resistant
  return `L1_${addressHash}`;
}

/**
 * Generate L2 address from Ed25519 public key
 * Format: L2_ + 40 hex chars (e.g., L2_48F582A1BC8976D3E45F6789AB...)
 * Algorithm: L2_ + SHA256(pubkey).slice(0, 20 bytes) = 160-bit security (same as Bitcoin RIPEMD160)
 * @param {string} publicKeyHex - 64-character hex public key
 * @returns {string} L2 address (43 characters: L2_ + 40 hex)
 */
function generateL2Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const addressHash = hash.slice(0, 40).toUpperCase(); // 160 bits = collision resistant
  return `L2_${addressHash}`;
}

// ============================================================================
// UNIFIED WALLET CLASS
// ============================================================================

export class UnifiedWallet {
  constructor(account) {
    this.name = account.name || 'Wallet';
    this.address = account.address;
    this.publicKey = account.public_key;
    this.email = account.email || '';
    this.username = account.username || '';
    
    // Set up signing keys (if private_key provided)
    if (account.private_key) {
      const seed = hexToBytes(account.private_key);
      const keyPair = nacl.sign.keyPair.fromSeed(seed);
      this._privateKey = keyPair.secretKey;
      this._publicKey = keyPair.publicKey;
    } else {
      this._privateKey = null;
      this._publicKey = null;
    }
    
    // Balance state (will be refreshed from server)
    this._l1Available = 0;
    this._l1Locked = 0;
    this._l2Balance = 0;
    
    // Full wallet state (for BIP-39 mode)
    this._mnemonic = null;
    this._salt = null;
    this._walletKey = null;
    this._isUnlocked = false;
    
    // Supabase client (lazy initialized)
    this._supabase = null;
  }

  // ==========================================================================
  // SUPABASE INTEGRATION
  // ==========================================================================

  /** Get Supabase client (lazy init) */
  get supabase() {
    if (!this._supabase && CONFIG.SUPABASE_URL && CONFIG.SUPABASE_KEY) {
      this._supabase = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_KEY);
    }
    return this._supabase;
  }

  /** Set Supabase client (inject from app) */
  set supabase(client) {
    this._supabase = client;
  }

  /** Get salt */
  get salt() {
    return this._salt;
  }

  /** Set salt */
  set salt(value) {
    this._salt = value;
  }

  /** Get wallet key */
  get walletKey() {
    return this._walletKey;
  }

  /** Set wallet key */
  set walletKey(value) {
    this._walletKey = value;
  }

  /** Get userId */
  get userId() {
    return this._userId || this.username;
  }

  /** Set userId */
  set userId(value) {
    this._userId = value;
  }

  // ==========================================================================
  // CONNECT - Main entry point
  // ==========================================================================

  /**
   * Connect to a wallet
   * @param {string|Object} input - 'alice', 'bob', or { private_key, address }
   * @returns {Promise<UnifiedWallet>}
   * 
   * @example
   *   const alice = await UnifiedWallet.connect('alice');
   *   const bob = await UnifiedWallet.connect('bob');
   *   const custom = await UnifiedWallet.connect({ private_key: '...', address: '...' });
   */
  static async connect(input) {
    let account;
    
    if (typeof input === 'string') {
      // Connect by name (alice, bob)
      const name = input.toLowerCase();
      account = ACCOUNTS[name];
      
      if (!account) {
        // Try fetching from server
        try {
          const response = await fetch(`${CONFIG.L1_URL}/auth/test-accounts`);
          const data = await response.json();
          account = data[name];
        } catch (e) {
          // Server not available, use built-in accounts only
        }
      }
      
      if (!account) {
        throw new Error(`Unknown account: "${input}". Use 'alice' or 'bob'.`);
      }
    } else {
      // Connect with credentials object
      account = input;
    }
    
    const wallet = new UnifiedWallet(account);
    await wallet.refresh();
    
    console.log(`✅ Connected: ${wallet.name}`);
    console.log(`   Address: ${wallet.address}`);
    console.log(`   Balance: ${wallet.balance} BB\n`);
    
    return wallet;
  }

  // ==========================================================================
  // CREATE NEW WALLET - For real users
  // ==========================================================================

  /**
   * Create a brand new wallet with random keys
   * @returns {Promise<{wallet: UnifiedWallet, credentials: Object}>}
   * 
   * @example
   *   const { wallet, credentials } = await UnifiedWallet.create();
   *   // ⚠️ IMPORTANT: User must save credentials.private_key securely!
   *   console.log('Save this:', credentials.private_key);
   */
  static async create() {
    // Generate random seed (32 bytes) - MUST use cryptographic RNG
    const seed = new Uint8Array(32);
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
      throw new Error(
        'Secure random number generator not available. ' +
        'Use a modern browser with Web Crypto API or Node.js 15+.'
      );
    }
    crypto.getRandomValues(seed);
    
    // Derive keypair from seed
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    // Create address from public key (L1 prefix + first 14 chars)
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    const address = 'L1' + publicKeyHex.substring(0, 14).toUpperCase();
    
    const credentials = {
      address: address,
      public_key: publicKeyHex,
      private_key: bytesToHex(seed),  // 32-byte seed as hex
      created_at: new Date().toISOString()
    };
    
    // Try to register on L1 (for balance tracking)
    try {
      await fetch(`${CONFIG.L1_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: credentials.address,
          public_key: credentials.public_key
        })
      });
    } catch {
      // Registration endpoint may not exist, that's OK
    }
    
    const wallet = await UnifiedWallet.connect({
      name: 'New Wallet',
      ...credentials
    });
    
    console.log('');
    console.log('⚠️  SAVE YOUR PRIVATE KEY - YOU CANNOT RECOVER IT!');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`   ${credentials.private_key}`);
    console.log('═══════════════════════════════════════════════════════════');
    console.log('');
    
    return { wallet, credentials };
  }

  /**
   * Import wallet from private key only
   * Derives address and public key automatically
   * @param {string} privateKeyHex - 64 hex characters (32 byte seed)
   * @returns {Promise<UnifiedWallet>}
   * 
   * @example
   *   const wallet = await UnifiedWallet.import('abc123def456...');
   */
  static async import(privateKeyHex) {
    // Clean input (remove whitespace, 0x prefix)
    const cleanKey = privateKeyHex.trim().toLowerCase().replace(/^0x/, '');
    
    if (cleanKey.length !== 64) {
      throw new Error(`Invalid private key. Expected 64 hex characters, got ${cleanKey.length}.`);
    }
    
    const seed = hexToBytes(cleanKey);
    
    if (seed.length !== 32) {
      throw new Error('Invalid private key. Must be 64 hex characters (32 bytes).');
    }
    
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    const address = generateL1Address(publicKeyHex);  // Use proper address generation
    
    console.log(`🔑 Importing wallet: ${address}`);
    
    return UnifiedWallet.connect({
      name: 'Imported Wallet',
      address: address,
      public_key: publicKeyHex,
      private_key: cleanKey
    });
  }

  // ==========================================================================
  // FULL WALLET - Register/Login with Password Fork + BIP-39
  // ==========================================================================

  /**
   * Register a new user with Supabase + create encrypted wallet
   * @param {string} username - Unique username
   * @param {string} email - User's email
   * @param {string} password - User's plaintext password
   * @param {number} [wordCount=12] - Mnemonic word count (12 or 24)
   * @returns {Promise<{wallet: UnifiedWallet, mnemonic: string}>}
   * 
   * @example
   *   const { wallet, mnemonic } = await UnifiedWallet.register('alice', 'alice@example.com', 'MyPassword123!');
   *   // ⚠️ User MUST backup mnemonic!
   */
  static async register(username, email, password, wordCount = 12) {
    console.log(`📝 Registering new user: ${username}`);
    
    // Validate inputs
    if (!username || username.length < 3) {
      throw new Error('Username must be at least 3 characters');
    }
    if (!email || !email.includes('@')) {
      throw new Error('Invalid email address');
    }
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }
    
    // Step 1: Fork password
    const { loginPassword, walletKey, salt } = forkPassword(password);
    console.log('🔐 Password forked into login + wallet keys');
    
    // Step 2: Generate BIP-39 mnemonic
    const mnemonic = generateMnemonic(wordCount);
    console.log(`📜 Generated ${wordCount}-word mnemonic`);
    
    // Step 3: Derive keypair from mnemonic
    const keypair = deriveKeypairFromMnemonic(mnemonic);
    const address = generateL1Address(keypair.publicKeyHex);
    console.log(`🔑 Derived address: ${address}`);
    
    // Step 4: Encrypt mnemonic with wallet key
    const vaultContents = {
      mnemonic: mnemonic,
      created_at: Date.now(),
      version: 2,
      public_key: keypair.publicKeyHex
    };
    const { encrypted_blob, nonce } = await encryptVault(vaultContents, walletKey);
    const encryptedBlobJson = JSON.stringify({
      cipher: encrypted_blob,
      nonce,
      version: 2,
      created_at: Date.now()
    });
    
    // Create wallet instance
    const wallet = new UnifiedWallet({
      name: username,
      address: address,
      public_key: keypair.publicKeyHex,
      private_key: bytesToHex(keypair.privateKey.slice(0, 32)),
      email: email,
      username: username
    });
    
    // Store internal state
    wallet._mnemonic = mnemonic;
    wallet._salt = salt;
    wallet._walletKey = walletKey;
    wallet._isUnlocked = true;
    
    // Step 5: Register with Supabase (if available)
    if (wallet.supabase) {
      try {
        // Create auth user
        const { error: authError } = await wallet.supabase.auth.signUp({
          email,
          password: loginPassword,
          options: { data: { username } }
        });
        if (authError) throw new Error(`Auth failed: ${authError.message}`);
        
        // Create profile with salt + encrypted vault
        const { error: profileError } = await wallet.supabase
          .from('profiles')
          .insert({
            user_id: username,
            email: email,
            salt: salt,
            encrypted_blob: encryptedBlobJson,
            blackbook_address: address,
            reputation_score: 100.0
          });
        if (profileError) throw new Error(`Profile failed: ${profileError.message}`);
        
        console.log('✅ Registered with Supabase');
      } catch (err) {
        console.warn('⚠️ Supabase registration failed:', err.message);
        // Continue without Supabase - wallet still works locally
      }
    }
    
    // Try to register on L1
    try {
      await fetch(`${CONFIG.L1_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: address,
          public_key: keypair.publicKeyHex
        })
      });
    } catch {
      // L1 may not be running
    }
    
    await wallet.refresh();
    
    console.log('');
    console.log('⚠️  BACKUP YOUR MNEMONIC - YOU CANNOT RECOVER IT!');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`   ${mnemonic}`);
    console.log('═══════════════════════════════════════════════════════════');
    console.log('');
    
    return { wallet, mnemonic };
  }

  /**
   * Login existing user with password
   * @param {string} usernameOrEmail - Username or email
   * @param {string} password - User's plaintext password
   * @param {Object} [supabaseClient] - Optional Supabase client
   * @returns {Promise<UnifiedWallet>}
   * 
   * @example
   *   const wallet = await UnifiedWallet.login('alice', 'MyPassword123!');
   */
  static async login(usernameOrEmail, password, supabaseClient = null) {
    console.log(`🔓 Logging in: ${usernameOrEmail}`);
    
    // Get Supabase client
    const supabase = supabaseClient || (CONFIG.SUPABASE_URL && CONFIG.SUPABASE_KEY 
      ? createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_KEY) 
      : null);
    
    if (!supabase) {
      throw new Error('Supabase client required for login');
    }
    
    // Step 1: Fetch salt from profiles
    const isEmail = usernameOrEmail.includes('@');
    const query = isEmail
      ? supabase.from('profiles').select('user_id, email, salt, encrypted_blob, blackbook_address').eq('email', usernameOrEmail).single()
      : supabase.from('profiles').select('user_id, email, salt, encrypted_blob, blackbook_address').eq('user_id', usernameOrEmail).single();
    
    const { data: profile, error: profileError } = await query;
    if (profileError || !profile) {
      throw new Error('User not found');
    }
    if (!profile.salt) {
      throw new Error('No salt found - corrupted profile');
    }
    
    console.log('📋 Fetched profile, forking password...');
    
    // Step 2: Fork password with stored salt
    const { loginPassword, walletKey } = forkPassword(password, profile.salt);
    
    // Step 3: Authenticate with Supabase
    const { error: authError } = await supabase.auth.signInWithPassword({
      email: profile.email,
      password: loginPassword
    });
    if (authError) {
      throw new Error('Invalid password');
    }
    
    console.log('✅ Authenticated with Supabase');
    
    // Step 4: Decrypt vault
    if (!profile.encrypted_blob) {
      throw new Error('No encrypted wallet found');
    }
    
    const parsed = JSON.parse(profile.encrypted_blob);
    const vaultContents = decryptVault(parsed.cipher, parsed.nonce, walletKey);
    console.log('🔓 Vault decrypted');
    
    // Step 5: Derive keypair from mnemonic
    const keypair = deriveKeypairFromMnemonic(vaultContents.mnemonic);
    const address = profile.blackbook_address || generateL1Address(keypair.publicKeyHex);
    
    // Create wallet instance
    const wallet = new UnifiedWallet({
      name: profile.user_id,
      address: address,
      public_key: keypair.publicKeyHex,
      private_key: bytesToHex(keypair.privateKey.slice(0, 32)),
      email: profile.email,
      username: profile.user_id
    });
    
    wallet._mnemonic = vaultContents.mnemonic;
    wallet._salt = profile.salt;
    wallet._walletKey = walletKey;
    wallet._isUnlocked = true;
    wallet._supabase = supabase;
    
    await wallet.refresh();
    
    console.log(`✅ Logged in as ${profile.user_id}`);
    wallet.print();
    
    return wallet;
  }

  /**
   * Import wallet from BIP-39 mnemonic phrase
   * @param {string} mnemonic - 12 or 24 word mnemonic
   * @returns {Promise<UnifiedWallet>}
   * 
   * @example
   *   const wallet = await UnifiedWallet.importMnemonic('abandon abandon abandon...');
   */
  static async importMnemonic(mnemonic) {
    // Validate mnemonic
    const cleanMnemonic = mnemonic.trim().toLowerCase();
    if (!validateMnemonic(cleanMnemonic)) {
      throw new Error('Invalid mnemonic phrase');
    }
    
    console.log('📜 Importing wallet from mnemonic...');
    
    // Derive keypair
    const keypair = deriveKeypairFromMnemonic(cleanMnemonic);
    const address = generateL1Address(keypair.publicKeyHex);
    
    const wallet = new UnifiedWallet({
      name: 'Recovered Wallet',
      address: address,
      public_key: keypair.publicKeyHex,
      private_key: bytesToHex(keypair.privateKey.slice(0, 32))
    });
    
    wallet._mnemonic = cleanMnemonic;
    wallet._isUnlocked = true;
    
    await wallet.refresh();
    
    console.log(`✅ Wallet recovered: ${address}`);
    
    return wallet;
  }

  /**
   * Lock wallet (clear sensitive data from memory)
   */
  lock() {
    this._mnemonic = null;
    this._walletKey = null;
    this._privateKey = null;
    this._isUnlocked = false;
    console.log('🔒 Wallet locked');
  }

  // ==========================================================================
  // SSS RECOVERY - Shamir's Secret Sharing for Password Reset Recovery
  // ==========================================================================

  /**
   * Register a new user with SSS recovery backup
   * This is the enhanced version of register() that includes PIN-protected backups
   * 
   * @param {string} username - Unique username
   * @param {string} email - User's email
   * @param {string} password - User's plaintext password
   * @param {string} pin - 6-digit recovery PIN
   * @param {Object} options - Additional options
   * @param {number} [options.wordCount=12] - Mnemonic word count
   * @param {string} [options.serverKey] - Server encryption key (uses env if not provided)
   * @returns {Promise<{wallet: UnifiedWallet, mnemonic: string, cloudBackup: string, emailBackup: string}>}
   * 
   * @example
   *   const result = await UnifiedWallet.registerWithRecovery(
   *     'alice', 
   *     'alice@example.com', 
   *     'MyPassword123!',
   *     '123456'
   *   );
   *   // Save cloudBackup to Google Drive
   *   // Keep emailBackup in email
   *   // User must remember their 6-digit PIN!
   */
  /**
   * Register a new user with SSS (Shamir's Secret Sharing) recovery
   * Creates 3 encrypted shares (server, cloud, email) - need 2 to recover
   * 
   * @param {string} username - Unique username
   * @param {string} email - User's email
   * @param {string} password - User's plaintext password
   * @param {string} pin - 6-digit PIN for recovery
   * @param {Object} options - { wordCount: 12, serverKey: 'hex', supabaseClient }
   * @returns {Promise<{wallet, mnemonic, cloudShare, emailShare}>}
   * 
   * @example
   *   const result = await UnifiedWallet.registerWithRecovery('alice', 'alice@example.com', 'Pass123!', '123456');
   *   // Save cloudShare to Google Drive/iCloud
   *   // Send emailShare to user's email
   *   // User must remember their 6-digit PIN!
   */
  static async registerWithRecovery(username, email, password, pin, options = {}) {
    if (!walletRecovery) {
      throw new Error('SSS recovery module not loaded. Install: npm install secrets.js-grempe');
    }
    
    // Validate PIN
    if (!walletRecovery.isValidPIN(pin)) {
      throw new Error('PIN must be exactly 6 digits');
    }
    
    console.log(`📝 Registering with SSS recovery: ${username}`);
    
    // Validate inputs
    if (!username || username.length < 3) {
      throw new Error('Username must be at least 3 characters');
    }
    if (!email || !email.includes('@')) {
      throw new Error('Invalid email address');
    }
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }
    
    // Server key (must be provided or in env)
    const serverKey = options.serverKey || process.env.SERVER_ENCRYPTION_KEY;
    if (!serverKey || serverKey.length !== 64) {
      throw new Error('Server encryption key required (64 hex chars)');
    }
    
    // Step 1: Fork password
    const { loginPassword, walletKey, salt } = forkPassword(password);
    console.log('🔐 Password forked into login + wallet keys');
    
    // Step 2: Generate BIP-39 mnemonic
    const wordCount = options.wordCount || 12;
    const mnemonic = generateMnemonic(wordCount);
    console.log(`📜 Generated ${wordCount}-word mnemonic`);
    
    // Step 3: Derive keypair from mnemonic
    const keypair = deriveKeypairFromMnemonic(mnemonic);
    const address = generateL1Address(keypair.publicKeyHex);
    const l2Address = generateL2Address(keypair.publicKeyHex);
    console.log(`🔑 Derived addresses:`);
    console.log(`   L1: ${address}`);
    console.log(`   L2: ${l2Address}`);
    
    // Step 4: Generate SSS recovery shares
    // Use the private key seed (32 bytes) for splitting
    const seedHex = bytesToHex(keypair.privateKey.slice(0, 32));
    const recoveryShares = await walletRecovery.createRecoveryShares(seedHex, pin, serverKey);
    console.log('🔀 Generated SSS recovery shares (2-of-3 threshold)');
    console.log('   Share 1: Server (encrypted with server key)');
    console.log('   Share 2: Cloud (encrypted with PIN)');
    console.log('   Share 3: Email (encrypted with PIN)');
    
    // Step 5: Encrypt mnemonic with wallet key (standard vault)
    const vaultContents = {
      mnemonic: mnemonic,
      created_at: Date.now(),
      version: 2,
      public_key: keypair.publicKeyHex,
      has_recovery: true
    };
    const { encrypted_blob, nonce } = await encryptVault(vaultContents, walletKey);
    
    // Create wallet instance
    const wallet = new UnifiedWallet({
      name: username,
      address: address,
      public_key: keypair.publicKeyHex,
      private_key: seedHex,
      email: email,
      username: username
    });
    
    // Store internal state
    wallet._mnemonic = mnemonic;
    wallet._salt = salt;
    wallet._walletKey = walletKey;
    wallet._isUnlocked = true;
    
    // Step 6: Register with Supabase (if available)
    const supabase = options.supabaseClient || wallet.supabase;
    if (supabase) {
      try {
        // Create auth user
        const { data: authData, error: authError } = await supabase.auth.signUp({
          email,
          password: loginPassword,
          options: { data: { username } }
        });
        if (authError) throw authError;
        
        // Create wallet record with server recovery share
        const { error: walletError } = await supabase
          .from('wallets')
          .insert({
            user_id: authData.user.id,
            email: email,
            public_key: keypair.publicKeyHex,
            address: address,
            encrypted_private_key: encrypted_blob,
            server_recovery_share: JSON.stringify(recoveryShares.serverShare),
            recovery_share_version: 1,
            needs_recovery: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          });
        
        if (walletError) throw walletError;
        
        console.log('✅ Registered with Supabase + SSS recovery');
      } catch (err) {
        console.error('❌ Supabase registration failed:', err.message);
        throw new Error(`Database error: ${err.message}`);
      }
    }
    
    // Try to register on L1
    try {
      await fetch(`${CONFIG.L1_URL}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          address: address,
          public_key: keypair.publicKeyHex
        })
      });
      console.log('✅ Registered on L1');
    } catch (err) {
      console.warn('⚠️  L1 registration skipped (server offline)');
    }
    
    await wallet.refresh();
    
    return {
      wallet,
      mnemonic,
      cloudShare: recoveryShares.cloudShare,
      emailShare: recoveryShares.emailShare,
      // serverShare is NOT returned (stays on server)
    };
  }
          public_key: keypair.publicKeyHex
        })
      });
    } catch {
      // L1 may not be running
    }
    
    await wallet.refresh();
    
    // Create backup files
    const cloudBackup = walletRecovery.createCloudBackupFile(
      recoveryShares.cloudShare, 
      address, 
      email
    );
    const emailBackup = walletRecovery.createEmailBackupContent(
      recoveryShares.emailShare,
      address
    );
    
    console.log('');
    console.log('✅ WALLET CREATED WITH SSS RECOVERY');
    console.log('═══════════════════════════════════════════════════════════');
    console.log(`Address: ${address}`);
    console.log('');
    console.log('⚠️  SAVE YOUR RECOVERY PIN: ' + pin);
    console.log('⚠️  Save cloudBackup to Google Drive/iCloud');
    console.log('⚠️  Keep emailBackup email for emergency');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('');
    
    return { 
      wallet, 
      mnemonic,
      cloudBackup,
      emailBackup,
      serverShareStored: true
    };
  }

  /**
   * Check if wallet needs recovery (after Supabase password reset)
   * @param {string} usernameOrEmail - Username or email
   * @param {Object} [supabaseClient] - Optional Supabase client
   * @returns {Promise<{needsRecovery: boolean, hasRecoveryShares: boolean, email: string}>}
   */
  static async checkRecoveryStatus(usernameOrEmail, supabaseClient = null) {
    const supabase = supabaseClient || (CONFIG.SUPABASE_URL && CONFIG.SUPABASE_KEY 
      ? createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_KEY) 
      : null);
    
    if (!supabase) {
      throw new Error('Supabase client required');
    }
    
    const isEmail = usernameOrEmail.includes('@');
    const query = isEmail
      ? supabase.from('profiles').select('needs_recovery, server_recovery_share, recovery_share_version, email').eq('email', usernameOrEmail).single()
      : supabase.from('profiles').select('needs_recovery, server_recovery_share, recovery_share_version, email').eq('user_id', usernameOrEmail).single();
    
    const { data, error } = await query;
    
    if (error || !data) {
      throw new Error('User not found');
    }
    
    return {
      needsRecovery: data.needs_recovery === true,
      hasRecoveryShares: !!data.server_recovery_share,
      shareVersion: data.recovery_share_version || 0,
      email: data.email
    };
  }

  /**
   * Recover wallet after Supabase password reset using SSS
   * Requires: PIN + backup share (cloud or email)
   * 
   * @param {string} usernameOrEmail - Username or email
   * @param {string} newPassword - New password (already set in Supabase)
   * @param {string} pin - User's 6-digit recovery PIN
   * @param {string} backupShare - Encrypted backup share (from cloud or email)
   * @param {Object} [supabaseClient] - Optional Supabase client
   * @param {Object} [options] - Additional options
   * @param {string} [options.serverKey] - Server decryption key (uses env if not provided)
   * @returns {Promise<UnifiedWallet>}
   * 
   * @example
   *   // After Supabase password reset
   *   const wallet = await UnifiedWallet.recoverWithBackup(
   *     'alice@example.com',
   *     'NewPassword456!',
   *     '123456',
   *     cloudBackupShare
   *   );
   */
  static async recoverWithBackup(usernameOrEmail, newPassword, pin, backupShare, supabaseClient = null, options = {}) {
    if (!walletRecovery) {
      throw new Error('SSS recovery module not loaded');
    }
    
    console.log(`🔄 Recovering wallet for: ${usernameOrEmail}`);
    
    const supabase = supabaseClient || (CONFIG.SUPABASE_URL && CONFIG.SUPABASE_KEY 
      ? createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_KEY) 
      : null);
    
    if (!supabase) {
      throw new Error('Supabase client required');
    }
    
    // Step 1: Fetch profile with server share
    const isEmail = usernameOrEmail.includes('@');
    const query = isEmail
      ? supabase.from('profiles').select('*').eq('email', usernameOrEmail).single()
      : supabase.from('profiles').select('*').eq('user_id', usernameOrEmail).single();
    
    const { data: profile, error: profileError } = await query;
    
    if (profileError || !profile) {
      throw new Error('User not found');
    }
    
    if (!profile.server_recovery_share) {
      throw new Error('No recovery shares found. Wallet was created without SSS recovery.');
    }
    
    console.log('📋 Fetched profile with server share');
    
    // Step 2: Recover seed using SSS
    let recoveredSeedHex;
    try {
      recoveredSeedHex = await walletRecovery.recoverSeedFromShares(
        profile.server_recovery_share,
        backupShare,
        pin,
        options.serverKey
      );
      console.log('🔀 Seed recovered from SSS shares');
    } catch (e) {
      throw new Error('Recovery failed: ' + e.message + ' (wrong PIN or invalid backup?)');
    }
    
    // Step 3: Reconstruct keypair from recovered seed
    const seedBytes = new Uint8Array(
      recoveredSeedHex.match(/.{2}/g).map(byte => parseInt(byte, 16))
    );
    const keypair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    const publicKeyHex = Array.from(keypair.publicKey, b => b.toString(16).padStart(2, '0')).join('');
    const privateKeyHex = Array.from(keypair.secretKey, b => b.toString(16).padStart(2, '0')).join('');
    
    console.log('🔑 Keypair reconstructed from seed');
    
    // Step 4: Generate addresses
    const addresses = UnifiedWallet.generateAddresses(publicKeyHex);
    
    // Step 5: Generate new wallet key from new password
    const passwordFork = await UnifiedWallet.forkPassword(newPassword);
    
    // Step 6: Create new vault (encrypted with new password's wallet key)
    const vault = {
      publicKey: publicKeyHex,
      privateKey: privateKeyHex,
      l1Address: addresses.l1Address,
      l2Address: addresses.l2Address,
      version: '2.0.0',
      recoveredAt: new Date().toISOString(),
    };
    
    // Encrypt vault with new wallet key
    const vaultJson = JSON.stringify(vault);
    const encryptedVault = CryptoJS.AES.encrypt(vaultJson, passwordFork.walletKey).toString();
    
    console.log('🔐 New vault encrypted with new password');
    
    // Step 7: Update database with new encrypted vault
    const { error: updateError } = await supabase
      .from('profiles')
      .update({
        encrypted_private_key: encryptedVault,
        needs_recovery: false,
        recovered_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      })
      .eq('user_id', profile.user_id);
    
    if (updateError) {
      throw new Error('Failed to update wallet: ' + updateError.message);
    }
    
    console.log('✅ Wallet recovered and re-encrypted successfully');
    
    // Step 8: Create wallet instance
    const walletData = {
      l1Address: addresses.l1Address,
      l2Address: addresses.l2Address,
      publicKey: publicKeyHex,
      keypair: keypair,
      passwordFork: passwordFork,
      encryptedVault: encryptedVault,
      supabaseClient: supabase,
    };
    
    return new UnifiedWallet(walletData);
      'In production, split the mnemonic directly in SSS shares.');
  }

  /**
   * Add SSS recovery to an existing wallet (for migration)
   * Requires wallet to be unlocked (has mnemonic)
   * 
   * @param {string} pin - 6-digit recovery PIN
   * @param {Object} [options] - Additional options
   * @returns {Promise<{cloudBackup: string, emailBackup: string}>}
   */
  async enableRecovery(pin, options = {}) {
    if (!walletRecovery) {
      throw new Error('SSS recovery module not loaded');
    }
    
    if (!this._mnemonic) {
      throw new Error('Wallet must be unlocked to enable recovery');
    }
    
    if (!walletRecovery.validatePIN(pin)) {
      throw new Error('PIN must be 4-8 digits');
    }
    
    console.log('🔀 Enabling SSS recovery for existing wallet...');
    
    // Create recovery shares from mnemonic
    const seedHex = CryptoJS.SHA256(this._mnemonic).toString(CryptoJS.enc.Hex);
    const recoveryShares = walletRecovery.createRecoveryShares(seedHex, pin, options.serverKey);
    
    // Store server share in Supabase
    if (this.supabase) {
      const { error } = await this.supabase
        .from('profiles')
        .update({
          server_recovery_share: recoveryShares.serverShare,
          recovery_share_version: recoveryShares.shareVersion,
          needs_recovery: false
        })
        .eq('user_id', this.userId || this.username);
      
      if (error) {
        throw new Error('Failed to store server share: ' + error.message);
      }
    }
    
    // Create backup files
    const cloudBackup = walletRecovery.createCloudBackupFile(
      recoveryShares.cloudShare,
      this.address,
      this.email
    );
    const emailBackup = walletRecovery.createEmailBackupContent(
      recoveryShares.emailShare,
      this.address
    );
    
    console.log('✅ SSS recovery enabled');
    console.log('⚠️  Remember your PIN: ' + pin);
    
    return {
      cloudBackup,
      emailBackup
    };
  }

  /**
   * Change password (when user knows old password)
   * Re-encrypts vault with new password
   * 
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<void>}
   */
  async changePassword(oldPassword, newPassword) {
    if (!this._salt) {
      throw new Error('Salt not set');
    }
    if (!this._mnemonic) {
      throw new Error('Wallet must be unlocked');
    }
    if (!this.supabase) {
      throw new Error('Supabase client required');
    }
    
    console.log('🔄 Changing password...');
    
    // Verify old password
    const { loginPassword: oldLogin, walletKey: oldWalletKey } = forkPassword(oldPassword, this._salt);
    
    // This will fail if old password is wrong
    const { error: authError } = await this.supabase.auth.signInWithPassword({
      email: this.email,
      password: oldLogin
    });
    if (authError) {
      throw new Error('Current password is incorrect');
    }
    
    // Generate new keys with same salt
    const { loginPassword: newLogin, walletKey: newWalletKey } = forkPassword(newPassword, this._salt);
    
    // Re-encrypt vault with new wallet key
    const vaultContents = {
      mnemonic: this._mnemonic,
      created_at: Date.now(),
      version: 2,
      public_key: this.publicKey,
      has_recovery: true
    };
    const { encrypted_blob, nonce } = await encryptVault(vaultContents, newWalletKey);
    const encryptedBlobJson = JSON.stringify({
      cipher: encrypted_blob,
      nonce,
      version: 2,
      created_at: Date.now()
    });
    
    // Update Supabase auth password
    const { error: updateAuthError } = await this.supabase.auth.updateUser({
      password: newLogin
    });
    if (updateAuthError) {
      throw new Error('Failed to update auth password: ' + updateAuthError.message);
    }
    
    // Update encrypted blob
    const { error: updateError } = await this.supabase
      .from('profiles')
      .update({ encrypted_blob: encryptedBlobJson })
      .eq('user_id', this.userId || this.username);
    
    if (updateError) {
      throw new Error('Failed to update vault: ' + updateError.message);
    }
    
    // Update instance
    this._walletKey = newWalletKey;
    
    console.log('✅ Password changed successfully');
  }

  // ==========================================================================
  // INSTANCE WALLET OPERATIONS (for existing logged-in users)
  // ==========================================================================

  /**
   * Create a new wallet for an existing logged-in user
   * Requires salt and walletKey to be set on the instance
   * @param {number} [wordCount=12] - Mnemonic word count (12 or 24)
   * @returns {Promise<{mnemonic: string, l1Address: string, publicKey: string}>}
   */
  async createWallet(wordCount = 12) {
    if (!this._salt) {
      throw new Error('Salt not set. Set wallet.salt before calling createWallet()');
    }
    if (!this._walletKey) {
      throw new Error('Wallet key not set. Set wallet.walletKey before calling createWallet()');
    }

    console.log(`📜 Generating ${wordCount}-word mnemonic...`);
    
    // Generate BIP-39 mnemonic
    const mnemonic = generateMnemonic(wordCount);
    
    // Derive keypair from mnemonic
    const keypair = deriveKeypairFromMnemonic(mnemonic);
    const address = generateL1Address(keypair.publicKeyHex);
    
    console.log(`🔑 Derived address: ${address}`);
    
    // Store on instance
    this._mnemonic = mnemonic;
    this.address = address;
    this.publicKey = keypair.publicKeyHex;
    this._privateKey = keypair.privateKey;
    this._publicKey = keypair.publicKey;
    this._isUnlocked = true;
    
    return {
      mnemonic: mnemonic,
      l1Address: address,
      publicKey: keypair.publicKeyHex
    };
  }

  /**
   * Encrypt and store the wallet vault in Supabase
   * Requires mnemonic and walletKey to be set
   * @returns {Promise<{success: boolean, l1Address: string, encryptedBlob: string}>}
   */
  async storeEncryptedVault() {
    if (!this._mnemonic) {
      throw new Error('No mnemonic set. Call createWallet() first.');
    }
    if (!this._walletKey) {
      throw new Error('Wallet key not set.');
    }
    if (!this.supabase) {
      throw new Error('Supabase client not set.');
    }

    console.log('🔐 Encrypting vault...');
    
    // Create vault contents
    const vaultContents = {
      mnemonic: this._mnemonic,
      created_at: Date.now(),
      version: 2,
      public_key: this.publicKey
    };
    
    // Encrypt with wallet key
    const { encrypted_blob, nonce } = await encryptVault(vaultContents, this._walletKey);
    const encryptedBlobJson = JSON.stringify({
      cipher: encrypted_blob,
      nonce,
      version: 2,
      created_at: Date.now()
    });
    
    console.log('💾 Storing encrypted vault...');
    
    // Update profile with encrypted blob and address
    const { error } = await this.supabase
      .from('profiles')
      .update({
        encrypted_blob: encryptedBlobJson,
        blackbook_address: this.address
      })
      .eq('user_id', this.userId || this.username);
    
    if (error) {
      console.error('Failed to store vault:', error);
      throw new Error(`Failed to store encrypted vault: ${error.message}`);
    }
    
    console.log('✅ Vault stored successfully');
    
    return {
      success: true,
      l1Address: this.address,
      encryptedBlob: encryptedBlobJson
    };
  }

  /**
   * Unlock wallet by decrypting the vault from Supabase
   * Requires salt and walletKey to be set
   * @returns {Promise<{blackbookAddress: string, l1Address: string}>}
   */
  async unlockWallet() {
    if (!this._walletKey) {
      throw new Error('Wallet key not set. Set wallet.walletKey before calling unlockWallet()');
    }
    if (!this.supabase) {
      throw new Error('Supabase client not set.');
    }

    console.log('🔓 Unlocking wallet...');
    
    // Fetch encrypted blob from profile
    const { data: profile, error } = await this.supabase
      .from('profiles')
      .select('encrypted_blob, blackbook_address, user_id')
      .eq('user_id', this.userId || this.username)
      .single();
    
    if (error || !profile) {
      throw new Error('Could not find profile');
    }
    
    if (!profile.encrypted_blob) {
      throw new Error('No encrypted vault found. Please create a wallet first.');
    }
    
    // Parse and decrypt
    const parsed = JSON.parse(profile.encrypted_blob);
    const vaultContents = decryptVault(parsed.cipher, parsed.nonce, this._walletKey);
    
    console.log('🔓 Vault decrypted');
    
    // Derive keypair from mnemonic
    const keypair = deriveKeypairFromMnemonic(vaultContents.mnemonic);
    const address = profile.blackbook_address || generateL1Address(keypair.publicKeyHex);
    
    // Set instance properties
    this._mnemonic = vaultContents.mnemonic;
    this.address = address;
    this.publicKey = keypair.publicKeyHex;
    this._privateKey = keypair.privateKey;
    this._publicKey = keypair.publicKey;
    this._isUnlocked = true;
    this.name = profile.user_id;
    
    console.log(`✅ Wallet unlocked: ${address}`);
    
    // Refresh balance
    try {
      await this.refresh();
    } catch (e) {
      // Balance refresh may fail if server is down
      console.warn('Could not refresh balance:', e.message);
    }
    
    return {
      blackbookAddress: address,
      l1Address: address
    };
  }

  /**
   * Get balance from L1 (convenience method)
   * @returns {Promise<{balance: number}>}
   */
  async getBalance() {
    await this.refresh();
    return { balance: this.balance };
  }

  /** Check if wallet is unlocked */
  get isUnlocked() {
    return this._isUnlocked && this._privateKey !== null;
  }

  /** Get mnemonic (only if unlocked) */
  get mnemonic() {
    return this._isUnlocked ? this._mnemonic : null;
  }

  /** Get private key bytes (only if unlocked) */
  get privateKey() {
    return this._isUnlocked ? this._privateKey : null;
  }

  // ==========================================================================
  // BALANCE GETTERS (Unified View)
  // ==========================================================================

  /** Total balance (what user sees in UI) = available + locked */
  get balance() {
    return this._l1Available + this._l1Locked;
  }

  /** Alias for balance */
  get totalBalance() {
    return this.balance;
  }

  /** L1 available (can transfer or bridge) */
  get available() {
    return this._l1Available;
  }

  /** Alias */
  get l1Available() {
    return this._l1Available;
  }

  /** L1 locked (bridged to L2) */
  get locked() {
    return this._l1Locked;
  }

  /** L2 balance (for betting) */
  get l2Balance() {
    return this._l2Balance;
  }

  /** Check if user has active L2 session */
  get hasL2Session() {
    return this._l2Balance > 0 || this._l1Locked > 0;
  }

  // ==========================================================================
  // SIGNING
  // ==========================================================================

  /**
   * Sign a message with ed25519 (detached signature) with domain separation
   * @param {string} message - Message to sign
   * @param {number} chainId - CHAIN_ID_L1 (0x01) or CHAIN_ID_L2 (0x02)
   * @returns {string} 128-char hex signature
   */
  sign(message, chainId = CHAIN_ID_L1) {
    if (chainId !== CHAIN_ID_L1 && chainId !== CHAIN_ID_L2) {
      throw new Error(`Invalid chain_id: 0x${chainId.toString(16)}. Must be 0x01 (L1) or 0x02 (L2)`);
    }
    
    // Domain-separated message: [chain_id][message]
    const messageBytes = new TextEncoder().encode(message);
    const domainSeparatedMessage = new Uint8Array(1 + messageBytes.length);
    domainSeparatedMessage[0] = chainId;  // <--- CRITICAL: Domain separator
    domainSeparatedMessage.set(messageBytes, 1);
    
    const signatureBytes = nacl.sign.detached(domainSeparatedMessage, this._privateKey);
    return bytesToHex(signatureBytes);
  }

  /**
   * Create a signed request for L1 or L2 API with domain separation
   * @param {Object} payload - Request payload
   * @param {number} [chainId=CHAIN_ID_L1] - Chain ID (0x01 for L1, 0x02 for L2)
   * @returns {Object} SignedRequest with chain_id
   */
  createSignedRequest(payload, chainId = CHAIN_ID_L1) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce();
    const payloadJson = JSON.stringify(payload);
    const signedContent = `${payloadJson}\n${timestamp}\n${nonce}`;
    
    return {
      public_key: this.publicKey,
      wallet_address: this.address,
      payload: payloadJson,
      timestamp,
      nonce,
      chain_id: chainId,  // <--- NEW: Domain separation
      signature: this.sign(signedContent, chainId)  // Sign with chain_id
    };
  }

  // ==========================================================================
  // BALANCE OPERATIONS
  // ==========================================================================

  /**
   * Refresh balance from servers
   */
  async refresh() {
    try {
      // Get L1 balance
      const l1Response = await fetch(`${CONFIG.L1_URL}/balance/${this.address}`);
      const l1Data = await l1Response.json();
      this._l1Available = l1Data.balance || 0;
      
      // Get L2 balance (may fail if L2 not running)
      try {
        const l2Response = await fetch(`${CONFIG.L2_URL}/balance/${this.address}`);
        if (l2Response.ok) {
          const l2Data = await l2Response.json();
          this._l2Balance = l2Data.balance || 0;
        }
      } catch {
        this._l2Balance = 0;
      }
      
      return this.getBalanceBreakdown();
    } catch (error) {
      console.error('Failed to refresh balance:', error.message);
      throw error;
    }
  }

  /** Alias for refresh */
  async refreshBalance() {
    return this.refresh();
  }

  /**
   * Get balance breakdown (formatted for UI)
   */
  getBalanceBreakdown() {
    return {
      total: this.balance,
      available: this._l1Available,
      locked: this._l1Locked,
      l2_gaming: this._l2Balance,
      canBridge: this._l1Available > 0,
      canWithdraw: this._l2Balance > 0
    };
  }

  // ==========================================================================
  // L1 OPERATIONS
  // ==========================================================================

  /**
   * Transfer tokens on L1
   * @param {string} to - Recipient address
   * @param {number} amount - Amount to transfer
   */
  async transfer(to, amount) {
    if (amount > this._l1Available) {
      throw new Error(`Insufficient balance. Available: ${this._l1Available} BB, Need: ${amount} BB`);
    }
    
    const signedRequest = this.createSignedRequest({ to, amount });
    
    const response = await fetch(`${CONFIG.L1_URL}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    const result = await response.json();
    
    if (result.success) {
      await this.refresh();
      console.log(`✅ Transferred ${amount} BB to ${to}`);
    }
    
    return result;
  }

  // ==========================================================================
  // BRIDGE OPERATIONS (L1 ↔ L2)
  // ==========================================================================

  /**
   * Bridge funds from L1 to L2
   * Locks funds on L1, credits L2 for betting
   * @param {number} amount - Amount to bridge
   */
  async bridgeToL2(amount) {
    if (amount > this._l1Available) {
      throw new Error(`Insufficient balance. Available: ${this._l1Available} BB, Need: ${amount} BB`);
    }
    
    console.log(`🌉 Bridging ${amount} BB to L2...`);
    
    const signedRequest = this.createSignedRequest({
      target_address: this.address,
      amount: amount,
      target_layer: 'L2'
    });
    
    const response = await fetch(`${CONFIG.L1_URL}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    const result = await response.json();
    
    if (result.success) {
      // Update local state
      this._l1Available -= amount;
      this._l1Locked += amount;
      this._l2Balance += amount;
      
      // Also credit L2 directly
      await this._creditL2(amount);
      
      console.log(`✅ Bridge complete!`);
      console.log(`   L1 Available: ${this._l1Available} BB`);
      console.log(`   L1 Locked:    ${this._l1Locked} BB`);
      console.log(`   L2 Balance:   ${this._l2Balance} BB`);
    } else {
      console.error(`❌ Bridge failed:`, result.error);
    }
    
    return result;
  }

  /**
   * Withdraw funds from L2 back to L1
   * Settles L2 balance (with profit/loss) and unlocks on L1
   * @param {number} [amount] - Amount to withdraw (default: all)
   */
  async withdraw(amount = null) {
    const withdrawAmount = amount || this._l2Balance;
    
    if (withdrawAmount <= 0) {
      throw new Error('Nothing to withdraw. L2 balance is 0.');
    }
    
    if (withdrawAmount > this._l2Balance) {
      throw new Error(`Insufficient L2 balance. Available: ${this._l2Balance} BB`);
    }
    
    console.log(`🏦 Withdrawing ${withdrawAmount} BB from L2...`);
    
    // Calculate profit/loss
    const profitLoss = withdrawAmount - this._l1Locked;
    
    const response = await fetch(`${CONFIG.L1_URL}/bridge/withdraw`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_address: this.address,
        amount: withdrawAmount,
        l2_burn_tx: `burn_${Date.now()}`,
        l2_signature: 'dev_mode'
      })
    });
    
    const result = await response.json();
    
    if (result.success) {
      // Update local state
      this._l2Balance -= withdrawAmount;
      this._l1Locked = 0;
      
      await this.refresh();
      
      console.log(`✅ Withdrawal complete!`);
      console.log(`   Profit/Loss: ${profitLoss >= 0 ? '+' : ''}${profitLoss} BB`);
      console.log(`   L1 Balance:  ${this.balance} BB`);
    } else {
      console.error(`❌ Withdrawal failed:`, result.error);
    }
    
    return result;
  }

  /** Alias for withdraw */
  async withdrawToL1(amount = null) {
    return this.withdraw(amount);
  }

  /**
   * Credit L2 balance (called after successful bridge)
   * @private
   * @deprecated L2 credit is now handled by the bridge endpoint itself
   */
  async _creditL2(amount) {
    // No-op: L2 credit is handled by the bridge endpoint on the backend
    // This function is kept for backwards compatibility
    return;
  }

  // ==========================================================================
  // L2 BETTING OPERATIONS
  // ==========================================================================

  /**
   * Get all available markets
   */
  async getMarkets() {
    try {
      const response = await fetch(`${CONFIG.L2_URL}/markets`);
      const data = await response.json();
      return data.markets || [];
    } catch {
      return [];
    }
  }

  // ==========================================================================
  // INTENT-BASED BETTING (v2 Settlement Protocol)
  // ==========================================================================

  /**
   * Place a bet using the new intent-based settlement system
   * This is INSTANT - dealer fronts funds immediately
   * 
   * @param {string} marketId - Market ID to bet on
   * @param {string} outcome - "YES" or "NO"
   * @param {number} amount - Bet amount in BB
   * @param {Object} [options] - Additional options
   * @param {number} [options.minOddsBps=0] - Minimum odds (basis points, 4500 = 45%)
   * @param {number} [options.fee=0.01] - Dealer fee in BB
   * @param {number} [options.expiresIn=300] - Expiry in seconds (default 5 min)
   * @returns {Promise<Object>} Intent response with dealer_tx_hash
   * 
   * @example
   *   const result = await wallet.placeBetIntent('btc_100k', 'YES', 100, { minOddsBps: 4500 });
   *   console.log('Dealer fronted instantly:', result.dealer_tx_hash);
   */
  async placeBetIntent(marketId, outcome, amount, options = {}) {
    if (!this._isUnlocked) {
      throw new Error('Wallet must be unlocked to place bets');
    }
    
    const { minOddsBps = 0, fee = 0.01, expiresIn = 300 } = options;
    
    // Get or increment nonce
    if (!this._intentNonce) {
      try {
        const nonceData = await getNextNonce(this._publicKey);
        this._intentNonce = nonceData.next_nonce;
      } catch {
        this._intentNonce = 1;
      }
    }
    const nonce = this._intentNonce++;
    
    const privateKey = this._privateKey.slice(0, 32);
    const publicKey = this._publicKey;
    
    const intent = createIntent({
      privateKey,
      publicKey,
      nonce,
      amount,
      fee,
      expiresInSeconds: expiresIn,
      action: {
        bet: {
          market_id: marketId,
          outcome: outcome.toUpperCase(),
          min_odds_bps: minOddsBps
        }
      }
    });
    
    console.log(`🎲 Submitting bet intent: ${amount} BB on ${marketId} ${outcome}`);
    
    const result = await submitIntent(intent);
    
    if (result.success) {
      console.log(`✅ Bet accepted! Dealer fronted ${result.dealer_fronted_amount / 1_000_000} BB`);
      console.log(`   Intent ID: ${result.intent_id}`);
      console.log(`   L2 TX: ${result.dealer_tx_hash}`);
    } else {
      console.error(`❌ Bet rejected: ${result.error}`);
    }
    
    return result;
  }

  /**
   * Transfer using intent-based settlement (instant)
   * @param {string} recipientPubkey - Recipient's public key (hex)
   * @param {number} amount - Amount in BB
   * @param {string} [memo=''] - Optional memo
   * @returns {Promise<Object>} Intent response
   */
  async transferIntent(recipientPubkey, amount, memo = '') {
    if (!this._isUnlocked) {
      throw new Error('Wallet must be unlocked to transfer');
    }
    
    if (!this._intentNonce) {
      try {
        const nonceData = await getNextNonce(this._publicKey);
        this._intentNonce = nonceData.next_nonce;
      } catch {
        this._intentNonce = 1;
      }
    }
    const nonce = this._intentNonce++;
    
    const privateKey = this._privateKey.slice(0, 32);
    const publicKey = this._publicKey;
    
    const recipientBytes = typeof recipientPubkey === 'string' 
      ? hexToBytes(recipientPubkey) 
      : recipientPubkey;
    
    const intent = createIntent({
      privateKey,
      publicKey,
      nonce,
      amount,
      action: {
        transfer: {
          recipient_pubkey: recipientBytes,
          memo
        }
      }
    });
    
    console.log(`💸 Submitting transfer intent: ${amount} BB to ${recipientPubkey.slice(0, 16)}...`);
    
    return submitIntent(intent);
  }

  /**
   * Get current nonce and pending intent status
   * @returns {Promise<{next_nonce: number, pending_intent_count: number}>}
   */
  async getIntentStatus() {
    if (!this._publicKey) {
      throw new Error('Wallet not initialized');
    }
    return getNextNonce(this._publicKey);
  }

  /**
   * Place a bet on L2 (legacy method - now uses intent system)
   * @param {string} marketId - Market ID
   * @param {string} option - "yes" or "no"
   * @param {number} amount - Amount in BB
   * @returns {Promise<Object>}
   */
  async placeBet(marketId, option, amount) {
    // Use the new intent-based system
    return this.placeBetIntent(marketId, option, amount);
  }

  /**
   * Get user's bet history
   */
  async getBets() {
    try {
      const response = await fetch(`${CONFIG.L2_URL}/bets/${this.address}`);
      return await response.json();
    } catch {
      return [];
    }
  }

  // ==========================================================================
  // TRANSACTION HISTORY
  // ==========================================================================

  /**
   * Get transaction history from L1
   * @param {number} [limit=50] - Maximum transactions to return
   * @returns {Promise<Array>} Transaction list
   */
  async getTransactions(limit = 50) {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/transactions/${this.address}?limit=${limit}`);
      if (!response.ok) {
        return [];
      }
      const data = await response.json();
      return data.transactions || data || [];
    } catch {
      return [];
    }
  }

  /**
   * Get transaction details by ID
   * @param {string} txId - Transaction ID
   * @returns {Promise<Object|null>}
   */
  async getTransaction(txId) {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/transaction/${txId}`);
      if (!response.ok) return null;
      return await response.json();
    } catch {
      return null;
    }
  }

  // ==========================================================================
  // BRIDGE STATUS & SETTLEMENTS
  // ==========================================================================

  /**
   * Get bridge transaction status
   * @param {string} bridgeId - Bridge transaction ID
   * @returns {Promise<Object>}
   */
  async getBridgeStatus(bridgeId) {
    const response = await fetch(`${CONFIG.L1_URL}/bridge/status/${bridgeId}`);
    return await response.json();
  }

  /**
   * Get bridge statistics
   * @returns {Promise<Object>} Bridge stats
   */
  async getBridgeStats() {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/bridge/stats`);
      return await response.json();
    } catch {
      return { total_bridged: 0, total_withdrawn: 0, active_sessions: 0 };
    }
  }

  /**
   * Claim a Merkle settlement from L2
   * @param {string} rootHash - Merkle root hash
   * @param {Array<string>} proof - Merkle proof
   * @param {number} amount - Amount to claim
   * @returns {Promise<Object>}
   */
  async claimSettlement(rootHash, proof, amount) {
    const signedRequest = this.createSignedRequest({
      root_hash: rootHash,
      proof: proof,
      amount: amount,
      claimer: this.address
    });

    const response = await fetch(`${CONFIG.L1_URL}/bridge/claim`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });

    const result = await response.json();
    
    if (result.success) {
      await this.refresh();
      console.log(`✅ Claimed settlement: ${amount} BB`);
    }
    
    return result;
  }

  // ==========================================================================
  // WALLET & SYSTEM INFO
  // ==========================================================================

  /**
   * Get authenticated wallet info from server
   * @returns {Promise<Object>}
   */
  async getWalletInfo() {
    const signedRequest = this.createSignedRequest({ action: 'get_info' });
    
    const response = await fetch(`${CONFIG.L1_URL}/wallet/info`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    return await response.json();
  }

  /**
   * Get blockchain statistics
   * @returns {Promise<Object>}
   */
  async getStats() {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/stats`);
      return await response.json();
    } catch {
      return { blocks: 0, transactions: 0, accounts: 0 };
    }
  }

  /**
   * Health check - verify L1 connection
   * @returns {Promise<boolean>}
   */
  async health() {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  /**
   * Health check for L2
   * @returns {Promise<boolean>}
   */
  async healthL2() {
    try {
      const response = await fetch(`${CONFIG.L2_URL}/health`);
      return response.ok;
    } catch {
      return false;
    }
  }

  // ==========================================================================
  // SESSION MANAGEMENT (Alternative to Bridge)
  // ==========================================================================

  /**
   * Start an L2 session (mirrors L1 balance for instant L2 play)
   * Unlike bridge, this doesn't lock funds - it creates a "session"
   * @param {number} [depositAmount=0] - Optional initial deposit
   * @returns {Promise<Object>}
   */
  async startSession(depositAmount = 0) {
    const signedRequest = this.createSignedRequest({
      deposit: depositAmount,
      session_type: 'gaming'
    });

    const response = await fetch(`${CONFIG.L1_URL}/session/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });

    const result = await response.json();
    
    if (result.success || result.session_id) {
      console.log(`🎮 Session started: ${result.session_id || 'active'}`);
      await this.refresh();
    }
    
    return result;
  }

  /**
   * Get current session status
   * @param {string} [address] - Address to check (default: this wallet)
   * @returns {Promise<Object>}
   */
  async getSessionStatus(address = null) {
    const addr = address || this.address;
    try {
      const response = await fetch(`${CONFIG.L1_URL}/session/status/${addr}`);
      return await response.json();
    } catch {
      return { active: false, balance: 0 };
    }
  }

  /**
   * Settle L2 session - write profit/loss back to L1
   * @returns {Promise<Object>}
   */
  async settleSession() {
    const signedRequest = this.createSignedRequest({
      action: 'settle',
      final_balance: this._l2Balance
    });

    const response = await fetch(`${CONFIG.L1_URL}/session/settle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });

    const result = await response.json();
    
    if (result.success) {
      console.log(`📊 Session settled. P/L: ${result.profit_loss || 0} BB`);
      await this.refresh();
    }
    
    return result;
  }

  /**
   * List all active sessions (admin/debugging)
   * @returns {Promise<Array>}
   */
  async listSessions() {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/session/list`);
      const data = await response.json();
      return data.sessions || [];
    } catch {
      return [];
    }
  }

  // ==========================================================================
  // ADVANCED: POH & RPC
  // ==========================================================================

  /**
   * Get Proof of History status
   * @returns {Promise<Object>}
   */
  async getPoHStatus() {
    try {
      const response = await fetch(`${CONFIG.L1_URL}/poh/status`);
      return await response.json();
    } catch {
      return { tick: 0, hash: null, running: false };
    }
  }

  /**
   * Make raw RPC call to L1
   * @param {string} method - RPC method name
   * @param {Object} [params={}] - RPC parameters
   * @returns {Promise<Object>}
   */
  async rpc(method, params = {}) {
    const response = await fetch(`${CONFIG.L1_URL}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: Date.now(),
        method: method,
        params: params
      })
    });

    const result = await response.json();
    
    if (result.error) {
      throw new Error(result.error.message || JSON.stringify(result.error));
    }
    
    return result.result;
  }

  // ==========================================================================
  // STATIC HELPER METHODS
  // ==========================================================================

  /**
   * Generate a random keypair (without creating full wallet)
   * @returns {{address: string, publicKey: string, privateKey: string}}
   */
  static generateRandomKeypair() {
    if (typeof crypto === 'undefined' || !crypto.getRandomValues) {
      throw new Error(
        'Secure random number generator not available. ' +
        'Use a modern browser with Web Crypto API or Node.js 15+.'
      );
    }
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const publicKeyHex = bytesToHex(keyPair.publicKey);
    const address = generateL1Address(publicKeyHex);
    
    return {
      address: address,
      publicKey: publicKeyHex,
      privateKey: bytesToHex(seed)
    };
  }

  /**
   * Derive public key from private key
   * @param {string} privateKeyHex - 64-char hex private key (32-byte seed)
   * @returns {string} 64-char hex public key
   */
  static derivePublicKey(privateKeyHex) {
    const seed = hexToBytes(privateKeyHex);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    return bytesToHex(keyPair.publicKey);
  }

  /**
   * Generate L1 address from public key
   * @param {string} publicKeyHex - 64-char hex public key
   * @returns {string} L1 address (L1 + 14 hex chars)
   */
  static generateAddress(publicKeyHex) {
    return generateL1Address(publicKeyHex);
  }

  /**
   * Validate a mnemonic phrase
   * @param {string} mnemonic - 12 or 24 word phrase
   * @returns {boolean}
   */
  static validateMnemonic(mnemonic) {
    return validateMnemonic(mnemonic);
  }

  /**
   * Get the SDK configuration
   * @returns {Object}
   */
  static getConfig() {
    return { ...CONFIG };
  }

  /**
   * Update SDK configuration
   * @param {Object} newConfig - New config values
   */
  static setConfig(newConfig) {
    Object.assign(CONFIG, newConfig);
  }

  // ==========================================================================
  // DISPLAY HELPERS
  // ==========================================================================

  /**
   * Print wallet status to console
   */
  print() {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║  ${this.name.padEnd(52)} ║
║  ${this.address.padEnd(52)} ║
╠═══════════════════════════════════════════════════════════╣
║  💰 TOTAL BALANCE: ${String(this.balance + ' BB').padEnd(35)} ║
║  ─────────────────────────────────────────────────────── ║
║  L1 Available:  ${String(this._l1Available + ' BB').padEnd(38)} ║
║  L1 Locked:     ${String(this._l1Locked + ' BB').padEnd(38)} ║
║  L2 Gaming:     ${String(this._l2Balance + ' BB').padEnd(38)} ║
╚═══════════════════════════════════════════════════════════╝
`);
  }

  /** Alias for print */
  printStatus() {
    this.print();
  }

  /**
   * Export wallet info as JSON
   */
  toJSON() {
    return {
      name: this.name,
      address: this.address,
      username: this.username,
      email: this.email,
      balance: {
        total: this.balance,
        l1_available: this._l1Available,
        l1_locked: this._l1Locked,
        l2_gaming: this._l2Balance
      }
    };
  }
}

// ============================================================================
// DEMO FUNCTION - Run: bun unified-wallet-sdk.js
// ============================================================================

export async function demo() {
  console.log(`
╔═══════════════════════════════════════════════════════════╗
║         UNIFIED WALLET SDK - DEMO                         ║
╚═══════════════════════════════════════════════════════════╝
`);

  // 1. Connect Alice
  console.log('📱 Step 1: Connecting Alice...\n');
  const alice = await UnifiedWallet.connect('alice');
  alice.print();
  
  // 2. Bridge to L2
  console.log('🌉 Step 2: Bridging 5,000 BB to L2...\n');
  await alice.bridgeToL2(5000);
  alice.print();
  
  // 3. Simulate betting win
  console.log('🎰 Step 3: Simulating bet + win (+1,500 BB)...\n');
  alice._l2Balance += 1500;  // Simulated win
  console.log('   Alice won 1500 BB!');
  alice.print();
  
  // 4. Withdraw
  console.log('🏦 Step 4: Withdrawing to L1...\n');
  await alice.withdraw();
  alice.print();
  
  // 5. Transfer to Bob
  console.log('💸 Step 5: Transferring 1,000 BB to Bob...\n');
  const bob = await UnifiedWallet.connect('bob');
  await alice.transfer(bob.address, 1000);
  
  console.log('Final balances:');
  await alice.refresh();
  await bob.refresh();
  alice.print();
  bob.print();
  
  console.log('✅ Demo complete!\n');
}

// ============================================================================
// INTENT BUILDER - For gRPC Settlement Protocol (v2)
// ============================================================================
//
// The new settlement system uses signed "intents" instead of direct transfers:
// 1. User signs intent ("I owe 100 BB for this bet")
// 2. Dealer fronts funds instantly on L2
// 3. Batch settlement happens async on L1
//
// OPTIMIZATIONS:
// - Uses raw bytes (not hex strings) - 50% bandwidth savings
// - Typed actions (no JSON parsing overhead)
// - expires_at prevents zombie intents
// - fee_lamports incentivizes dealers

/**
 * Intent action types for the settlement protocol
 */
const IntentActionType = {
  BET: 'bet',
  TRANSFER: 'transfer',
  TRADE: 'trade',
  LIQUIDITY: 'liquidity',
  STAKE: 'stake'
};

/**
 * Create a signed intent for the settlement protocol
 * @param {Object} params - Intent parameters
 * @param {Uint8Array} params.privateKey - User's private key (32 bytes)
 * @param {Uint8Array} params.publicKey - User's public key (32 bytes)
 * @param {number} params.nonce - Monotonically increasing nonce
 * @param {number} params.amount - Amount in BB (will be converted to lamports)
 * @param {number} [params.fee=0.01] - Dealer fee in BB (default 0.01 BB)
 * @param {number} [params.expiresInSeconds=300] - Expiry time (default 5 minutes)
 * @param {Object} params.action - Action object (bet, transfer, trade, etc.)
 * @param {string} [params.sessionId=''] - Optional session ID
 * @param {number} [params.chainId=CHAIN_ID_L1] - Chain ID for domain separation (1=L1, 2=L2)
 * @returns {Object} Signed intent ready for gRPC
 */
function createIntent({
  privateKey,
  publicKey,
  nonce,
  amount,
  fee = 0.01,
  expiresInSeconds = 300,
  action,
  sessionId = '',
  chainId = CHAIN_ID_L1  // Default to L1 for safety
}) {
  const now = Math.floor(Date.now() / 1000);
  const amountLamports = Math.floor(amount * 1_000_000);
  const feeLamports = Math.floor(fee * 1_000_000);
  
  // Build the intent structure
  const intent = {
    sender_pubkey: publicKey,
    nonce: nonce,
    created_at: now,
    expires_at: now + expiresInSeconds,
    amount_lamports: amountLamports,
    fee_lamports: feeLamports,
    session_id: sessionId,
    chain_id: chainId,  // Domain separation
    action: action,
    signature: null // Will be filled after signing
  };
  
  // Create message to sign (includes chain_id for domain separation)
  const message = createIntentSigningMessage(intent);
  
  // Sign with Ed25519
  const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
  const signature = nacl.sign.detached(message, keyPair.secretKey);
  
  intent.signature = signature;
  
  return intent;
}

/**
 * Create the message bytes that get signed for an intent
 * Format: chain_id || pubkey || nonce || created_at || expires_at || amount || fee || action_hash
 * 
 * SECURITY: chain_id MUST be first byte for domain separation!
 * This prevents L1 signatures from being replayed on L2 (and vice versa)
 */
function createIntentSigningMessage(intent) {
  const parts = [];
  
  // chain_id (1 byte) - DOMAIN SEPARATOR - MUST BE FIRST!
  parts.push(new Uint8Array([intent.chain_id || CHAIN_ID_L1]));
  
  // sender_pubkey (32 bytes)
  parts.push(intent.sender_pubkey);
  
  // nonce (8 bytes, big-endian)
  parts.push(uint64ToBytes(intent.nonce));
  
  // created_at (8 bytes, big-endian)
  parts.push(uint64ToBytes(intent.created_at));
  
  // expires_at (8 bytes, big-endian)
  parts.push(uint64ToBytes(intent.expires_at));
  
  // amount_lamports (8 bytes, big-endian)
  parts.push(uint64ToBytes(intent.amount_lamports));
  
  // fee_lamports (8 bytes, big-endian)
  parts.push(uint64ToBytes(intent.fee_lamports));
  
  // action_hash (32 bytes SHA256)
  parts.push(hashAction(intent.action));
  
  // Concatenate all parts
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const message = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    message.set(part, offset);
    offset += part.length;
  }
  
  return message;
}

/**
 * Convert uint64 to big-endian bytes
 */
function uint64ToBytes(value) {
  const bytes = new Uint8Array(8);
  const bigValue = BigInt(value);
  for (let i = 7; i >= 0; i--) {
    bytes[i] = Number(bigValue >> BigInt((7 - i) * 8) & BigInt(0xFF));
  }
  return bytes;
}

/**
 * Hash an action for signing
 */
function hashAction(action) {
  let actionString = '';
  
  if (action.bet) {
    actionString = `bet:${action.bet.market_id}:${action.bet.outcome}:${action.bet.min_odds_bps || 0}`;
  } else if (action.transfer) {
    const recipientHex = action.transfer.recipient_pubkey instanceof Uint8Array 
      ? bytesToHex(action.transfer.recipient_pubkey)
      : action.transfer.recipient_pubkey;
    actionString = `transfer:${recipientHex}:${action.transfer.memo || ''}`;
  } else if (action.trade) {
    actionString = `trade:${action.trade.pair}:${action.trade.is_buy}:${action.trade.limit_price}:${action.trade.min_amount_out || 0}`;
  } else if (action.liquidity) {
    actionString = `liquidity:${action.liquidity.market_id}:${action.liquidity.is_add}:${action.liquidity.amount_a}:${action.liquidity.amount_b}:${action.liquidity.min_lp_tokens || 0}`;
  } else if (action.stake) {
    actionString = `stake:${action.stake.pool_id}:${action.stake.is_stake}:${action.stake.lock_duration || 0}`;
  } else {
    actionString = 'none';
  }
  
  // SHA256 hash
  const hash = CryptoJS.SHA256(actionString);
  return hexToBytes(hash.toString(CryptoJS.enc.Hex));
}

/**
 * Create a bet intent
 * @param {Object} wallet - UnifiedWallet instance
 * @param {string} marketId - Market ID
 * @param {string} outcome - "YES" or "NO"
 * @param {number} amount - Bet amount in BB
 * @param {number} [minOddsBps=0] - Minimum odds in basis points (4500 = 45%)
 * @returns {Object} Signed bet intent
 */
async function createBetIntent(wallet, marketId, outcome, amount, minOddsBps = 0) {
  if (!wallet._isUnlocked) {
    throw new Error('Wallet must be unlocked to create intents');
  }
  
  // Get next nonce from server or local tracking
  const nonce = wallet._intentNonce || 1;
  wallet._intentNonce = nonce + 1;
  
  const privateKey = wallet._privateKey.slice(0, 32);
  const publicKey = wallet._publicKey;
  
  // Bets are typically L2 operations
  return createIntent({
    privateKey,
    publicKey,
    nonce,
    amount,
    chainId: CHAIN_ID_L2,  // Bets go to L2
    action: {
      bet: {
        market_id: marketId,
        outcome: outcome.toUpperCase(),
        min_odds_bps: minOddsBps
      }
    }
  });
}

/**
 * Create a transfer intent
 * @param {Object} wallet - UnifiedWallet instance
 * @param {string|Uint8Array} recipientPubkey - Recipient's public key
 * @param {number} amount - Amount in BB
 * @param {string} [memo=''] - Optional memo
 * @param {number} [chainId=CHAIN_ID_L1] - Chain ID (1=L1, 2=L2)
 * @returns {Object} Signed transfer intent
 */
async function createTransferIntent(wallet, recipientPubkey, amount, memo = '', chainId = CHAIN_ID_L1) {
  if (!wallet._isUnlocked) {
    throw new Error('Wallet must be unlocked to create intents');
  }
  
  const nonce = wallet._intentNonce || 1;
  wallet._intentNonce = nonce + 1;
  
  const privateKey = wallet._privateKey.slice(0, 32);
  const publicKey = wallet._publicKey;
  
  // Convert recipient to bytes if needed
  const recipientBytes = typeof recipientPubkey === 'string' 
    ? hexToBytes(recipientPubkey) 
    : recipientPubkey;
  
  return createIntent({
    privateKey,
    publicKey,
    nonce,
    amount,
    chainId,  // Transfers can be L1 or L2
    action: {
      transfer: {
        recipient_pubkey: recipientBytes,
        memo
      }
    }
  });
}

/**
 * Create a trade intent
 * @param {Object} wallet - UnifiedWallet instance
 * @param {string} pair - Trading pair (e.g., "BB/USDC")
 * @param {boolean} isBuy - true = buy, false = sell
 * @param {number} amount - Amount in BB
 * @param {number} limitPrice - Max price willing to pay (in lamports)
 * @param {number} [minAmountOut=0] - Slippage protection
 * @returns {Object} Signed trade intent
 */
async function createTradeIntent(wallet, pair, isBuy, amount, limitPrice, minAmountOut = 0) {
  if (!wallet._isUnlocked) {
    throw new Error('Wallet must be unlocked to create intents');
  }
  
  const nonce = wallet._intentNonce || 1;
  wallet._intentNonce = nonce + 1;
  
  const privateKey = wallet._privateKey.slice(0, 32);
  const publicKey = wallet._publicKey;
  
  return createIntent({
    privateKey,
    publicKey,
    nonce,
    amount,
    action: {
      trade: {
        pair,
        is_buy: isBuy,
        limit_price: limitPrice,
        min_amount_out: minAmountOut
      }
    }
  });
}

/**
 * Submit an intent to the settlement service (via REST gateway or gRPC-web)
 * @param {Object} intent - Signed intent
 * @param {string} [endpoint] - Optional custom endpoint
 * @returns {Promise<Object>} Intent response
 */
async function submitIntent(intent, endpoint = null) {
  const url = endpoint || `${CONFIG.L1_URL}/rpc/submit-intent`;
  
  // Convert intent to JSON-serializable format (hex encode bytes)
  const payload = {
    sender_pubkey: bytesToHex(intent.sender_pubkey),
    nonce: intent.nonce,
    created_at: intent.created_at,
    expires_at: intent.expires_at,
    amount_lamports: intent.amount_lamports,
    fee_lamports: intent.fee_lamports,
    session_id: intent.session_id,
    action: serializeAction(intent.action),
    signature: bytesToHex(intent.signature)
  };
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Intent submission failed: ${error}`);
  }
  
  return response.json();
}

/**
 * Serialize action for JSON transport
 */
function serializeAction(action) {
  if (action.bet) {
    return { bet: action.bet };
  } else if (action.transfer) {
    return {
      transfer: {
        recipient_pubkey: action.transfer.recipient_pubkey instanceof Uint8Array
          ? bytesToHex(action.transfer.recipient_pubkey)
          : action.transfer.recipient_pubkey,
        memo: action.transfer.memo || ''
      }
    };
  } else if (action.trade) {
    return { trade: action.trade };
  } else if (action.liquidity) {
    return { liquidity: action.liquidity };
  } else if (action.stake) {
    return { stake: action.stake };
  }
  return {};
}

/**
 * Get next nonce for a user from the settlement service
 * @param {Uint8Array|string} pubkey - User's public key
 * @param {string} [endpoint] - Optional custom endpoint
 * @returns {Promise<{next_nonce: number, pending_intent_count: number}>}
 */
async function getNextNonce(pubkey, endpoint = null) {
  const url = endpoint || `${CONFIG.L1_URL}/rpc/get-nonce`;
  const pubkeyHex = pubkey instanceof Uint8Array ? bytesToHex(pubkey) : pubkey;
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_pubkey: pubkeyHex })
  });
  
  if (!response.ok) {
    throw new Error('Failed to get nonce');
  }
  
  return response.json();
}

/**
 * Verify an intent is valid (signature + balance check)
 * @param {Object} intent - Intent to verify
 * @param {boolean} [checkBalance=true] - Whether to check L1 balance
 * @param {string} [endpoint] - Optional custom endpoint
 * @returns {Promise<Object>} Verification result
 */
async function verifyIntent(intent, checkBalance = true, endpoint = null) {
  const url = endpoint || `${CONFIG.L1_URL}/rpc/verify-intent`;
  
  const payload = {
    intent: {
      sender_pubkey: bytesToHex(intent.sender_pubkey),
      nonce: intent.nonce,
      created_at: intent.created_at,
      expires_at: intent.expires_at,
      amount_lamports: intent.amount_lamports,
      fee_lamports: intent.fee_lamports,
      session_id: intent.session_id,
      action: serializeAction(intent.action),
      signature: bytesToHex(intent.signature)
    },
    check_balance: checkBalance
  };
  
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  
  if (!response.ok) {
    throw new Error('Intent verification failed');
  }
  
  return response.json();
}

// ============================================================================
// EXPORTS
// ============================================================================

// Export accounts for direct use
export { ACCOUNTS };
export const ALICE = ACCOUNTS.alice;
export const BOB = ACCOUNTS.bob;

// Export domain separation constants (MUST match Rust identity.rs)
export { CHAIN_ID_L1, CHAIN_ID_L2 };

// Export helper functions for advanced use
export {
  forkPassword,
  generateSalt,
  deriveLoginPassword,
  deriveWalletKey,
  encryptVault,
  decryptVault,
  generateMnemonic,
  validateMnemonic,
  deriveKeypairFromMnemonic,
  generateL1Address,
  hexToBytes,
  bytesToHex
};

// Export Intent/Settlement functions (v2 protocol with domain separation)
export {
  IntentActionType,
  createIntent,
  createBetIntent,
  createTransferIntent,
  createTradeIntent,
  submitIntent,
  getNextNonce,
  verifyIntent,
  uint64ToBytes,
  hashAction
};

// Export SSS recovery module (if loaded)
export { walletRecovery };

// Browser globals
if (typeof window !== 'undefined') {
  window.UnifiedWallet = UnifiedWallet;
  window.ALICE = ALICE;
  window.BOB = BOB;
  window.CHAIN_ID_L1 = CHAIN_ID_L1;
  window.CHAIN_ID_L2 = CHAIN_ID_L2;
}

// Auto-run demo if executed directly
const isMainModule = typeof process !== 'undefined' && 
  process.argv && 
  process.argv[1]?.includes('unified-wallet-sdk');
  
if (isMainModule) {
  demo().catch(console.error);
}

export default UnifiedWallet;
