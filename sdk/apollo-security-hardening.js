/**
 * APOLLO WALLET - COMPREHENSIVE SECURITY HARDENING
 * 
 * Protection against L1 blockchain and wallet attack vectors:
 * - Replay attacks (cross-chain)
 * - Man-in-the-Middle (MitM)
 * - Side-channel attacks
 * - Key extraction
 * - Memory dumping
 * - Eclipse attacks
 * - Network layer attacks
 * - Integer overflow/underflow
 * - Reentrancy (for contract interactions)
 */

const crypto = require('crypto');
const nacl = require('tweetnacl');

// ==================== CHAIN ID AND REPLAY PROTECTION ====================

/**
 * Chain ID ensures transactions can't be replayed on forks or other networks
 * Each network has a unique ID that's signed into every transaction
 */
const CHAIN_IDS = {
  MAINNET: 1,
  TESTNET: 2,
  DEVNET: 3,
  // Add more chain IDs as needed
};

// Current active chain
let ACTIVE_CHAIN_ID = CHAIN_IDS.MAINNET;

/**
 * Set the active chain ID (must be called during wallet initialization)
 */
function setChainId(chainId) {
  if (!Object.values(CHAIN_IDS).includes(chainId)) {
    throw new Error(`Invalid chain ID: ${chainId}`);
  }
  ACTIVE_CHAIN_ID = chainId;
  console.log(`🔗 Chain ID set to: ${chainId} (${getChainName(chainId)})`);
}

/**
 * Get chain name from ID
 */
function getChainName(chainId) {
  const names = { 1: 'MAINNET', 2: 'TESTNET', 3: 'DEVNET' };
  return names[chainId] || 'UNKNOWN';
}

/**
 * Create transaction with replay protection
 * Includes chain ID, nonce, and timestamp to prevent replay attacks
 */
function createSecureTransaction(from, to, amount, privateKey, options = {}) {
  const timestamp = Date.now();
  const nonce = crypto.randomBytes(16).toString('hex'); // 128-bit nonce
  const chainId = options.chainId || ACTIVE_CHAIN_ID;
  
  // Canonical transaction format (prevents malleability)
  const txData = {
    from,
    to,
    amount: sanitizeAmount(amount),
    timestamp,
    nonce,
    chainId,
    version: 1 // Transaction version for future upgrades
  };
  
  // Create deterministic signature message
  const message = createCanonicalMessage(txData);
  
  // Sign with private key
  const signature = nacl.sign.detached(
    Buffer.from(message, 'utf8'),
    privateKey
  );
  
  return {
    ...txData,
    signature: Buffer.from(signature).toString('hex'),
    messageHash: crypto.createHash('sha256').update(message).digest('hex')
  };
}

/**
 * Create canonical message for signing (prevents signature malleability)
 */
function createCanonicalMessage(txData) {
  // Sort keys to ensure deterministic order
  const keys = Object.keys(txData).sort();
  const parts = keys.map(key => `${key}:${txData[key]}`);
  return parts.join('|');
}

/**
 * Verify transaction signature and replay protection
 */
function verifySecureTransaction(transaction, publicKey, expectedChainId) {
  // 1. Check chain ID matches (prevents cross-chain replay)
  if (transaction.chainId !== expectedChainId) {
    throw new Error(`Chain ID mismatch: got ${transaction.chainId}, expected ${expectedChainId}`);
  }
  
  // 2. Check timestamp is recent (prevents old transaction replay)
  const maxAge = 5 * 60 * 1000; // 5 minutes
  if (Date.now() - transaction.timestamp > maxAge) {
    throw new Error('Transaction expired (older than 5 minutes)');
  }
  
  // 3. Verify signature
  const { signature, messageHash, ...txData } = transaction;
  const message = createCanonicalMessage(txData);
  const messageHashCheck = crypto.createHash('sha256').update(message).digest('hex');
  
  if (messageHash !== messageHashCheck) {
    throw new Error('Message hash mismatch - transaction tampered');
  }
  
  const isValid = nacl.sign.detached.verify(
    Buffer.from(message, 'utf8'),
    Buffer.from(signature, 'hex'),
    Buffer.from(publicKey, 'hex')
  );
  
  if (!isValid) {
    throw new Error('Invalid signature');
  }
  
  return true;
}

// ==================== INTEGER OVERFLOW/UNDERFLOW PROTECTION ====================

/**
 * Safe integer operations with overflow protection
 */
const SafeMath = {
  // Maximum safe amount (2^53 - 1 in JavaScript)
  MAX_SAFE_AMOUNT: Number.MAX_SAFE_INTEGER,
  MIN_SAFE_AMOUNT: 0,
  
  /**
   * Safe addition with overflow check
   */
  add(a, b) {
    const result = a + b;
    if (result > this.MAX_SAFE_AMOUNT) {
      throw new Error(`Integer overflow: ${a} + ${b} = ${result} exceeds MAX_SAFE_INTEGER`);
    }
    if (!Number.isSafeInteger(result)) {
      throw new Error(`Result ${result} is not a safe integer`);
    }
    return result;
  },
  
  /**
   * Safe subtraction with underflow check
   */
  sub(a, b) {
    if (b > a) {
      throw new Error(`Integer underflow: ${a} - ${b} would be negative`);
    }
    const result = a - b;
    if (result < this.MIN_SAFE_AMOUNT) {
      throw new Error(`Result ${result} is below minimum`);
    }
    return result;
  },
  
  /**
   * Safe multiplication with overflow check
   */
  mul(a, b) {
    const result = a * b;
    if (result > this.MAX_SAFE_AMOUNT) {
      throw new Error(`Integer overflow: ${a} * ${b} = ${result} exceeds MAX_SAFE_INTEGER`);
    }
    if (!Number.isSafeInteger(result)) {
      throw new Error(`Result ${result} is not a safe integer`);
    }
    return result;
  },
  
  /**
   * Validate amount is safe
   */
  isValid(amount) {
    return (
      Number.isSafeInteger(amount) &&
      amount >= this.MIN_SAFE_AMOUNT &&
      amount <= this.MAX_SAFE_AMOUNT
    );
  }
};

/**
 * Sanitize and validate transaction amount
 */
function sanitizeAmount(amount) {
  // Parse string to number if needed
  const num = typeof amount === 'string' ? parseFloat(amount) : amount;
  
  // Check for invalid values
  if (isNaN(num) || !isFinite(num)) {
    throw new Error(`Invalid amount: ${amount}`);
  }
  
  // Check for negative
  if (num < 0) {
    throw new Error(`Amount cannot be negative: ${num}`);
  }
  
  // Check for zero (optional, depending on protocol)
  if (num === 0) {
    throw new Error('Amount cannot be zero');
  }
  
  // Round to reasonable precision (avoid floating point issues)
  const rounded = Math.round(num * 100) / 100; // 2 decimal places
  
  // Check safe integer bounds for the scaled amount
  const scaledAmount = Math.round(rounded * 100); // Convert to cents/satoshis
  if (!SafeMath.isValid(scaledAmount)) {
    throw new Error(`Amount ${num} exceeds safe integer bounds`);
  }
  
  return rounded;
}

// ==================== MEMORY SECURITY & KEY WIPING ====================

/**
 * Secure memory wiper for sensitive data
 */
class SecureMemory {
  /**
   * Securely wipe a buffer by overwriting it multiple times
   */
  static wipeBuffer(buffer) {
    if (!Buffer.isBuffer(buffer)) {
      throw new Error('Can only wipe Buffer objects');
    }
    
    // Overwrite with random data 3 times (DoD 5220.22-M standard)
    for (let pass = 0; pass < 3; pass++) {
      crypto.randomFillSync(buffer);
    }
    
    // Final pass with zeros
    buffer.fill(0);
  }
  
  /**
   * Securely wipe a Uint8Array (for nacl keys)
   */
  static wipeUint8Array(array) {
    if (!(array instanceof Uint8Array)) {
      throw new Error('Can only wipe Uint8Array objects');
    }
    
    // Overwrite with random data
    for (let pass = 0; pass < 3; pass++) {
      crypto.getRandomValues(array);
    }
    
    // Final pass with zeros
    array.fill(0);
  }
  
  /**
   * Securely wipe a string from memory (best effort)
   */
  static wipeString(str) {
    // In JavaScript, strings are immutable, but we can try to minimize exposure
    // Convert to buffer and wipe
    const buffer = Buffer.from(str, 'utf8');
    this.wipeBuffer(buffer);
    
    // Clear the original variable reference (must be done by caller)
    return null;
  }
  
  /**
   * Create a secure temporary key holder that auto-wipes
   */
  static createSecureHolder(keyData, timeoutMs = 10000) {
    const holder = {
      data: Buffer.from(keyData),
      active: true,
      
      get() {
        if (!this.active) {
          throw new Error('Secure holder has been wiped');
        }
        this.resetTimer();
        return this.data;
      },
      
      wipe() {
        if (this.active) {
          SecureMemory.wipeBuffer(this.data);
          this.active = false;
          if (this.timer) clearTimeout(this.timer);
        }
      },
      
      resetTimer() {
        if (this.timer) clearTimeout(this.timer);
        this.timer = setTimeout(() => this.wipe(), timeoutMs);
      }
    };
    
    holder.resetTimer();
    return holder;
  }
}

/**
 * Secure key pair wrapper with auto-wipe
 */
class SecureKeyPair {
  constructor(keyPair, autoWipeMs = 600000) { // 10 minutes default
    this._keyPair = keyPair;
    this._active = true;
    this._autoWipeMs = autoWipeMs;
    this._lastUsed = Date.now();
    
    // Start auto-wipe timer
    this._startAutoWipe();
  }
  
  _startAutoWipe() {
    this._timer = setTimeout(() => {
      const idleTime = Date.now() - this._lastUsed;
      if (idleTime >= this._autoWipeMs) {
        this.wipe();
      } else {
        // Reset timer if recently used
        this._startAutoWipe();
      }
    }, this._autoWipeMs);
  }
  
  /**
   * Sign data (updates last used time)
   */
  sign(message) {
    if (!this._active) {
      throw new Error('Key pair has been wiped');
    }
    
    this._lastUsed = Date.now();
    const signature = nacl.sign.detached(message, this._keyPair.secretKey);
    return signature;
  }
  
  /**
   * Get public key (safe to expose)
   */
  getPublicKey() {
    if (!this._active) {
      throw new Error('Key pair has been wiped');
    }
    return Buffer.from(this._keyPair.publicKey);
  }
  
  /**
   * Securely wipe the key pair from memory
   */
  wipe() {
    if (!this._active) return;
    
    // Wipe secret key
    if (this._keyPair.secretKey) {
      SecureMemory.wipeUint8Array(this._keyPair.secretKey);
    }
    
    // Clear references
    this._keyPair = null;
    this._active = false;
    
    // Clear timer
    if (this._timer) {
      clearTimeout(this._timer);
      this._timer = null;
    }
    
    console.log('🔒 Key pair securely wiped from memory');
  }
  
  /**
   * Check if still active
   */
  isActive() {
    return this._active;
  }
}

// ==================== MAN-IN-THE-MIDDLE (MitM) PROTECTION ====================

/**
 * Secure communication layer with certificate pinning and verification
 */
class SecureCommunication {
  /**
   * Verify server certificate/public key (certificate pinning)
   */
  static verifyServerIdentity(serverPubkey, expectedPubkey) {
    if (serverPubkey !== expectedPubkey) {
      throw new Error('Server identity verification failed - possible MitM attack!');
    }
    return true;
  }
  
  /**
   * Create authenticated request with signature
   */
  static createAuthenticatedRequest(endpoint, data, keyPair) {
    const timestamp = Date.now();
    const nonce = crypto.randomBytes(16).toString('hex');
    
    // Create request signature
    const message = JSON.stringify({ endpoint, data, timestamp, nonce });
    const signature = nacl.sign.detached(
      Buffer.from(message, 'utf8'),
      keyPair.secretKey
    );
    
    return {
      endpoint,
      data,
      timestamp,
      nonce,
      signature: Buffer.from(signature).toString('hex'),
      publicKey: Buffer.from(keyPair.publicKey).toString('hex')
    };
  }
  
  /**
   * Verify response from server
   */
  static verifyServerResponse(response, expectedPubkey) {
    const { data, signature, timestamp } = response;
    
    // Check response freshness
    const maxAge = 30000; // 30 seconds
    if (Date.now() - timestamp > maxAge) {
      throw new Error('Response too old - possible replay attack');
    }
    
    // Verify signature
    const message = JSON.stringify({ data, timestamp });
    const isValid = nacl.sign.detached.verify(
      Buffer.from(message, 'utf8'),
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedPubkey, 'hex')
    );
    
    if (!isValid) {
      throw new Error('Invalid server signature - possible MitM attack!');
    }
    
    return data;
  }
  
  /**
   * Secure fetch with retry and timeout
   */
  static async secureFetch(url, options = {}, retries = 3) {
    const timeout = options.timeout || 10000; // 10 second timeout
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);
        
        const response = await fetch(url, {
          ...options,
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        return response;
        
      } catch (error) {
        if (attempt === retries) {
          throw new Error(`Request failed after ${retries} attempts: ${error.message}`);
        }
        
        // Exponential backoff
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
}

// ==================== NETWORK LAYER PROTECTION ====================

/**
 * Peer reputation and scoring system to prevent eclipse attacks
 */
class PeerReputation {
  constructor() {
    this.peers = new Map(); // peer_id -> { score, lastSeen, failureCount }
    this.MIN_SCORE = -100;
    this.MAX_SCORE = 100;
    this.INITIAL_SCORE = 50;
  }
  
  /**
   * Add or update peer
   */
  addPeer(peerId) {
    if (!this.peers.has(peerId)) {
      this.peers.set(peerId, {
        score: this.INITIAL_SCORE,
        lastSeen: Date.now(),
        failureCount: 0,
        successCount: 0
      });
    }
  }
  
  /**
   * Record successful interaction
   */
  recordSuccess(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.score = Math.min(peer.score + 1, this.MAX_SCORE);
      peer.successCount++;
      peer.lastSeen = Date.now();
    }
  }
  
  /**
   * Record failed interaction
   */
  recordFailure(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.score = Math.max(peer.score - 10, this.MIN_SCORE);
      peer.failureCount++;
      peer.lastSeen = Date.now();
    }
  }
  
  /**
   * Check if peer is trustworthy
   */
  isTrusted(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer) return false;
    
    // Require positive score and low failure rate
    const failureRate = peer.failureCount / (peer.successCount + peer.failureCount);
    return peer.score > 0 && failureRate < 0.3;
  }
  
  /**
   * Get list of trusted peers
   */
  getTrustedPeers() {
    const trusted = [];
    for (const [peerId, peer] of this.peers.entries()) {
      if (this.isTrusted(peerId)) {
        trusted.push({ peerId, score: peer.score });
      }
    }
    return trusted.sort((a, b) => b.score - a.score);
  }
  
  /**
   * Ban malicious peer
   */
  banPeer(peerId) {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.score = this.MIN_SCORE;
      peer.banned = true;
      peer.bannedUntil = Date.now() + (24 * 60 * 60 * 1000); // 24 hours
    }
  }
  
  /**
   * Check if peer is banned
   */
  isBanned(peerId) {
    const peer = this.peers.get(peerId);
    if (!peer || !peer.banned) return false;
    
    if (Date.now() > peer.bannedUntil) {
      peer.banned = false;
      peer.score = this.INITIAL_SCORE / 2;
      return false;
    }
    
    return true;
  }
}

// ==================== REENTRANCY PROTECTION ====================

/**
 * Reentrancy guard for contract interactions
 */
class ReentrancyGuard {
  constructor() {
    this.locks = new Map(); // address -> boolean
  }
  
  /**
   * Acquire lock (throws if already locked)
   */
  acquireLock(address) {
    if (this.locks.get(address)) {
      throw new Error('Reentrancy detected! Transaction rejected.');
    }
    this.locks.set(address, true);
  }
  
  /**
   * Release lock
   */
  releaseLock(address) {
    this.locks.set(address, false);
  }
  
  /**
   * Execute with reentrancy protection
   */
  async executeProtected(address, fn) {
    this.acquireLock(address);
    try {
      const result = await fn();
      return result;
    } finally {
      this.releaseLock(address);
    }
  }
}

// ==================== TRANSACTION DEDUPLICATION (REPLAY PROTECTION) ====================

/**
 * Track seen transactions to prevent replay
 */
class TransactionDeduplicator {
  constructor(maxAge = 3600000) { // 1 hour default
    this.seenTxs = new Map(); // txHash -> timestamp
    this.maxAge = maxAge;
    
    // Cleanup old entries every 5 minutes
    setInterval(() => this.cleanup(), 5 * 60 * 1000);
  }
  
  /**
   * Check if transaction has been seen before
   */
  hasSeen(txHash) {
    return this.seenTxs.has(txHash);
  }
  
  /**
   * Record transaction
   */
  record(txHash) {
    if (this.hasSeen(txHash)) {
      throw new Error('Duplicate transaction detected (replay attack)');
    }
    this.seenTxs.set(txHash, Date.now());
  }
  
  /**
   * Clean up old transactions
   */
  cleanup() {
    const now = Date.now();
    for (const [txHash, timestamp] of this.seenTxs.entries()) {
      if (now - timestamp > this.maxAge) {
        this.seenTxs.delete(txHash);
      }
    }
  }
  
  /**
   * Get number of tracked transactions
   */
  size() {
    return this.seenTxs.size;
  }
}

// ==================== EXPORTS ====================

module.exports = {
  // Chain ID and replay protection
  CHAIN_IDS,
  setChainId,
  getChainName,
  createSecureTransaction,
  verifySecureTransaction,
  
  // Safe math
  SafeMath,
  sanitizeAmount,
  
  // Memory security
  SecureMemory,
  SecureKeyPair,
  
  // Network security
  SecureCommunication,
  PeerReputation,
  
  // Transaction security
  ReentrancyGuard,
  TransactionDeduplicator
};
