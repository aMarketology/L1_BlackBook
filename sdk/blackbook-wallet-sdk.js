/**
 * ╔═══════════════════════════════════════════════════════════════════════════╗
 * ║                    BLACKBOOK WALLET SDK V3.0                              ║
 * ║                    Frontend Integration Library                           ║
 * ╚═══════════════════════════════════════════════════════════════════════════╝
 * 
 * Production-ready wallet SDK for BlackBook L1 blockchain integration.
 * Supports both consumer (Mnemonic) and institutional (FROST) tracks.
 * 
 * Features:
 * - BIP-39 24-word mnemonic wallet creation and restoration
 * - Mnemonic wallet API integration (create, recover, transfer)
 * - Ed25519 signature generation (V2 SDK canonical format)
 * - BB_ address derivation
 * - Transfer, burn, and balance operations
 * - ZKP authentication for secure Share B retrieval
 * - Multi-recovery path support (A+B, A+C, B+C)
 * - Replay attack prevention with nonces
 * - Browser-compatible (uses Web Crypto API)
 * 
 * Dependencies:
 * - @noble/ed25519 or tweetnacl (for Ed25519 signing)
 * - bip39 (for mnemonic generation)
 * 
 * @version 3.0.0
 * @author BlackBook Team
 * @license MIT
 */

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const BLACKBOOK_CONFIG = {
    // Network endpoints
    L1_RPC_URL: 'http://localhost:8080',
    MNEMONIC_API_URL: 'http://localhost:8080/mnemonic',  // Unified with L1 server
    
    // Chain configuration
    CHAIN_ID: 1,
    DERIVATION_PATH: "m/44'/501'/0'/0'", // Solana-compatible SLIP-10
    
    // Address prefixes
    MNEMONIC_PREFIX: 'BB_',   // Consumer track (mnemonic wallet)
    
    // Security
    SCHEMA_VERSION: 2,
    HIGH_VALUE_THRESHOLD: 1000, // Vault verification above this amount
};

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Generate a unique nonce for transaction replay prevention
 * @returns {string} UUID-based nonce
 */
function generateNonce() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
        return crypto.randomUUID();
    }
    // Fallback for older browsers
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

/**
 * SHA-256 hash function (browser-compatible)
 * @param {string} message - Message to hash
 * @returns {Promise<string>} Hex-encoded hash
 */
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex - Hex string
 * @returns {Uint8Array}
 */
function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

/**
 * Convert Uint8Array to hex string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ═══════════════════════════════════════════════════════════════════════════
// MNEMONIC WALLET CLASS - Production Integration
// ═══════════════════════════════════════════════════════════════════════════

class MnemonicWallet {
    /**
     * Create a new MnemonicWallet instance
     * @param {Object} options
     * @param {string} options.walletAddress - BB_ prefixed address
     * @param {string} options.mnemonic - 24-word BIP-39 mnemonic (keep secure!)
     * @param {string} options.password - Encryption password
     * @param {string} options.apiUrl - Mnemonic API endpoint
     */
    constructor(options) {
        this.walletAddress = options.walletAddress;
        this.mnemonic = options.mnemonic || null;
        this.password = options.password || null;
        this.apiUrl = options.apiUrl || BLACKBOOK_CONFIG.MNEMONIC_API_URL;
        this.publicKey = options.publicKey || null;
        this.privateKey = options.privateKey || null;
    }

    /**
     * Create a new mnemonic wallet on the server
     * @param {string} password - Encryption password for Share A
     * @param {string} apiUrl - Optional API URL override
     * @returns {Promise<MnemonicWallet>}
     */
    static async create(password, apiUrl = BLACKBOOK_CONFIG.MNEMONIC_API_URL) {
        const response = await fetch(`${apiUrl}/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Wallet creation failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        
        return new MnemonicWallet({
            walletAddress: data.wallet_address,
            mnemonic: data.mnemonic, // CRITICAL: User must backup this!
            password: password,
            apiUrl: apiUrl
        });
    }

    /**
     * Recover wallet using A+B recovery path (password + blockchain)
     * @param {string} walletAddress - BB_ wallet address
     * @param {string} password - Encryption password
     * @param {string} apiUrl - Optional API URL override
     * @returns {Promise<MnemonicWallet>}
     */
    static async recoverAB(walletAddress, password, apiUrl = BLACKBOOK_CONFIG.MNEMONIC_API_URL) {
        const response = await fetch(`${apiUrl}/recover/ab`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ wallet_address: walletAddress, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Recovery failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        
        return new MnemonicWallet({
            walletAddress: data.wallet_address,
            mnemonic: data.mnemonic,
            password: password,
            apiUrl: apiUrl
        });
    }

    /**
     * Recover wallet using A+C recovery path (password + vault)
     * @param {string} walletAddress - BB_ wallet address
     * @param {string} password - Encryption password
     * @param {string} apiUrl - Optional API URL override
     * @returns {Promise<MnemonicWallet>}
     */
    static async recoverAC(walletAddress, password, apiUrl = BLACKBOOK_CONFIG.MNEMONIC_API_URL) {
        const response = await fetch(`${apiUrl}/recover/ac`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ wallet_address: walletAddress, password })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Recovery failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        
        return new MnemonicWallet({
            walletAddress: data.wallet_address,
            mnemonic: data.mnemonic,
            password: password,
            apiUrl: apiUrl
        });
    }

    /**
     * Derive Ed25519 keypair from mnemonic for signing
     * @param {Object} bip39 - BIP-39 library instance
     * @param {Object} nacl - TweetNaCl library instance
     * @returns {Promise<Object>} { publicKey, privateKey, secretKey }
     */
    async deriveKeypair(bip39, nacl) {
        if (!this.mnemonic) {
            throw new Error('Mnemonic not available. Call recovery method first.');
        }

        // Derive seed from mnemonic
        const seed = await bip39.mnemonicToSeed(this.mnemonic);
        const privateKey = new Uint8Array(seed.slice(0, 32));
        
        // Generate keypair
        const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
        
        this.publicKey = keyPair.publicKey;
        this.privateKey = privateKey;
        
        return {
            publicKey: keyPair.publicKey,
            privateKey: privateKey,
            secretKey: keyPair.secretKey
        };
    }

    /**
     * Request ZKP challenge for Share B retrieval
     * @param {Object} bip39 - BIP-39 library
     * @param {Object} nacl - TweetNaCl library
     * @returns {Promise<string>} Challenge string
     */
    async requestZKPChallenge(bip39, nacl) {
        // Derive keypair if not already done
        if (!this.publicKey) {
            await this.deriveKeypair(bip39, nacl);
        }

        // Server endpoint: POST /mnemonic/zkp/challenge/:address
        const response = await fetch(`${this.apiUrl}/zkp/challenge/${this.walletAddress}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`ZKP challenge failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        return data.challenge;
    }

    /**
     * Verify ZKP challenge and retrieve Share B
     * @param {string} challenge - Challenge from server
     * @param {Object} nacl - TweetNaCl library
     * @returns {Promise<string>} Share B data
     */
    async verifyZKPChallenge(challenge, nacl) {
        if (!this.publicKey || !this.privateKey) {
            throw new Error('Keypair not derived. Call deriveKeypair() first.');
        }

        // Sign the challenge using the correct message format
        // Message format: "BLACKBOOK_SHARE_B\n{challenge}\n{address}"
        const message = `BLACKBOOK_SHARE_B\n${challenge}\n${this.walletAddress}`;
        const messageBytes = new TextEncoder().encode(message);
        const keyPair = nacl.sign.keyPair.fromSeed(this.privateKey);
        const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);

        // Server endpoint: POST /mnemonic/share-b/:address
        const response = await fetch(`${this.apiUrl}/share-b/${this.walletAddress}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                public_key: bytesToHex(this.publicKey),
                signature: bytesToHex(signature)
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`ZKP verification failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        return data.share_b;
    }

    /**
     * Transfer tokens
     * @param {string} toAddress - Recipient BB_ address
     * @param {number} amount - Amount to transfer
     * @returns {Promise<Object>} Transfer result
     */
    async transfer(toAddress, amount) {
        if (!this.password) {
            throw new Error('Password required for transfer');
        }

        const response = await fetch(`${this.apiUrl}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                wallet_address: this.walletAddress,
                password: this.password,
                to: toAddress,
                amount: amount
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Transfer failed: ${error.error || response.statusText}`);
        }

        return await response.json();
    }

    /**
     * Get wallet balance
     * @returns {Promise<number>} Balance in BB tokens
     */
    async getBalance() {
        const response = await fetch(`${this.apiUrl}/balance/${this.walletAddress}`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(`Balance check failed: ${error.error || response.statusText}`);
        }

        const data = await response.json();
        return data.balance || 0;
    }

    /**
     * Get wallet info (safe for display - no secrets)
     * @returns {Object}
     */
    getInfo() {
        return {
            walletAddress: this.walletAddress,
            hasMnemonic: !!this.mnemonic,
            hasPassword: !!this.password,
            hasKeypair: !!(this.publicKey && this.privateKey),
            publicKey: this.publicKey ? bytesToHex(this.publicKey) : null
        };
    }

    /**
     * Export wallet data (DANGEROUS - contains mnemonic!)
     * @returns {Object}
     */
    export() {
        return {
            version: '3.0',
            walletAddress: this.walletAddress,
            mnemonic: this.mnemonic, // ENCRYPT BEFORE STORAGE!
            publicKey: this.publicKey ? bytesToHex(this.publicKey) : null
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// WALLET CLASS - Legacy Ed25519 Direct Signing
// ═══════════════════════════════════════════════════════════════════════════

class BlackBookWallet {
    /**
     * Create a new BlackBook wallet instance (legacy mode)
     * @param {Object} options
     * @param {string} options.mnemonic - 24-word BIP-39 mnemonic
     * @param {Uint8Array} options.privateKey - Raw private key (32 bytes)
     * @param {Uint8Array} options.publicKey - Public key (32 bytes)
     * @param {string} options.address - BB_ address
     * @param {string} options.rpcUrl - RPC endpoint URL
     */
    constructor(options) {
        this.mnemonic = options.mnemonic || null;
        this.privateKey = options.privateKey;
        this.publicKey = options.publicKey;
        this.address = options.address;
        this.rpcUrl = options.rpcUrl || BLACKBOOK_CONFIG.L1_RPC_URL;
        this.track = 'Mnemonic (Consumer)';
    }

    /**
     * Create a new wallet with random mnemonic
     * @param {Object} bip39 - BIP-39 library instance
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @returns {Promise<BlackBookWallet>}
     */
    static async createNew(bip39, nacl) {
        // Generate 24-word mnemonic (256 bits entropy)
        const mnemonic = bip39.generateMnemonic(256);
        return await BlackBookWallet.fromMnemonic(mnemonic, bip39, nacl);
    }

    /**
     * Restore wallet from 24-word mnemonic
     * @param {string} mnemonic - 24-word BIP-39 phrase
     * @param {Object} bip39 - BIP-39 library instance
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @returns {Promise<BlackBookWallet>}
     */
    static async fromMnemonic(mnemonic, bip39, nacl) {
        if (!bip39.validateMnemonic(mnemonic)) {
            throw new Error('Invalid mnemonic phrase');
        }

        // Derive seed from mnemonic (512 bits)
        const seed = await bip39.mnemonicToSeed(mnemonic);
        
        // For Ed25519, use first 32 bytes as private key
        const privateKey = new Uint8Array(seed.slice(0, 32));
        
        // Generate keypair
        const keyPair = nacl.sign.keyPair.fromSeed(privateKey);
        const publicKey = keyPair.publicKey;
        
        // Derive BB_ address (SHA256 → first 32 hex chars uppercase)
        const pubkeyHex = bytesToHex(publicKey);
        const addressHash = await sha256(pubkeyHex);
        const address = BLACKBOOK_CONFIG.MNEMONIC_PREFIX + addressHash.substring(0, 32).toUpperCase();

        return new BlackBookWallet({
            mnemonic,
            privateKey,
            publicKey,
            address
        });
    }

    /**
     * Create signed transfer request (V2 SDK format)
     * @param {string} toAddress - Recipient address (bb_ or L1_)
     * @param {number} amount - Amount to transfer
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @param {Object} options - Optional parameters
     * @returns {Promise<Object>} Signed transfer request
     */
    async createSignedTransfer(toAddress, amount, nacl, options = {}) {
        const timestamp = options.timestamp || Math.floor(Date.now() / 1000);
        const nonce = options.nonce || generateNonce();
        
        // Step 1: Create canonical payload
        const canonical = `${this.address}|${toAddress}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = await sha256(canonical);
        
        // Step 2: Create signing message with domain prefix
        const chainId = options.chainId || BLACKBOOK_CONFIG.CHAIN_ID;
        const requestPath = '/transfer';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        // Step 3: Sign with Ed25519 (CRITICAL: use keyPair.fromSeed then sign with secretKey)
        const messageBytes = new TextEncoder().encode(message);
        const keyPair = nacl.sign.keyPair.fromSeed(this.privateKey);
        const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);
        
        return {
            public_key: bytesToHex(this.publicKey),
            payload_hash: payloadHash,
            payload_fields: {
                from: this.address,
                to: toAddress,
                amount: parseInt(amount),
                timestamp: timestamp,
                nonce: nonce
            },
            operation_type: 'transfer',
            schema_version: BLACKBOOK_CONFIG.SCHEMA_VERSION,
            timestamp: timestamp,
            nonce: nonce,
            chain_id: chainId,
            request_path: requestPath,
            signature: bytesToHex(signature),
            security_pin: options.securityPin || undefined
        };
    }

    /**
     * Create signed burn request (V2 SDK format)
     * @param {number} amount - Amount to burn
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @param {Object} options - Optional parameters
     * @returns {Promise<Object>} Signed burn request
     */
    async createSignedBurn(amount, nacl, options = {}) {
        const timestamp = options.timestamp || Math.floor(Date.now() / 1000);
        const nonce = options.nonce || generateNonce();
        
        // Step 1: Create canonical payload (no "to" for burns)
        const canonical = `${this.address}|${amount}|${timestamp}|${nonce}`;
        const payloadHash = await sha256(canonical);
        
        // Step 2: Create signing message with domain prefix
        const chainId = options.chainId || BLACKBOOK_CONFIG.CHAIN_ID;
        const requestPath = '/admin/burn';
        const domainPrefix = `BLACKBOOK_L${chainId}${requestPath}`;
        const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
        
        // Step 3: Sign with Ed25519 (CRITICAL: use keyPair.fromSeed then sign with secretKey)
        const messageBytes = new TextEncoder().encode(message);
        const keyPair = nacl.sign.keyPair.fromSeed(this.privateKey);
        const signature = nacl.sign.detached(messageBytes, keyPair.secretKey);
        
        return {
            public_key: bytesToHex(this.publicKey),
            payload_hash: payloadHash,
            payload_fields: {
                from: this.address,
                amount: parseInt(amount),
                timestamp: timestamp,
                nonce: nonce
            },
            operation_type: 'burn',
            schema_version: BLACKBOOK_CONFIG.SCHEMA_VERSION,
            timestamp: timestamp,
            nonce: nonce,
            chain_id: chainId,
            request_path: requestPath,
            signature: bytesToHex(signature),
            security_pin: options.securityPin || undefined
        };
    }

    /**
     * Send transfer transaction
     * @param {string} toAddress - Recipient address
     * @param {number} amount - Amount to transfer
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @param {Object} options - Optional parameters
     * @returns {Promise<Object>} Transaction result
     */
    async transfer(toAddress, amount, nacl, options = {}) {
        const signedRequest = await this.createSignedTransfer(toAddress, amount, nacl, options);
        
        const response = await fetch(`${this.rpcUrl}/transfer`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        
        return await response.json();
    }

    /**
     * Burn tokens
     * @param {number} amount - Amount to burn
     * @param {Object} nacl - TweetNaCl or @noble/ed25519
     * @param {Object} options - Optional parameters
     * @returns {Promise<Object>} Transaction result
     */
    async burn(amount, nacl, options = {}) {
        const signedRequest = await this.createSignedBurn(amount, nacl, options);
        
        const response = await fetch(`${this.rpcUrl}/admin/burn`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(signedRequest)
        });
        
        return await response.json();
    }

    /**
     * Get wallet balance
     * @returns {Promise<number>} Balance in BB tokens
     */
    async getBalance() {
        const response = await fetch(`${this.rpcUrl}/balance/${this.address}`);
        const data = await response.json();
        return data.balance || 0;
    }

    /**
     * Get unified balance (L1 + L2)
     * @returns {Promise<Object>} Unified balance information
     */
    async getUnifiedBalance() {
        const response = await fetch(`${this.rpcUrl}/balance/${this.address}/unified`);
        return await response.json();
    }

    /**
     * Export wallet as JSON (includes mnemonic - handle securely!)
     * @returns {Object} Wallet export data
     */
    export() {
        return {
            version: '2.0',
            track: this.track,
            mnemonic: this.mnemonic,
            address: this.address,
            l2Address: this.l2Address,
            publicKey: bytesToHex(this.publicKey),
            // WARNING: privateKey exported - encrypt before storage!
            privateKey: bytesToHex(this.privateKey)
        };
    }

    /**
     * Get wallet info (safe for display - no private keys)
     * @returns {Object}
     */
    getInfo() {
        return {
            track: this.track,
            address: this.address,
            publicKey: bytesToHex(this.publicKey),
            hasMnemonic: !!this.mnemonic
        };
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// API CLIENT - Direct RPC Calls
// ═══════════════════════════════════════════════════════════════════════════

class BlackBookClient {
    /**
     * Create BlackBook RPC client
     * @param {string} rpcUrl - RPC endpoint URL
     */
    constructor(rpcUrl = BLACKBOOK_CONFIG.L1_RPC_URL) {
        this.rpcUrl = rpcUrl;
    }

    /**
     * Check node health
     * @returns {Promise<Object>}
     */
    async health() {
        const response = await fetch(`${this.rpcUrl}/health`);
        return await response.json();
    }

    /**
     * Get network statistics
     * @returns {Promise<Object>}
     */
    async stats() {
        const response = await fetch(`${this.rpcUrl}/stats`);
        return await response.json();
    }

    /**
     * Get balance for any address
     * @param {string} address
     * @returns {Promise<number>}
     */
    async getBalance(address) {
        const response = await fetch(`${this.rpcUrl}/balance/${address}`);
        const data = await response.json();
        return data.balance || 0;
    }

    /**
     * Get transaction history
     * @param {string} address - Optional address filter
     * @param {number} limit - Optional result limit
     * @returns {Promise<Array>}
     */
    async getTransactions(address = null, limit = 100) {
        let url = `${this.rpcUrl}/transactions?limit=${limit}`;
        if (address) url += `&address=${address}`;
        
        const response = await fetch(url);
        return await response.json();
    }

    /**
     * Get ledger view (formatted transaction list)
     * @returns {Promise<string>}
     */
    async getLedger() {
        const response = await fetch(`${this.rpcUrl}/ledger`);
        return await response.text();
    }

    /**
     * Admin: Mint tokens (requires admin privileges)
     * @param {string} address
     * @param {number} amount
     * @returns {Promise<Object>}
     */
    async mint(address, amount) {
        const response = await fetch(`${this.rpcUrl}/admin/mint`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ to: address, amount })
        });
        return await response.json();
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════════════════

// CommonJS (Node.js)
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        MnemonicWallet,
        BlackBookWallet,
        BlackBookClient,
        BLACKBOOK_CONFIG,
        generateNonce,
        sha256,
        hexToBytes,
        bytesToHex
    };
}

// ES6 Modules
if (typeof window !== 'undefined') {
    window.MnemonicWallet = MnemonicWallet;
    window.BlackBookWallet = BlackBookWallet;
    window.BlackBookClient = BlackBookClient;
    window.BLACKBOOK_CONFIG = BLACKBOOK_CONFIG;
}

// ═══════════════════════════════════════════════════════════════════════════
// USAGE EXAMPLES
// ═══════════════════════════════════════════════════════════════════════════

/*

// ─────────────────────────────────────────────────────────────────────────
// Example 1: Create New Wallet
// ─────────────────────────────────────────────────────────────────────────

import bip39 from 'bip39';
import nacl from 'tweetnacl';
import { BlackBookWallet } from './blackbook-wallet-sdk.js';

async function createWallet() {
    const wallet = await BlackBookWallet.createNew(bip39, nacl);
    console.log('Address:', wallet.address);
    console.log('Mnemonic:', wallet.mnemonic); // BACKUP THIS!
    
    // Get balance
    const balance = await wallet.getBalance();
    console.log('Balance:', balance, 'BB');
}

// ─────────────────────────────────────────────────────────────────────────
// Example 2: Restore Wallet from Mnemonic
// ─────────────────────────────────────────────────────────────────────────

async function restoreWallet() {
    const mnemonic = 'romance tape leaf devote cable spot evolve few voice spy sword material midnight genius cave pulp spin shoe milk shrimp spike poverty fork brown';
    
    const wallet = await BlackBookWallet.fromMnemonic(mnemonic, bip39, nacl);
    console.log('Restored wallet:', wallet.address);
}

// ─────────────────────────────────────────────────────────────────────────
// Example 3: Send Transfer
// ─────────────────────────────────────────────────────────────────────────

async function sendTransfer(wallet) {
    const recipient = 'bb_d8ed1c2f27ed27081bf11e58bb6eb160'; // Bob
    const amount = 100;
    
    try {
        const result = await wallet.transfer(recipient, amount, nacl);
        
        if (result.success) {
            console.log('Transfer successful!');
            console.log('TX ID:', result.tx_id);
            console.log('New balance:', result.new_balance);
        } else {
            console.error('Transfer failed:', result.error);
        }
    } catch (err) {
        console.error('Error:', err.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Example 4: Burn Tokens
// ─────────────────────────────────────────────────────────────────────────

async function burnTokens(wallet) {
    const amount = 50;
    
    try {
        const result = await wallet.burn(amount, nacl);
        
        if (result.success) {
            console.log('Burn successful!');
            console.log('Burned:', result.burned, 'BB');
            console.log('New balance:', result.new_balance);
        }
    } catch (err) {
        console.error('Error:', err.message);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Example 5: Using the RPC Client
// ─────────────────────────────────────────────────────────────────────────

import { BlackBookClient } from './blackbook-wallet-sdk.js';

async function useClient() {
    const client = new BlackBookClient('http://localhost:8080');
    
    // Check health
    const health = await client.health();
    console.log('Node status:', health.status);
    console.log('TPS:', health.sealevel.tps);
    
    // Get stats
    const stats = await client.stats();
    console.log('Total supply:', stats.total_supply, 'BB');
    
    // Get balance
    const balance = await client.getBalance('bb_6b7665632e4d8284c9ff288b6cab2f94');
    console.log('Balance:', balance, 'BB');
    
    // Get transactions
    const txs = await client.getTransactions('bb_6b7665632e4d8284c9ff288b6cab2f94', 10);
    console.log('Recent transactions:', txs.length);
}

// ─────────────────────────────────────────────────────────────────────────
// Example 6: High-Value Transfer (Requires PIN)
// ─────────────────────────────────────────────────────────────────────────

async function highValueTransfer(wallet) {
    const result = await wallet.transfer(
        'bb_d8ed1c2f27ed27081bf11e58bb6eb160',
        150000, // Above HIGH_VALUE_THRESHOLD
        nacl,
        { securityPin: '1234' } // Required for amounts > 100,000 BB
    );
    
    console.log(result);
}

*/
