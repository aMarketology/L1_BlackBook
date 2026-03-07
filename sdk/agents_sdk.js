// ============================================================================
// BLACKBOOK AGENTS SDK — v1.0
// ============================================================================
//
// For AI agents and autonomous programs that hold a raw Ed25519 keypair.
// The agent signs ALL transactions client-side. The server NEVER sees the
// private key — only the public key and finalized signature travel the wire.
//
// AUTH MODEL (how agents connect):
//   ┌─────────────────────────────────────────────────────────────────┐
//   │  Agent holds: privateKey (32 bytes) + publicKey (32 bytes)     │
//   │                                                                 │
//   │  Per-request:                                                   │
//   │    1. nonce  = crypto.randomUUID()        (replay guard)        │
//   │    2. ts     = Date.now() / 1000 | 0      (60s window)         │
//   │    3. msg    = buildMessage(endpoint, ...fields, ts, nonce)     │
//   │    4. sig    = ed25519.sign(msg, privateKey)   → 64 bytes       │
//   │    5. POST   { public_key: hex(pubkey), signature: hex(sig),   │
//   │               timestamp: ts, nonce, ...rest }                   │
//   │                                                                 │
//   │  Server:                                                        │
//   │    1. Reconstruct the SAME message bytes server-side            │
//   │    2. ed25519_dalek::VerifyingKey::verify(msg, sig)             │
//   │    3. Check nonce not seen before (DashMap)                     │
//   │    4. Check timestamp within 60s window                        │
//   │    5. Execute if all pass                                       │
//   └─────────────────────────────────────────────────────────────────┘
//
// SIGNING CONVENTIONS (must match Rust server exactly):
//
//   /transfer/simple      → Uint8Array: [CHAIN_ID, ...payload_json, \n, ...ts_str, \n, ...nonce]
//   /escrow/deposit       → UTF-8 string: "ESCROW_DEPOSIT:{addr}:{amount}:{ts}:{nonce}"
//   /escrow/withdraw      → UTF-8 string: "ESCROW_WITHDRAW:{market}:{addr}:{amount}:{ts}:{nonce}"
//   /escrow/submit-state-root → UTF-8 string: "STATE_ROOT:{market}:{root}:{l2_block}"
//
// DEPENDENCIES (Node.js):
//   npm install @noble/ed25519 @noble/hashes
//
// BROWSER:
//   <script type="module"> import * as ed from 'https://esm.sh/@noble/ed25519'; </script>
//
// SECTIONS:
//   1. KEYPAIR    — Generate, import, export, derive address
//   2. TRANSFER   — Sign and submit BB transfers
//   3. ESCROW     — Deposit, withdraw, state root (L2 sequencer)
//   4. BALANCE    — BB + USDC balance queries
//   5. POH        — Proof-of-History chain reads
//   6. LEDGER     — Transaction history
//   7. HEALTH     — Node health + stats
//   8. MERKLE     — Client-side sorted Merkle tree (for L2 sequencers)
//   9. UTILITIES  — Nonce, lamport conversion, hex helpers, address format
//
// ============================================================================

const LAMPORTS_PER_BB = 100_000;
const CHAIN_ID        = 0xBB;  // 187

// ============================================================================
// SECTION 1 — KEYPAIR
// ============================================================================

/**
 * BlackBookKeypair — wraps a raw Ed25519 keypair with BlackBook-specific helpers.
 *
 * @example
 *   // Node.js
 *   const kp = await BlackBookKeypair.generate();
 *   console.log(kp.address);   // base58 wallet address (store this)
 *   console.log(kp.publicHex); // 64-char hex public key
 *
 *   // From saved private key
 *   const kp = await BlackBookKeypair.fromPrivateKey(savedHex);
 */
class BlackBookKeypair {
  /**
   * @param {Uint8Array} privateKey - 32-byte Ed25519 private key
   * @param {Uint8Array} publicKey  - 32-byte Ed25519 public key
   */
  constructor(privateKey, publicKey) {
    this._private = privateKey;
    this._public  = publicKey;

    /** Hex-encoded public key (64 chars) — send this to the server */
    this.publicHex = BlackBookKeypair._toHex(publicKey);

    /** Base58-encoded wallet address — derived from public key, Solana-compatible */
    this.address = BlackBookKeypair._toBase58(publicKey);
  }

  // ─── CONSTRUCTORS ──────────────────────────────────────────────────────────

  /**
   * Generate a new random Ed25519 keypair.
   * @returns {Promise<BlackBookKeypair>}
   */
  static async generate() {
    const ed = await BlackBookKeypair._ed();
    const priv = ed.utils.randomPrivateKey();
    const pub  = await ed.getPublicKeyAsync(priv);
    return new BlackBookKeypair(priv, pub);
  }

  /**
   * Import a keypair from a hex-encoded private key string.
   * @param {string} privateKeyHex - 64-char hex private key
   * @returns {Promise<BlackBookKeypair>}
   */
  static async fromPrivateKey(privateKeyHex) {
    const ed   = await BlackBookKeypair._ed();
    const priv = BlackBookKeypair._fromHex(privateKeyHex);
    if (priv.length !== 32) throw new Error('Private key must be 32 bytes (64 hex chars)');
    const pub  = await ed.getPublicKeyAsync(priv);
    return new BlackBookKeypair(priv, pub);
  }

  /**
   * Import a keypair from a JSON object (e.g. saved with toJSON()).
   * @param {Object} json - { private_key_hex, public_key_hex, address }
   * @returns {Promise<BlackBookKeypair>}
   */
  static async fromJSON(json) {
    return BlackBookKeypair.fromPrivateKey(json.private_key_hex);
  }

  // ─── INSTANCE METHODS ──────────────────────────────────────────────────────

  /**
   * Sign a message. Accepts string (UTF-8) or Uint8Array.
   * @param {string|Uint8Array} message
   * @returns {Promise<string>} hex-encoded 64-byte signature
   */
  async sign(message) {
    const ed  = await BlackBookKeypair._ed();
    const msg = typeof message === 'string'
      ? new TextEncoder().encode(message)
      : message;
    const sig = await ed.signAsync(msg, this._private);
    return BlackBookKeypair._toHex(sig);
  }

  /**
   * Export keypair as a JSON-serializable object.
   * WARNING: contains the private key — store securely.
   * @returns {Object}
   */
  toJSON() {
    return {
      private_key_hex: BlackBookKeypair._toHex(this._private),
      public_key_hex:  this.publicHex,
      address:         this.address,
      format:          'ed25519-raw',
      chain:           'BlackBook-L1',
    };
  }

  /**
   * Export ONLY the public portion — safe to log/share.
   * @returns {Object}
   */
  toPublicJSON() {
    return {
      public_key_hex: this.publicHex,
      address:        this.address,
    };
  }

  // ─── INTERNAL ─────────────────────────────────────────────────────────────

  static _ed_cache = null;
  static async _ed() {
    if (BlackBookKeypair._ed_cache) return BlackBookKeypair._ed_cache;
    // Node.js — require
    if (typeof require !== 'undefined') {
      BlackBookKeypair._ed_cache = require('@noble/ed25519');
      return BlackBookKeypair._ed_cache;
    }
    // ESM / browser
    const mod = await import('@noble/ed25519');
    BlackBookKeypair._ed_cache = mod;
    return mod;
  }

  static _toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static _fromHex(hex) {
    const clean = hex.replace(/^0x/, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * Base58 encode — Solana-compatible (same alphabet as bs58::encode in Rust).
   * Produces the wallet address format stored in BlackBook.
   */
  static _toBase58(bytes) {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let num = 0n;
    for (const byte of bytes) num = (num << 8n) | BigInt(byte);
    const leadingZeros = [...bytes].filter(b => b === 0).length;
    let result = '';
    while (num > 0n) {
      const mod = num % 58n;
      result = ALPHABET[Number(mod)] + result;
      num = num / 58n;
    }
    return '1'.repeat(leadingZeros) + result;
  }
}

// ============================================================================
// BLACKBOOK AGENT — main SDK class
// ============================================================================

class BlackBookAgent {
  /**
   * Create an agent instance.
   *
   * @param {string}           apiUrl  - BlackBook HTTP API (e.g. 'https://api.blackbook.finance:8080')
   * @param {BlackBookKeypair} keypair - Ed25519 keypair for signing
   * @param {Object}           [opts]
   * @param {number}           [opts.timeout]   - Request timeout ms (default: 30000)
   * @param {boolean}          [opts.logTxns]   - Log each transaction to console (default: false)
   *
   * @example
   *   const kp    = await BlackBookKeypair.generate();
   *   const agent = new BlackBookAgent('http://localhost:8080', kp);
   *
   *   // Check balance
   *   const { balance } = await agent.getBalance(kp.address);
   *
   *   // Transfer
   *   const tx = await agent.transfer(kp.address, 'RecipientAddress', 1.5);
   *   console.log(tx.success); // true
   */
  constructor(apiUrl, keypair, opts = {}) {
    if (!(keypair instanceof BlackBookKeypair)) {
      throw new Error('keypair must be a BlackBookKeypair instance. Call BlackBookKeypair.generate() or BlackBookKeypair.fromPrivateKey()');
    }
    this.apiUrl  = apiUrl.replace(/\/+$/, '');
    this.keypair = keypair;
    this.timeout = opts.timeout  || 30_000;
    this.logTxns = opts.logTxns  || false;

    /** Convenience — the agent's own wallet address */
    this.address = keypair.address;
    /** Convenience — the agent's hex public key */
    this.publicKey = keypair.publicHex;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL TRANSPORT
  // ═══════════════════════════════════════════════════════════════════════════

  /** @private */
  async _post(path, body) {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        signal:  ctrl.signal,
      });
      const json = await res.json();
      if (!res.ok) throw Object.assign(new Error(json.error || `HTTP ${res.status}`), { status: res.status, body: json });
      return json;
    } finally {
      clearTimeout(timer);
    }
  }

  /** @private */
  async _get(path) {
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method: 'GET',
        signal: ctrl.signal,
      });
      const json = await res.json();
      if (!res.ok) throw Object.assign(new Error(json.error || `HTTP ${res.status}`), { status: res.status, body: json });
      return json;
    } finally {
      clearTimeout(timer);
    }
  }

  /** @private — generate a cryptographically random nonce */
  _nonce() {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return crypto.randomUUID().replace(/-/g, '');
    }
    // Node.js < 19 fallback
    const { randomBytes } = require('crypto');
    return randomBytes(16).toString('hex');
  }

  /** @private — current unix timestamp (seconds) */
  _ts() {
    return Math.floor(Date.now() / 1000);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 2 — TRANSFER
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer BB tokens. Signs with the agent's private key.
   *
   * Signing message (must match Rust server exactly):
   *   Bytes: [0xBB, ...JSON.stringify({to, amount}), 0x0A, ...String(ts), 0x0A, ...nonce]
   *
   * @param {string} fromAddress - Sender wallet address (must match this agent's keypair)
   * @param {string} toAddress   - Recipient wallet address (base58)
   * @param {number} amount      - Amount in BB (e.g. 1.5)
   * @returns {Promise<Object>}  - { success, from, to, amount, from_balance, to_balance }
   *
   * @example
   *   const tx = await agent.transfer(agent.address, 'RecipientAddressHere', 5.0);
   *   console.log(`New balance: ${tx.from_balance} BB`);
   */
  async transfer(fromAddress, toAddress, amount) {
    if (amount <= 0) throw new Error('Amount must be positive');

    const ts    = this._ts();
    const nonce = this._nonce();

    // Build the exact message the server reconstructs:
    // [chain_id_byte] + payload_json_bytes + \n + timestamp_str + \n + nonce
    const payload = JSON.stringify({ to: toAddress, amount });
    const enc     = new TextEncoder();
    const msg     = new Uint8Array([
      CHAIN_ID,
      ...enc.encode(payload),
      0x0A,                       // \n
      ...enc.encode(String(ts)),
      0x0A,                       // \n
      ...enc.encode(nonce),
    ]);

    const sigHex = await this.keypair.sign(msg);

    if (this.logTxns) {
      console.log(`[Agent] TRANSFER ${amount} BB : ${fromAddress.slice(0,8)}… → ${toAddress.slice(0,8)}…`);
    }

    return this._post('/transfer/simple', {
      public_key:     this.publicKey,
      wallet_address: fromAddress,
      payload,
      timestamp:      ts,
      nonce,
      chain_id:       CHAIN_ID,
      signature:      sigHex,
    });
  }

  /**
   * Transfer BB using this agent's own address as sender (convenience method).
   *
   * @param {string} toAddress - Recipient wallet address
   * @param {number} amount    - Amount in BB
   * @returns {Promise<Object>}
   *
   * @example
   *   const tx = await agent.send('RecipientAddressHere', 10.0);
   */
  async send(toAddress, amount) {
    return this.transfer(this.address, toAddress, amount);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 3 — ESCROW
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Lock BB tokens into the global escrow vault.
   *
   * Signing message: "ESCROW_DEPOSIT:{walletAddress}:{amount}:{ts}:{nonce}"
   *
   * @param {string} walletAddress - Wallet to debit (must match this agent's keypair)
   * @param {number} amount        - Amount in BB to lock
   * @returns {Promise<Object>}    - { success, deposited, wallet_address, escrow_address, user_balance, escrow_balance }
   *
   * @example
   *   const res = await agent.escrowDeposit(agent.address, 100.0);
   *   console.log(`Escrow balance: ${res.escrow_balance} BB`);
   */
  async escrowDeposit(walletAddress, amount) {
    if (amount <= 0) throw new Error('Amount must be positive');

    const ts    = this._ts();
    const nonce = this._nonce();
    const msg   = `ESCROW_DEPOSIT:${walletAddress}:${amount}:${ts}:${nonce}`;
    const sig   = await this.keypair.sign(msg);

    if (this.logTxns) {
      console.log(`[Agent] ESCROW DEPOSIT ${amount} BB from ${walletAddress.slice(0,8)}…`);
    }

    return this._post('/escrow/deposit', {
      wallet_address: walletAddress,
      amount,
      public_key:     this.publicKey,
      signature:      sig,
      timestamp:      ts,
      nonce,
    });
  }

  /**
   * Withdraw tokens from escrow using a Merkle proof (from L2 settlement).
   *
   * Signing message: "ESCROW_WITHDRAW:{marketId}:{walletAddress}:{amount}:{ts}:{nonce}"
   * The merkle_proof is NOT signed — it is public math that the server verifies independently.
   *
   * Merkle proof format: array of hex sibling hashes from leaf to root.
   * The L2 sequencer provides these after settlement. Hashing uses sorted order
   * (smaller [u8;32] first) — see Section 8 for client-side proof generation.
   *
   * @param {string}   marketId      - Market ID (from L2)
   * @param {string}   walletAddress - Recipient wallet (must match this agent's keypair)
   * @param {number}   amount        - Amount entitled to withdraw (must match leaf)
   * @param {string[]} merkleProof   - Array of 64-char hex sibling hashes
   * @returns {Promise<Object>}      - { success, withdrawn, wallet_address, new_balance }
   *
   * @example
   *   const proof = ['aabbcc...', 'ddeeff...'];  // from L2 after settlement
   *   const res = await agent.escrowWithdraw('market_42', agent.address, 50.0, proof);
   */
  async escrowWithdraw(marketId, walletAddress, amount, merkleProof) {
    if (!Array.isArray(merkleProof)) throw new Error('merkleProof must be an array of hex strings');
    if (amount <= 0)                throw new Error('Amount must be positive');

    const ts    = this._ts();
    const nonce = this._nonce();
    const msg   = `ESCROW_WITHDRAW:${marketId}:${walletAddress}:${amount}:${ts}:${nonce}`;
    const sig   = await this.keypair.sign(msg);

    if (this.logTxns) {
      console.log(`[Agent] ESCROW WITHDRAW ${amount} BB from market ${marketId}`);
    }

    return this._post('/escrow/withdraw', {
      market_id:      marketId,
      amount,
      wallet_address: walletAddress,
      merkle_proof:   merkleProof,
      public_key:     this.publicKey,
      signature:      sig,
      timestamp:      ts,
      nonce,
    });
  }

  /**
   * Submit a settlement state root to the escrow vault.
   * This endpoint is for L2 SEQUENCERS ONLY — agents acting as an L2 oracle.
   *
   * Signing message: "STATE_ROOT:{marketId}:{merkleRoot}:{l2BlockNumber}"
   * NOTE: No timestamp/nonce — replay is prevented by l2_block_number monotonicity.
   *
   * @param {string} marketId       - Unique market identifier
   * @param {string} merkleRoot     - 64-char hex (32 bytes) Merkle root of payouts
   * @param {number} l2BlockNumber  - Monotonically incrementing L2 block number
   * @returns {Promise<Object>}     - { success, market_id, merkle_root, l2_block_number, slot }
   *
   * @example
   *   // L2 sequencer submitting market settlement
   *   const tree   = new BlackBookMerkleTree();
   *   tree.addLeaf(agent.address, 'winner1_addr', 500.0);
   *   tree.addLeaf(agent.address, 'winner2_addr', 250.0);
   *   const root   = tree.getRoot();
   *   const result = await agent.submitStateRoot('sports_market_001', root, l2Block++);
   */
  async submitStateRoot(marketId, merkleRoot, l2BlockNumber) {
    if (merkleRoot.replace(/^0x/, '').length !== 64) {
      throw new Error('merkleRoot must be 64 hex chars (32 bytes)');
    }
    const cleanRoot = merkleRoot.replace(/^0x/, '');
    const msg = `STATE_ROOT:${marketId}:${cleanRoot}:${l2BlockNumber}`;
    const sig = await this.keypair.sign(msg);

    if (this.logTxns) {
      console.log(`[Agent] STATE ROOT market=${marketId} block=${l2BlockNumber} root=${cleanRoot.slice(0,16)}…`);
    }

    return this._post('/escrow/submit-state-root', {
      market_id:       marketId,
      merkle_root:     cleanRoot,
      signature:       sig,
      l2_block_number: l2BlockNumber,
    });
  }

  /**
   * Get global escrow vault status (no auth required).
   * @returns {Promise<Object>} - { escrow_address, escrow_balance_lamports, total_markets_settled, l2_sequencer_configured }
   */
  async getEscrowStatus() {
    return this._get('/escrow/status');
  }

  /**
   * Get the settled Merkle root for a specific market (no auth required).
   * @param {string} marketId
   * @returns {Promise<Object>} - { success, market_id, merkle_root }
   */
  async getEscrowMarket(marketId) {
    return this._get(`/escrow/market/${encodeURIComponent(marketId)}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 4 — BALANCE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get BB balance for any wallet address.
   * @param {string} [address] - Wallet address (defaults to this agent's address)
   * @returns {Promise<Object>} - { address, balance, unit: 'BB' }
   *
   * @example
   *   const { balance } = await agent.getBalance();
   *   // or
   *   const { balance } = await agent.getBalance('OtherWalletAddress');
   */
  async getBalance(address) {
    return this._get(`/balance/${encodeURIComponent(address || this.address)}`);
  }

  /**
   * Get USDC (SPL token) balance for any wallet address.
   * @param {string} [address] - Wallet address (defaults to this agent's address)
   * @returns {Promise<Object>} - { address, usdc_balance, usdc_decimals: 6 }
   */
  async getUsdcBalance(address) {
    return this._get(`/usdc/balance/${encodeURIComponent(address || this.address)}`);
  }

  /**
   * Get both BB and USDC balances in a single call.
   * @param {string} [address] - Wallet address (defaults to this agent's address)
   * @returns {Promise<{bb: Object, usdc: Object}>}
   */
  async getAllBalances(address) {
    const addr = address || this.address;
    const [bb, usdc] = await Promise.all([
      this.getBalance(addr),
      this.getUsdcBalance(addr),
    ]);
    return { bb, usdc };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 5 — POH (Proof of History)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get current PoH chain status (slot, hash, throughput).
   * @returns {Promise<Object>}
   */
  async getPohStatus() {
    return this._get('/poh/status');
  }

  /**
   * Get the latest PoH block.
   * @returns {Promise<Object>}
   */
  async getLatestBlock() {
    return this._get('/poh/block/latest');
  }

  /**
   * Get a PoH block by slot number.
   * @param {number} slot
   * @returns {Promise<Object>}
   */
  async getBlockBySlot(slot) {
    return this._get(`/poh/block/${slot}`);
  }

  /**
   * Get transaction status by transaction ID / signature hash.
   * @param {string} txId
   * @returns {Promise<Object>}
   */
  async getTxStatus(txId) {
    return this._get(`/poh/tx/${encodeURIComponent(txId)}/status`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 6 — LEDGER
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get paginated transaction ledger.
   * @param {Object} [opts]
   * @param {number} [opts.page]  - Page number (default: 1)
   * @param {number} [opts.limit] - Transactions per page (default: 50)
   * @returns {Promise<Object>}
   */
  async getLedger({ page = 1, limit = 50 } = {}) {
    return this._get(`/ledger?page=${page}&limit=${limit}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 7 — HEALTH
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Node health check.
   * @returns {Promise<Object>} - { status: 'ok', slot, uptime_secs, ...}
   */
  async health() {
    return this._get('/health');
  }

  /**
   * Chain + pipeline stats (TPS, slot, block count, mempool).
   * @returns {Promise<Object>}
   */
  async getStats() {
    return this._get('/stats');
  }

  /**
   * Check if a node is alive. Returns true/false (never throws).
   * @returns {Promise<boolean>}
   */
  async isAlive() {
    try {
      const res = await this.health();
      return res?.status === 'ok';
    } catch {
      return false;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECTION 8 — MERKLE (for L2 sequencers)
  // ═══════════════════════════════════════════════════════════════════════════
  // NOTE: Also available as standalone BlackBookMerkleTree class below.

  /**
   * Build a sorted Merkle tree from payout records and return the root + proofs.
   * Matches the Rust implementation in poh_blockchain.rs::compute_root().
   *
   * Leaf construction (must match Rust withdrawal verifier):
   *   SHA256(wallet_address_utf8_bytes || f64_amount_little_endian_8_bytes)
   *
   * Sorted hashing (combine_hashes in Rust):
   *   hash(a, b) = SHA256(min(a,b) || max(a,b))   — lexicographic comparison
   *
   * @param {Array<{address: string, amount: number}>} payouts - Payout records
   * @returns {Promise<{root: string, proofs: Object}>}
   *   root:   64-char hex Merkle root — pass to submitStateRoot()
   *   proofs: { [address]: string[] } — array of sibling hex hashes — pass to escrowWithdraw()
   *
   * @example
   *   const { root, proofs } = await agent.buildMerkleTree([
   *     { address: 'Winner1AddressHere', amount: 500.0 },
   *     { address: 'Winner2AddressHere', amount: 250.0 },
   *   ]);
   *
   *   await agent.submitStateRoot('market_001', root, blockNum);
   *   // Later, winners call:
   *   await agent.escrowWithdraw('market_001', winnerAddress, 500.0, proofs[winnerAddress]);
   */
  async buildMerkleTree(payouts) {
    return BlackBookMerkleTree.build(payouts);
  }
}

// ============================================================================
// SECTION 8 — MERKLE TREE (standalone, no agent required)
// ============================================================================

/**
 * Client-side sorted Merkle tree matching BlackBook L1's Rust implementation.
 *
 * Used by L2 sequencers to:
 *   1. Build a payout tree from settlement results
 *   2. Get the Merkle root to submit via submitStateRoot()
 *   3. Get each winner's proof to return via offchain API (or L2 DB)
 *
 * @example
 *   const { root, proofs } = await BlackBookMerkleTree.build([
 *     { address: 'Alice...', amount: 100.0 },
 *     { address: 'Bob...',   amount:  50.0 },
 *   ]);
 */
class BlackBookMerkleTree {
  /**
   * Build a Merkle tree and return root + all proofs.
   *
   * @param {Array<{address: string, amount: number}>} payouts
   * @returns {Promise<{root: string, proofs: Object<string, string[]>, leaves: string[]}>}
   */
  static async build(payouts) {
    if (!payouts || payouts.length === 0) throw new Error('payouts array is empty');

    // 1. Build leaves: SHA256(address_utf8 || amount_f64_le)
    const leaves = await Promise.all(
      payouts.map(p => BlackBookMerkleTree._makeLeaf(p.address, p.amount))
    );

    // 2. Build tree levels
    const levels = [leaves.map(l => BlackBookMerkleTree._toHex(l))];
    let current  = leaves;

    while (current.length > 1) {
      const next = [];
      for (let i = 0; i < current.length; i += 2) {
        const a = current[i];
        const b = i + 1 < current.length ? current[i + 1] : current[i]; // duplicate last if odd
        next.push(await BlackBookMerkleTree._combineHashes(a, b));
      }
      current = next;
      levels.push(next.map(l => BlackBookMerkleTree._toHex(l)));
    }

    const root = BlackBookMerkleTree._toHex(current[0]);

    // 3. Generate proof for each leaf
    const proofs = {};
    for (let leafIdx = 0; leafIdx < payouts.length; leafIdx++) {
      const proof  = [];
      let   idx    = leafIdx;

      for (let level = 0; level < levels.length - 1; level++) {
        const levelNodes = levels[level];
        const siblingIdx = idx % 2 === 0
          ? Math.min(idx + 1, levelNodes.length - 1)
          : idx - 1;
        proof.push(levelNodes[siblingIdx]);
        idx = Math.floor(idx / 2);
      }
      proofs[payouts[leafIdx].address] = proof;
    }

    return {
      root,
      proofs,
      leaves: leaves.map(l => BlackBookMerkleTree._toHex(l)),
    };
  }

  /**
   * Verify a single Merkle proof (matches L1 withdrawal verifier).
   * Use this client-side to validate before submitting a withdrawal.
   *
   * @param {string}   address   - Wallet address
   * @param {number}   amount    - Payout amount
   * @param {string[]} proof     - Sibling hashes (from BlackBookMerkleTree.build proofs)
   * @param {string}   root      - Expected Merkle root (64-char hex)
   * @returns {Promise<boolean>}
   *
   * @example
   *   const valid = await BlackBookMerkleTree.verify(myAddress, 100.0, proof, root);
   *   if (!valid) throw new Error('Proof invalid — do not submit');
   */
  static async verify(address, amount, proof, root) {
    let current = await BlackBookMerkleTree._makeLeaf(address, amount);

    for (const siblingHex of proof) {
      const sibling = BlackBookMerkleTree._fromHex(siblingHex);
      current = await BlackBookMerkleTree._combineHashes(current, sibling);
    }

    return BlackBookMerkleTree._toHex(current) === root;
  }

  // ─── INTERNAL ─────────────────────────────────────────────────────────────

  /** SHA256(address_utf8 || amount_f64_le_bytes) — matches Rust withdrawal handler */
  static async _makeLeaf(address, amount) {
    const addrBytes   = new TextEncoder().encode(address);
    const amountBuf   = new ArrayBuffer(8);
    new DataView(amountBuf).setFloat64(0, amount, true); // little-endian
    const amountBytes = new Uint8Array(amountBuf);

    const combined = new Uint8Array(addrBytes.length + 8);
    combined.set(addrBytes);
    combined.set(amountBytes, addrBytes.length);

    return BlackBookMerkleTree._sha256(combined);
  }

  /** combine_hashes — sorted: SHA256(min(a,b) || max(a,b)) */
  static async _combineHashes(a, b) {
    // Lexicographic comparison of byte arrays
    for (let i = 0; i < 32; i++) {
      if (a[i] !== b[i]) {
        const [first, second] = a[i] < b[i] ? [a, b] : [b, a];
        const combined = new Uint8Array(64);
        combined.set(first);
        combined.set(second, 32);
        return BlackBookMerkleTree._sha256(combined);
      }
    }
    // Equal — hash a twice
    const combined = new Uint8Array(64);
    combined.set(a);
    combined.set(a, 32);
    return BlackBookMerkleTree._sha256(combined);
  }

  /** SHA256 using Web Crypto (browser) or Node crypto */
  static async _sha256(data) {
    if (typeof crypto !== 'undefined' && crypto.subtle) {
      const buf = await crypto.subtle.digest('SHA-256', data);
      return new Uint8Array(buf);
    }
    // Node.js
    const { createHash } = require('crypto');
    const hash = createHash('sha256');
    hash.update(data);
    return new Uint8Array(hash.digest());
  }

  static _toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static _fromHex(hex) {
    const clean = hex.replace(/^0x/, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }
}

// ============================================================================
// SECTION 9 — UTILITIES
// ============================================================================

const AgentUtils = {
  /** Convert BB → lamports (u64 on-chain unit) */
  bbToLamports(bb) {
    return Math.round(bb * LAMPORTS_PER_BB);
  },

  /** Convert lamports → BB */
  lamportsToBB(lamports) {
    return lamports / LAMPORTS_PER_BB;
  },

  /** Shorten a base58 address for display: "AbC...XyZ" */
  shortAddress(address, chars = 4) {
    if (!address || address.length <= chars * 2) return address;
    return `${address.slice(0, chars)}...${address.slice(-chars)}`;
  },

  /** Format BB amount with up to 5 decimal places */
  formatBB(amount) {
    return `${parseFloat(amount.toFixed(5))} BB`;
  },

  /** Hex-encode a Uint8Array */
  toHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  /** Hex-decode a string to Uint8Array */
  fromHex(hex) {
    const clean = hex.replace(/^0x/, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  },

  /**
   * Verify an Ed25519 signature without a full keypair (useful for debugging).
   * @param {string} publicKeyHex  - 64-char hex public key
   * @param {string|Uint8Array} message
   * @param {string} signatureHex  - 128-char hex signature
   * @returns {Promise<boolean>}
   */
  async verifySignature(publicKeyHex, message, signatureHex) {
    const ed  = BlackBookKeypair._ed_cache || await (async () => {
      if (typeof require !== 'undefined') return require('@noble/ed25519');
      return import('@noble/ed25519');
    })();
    const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    const pub = AgentUtils.fromHex(publicKeyHex);
    const sig = AgentUtils.fromHex(signatureHex);
    try {
      return await ed.verifyAsync(sig, msg, pub);
    } catch {
      return false;
    }
  },
};

// ============================================================================
// EXPORTS
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  // Node.js / CommonJS
  module.exports = {
    BlackBookAgent,
    BlackBookKeypair,
    BlackBookMerkleTree,
    AgentUtils,
    LAMPORTS_PER_BB,
    CHAIN_ID,
  };
}

if (typeof globalThis !== 'undefined') {
  // Browser global
  globalThis.BlackBookAgent       = BlackBookAgent;
  globalThis.BlackBookKeypair     = BlackBookKeypair;
  globalThis.BlackBookMerkleTree  = BlackBookMerkleTree;
  globalThis.AgentUtils           = AgentUtils;
}

// ============================================================================
// QUICK-START EXAMPLES
// ============================================================================
//
// ─── BASIC AGENT (Node.js) ───────────────────────────────────────────────────
//
//   const { BlackBookAgent, BlackBookKeypair } = require('./agents_sdk');
//
//   async function main() {
//     // Generate a new keypair (save private_key_hex securely!)
//     const kp = await BlackBookKeypair.generate();
//     console.log('Address:    ', kp.address);
//     console.log('Public key: ', kp.publicHex);
//     console.log('Save this!  ', kp.toJSON().private_key_hex);
//
//     const agent = new BlackBookAgent('http://localhost:8080', kp, { logTxns: true });
//
//     // Check balance
//     const { balance } = await agent.getBalance();
//     console.log('Balance:', balance, 'BB');
//
//     // Transfer
//     const tx = await agent.send('RecipientAddressHere', 5.0);
//     console.log('TX:', tx);
//
//     // Restore keypair later
//     const kp2 = await BlackBookKeypair.fromPrivateKey('your_saved_hex_here');
//   }
//
// ─── L2 SEQUENCER (settle a market) ─────────────────────────────────────────
//
//   const kp      = await BlackBookKeypair.fromPrivateKey(process.env.L2_SEQUENCER_PKEY);
//   const agent   = new BlackBookAgent(process.env.L1_API_URL, kp);
//
//   const payouts = [
//     { address: 'Winner1AddressBase58', amount: 500.0 },
//     { address: 'Winner2AddressBase58', amount: 200.0 },
//   ];
//
//   // Build Merkle tree
//   const { root, proofs } = await agent.buildMerkleTree(payouts);
//
//   // Submit root to L1
//   await agent.submitStateRoot('market_001', root, l2BlockNumber++);
//
//   // Return proofs to winners (via your L2 API)
//   // Winners call agent.escrowWithdraw('market_001', theirAddress, theirAmount, proofs[theirAddress])
//
// ─── ESCROW DEPOSIT ──────────────────────────────────────────────────────────
//
//   await agent.escrowDeposit(agent.address, 100.0);
//
// ─── ESCROW WITHDRAW (user has proof from L2) ────────────────────────────────
//
//   const proof = await fetch(`https://l2.yourplatform.com/proof/${marketId}/${myAddress}`)
//     .then(r => r.json())
//     .then(r => r.proof);   // string[]
//
//   await agent.escrowWithdraw('market_001', agent.address, 500.0, proof);
//
// ─── VERIFY PROOF BEFORE SUBMITTING ─────────────────────────────────────────
//
//   const { root } = await agent.getEscrowMarket('market_001');
//   const valid    = await BlackBookMerkleTree.verify(myAddress, 500.0, proof, root);
//   if (!valid) throw new Error('Bad proof from L2 — refusing to submit');
//   await agent.escrowWithdraw('market_001', myAddress, 500.0, proof);
//
// ─── ENV VARS ────────────────────────────────────────────────────────────────
//
//   L1_API_URL          = http://localhost:8080
//   AGENT_PRIVATE_KEY   = <64-char hex Ed25519 private key>
//   L2_SEQUENCER_PKEY   = <same — only if this agent IS the L2 sequencer>
//
// ════════════════════════════════════════════════════════════════════════════
