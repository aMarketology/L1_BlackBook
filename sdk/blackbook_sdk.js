// ============================================================================
// BLACKBOOK AGENT SDK — v5.0 — AI Agent Microtransactions
// ============================================================================
//
// Purpose-built SDK for AI agents running on Node.js (18+).
// Uses native WebCrypto Ed25519 for key generation, signing, and verification.
// No browser dependencies, no SSS, no localStorage — raw keypairs only.
//
// ┌──────────────────────────────────────────────────────────────────────┐
// │  AI AGENT LIFECYCLE                                                 │
// │                                                                     │
// │  1. const agent = await BlackBookAgent.create(API_URL)              │
// │     → generates Ed25519 keypair in memory                           │
// │                                                                     │
// │  2. await agent.fundMe(1000)                                        │
// │     → faucet with auto-signed Ed25519 auth                          │
// │                                                                     │
// │  3. await agent.send(recipientAddr, 0.5)                            │
// │     → signed transfer via /transfer/simple                          │
// │                                                                     │
// │  4. await agent.submitSealevel(recipientAddr, 0.1)                  │
// │     → parallel execution via Gulf Stream                            │
// │                                                                     │
// │  5. await agent.sendUsdc(recipientAddr, 10.0)                       │
// │     → USDC transfer with Ed25519 auth                               │
// │                                                                     │
// │  Every write is Ed25519-signed client-side, verified server-side.   │
// │  Replay protection: nonce + timestamp (60s window).                 │
// └──────────────────────────────────────────────────────────────────────┘
//
// ENDPOINTS COVERED
// ─────────────────────────────────────────────────────────────────────────────
// WRITE (Ed25519 signed)              READ (no auth)
// ─────────────────────────────────   ─────────────────────────────────────
// send(to, amount)                    getHealth()
// submitSealevel(to, amount, opts)    getVersion()
// fundMe(amount)                      getSlot()
// sendUsdc(to, amount)                getEpochInfo()
//                                     getLatestBlockhash()
// ADMIN / DEALER                      getGenesisHash()
// ─────────────────────────────────   getBalance(addr)
// adminMint(to, amount, opts)         getBalances(addrs[])
// adminBurn(from, amount, opts)       getAccountInfo(addr)
// adminAccounts()                     getSignaturesForAddress(addr, n)
// adminUsdcMint(to, amount)           getTransaction(sig)
//                                     getStats()
// KEYPAIR                             getNodeHealth()
// ─────────────────────────────────   getLedger(page, limit)
// BlackBookAgent.create(url)          getPohStatus()
// BlackBookAgent.fromHex(url, hex)    getLatestBlock()
// agent.exportKeypair()               getBlockBySlot(slot)
// agent.address                       getTxStatus(txId)
// agent.publicKeyHex                  getTowerBft()
//                                     getTurbineStatus()
//                                     getUsdcBalance(addr)
//                                     getUsdcSupply()
//                                     getUsdcAccounts(addr)
//                                     getSupply()
// ─────────────────────────────────────────────────────────────────────────────
//
// Quick start (Node.js 18+ with --experimental-vm-modules or .mjs):
//
//   import { BlackBookAgent } from './blackbook_sdk.js';
//
//   const agent = await BlackBookAgent.create('http://localhost:8080');
//   await agent.fundMe(100);
//   const bal = await agent.myBalance();
//   console.log(`Agent ${agent.address} has ${bal.bb} BB`);
//
//   const result = await agent.send(recipientAddr, 5.0);
//   console.log(`Sent! sig: ${result.signature}`);
//
// ============================================================================

import { webcrypto } from 'node:crypto';

const LAMPORTS_PER_BB = 100_000;
const CHAIN_ID        = 0xBB;

// ============================================================================
// BLACKBOOK AGENT — Ed25519 AI Agent SDK
// ============================================================================

class BlackBookAgent {

  // ═══════════════════════════════════════════════════════════════════════════
  // CONSTRUCTION — use static factories, not `new`
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * @private — use BlackBookAgent.create() or BlackBookAgent.fromHex()
   */
  constructor(apiUrl, rpcUrl, keyPair, publicKeyHex, address) {
    /** @type {string} HTTP API base (port 8080) */
    this.apiUrl = apiUrl.replace(/\/+$/, '');

    /** @type {string} JSON-RPC base (port 8899) */
    this.rpcUrl = (rpcUrl || apiUrl.replace(':8080', ':8899')).replace(/\/+$/, '');

    /** @type {CryptoKeyPair} WebCrypto Ed25519 key pair */
    this._keyPair = keyPair;

    /** @type {string} 64-char hex public key */
    this.publicKeyHex = publicKeyHex;

    /** @type {string} Wallet address (= hex pubkey) */
    this.address = address;

    /** @type {number} Request timeout in ms */
    this.timeout = 30_000;

    /** @private JSON-RPC ID counter */
    this._rpcId = 0;
  }

  /**
   * Create a new agent with a fresh Ed25519 keypair.
   *
   * @param {string} apiUrl - HTTP API endpoint (port 8080)
   * @param {string} [rpcUrl] - JSON-RPC endpoint (port 8899), auto-derived if omitted
   * @returns {Promise<BlackBookAgent>}
   *
   * @example
   *   const agent = await BlackBookAgent.create('http://localhost:8080');
   *   console.log(agent.address); // 64-char hex public key
   */
  static async create(apiUrl, rpcUrl) {
    const keyPair = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    const rawPub  = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey));
    const pubHex  = Buffer.from(rawPub).toString('hex');
    return new BlackBookAgent(apiUrl, rpcUrl, keyPair, pubHex, pubHex);
  }

  /**
   * Restore an agent from a hex-encoded 64-byte Ed25519 keypair (seed + pubkey).
   *
   * @param {string} apiUrl
   * @param {string} keypairHex - 128-char hex string (32-byte seed + 32-byte pubkey)
   * @param {string} [rpcUrl]
   * @returns {Promise<BlackBookAgent>}
   *
   * @example
   *   const saved = await agent.exportKeypair();   // 128 hex chars
   *   const agent2 = await BlackBookAgent.fromHex('http://localhost:8080', saved);
   *   console.log(agent2.address === agent.address); // true
   */
  static async fromHex(apiUrl, keypairHex, rpcUrl) {
    const raw    = Buffer.from(keypairHex, 'hex');
    const seed   = raw.slice(0, 32);
    const pubRaw = raw.slice(32, 64);
    const pubHex = Buffer.from(pubRaw).toString('hex');

    const privKey = await webcrypto.subtle.importKey(
      'pkcs8', _ed25519Pkcs8(seed), 'Ed25519', true, ['sign']
    );
    const pubKey = await webcrypto.subtle.importKey(
      'raw', pubRaw, 'Ed25519', true, ['verify']
    );
    const keyPair = { privateKey: privKey, publicKey: pubKey };
    return new BlackBookAgent(apiUrl, rpcUrl, keyPair, pubHex, pubHex);
  }

  /**
   * Export the keypair as a 128-char hex string (seed + pubkey).
   * Store this securely — it IS the private key.
   *
   * @returns {Promise<string>} 128-char hex (32-byte seed + 32-byte pubkey)
   */
  async exportKeypair() {
    const pkcs8  = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', this._keyPair.privateKey));
    const seed   = pkcs8.slice(pkcs8.length - 32);
    const rawPub = new Uint8Array(await webcrypto.subtle.exportKey('raw', this._keyPair.publicKey));
    return Buffer.from(seed).toString('hex') + Buffer.from(rawPub).toString('hex');
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL — Transport
  // ═══════════════════════════════════════════════════════════════════════════

  /** @private HTTP GET */
  async _get(path) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res  = await fetch(`${this.apiUrl}${path}`, { method: 'GET', signal: ctrl.signal });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally { clearTimeout(t); }
  }

  /** @private HTTP POST */
  async _post(path, body = {}) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        signal:  ctrl.signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally { clearTimeout(t); }
  }

  /** @private JSON-RPC 2.0 */
  async _rpc(method, params = []) {
    const id   = ++this._rpcId;
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(this.rpcUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal:  ctrl.signal,
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
      return json.result;
    } finally { clearTimeout(t); }
  }

  /** @private Batched JSON-RPC */
  async _rpcBatch(calls) {
    const body = calls.map((c, i) => ({
      jsonrpc: '2.0', id: i, method: c.method, params: c.params || [],
    }));
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(this.rpcUrl, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(body),
        signal:  ctrl.signal,
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const results = await res.json();
      return results.sort((a, b) => a.id - b.id);
    } finally { clearTimeout(t); }
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL — Ed25519 Signing
  // ═══════════════════════════════════════════════════════════════════════════

  /** @private Sign arbitrary bytes → hex signature (128 chars) */
  async _sign(message) {
    const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    const sigBytes = new Uint8Array(await webcrypto.subtle.sign('Ed25519', this._keyPair.privateKey, msgBytes));
    return Buffer.from(sigBytes).toString('hex');
  }

  /** @private Generate nonce + timestamp for replay protection */
  _replayFields() {
    return {
      timestamp: Math.floor(Date.now() / 1000),
      nonce:     _uuid(),
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WRITE — BB Transfers (Ed25519 signed)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Send BB tokens to another address.
   *
   * Constructs the signed payload, signs with Ed25519, submits to
   * `/transfer/simple`. Replay-protected with nonce + timestamp.
   *
   * @param {string} to       - Recipient address (hex pubkey)
   * @param {number} amount   - Amount in BB (e.g. 0.5)
   * @returns {Promise<{ success, signature, from, to, amount, from_balance, to_balance }>}
   *
   * @example
   *   const r = await agent.send(recipientAddr, 5.0);
   *   console.log(`Sent ${r.amount} BB — sig: ${r.signature}`);
   */
  async send(to, amount) {
    const { timestamp, nonce } = this._replayFields();
    const payload = JSON.stringify({ to, amount });

    // Build message: chain_id byte + payload + \n + timestamp + \n + nonce
    const msgParts = [
      new Uint8Array([CHAIN_ID]),
      new TextEncoder().encode(payload),
      new TextEncoder().encode('\n'),
      new TextEncoder().encode(timestamp.toString()),
      new TextEncoder().encode('\n'),
      new TextEncoder().encode(nonce),
    ];
    const msg = _concat(msgParts);
    const signature = await this._sign(msg);

    return this._post('/transfer/simple', {
      public_key:     this.publicKeyHex,
      wallet_address: this.address,
      payload,
      timestamp,
      nonce,
      chain_id:       CHAIN_ID,
      signature,
    });
  }

  /**
   * Submit a transaction to the Sealevel parallel execution engine.
   *
   * Uses Gulf Stream (`/sealevel/submit`) for parallel execution.
   * Ed25519 message format: "SEALEVEL:{from}:{to}:{amount}:{timestamp}:{nonce}"
   *
   * @param {string} to           - Recipient address
   * @param {number} amount       - Amount in BB
   * @param {Object} [opts]
   * @param {number} [opts.priority] - Priority hint (higher = faster)
   * @returns {Promise<{ success, tx_id, status }>}
   *
   * @example
   *   const r = await agent.submitSealevel(recipientAddr, 0.01, { priority: 10 });
   *   console.log(`TX pending: ${r.tx_id}`);
   */
  async submitSealevel(to, amount, opts = {}) {
    const { timestamp, nonce } = this._replayFields();
    const message = `SEALEVEL:${this.address}:${to}:${amount}:${timestamp}:${nonce}`;
    const signature = await this._sign(message);

    return this._post('/sealevel/submit', {
      from:      this.address,
      to,
      amount,
      priority:  opts.priority ?? undefined,
      signature,
      timestamp,
      nonce,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WRITE — Faucet (Ed25519 signed)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Request BB from the faucet (self-signed).
   *
   * Ed25519 message format: "FAUCET:{to}:{amount}:{timestamp}:{nonce}"
   *
   * @param {number} [amount=0.1] - Amount in BB
   * @returns {Promise<{ success, minted, to, new_balance, auth_method }>}
   *
   * @example
   *   await agent.fundMe(1000);
   *   const bal = await agent.myBalance();
   *   console.log(`Funded: ${bal.bb} BB`);
   */
  async fundMe(amount = 0.1) {
    if (amount <= 0) throw new Error('Amount must be positive');
    const { timestamp, nonce } = this._replayFields();
    const message = `FAUCET:${this.address}:${amount}:${timestamp}:${nonce}`;
    const signature = await this._sign(message);

    return this._post('/faucet', {
      to: this.address,
      amount,
      signature,
      timestamp,
      nonce,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WRITE — USDC (Ed25519 signed)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer USDC tokens to another address.
   *
   * Ed25519 message format: "USDC_TRANSFER:{from}:{to}:{amount}:{timestamp}:{nonce}"
   *
   * @param {string} to     - Recipient address (base58)
   * @param {number} amount - Amount in human USDC (e.g. 10.50)
   * @returns {Promise<{ success, amount_usdc, raw_amount, from, to, from_ata, to_ata, from_balance, to_balance }>}
   *
   * @example
   *   const r = await agent.sendUsdc(recipientAddr, 25.0);
   *   console.log(`Sent ${r.amount_usdc} USDC`);
   */
  async sendUsdc(to, amount) {
    if (amount <= 0) throw new Error('Amount must be positive');
    const { timestamp, nonce } = this._replayFields();
    const message = `USDC_TRANSFER:${this.address}:${to}:${amount}:${timestamp}:${nonce}`;
    const signature = await this._sign(message);

    return this._post('/usdc/transfer', {
      from: this.address,
      to,
      amount,
      signature,
      timestamp,
      nonce,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN — Dealer mint / burn (L2 settlement)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Mint BB tokens (Dealer / L2 settlement).
   *
   * @param {string} to          - Recipient address
   * @param {number} amount      - Amount in BB
   * @param {Object} [opts]
   * @param {string} [opts.dealerSignature] - Dealer auth sig
   * @param {string} [opts.l2ReceiptId]     - L2 receipt ID for audit trail
   * @returns {Promise<{ success, minted, to, new_balance, l2_receipt_id }>}
   */
  async adminMint(to, amount, opts = {}) {
    return this._post('/admin/mint', {
      to,
      amount,
      dealer_signature: opts.dealerSignature ?? undefined,
      l2_receipt_id:    opts.l2ReceiptId ?? undefined,
    });
  }

  /**
   * Burn BB tokens (Dealer / L2 settlement).
   *
   * @param {string} from   - Address to burn from
   * @param {number} amount - Amount in BB
   * @param {Object} [opts]
   * @param {string} [opts.dealerSignature]
   * @param {string} [opts.l2ReceiptId]
   * @returns {Promise<{ success, burned, from, new_balance, l2_receipt_id }>}
   */
  async adminBurn(from, amount, opts = {}) {
    return this._post('/admin/burn', {
      from,
      amount,
      dealer_signature: opts.dealerSignature ?? undefined,
      l2_receipt_id:    opts.l2ReceiptId ?? undefined,
    });
  }

  /**
   * List all accounts with non-zero balances.
   * @returns {Promise<{ accounts: Array<{ address, balance, lamports }>, total_accounts, total_supply }>}
   */
  async adminAccounts() {
    return this._get('/admin/accounts');
  }

  /**
   * Mint USDC tokens (admin / Dealer).
   *
   * @param {string} to     - Recipient wallet address (base58)
   * @param {number} amount - Amount in human USDC
   * @returns {Promise<{ success, minted_usdc, raw_amount, to, ata, mint, new_total_supply }>}
   */
  async adminUsdcMint(to, amount) {
    return this._post('/admin/usdc/mint', { to, amount });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Network & Node
  // ═══════════════════════════════════════════════════════════════════════════

  /** Check node health via JSON-RPC. Returns "ok" or throws. */
  async getHealth() { return this._rpc('getHealth'); }

  /** Node version: `{ 'solana-core': string, 'feature-set': number }` */
  async getVersion() { return this._rpc('getVersion'); }

  /** Chain genesis hash (base58). */
  async getGenesisHash() { return this._rpc('getGenesisHash'); }

  /** Current slot number. */
  async getSlot() { return this._rpc('getSlot'); }

  /** Epoch info: `{ absoluteSlot, blockHeight, epoch, slotIndex, slotsInEpoch, transactionCount }` */
  async getEpochInfo() { return this._rpc('getEpochInfo'); }

  /** Latest blockhash: `{ blockhash, lastValidBlockHeight }` */
  async getLatestBlockhash() { return this._rpc('getLatestBlockhash'); }

  /**
   * Full node health + block production status (REST).
   * @returns {Promise<{ status, version, blockchain, poh_clock, consensus, block_production, infrastructure }>}
   */
  async getNodeHealth() { return this._get('/health'); }

  /**
   * Chain performance stats: pipeline, Gulf Stream, Sealevel.
   * @returns {Promise<{ blockchain, pipeline, gulf_stream, parallel_execution }>}
   */
  async getStats() { return this._get('/stats'); }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Supply
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Total + circulating BB supply.
   * @returns {Promise<{ totalLamports: number, totalBB: number, circulating: number }>}
   */
  async getSupply() {
    const r = await this._rpc('getSupply');
    return {
      totalLamports: r.value.total,
      totalBB:       r.value.total / LAMPORTS_PER_BB,
      circulating:   r.value.circulating / LAMPORTS_PER_BB,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Accounts & Balances
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * BB balance for one address.
   * @param {string} address
   * @returns {Promise<{ lamports: number, bb: number }>}
   */
  async getBalance(address) {
    const r = await this._rpc('getBalance', [address]);
    return { lamports: r.value, bb: r.value / LAMPORTS_PER_BB };
  }

  /**
   * BB balance via REST (address, balance in BB, unit).
   * @param {string} address
   * @returns {Promise<{ address: string, balance: number, unit: string }>}
   */
  async getBalanceREST(address) {
    return this._get(`/balance/${address}`);
  }

  /**
   * Batch balance lookup. Returns `{ [address]: { lamports, bb } }`.
   * @param {string[]} addresses
   * @returns {Promise<Object.<string, { lamports: number, bb: number }>>}
   */
  async getBalances(addresses) {
    const calls   = addresses.map(a => ({ method: 'getBalance', params: [a] }));
    const results = await this._rpcBatch(calls);
    const map = {};
    results.forEach((r, i) => {
      if (r.result) map[addresses[i]] = {
        lamports: r.result.value,
        bb:       r.result.value / LAMPORTS_PER_BB,
      };
    });
    return map;
  }

  /**
   * Full account info (lamports, owner, data, executable) or null.
   * @param {string} address
   * @returns {Promise<Object|null>}
   */
  async getAccountInfo(address) {
    const r = await this._rpc('getAccountInfo', [address, { encoding: 'base64' }]);
    return r.value;
  }

  /**
   * Shortcut: get this agent's own balance.
   * @returns {Promise<{ lamports: number, bb: number }>}
   */
  async myBalance() {
    return this.getBalance(this.address);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Transactions
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Recent transaction signatures for an address.
   * @param {string} address
   * @param {number} [limit=20]
   * @returns {Promise<Array<{ signature, slot, err, blockTime, confirmationStatus }>>}
   */
  async getSignaturesForAddress(address, limit = 20) {
    return this._rpc('getSignaturesForAddress', [address, { limit }]);
  }

  /**
   * Full transaction detail by signature, or null.
   * @param {string} signature
   * @returns {Promise<Object|null>}
   */
  async getTransaction(signature) {
    return this._rpc('getTransaction', [signature, { encoding: 'json' }]);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Ledger
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Paginated audit ledger (JSON format).
   * @param {number} [page=1]
   * @param {number} [limit=50]
   */
  async getLedger(page = 1, limit = 50) {
    return this._get(`/ledger?page=${page}&limit=${limit}&format=json`);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — PoH / Blocks
  // ═══════════════════════════════════════════════════════════════════════════

  /** Current PoH clock: `{ current_slot, num_hashes, current_hash, is_running }` */
  async getPohStatus() { return this._get('/poh/status'); }

  /** Latest finalized block with header + tx list. */
  async getLatestBlock() { return this._get('/poh/block/latest'); }

  /**
   * Block by slot (includes full transaction list).
   * @param {number} slot
   */
  async getBlockBySlot(slot) { return this._get(`/poh/block/${slot}`); }

  /**
   * Finality status for a transaction.
   * @param {string} txId
   * @returns {Promise<{ tx_id, status, is_finalized }>}
   */
  async getTxStatus(txId) { return this._get(`/poh/tx/${encodeURIComponent(txId)}/status`); }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Consensus & Propagation
  // ═══════════════════════════════════════════════════════════════════════════

  /** Tower BFT consensus state. */
  async getTowerBft() { return this._get('/consensus/tower'); }

  /** Turbine shred propagation status. */
  async getTurbineStatus() { return this._get('/turbine/status'); }


  // ═══════════════════════════════════════════════════════════════════════════
  // READ — USDC (SPL Token)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * USDC balance for an address.
   * @param {string} address
   * @returns {Promise<{ address, balance_usdc, raw_balance, decimals, mint }>}
   */
  async getUsdcBalance(address) { return this._get(`/usdc/balance/${address}`); }

  /** Total USDC supply on-chain. */
  async getUsdcSupply() { return this._get('/usdc/supply'); }

  /**
   * All USDC token accounts (ATAs) for a wallet.
   * @param {string} address
   */
  async getUsdcAccounts(address) { return this._get(`/usdc/accounts/${address}`); }


  // ═══════════════════════════════════════════════════════════════════════════
  // UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  static toLamports(bb)   { return Math.floor(bb * LAMPORTS_PER_BB); }
  static toBB(lamports)   { return lamports / LAMPORTS_PER_BB; }

  /** Format lamports as "1,000.00 BB" */
  static formatBB(lamports, decimals = 2) {
    return (lamports / LAMPORTS_PER_BB).toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: Math.max(decimals, 4),
    }) + ' BB';
  }

  /** Shorten address for logs: "a1b2c3…f4e5" */
  static shortAddr(address, chars = 6) {
    if (!address || address.length <= chars * 2) return address;
    return `${address.slice(0, chars)}…${address.slice(-4)}`;
  }
}


// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/** Generate a UUID v4 nonce */
function _uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
  });
}

/** Concatenate Uint8Arrays */
function _concat(arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out   = new Uint8Array(total);
  let offset  = 0;
  for (const a of arrays) { out.set(a, offset); offset += a.length; }
  return out;
}

/**
 * Wrap a raw 32-byte Ed25519 seed in PKCS#8 DER for WebCrypto import.
 * Ed25519 PKCS#8 = fixed 16-byte prefix + 32-byte seed.
 */
function _ed25519Pkcs8(seed) {
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
    0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  return pkcs8.buffer;
}


// ============================================================================
// EXPORTS
// ============================================================================

export { BlackBookAgent, LAMPORTS_PER_BB, CHAIN_ID };

// CommonJS fallback
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BlackBookAgent, LAMPORTS_PER_BB, CHAIN_ID };
}
