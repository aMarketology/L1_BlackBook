// ============================================================================
// BLACKBOOK EXPLORER SDK — v1.0
// ============================================================================
//
// Read-only SDK for the BlackBook L1 block explorer frontend.
// All methods are unauthenticated — no wallet, no shards, no signing.
//
// Covers:
//   1. NETWORK     — Health, version, genesis hash, slot, epoch info
//   2. SUPPLY      — Total supply, circulating, lamport conversion
//   3. ACCOUNTS    — Balance lookups (single + batch), account info
//   4. BLOCKS      — Block data, latest blockhash
//   5. TRANSACTIONS — History by address, detail by signature
//   6. RESERVES    — Proof-of-reserves (BB supply vs USDC backing)
//   7. VALIDATORS  — Leader schedule, cluster info (future)
//   8. UTILITIES   — Formatting, address shortening, time display
//
// Usage:
//   <script src="explorer_sdk.js"></script>
//   const explorer = new BlackBookExplorer('https://rpc.blackbook.finance:8899');
//
//   // Node.js:
//   const { BlackBookExplorer } = require('./explorer_sdk');
//   const explorer = new BlackBookExplorer('http://localhost:8899');
//
// ============================================================================

const LAMPORTS_PER_BB = 1_000_000_000;
const CHAIN_ID = 0xBB;

// ============================================================================
// EXPLORER CLASS
// ============================================================================

class BlackBookExplorer {
  /**
   * Create an explorer instance.
   *
   * @param {string} rpcUrl   - BlackBook JSON-RPC endpoint (port 8899)
   * @param {string} [apiUrl] - BlackBook HTTP API endpoint (port 8080)
   * @param {Object} [opts]   - Optional config
   * @param {number} [opts.timeout] - Request timeout in ms (default: 30000)
   *
   * @example
   *   const explorer = new BlackBookExplorer('https://rpc.blackbook.finance:8899');
   */
  constructor(rpcUrl, apiUrl, opts = {}) {
    this.rpcUrl = rpcUrl.replace(/\/+$/, '');
    this.apiUrl = (apiUrl || rpcUrl.replace(':8899', ':8080')).replace(/\/+$/, '');
    this.timeout = opts.timeout || 30_000;
    this._rpcId = 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL TRANSPORT
  // ═══════════════════════════════════════════════════════════════════════════

  /** @private JSON-RPC 2.0 call */
  async _rpc(method, params = []) {
    const id = ++this._rpcId;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(this.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const json = await res.json();
      if (json.error) throw new Error(json.error.message || JSON.stringify(json.error));
      return json.result;
    } finally {
      clearTimeout(timer);
    }
  }

  /** @private Batched JSON-RPC (multiple calls in one HTTP request) */
  async _rpcBatch(calls) {
    const body = calls.map((c, i) => ({
      jsonrpc: '2.0',
      id: i,
      method: c.method,
      params: c.params || [],
    }));
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(this.rpcUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      const results = await res.json();
      return results.sort((a, b) => a.id - b.id);
    } finally {
      clearTimeout(timer);
    }
  }

  /** @private HTTP API GET */
  async _apiGet(path) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method: 'GET',
        signal: ctrl.signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally {
      clearTimeout(timer);
    }
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 1. NETWORK — Chain state & node info
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Check if the node is healthy.
   * @returns {Promise<string>} "ok" if healthy
   *
   * @example
   *   const health = await explorer.getHealth(); // "ok"
   */
  async getHealth() {
    return this._rpc('getHealth');
  }

  /**
   * Get node version info.
   * @returns {Promise<{ 'solana-core': string, 'feature-set': number }>}
   */
  async getVersion() {
    return this._rpc('getVersion');
  }

  /**
   * Get genesis hash (identifies the chain).
   * @returns {Promise<string>} Base58 genesis hash
   */
  async getGenesisHash() {
    return this._rpc('getGenesisHash');
  }

  /**
   * Get current slot number.
   * @returns {Promise<number>}
   *
   * @example
   *   const slot = await explorer.getSlot(); // 142857
   */
  async getSlot() {
    return this._rpc('getSlot');
  }

  /**
   * Get epoch info: current slot, epoch number, block height, tx count.
   * @returns {Promise<{ absoluteSlot, blockHeight, epoch, slotIndex, slotsInEpoch, transactionCount }>}
   *
   * @example
   *   const info = await explorer.getEpochInfo();
   *   console.log(`Epoch ${info.epoch}, Slot ${info.absoluteSlot}`);
   *   console.log(`${info.transactionCount} total transactions`);
   */
  async getEpochInfo() {
    return this._rpc('getEpochInfo');
  }

  /**
   * Get latest blockhash.
   * @returns {Promise<{ blockhash: string, lastValidBlockHeight: number }>}
   */
  async getLatestBlockhash() {
    return this._rpc('getLatestBlockhash');
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 2. SUPPLY — Token supply overview
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get total on-chain BB supply.
   * @returns {Promise<{ totalLamports: number, totalBB: number, circulating: number }>}
   *
   * @example
   *   const supply = await explorer.getSupply();
   *   console.log(`Total: ${supply.totalBB} BB`);
   *   console.log(`Circulating: ${supply.circulating} BB`);
   */
  async getSupply() {
    const result = await this._rpc('getSupply');
    return {
      totalLamports: result.value.total,
      totalBB: result.value.total / LAMPORTS_PER_BB,
      circulating: result.value.circulating / LAMPORTS_PER_BB,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 3. ACCOUNTS — Balance & account lookups
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get BB balance for an address.
   * @param {string} address - Base58 public key
   * @returns {Promise<{ lamports: number, bb: number }>}
   *
   * @example
   *   const bal = await explorer.getBalance('8CZJAZnbm85qywRfAw1tXRnAvACPciuYvK36A4BS3hCm');
   *   console.log(`${bal.bb} BB`); // "1000 BB"
   */
  async getBalance(address) {
    const result = await this._rpc('getBalance', [address]);
    return {
      lamports: result.value,
      bb: result.value / LAMPORTS_PER_BB,
    };
  }

  /**
   * Get BB balance via REST endpoint.
   * @param {string} address
   * @returns {Promise<{ address: string, balance: number, name: string|null, unit: string }>}
   *
   * @example
   *   const info = await explorer.getBalanceREST('8CZJAZn...');
   *   console.log(`${info.balance} ${info.unit}`); // "1000 BB"
   */
  async getBalanceREST(address) {
    return this._apiGet(`/balance/${address}`);
  }

  /**
   * Get balances for multiple addresses in a single HTTP round-trip.
   * @param {string[]} addresses - Array of base58 public keys
   * @returns {Promise<Object.<string, { lamports: number, bb: number }>>}
   *
   * @example
   *   const balances = await explorer.getBalances([addr1, addr2, addr3]);
   *   Object.entries(balances).forEach(([addr, bal]) => {
   *     console.log(`${BlackBookExplorer.shortAddr(addr)}: ${bal.bb} BB`);
   *   });
   */
  async getBalances(addresses) {
    const calls = addresses.map(addr => ({ method: 'getBalance', params: [addr] }));
    const results = await this._rpcBatch(calls);
    const map = {};
    results.forEach((r, i) => {
      if (r.result) {
        map[addresses[i]] = {
          lamports: r.result.value,
          bb: r.result.value / LAMPORTS_PER_BB,
        };
      }
    });
    return map;
  }

  /**
   * Get full account info (lamports, owner, data, executable).
   * @param {string} address
   * @returns {Promise<Object|null>}
   *
   * @example
   *   const info = await explorer.getAccountInfo('8CZJAZn...');
   *   if (info) {
   *     console.log(`Lamports: ${info.lamports}`);
   *     console.log(`Owner: ${info.owner}`);
   *   }
   */
  async getAccountInfo(address) {
    const result = await this._rpc('getAccountInfo', [address, { encoding: 'base64' }]);
    return result.value;
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 4. TRANSACTIONS — History & detail lookups
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get recent transaction signatures for an address.
   * @param {string} address - Base58 public key
   * @param {number} [limit=20] - Max results (default 20)
   * @returns {Promise<Array<TxSignature>>}
   *
   * @typedef {Object} TxSignature
   * @property {string} signature          - Transaction signature
   * @property {number} slot               - Slot number
   * @property {Object|null} err           - Error object (null = success)
   * @property {number} blockTime          - Unix timestamp
   * @property {string} confirmationStatus - "finalized" | "confirmed" | "processed"
   *
   * @example
   *   const txs = await explorer.getSignaturesForAddress('8CZJAZn...', 10);
   *   txs.forEach(tx => {
   *     const time = BlackBookExplorer.timeAgo(tx.blockTime);
   *     const status = tx.err ? 'FAILED' : 'OK';
   *     console.log(`${tx.signature} — ${status} — ${time}`);
   *   });
   */
  async getSignaturesForAddress(address, limit = 20) {
    return this._rpc('getSignaturesForAddress', [address, { limit }]);
  }

  /**
   * Get full transaction detail by signature.
   * @param {string} signature - Transaction signature
   * @returns {Promise<Object|null>} Full transaction object or null
   *
   * @example
   *   const tx = await explorer.getTransaction('3fKx...');
   *   if (tx) {
   *     console.log('Block time:', new Date(tx.blockTime * 1000));
   *     console.log('Slot:', tx.slot);
   *   }
   */
  async getTransaction(signature) {
    return this._rpc('getTransaction', [signature, { encoding: 'json' }]);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 5. RESERVES — Proof of Reserves
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get proof-of-reserves data.
   * Shows BB supply vs USDC reserve backing, ratio, and Merkle root.
   *
   * @returns {Promise<ReservesData>}
   *
   * @typedef {Object} ReservesData
   * @property {number} bbSupply           - Total BB supply (in BB)
   * @property {number} bbSupplyLamports   - Total BB supply (in lamports)
   * @property {number} usdcHeld           - USDC held in reserve
   * @property {string} usdcReserveWallet  - Solana address of USDC reserve
   * @property {number} ratio              - BB:USDC ratio (target: 10:1)
   * @property {boolean} fullyBacked       - True if reserves cover supply
   * @property {string} merkleRoot         - Merkle root of reserve proof
   * @property {string} lastVerified       - ISO timestamp of last verification
   * @property {string} solanaExplorerUrl  - Link to Solana explorer for USDC wallet
   *
   * @example
   *   const reserves = await explorer.getReserves();
   *   console.log(`BB Supply: ${reserves.bbSupply} BB`);
   *   console.log(`USDC Held: $${reserves.usdcHeld}`);
   *   console.log(`Ratio: ${reserves.ratio}:1`);
   *   console.log(`Fully backed: ${reserves.fullyBacked ? 'YES' : 'NO'}`);
   */
  async getReserves() {
    const data = await this._apiGet('/reserves');
    return {
      bbSupply:          data.bb_supply_bb || data.bb_supply,
      bbSupplyLamports:  data.bb_supply,
      usdcHeld:          data.usdc_held,
      usdcReserveWallet: data.usdc_reserve_wallet,
      ratio:             data.ratio,
      fullyBacked:       data.fully_backed,
      merkleRoot:        data.merkle_root,
      lastVerified:      data.last_verified,
      solanaExplorerUrl: data.solana_explorer_url,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 6. UTILITIES — Formatting helpers for explorer UI
  // ═══════════════════════════════════════════════════════════════════════════

  /** Convert BB to lamports */
  static toLamports(bb) {
    return Math.floor(bb * LAMPORTS_PER_BB);
  }

  /** Convert lamports to BB */
  static toBB(lamports) {
    return lamports / LAMPORTS_PER_BB;
  }

  /**
   * Format BB for display: "1,000.00"
   * @param {number} lamports
   * @param {number} [decimals=2]
   * @returns {string}
   */
  static formatBB(lamports, decimals = 2) {
    const bb = lamports / LAMPORTS_PER_BB;
    return bb.toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: Math.max(decimals, 4),
    });
  }

  /**
   * Shorten address for UI: "4PtfY2…2oby"
   * @param {string} address
   * @param {number} [chars=6]
   * @returns {string}
   */
  static shortAddr(address, chars = 6) {
    if (!address || address.length <= chars * 2) return address;
    return `${address.slice(0, chars)}…${address.slice(-4)}`;
  }

  /**
   * Human-readable time since Unix timestamp.
   * @param {number} unixSeconds
   * @returns {string} e.g. "5m ago", "2h ago", "3d ago"
   *
   * @example
   *   const txs = await explorer.getSignaturesForAddress(addr);
   *   txs.forEach(tx => {
   *     console.log(`${tx.signature} — ${BlackBookExplorer.timeAgo(tx.blockTime)}`);
   *   });
   */
  static timeAgo(unixSeconds) {
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;
    if (diff < 5) return 'just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  /**
   * Format a Unix timestamp as a locale date string.
   * @param {number} unixSeconds
   * @returns {string}
   */
  static formatDate(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  /**
   * Format lamports with unit suffix for display.
   * @param {number} lamports
   * @returns {string} e.g. "1,000.00 BB"
   */
  static formatWithUnit(lamports, decimals = 2) {
    return `${BlackBookExplorer.formatBB(lamports, decimals)} BB`;
  }
}


// ============================================================================
// EXPORTS
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BlackBookExplorer, LAMPORTS_PER_BB, CHAIN_ID };
}

if (typeof globalThis !== 'undefined') {
  globalThis.BlackBookExplorer = BlackBookExplorer;
}
