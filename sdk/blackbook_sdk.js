// ============================================================================
// BLACKBOOK SDK — Production v2.0
// ============================================================================
//
// Complete JavaScript SDK for BlackBook L1 blockchain.
// Supports: Wallet creation (FROST 2-of-3), SSS signing, transfers,
//           faucet, balance queries, and WalletConnect v2 session management.
//
// Browser:
//   <script src="blackbook_sdk.js"></script>
//   const bb = new BlackBookSDK('https://rpc.blackbook.finance:8899')
//
// Node.js / CJS:
//   const { BlackBookSDK } = require('@blackbook/sdk')
//
// ES Modules:
//   import { BlackBookSDK } from '@blackbook/sdk'
//
// ============================================================================

const LAMPORTS_PER_BB = 1_000_000_000;
const CHAIN_ID = 0xBB;
const MAX_FAUCET_BB = 100;

// ============================================================================
// SDK CLASS
// ============================================================================

class BlackBookSDK {
  /**
   * @param {string} rpcUrl    - BlackBook JSON-RPC endpoint (port 8899)
   * @param {string} [apiUrl]  - BlackBook HTTP API endpoint (port 8080)
   * @param {Object} [opts]    - Optional config
   * @param {string} [opts.jwt]         - Supabase JWT for authenticated endpoints
   * @param {number} [opts.timeout]     - Request timeout in ms (default: 30000)
   */
  constructor(rpcUrl, apiUrl, opts = {}) {
    // Normalise URLs (strip trailing slash)
    this.rpcUrl = rpcUrl.replace(/\/+$/, '');
    this.apiUrl = (apiUrl || rpcUrl.replace(':8899', ':8080')).replace(/\/+$/, '');
    this.jwt = opts.jwt || null;
    this.timeout = opts.timeout || 30_000;
    this._rpcId = 0;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // INTERNAL HELPERS
  // ───────────────────────────────────────────────────────────────────────────

  /** JSON-RPC 2.0 call */
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

  /** Batched JSON-RPC (multiple calls in one HTTP request) */
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

  /** HTTP API call (POST to /path) */
  async _api(path, body = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (this.jwt) headers['Authorization'] = `Bearer ${this.jwt}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);

    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  /** HTTP API GET call */
  async _apiGet(path) {
    const headers = {};
    if (this.jwt) headers['Authorization'] = `Bearer ${this.jwt}`;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeout);

    try {
      const res = await fetch(`${this.apiUrl}${path}`, {
        method: 'GET',
        headers,
        signal: ctrl.signal,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally {
      clearTimeout(timer);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 1. NETWORK — Read chain state
  // ───────────────────────────────────────────────────────────────────────────

  /** Check if the node is healthy */
  async getHealth() {
    return this._rpc('getHealth');
  }

  /** Get node version */
  async getVersion() {
    return this._rpc('getVersion');
  }

  /** Get genesis hash */
  async getGenesisHash() {
    return this._rpc('getGenesisHash');
  }

  /** Get current slot */
  async getSlot() {
    return this._rpc('getSlot');
  }

  /** Get epoch info (slot, epoch, blockHeight, transactionCount) */
  async getEpochInfo() {
    return this._rpc('getEpochInfo');
  }

  /** Get total on-chain supply (returns lamports + BB conversion) */
  async getSupply() {
    const result = await this._rpc('getSupply');
    return {
      totalLamports: result.value.total,
      totalBB: result.value.total / LAMPORTS_PER_BB,
      circulating: result.value.circulating / LAMPORTS_PER_BB,
    };
  }

  /** Get latest blockhash */
  async getLatestBlockhash() {
    return this._rpc('getLatestBlockhash');
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 2. ACCOUNTS — Balances and account info
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Get BB balance for an address
   * @param {string} address - BlackBook public address
   * @returns {{ lamports: number, bb: number }}
   */
  async getBalance(address) {
    const result = await this._rpc('getBalance', [address]);
    return {
      lamports: result.value,
      bb: result.value / LAMPORTS_PER_BB,
    };
  }

  /**
   * Get balances for multiple addresses (single HTTP round-trip)
   * @param {string[]} addresses
   * @returns {Object.<string, { lamports: number, bb: number }>}
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
   * Get full account info (lamports, owner, data, executable)
   * @param {string} address
   * @returns {Object|null}
   */
  async getAccountInfo(address) {
    const result = await this._rpc('getAccountInfo', [address, { encoding: 'base64' }]);
    return result.value;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 3. WALLET — Create + SSS (FROST 2-of-3)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Create a new FROST 2-of-3 wallet on the BlackBook node.
   *
   * The server performs FROST Ed25519 key generation producing three shards:
   *   - Shard A (Active):   Encrypted with user's password (Argon2id + AES-256-GCM).
   *                         Returned to the client → store in localStorage or Supabase.
   *   - Shard B (Cloud):    Encrypted with SERVER_MASTER_KEY → stored on node in ReDB.
   *                         Never leaves the server in raw form.
   *   - Shard C (Recovery): Returned raw in response → user writes it down offline.
   *                         Also synced to HashiCorp Vault for emergency recovery.
   *
   * @param {string} username    - Username (for Supabase account sync)
   * @param {string} password    - Encrypts Shard A server-side (Argon2id → AES-256-GCM)
   * @param {string} pin         - PIN hash stored for high-value tx authorization
   * @param {number} [dailyLimit=500] - BB threshold above which PIN is required
   * @returns {{ walletId, address, mnemonic, shardA, shardC, publicKey }}
   */
  async createWallet(username, password, pin, dailyLimit = 500) {
    const result = await this._api('/wallet/create', {
      username,
      password,
      pin,
      daily_limit: dailyLimit,
    });

    return {
      walletId:  result.wallet_id,
      address:   result.address,
      mnemonic:  result.mnemonic,   // BIP-39 — user writes this down
      shardA:    result.share_a,    // Encrypted with password (Argon2id + AES-256-GCM)
      shardC:    result.share_c,    // Raw hex — show ONCE, user stores offline
      publicKey: result.public_key,
    };
  }

  /**
   * Retrieve Shard B metadata from the node (server-encrypted, never raw).
   * Used to verify the shard exists; the node decrypts it internally during signing.
   *
   * @param {string} walletId
   * @returns {{ shardB: string, status: string }}
   */
  async getShardB(walletId) {
    const result = await this._api('/wallet/secure/shard-b', {
      wallet_id: walletId,
    });
    return {
      shardB: result.shard_b || result.encrypted_share_b,
      status: result.status,
    };
  }

  /**
   * Recover Shard C from HashiCorp Vault (emergency recovery only).
   * Requires authenticated JWT with aal2 (2FA).
   *
   * @returns {{ shardC: string, warning: string }}
   */
  async recoverShardC() {
    const result = await this._api('/wallet/secure/recover-shard-c', {});
    return {
      shardC:  result.shard_c,
      warning: result.warning,
    };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 4. TRANSFERS — Send BB tokens
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * SSS-authenticated transfer (FROST 2-of-3 signing on the node).
   *
   * Flow:
   *   1. Client sends encrypted Shard A + password
   *   2. Server decrypts Shard A (password) + Shard B (SERVER_MASTER_KEY)
   *   3. FROST round1 → commitments
   *   4. FROST round2 → signature shares
   *   5. Aggregate → valid Ed25519 signature
   *   6. Transfer executed on-chain
   *
   * @param {string} fromWalletId - Sender wallet ID
   * @param {string} toAddress    - Recipient address
   * @param {number} amountBB     - Amount in BB (not lamports)
   * @param {string} shardA       - Encrypted Shard A (from localStorage / Supabase)
   * @param {string} password     - Password to decrypt Shard A
   * @returns {{ success, signature, from, to, amount, fromBalance, toBalance }}
   */
  async transferWithSSS(fromWalletId, toAddress, amountBB, shardA, password) {
    const result = await this._api('/transfer', {
      from_wallet_id: fromWalletId,
      to_address:     toAddress,
      amount:         amountBB,
      share_a:        shardA,
      password,
    });
    return {
      success:     result.success,
      signature:   result.signature,
      from:        result.from,
      to:          result.to,
      amount:      result.amount,
      fromBalance: result.from_balance,
      toBalance:   result.to_balance,
    };
  }

  /**
   * Simple transfer with pre-signed Ed25519 payload.
   * Used by the embedded web wallet and admin tools.
   *
   * @param {string} from     - Sender address
   * @param {string} to       - Recipient address
   * @param {number} amountBB - Amount in BB
   * @returns {{ signature, from, to }}
   */
  async transferSimple(from, to, amountBB) {
    const lamports = Math.floor(amountBB * LAMPORTS_PER_BB);
    return this._api('/transfer/simple', { from, to, amount: lamports });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 5. TRANSACTIONS — History + lookups
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Get recent transaction signatures for an address
   * @param {string} address
   * @param {number} [limit=20]
   * @returns {Array<{ signature, slot, err, blockTime, confirmationStatus }>}
   */
  async getSignaturesForAddress(address, limit = 20) {
    return this._rpc('getSignaturesForAddress', [address, { limit }]);
  }

  /**
   * Get full transaction detail by signature
   * @param {string} signature
   * @returns {Object|null}
   */
  async getTransaction(signature) {
    return this._rpc('getTransaction', [signature, { encoding: 'json' }]);
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 6. FAUCET — Mint tokens (max 100 BB per request, rate-limited)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Request up to 100 BB from the faucet.
   * Available to any address. Rate-limited to one mint per address per epoch.
   *
   * @param {string} toAddress - Recipient address
   * @param {number} [amountBB=100] - Amount in BB (server caps at 100)
   * @returns {{ success, minted, to, new_balance }}
   */
  async faucet(toAddress, amountBB = 100) {
    if (amountBB > MAX_FAUCET_BB) amountBB = MAX_FAUCET_BB;
    if (amountBB <= 0) throw new Error('Amount must be positive');
    return this._api('/faucet', { to: toAddress, amount: amountBB });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 7. RESERVES — Proof of Reserves
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Get proof-of-reserves data.
   * Returns BB supply, USDC reserve balance, ratio, and Merkle root.
   *
   * @returns {{ bbSupply, usdcHeld, ratio, fullyBacked, merkleRoot, lastVerified }}
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

  // ───────────────────────────────────────────────────────────────────────────
  // 8. WALLETCONNECT v2 — Session helpers
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Chain metadata for WalletConnect v2 SignClient registration.
   *
   * @returns {{ chainId, chainName, rpcUrl, nativeCurrency }}
   */
  getChainConfig() {
    return {
      // CAIP-2 identifier for BlackBook L1
      chainId: 'solana:blackbook-l1',
      chainName: 'BlackBook L1',
      rpcUrl: this.rpcUrl,
      nativeCurrency: {
        name: 'BlackBook',
        symbol: 'BB',
        decimals: 9,  // LAMPORTS_PER_BB = 1e9
      },
    };
  }

  /**
   * WalletConnect v2 required namespaces for session proposal.
   * Pass to: client.connect({ requiredNamespaces: bb.getWCNamespaces() })
   *
   * @returns {Object}
   */
  getWCNamespaces() {
    return {
      solana: {
        methods: ['solana_signTransaction', 'solana_signMessage'],
        chains: ['solana:blackbook-l1'],
        events: ['accountsChanged'],
      },
    };
  }

  /**
   * Extract the connected address from a WalletConnect session.
   *
   * @param {Object} session - WalletConnect session object
   * @returns {string|null} - BlackBook address or null
   */
  parseWCAddress(session) {
    const accounts = session?.namespaces?.solana?.accounts ?? [];
    if (accounts.length === 0) return null;
    // Format: "solana:blackbook-l1:ADDRESS"
    return accounts[0].split(':')[2] || null;
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 9. SHARD STORAGE HELPERS — Local + Supabase backup
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Save Shard A to browser localStorage.
   * The shard is already encrypted (Argon2id + AES-256-GCM) by the server.
   *
   * @param {string} walletId - Wallet identifier
   * @param {string} encryptedShardA - Pre-encrypted shard from createWallet()
   */
  saveShardALocal(walletId, encryptedShardA) {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available — use Node.js file storage instead');
    }
    localStorage.setItem(`bb_shard_a_${walletId}`, encryptedShardA);
  }

  /**
   * Load Shard A from browser localStorage.
   *
   * @param {string} walletId
   * @returns {string|null}
   */
  loadShardALocal(walletId) {
    if (typeof localStorage === 'undefined') return null;
    return localStorage.getItem(`bb_shard_a_${walletId}`);
  }

  /**
   * Delete Shard A from browser localStorage (e.g. on logout).
   *
   * @param {string} walletId
   */
  deleteShardALocal(walletId) {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(`bb_shard_a_${walletId}`);
    }
  }

  /**
   * Backup Shard A to Supabase (for users who create an account).
   * Requires JWT to be set.
   *
   * @param {string} walletId
   * @param {string} encryptedShardA
   * @returns {Promise<Object>}
   */
  async backupShardAToSupabase(walletId, encryptedShardA) {
    if (!this.jwt) throw new Error('JWT required for Supabase backup');
    return this._api('/wallet/backup-shard-a', {
      wallet_id: walletId,
      encrypted_shard_a: encryptedShardA,
    });
  }

  /**
   * Restore Shard A from Supabase backup.
   * Requires JWT to be set.
   *
   * @param {string} walletId
   * @returns {Promise<{ encryptedShardA: string }>}
   */
  async restoreShardAFromSupabase(walletId) {
    if (!this.jwt) throw new Error('JWT required for Supabase restore');
    const result = await this._api('/wallet/restore-shard-a', {
      wallet_id: walletId,
    });
    return { encryptedShardA: result.encrypted_shard_a };
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 10. UTILITIES
  // ───────────────────────────────────────────────────────────────────────────

  /** Convert BB to lamports */
  static toLamports(bb) {
    return Math.floor(bb * LAMPORTS_PER_BB);
  }

  /** Convert lamports to BB */
  static toBB(lamports) {
    return lamports / LAMPORTS_PER_BB;
  }

  /** Format BB for display */
  static formatBB(lamports, decimals = 2) {
    const bb = lamports / LAMPORTS_PER_BB;
    return bb.toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: Math.max(decimals, 4),
    });
  }

  /** Shorten address for UI: "4PtfY2…2oby" */
  static shortAddr(address, chars = 6) {
    if (!address || address.length <= chars * 2) return address;
    return `${address.slice(0, chars)}…${address.slice(-4)}`;
  }

  /** Human-readable time since Unix timestamp */
  static timeAgo(unixSeconds) {
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;
    if (diff < 5) return 'just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  /** Set or update JWT (e.g. after Supabase login) */
  setJWT(jwt) {
    this.jwt = jwt;
  }
}

// ============================================================================
// EXPORTS — Works in Node.js (CJS), ES Modules, and browser <script> tags
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BlackBookSDK, LAMPORTS_PER_BB, CHAIN_ID, MAX_FAUCET_BB };
}

if (typeof globalThis !== 'undefined') {
  globalThis.BlackBookSDK = BlackBookSDK;
}