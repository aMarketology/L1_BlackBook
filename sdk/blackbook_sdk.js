// ============================================================================
// BLACKBOOK SDK — Production v3.0
// ============================================================================
//
// Complete JavaScript SDK for BlackBook L1 blockchain.
// Supports: Wallet creation (BIP-39 + Shamir 2-of-3 SSS), SSS signing,
//           SSS recovery verification, transfers, faucet, balance queries,
//           wallet session management, and WalletConnect v2 sessions.
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
const MAX_FAUCET_BB = 99_999;

/**
 * Valid 2-of-3 SSS shard combinations for wallet recovery/verification.
 * Each combo specifies which two of the three shards to use.
 */
const SSS_COMBOS = {
  AB: { label: 'A + B', desc: 'User + Server',  shards: ['A', 'B'] },
  AC: { label: 'A + C', desc: 'User + Cold',    shards: ['A', 'C'] },
  BC: { label: 'B + C', desc: 'Server + Cold',  shards: ['B', 'C'] },
};

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
  // 3. WALLET — Create + SSS (BIP-39 + Shamir 2-of-3)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Create a new Shamir 2-of-3 wallet on the BlackBook node.
   *
   * The server generates a BIP-39 mnemonic → Ed25519 keypair → Shamir splits
   * the 32-byte seed into three shares (any 2 reconstruct the full keypair):
   *
   *   - Shard A (User):     Encrypted with user's password (Argon2id + AES-256-GCM).
   *                         Returned to the client → store in localStorage or Supabase.
   *   - Shard B (Server):   Encrypted with SERVER_MASTER_KEY → stored on node in ReDB.
   *                         Never leaves the server in raw form.
   *   - Shard C (Cold):     Returned raw hex → user writes it down offline.
   *                         Also synced to HashiCorp Vault for emergency recovery.
   *
   * @param {string} username              - Username (for Supabase account sync)
   * @param {Object} [opts]                - Optional parameters
   * @param {string} [opts.password]        - Encrypts Shard A (Argon2id → AES-256-GCM). Highly recommended.
   * @param {string} [opts.pin]            - PIN hash stored for high-value tx authorization
   * @param {number} [opts.dailyLimit=500] - BB threshold above which PIN is required
   * @returns {{ walletId, address, mnemonic, shardA, shardAIsEncrypted, shardC, publicKey }}
   */
  async createWallet(username, opts = {}) {
    const result = await this._api('/wallet/create', {
      username,
      password:    opts.password || undefined,
      pin:         opts.pin || undefined,
      daily_limit: opts.dailyLimit || undefined,
    });

    const wallet = {
      walletId:         result.wallet_id,
      address:          result.address,
      mnemonic:         result.mnemonic,           // BIP-39 24-word phrase
      shardA:           result.share_a,            // Encrypted with password (or raw hex if no password)
      shardAIsEncrypted: result.share_a_is_encrypted,
      shardC:           result.share_c,            // Raw hex — show ONCE, user stores offline
      publicKey:        result.public_key,
    };

    return wallet;
  }

  /**
   * Retrieve Shard B from the node (server-encrypted blob).
   * The server stores this encrypted with SERVER_MASTER_KEY.
   * During SSS verify or transfer, the server decrypts it internally.
   *
   * @param {string} walletId - Wallet address / ID
   * @returns {{ shardB: string, status: string }}
   */
  async getShardB(walletId) {
    const result = await this._api('/wallet/secure/shard-b', {
      wallet_id: walletId,
    });
    return {
      shardB: result.shard_b,
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
  // 3b. SSS VERIFICATION — Test 2-of-3 shard reconstruction
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Verify that two Shamir shards reconstruct the correct wallet.
   *
   * Sends two shards to the server, which reconstructs the Ed25519 seed,
   * derives the public key, and checks it matches the wallet address.
   *
   * @param {Object} params
   * @param {string} params.walletId               - Wallet address to verify against
   * @param {string} params.shard1                 - First shard (hex or encrypted blob)
   * @param {string} params.shard2                 - Second shard (hex or encrypted blob)
   * @param {string} [params.password]             - Password if shard1 is password-encrypted (Share A)
   * @param {boolean} [params.shard2IsServerEncrypted] - True if shard2 is server-encrypted (Share B)
   * @returns {{ success, walletId, derivedAddress, matches, message }}
   */
  async verifySss({ walletId, shard1, shard2, password, shard2IsServerEncrypted = false }) {
    const result = await this._api('/wallet/verify-sss', {
      wallet_id:                walletId,
      shard_1:                  shard1,
      shard_2:                  shard2,
      password:                 password || undefined,
      shard_2_is_server_encrypted: shard2IsServerEncrypted,
    });
    return {
      success:        result.success,
      walletId:       result.wallet_id,
      derivedAddress: result.derived_address,
      matches:        result.matches,
      message:        result.message,
    };
  }

  /**
   * High-level SSS verification using a named combo (AB, AC, or BC).
   *
   * Automatically handles shard ordering, server-encrypted flags, and
   * auto-fetches Shard B from the node when needed.
   *
   * @param {Object} params
   * @param {'AB'|'AC'|'BC'} params.combo    - Which two shards to combine
   * @param {string} params.walletId         - Wallet address to verify against
   * @param {string} [params.shardA]         - Share A (encrypted with password)
   * @param {string} [params.shardB]         - Share B (server-encrypted). Auto-fetched if omitted for AB/BC.
   * @param {string} [params.shardC]         - Share C (raw hex from cold storage)
   * @param {string} [params.password]       - Password to decrypt Share A (required for AB, AC)
   * @returns {{ success, walletId, derivedAddress, matches, message }}
   */
  async verifySssWithCombo({ combo, walletId, shardA, shardB, shardC, password }) {
    if (!SSS_COMBOS[combo]) {
      throw new Error(`Invalid combo "${combo}". Use: ${Object.keys(SSS_COMBOS).join(', ')}`);
    }

    // Auto-fetch Shard B from node if not provided
    if ((combo === 'AB' || combo === 'BC') && !shardB) {
      const bResp = await this.getShardB(walletId);
      shardB = bResp.shardB;
    }

    switch (combo) {
      case 'AB':
        // shard1 = A (password-encrypted), shard2 = B (server-encrypted)
        return this.verifySss({
          walletId,
          shard1: shardA,
          shard2: shardB,
          password,
          shard2IsServerEncrypted: true,
        });

      case 'AC':
        // shard1 = A (password-encrypted), shard2 = C (raw hex)
        return this.verifySss({
          walletId,
          shard1: shardA,
          shard2: shardC,
          password,
          shard2IsServerEncrypted: false,
        });

      case 'BC':
        // shard1 = C (raw hex), shard2 = B (server-encrypted)
        // Note: we pass C as shard_1 (no password) and B as shard_2 (server-encrypted)
        return this.verifySss({
          walletId,
          shard1: shardC,
          shard2: shardB,
          password: undefined,
          shard2IsServerEncrypted: true,
        });

      default:
        throw new Error(`Unhandled combo: ${combo}`);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 4. TRANSFERS — Send BB tokens
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * SSS-authenticated transfer (Shamir 2-of-3 signing on the node).
   *
   * Flow:
   *   1. Client sends encrypted Shard A + password
   *   2. Server decrypts Shard A (password) + Shard B (SERVER_MASTER_KEY)
   *   3. Shamir reconstruction → 32-byte Ed25519 seed
   *   4. Derive signing key → verify address matches
   *   5. Sign transfer message → Ed25519 signature
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
  // 6. FAUCET — Mint tokens (max 99,999 BB per address per epoch, rate-limited)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Request up to 99,999 BB from the faucet.
   * Available to any address. Rate-limited to one mint per address per epoch.
   *
   * @param {string} toAddress - Recipient address
   * @param {number} [amountBB=100] - Amount in BB (server caps at 99,999 per epoch)
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
  // 9. WALLET SESSION — Full wallet persistence (localStorage)
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Save full wallet session to browser localStorage.
   * Stores: walletId, address, shardA (encrypted), shardAIsEncrypted, publicKey.
   * NOTE: Mnemonic and Shard C are intentionally NOT stored — show once only.
   *
   * @param {Object} wallet - Wallet object from createWallet()
   */
  saveWalletLocal(wallet) {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available — use Node.js file storage instead');
    }
    const session = {
      wallet_id:          wallet.walletId,
      address:            wallet.address,
      share_a:            wallet.shardA,
      share_a_is_encrypted: wallet.shardAIsEncrypted,
      public_key:         wallet.publicKey,
      created_at:         new Date().toISOString(),
    };
    localStorage.setItem('bb_wallet', JSON.stringify(session));
    // Also save shard A separately for backward compat
    localStorage.setItem(`bb_shard_a_${wallet.walletId}`, wallet.shardA);
  }

  /**
   * Load wallet session from browser localStorage.
   *
   * @returns {{ walletId, address, shardA, shardAIsEncrypted, publicKey, createdAt }|null}
   */
  loadWalletLocal() {
    if (typeof localStorage === 'undefined') return null;
    try {
      const raw = localStorage.getItem('bb_wallet');
      if (!raw) return null;
      const s = JSON.parse(raw);
      return {
        walletId:         s.wallet_id,
        address:          s.address,
        shardA:           s.share_a,
        shardAIsEncrypted: s.share_a_is_encrypted,
        publicKey:        s.public_key,
        createdAt:        s.created_at,
      };
    } catch (_) {
      return null;
    }
  }

  /**
   * Delete wallet session from browser localStorage.
   * Removes both the session and the shard-specific key.
   *
   * @param {string} [walletId] - If provided, also removes the shard-specific key
   */
  deleteWalletLocal(walletId) {
    if (typeof localStorage === 'undefined') return;
    localStorage.removeItem('bb_wallet');
    if (walletId) {
      localStorage.removeItem(`bb_shard_a_${walletId}`);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 9b. SHARD STORAGE HELPERS — Individual shard + Supabase backup
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Save Shard A to browser localStorage (individual storage).
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
  module.exports = { BlackBookSDK, LAMPORTS_PER_BB, CHAIN_ID, MAX_FAUCET_BB, SSS_COMBOS };
}

if (typeof globalThis !== 'undefined') {
  globalThis.BlackBookSDK = BlackBookSDK;
  globalThis.SSS_COMBOS = SSS_COMBOS;
}