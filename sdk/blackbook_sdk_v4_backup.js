// ============================================================================
// BLACKBOOK SDK — v4.0 — Unified Explorer + Wallet
// ============================================================================
//
// Single-file SDK covering every BlackBook L1 HTTP and JSON-RPC endpoint.
// Import this file for both the block explorer UI and the wallet UI.
//
// PUBLIC ENDPOINTS (no auth)          WALLET ENDPOINTS (SSS 2-of-3)
// ─────────────────────────────────   ─────────────────────────────────────
// getHealth()                         createWallet(username, opts)
// getVersion()                        login({ walletId, shard1, ... })
// getGenesisHash()                    logout({ sessionToken?, walletId? })
// getSlot()                           transfer(from, to, bb, shardA, pass)
// getEpochInfo()                      transferSession(token, from, to, bb)
// getLatestBlockhash()                verifySss({ walletId, shard1, ... })
// getSupply()                         verifySssCombo({ combo, ... })
// getBalance(address)                 getShardB(walletId)
// getBalances(addresses[])            faucet(address, bb)
// getAccountInfo(address)             saveWalletLocal(wallet)
// getSignaturesForAddress(addr, n)    loadWalletLocal()
// getTransaction(sig)                 deleteWalletLocal(walletId)
// getStats()
// getLedger(page, limit)
// getPohStatus()
// getLatestBlock()
// getBlockBySlot(slot)
// getTxStatus(txId)
// getTowerBft()
// getTurbineStatus()
// getUsdcBalance(address)
// getUsdcSupply()
// getUsdcAccounts(address)
// getReserves()              ← planned, not live
//
// SIGNED TRANSFERS (Ed25519)       ADMIN / DEALER
// ─────────────────────────────────  ─────────────────────────────────────
// transferSimple(req)               adminMint(to, amount, opts)
// sealevelSubmit(req)               adminBurn(from, amount, opts)
//                                   adminAccounts()
// USDC WRITE                        adminUsdcMint(to, amount)
// ─────────────────────────────────
// usdcTransfer(req)
//
// ─────────────────────────────────────────────────────────────────────────────
// Quick start:
//
//   <script src="blackbook_sdk.js"></script>
//   const bb = new BlackBook('https://rpc.blackbook.finance:8899');
//
//   // Explorer
//   const { block } = await bb.getLatestBlock();
//   console.log(`Slot ${block.slot}`);
//
//   // Wallet
//   const wallet = await bb.createWallet('alice', { password: 'hunter2' });
//   const result = await bb.transfer(wallet.address, recipientAddr, 10, wallet.shardA, 'hunter2');
//
// Node.js:
//   const { BlackBook } = require('./blackbook_sdk');
//
// ============================================================================

const LAMPORTS_PER_BB = 100_000;
const CHAIN_ID        = 0xBB;
const MAX_FAUCET_BB   = 99_999;

const SSS_COMBOS = {
  AB: { label: 'A + B', desc: 'User + Server', shards: ['A', 'B'] },
  AC: { label: 'A + C', desc: 'User + Cold',   shards: ['A', 'C'] },
  BC: { label: 'B + C', desc: 'Server + Cold', shards: ['B', 'C'] },
};

// ============================================================================
// BLACKBOOK — Unified SDK class
// ============================================================================

class BlackBook {
  /**
   * @param {string} rpcUrl   - JSON-RPC endpoint, e.g. 'http://localhost:8899'
   * @param {string} [apiUrl] - HTTP API endpoint, e.g. 'http://localhost:8080'
   *                            Defaults to rpcUrl with port swapped to 8080.
   * @param {Object} [opts]
   * @param {number} [opts.timeout=30000] - Request timeout in ms
   */
  constructor(rpcUrl, apiUrl, opts = {}) {
    this.rpcUrl  = rpcUrl.replace(/\/+$/, '');
    this.apiUrl  = (apiUrl || rpcUrl.replace(':8899', ':8080')).replace(/\/+$/, '');
    this.timeout = opts.timeout || 30_000;
    this._rpcId  = 0;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INTERNAL TRANSPORT
  // ═══════════════════════════════════════════════════════════════════════════

  /** @private */
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

  /** @private HTTP GET */
  async _get(path) {
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), this.timeout);
    try {
      const res  = await fetch(`${this.apiUrl}${path}`, { method: 'GET', signal: ctrl.signal });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
      return data;
    } finally { clearTimeout(t); }
  }

  /** @private HTTP POST (JSON body) */
  async _post(path, body = {}) {
    const ctrl = new AbortController();
    const t    = setTimeout(() => ctrl.abort(), this.timeout);
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


  // ═══════════════════════════════════════════════════════════════════════════
  // NETWORK
  // ═══════════════════════════════════════════════════════════════════════════

  /** Check node health. Returns "ok" or throws. */
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
  // SUPPLY
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Total + circulating BB supply.
   * @returns {Promise<{ totalLamports, totalBB, circulating }>}
   */
  async getSupply() {
    const result = await this._rpc('getSupply');
    return {
      totalLamports: result.value.total,
      totalBB:       result.value.total / LAMPORTS_PER_BB,
      circulating:   result.value.circulating / LAMPORTS_PER_BB,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // ACCOUNTS & BALANCES
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * BB balance for one address.
   * @returns {Promise<{ lamports, bb }>}
   */
  async getBalance(address) {
    const result = await this._rpc('getBalance', [address]);
    return { lamports: result.value, bb: result.value / LAMPORTS_PER_BB };
  }

  /**
   * BB balance via REST (returns address, balance in BB, name, unit).
   * @returns {Promise<{ address, balance, name, unit }>}
   */
  async getBalanceREST(address) {
    return this._get(`/balance/${address}`);
  }

  /**
   * Batch balance lookup. Returns `{ [address]: { lamports, bb } }`.
   * @param {string[]} addresses
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
   */
  async getAccountInfo(address) {
    const result = await this._rpc('getAccountInfo', [address, { encoding: 'base64' }]);
    return result.value;
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // TRANSACTIONS
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
   */
  async getTransaction(signature) {
    return this._rpc('getTransaction', [signature, { encoding: 'json' }]);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // LEDGER
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Paginated ASCII audit ledger.
   * @param {number} [page=1]   - Page number (1-indexed)
   * @param {number} [limit=50] - Rows per page (max 100)
   */
  async getLedger(page = 1, limit = 50) {
    return this._get(`/ledger?page=${page}&limit=${limit}`);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // POH — Proof of History clock & blocks
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Current PoH clock: `{ current_slot, num_hashes, current_hash, is_running }`.
   */
  async getPohStatus() { return this._get('/poh/status'); }

  /**
   * Latest finalized block: `{ success, block: { slot, hash, tx_count, leader, epoch, ... } }`.
   */
  async getLatestBlock() { return this._get('/poh/block/latest'); }

  /**
   * Block by slot (includes full transaction list).
   * @param {number} slot
   * @returns {Promise<{ success, block: { slot, hash, transactions[], tx_count, confirmations, ... } }>}
   */
  async getBlockBySlot(slot) { return this._get(`/poh/block/${slot}`); }

  /**
   * Finality status for a transaction.
   * @param {string} txId - Transaction hash / ID
   * @returns {Promise<{ tx_id, status, is_finalized }>}
   */
  async getTxStatus(txId) { return this._get(`/poh/tx/${encodeURIComponent(txId)}/status`); }


  // ═══════════════════════════════════════════════════════════════════════════
  // CONSENSUS & PROPAGATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Tower BFT state: `{ validator_count, global_root, confirmed_slots, active_forks, best_fork, ... }`.
   */
  async getTowerBft() { return this._get('/consensus/tower'); }

  /**
   * Turbine shred propagation status: `{ data_shreds, fec_shreds, max_hops, ... }`.
   */
  async getTurbineStatus() { return this._get('/turbine/status'); }


  // ═══════════════════════════════════════════════════════════════════════════
  // USDC (SPL Token)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * USDC balance for an address.
   * @returns {Promise<{ address, balance_usdc, raw_balance, decimals, mint }>}
   */
  async getUsdcBalance(address) { return this._get(`/usdc/balance/${address}`); }

  /**
   * Total USDC supply on-chain.
   * @returns {Promise<{ mint, total_supply, raw_supply, decimals }>}
   */
  async getUsdcSupply() { return this._get('/usdc/supply'); }

  /**
   * All USDC token accounts (ATAs) for a wallet.
   * @returns {Promise<{ owner, token_accounts: Array<{ address, mint, owner, balance_usdc, ... }> }>}
   */
  async getUsdcAccounts(address) { return this._get(`/usdc/accounts/${address}`); }


  // ═══════════════════════════════════════════════════════════════════════════
  // SIGNED TRANSFERS (Ed25519 — microtx / AI agent wallets)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Ed25519-signed transfer via `/transfer/simple`.
   *
   * Used by microtransaction wallets and AI agents that hold raw Ed25519 keys.
   * The server verifies the signature, checks replay protection (nonce +
   * timestamp), then executes the transfer.
   *
   * @param {Object} req
   * @param {string} req.publicKey      - Hex-encoded Ed25519 public key (64 hex chars)
   * @param {string} req.walletAddress  - Sender address (hex pubkey)
   * @param {string} req.payload        - JSON string: {"to":"...","amount":1.5}
   * @param {number} req.timestamp      - Unix seconds
   * @param {string} req.nonce          - Unique UUID
   * @param {number} req.chainId        - Chain ID (0xBB = 187)
   * @param {string} req.signature      - Hex-encoded Ed25519 signature (128 hex chars)
   * @returns {Promise<{ success, signature, from, to, amount, from_balance, to_balance }>}
   */
  async transferSimple(req) {
    return this._post('/transfer/simple', {
      public_key:     req.publicKey,
      wallet_address: req.walletAddress,
      payload:        req.payload,
      timestamp:      req.timestamp,
      nonce:          req.nonce,
      chain_id:       req.chainId ?? CHAIN_ID,
      signature:      req.signature,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // SEALEVEL — Gulf Stream parallel execution pipeline
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Submit a transaction to the Sealevel parallel execution engine via
   * Gulf Stream (`/sealevel/submit`).
   *
   * Supports DUAL AUTH — provide EITHER:
   *   1. Ed25519 signature (`signature`, `timestamp`, `nonce`)
   *   2. SSS session token (`sessionToken`)
   *
   * @param {Object} req
   * @param {string} req.from           - Sender address
   * @param {string} req.to             - Recipient address
   * @param {number} req.amount         - Amount in BB
   * @param {number} [req.priority]     - Priority hint (higher = faster)
   * @param {string} [req.signature]    - Ed25519 hex sig (128 chars)
   * @param {number} [req.timestamp]    - Unix seconds
   * @param {string} [req.nonce]        - Unique UUID
   * @param {string} [req.sessionToken] - SSS session token
   * @returns {Promise<{ success, tx_id, status }>}
   */
  async sealevelSubmit(req) {
    return this._post('/sealevel/submit', {
      from:          req.from,
      to:            req.to,
      amount:        req.amount,
      priority:      req.priority ?? undefined,
      signature:     req.signature ?? undefined,
      timestamp:     req.timestamp ?? undefined,
      nonce:         req.nonce ?? undefined,
      session_token: req.sessionToken ?? undefined,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN — Dealer mint / burn / accounts
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
   * @param {string} from        - Address to burn from
   * @param {number} amount      - Amount in BB
   * @param {Object} [opts]
   * @param {string} [opts.dealerSignature] - Dealer auth sig
   * @param {string} [opts.l2ReceiptId]     - L2 receipt ID
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
   * List all accounts with non-zero balances (admin).
   *
   * @returns {Promise<{ accounts: Array<{ address, balance, lamports }>, total_accounts, total_supply }>}
   */
  async adminAccounts() {
    return this._get('/admin/accounts');
  }

  /**
   * Mint USDC tokens (admin/Dealer).
   *
   * @param {string} to     - Recipient wallet address (base58)
   * @param {number} amount - Amount in human USDC (e.g. 100.50)
   * @returns {Promise<{ success, minted_usdc, raw_amount, to, ata, mint, new_total_supply }>}
   */
  async adminUsdcMint(to, amount) {
    return this._post('/admin/usdc/mint', { to, amount });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // USDC — Transfers (authenticated)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer USDC between wallets.
   *
   * Supports DUAL AUTH — provide EITHER:
   *   1. Ed25519 signature (`signature`, `timestamp`, `nonce`)
   *   2. SSS session token (`sessionToken`)
   *
   * @param {Object} req
   * @param {string} req.from           - Sender address (base58)
   * @param {string} req.to             - Recipient address (base58)
   * @param {number} req.amount         - Amount in human USDC
   * @param {string} [req.signature]    - Ed25519 hex sig
   * @param {number} [req.timestamp]    - Unix seconds
   * @param {string} [req.nonce]        - Unique UUID
   * @param {string} [req.sessionToken] - SSS session token
   * @returns {Promise<{ success, amount_usdc, raw_amount, from, to, from_ata, to_ata, from_balance, to_balance }>}
   */
  async usdcTransfer(req) {
    return this._post('/usdc/transfer', {
      from:          req.from,
      to:            req.to,
      amount:        req.amount,
      signature:     req.signature ?? undefined,
      timestamp:     req.timestamp ?? undefined,
      nonce:         req.nonce ?? undefined,
      session_token: req.sessionToken ?? undefined,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // PROOF OF RESERVES (planned — route not yet implemented)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Proof-of-reserves data (BB supply vs USDC backing).
   * @deprecated Route `/reserves` is not yet implemented. Will 404.
   * @returns {Promise<{ bbSupply, usdcHeld, ratio, fullyBacked, merkleRoot, lastVerified }>}
   */
  async getReserves() {
    const d = await this._get('/reserves');
    return {
      bbSupply:          d.bb_supply_bb ?? d.bb_supply,
      bbSupplyLamports:  d.bb_supply,
      usdcHeld:          d.usdc_held,
      usdcReserveWallet: d.usdc_reserve_wallet,
      ratio:             d.ratio,
      fullyBacked:       d.fully_backed,
      merkleRoot:        d.merkle_root,
      lastVerified:      d.last_verified,
      solanaExplorerUrl: d.solana_explorer_url,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET — Create / Login / Logout
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new Shamir 2-of-3 wallet (BIP-39 → Ed25519 → SSS split).
   *
   * @param {string} username              - Username
   * @param {Object} [opts]
   * @param {string} [opts.password]       - Encrypts Shard A (strongly recommended)
   * @param {string} [opts.pin]            - PIN for high-value tx confirmation
   * @param {number} [opts.dailyLimit]     - BB threshold requiring PIN
   * @returns {Promise<{ walletId, address, mnemonic, shardA, shardAIsEncrypted, shardC, publicKey, sessionToken }>}
   *
   * @example
   *   const w = await bb.createWallet('alice', { password: 'hunter2' });
   *   // ⚠ Show w.mnemonic and w.shardC to user ONCE, then discard
   *   bb.saveWalletLocal(w);
   */
  async createWallet(username, opts = {}) {
    const r = await this._post('/wallet/create', {
      username,
      password:    opts.password   || undefined,
      pin:         opts.pin        || undefined,
      daily_limit: opts.dailyLimit || undefined,
    });
    return {
      walletId:          r.wallet_id,
      address:           r.address,
      mnemonic:          r.mnemonic,
      shardA:            r.share_a,
      shardAIsEncrypted: r.share_a_is_encrypted,
      shardC:            r.share_c,
      publicKey:         r.public_key,
      sessionToken:      r.session_token,
    };
  }

  /**
   * Login: reconstruct wallet from 2 Shamir shards → session token.
   *
   * @param {Object} params
   * @param {string} params.walletId
   * @param {string} params.shard1   - Encrypted Shard A blob (from localStorage)
   * @param {string} [params.shard2] - Omit to have server auto-fetch Shard B
   * @param {string} [params.password] - Required if shard1 is encrypted
   * @param {boolean} [params.shard2IsServerEncrypted=true]
   * @returns {Promise<{ success, walletId, sessionToken }>}
   *
   * @example
   *   const { sessionToken } = await bb.login({
   *     walletId: saved.walletId,
   *     shard1:   saved.shardA,
   *     password: 'hunter2',
   *   });
   */
  async login({ walletId, shard1, shard2 = '', password, shard2IsServerEncrypted = true }) {
    const r = await this._post('/wallet/login', {
      wallet_id:                   walletId,
      shard_1:                     shard1,
      shard_2:                     shard2,
      password:                    password || undefined,
      shard_2_is_server_encrypted: shard2IsServerEncrypted,
    });
    return { success: r.success, walletId: r.wallet_id, sessionToken: r.session_token };
  }

  /**
   * Revoke a session server-side (delete cached Ed25519 seed).
   *
   * @param {Object} [opts]
   * @param {string} [opts.sessionToken] - Specific session to revoke
   * @param {string} [opts.walletId]     - Revoke all sessions for this wallet
   * @returns {Promise<{ success: boolean }>}
   *
   * @example
   *   await bb.logout({ sessionToken });
   */
  async logout({ sessionToken, walletId } = {}) {
    return this._post('/wallet/logout', {
      session_token: sessionToken || undefined,
      wallet_id:     walletId     || undefined,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET — Transfers
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer BB using SSS 2-of-3 authentication.
   *
   * The server decrypts Shard A (Argon2id + AES-GCM), fetches + decrypts
   * Shard B, reconstructs the Ed25519 key, signs, executes, and zeroizes.
   *
   * @param {string} fromWalletId
   * @param {string} toAddress
   * @param {number} amountBB      - Amount in BB (e.g. 50 for 50 BB)
   * @param {string} shardA        - Encrypted blob (salt:nonce:ciphertext)
   * @param {string} password      - Password used to encrypt Shard A
   * @returns {Promise<{ success, signature, from, to, amount, fromBalance, toBalance, sessionToken }>}
   *
   * @example
   *   const r = await bb.transfer(myAddr, recipientAddr, 50, shardA, 'hunter2');
   *   console.log(`Sent — sig: ${r.signature}`);
   *   // r.sessionToken is valid for 30 min — pass to transferSession() for fast-path
   */
  async transfer(fromWalletId, toAddress, amountBB, shardA, password) {
    const r = await this._post('/transfer', {
      from_wallet_id: fromWalletId,
      to_address:     toAddress,
      amount:         amountBB,
      share_a:        shardA,
      password,
    });
    return {
      success:      r.success,
      signature:    r.signature,
      from:         r.from,
      to:           r.to,
      amount:       r.amount,
      fromBalance:  r.from_balance,
      toBalance:    r.to_balance,
      sessionToken: r.session_token,
    };
  }

  /**
   * Fast-path transfer using a cached session token (no Argon2id / shard I/O).
   *
   * Requires a `sessionToken` from a prior `login()` or `transfer()` call.
   * Valid for 30 minutes; TTL refreshed on each use.
   *
   * @param {string} sessionToken
   * @param {string} fromWalletId
   * @param {string} toAddress
   * @param {number} amountBB
   * @returns {Promise<{ success, signature, from, to, amount, fromBalance, toBalance, sessionToken }>}
   *
   * @example
   *   // First call (full SSS)
   *   const r1 = await bb.transfer(myAddr, recipient, 10, shardA, 'hunter2');
   *   // Subsequent calls (fast-path, same session)
   *   const r2 = await bb.transferSession(r1.sessionToken, myAddr, recipient, 5);
   */
  async transferSession(sessionToken, fromWalletId, toAddress, amountBB) {
    const r = await this._post('/transfer/session', {
      session_token:  sessionToken,
      from_wallet_id: fromWalletId,
      to_address:     toAddress,
      amount:         amountBB,
    });
    return {
      success:      r.success,
      signature:    r.signature,
      from:         r.from,
      to:           r.to,
      amount:       r.amount,
      fromBalance:  r.from_balance,
      toBalance:    r.to_balance,
      sessionToken: r.session_token,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET — SSS Verification
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Verify two shards reconstruct the correct wallet (non-destructive).
   *
   * @param {Object} params
   * @param {string} params.walletId
   * @param {string} params.shard1
   * @param {string} params.shard2
   * @param {string} [params.password]
   * @param {boolean} [params.shard2IsServerEncrypted=false]
   * @returns {Promise<{ success, walletId, derivedAddress, matches, message }>}
   */
  async verifySss({ walletId, shard1, shard2, password, shard2IsServerEncrypted = false }) {
    const r = await this._post('/wallet/verify-sss', {
      wallet_id:                   walletId,
      shard_1:                     shard1,
      shard_2:                     shard2,
      password:                    password || undefined,
      shard_2_is_server_encrypted: shard2IsServerEncrypted,
    });
    return {
      success:        r.success,
      walletId:       r.wallet_id,
      derivedAddress: r.derived_address,
      matches:        r.matches,
      message:        r.message,
    };
  }

  /**
   * High-level SSS verification using a named combo (`'AB'`, `'AC'`, `'BC'`).
   * Auto-fetches Shard B when needed.
   *
   * @param {Object} params
   * @param {'AB'|'AC'|'BC'} params.combo
   * @param {string} params.walletId
   * @param {string} [params.shardA] - Required for AB / AC
   * @param {string} [params.shardB] - Auto-fetched if omitted (AB / BC)
   * @param {string} [params.shardC] - Required for AC / BC
   * @param {string} [params.password] - Required for AB / AC
   * @returns {Promise<VerifyResult>}
   *
   * @example
   *   await bb.verifySssCombo({ combo: 'AB', walletId, shardA, password: 'hunter2' });
   */
  async verifySssCombo({ combo, walletId, shardA, shardB, shardC, password }) {
    if (!SSS_COMBOS[combo]) {
      throw new Error(`Invalid combo "${combo}". Use: ${Object.keys(SSS_COMBOS).join(', ')}`);
    }
    if ((combo === 'AB' || combo === 'BC') && !shardB) {
      const b = await this.getShardB(walletId);
      shardB  = b.shardB;
    }
    switch (combo) {
      case 'AB':
        return this.verifySss({ walletId, shard1: shardA, shard2: shardB, password, shard2IsServerEncrypted: true });
      case 'AC':
        return this.verifySss({ walletId, shard1: shardA, shard2: shardC, password, shard2IsServerEncrypted: false });
      case 'BC':
        return this.verifySss({ walletId, shard1: shardC, shard2: shardB, shard2IsServerEncrypted: true });
      default:
        throw new Error(`Unhandled combo: ${combo}`);
    }
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET — Shard B retrieval
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Retrieve Shard B (server-encrypted) from ReDB.
   * @param {string} walletId
   * @returns {Promise<{ shardB, status }>}
   */
  async getShardB(walletId) {
    const r = await this._post('/wallet/secure/shard-b', { wallet_id: walletId });
    return { shardB: r.shard_b, status: r.status };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // WALLET — Faucet (Dual Auth)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Request BB from the faucet. Supports EITHER:
   *   1. Session token (SSS wallet — login first)
   *   2. Ed25519 signature (microtx wallet — use faucetSigned())
   *
   * @param {string} toAddress
   * @param {number} [amountBB=0.1] - Max 0.1 BB per request
   * @param {string} [sessionToken] - Session token from login()
   * @returns {Promise<{ success, minted, to, new_balance, auth_method }>}
   */
  async faucet(toAddress, amountBB = 0.1, sessionToken = null) {
    if (amountBB > MAX_FAUCET_BB) amountBB = MAX_FAUCET_BB;
    if (amountBB <= 0) throw new Error('Amount must be positive');

    const body = { to: toAddress, amount: amountBB };
    if (sessionToken) body.session_token = sessionToken;

    return this._post('/faucet', body);
  }

  /**
   * Faucet with Ed25519 signature (microtx wallets with raw keypair).
   * @param {string} toAddress
   * @param {number} amountBB
   * @param {string} signature - 128 hex chars
   * @param {number} timestamp - Unix seconds
   * @param {string} nonce     - Unique UUID
   */
  async faucetSigned(toAddress, amountBB, signature, timestamp, nonce) {
    if (amountBB <= 0) throw new Error('Amount must be positive');
    return this._post('/faucet', {
      to: toAddress, amount: amountBB,
      signature, timestamp, nonce,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // LOCAL SESSION MANAGEMENT (Browser localStorage)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save wallet session to browser localStorage.
   * Stores: walletId, address, encrypted shardA, publicKey.
   * Does NOT store mnemonic, shardC, or any plaintext secret.
   * @param {Object} wallet - Result of createWallet()
   */
  saveWalletLocal(wallet) {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available — use Node.js file storage instead');
    }
    const s = {
      wallet_id:            wallet.walletId,
      address:              wallet.address,
      share_a:              wallet.shardA,
      share_a_is_encrypted: wallet.shardAIsEncrypted,
      public_key:           wallet.publicKey,
      created_at:           new Date().toISOString(),
    };
    localStorage.setItem('bb_wallet', JSON.stringify(s));
    localStorage.setItem(`bb_shard_a_${wallet.walletId}`, wallet.shardA);
  }

  /**
   * Load wallet session from browser localStorage.
   * @returns {{ walletId, address, shardA, shardAIsEncrypted, publicKey, createdAt } | null}
   */
  loadWalletLocal() {
    if (typeof localStorage === 'undefined') return null;
    try {
      const raw = localStorage.getItem('bb_wallet');
      if (!raw) return null;
      const s = JSON.parse(raw);
      return {
        walletId:          s.wallet_id,
        address:           s.address,
        shardA:            s.share_a,
        shardAIsEncrypted: s.share_a_is_encrypted,
        publicKey:         s.public_key,
        createdAt:         s.created_at,
      };
    } catch (_) { return null; }
  }

  /**
   * Remove wallet session from localStorage (client-side logout).
   * @param {string} [walletId]
   */
  deleteWalletLocal(walletId) {
    if (typeof localStorage === 'undefined') return;
    localStorage.removeItem('bb_wallet');
    if (walletId) localStorage.removeItem(`bb_shard_a_${walletId}`);
  }

  /** Save encrypted Shard A to localStorage. */
  saveShardALocal(walletId, encryptedShardA) {
    if (typeof localStorage === 'undefined') throw new Error('localStorage not available');
    localStorage.setItem(`bb_shard_a_${walletId}`, encryptedShardA);
  }

  /** Load encrypted Shard A from localStorage. */
  loadShardALocal(walletId) {
    if (typeof localStorage === 'undefined') return null;
    return localStorage.getItem(`bb_shard_a_${walletId}`);
  }

  /** Delete Shard A from localStorage. */
  deleteShardALocal(walletId) {
    if (typeof localStorage !== 'undefined') localStorage.removeItem(`bb_shard_a_${walletId}`);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // STATIC UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  static toLamports(bb)       { return Math.floor(bb * LAMPORTS_PER_BB); }
  static toBB(lamports)       { return lamports / LAMPORTS_PER_BB; }

  /**
   * Format lamports as "1,000.00"
   * @param {number} lamports
   * @param {number} [decimals=2]
   */
  static formatBB(lamports, decimals = 2) {
    return (lamports / LAMPORTS_PER_BB).toLocaleString('en-US', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: Math.max(decimals, 4),
    });
  }

  /** Format lamports as "1,000.00 BB" */
  static formatWithUnit(lamports, decimals = 2) {
    return `${BlackBook.formatBB(lamports, decimals)} BB`;
  }

  /**
   * Shorten address for UI: "4PtfY2…2oby"
   * @param {string} address
   * @param {number} [chars=6]
   */
  static shortAddr(address, chars = 6) {
    if (!address || address.length <= chars * 2) return address;
    return `${address.slice(0, chars)}…${address.slice(-4)}`;
  }

  /**
   * Human-readable time since Unix timestamp: "5m ago", "2h ago", "3d ago"
   * @param {number} unixSeconds
   */
  static timeAgo(unixSeconds) {
    const diff = Math.floor(Date.now() / 1000) - unixSeconds;
    if (diff < 5)     return 'just now';
    if (diff < 60)    return `${diff}s ago`;
    if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  /**
   * Format Unix timestamp as locale date string.
   * @param {number} unixSeconds
   */
  static formatDate(unixSeconds) {
    return new Date(unixSeconds * 1000).toLocaleString();
  }
}


// ============================================================================
// EXPORTS
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    BlackBook,
    LAMPORTS_PER_BB,
    CHAIN_ID,
    MAX_FAUCET_BB,
    SSS_COMBOS,
  };
}

if (typeof globalThis !== 'undefined') {
  globalThis.BlackBook     = BlackBook;
  globalThis.SSS_COMBOS    = SSS_COMBOS;
  globalThis.LAMPORTS_PER_BB = LAMPORTS_PER_BB;
}
