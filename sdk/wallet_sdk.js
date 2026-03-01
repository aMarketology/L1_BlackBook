// ============================================================================
// BLACKBOOK WALLET SDK — v1.0
// ============================================================================
//
// Dedicated wallet module for BlackBook L1 blockchain.
// Covers the full wallet lifecycle:
//
//   1. CREATE   — BIP-39 mnemonic → Ed25519 keypair → Shamir 2-of-3 split
//   2. LOGIN    — Reconstruct seed from 2-of-3 shards → session token
//   3. BALANCE  — Check BB balance for any address
//   4. TRANSFER — SSS-authenticated send (server-side reconstruction)
//   5. VERIFY   — Test that 2 shards reconstruct the correct wallet
//   6. RECOVER  — Shard B (server), Shard C (Vault), Shard A (Supabase)
//   7. SESSION  — localStorage persistence + Supabase backup
//   8. FAUCET   — Dev/testnet token minting
//
// ============================================================================
//
// ARCHITECTURE: How BlackBook Wallets Work
// ═══════════════════════════════════════════════════════════════════════════
//
// BlackBook uses Shamir's Secret Sharing (SSS) 2-of-3 to split your private
// key so it NEVER exists as a single piece after wallet creation.
//
// ┌──────────────────────────────────────────────────────────────────────┐
// │  BIP-39 Mnemonic (24 words)                                        │
// │       ↓                                                             │
// │  Ed25519 Seed (32 bytes) ← this IS the private key                 │
// │       ↓                                                             │
// │  Shamir 2-of-3 Split:                                               │
// │                                                                     │
// │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                │
// │  │  SHARD A     │  │  SHARD B     │  │  SHARD C     │               │
// │  │  (User)      │  │  (Server)    │  │  (Cold)      │               │
// │  │             │  │             │  │             │               │
// │  │  Encrypted   │  │  Encrypted   │  │  Raw hex     │               │
// │  │  with user's │  │  with SERVER │  │  written     │               │
// │  │  password    │  │  _MASTER_KEY │  │  offline     │               │
// │  │  (Argon2id   │  │  → stored in │  │  by user     │               │
// │  │   + AES-256) │  │  ReDB on     │  │  (+ Vault    │               │
// │  │             │  │  the node    │  │  backup)     │               │
// │  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘               │
// │         │                │                │                        │
// │         └────────┬───────┘                │                        │
// │                  │ ANY 2 = full key       │                        │
// │         ┌────────┼───────┐                │                        │
// │         │        │       │                │                        │
// │       A + B    A + C   B + C                                       │
// │       User+    User+   Server+                                     │
// │       Server   Cold    Cold                                        │
// │       (normal) (self-  (emergency                                  │
// │                custody) recovery)                                  │
// └──────────────────────────────────────────────────────────────────────┘
//
// SECURITY MODEL:
//
//   • The full Ed25519 seed is DESTROYED after Shamir split
//   • No single party ever holds the full key
//   • Shard A blob = "salt_b64 : nonce_hex : ciphertext_hex"
//     - Salt is PLAINTEXT (required by Argon2id to re-derive the AES key)
//     - Nonce is PLAINTEXT (required by AES-GCM for decryption)
//     - Ciphertext is ENCRYPTED (the actual shard bytes)
//     - The PASSWORD is the real secret — never stored anywhere
//   • Shard B is encrypted with the SERVER_MASTER_KEY on the node
//   • Shard C is raw hex — the user stores it offline
//
// ENCRYPTION DETAILS:
//
//   Argon2id(password, random_salt) → 32-byte AES key
//   AES-256-GCM(key, random_nonce, shard_bytes) → ciphertext
//   Stored as: "salt:nonce:ciphertext" — a single opaque string
//
//   This means:
//   ✓ Even if someone steals Shard A, they can't use it without the password
//   ✓ The salt being visible is fine — security comes from Argon2id being slow
//   ✓ All encryption/decryption happens server-side in Rust (never in JS)
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
// WALLET SDK CLASS
// ============================================================================

class BlackBookWalletSDK {
  /**
   * Create a new WalletSDK instance.
   *
   * @param {string} rpcUrl    - BlackBook JSON-RPC endpoint (port 8899)
   * @param {string} [apiUrl]  - BlackBook HTTP API endpoint (port 8080)
   * @param {Object} [opts]    - Optional config
   * @param {string} [opts.jwt]         - Supabase JWT for authenticated endpoints
   * @param {number} [opts.timeout]     - Request timeout in ms (default: 30000)
   *
   * @example
   *   // Browser
   *   const wallet = new BlackBookWalletSDK('https://rpc.blackbook.finance:8899');
   *
   *   // Node.js
   *   const { BlackBookWalletSDK } = require('./wallet_sdk');
   *   const wallet = new BlackBookWalletSDK('http://localhost:8899');
   */
  constructor(rpcUrl, apiUrl, opts = {}) {
    this.rpcUrl = rpcUrl.replace(/\/+$/, '');
    this.apiUrl = (apiUrl || rpcUrl.replace(':8899', ':8080')).replace(/\/+$/, '');
    this.jwt = opts.jwt || null;
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

  /** @private HTTP API POST */
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

  /** @private HTTP API GET */
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


  // ═══════════════════════════════════════════════════════════════════════════
  // 1. CREATE WALLET
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /wallet/create
  //
  // What happens server-side:
  //   1. Generate 32 bytes of entropy → BIP-39 mnemonic (24 words)
  //   2. Derive BIP-39 seed → take first 32 bytes → Ed25519 signing key
  //   3. Shamir 2-of-3 split the 32-byte seed into 3 shares
  //   4. Shard A → encrypt with user's password (Argon2id + AES-256-GCM)
  //   5. Shard B → encrypt with SERVER_MASTER_KEY → store in ReDB
  //   6. Shard C → return raw hex (user writes down offline)
  //   7. DESTROY the original seed (zeroized in memory)
  //   8. Return: mnemonic, encrypted Shard A, raw Shard C, public address
  //
  // The user gets back:
  //   - mnemonic:  24 words (SHOW ONCE — user must write down)
  //   - shardA:    encrypted blob (store in localStorage or Supabase)
  //   - shardC:    raw hex (SHOW ONCE — user writes down offline)
  //   - address:   public key in base58 (safe to share)
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Create a new Shamir 2-of-3 wallet.
   *
   * @param {string} username              - Username (for Supabase account sync)
   * @param {Object} [opts]                - Options
   * @param {string} [opts.password]       - Encrypts Shard A. HIGHLY recommended.
   * @param {string} [opts.pin]            - PIN for high-value tx authorization
   * @param {number} [opts.dailyLimit=500] - BB threshold above which PIN is required
   * @returns {Promise<WalletCreateResult>}
   *
   * @typedef {Object} WalletCreateResult
   * @property {string} walletId         - Wallet address (= public key base58)
   * @property {string} address          - Same as walletId
   * @property {string} mnemonic         - BIP-39 24-word phrase (SHOW ONCE)
   * @property {string} shardA           - Encrypted blob (salt:nonce:ciphertext)
   * @property {boolean} shardAIsEncrypted - True if password was provided
   * @property {string} shardC           - Raw hex (SHOW ONCE, store offline)
   * @property {string} publicKey        - Ed25519 public key (base58)
   * @property {string} sessionToken     - Auto-login session token
   *
   * @example
   *   const wallet = await sdk.createWallet('alice', { password: 'hunter2' });
   *   console.log(wallet.address);   // "4PtfY2qR..."
   *   console.log(wallet.mnemonic);  // "abandon ability able ... (24 words)"
   *
   *   // IMPORTANT: Show mnemonic + shardC to user ONCE, then discard
   *   // Store shardA in localStorage (it's encrypted with their password)
   *   sdk.saveWalletLocal(wallet);
   */
  async createWallet(username, opts = {}) {
    const result = await this._api('/wallet/create', {
      username,
      password:    opts.password || undefined,
      pin:         opts.pin || undefined,
      daily_limit: opts.dailyLimit || undefined,
    });
    return {
      walletId:         result.wallet_id,
      address:          result.address,
      mnemonic:         result.mnemonic,
      shardA:           result.share_a,
      shardAIsEncrypted: result.share_a_is_encrypted,
      shardC:           result.share_c,
      publicKey:        result.public_key,
      sessionToken:     result.session_token,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 2. LOGIN (SSS Reconstruction → Session)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /wallet/login
  //
  // What happens server-side:
  //   1. Receive 2 shards (typically A + B)
  //   2. If Shard A is encrypted → Argon2id(password, salt) → AES decrypt
  //   3. If Shard B is server-encrypted → decrypt with SERVER_MASTER_KEY
  //   4. Shamir reconstruct 32-byte seed from the 2 decrypted shares
  //   5. Derive Ed25519 key → check pubkey matches wallet_id
  //   6. Cache seed in memory session store (30-min expiry)
  //   7. Return session token (UUID) for subsequent requests
  //
  // After login, transfers can use the session token instead of
  // re-sending shards every time (until the 30-min TTL expires).
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Login by reconstructing the wallet from 2 Shamir shards.
   *
   * Typical flow: Send encrypted Shard A + password. The server auto-fetches
   * Shard B from ReDB, decrypts both, reconstructs the seed, and returns
   * a session token.
   *
   * @param {Object} params
   * @param {string} params.walletId               - Wallet address to login to
   * @param {string} params.shard1                 - First shard (hex or encrypted blob)
   * @param {string} params.shard2                 - Second shard (hex or encrypted blob)
   * @param {string} [params.password]             - Password if shard1 is Shard A (encrypted)
   * @param {boolean} [params.shard2IsServerEncrypted] - True if shard2 is Shard B
   * @returns {Promise<LoginResult>}
   *
   * @typedef {Object} LoginResult
   * @property {boolean} success     - True if login succeeded
   * @property {string}  walletId    - Wallet address
   * @property {string}  sessionToken - UUID session token (30-min TTL)
   *
   * @example
   *   // Load Shard A from localStorage
   *   const shardA = sdk.loadShardALocal(walletId);
   *
   *   // Login (server auto-fetches Shard B)
   *   const session = await sdk.login({
   *     walletId: '4PtfY2qR...',
   *     shard1:    shardA,
   *     shard2:    '',             // empty = server fetches Shard B automatically
   *     password:  'hunter2',
   *     shard2IsServerEncrypted: true,
   *   });
   *   console.log(session.sessionToken); // "a1b2c3d4-..."
   */
  async login({ walletId, shard1, shard2, password, shard2IsServerEncrypted = true }) {
    const result = await this._api('/wallet/login', {
      wallet_id:                   walletId,
      shard_1:                     shard1,
      shard_2:                     shard2,
      password:                    password || undefined,
      shard_2_is_server_encrypted: shard2IsServerEncrypted,
    });
    return {
      success:      result.success,
      walletId:     result.wallet_id,
      sessionToken: result.session_token,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 3. CHECK BALANCE
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Two methods available:
  //   - JSON-RPC: getBalance (returns lamports via RPC port 8899)
  //   - HTTP GET: /balance/:address (returns BB via REST port 8080)
  //
  // Both are unauthenticated — anyone can check any address's balance.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get BB balance for an address (via JSON-RPC).
   *
   * @param {string} address - BlackBook public address (base58)
   * @returns {Promise<BalanceResult>}
   *
   * @typedef {Object} BalanceResult
   * @property {number} lamports - Balance in lamports (1 BB = 1,000,000,000 lamports)
   * @property {number} bb       - Balance in BB
   *
   * @example
   *   const bal = await sdk.getBalance('8CZJAZnbm85qywRfAw1tXRnAvACPciuYvK36A4BS3hCm');
   *   console.log(`${bal.bb} BB`);  // "1000 BB"
   */
  async getBalance(address) {
    const result = await this._rpc('getBalance', [address]);
    return {
      lamports: result.value,
      bb: result.value / LAMPORTS_PER_BB,
    };
  }

  /**
   * Get BB balance via HTTP REST endpoint (simpler, returns BB directly).
   *
   * @param {string} address
   * @returns {Promise<{ address: string, balance: number, unit: string }>}
   *
   * @example
   *   const info = await sdk.getBalanceREST('8CZJAZn...');
   *   console.log(info.balance); // 1000.0
   */
  async getBalanceREST(address) {
    return this._apiGet(`/balance/${address}`);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 4. TRANSFER TOKENS
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /wallet/transfer
  //
  // What happens server-side:
  //   1. Client sends encrypted Shard A + password + recipient + amount
  //   2. Server decrypts Shard A with password (Argon2id → AES-GCM)
  //   3. Server decrypts Shard B from ReDB (SERVER_MASTER_KEY → AES-GCM)
  //   4. Shamir reconstruct → 32-byte Ed25519 seed
  //   5. Derive signing key → VERIFY pubkey matches sender address
  //   6. Sign transfer message with Ed25519
  //   7. Execute transfer (debit sender, credit recipient)
  //   8. Record transaction in PoH block
  //   9. ZEROIZE seed from memory immediately
  //   10. Return: signature, balances, tx details
  //
  // The private key exists in memory for ~microseconds, only on the server,
  // only during signing, then it's zeroized.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Transfer BB tokens using Shamir 2-of-3 authentication.
   *
   * This is the primary transfer method. The client sends their encrypted
   * Shard A + password. The server combines it with Shard B to reconstruct
   * the signing key, signs the transfer, and destroys the key.
   *
   * @param {string} fromWalletId - Sender wallet address
   * @param {string} toAddress    - Recipient address
   * @param {number} amountBB     - Amount in BB (not lamports)
   * @param {string} shardA       - Encrypted Shard A blob
   * @param {string} password     - Password to decrypt Shard A
   * @returns {Promise<TransferResult>}
   *
   * @typedef {Object} TransferResult
   * @property {boolean} success     - True if transfer succeeded
   * @property {string}  signature   - Ed25519 transaction signature
   * @property {string}  from        - Sender address
   * @property {string}  to          - Recipient address
   * @property {number}  amount      - Amount transferred (BB)
   * @property {number}  fromBalance - Sender's new balance
   * @property {number}  toBalance   - Recipient's new balance
   *
   * @example
   *   const shardA = sdk.loadShardALocal(myWalletId);
   *   const result = await sdk.transfer(
   *     myWalletId,
   *     'RecipientAddress...',
   *     50,          // 50 BB
   *     shardA,
   *     'hunter2'    // password that encrypts Shard A
   *   );
   *   console.log(result.signature);   // "3fKx..."
   *   console.log(result.fromBalance); // 950
   *   console.log(result.toBalance);   // 50
   */
  async transfer(fromWalletId, toAddress, amountBB, shardA, password) {
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


  // ═══════════════════════════════════════════════════════════════════════════
  // 4b. SESSION TRANSFER — fast path after first login
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /transfer/session
  //
  // After a successful login() or transfer(), the server returns a session_token.
  // Subsequent transfers within 30 minutes can use this token instead of
  // re-sending shards and re-running Argon2id. ~10x faster per call.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Fast-path transfer using a cached session token (no shard decryption).
   *
   * Requires a valid session_token from a prior login() or transfer() call.
   * The server retains the reconstructed seed for 30 minutes.
   *
   * @param {string} sessionToken  - Token from login() or transfer() response
   * @param {string} fromWalletId  - Sender address
   * @param {string} toAddress     - Recipient address
   * @param {number} amountBB      - Amount in BB
   * @returns {Promise<TransferResult>}
   *
   * @example
   *   // First transfer (reconstructs key, returns session_token)
   *   const r1 = await sdk.transfer(myWalletId, recipient, 10, shardA, 'password');
   *
   *   // Fast subsequent transfers using the cached session
   *   const r2 = await sdk.transferSession(r1.sessionToken, myWalletId, recipient, 5);
   */
  async transferSession(sessionToken, fromWalletId, toAddress, amountBB) {
    const result = await this._api('/transfer/session', {
      session_token:  sessionToken,
      from_wallet_id: fromWalletId,
      to_address:     toAddress,
      amount:         amountBB,
    });
    return {
      success:      result.success,
      signature:    result.signature,
      from:         result.from,
      to:           result.to,
      amount:       result.amount,
      fromBalance:  result.from_balance,
      toBalance:    result.to_balance,
      sessionToken: result.session_token,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 5. VERIFY SSS (Test Shard Reconstruction)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /wallet/verify-sss
  //
  // Non-destructive test: sends 2 shards to the server, which reconstructs
  // the seed, derives the public key, and checks if it matches the wallet
  // address. Does NOT execute any transaction.
  //
  // Use this to confirm your shards are valid before you need them.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Verify that two Shamir shards reconstruct the correct wallet.
   *
   * @param {Object} params
   * @param {string} params.walletId               - Wallet address to verify against
   * @param {string} params.shard1                 - First shard (hex or encrypted blob)
   * @param {string} params.shard2                 - Second shard (hex or encrypted blob)
   * @param {string} [params.password]             - Password if shard1 is Shard A
   * @param {boolean} [params.shard2IsServerEncrypted] - True if shard2 is Shard B
   * @returns {Promise<VerifyResult>}
   *
   * @typedef {Object} VerifyResult
   * @property {boolean} success        - True if reconstruction succeeded
   * @property {string}  walletId       - Wallet address checked
   * @property {string}  derivedAddress - Address derived from reconstructed key
   * @property {boolean} matches        - True if derivedAddress === walletId
   * @property {string}  message        - Human-readable status
   *
   * @example
   *   const result = await sdk.verifySss({
   *     walletId: '4PtfY2qR...',
   *     shard1:   shardA,
   *     shard2:   shardB,
   *     password: 'hunter2',
   *     shard2IsServerEncrypted: true,
   *   });
   *   console.log(result.matches); // true ✓
   */
  async verifySss({ walletId, shard1, shard2, password, shard2IsServerEncrypted = false }) {
    const result = await this._api('/wallet/verify-sss', {
      wallet_id:                   walletId,
      shard_1:                     shard1,
      shard_2:                     shard2,
      password:                    password || undefined,
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
   * Auto-fetches Shard B from the node when needed.
   *
   * @param {Object} params
   * @param {'AB'|'AC'|'BC'} params.combo   - Which 2 shards to use
   * @param {string} params.walletId        - Wallet address
   * @param {string} [params.shardA]        - Share A (encrypted blob)
   * @param {string} [params.shardB]        - Share B (auto-fetched if omitted)
   * @param {string} [params.shardC]        - Share C (raw hex)
   * @param {string} [params.password]      - Password (required for A+B, A+C)
   * @returns {Promise<VerifyResult>}
   *
   * @example
   *   // Test with User shard + Server shard (most common)
   *   await sdk.verifySssCombo({
   *     combo: 'AB',
   *     walletId: '4PtfY2qR...',
   *     shardA: encryptedBlob,
   *     password: 'hunter2',
   *   });
   *
   *   // Test with User shard + Cold shard (self-custody)
   *   await sdk.verifySssCombo({
   *     combo: 'AC',
   *     walletId: '4PtfY2qR...',
   *     shardA: encryptedBlob,
   *     shardC: 'deadbeef...',
   *     password: 'hunter2',
   *   });
   *
   *   // Test with Server shard + Cold shard (emergency recovery)
   *   await sdk.verifySssCombo({
   *     combo: 'BC',
   *     walletId: '4PtfY2qR...',
   *     shardC: 'deadbeef...',
   *   });
   */
  async verifySssCombo({ combo, walletId, shardA, shardB, shardC, password }) {
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
        return this.verifySss({
          walletId,
          shard1: shardA,
          shard2: shardB,
          password,
          shard2IsServerEncrypted: true,
        });

      case 'AC':
        return this.verifySss({
          walletId,
          shard1: shardA,
          shard2: shardC,
          password,
          shard2IsServerEncrypted: false,
        });

      case 'BC':
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


  // ═══════════════════════════════════════════════════════════════════════════
  // 5b. LOGOUT — Revoke server-side session
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Invalidate a session server-side.
   *
   * Removes the cached seed from the server's session store before the
   * 30-minute TTL expires. Best practice: call on page unload / sign-out.
   *
   * @param {Object} [opts]
   * @param {string} [opts.sessionToken] - Specific session to revoke
   * @param {string} [opts.walletId]     - Revoke ALL sessions for this wallet
   * @returns {Promise<{ success: boolean }>}
   *
   * @example
   *   await sdk.logout({ sessionToken: mySessionToken });
   *   // or revoke all sessions for a wallet:
   *   await sdk.logout({ walletId: myWalletId });
   */
  async logout({ sessionToken, walletId } = {}) {
    return this._api('/wallet/logout', {
      session_token: sessionToken || undefined,
      wallet_id:     walletId     || undefined,
    });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 6. SHARD RETRIEVAL & RECOVERY
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // Shard B: Always on the server (ReDB), encrypted with SERVER_MASTER_KEY
  // Shard C: User's cold storage, backed up to HashiCorp Vault
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Retrieve Shard B from the server (server-encrypted blob).
   * During SSS verify or transfer, the server decrypts it internally.
   *
   * @param {string} walletId - Wallet address
   * @returns {Promise<{ shardB: string, status: string }>}
   *
   * @example
   *   const { shardB } = await sdk.getShardB('4PtfY2qR...');
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
   * Emergency recovery: retrieve Shard C from HashiCorp Vault.
   * Requires JWT with aal2 (2FA) authentication.
   *
   * @returns {Promise<{ shardC: string, warning: string }>}
   *
   * @example
   *   sdk.setJWT(supabaseJwt);
   *   const { shardC, warning } = await sdk.recoverShardC();
   *   console.log(warning); // "This is a one-time recovery..."
   */
  async recoverShardC() {
    const result = await this._api('/wallet/secure/recover-shard-c', {});
    return {
      shardC:  result.shard_c,
      warning: result.warning,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 7. FAUCET (Dev/Testnet Token Minting)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // POST /faucet
  //
  // Mints BB tokens to any address. Rate-limited: max 99,999 BB per address
  // per epoch. No authentication required.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Request BB tokens from the faucet.
   *
   * @param {string} toAddress     - Recipient address
   * @param {number} [amountBB=100] - Amount in BB (max 99,999 per epoch)
   * @returns {Promise<{ success: boolean, minted: number, to: string, new_balance: number }>}
   *
   * @example
   *   const result = await sdk.faucet('4PtfY2qR...', 1000);
   *   console.log(result.new_balance); // 1000
   */
  async faucet(toAddress, amountBB = 100) {
    if (amountBB > MAX_FAUCET_BB) amountBB = MAX_FAUCET_BB;
    if (amountBB <= 0) throw new Error('Amount must be positive');
    return this._api('/faucet', { to: toAddress, amount: amountBB });
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 8. TRANSACTION HISTORY
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Get recent transaction signatures for an address.
   *
   * @param {string} address
   * @param {number} [limit=20]
   * @returns {Promise<Array<{ signature, slot, err, blockTime, confirmationStatus }>>}
   *
   * @example
   *   const txs = await sdk.getTransactionHistory('4PtfY2qR...');
   *   txs.forEach(tx => console.log(tx.signature, tx.blockTime));
   */
  async getTransactionHistory(address, limit = 20) {
    return this._rpc('getSignaturesForAddress', [address, { limit }]);
  }

  /**
   * Get full transaction detail by signature.
   *
   * @param {string} signature
   * @returns {Promise<Object|null>}
   *
   * @example
   *   const tx = await sdk.getTransaction('3fKx...');
   *   console.log(tx);
   */
  async getTransaction(signature) {
    return this._rpc('getTransaction', [signature, { encoding: 'json' }]);
  }


  // ═══════════════════════════════════════════════════════════════════════════
  // 9. LOCAL SESSION MANAGEMENT (Browser localStorage)
  // ═══════════════════════════════════════════════════════════════════════════
  //
  // These methods persist the wallet session in the browser. Only the
  // encrypted Shard A and public info are stored — NEVER the mnemonic,
  // Shard C, or any plaintext secret.
  //
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Save wallet session to browser localStorage.
   *
   * Stores: walletId, address, encrypted shardA, publicKey.
   * Does NOT store: mnemonic, shardC (show-once secrets).
   *
   * @param {WalletCreateResult} wallet - Wallet object from createWallet()
   *
   * @example
   *   const wallet = await sdk.createWallet('alice', { password: 'hunter2' });
   *   sdk.saveWalletLocal(wallet);   // Persists to localStorage
   */
  saveWalletLocal(wallet) {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available — use Node.js file storage instead');
    }
    const session = {
      wallet_id:            wallet.walletId,
      address:              wallet.address,
      share_a:              wallet.shardA,
      share_a_is_encrypted: wallet.shardAIsEncrypted,
      public_key:           wallet.publicKey,
      created_at:           new Date().toISOString(),
    };
    localStorage.setItem('bb_wallet', JSON.stringify(session));
    localStorage.setItem(`bb_shard_a_${wallet.walletId}`, wallet.shardA);
  }

  /**
   * Load wallet session from browser localStorage.
   *
   * @returns {WalletSession|null}
   *
   * @typedef {Object} WalletSession
   * @property {string}  walletId
   * @property {string}  address
   * @property {string}  shardA           - Encrypted blob
   * @property {boolean} shardAIsEncrypted
   * @property {string}  publicKey
   * @property {string}  createdAt
   *
   * @example
   *   const session = sdk.loadWalletLocal();
   *   if (session) {
   *     console.log(`Logged in as ${session.address}`);
   *   }
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
    } catch (_) {
      return null;
    }
  }

  /**
   * Delete wallet session from localStorage (logout).
   *
   * @param {string} [walletId] - Also removes shard-specific key
   *
   * @example
   *   sdk.deleteWalletLocal(myWalletId);  // Full cleanup
   */
  deleteWalletLocal(walletId) {
    if (typeof localStorage === 'undefined') return;
    localStorage.removeItem('bb_wallet');
    if (walletId) {
      localStorage.removeItem(`bb_shard_a_${walletId}`);
    }
  }

  // ───────────────────────────────────────────────────────────────────────────
  // 9b. Individual Shard A Storage
  // ───────────────────────────────────────────────────────────────────────────

  /**
   * Save encrypted Shard A to localStorage.
   * @param {string} walletId
   * @param {string} encryptedShardA
   */
  saveShardALocal(walletId, encryptedShardA) {
    if (typeof localStorage === 'undefined') {
      throw new Error('localStorage not available');
    }
    localStorage.setItem(`bb_shard_a_${walletId}`, encryptedShardA);
  }

  /**
   * Load encrypted Shard A from localStorage.
   * @param {string} walletId
   * @returns {string|null}
   */
  loadShardALocal(walletId) {
    if (typeof localStorage === 'undefined') return null;
    return localStorage.getItem(`bb_shard_a_${walletId}`);
  }

  /**
   * Delete Shard A from localStorage.
   * @param {string} walletId
   */
  deleteShardALocal(walletId) {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem(`bb_shard_a_${walletId}`);
    }
  }



  // ═══════════════════════════════════════════════════════════════════════════
  // 10. UTILITIES
  // ═══════════════════════════════════════════════════════════════════════════

  /** Convert BB to lamports */
  static toLamports(bb) { return Math.floor(bb * LAMPORTS_PER_BB); }

  /** Convert lamports to BB */
  static toBB(lamports) { return lamports / LAMPORTS_PER_BB; }

  /** Format BB for display: "1,000.00" */
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

  /** Set or update JWT (e.g. after Supabase login) */
  setJWT(jwt) { this.jwt = jwt; }
}


// ============================================================================
// COMPLETE USAGE GUIDE
// ============================================================================
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 1: Initialize SDK
// ─────────────────────────────────────────────────────────────────────────────
//
//   const sdk = new BlackBookWalletSDK('https://rpc.blackbook.finance:8899');
//
//   // Or with Supabase auth:
//   const sdk = new BlackBookWalletSDK(
//     'https://rpc.blackbook.finance:8899',
//     'https://rpc.blackbook.finance:8080',
//     { jwt: supabaseAccessToken }
//   );
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 2: Create a Wallet
// ─────────────────────────────────────────────────────────────────────────────
//
//   const wallet = await sdk.createWallet('alice', {
//     password: 'my-strong-password',  // Encrypts Shard A
//     pin: '1234',                     // For high-value tx auth
//   });
//
//   // ⚠️  SHOW THESE TO THE USER ONCE, THEN DISCARD:
//   console.log('Mnemonic:', wallet.mnemonic);     // 24-word recovery phrase
//   console.log('Shard C:',  wallet.shardC);       // Cold storage hex
//
//   // Save encrypted Shard A to browser:
//   sdk.saveWalletLocal(wallet);
//
//   // The wallet is auto-logged-in via wallet.sessionToken
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 3: Login (Returning User)
// ─────────────────────────────────────────────────────────────────────────────
//
//   // Load saved session
//   const saved = sdk.loadWalletLocal();
//   if (!saved) { /* redirect to create/import */ }
//
//   // Authenticate with password + Shard A
//   const session = await sdk.login({
//     walletId:  saved.walletId,
//     shard1:    saved.shardA,       // Encrypted blob from localStorage
//     shard2:    '',                  // Server auto-fetches Shard B
//     password:  userEnteredPassword,
//     shard2IsServerEncrypted: true,
//   });
//
//   // session.sessionToken is valid for 30 minutes
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 4: Check Balance
// ─────────────────────────────────────────────────────────────────────────────
//
//   const bal = await sdk.getBalance(saved.address);
//   console.log(`Balance: ${bal.bb} BB`);
//
//   // Or via REST:
//   const info = await sdk.getBalanceREST(saved.address);
//   console.log(`Balance: ${info.balance} BB`);
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 5: Send Tokens
// ─────────────────────────────────────────────────────────────────────────────
//
//   const result = await sdk.transfer(
//     saved.walletId,                // From
//     'RecipientAddr...',            // To
//     50,                            // 50 BB
//     saved.shardA,                  // Encrypted Shard A
//     'my-strong-password'           // Password to decrypt it
//   );
//
//   console.log('Signature:', result.signature);
//   console.log('My balance:', result.fromBalance, 'BB');
//   console.log('Their balance:', result.toBalance, 'BB');
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 6: Verify Your Shards Still Work
// ─────────────────────────────────────────────────────────────────────────────
//
//   // Quick check: A + B (most common)
//   const check = await sdk.verifySssCombo({
//     combo: 'AB',
//     walletId: saved.walletId,
//     shardA: saved.shardA,
//     password: 'my-strong-password',
//   });
//   console.log('Shards valid:', check.matches);  // true ✓
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 7: Transaction History
// ─────────────────────────────────────────────────────────────────────────────
//
//   const history = await sdk.getTransactionHistory(saved.address);
//   history.forEach(tx => {
//     console.log(tx.signature, tx.blockTime);
//   });
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 8: Emergency Recovery (Lost Phone / New Device)
// ─────────────────────────────────────────────────────────────────────────────
//
//   // Option A: Restore Shard A from Supabase
//   sdk.setJWT(newSupabaseToken);
//   const { encryptedShardA } = await sdk.restoreShardA(walletId);
//   sdk.saveShardALocal(walletId, encryptedShardA);
//   // Then login normally with password
//
//   // Option B: Use Shard C (cold storage) + Server
//   const check = await sdk.verifySssCombo({
//     combo: 'BC',
//     walletId: walletId,
//     shardC: 'your-cold-shard-hex...',
//   });
//
//   // Option C: Emergency Vault recovery
//   sdk.setJWT(aal2Token); // Requires 2FA
//   const { shardC } = await sdk.recoverShardC();
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 9: Logout
// ─────────────────────────────────────────────────────────────────────────────
//
//   sdk.deleteWalletLocal(saved.walletId);
//   // Session token expires server-side after 30 minutes automatically
//
// ─────────────────────────────────────────────────────────────────────────────
// STEP 10: Fund Wallet (Dev/Testnet)
// ─────────────────────────────────────────────────────────────────────────────
//
//   await sdk.faucet(saved.address, 1000);  // Mint 1000 BB
//
// ============================================================================


// ============================================================================
// EXPORTS
// ============================================================================

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BlackBookWalletSDK, LAMPORTS_PER_BB, CHAIN_ID, MAX_FAUCET_BB, SSS_COMBOS };
}

if (typeof globalThis !== 'undefined') {
  globalThis.BlackBookWalletSDK = BlackBookWalletSDK;
  globalThis.SSS_COMBOS = SSS_COMBOS;
}
