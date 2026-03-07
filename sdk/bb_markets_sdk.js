/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  BB MARKETS SDK — BlackBook L1 ↔ L2 Betting Integration
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  Unified SDK for browsing BB markets (L2), depositing BB tokens from
 *  your L1 wallet into contest escrow, placing bets, and claiming winnings.
 *
 *  ═══════════════════════════════════════════════════════════════════════════
 *  ARCHITECTURE: How L1 and L2 Talk
 *  ═══════════════════════════════════════════════════════════════════════════
 *
 *  ┌──────────────────────────────────┐      ┌──────────────────────────────┐
 *  │  L1 — BlackBook Chain           │      │  L2 — Contest Engine         │
 *  │                                  │      │                              │
 *  │  • BB token balances             │      │  • Market create/fund/resolve │
 *  │  • Global escrow PDA             │      │  • Entry logic + picks        │
 *  │  • Per-contest vault accounting  │◄─────│  • gRPC VerifyDeposit bridge  │
 *  │  • Merkle root storage           │      │  • Merkle tree + proof cache  │
 *  │  • Withdrawal (Merkle proof)     │      │  • Settlement proofs          │
 *  └──────────────────────────────────┘      └──────────────────────────────┘
 *
 *  ═══════════════════════════════════════════════════════════════════════════
 *  BETTING FLOW (end-to-end)
 *  ═══════════════════════════════════════════════════════════════════════════
 *
 *  1. DEPOSIT: User sends BB from their L1 wallet to the contest escrow vault
 *     └─ L1 transfer: wallet → escrow PDA (returns BlackBook tx signature)
 *
 *  2. ENTER:  User presents the tx sig to L2 with their pick
 *     └─ L2 calls L1 gRPC VerifyDeposit: checks tx finalized, correct vault,
 *        correct amount, not double-spent. L1 returns the depositor wallet
 *        address it observed on-chain (L2 never trusts self-reported wallet).
 *
 *  3. RESOLVE: Dealer resolves market → L2 builds Merkle tree → submits root
 *     to L1 via gRPC → caches per-wallet proofs in memory
 *
 *  4. CLAIM: Winner fetches their Merkle proof from L2, then calls L1
 *     escrow withdraw with the proof to receive their payout.
 *
 *  If L2 rejects the entry (wrong pick, market full, etc.), the user's
 *  deposit stays in the L1 escrow vault. Recovery requires dealer intervention.
 *
 *  ═══════════════════════════════════════════════════════════════════════════
 *  CURRENCY
 *  ═══════════════════════════════════════════════════════════════════════════
 *
 *    BB (BlackBook) = $0.10 USD — redeemable sweepstakes prize token
 *    BB balances live on Layer 1. L2 does NOT track BB balances.
 *    1 BB = 100,000 lamports (5 decimal places)
 *
 *  ═══════════════════════════════════════════════════════════════════════════
 *  QUICK START
 *  ═══════════════════════════════════════════════════════════════════════════
 *
 *  import { BbMarketsSDK } from './bb_markets_sdk.js';
 *  import { BlackBookWalletSDK } from './wallet_sdk.js';
 *
 *  // ── Initialize both layers ──
 *  const l1 = new BlackBookWalletSDK('http://localhost:8899', 'http://localhost:8080');
 *  const bb = new BbMarketsSDK({
 *    supabaseUrl: 'https://your-project.supabase.co',
 *    supabaseKey: 'your-anon-key',
 *    l2Url:       'http://localhost:1234',
 *    l1Sdk:       l1,                       // ← attach your L1 wallet SDK
 *  });
 *
 *  // ── Auth ──
 *  await bb.signIn('alice@example.com', 'Password123!');
 *
 *  // ── Browse markets ──
 *  const markets = await bb.listActive();
 *  const market  = await bb.getMarket('rain-austin-bb-0601');
 *  console.log(`Entry fee: ${market.entryFee} BB (${market.entryFeeUsd})`);
 *
 *  // ── Check L1 balance ──
 *  const bal = await bb.getL1Balance('8CZJAZn...');
 *  console.log(`L1 wallet: ${bal.bb} BB`);
 *
 *  // ── Place a bet (deposit to escrow + enter market) ──
 *  // Step 1: Deposit BB to the contest escrow on L1
 *  const deposit = await bb.depositToEscrow({
 *    walletAddress: '8CZJAZn...',
 *    amount:        market.entryFee,
 *    publicKey:     pubkeyHex,
 *    signature:     myEd25519Sig,     // sign "ESCROW_DEPOSIT:..." message
 *    timestamp:     Math.floor(Date.now() / 1000),
 *    nonce:         crypto.randomUUID(),
 *  });
 *  console.log(`Deposited ${deposit.deposited} BB → escrow`);
 *
 *  // Step 2: Enter the market on L2 with the BlackBook tx signature
 *  const entry = await bb.enterMarket('rain-austin-bb-0601', 'yes', deposit.txSignature);
 *  console.log('Entered! Pool:', entry.usdPrizePool);
 *
 *  // ── Or do both in one call ──
 *  const result = await bb.placeBet({
 *    marketId:      'rain-austin-bb-0601',
 *    pick:          'yes',
 *    walletAddress: '8CZJAZn...',
 *    publicKey:     pubkeyHex,
 *    signature:     myEd25519Sig,
 *    timestamp:     ts,
 *    nonce:         nonce,
 *  });
 *
 *  // ── Claim winnings after resolution ──
 *  const proof = await bb.getSettlementProof('rain-austin-bb-0601', '8CZJAZn...');
 *  const claim = await bb.claimWinnings({
 *    marketId:      'rain-austin-bb-0601',
 *    walletAddress: '8CZJAZn...',
 *    amount:        proof.amount,
 *    merkleProof:   proof.merkleProof,
 *    publicKey:     pubkeyHex,
 *    signature:     withdrawSig,
 *    timestamp:     ts,
 *    nonce:         nonce,
 *  });
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

// ──────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ──────────────────────────────────────────────────────────────────────────

const BB_USD        = 0.10;      // 1 BB = $0.10
const LAMPORTS_PER_BB = 100_000; // 1 BB = 100,000 lamports

// ──────────────────────────────────────────────────────────────────────────
// HELPERS
// ──────────────────────────────────────────────────────────────────────────

function formatBB(n)       { return `${Number(n).toFixed(2)} BB`; }
function bbToUsd(n)        { return `$${(Number(n) * BB_USD).toFixed(2)}`; }
function bbToLamports(n)   { return Math.round(Number(n) * LAMPORTS_PER_BB); }
function lamportsToBB(n)   { return Number(n) / LAMPORTS_PER_BB; }

function decodeJwt(token) {
  try {
    const payload = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    const decoded = typeof atob !== 'undefined'
      ? atob(payload)
      : Buffer.from(payload, 'base64').toString('utf-8');
    return JSON.parse(decoded);
  } catch { return null; }
}

function isJwtExpired(token) {
  const p = decodeJwt(token);
  if (!p?.exp) return true;
  return p.exp * 1000 < Date.now();
}

// ──────────────────────────────────────────────────────────────────────────
// SDK CLASS
// ──────────────────────────────────────────────────────────────────────────

export class BbMarketsSDK {

  /**
   * @param {Object} config
   * @param {string} config.supabaseUrl  - Supabase project URL
   * @param {string} config.supabaseKey  - Supabase anon (public) key
   * @param {string} [config.l2Url]      - L2 base URL (default: localhost:1234)
   * @param {string} [config.dealerJwt]  - Dealer JWT for admin operations
   * @param {Object} [config.l1Sdk]      - BlackBookWalletSDK instance for L1 operations
   * @param {string} [config.l1ApiUrl]   - L1 HTTP API URL (fallback if no l1Sdk)
   * @param {string} [config.l1RpcUrl]   - L1 JSON-RPC URL (fallback if no l1Sdk)
   */
  constructor(config = {}) {
    if (!config.supabaseUrl || !config.supabaseKey) {
      throw new Error('BbMarketsSDK requires supabaseUrl and supabaseKey');
    }
    this._supabaseUrl = config.supabaseUrl.replace(/\/$/, '');
    this._supabaseKey = config.supabaseKey;
    this._l2Url       = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
    this._dealerJwt   = config.dealerJwt || null;

    // L1 connection (wallet SDK or direct URLs)
    this._l1Sdk       = config.l1Sdk || null;
    this._l1ApiUrl    = (config.l1ApiUrl || 'http://localhost:8080').replace(/\/$/, '');
    this._l1RpcUrl    = (config.l1RpcUrl || 'http://localhost:8899').replace(/\/$/, '');

    this._username    = null;
    this._accessToken = null;
  }

  // ── Getters ──────────────────────────────────────────────────────────────

  get username()   { return this._username; }
  get isSignedIn() { return !!this._username && !!this._accessToken; }
  get hasL1()      { return !!this._l1Sdk; }


  // ═════════════════════════════════════════════════════════════════════════
  // AUTH — Supabase (same account used by fc sdk)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Sign in with email + password.
   * JWT is required for enterMarket().
   *
   * @param {string} email
   * @param {string} password
   * @returns {Promise<{username, accessToken}>}
   */
  async signIn(email, password) {
    const resp = await fetch(
      `${this._supabaseUrl}/auth/v1/token?grant_type=password`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'apikey': this._supabaseKey },
        body:    JSON.stringify({ email, password }),
      }
    );
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error_description || data.msg || 'Sign-in failed');

    const username = data.user?.user_metadata?.username;
    if (!username) throw new Error('No username in user_metadata — account misconfigured');

    this._username    = username;
    this._accessToken = data.access_token;

    return { username, accessToken: data.access_token };
  }

  /** Sign out — clears session. */
  signOut() {
    this._username    = null;
    this._accessToken = null;
  }

  /** Whether the current token is expired. */
  isTokenExpired() {
    if (!this._accessToken) return true;
    return isJwtExpired(this._accessToken);
  }


  // ═════════════════════════════════════════════════════════════════════════
  // L1 WALLET — Balance + Escrow (talks to BlackBook chain)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Get BB balance for an L1 wallet address.
   *
   * @param {string} address - BlackBook L1 public address (base58)
   * @returns {Promise<{lamports: number, bb: number, usd: string}>}
   *
   * @example
   *   const bal = await bb.getL1Balance('8CZJAZn...');
   *   console.log(`${bal.bb} BB (${bal.usd})`);
   */
  async getL1Balance(address) {
    if (this._l1Sdk) {
      const result = await this._l1Sdk.getBalance(address);
      return { lamports: result.lamports, bb: result.bb, usd: bbToUsd(result.bb) };
    }
    const data = await this._l1Get(`/balance/${address}`);
    return { lamports: bbToLamports(data.balance), bb: data.balance, usd: bbToUsd(data.balance) };
  }

  /**
   * Get the global escrow vault status from L1.
   *
   * @returns {Promise<{escrowAddress: string, escrowBalance: number, escrowBalanceBB: number, totalMarketsSettled: number, l2SequencerConfigured: boolean}>}
   */
  async getEscrowStatus() {
    if (this._l1Sdk) {
      const s = await this._l1Sdk.getEscrowStatus();
      return {
        escrowAddress:          s.escrow_address,
        escrowBalance:          s.escrow_balance_lamports,
        escrowBalanceBB:        lamportsToBB(s.escrow_balance_lamports),
        totalMarketsSettled:    s.total_markets_settled,
        l2SequencerConfigured:  s.l2_sequencer_configured,
      };
    }
    const s = await this._l1Get('/escrow/status');
    return {
      escrowAddress:          s.escrow_address,
      escrowBalance:          s.escrow_balance_lamports,
      escrowBalanceBB:        lamportsToBB(s.escrow_balance_lamports),
      totalMarketsSettled:    s.total_markets_settled,
      l2SequencerConfigured:  s.l2_sequencer_configured,
    };
  }

  /**
   * Look up the Merkle root stored on L1 for a settled market.
   *
   * @param {string} marketId
   * @returns {Promise<{success: boolean, marketId: string, merkleRoot: string|null}>}
   */
  async getMarketMerkleRoot(marketId) {
    if (this._l1Sdk) {
      const r = await this._l1Sdk.getEscrowMarket(marketId);
      return { success: r.success, marketId: r.market_id, merkleRoot: r.merkle_root || null };
    }
    const r = await this._l1Get(`/escrow/market/${encodeURIComponent(marketId)}`);
    return { success: r.success, marketId: r.market_id, merkleRoot: r.merkle_root || null };
  }

  /**
   * Deposit BB tokens into the L1 global escrow vault.
   *
   * This is Step 1 of the betting flow. The caller must pre-sign the message:
   *   "ESCROW_DEPOSIT:{walletAddress}:{amount}:{timestamp}:{nonce}"
   *
   * The returned txSignature is what you pass to enterMarket() as depositTxSig.
   *
   * @param {Object} params
   * @param {string} params.walletAddress - L1 wallet address sending BB
   * @param {number} params.amount        - Amount in BB (must match market entryFee)
   * @param {string} params.publicKey     - Ed25519 public key hex (64 chars)
   * @param {string} params.signature     - Ed25519 signature hex (128 chars)
   * @param {number} params.timestamp     - Unix seconds (must be within 60s of L1 server)
   * @param {string} params.nonce         - Unique string (UUID v4 recommended)
   * @returns {Promise<{success: boolean, deposited: number, walletAddress: string, escrowAddress: string, userBalance: number, escrowBalance: number, txSignature: string}>}
   *
   * @example
   *   const ts    = Math.floor(Date.now() / 1000);
   *   const nonce = crypto.randomUUID();
   *   const msg   = `ESCROW_DEPOSIT:${addr}:${amount}:${ts}:${nonce}`;
   *   const sig   = await myEd25519Sign(msg);
   *
   *   const dep = await bb.depositToEscrow({
   *     walletAddress: addr,
   *     amount:        10.0,
   *     publicKey:     pubkeyHex,
   *     signature:     sig,
   *     timestamp:     ts,
   *     nonce,
   *   });
   *   console.log(`Deposited ${dep.deposited} BB, tx: ${dep.txSignature}`);
   */
  async depositToEscrow({ walletAddress, amount, publicKey, signature, timestamp, nonce }) {
    if (!walletAddress || amount <= 0) throw new Error('walletAddress and positive amount required');
    if (!publicKey || !signature) throw new Error('publicKey and signature required');
    if (!timestamp || !nonce) throw new Error('timestamp and nonce required');

    let data;
    if (this._l1Sdk) {
      data = await this._l1Sdk.escrowDeposit({ walletAddress, amount, publicKey, signature, timestamp, nonce });
    } else {
      data = await this._l1Post('/escrow/deposit', {
        wallet_address: walletAddress,
        amount,
        public_key:  publicKey,
        signature,
        timestamp,
        nonce,
      });
    }

    return {
      success:        data.success !== false,
      deposited:      data.deposited,
      walletAddress:  data.wallet_address,
      escrowAddress:  data.escrow_address,
      userBalance:    data.user_balance,
      escrowBalance:  data.escrow_balance,
      txSignature:    data.tx_signature || data.signature || null,
    };
  }


  // ═════════════════════════════════════════════════════════════════════════
  // MARKETS — Read (no auth required)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * List all BB markets.
   * @returns {Promise<Array>}
   */
  async listMarkets() {
    const data = await this._get('/bb');
    return (data.markets || []).map(m => this._mapMarket(m));
  }

  /**
   * List only active markets (status = Active, funded = true).
   * These are the markets users can bet on right now.
   * @returns {Promise<Array>}
   */
  async listActive() {
    const all = await this.listMarkets();
    return all.filter(m => m.status === 'Active');
  }

  /**
   * List markets filtered by status.
   * @param {'Active'|'Frozen'|'Resolved'|'Draft'} status
   * @returns {Promise<Array>}
   */
  async listByStatus(status) {
    const all = await this.listMarkets();
    return all.filter(m => m.status === status);
  }

  /**
   * List resolved markets (settled — winners can claim).
   * @returns {Promise<Array>}
   */
  async listResolved() {
    return this.listByStatus('Resolved');
  }

  /**
   * Get a single BB market (full detail including entries_detail).
   *
   * @param {string} marketId
   * @returns {Promise<Object>}
   */
  async getMarket(marketId) {
    const data = await this._get(`/bb/${marketId}`);
    return this._mapMarketDetail(data);
  }

  /**
   * Get market + check if current user has already entered.
   * @param {string} marketId
   * @returns {Promise<{market, hasEntered, userEntry}>}
   */
  async getMarketWithEntry(marketId) {
    const market = await this.getMarket(marketId);
    if (!this._username) return { market, hasEntered: false, userEntry: null };
    const entry = (market.entriesDetail || []).find(e => e.username === this._username);
    return { market, hasEntered: !!entry, userEntry: entry || null };
  }

  /**
   * Get market + L1 balance for a wallet in one call.
   * Useful for rendering a "bet placement" UI.
   *
   * @param {string} marketId
   * @param {string} walletAddress - L1 wallet to check balance for
   * @returns {Promise<{market, balance, canAfford, hasEntered, userEntry}>}
   */
  async getMarketWithBalance(marketId, walletAddress) {
    const [marketInfo, bal] = await Promise.all([
      this.getMarketWithEntry(marketId),
      this.getL1Balance(walletAddress),
    ]);
    return {
      market:     marketInfo.market,
      balance:    bal,
      canAfford:  bal.bb >= marketInfo.market.entryFee,
      hasEntered: marketInfo.hasEntered,
      userEntry:  marketInfo.userEntry,
    };
  }


  // ═════════════════════════════════════════════════════════════════════════
  // ENTER — Requires JWT + on-chain deposit proof
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Enter a BB market.
   *
   * REQUIREMENTS:
   *   1. Signed in (valid Supabase JWT)
   *   2. On-chain deposit already sent to the market's escrow vault
   *   3. `depositTxSig` must be the confirmed BlackBook tx signature (base58, 88 chars)
   *
   * The L2 server calls L1 gRPC VerifyDeposit:
   *   - Tx is finalized on-chain
   *   - Sent to the correct contest vault
   *   - Correct amount (entry_fee converted to SPL units)
   *   - Not already used for a different entry (no double-spend)
   *   - L1 returns the depositor wallet address (L2 never trusts self-reported wallet)
   *
   * @param {string}  marketId      - Market ID to enter
   * @param {string}  pick          - Your pick (must match market.outcomeOptions)
   * @param {string}  depositTxSig  - Confirmed BlackBook tx signature (base58)
   * @returns {Promise<{success, marketId, username, entryFee, depositorWallet, prizePool, usdPrizePool}>}
   *
   * @example
   *   // After depositing BB to escrow via depositToEscrow():
   *   const entry = await bb.enterMarket(
   *     'rain-austin-bb',
   *     'yes',
   *     deposit.txSignature   // from depositToEscrow()
   *   );
   */
  async enterMarket(marketId, pick, depositTxSig) {
    const username = this._requireUsername();
    const token    = this._requireToken();

    if (!depositTxSig) throw new Error('depositTxSig is required — call depositToEscrow() first');
    if (!pick)         throw new Error('pick is required');

    const data = await this._post(`/bb/${marketId}/enter`, {
      username,
      choice: { pick, deposit_tx: depositTxSig },
    }, token);

    return {
      success:         true,
      marketId:        data.market_id,
      username:        data.username,
      entryFee:        data.entry_fee,
      entryFeeUsd:     bbToUsd(data.entry_fee),
      depositorWallet: data.depositor_wallet,  // L1-verified, not self-reported
      prizePool:       data.prize_pool,
      usdPrizePool:    data.usd_prize_pool,
    };
  }

  /**
   * Place a bet — unified flow: deposit BB to L1 escrow + enter market on L2.
   *
   * Combines depositToEscrow() + enterMarket() into a single call.
   * The deposit amount is automatically set to the market's entry_fee.
   *
   * Requires: signed in + Ed25519 signature over the escrow deposit message.
   *
   * Signing convention (sign this UTF-8 string with your wallet's Ed25519 key):
   *   "ESCROW_DEPOSIT:{walletAddress}:{entryFee}:{timestamp}:{nonce}"
   *
   * @param {Object} params
   * @param {string} params.marketId      - Market to enter
   * @param {string} params.pick          - Your pick (e.g. 'yes', 'no', 'over')
   * @param {string} params.walletAddress - L1 wallet address
   * @param {string} params.publicKey     - Ed25519 public key hex (64 chars)
   * @param {string} params.signature     - Ed25519 signature hex (128 chars)
   * @param {number} params.timestamp     - Unix seconds (within 60s of L1 server)
   * @param {string} params.nonce         - Unique string (UUID v4)
   * @param {number} [params.amount]      - Override deposit amount (default: market entryFee)
   * @returns {Promise<{deposit, entry, market}>}
   *
   * @example
   *   const market = await bb.getMarket('rain-austin-bb');
   *   const ts     = Math.floor(Date.now() / 1000);
   *   const nonce  = crypto.randomUUID();
   *   const msg    = `ESCROW_DEPOSIT:${myAddr}:${market.entryFee}:${ts}:${nonce}`;
   *   const sig    = await myEd25519Sign(msg);
   *
   *   const result = await bb.placeBet({
   *     marketId:      'rain-austin-bb',
   *     pick:          'yes',
   *     walletAddress: myAddr,
   *     publicKey:     pubkeyHex,
   *     signature:     sig,
   *     timestamp:     ts,
   *     nonce,
   *   });
   *   console.log('Deposit:', result.deposit.deposited, 'BB');
   *   console.log('Entry:', result.entry.prizePool, 'BB pool');
   */
  async placeBet({ marketId, pick, walletAddress, publicKey, signature, timestamp, nonce, amount }) {
    this._requireUsername();
    this._requireToken();

    // Fetch market to get entry fee if amount not provided
    let market;
    if (!amount) {
      market = await this.getMarket(marketId);
      if (!market.canEnter) {
        throw new Error(`Market "${marketId}" is not open for entries (status: ${market.status}, funded: ${market.funded})`);
      }
      amount = market.entryFee;
    }

    // Step 1: Deposit BB to L1 escrow
    const deposit = await this.depositToEscrow({
      walletAddress, amount, publicKey, signature, timestamp, nonce,
    });

    if (!deposit.txSignature) {
      throw new Error('Escrow deposit succeeded but no tx signature returned — cannot verify entry');
    }

    // Step 2: Enter the market on L2 with the BlackBook tx signature
    const entry = await this.enterMarket(marketId, pick, deposit.txSignature);

    return { deposit, entry, market: market || null };
  }


  // ═════════════════════════════════════════════════════════════════════════
  // CLAIM WINNINGS — After market resolution
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Fetch settlement proof for a resolved market.
   *
   * After a market is resolved, L2 caches Merkle proofs per wallet.
   * Call this to get your proof, then pass it to claimWinnings().
   *
   * NOTE: The L2 proof endpoint (GET /bb/{id}/proof/{wallet}) must be
   * implemented on your L2 server. This method calls it.
   *
   * @param {string} marketId      - Resolved market ID
   * @param {string} walletAddress - Your L1 wallet address (base58)
   * @returns {Promise<{marketId, walletAddress, amount, merkleProof: string[]}>}
   */
  async getSettlementProof(marketId, walletAddress) {
    const data = await this._get(`/bb/${marketId}/proof/${walletAddress}`);
    return {
      marketId:      data.market_id || marketId,
      walletAddress: data.wallet_address || walletAddress,
      amount:        data.amount,
      merkleProof:   data.merkle_proof || [],
    };
  }

  /**
   * Claim winnings from a resolved market via L1 escrow withdrawal.
   *
   * Requires a Merkle proof (from getSettlementProof) and an Ed25519 signature.
   *
   * Signing convention:
   *   "ESCROW_WITHDRAW:{marketId}:{walletAddress}:{amount}:{timestamp}:{nonce}"
   *
   * @param {Object} params
   * @param {string}   params.marketId      - Resolved market ID
   * @param {string}   params.walletAddress - L1 wallet to receive payout
   * @param {number}   params.amount        - BB amount entitled by Merkle leaf
   * @param {string[]} params.merkleProof   - Sibling hashes leaf→root (64-char hex each)
   * @param {string}   params.publicKey     - Ed25519 public key hex (64 chars)
   * @param {string}   params.signature     - Ed25519 signature hex (128 chars)
   * @param {number}   params.timestamp     - Unix seconds (within 60s of L1 server)
   * @param {string}   params.nonce         - Unique string (UUID v4)
   * @returns {Promise<{success, withdrawn, marketId, walletAddress, newBalance}>}
   *
   * @example
   *   const proof = await bb.getSettlementProof('rain-austin-bb', myAddr);
   *   const ts    = Math.floor(Date.now() / 1000);
   *   const nonce = crypto.randomUUID();
   *   const msg   = `ESCROW_WITHDRAW:${proof.marketId}:${myAddr}:${proof.amount}:${ts}:${nonce}`;
   *   const sig   = await myEd25519Sign(msg);
   *
   *   const claim = await bb.claimWinnings({
   *     marketId:      proof.marketId,
   *     walletAddress: myAddr,
   *     amount:        proof.amount,
   *     merkleProof:   proof.merkleProof,
   *     publicKey:     pubkeyHex,
   *     signature:     sig,
   *     timestamp:     ts,
   *     nonce,
   *   });
   *   console.log(`Claimed ${claim.withdrawn} BB — new balance: ${claim.newBalance} BB`);
   */
  async claimWinnings({ marketId, walletAddress, amount, merkleProof, publicKey, signature, timestamp, nonce }) {
    if (!marketId || !walletAddress || amount <= 0) throw new Error('marketId, walletAddress, and positive amount required');
    if (!Array.isArray(merkleProof)) throw new Error('merkleProof must be an array of hex strings');
    if (!publicKey || !signature) throw new Error('publicKey and signature required');

    let data;
    if (this._l1Sdk) {
      data = await this._l1Sdk.escrowWithdraw({ marketId, walletAddress, amount, merkleProof, publicKey, signature, timestamp, nonce });
    } else {
      data = await this._l1Post('/escrow/withdraw', {
        market_id:      marketId,
        wallet_address: walletAddress,
        amount,
        merkle_proof:   merkleProof,
        public_key:     publicKey,
        signature,
        timestamp,
        nonce,
      });
    }

    return {
      success:       data.success !== false,
      withdrawn:     data.withdrawn,
      marketId:      data.market_id,
      walletAddress: data.wallet_address,
      newBalance:    data.new_balance,
    };
  }

  /**
   * Check if a wallet has already claimed winnings for a market.
   *
   * @param {string} marketId
   * @param {string} walletAddress
   * @returns {Promise<boolean>}
   */
  async hasClaimedWinnings(marketId, walletAddress) {
    try {
      const market = await this.getMarket(marketId);
      if (market.status !== 'Resolved') return false;
      const entry = (market.entriesDetail || []).find(
        e => e.wallet === walletAddress || e.depositor_wallet === walletAddress
      );
      return entry?.claimed === true;
    } catch {
      return false;
    }
  }


  // ═════════════════════════════════════════════════════════════════════════
  // MARKET ANALYTICS — Computed helpers for UI
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Get odds breakdown for a market (percentage of entries per pick).
   *
   * @param {string} marketId
   * @returns {Promise<{marketId, title, totalEntries, odds: Object<string, {count, pct, impliedOdds}>}>}
   *
   * @example
   *   const odds = await bb.getMarketOdds('rain-austin-bb');
   *   // { totalEntries: 20, odds: { yes: { count: 12, pct: '60.0%', impliedOdds: '1.67x' }, ... } }
   */
  async getMarketOdds(marketId) {
    const market = await this.getMarket(marketId);
    const entries = market.entriesDetail || [];
    const total = entries.length;

    const counts = {};
    for (const opt of market.outcomeOptions) counts[opt] = 0;
    for (const e of entries) {
      const pick = e.pick || e.choice;
      if (pick in counts) counts[pick]++;
    }

    const odds = {};
    for (const [pick, count] of Object.entries(counts)) {
      const pct = total > 0 ? (count / total * 100) : 0;
      odds[pick] = {
        count,
        pct:         `${pct.toFixed(1)}%`,
        impliedOdds: count > 0 ? `${(total / count).toFixed(2)}x` : '—',
      };
    }

    return { marketId, title: market.title, totalEntries: total, odds };
  }

  /**
   * Get a user's betting history across all markets.
   *
   * @param {string} [username] - Defaults to signed-in user
   * @returns {Promise<Array<{marketId, title, pick, status, outcome, won}>>}
   */
  async getUserBets(username) {
    const user = username || this._username;
    if (!user) throw new Error('Username required — sign in or pass username');

    const all = await this.listMarkets();
    const bets = [];

    for (const market of all) {
      try {
        const detail = await this.getMarket(market.id);
        const entry = (detail.entriesDetail || []).find(e => e.username === user);
        if (entry) {
          bets.push({
            marketId:  market.id,
            title:     market.title,
            pick:      entry.pick || entry.choice,
            entryFee:  market.entryFee,
            status:    market.status,
            outcome:   market.outcome,
            won:       market.outcome ? (entry.pick || entry.choice) === market.outcome : null,
            prizePool: market.prizePool,
          });
        }
      } catch { /* market detail may fail for deleted markets */ }
    }

    return bets;
  }


  // ═════════════════════════════════════════════════════════════════════════
  // DEALER — Admin operations (require DEALER_JWT)
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * Create a new BB market (dealer only).
   *
   * @param {Object} opts
   * @param {string}   opts.id           - Unique market ID
   * @param {string}   opts.title        - Display title
   * @param {number}   opts.entryFee     - Entry fee in BB (e.g. 1.0 = $0.10)
   * @param {string[]} [opts.options]    - Valid picks, e.g. ['yes', 'no']
   * @param {string}  [opts.gameType]    - e.g. 'over_under', 'binary_prop'
   * @param {number}  [opts.maxEntries]
   * @param {number}  [opts.freezeAt]    - Unix timestamp when entries close
   * @param {number}  [opts.resolveAfter]- Unix timestamp earliest resolution
   * @returns {Promise<Object>}
   */
  async createMarket(opts = {}) {
    if (!opts.id || !opts.title)           throw new Error('id and title required');
    if (!opts.entryFee || opts.entryFee <= 0) throw new Error('entryFee must be > 0');

    return this._post('/dealer/create', {
      id:               opts.id,
      title:            opts.title,
      currency:         'BB',
      entry_fee:        opts.entryFee,
      game_type:        opts.gameType      || 'binary_prop',
      outcome_options:  opts.options       || ['yes', 'no'],
      max_entries:      opts.maxEntries    || null,
      prize_structure:  opts.prizeStructure || [1.0],
      freeze_at:        opts.freezeAt      || Math.floor(Date.now() / 1000) + 86400,
      resolve_after:    opts.resolveAfter  || 0,
    }, this._requireDealerJwt());
  }

  /**
   * Fund a BB market (dealer only — triggers L1 reserve lock via gRPC init_contest_reserve).
   * Entries are blocked until the market is funded.
   * @param {string} marketId
   * @returns {Promise<Object>}
   */
  async fundMarket(marketId) {
    return this._post(`/dealer/${marketId}/fund`, {}, this._requireDealerJwt());
  }

  /**
   * Freeze a market — stops accepting new entries.
   * @param {string} marketId
   * @returns {Promise<Object>}
   */
  async freezeMarket(marketId) {
    return this._post(`/dealer/${marketId}/freeze`, {}, this._requireDealerJwt());
  }

  /**
   * Resolve a market with the winning outcome.
   * Triggers: L2 builds Merkle tree → submits root to L1 → caches proofs.
   *
   * @param {string} marketId
   * @param {string} outcome  - Winning pick (must match outcomeOptions)
   * @returns {Promise<Object>}
   */
  async resolveMarket(marketId, outcome) {
    if (!outcome) throw new Error('outcome is required');
    return this._post(`/dealer/${marketId}/resolve`, { outcome }, this._requireDealerJwt());
  }

  /**
   * Cancel a market — refunds all on-chain deposits via L1.
   * @param {string} marketId
   * @returns {Promise<Object>}
   */
  async cancelMarket(marketId) {
    return this._post(`/dealer/${marketId}/cancel`, {}, this._requireDealerJwt());
  }

  /**
   * Delete a market record (only valid before any entries).
   * @param {string} marketId
   * @returns {Promise<Object>}
   */
  async deleteMarket(marketId) {
    return this._delete(`/dealer/${marketId}`);
  }

  /**
   * Dealer-side entry bypass (no deposit_tx required — dealer assumes L1 handled).
   * Use sparingly: for testing or comping an entry.
   * @param {string}  marketId
   * @param {string}  username
   * @param {string}  pick
   * @param {string}  depositTxSig
   * @returns {Promise<Object>}
   */
  async dealerEnterMarket(marketId, username, pick, depositTxSig) {
    return this._post(`/dealer/${marketId}/enter`, {
      username,
      choice: { pick, deposit_tx: depositTxSig },
    }, this._requireDealerJwt());
  }

  /**
   * Get the dealer ledger / pool summary.
   * @returns {Promise<Object>}
   */
  async ledger() {
    return this._get('/dealer/ledger', this._requireDealerJwt());
  }


  // ═════════════════════════════════════════════════════════════════════════
  // SYSTEM
  // ═════════════════════════════════════════════════════════════════════════

  /**
   * L2 server health check.
   * @returns {Promise<{ok, service, version}>}
   */
  async health() {
    try {
      const data = await this._get('/health');
      return { ok: data.ok === true, service: data.service, version: data.version };
    } catch {
      return { ok: false, service: null, version: null };
    }
  }

  /**
   * L1 node health check.
   * @returns {Promise<{ok: boolean, escrowBalance: number}>}
   */
  async healthL1() {
    try {
      const s = await this.getEscrowStatus();
      return { ok: true, escrowBalance: s.escrowBalanceBB };
    } catch {
      return { ok: false, escrowBalance: 0 };
    }
  }

  /**
   * Check both L1 and L2 health.
   * @returns {Promise<{l1: {ok, escrowBalance}, l2: {ok, service, version}}>}
   */
  async healthAll() {
    const [l1, l2] = await Promise.all([this.healthL1(), this.health()]);
    return { l1, l2 };
  }


  // ═════════════════════════════════════════════════════════════════════════
  // FORMATTING — Static helpers
  // ═════════════════════════════════════════════════════════════════════════

  /** Format BB amount: 2.5 → "2.50 BB" */
  static formatBB(n) { return formatBB(n); }
  /** BB → USD string: 10 → "$1.00" */
  static bbToUsd(n)  { return bbToUsd(n); }
  /** BB → lamports: 1.0 → 100000 */
  static bbToLamports(n) { return bbToLamports(n); }
  /** Lamports → BB: 100000 → 1.0 */
  static lamportsToBB(n) { return lamportsToBB(n); }

  formatBB(n) { return formatBB(n); }
  bbToUsd(n)  { return bbToUsd(n); }

  /**
   * Build the escrow deposit signing message.
   * Sign this with your Ed25519 key before calling depositToEscrow() or placeBet().
   *
   * @param {string} walletAddress
   * @param {number} amount - BB amount
   * @param {number} timestamp - Unix seconds
   * @param {string} nonce - UUID v4
   * @returns {string} The message to sign
   */
  static buildDepositMessage(walletAddress, amount, timestamp, nonce) {
    return `ESCROW_DEPOSIT:${walletAddress}:${amount}:${timestamp}:${nonce}`;
  }

  /**
   * Build the escrow withdrawal signing message.
   * Sign this with your Ed25519 key before calling claimWinnings().
   *
   * @param {string} marketId
   * @param {string} walletAddress
   * @param {number} amount - BB amount
   * @param {number} timestamp - Unix seconds
   * @param {string} nonce - UUID v4
   * @returns {string} The message to sign
   */
  static buildWithdrawMessage(marketId, walletAddress, amount, timestamp, nonce) {
    return `ESCROW_WITHDRAW:${marketId}:${walletAddress}:${amount}:${timestamp}:${nonce}`;
  }

  /**
   * Status badge for UI rendering.
   * @param {string} status
   * @returns {{label, color}}
   */
  static statusBadge(status) {
    return {
      'Active':   { label: '🟢 OPEN',    color: '#22c55e' },
      'Frozen':   { label: '🔒 FROZEN',  color: '#f59e0b' },
      'Resolved': { label: '✅ SETTLED', color: '#3b82f6' },
      'Draft':    { label: '⏳ DRAFT',   color: '#94a3b8' },
    }[status] || { label: status, color: '#94a3b8' };
  }


  // ═════════════════════════════════════════════════════════════════════════
  // PRIVATE
  // ═════════════════════════════════════════════════════════════════════════

  /** Map raw server market list item → SDK shape */
  _mapMarket(m) {
    return {
      id:              m.id,
      title:           m.title,
      gameType:        m.game_type,
      currency:        'BB',
      entryFee:        m.entry_fee,
      entryFeeUsd:     bbToUsd(m.entry_fee),
      usdEntryFee:     m.usd_entry_fee,
      status:          m.status,
      funded:          m.funded,
      entryCount:      m.entries,
      maxEntries:      m.max_entries || null,
      prizePool:       m.prize_pool,
      usdPrizePool:    m.usd_prize_pool,
      freezeAt:        m.freeze_at,
      resolveAfter:    m.resolve_after,
      outcomeOptions:  m.outcome_options || [],
      outcome:         m.outcome || null,
      l1ReserveRef:    m.l1_reserve_ref || null,
      // Computed
      canEnter:        m.status === 'Active' && m.funded,
    };
  }

  /** Map raw server market detail (includes entries_detail + metadata) → SDK shape */
  _mapMarketDetail(m) {
    return {
      ...this._mapMarket(m),
      entriesDetail: m.entries_detail || [],
      metadata:      m.metadata || {},
    };
  }

  _requireUsername() {
    if (!this._username) throw new Error('Not signed in. Call signIn() first.');
    return this._username;
  }

  _requireToken() {
    if (!this._accessToken) throw new Error('Not signed in. Call signIn() first.');
    if (isJwtExpired(this._accessToken)) throw new Error('Token expired. Call signIn() again.');
    return this._accessToken;
  }

  _requireDealerJwt() {
    if (!this._dealerJwt) throw new Error('No dealer JWT. Pass dealerJwt in constructor.');
    return this._dealerJwt;
  }

  // ── L2 HTTP transport ──

  async _get(path, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const resp = await fetch(`${this._l2Url}${path}`, { headers });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || data.message || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  async _post(path, body, token = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const resp = await fetch(`${this._l2Url}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || data.message || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  async _delete(path) {
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this._requireDealerJwt()}`,
    };
    const resp = await fetch(`${this._l2Url}${path}`, { method: 'DELETE', headers });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || data.message || `HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  // ── L1 HTTP transport (fallback when no l1Sdk) ──

  async _l1Get(path) {
    const resp = await fetch(`${this._l1ApiUrl}${path}`, {
      headers: { 'Content-Type': 'application/json' },
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || data.message || `L1 HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }

  async _l1Post(path, body) {
    const resp = await fetch(`${this._l1ApiUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      const err = new Error(data.error || data.message || `L1 HTTP ${resp.status}`);
      err.status = resp.status;
      throw err;
    }
    return data;
  }
}


// ══════════════════════════════════════════════════════════════════════════
// EXPORTS
// ══════════════════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { BbMarketsSDK };
  module.exports.default = BbMarketsSDK;
}

if (typeof window !== 'undefined') {
  window.BbMarketsSDK = BbMarketsSDK;
}
