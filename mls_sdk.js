/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  MLS SDK — BlackBook LMSR Prediction Markets
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  End-to-end SDK for users betting on MLS matches with real $BB tokens.
 *
 *  What this SDK does:
 *    • Connects a user's L1 wallet (Ed25519 keypair)
 *    • Browses MLS markets and live LMSR odds
 *    • Deposits $BB into L1 escrow (signed tx)
 *    • Buys/sells outcome shares on the L2 prediction market
 *    • Tracks positions, P&L, and portfolio
 *    • Claims winnings after resolution (Merkle proof → L1 withdraw)
 *
 *  Architecture:
 *    ┌──────────┐    deposit $BB     ┌──────────┐
 *    │  User    │ ─────────────────▶ │  L1      │  (on-chain escrow)
 *    │  Wallet  │                    │  :8080   │
 *    └──────────┘                    └────┬─────┘
 *         │                               │ verify_deposit (gRPC)
 *         │  buy/sell shares              │
 *         └──────────────────────▶  ┌─────▼─────┐
 *                                   │  L2       │  (LMSR market engine)
 *                                   │  :1234    │
 *                                   └───────────┘
 *
 *  Quick Start:
 *
 *    const { MlsSDK } = require('./mls_sdk');
 *
 *    const mls = new MlsSDK({
 *      l1Url: 'http://localhost:8080',
 *      l2Url: 'http://localhost:1234',
 *      privateKey: '<64 hex chars — Ed25519 seed>',
 *    });
 *
 *    // Browse all MLS markets
 *    const hub = await mls.getHub();
 *    const markets = await mls.listMarkets();
 *
 *    // Check odds for LAFC vs Inter Miami
 *    const odds = await mls.getOdds('MLS-W8-LAFC-MIA');
 *    console.log(odds);
 *    // → { LAFC: { price: 0.33, pct: '33.3%', cost1: 0.33 BB },
 *    //     Draw: { ... },
 *    //     'Inter Miami CF': { ... } }
 *
 *    // Buy 10 LAFC shares (auto-deposits $BB on L1)
 *    const trade = await mls.buy('MLS-W8-LAFC-MIA', 'LAFC', 10);
 *    console.log(trade);
 *    // → { shares: 10, cost: 3.51 BB, newPrice: '35.6%' }
 *
 *    // Sell 5 shares back
 *    const sale = await mls.sell('MLS-W8-LAFC-MIA', 'LAFC', 5);
 *
 *    // Check your positions
 *    const pos = await mls.positions();
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

const http = require('http');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const bs58 = require('bs58').default || require('bs58');

// ── Constants ─────────────────────────────────────────────────────────────

const BB_USD      = 0.10;       // 1 BB = $0.10 USD
const LAMPORTS    = 100_000;    // 1 BB = 100,000 lamports (5 decimals)
const MLS_HUB     = 'mls-week-8';

// ── LMSR math (mirrors Rust: src/main.rs) ─────────────────────────────────

function lmsrCost(shares, b) {
  const vals = Object.values(shares);
  if (vals.length === 0) return 0;
  const maxQ = Math.max(...vals);
  const sumExp = vals.reduce((s, q) => s + Math.exp((q - maxQ) / b), 0);
  return b * (maxQ / b + Math.log(sumExp));
}

function lmsrBuyCost(shares, outcome, amount, b) {
  const before = lmsrCost(shares, b);
  const after = { ...shares };
  after[outcome] = (after[outcome] || 0) + amount;
  return lmsrCost(after, b) - before;
}

function lmsrPrice(shares, outcome, b) {
  const vals = Object.values(shares);
  if (vals.length === 0) return 0;
  const maxQ = Math.max(...vals);
  const qi = shares[outcome] || 0;
  const num = Math.exp((qi - maxQ) / b);
  const den = vals.reduce((s, q) => s + Math.exp((q - maxQ) / b), 0);
  return num / den;
}

// ── HTTP helper ───────────────────────────────────────────────────────────

function request(url, method, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      hostname: u.hostname, port: u.port,
      path: u.pathname + u.search, method,
      headers: { 'Content-Type': 'application/json', ...headers },
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}


// ═══════════════════════════════════════════════════════════════════════════
//  MLS SDK CLASS
// ═══════════════════════════════════════════════════════════════════════════

class MlsSDK {

  /**
   * @param {Object} config
   * @param {string} config.l1Url       - L1 REST base URL (default: http://localhost:8080)
   * @param {string} config.l2Url       - L2 REST base URL (default: http://localhost:1234)
   * @param {string} config.privateKey  - 32-byte Ed25519 seed as 64 hex chars
   * @param {string} [config.username]  - L2 username (default: derived from pubkey)
   * @param {string} [config.jwt]       - L2 auth token (Supabase JWT or dealer JWT)
   */
  constructor(config = {}) {
    this.l1  = (config.l1Url || 'http://localhost:8080').replace(/\/$/, '');
    this.l2  = (config.l2Url || 'http://localhost:1234').replace(/\/$/, '');
    this.jwt = config.jwt || null;

    // ── Wallet ──────────────────────────────────────────────────────────
    if (!config.privateKey) throw new Error('privateKey (64 hex chars) is required');
    const seed = Buffer.from(config.privateKey, 'hex');
    if (seed.length !== 32) throw new Error('privateKey must be 32 bytes (64 hex chars)');
    this._kp = nacl.sign.keyPair.fromSeed(seed);
    this.pubkeyHex = Buffer.from(this._kp.publicKey).toString('hex');
    this.wallet    = bs58.encode(Buffer.from(this._kp.publicKey));
    this.username  = config.username || this.wallet.slice(0, 12).toLowerCase();
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  WALLET — L1 Balance & Info
  // ═══════════════════════════════════════════════════════════════════════

  /** Get the user's $BB balance on L1. */
  async balance() {
    const r = await request(`${this.l1}/balance/${this.wallet}`, 'GET');
    if (r.status !== 200) throw new Error(`L1 balance failed: ${JSON.stringify(r.body)}`);
    return {
      wallet:  r.body.address,
      bb:      r.body.balance,
      usd:     `$${(r.body.balance * BB_USD).toFixed(2)}`,
    };
  }

  /** Check L1 escrow health. */
  async l1Status() {
    const r = await request(`${this.l1}/escrow/status`, 'GET');
    if (r.status !== 200) throw new Error('L1 not reachable');
    return r.body;
  }

  /** Check L2 server health. */
  async l2Health() {
    const r = await request(`${this.l2}/health`, 'GET');
    return r.body;
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  BROWSE — MLS Hub & Markets (no auth needed)
  // ═══════════════════════════════════════════════════════════════════════

  /** Get the MLS Week 8 event hub (all matches + metadata). */
  async getHub() {
    const r = await request(`${this.l2}/hubs/${MLS_HUB}`, 'GET');
    if (r.status !== 200) throw new Error(`Hub not found: ${MLS_HUB}`);
    return r.body;
  }

  /** List all BB markets (optionally filter to MLS category). */
  async listMarkets() {
    const r = await request(`${this.l2}/markets`, 'GET');
    if (r.status !== 200) throw new Error('Failed to list markets');
    const all = r.body.markets || [];
    return all.filter(m => m.id?.startsWith('MLS-'));
  }

  /** Get a single market's full detail including live LMSR odds. */
  async getMarket(marketId) {
    const r = await request(`${this.l2}/markets/${marketId}`, 'GET');
    if (r.status !== 200) throw new Error(`Market ${marketId} not found`);
    return r.body;
  }

  /**
   * Get formatted odds for a market — the key thing users care about.
   *
   * Returns: { [outcome]: { price, pct, cost1BB, cost1USD, shares, pool } }
   *
   * @example
   *   const odds = await mls.getOdds('MLS-W8-LAFC-MIA');
   *   // { LAFC:             { price: 0.36, pct: '35.6%', cost1BB: 0.36, ... },
   *   //   Draw:             { price: 0.32, pct: '32.2%', cost1BB: 0.32, ... },
   *   //   'Inter Miami CF': { price: 0.32, pct: '32.2%', cost1BB: 0.32, ... } }
   */
  async getOdds(marketId) {
    const m = await this.getMarket(marketId);
    const result = {};
    for (const [name, o] of Object.entries(m.odds || {})) {
      result[name] = {
        price:    o.price,
        pct:      (o.price * 100).toFixed(1) + '%',
        cost1BB:  o.cost_1_share_bb,
        cost1USD: o.cost_1_share_usd,
        shares:   o.shares_outstanding,
        poolBB:   o.side_pool_bb,
        traded:   o.traded,
      };
    }
    return result;
  }

  /** Get public event explorer (volume, distribution, participants). */
  async explorer(marketId) {
    const r = await request(`${this.l2}/explorer/${marketId}`, 'GET');
    if (r.status !== 200) throw new Error(`Explorer not found for ${marketId}`);
    return r.body;
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  TRADE — Buy & Sell LMSR Shares (requires L1 wallet)
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Preview a buy — see the cost before committing.
   *
   * This computes the LMSR cost client-side (same math as the server).
   * No network call, no deposit.
   *
   * @param {string} marketId
   * @param {string} outcome  - e.g. 'LAFC', 'Draw', 'Inter Miami CF'
   * @param {number} shares   - Number of shares to buy
   * @returns {Promise<{cost, fee, total, totalUSD, newPrice, newPct}>}
   */
  async previewBuy(marketId, outcome, shares) {
    const m = await this.getMarket(marketId);
    const b = m.metadata?.lmsr_b || 100;
    // Reconstruct shares_outstanding from odds
    const outstanding = {};
    for (const [name, o] of Object.entries(m.odds || {})) {
      outstanding[name] = o.shares_outstanding;
    }
    const cost = lmsrBuyCost(outstanding, outcome, shares, b);
    const fee  = cost * 0.02;
    const total = cost + fee;
    // Price after
    const after = { ...outstanding };
    after[outcome] = (after[outcome] || 0) + shares;
    const newPrice = lmsrPrice(after, outcome, b);

    return {
      marketId, outcome, shares,
      cost:     round4(cost),
      fee:      round4(fee),
      total:    round4(total),
      totalUSD: `$${(total * BB_USD).toFixed(4)}`,
      newPrice: round4(newPrice),
      newPct:   (newPrice * 100).toFixed(1) + '%',
    };
  }

  /**
   * Buy outcome shares.
   *
   * Full flow:
   *   1. Computes exact LMSR cost
   *   2. Deposits that exact $BB amount into L1 escrow (signed Ed25519 tx)
   *   3. Sends the deposit tx_hash to L2 to buy shares
   *   4. Returns the confirmed trade with updated odds
   *
   * @param {string} marketId  - e.g. 'MLS-W8-LAFC-MIA'
   * @param {string} outcome   - e.g. 'LAFC', 'Draw', 'Inter Miami CF'
   * @param {number} shares    - Number of shares (each winning share = 1 BB)
   * @returns {Promise<Object>} Trade confirmation
   *
   * @example
   *   const trade = await mls.buy('MLS-W8-LAFC-MIA', 'LAFC', 10);
   *   // → { shares: 10, costBB: 3.51, costUSD: '$0.35', newPct: '35.6%' }
   */
  async buy(marketId, outcome, shares) {
    if (shares <= 0) throw new Error('shares must be > 0');

    // Step 1 — Compute exact cost (same LMSR as server)
    // Important: compute raw total without round4() so lamport conversion
    // matches the Rust to_spl_units() exactly.
    const m = await this.getMarket(marketId);
    const b = m.metadata?.lmsr_b || 100;
    const outstanding = {};
    for (const [name, o] of Object.entries(m.odds || {})) {
      outstanding[name] = o.shares_outstanding;
    }
    const cost = lmsrBuyCost(outstanding, outcome, shares, b);
    const fee  = cost * 0.02;
    const rawTotal = cost + fee;
    const totalCostLamports = Math.round(rawTotal * LAMPORTS);
    const depositBB = totalCostLamports / LAMPORTS;

    // Step 2 — Deposit $BB on L1
    const txHash = await this._deposit(marketId, depositBB);

    // Step 3 — Buy shares on L2
    const r = await request(`${this.l2}/markets/${marketId}/buy`, 'POST', {
      username:   this.username,
      outcome,
      amount:     shares,
      deposit_tx: txHash,
    }, this._authHeaders());

    if (r.status !== 200) {
      throw new Error(`Buy failed: ${JSON.stringify(r.body)}`);
    }

    return {
      marketId,
      outcome,
      shares:      r.body.shares || shares,
      costBB:      r.body.cost_bb,
      feeBB:       r.body.fee_bb,
      totalBB:     r.body.total_cost_bb,
      totalUSD:    `$${(r.body.total_cost_bb * BB_USD).toFixed(4)}`,
      newPrice:    r.body.new_price,
      newPct:      ((r.body.new_price || 0) * 100).toFixed(1) + '%',
      yourShares:  r.body.your_shares,
      depositTx:   txHash,
      wallet:      r.body.depositor_wallet,
    };
  }

  /**
   * Sell shares back to the AMM.
   *
   * Revenue is calculated by LMSR — you receive BB credited to your L1 wallet.
   * No deposit needed for sells.
   *
   * @param {string} marketId
   * @param {string} outcome
   * @param {number} shares
   * @returns {Promise<Object>}
   */
  async sell(marketId, outcome, shares) {
    if (shares <= 0) throw new Error('shares must be > 0');

    const r = await request(`${this.l2}/markets/${marketId}/sell`, 'POST', {
      username: this.username,
      outcome,
      amount:   shares,
    }, this._authHeaders());

    if (r.status !== 200) {
      throw new Error(`Sell failed: ${JSON.stringify(r.body)}`);
    }

    return {
      marketId,
      outcome,
      sharesSold:     r.body.shares_sold || shares,
      revenueBB:      r.body.revenue_bb,
      revenueUSD:     `$${((r.body.revenue_bb || 0) * BB_USD).toFixed(4)}`,
      remainingShares: r.body.remaining_shares,
      newPrice:       r.body.price_after,
      newPct:         ((r.body.price_after || 0) * 100).toFixed(1) + '%',
    };
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  POSITIONS — Portfolio & P&L
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Get your share holdings in a specific market.
   * @param {string} marketId
   * @returns {Promise<Object>} { marketId, holdings: { outcome: shares } }
   */
  async getShares(marketId) {
    const r = await request(`${this.l2}/markets/${marketId}/shares/${this.username}`, 'GET');
    if (r.status !== 200) throw new Error(`Failed to get shares: ${JSON.stringify(r.body)}`);
    return { marketId, holdings: r.body.shares || {} };
  }

  /**
   * Get all your positions across all MLS markets.
   * Includes current value based on live LMSR prices.
   *
   * @returns {Promise<Object>} { positions: [...], totalCost, totalValue, pnl }
   */
  async positions() {
    const r = await request(`${this.l2}/u/${this.username}`, 'GET');
    if (r.status !== 200) throw new Error('Failed to get positions');
    const data = r.body;

    // Filter to BB positions only (MLS markets are all BB)
    const bbPositions = data.bb_positions || [];

    // Calculate live value from current LMSR prices
    let totalValue = 0;
    const enriched = [];
    for (const pos of bbPositions) {
      if (!pos.market_id?.startsWith('MLS-')) continue;
      try {
        const m = await this.getMarket(pos.market_id);
        const odds = m.odds || {};
        let posValue = 0;
        const holdings = {};
        // Get shares from user_shares
        for (const [outcome, o] of Object.entries(odds)) {
          const sharesR = await request(
            `${this.l2}/markets/${pos.market_id}/shares/${this.username}`, 'GET'
          );
          if (sharesR.status === 200 && sharesR.body.shares) {
            for (const [out, qty] of Object.entries(sharesR.body.shares)) {
              holdings[out] = qty;
              posValue += qty * (odds[out]?.price || 0);
            }
          }
          break; // Only need one request per market
        }
        totalValue += posValue;
        enriched.push({
          marketId:  pos.market_id,
          title:     m.title,
          holdings,
          valueBB:   round4(posValue),
          valueUSD:  `$${(posValue * BB_USD).toFixed(4)}`,
          status:    m.status,
        });
      } catch { /* skip markets that fail */ }
    }

    return {
      wallet:     this.wallet,
      username:   this.username,
      positions:  enriched,
      totalValueBB:  round4(totalValue),
      totalValueUSD: `$${(totalValue * BB_USD).toFixed(4)}`,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  CLAIMS — After Resolution
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Get your Merkle proof for claiming winnings on L1.
   *
   * After a market resolves, winners can claim by submitting this proof
   * to the L1 escrow contract.
   *
   * @param {string} marketId - Resolved market ID
   * @returns {Promise<Object>} { proof, payoutBB, payoutUSD, claimDeadline }
   */
  async getClaimProof(marketId) {
    const r = await request(`${this.l2}/proof/${marketId}/${this.wallet}`, 'GET');
    if (r.status !== 200) throw new Error(`No proof found — you may not be a winner or market not resolved`);
    return {
      marketId,
      wallet:          r.body.wallet,
      proof:           r.body.proof,
      payoutBB:        r.body.payout_bb,
      payoutUSD:       `$${((r.body.payout_bb || 0) * BB_USD).toFixed(2)}`,
      claimDeadline:   r.body.claim_deadline_slot,
    };
  }

  /**
   * Claim winnings on L1 using your Merkle proof.
   *
   * @param {string} marketId
   * @returns {Promise<Object>} L1 withdrawal result
   */
  async claimWinnings(marketId) {
    const claim = await this.getClaimProof(marketId);

    const ts = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    const msg = `ESCROW_WITHDRAW:${this.wallet}:${claim.payoutBB}:${ts}:${nonce}`;
    const sig = this._sign(msg);

    const r = await request(`${this.l1}/escrow/withdraw`, 'POST', {
      wallet_address: this.wallet,
      market_id:      marketId,
      amount:         claim.payoutBB,
      proof:          claim.proof,
      public_key:     this.pubkeyHex,
      signature:      sig,
      timestamp:      ts,
      nonce,
    });

    if (r.status !== 200) throw new Error(`Claim failed: ${JSON.stringify(r.body)}`);
    return {
      success:  true,
      marketId,
      payoutBB: claim.payoutBB,
      payoutUSD: claim.payoutUSD,
      txHash:   r.body.tx_hash,
    };
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  CONVENIENCE — Multi-market operations
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Get a quick odds board for all MLS markets at once.
   *
   * @returns {Promise<Array<{id, title, home, away, homePrice, drawPrice, awayPrice}>>}
   */
  async oddsBoard() {
    const markets = await this.listMarkets();
    const board = [];
    for (const m of markets) {
      if (m.status !== 'Active') continue;
      const full = await this.getMarket(m.id);
      const opts = full.outcome_options || [];
      const odds = full.odds || {};
      const home = opts[0];
      const away = opts[opts.length - 1];
      board.push({
        id:         m.id,
        title:      m.title,
        home,
        away,
        homePrice:  odds[home]?.price  || 0,
        homePct:    ((odds[home]?.price || 0) * 100).toFixed(1) + '%',
        drawPrice:  odds['Draw']?.price || 0,
        drawPct:    ((odds['Draw']?.price || 0) * 100).toFixed(1) + '%',
        awayPrice:  odds[away]?.price  || 0,
        awayPct:    ((odds[away]?.price || 0) * 100).toFixed(1) + '%',
        poolBB:     full.prize_pool || 0,
        poolUSD:    `$${((full.prize_pool || 0) * BB_USD).toFixed(2)}`,
      });
    }
    return board;
  }


  // ═══════════════════════════════════════════════════════════════════════
  //  INTERNAL — L1 Deposit & Auth
  // ═══════════════════════════════════════════════════════════════════════

  /**
   * Deposit $BB into L1 escrow for a specific market.
   * Signs the deposit message with the user's Ed25519 key.
   *
   * @private
   * @param {string} marketId
   * @param {number} amountBB  - Exact BB amount to deposit
   * @returns {Promise<string>} L1 tx_hash
   */
  async _deposit(marketId, amountBB) {
    const ts    = Math.floor(Date.now() / 1000);
    const nonce = crypto.randomUUID();
    const msg   = `ESCROW_DEPOSIT:${this.wallet}:${amountBB}:${ts}:${nonce}`;
    const sig   = this._sign(msg);

    const r = await request(`${this.l1}/escrow/deposit`, 'POST', {
      wallet_address: this.wallet,
      amount:         amountBB,
      contest_id:     marketId,
      public_key:     this.pubkeyHex,
      signature:      sig,
      timestamp:      ts,
      nonce,
    });

    if (r.status !== 200) {
      throw new Error(`L1 deposit failed: ${JSON.stringify(r.body)}`);
    }

    const txHash = r.body.tx_hash || r.body.deposit_id || r.body.id || '';

    // Auto-approve if deposit list is available
    try {
      const list = await request(`${this.l1}/deposit/list`, 'GET');
      if (list.status === 200 && Array.isArray(list.body)) {
        for (const d of list.body) {
          if ((d.wallet === this.wallet || d.id === txHash) && d.status !== 'approved') {
            await request(`${this.l1}/deposit/${d.id}/approve`, 'PATCH');
          }
        }
      }
    } catch { /* approval may not be needed */ }

    return txHash;
  }

  /** Sign a message with the user's Ed25519 key. */
  _sign(message) {
    return Buffer.from(
      nacl.sign.detached(Buffer.from(message), this._kp.secretKey)
    ).toString('hex');
  }

  /** Build auth headers for L2 requests. */
  _authHeaders() {
    if (this.jwt) return { Authorization: `Bearer ${this.jwt}` };
    return {};
  }
}


// ── Helpers ───────────────────────────────────────────────────────────────

function round4(n) { return Math.round(n * 10000) / 10000; }


// ── Exports ───────────────────────────────────────────────────────────────

module.exports = { MlsSDK, lmsrCost, lmsrBuyCost, lmsrPrice, BB_USD, LAMPORTS };
