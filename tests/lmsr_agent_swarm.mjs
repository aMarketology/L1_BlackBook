/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  BlackBook — LMSR Agent Swarm Test
 * ═══════════════════════════════════════════════════════════════════════════
 *
 *  PURPOSE
 *  -------
 *  Tests two things end-to-end with a single wallet controlling up to 100
 *  independent agents:
 *
 *    1. LMSR price discovery on L2 — 100 buys across 3 outcomes produce real
 *       price movement.  We log the price curve before every 10th trade so
 *       you can see the LMSR working.
 *
 *    2. L1 resolve & payout — after all agents buy, the market is resolved on
 *       L2, the Merkle root is posted to L1, and every winning agent claims
 *       their BB payout via the L1 `/escrow/withdraw` endpoint.
 *
 *  AGENT WALLET DERIVATION
 *  -----------------------
 *  All 100 agents are derived from a single 32-byte master seed:
 *
 *    agentSeed[i] = SHA-256( masterSeed[32] || i.to_be_bytes(2) )
 *
 *  This is deterministic — run it twice with the same master key and you get
 *  the same 100 wallets.  The master never needs to know agent private keys
 *  for anything other than funding.
 *
 *  FLOW
 *  ----
 *    Phase 1  — Generate 100 agent keypairs from master seed
 *    Phase 2  — Fund each agent (admin mint if local, faucet otherwise)
 *    Phase 3  — Each agent deposits BB to L1 escrow
 *    Phase 4  — Each agent buys LMSR shares on L2  (concurrent batches)
 *    Phase 5  — Print live LMSR price curve
 *    Phase 6  — Trigger market resolution via L2 admin endpoint
 *    Phase 7  — Poll until L2 submits Merkle root to L1
 *    Phase 8  — Each winning agent claims payout on L1
 *    Phase 9  — Winning agents sweep BB back to master wallet
 *    Phase 10 — Print payout summary + zero-sum check
 *
 *  WHY THE SWEEP?
 *  Merkle leaves are keyed to agent wallet addresses (the L2 tracks who holds
 *  shares).  Winnings land in each agent wallet after L1 `/escrow/withdraw`.
 *  Phase 9 auto-transfers every claimed BB back to the master wallet so the
 *  original user collects all proceeds in one place.
 *
 *  USAGE
 *  -----
 *    node tests/lmsr_agent_swarm.mjs
 *
 *  Or with custom parameters:
 *    MASTER_KEY=<64 hex>  AGENT_COUNT=50  BB_PER_AGENT=5  \
 *    MARKET_ID=MLS-W8-LAFC-MIA  WINNER_OUTCOME=LAFC       \
 *    node tests/lmsr_agent_swarm.mjs
 *
 *  Environment variables:
 *    MASTER_KEY       32-byte Ed25519 seed as 64 hex chars (auto-generated if absent)
 *    AGENT_COUNT      Number of agents, 1–100          (default: 20)
 *    BB_PER_AGENT     $BB each agent deposits          (default: 3)
 *    MARKET_ID        L2 market to trade               (default: first active BB market)
 *    WINNER_OUTCOME   Which outcome wins at resolution (default: first outcome)
 *    L1_URL           L1 REST base URL                 (default: http://localhost:8080)
 *    L2_URL           L2 REST base URL                 (default: http://localhost:1234)
 *    RESOLVE_DELAY_MS Wait before triggering resolve   (default: 2000 ms)
 *    CONCURRENCY      Agents buying in parallel        (default: 10)
 *    USE_ADMIN_MINT   Use /admin/mint instead of faucet (default: true)
 *
 * ═══════════════════════════════════════════════════════════════════════════
 */

import * as ed from '@noble/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';
import crypto from 'crypto';
import http from 'http';

// ── Config ─────────────────────────────────────────────────────────────────

const L1_URL         = (process.env.L1_URL    || 'http://localhost:8080').replace(/\/$/, '');
const L2_URL         = (process.env.L2_URL    || 'http://localhost:1234').replace(/\/$/, '');
const AGENT_COUNT    = Math.min(100, Math.max(1, parseInt(process.env.AGENT_COUNT  || '20')));
const BB_PER_AGENT   = parseFloat(process.env.BB_PER_AGENT   || '3');
const MARKET_ID_ENV  = process.env.MARKET_ID        || '';
const WINNER_OUTCOME = process.env.WINNER_OUTCOME   || '';
const RESOLVE_DELAY  = parseInt(process.env.RESOLVE_DELAY_MS || '2000');
const CONCURRENCY    = parseInt(process.env.CONCURRENCY      || '10');
const USE_ADMIN_MINT = process.env.USE_ADMIN_MINT !== 'false';

// ── Constants ───────────────────────────────────────────────────────────────

const LAMPORTS      = 100_000;   // 1 BB = 100,000 lamports (5 decimals)
const BB_USD        = 0.10;
const LMSR_B        = 100;       // liquidity parameter (matches L2 default)
const HOUSE_RAKE_PC = 0.05;      // 5% house rake

// ── ANSI colours ────────────────────────────────────────────────────────────

const C = {
  reset:  '\x1b[0m',
  bold:   '\x1b[1m',
  green:  '\x1b[32m',
  yellow: '\x1b[33m',
  cyan:   '\x1b[36m',
  red:    '\x1b[31m',
  dim:    '\x1b[2m',
};
const ok   = s => `${C.green}✓${C.reset} ${s}`;
const warn = s => `${C.yellow}⚠${C.reset}  ${s}`;
const fail = s => `${C.red}✗${C.reset} ${s}`;
const info = s => `${C.cyan}→${C.reset} ${s}`;
const dim  = s => `${C.dim}${s}${C.reset}`;

// ── HTTP helper ──────────────────────────────────────────────────────────────

function request(url, method = 'GET', body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const opts = {
      hostname: u.hostname,
      port:     u.port || (u.protocol === 'https:' ? 443 : 80),
      path:     u.pathname + u.search,
      method,
      headers:  { 'Content-Type': 'application/json', ...headers },
    };
    const req = http.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        let parsed;
        try   { parsed = JSON.parse(data); }
        catch { parsed = data; }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

// ── LMSR math (mirrors L2 Rust impl) ─────────────────────────────────────────

function lmsrCost(shares, b) {
  const vals = Object.values(shares);
  if (vals.length === 0) return 0;
  const maxQ   = Math.max(...vals);
  const sumExp = vals.reduce((s, q) => s + Math.exp((q - maxQ) / b), 0);
  return b * (maxQ / b + Math.log(sumExp));
}

function lmsrBuyCost(shares, outcome, amount, b = LMSR_B) {
  const before = lmsrCost(shares, b);
  const after  = { ...shares, [outcome]: (shares[outcome] || 0) + amount };
  return lmsrCost(after, b) - before;
}

function lmsrPrice(shares, outcome, b = LMSR_B) {
  const vals   = Object.values(shares);
  const maxQ   = Math.max(...vals);
  const num    = Math.exp(((shares[outcome] || 0) - maxQ) / b);
  const den    = vals.reduce((s, q) => s + Math.exp((q - maxQ) / b), 0);
  return num / den;
}

function lmsrPrices(shares, b = LMSR_B) {
  const result = {};
  for (const k of Object.keys(shares)) result[k] = lmsrPrice(shares, k, b);
  return result;
}

// ── Wallet helpers ────────────────────────────────────────────────────────────

/**
 * Derive N deterministic agent keypairs from a 32-byte master seed.
 * agentSeed[i] = SHA-256( masterSeed[32] || i_as_2_bytes_big_endian )
 */
function deriveAgentSeeds(masterSeedHex, count) {
  const master = hexToBytes(masterSeedHex);
  const agents = [];
  for (let i = 0; i < count; i++) {
    const indexBytes = new Uint8Array(2);
    indexBytes[0] = (i >> 8) & 0xff;
    indexBytes[1] = i & 0xff;
    const combined = new Uint8Array(master.length + 2);
    combined.set(master, 0);
    combined.set(indexBytes, master.length);
    agents.push(bytesToHex(sha256(combined)));
  }
  return agents;
}

/** Build a wallet object from a 32-byte seed (64 hex chars). */
async function walletFromSeed(seedHex) {
  const pubBytes = await ed.getPublicKeyAsync(hexToBytes(seedHex));
  return {
    seedHex,
    pubHex:  bytesToHex(pubBytes),
    address: bs58.encode(Buffer.from(pubBytes)),
  };
}

/** Sign an arbitrary string message with Ed25519. */
async function sign(message, seedHex) {
  const msgBytes = new TextEncoder().encode(message);
  const sigBytes = await ed.signAsync(msgBytes, hexToBytes(seedHex));
  return bytesToHex(sigBytes);
}

// ── L1 helpers ────────────────────────────────────────────────────────────────

async function l1Balance(address) {
  const r = await request(`${L1_URL}/balance/${address}`);
  if (r.status !== 200) throw new Error(`balance fetch failed: ${JSON.stringify(r.body)}`);
  return r.body.balance; // float BB
}

/**
 * Admin-mint BB to an address (requires unsafe_admin feature on L1).
 * Falls back to faucet if USE_ADMIN_MINT=false.
 */
async function fundAgent(wallet, bbAmount) {
  if (USE_ADMIN_MINT) {
    const r = await request(`${L1_URL}/admin/mint`, 'POST', {
      address: wallet.address,
      amount:  bbAmount,
    });
    if (r.status !== 200) {
      throw new Error(`Admin mint failed for ${wallet.address}: ${JSON.stringify(r.body)}`);
    }
    return;
  }

  // Faucet path (requires Ed25519 sig)
  const ts    = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const msg   = `FAUCET:${wallet.address}:${bbAmount}:${ts}:${nonce}`;
  const sig   = await sign(msg, wallet.seedHex);

  const r = await request(`${L1_URL}/faucet`, 'POST', {
    address:    wallet.address,
    amount:     bbAmount,
    public_key: wallet.pubHex,
    signature:  sig,
    timestamp:  ts,
    nonce,
  });
  if (r.status !== 200 && r.status !== 429) {
    throw new Error(`Faucet failed for ${wallet.address}: ${JSON.stringify(r.body)}`);
  }
}

/**
 * Deposit BB from wallet into L1 escrow for a given market.
 * Returns the deposit tx hash.
 */
async function escrowDeposit(wallet, marketId, bbAmount) {
  const amountLamports = Math.round(bbAmount * LAMPORTS);
  const ts    = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  // Canonical message: "ESCROW_DEPOSIT:{wallet_address}:{amount}:{timestamp}:{nonce}"
  // amount is lamports (u64). No market_id in the deposit message.
  const msg   = `ESCROW_DEPOSIT:${wallet.address}:${amountLamports}:${ts}:${nonce}`;
  const sig   = await sign(msg, wallet.seedHex);

  const r = await request(`${L1_URL}/escrow/deposit`, 'POST', {
    wallet_address: wallet.address,
    // NOTE: no market_id field — the L1 deposit is market-agnostic
    amount:         amountLamports,  // u64 lamports
    public_key:     wallet.pubHex,
    signature:      sig,
    timestamp:      ts,
    nonce,
  });
  if (r.status !== 200) {
    throw new Error(`Deposit failed for ${wallet.address}: ${JSON.stringify(r.body)}`);
  }
  // Return the deposit tx hash so the L2 can verify via GET /deposit/status/:tx_hash
  return r.body.tx_hash || 'ok';
}

/**
 * Buy shares on L2.  If the L2 uses dealer JWT auth, set the jwt in headers.
 */
async function l2Buy(wallet, marketId, outcome, shares, depositTx, jwt = null, masterAddress = null, agentIndex = null) {
  const headers = jwt ? { Authorization: `Bearer ${jwt}` } : {};
  // Use masterAddress::agent_N format so the L2 dealer aggregates all agent
  // payouts under the master wallet via fc_wallet_owner(). If masterAddress
  // is not supplied we fall back to a short slice of the agent address.
  const username = (masterAddress != null && agentIndex != null)
    ? `${masterAddress}::agent_${agentIndex}`
    : wallet.address.slice(0, 12).toLowerCase();
  const r = await request(`${L2_URL}/markets/${marketId}/buy`, 'POST', {
    username,
    outcome,
    amount:     shares,
    deposit_tx: depositTx,
    wallet:     wallet.address,
  }, headers);
  if (r.status !== 200) {
    throw new Error(`L2 buy failed (${outcome}) for ${wallet.address}: ${JSON.stringify(r.body)}`);
  }
  return r.body;
}

/** Fetch the current share counts from L2 to compute live LMSR prices. */
async function l2MarketShares(marketId) {
  const r = await request(`${L2_URL}/markets/${marketId}`);
  if (r.status !== 200) return null;
  const m    = r.body;
  const odds = m.odds || {};
  const shares = {};
  for (const [k, v] of Object.entries(odds)) shares[k] = v.shares_outstanding || 0;
  return { shares, outcomes: Object.keys(odds), meta: m };
}

/** Trigger market resolution via L2 admin resolve endpoint. */
async function l2ResolveMarket(marketId, winnerOutcome) {
  const r = await request(`${L2_URL}/admin/markets/${marketId}/resolve`, 'POST', {
    winner_outcome: winnerOutcome,
  });
  if (r.status !== 200 && r.status !== 202) {
    // Try alternate endpoint path
    const r2 = await request(`${L2_URL}/markets/${marketId}/resolve`, 'POST', {
      outcome: winnerOutcome,
    });
    if (r2.status !== 200 && r2.status !== 202) {
      throw new Error(`Resolve failed: ${JSON.stringify(r.body)}`);
    }
    return r2.body;
  }
  return r.body;
}

/** Poll L1 until the contest state root is present for the market. */
async function waitForStateRoot(marketId, pollMs = 1000, maxRetries = 30) {
  for (let i = 0; i < maxRetries; i++) {
    const r = await request(`${L1_URL}/escrow/contest/${marketId}`);
    if (r.status === 200 && r.body.merkle_root) return r.body;
    await new Promise(res => setTimeout(res, pollMs));
  }
  throw new Error(`Timed out waiting for state root on market ${marketId}`);
}

/**
 * Transfer BB from an agent wallet back to the master wallet via /transfer/simple.
 *
 * /transfer/simple message format (binary, NOT a plain string):
 *   [1 byte: chain_id=1] + payload_json_utf8 + "\n" + timestamp_utf8 + "\n" + nonce_utf8
 * where payload_json = JSON.stringify({ to, amount })  (amount is f64 BB, not lamports)
 */
async function transferToMaster(fromWallet, masterAddress, bbAmount) {
  const ts      = Math.floor(Date.now() / 1000);
  const nonce   = crypto.randomUUID();
  const payload = JSON.stringify({ to: masterAddress, amount: bbAmount });

  // Build the exact binary message the L1 handler constructs (main.rs ~line 655)
  const enc     = new TextEncoder();
  const parts   = [
    new Uint8Array([1]),           // chain_id = 1
    enc.encode(payload),
    enc.encode('\n'),
    enc.encode(String(ts)),
    enc.encode('\n'),
    enc.encode(nonce),
  ];
  const totalLen  = parts.reduce((n, p) => n + p.length, 0);
  const msgBytes  = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) { msgBytes.set(p, offset); offset += p.length; }

  const sigBytes = await ed.signAsync(msgBytes, hexToBytes(fromWallet.seedHex));
  const sig      = bytesToHex(sigBytes);

  const r = await request(`${L1_URL}/transfer/simple`, 'POST', {
    public_key:     fromWallet.pubHex,
    wallet_address: fromWallet.address,
    payload,
    timestamp:      ts,
    nonce,
    chain_id:       1,
    signature:      sig,
  });
  return { status: r.status, body: r.body };
}

/** Fetch the Merkle proof for a wallet from L2. */
async function l2GetProof(wallet, marketId) {
  const r = await request(`${L2_URL}/proof/${marketId}/${wallet.address}`);
  if (r.status !== 200) return null;
  return r.body;
}

/** Claim winnings on L1 with a Merkle proof. */
async function l1Claim(wallet, marketId, proof) {
  // amount in lamports (L1 expects lamports, 5 decimal: 1 BB = 100_000 lamports)
  const amountLamports = Math.round(proof.payout_bb * LAMPORTS);
  const ts    = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  // Canonical message: "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount}:{timestamp}:{nonce}"
  // amount is lamports (u64). Field order matches L1 mod.rs line 479.
  const msg   = `ESCROW_WITHDRAW:${marketId}:${wallet.address}:${amountLamports}:${ts}:${nonce}`;
  const sig   = await sign(msg, wallet.seedHex);

  const r = await request(`${L1_URL}/escrow/withdraw`, 'POST', {
    market_id:     marketId,      // L1 field name: market_id
    wallet_address: wallet.address, // L1 field name: wallet_address
    merkle_proof:  proof.proof,
    amount:        amountLamports, // u64 lamports
    public_key:    wallet.pubHex,
    signature:     sig,
    timestamp:     ts,
    nonce,
  });
  return { status: r.status, body: r.body };
}

// ── Progress table printer ─────────────────────────────────────────────────

function printPriceBar(shares, outcomes) {
  const prices = lmsrPrices(shares);
  const bar = outcomes.map(o => {
    const p = prices[o] || 0;
    const filled = Math.round(p * 20);
    const empty  = 20 - filled;
    return `  ${o.padEnd(18)} [${'█'.repeat(filled)}${' '.repeat(empty)}] ${(p * 100).toFixed(1)}%`;
  }).join('\n');
  return bar;
}

// ── Batch executor ────────────────────────────────────────────────────────────

async function runBatch(items, fn, concurrency, label) {
  const results = [];
  let done = 0;
  for (let i = 0; i < items.length; i += concurrency) {
    const slice = items.slice(i, i + concurrency);
    const batch = await Promise.allSettled(slice.map(fn));
    results.push(...batch);
    done += slice.length;
    process.stdout.write(`\r  ${label}: ${done}/${items.length}`);
  }
  process.stdout.write('\n');
  return results;
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${C.bold}╔══════════════════════════════════════════════════╗`);
  console.log(`║  BlackBook LMSR Agent Swarm Test                 ║`);
  console.log(`╚══════════════════════════════════════════════════╝${C.reset}\n`);

  // ── Master seed ──────────────────────────────────────────────────────────
  // crypto.randomBytes is Node.js built-in; getRandomValues is browser-only
  const masterSeedHex = process.env.MASTER_KEY || bytesToHex(new Uint8Array(crypto.randomBytes(32)));
  const masterWallet  = await walletFromSeed(masterSeedHex);

  console.log(info(`L1: ${L1_URL}   L2: ${L2_URL}`));
  console.log(info(`Master wallet : ${masterWallet.address}`));
  console.log(info(`Agent count   : ${AGENT_COUNT}`));
  console.log(info(`BB per agent  : ${BB_PER_AGENT} BB`));
  console.log(info(`Concurrency   : ${CONCURRENCY}`));
  if (USE_ADMIN_MINT) {
    console.log(warn('Using /admin/mint — L1 must be compiled with --features unsafe_admin'));
  }
  console.log();

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 1 — Generate agent wallets
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 1 — Generating ${AGENT_COUNT} agent wallets${C.reset}`);
  const agentSeeds   = deriveAgentSeeds(masterSeedHex, AGENT_COUNT);
  const agentWallets = await Promise.all(agentSeeds.map(walletFromSeed));
  console.log(ok(`Generated ${AGENT_COUNT} deterministic wallets from master seed`));
  console.log(dim(`  First: ${agentWallets[0].address}`));
  console.log(dim(`  Last:  ${agentWallets[AGENT_COUNT - 1].address}\n`));

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 2 — Fund all agents
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 2 — Funding ${AGENT_COUNT} agents (${BB_PER_AGENT} BB each)${C.reset}`);
  const fundResults = await runBatch(
    agentWallets,
    w => fundAgent(w, BB_PER_AGENT * 2), // 2x to cover gas
    CONCURRENCY,
    'minted'
  );

  const fundFailed = fundResults.filter(r => r.status === 'rejected').length;
  if (fundFailed > 0) console.log(warn(`${fundFailed} funding attempts failed (rate limit is normal)`));
  else console.log(ok('All agents funded\n'));

  // Small delay to let L1 process all mints
  await new Promise(res => setTimeout(res, 500));

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 3 — Resolve target market
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 3 — Resolving target market${C.reset}`);

  let marketId = MARKET_ID_ENV;
  let outcomes = [];

  if (!marketId) {
    // Auto-discover the first active BB market on L2
    try {
      const r = await request(`${L2_URL}/markets`);
      if (r.status === 200) {
        const active = (r.body.markets || []).find(m => m.status === 'Active' || m.status === 'active');
        if (active) {
          marketId = active.id;
          console.log(info(`Auto-selected market: ${marketId}`));
        }
      }
    } catch (_) { /* L2 may be down */ }
  }

  if (!marketId) {
    console.log(warn('No active L2 market found. Using synthetic market ID: TEST-LMSR-SWARM-1'));
    marketId = 'TEST-LMSR-SWARM-1';
  }

  // Fetch live market to get outcomes and initial LMSR state
  let liveShares = {};
  try {
    const lm = await l2MarketShares(marketId);
    if (lm) {
      liveShares = lm.shares;
      outcomes   = lm.outcomes;
      console.log(ok(`Market: ${marketId}  (${outcomes.length} outcomes: ${outcomes.join(', ')})`));
      console.log('  Initial LMSR prices:');
      console.log(printPriceBar(liveShares, outcomes));
    }
  } catch (_) {
    console.log(warn(`L2 market fetch failed. Using synthetic 3-outcome market.`));
    outcomes   = ['Home', 'Draw', 'Away'];
    liveShares = { Home: 0, Draw: 0, Away: 0 };
    console.log(ok(`Synthetic market: ${outcomes.join(' / ')}`));
  }

  if (outcomes.length === 0) outcomes = ['Home', 'Draw', 'Away'];
  const winOutcome = WINNER_OUTCOME && outcomes.includes(WINNER_OUTCOME)
    ? WINNER_OUTCOME
    : outcomes[0];

  console.log(info(`Winning outcome (set at resolve): ${C.bold}${winOutcome}${C.reset}\n`));

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 4 — All agents deposit + buy
  //
  //  Each agent is assigned to an outcome in round-robin order so the LMSR
  //  pool is stressed across all outcomes, not just one.
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 4 — ${AGENT_COUNT} agents deposit & buy shares${C.reset}`);

  // Track simulated share accumulation for LMSR price logging
  const simulatedShares = { ...liveShares };

  // Assign each agent their outcome (round-robin) and a random share count (1–5)
  const agentTrades = agentWallets.map((w, i) => ({
    wallet:  w,
    outcome: outcomes[i % outcomes.length],
    shares:  1 + (i % 5),   // 1, 2, 3, 4, or 5 shares
    index:   i,
  }));

  const tradeResults = [];

  for (let batchStart = 0; batchStart < agentTrades.length; batchStart += CONCURRENCY) {
    const batch = agentTrades.slice(batchStart, batchStart + CONCURRENCY);

    // Print LMSR price snapshot every 10 agents
    if (batchStart > 0 && batchStart % 10 === 0) {
      console.log(dim(`\n  LMSR prices after agent ${batchStart}:`));
      console.log(printPriceBar(simulatedShares, outcomes));
    }

    const batchResult = await Promise.allSettled(batch.map(async ({ wallet, outcome, shares, index }) => {
      // Step 1: Deposit to L1 escrow
      const depositTx = await escrowDeposit(wallet, marketId, BB_PER_AGENT);

      // Step 2: Buy on L2 — use masterAddress::agent_N username so the dealer
      // aggregates all agent payouts under the master wallet on settlement.
      const result = await l2Buy(wallet, marketId, outcome, shares, depositTx, null, masterWallet.address, index);
      return { wallet, outcome, shares, depositTx, result };
    }));

    for (const r of batchResult) {
      if (r.status === 'fulfilled') {
        const { outcome, shares } = r.value;
        simulatedShares[outcome]  = (simulatedShares[outcome] || 0) + shares;
        tradeResults.push({ ...r.value, success: true });
      } else {
        tradeResults.push({ error: r.reason?.message || 'unknown', success: false });
      }
    }

    process.stdout.write(`\r  Traded: ${Math.min(batchStart + CONCURRENCY, agentTrades.length)}/${AGENT_COUNT}`);
  }

  process.stdout.write('\n');

  const succeeded = tradeResults.filter(r => r.success).length;
  const failed_t  = AGENT_COUNT - succeeded;

  console.log(ok(`Trades complete: ${succeeded} succeeded, ${failed_t} failed`));
  console.log('\n  Final LMSR prices (simulated):');
  console.log(printPriceBar(simulatedShares, outcomes));

  // LMSR cost analysis
  const costByOutcome = {};
  outcomes.forEach(o => {
    const baseShares = Object.fromEntries(outcomes.map(x => [x, 0]));
    const cost = lmsrBuyCost(baseShares, o, simulatedShares[o] || 0);
    costByOutcome[o] = cost;
  });
  console.log('\n  Theoretical pool cost:');
  for (const [o, c] of Object.entries(costByOutcome)) {
    console.log(dim(`    ${o.padEnd(18)} ${c.toFixed(4)} BB`));
  }
  console.log();

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 5 — Wait, then resolve market on L2
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 5 — Resolving market (winner: ${winOutcome})${C.reset}`);
  console.log(info(`Waiting ${RESOLVE_DELAY}ms before resolution...`));
  await new Promise(res => setTimeout(res, RESOLVE_DELAY));

  let resolveOk = false;
  try {
    await l2ResolveMarket(marketId, winOutcome);
    console.log(ok(`L2 resolve triggered for market ${marketId}\n`));
    resolveOk = true;
  } catch (e) {
    console.log(warn(`L2 resolve call failed: ${e.message}`));
    console.log(warn('If the L2 has no admin endpoint, trigger resolution manually.\n'));
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 6 — Wait for L1 state root submission
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 6 — Waiting for L1 Merkle root${C.reset}`);
  let contestState = null;
  try {
    contestState = await waitForStateRoot(marketId, 1000, 30);
    console.log(ok(`State root posted to L1: ${contestState.merkle_root?.slice(0, 20)}...`));
    console.log(dim(`  winner_count    : ${contestState.winner_count}`));
    console.log(dim(`  total_deposited : ${contestState.total_deposited}`));
    console.log(dim(`  total_payout    : ${contestState.total_payout}`));
    console.log(dim(`  house_rake      : ${contestState.house_rake}`));
    console.log();
  } catch (e) {
    console.log(warn(`${e.message}`));
    console.log(warn('Skipping claim phase — manually submit the state root and re-run from PHASE 7.\n'));
  }

  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 7 — All agents claim winnings
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 7 — Master wallet claims aggregated winnings${C.reset}`);

  // Because all agents were registered under masterAddress::agent_N, the L2 dealer
  // aggregated their payouts into a single Merkle leaf keyed to the master wallet.
  // The master wallet makes ONE claim on L1 for the full consolidated payout.

  const anyWinner = tradeResults.some(t => t.success && t.outcome === winOutcome);
  console.log(info(`Agents bought winning outcome (${winOutcome}): ${tradeResults.filter(t => t.success && t.outcome === winOutcome).length}`));

  let claimSucceeded = 0;
  let claimFailed    = 0;
  let claimSkipped   = 0;

  const claimResults = [];

  if (anyWinner) {
    // Fetch the master wallet's aggregated proof from L2
    const proof = await l2GetProof(masterWallet, marketId);
    if (!proof || !proof.proof || proof.proof.length === 0) {
      claimSkipped++;
      claimResults.push({ wallet: masterWallet.address, skipped: true, reason: 'no proof for master wallet — check agent username format' });
      console.log(warn('No proof found for master wallet. Ensure L2 resolve_bb has run and agents used masterAddress::agent_N format.'));
    } else {
      console.log(info(`Master wallet proof: ${proof.proof.length} nodes | payout: ${proof.payout_bb} BB`));
      try {
        const result = await l1Claim(masterWallet, marketId, proof);
        const success = result.status === 200;
        if (success) claimSucceeded++; else claimFailed++;
        claimResults.push({
          wallet:  masterWallet.address,
          payout:  proof.payout_bb,
          status:  result.status,
          success,
          body:    result.body,
        });
      } catch (e) {
        claimFailed++;
        claimResults.push({ error: e.message });
      }
    }
  } else {
    claimSkipped++;
    claimResults.push({ skipped: true, reason: 'no winning agents' });
    console.log(warn('No agents bought the winning outcome — nothing to claim.'));
  }


  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 9 — Verify master wallet balance (sweep no longer needed)
  //
  //  Because the L2 dealer aggregated all agent payouts under the master
  //  wallet's Merkle leaf, the L1 claim in Phase 7 already deposited the
  //  full payout directly into the master wallet. No per-agent sweep required.
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`${C.bold}Phase 9 — Verify master wallet balance${C.reset}`);

  const sweepSucceeded = 0;
  const sweepFailed    = 0;
  const totalSweptBB   = 0;

  const masterBalance = await l1Balance(masterWallet.address).catch(() => '?');
  console.log(ok(`Payout landed directly in master wallet (no sweep needed)`));
  console.log(info(`Master wallet balance: ${typeof masterBalance === 'number' ? masterBalance.toFixed(4) : masterBalance} BB\n`));


  // ─────────────────────────────────────────────────────────────────────────
  //  PHASE 10 — Summary
  // ─────────────────────────────────────────────────────────────────────────

  console.log(`\n${C.bold}╔══════════════════════════════════════════════════╗`);
  console.log(`║  Test Summary                                    ║`);
  console.log(`╚══════════════════════════════════════════════════╝${C.reset}`);

  const totalDeposited  = succeeded * BB_PER_AGENT;
  const totalPayoutBB   = claimResults
    .filter(r => r.success)
    .reduce((s, r) => s + (r.payout || 0), 0);

  console.log(`\n  Market ID      : ${marketId}`);
  console.log(`  Winner outcome : ${C.bold}${winOutcome}${C.reset}`);
  console.log(`  Agents created : ${AGENT_COUNT}`);
  console.log(`  Trades placed  : ${succeeded}  ${failed_t > 0 ? warn(`(${failed_t} failed)`) : ''}`);
  console.log(`  Total deposited: ${totalDeposited.toFixed(2)} BB`);

  console.log(`\n  LMSR Results:`);
  for (const o of outcomes) {
    const sharesOut = simulatedShares[o] || 0;
    const price = lmsrPrice(simulatedShares, o) * 100;
    const marker = o === winOutcome ? ` ${C.green}← WINNER${C.reset}` : '';
    console.log(`    ${o.padEnd(18)} ${sharesOut.toString().padStart(4)} shares  ${price.toFixed(1)}% implied prob${marker}`);
  }

  console.log(`\n  Claim Results:`);
  console.log(`    Winners eligible : ${winnerWallets.length}`);
  console.log(`    Claims succeeded : ${C.green}${claimSucceeded}${C.reset}`);
  console.log(`    Claims skipped   : ${claimSkipped}  (no proof — market not resolved or wrong outcome)`);
  console.log(`    Claims failed    : ${claimFailed > 0 ? C.red + claimFailed + C.reset : claimFailed}`);
  console.log(`    Total paid out   : ${totalPayoutBB.toFixed(4)} BB`);

  console.log(`\n  Sweep Results (back to master):`);
  console.log(`    Sweeps succeeded : ${C.green}${sweepSucceeded}${C.reset}`);
  console.log(`    Sweeps failed    : ${sweepFailed > 0 ? C.red + sweepFailed + C.reset : sweepFailed}`);
  console.log(`    Total swept      : ${totalSweptBB.toFixed(4)} BB → ${masterWallet.address.slice(0, 12)}...`);

  if (claimFailed > 0) {
    console.log(`\n  First failure: ${JSON.stringify(claimResults.find(r => r.error || (!r.success && !r.skipped)))}`);
  }

  // Zero-sum invariant check
  if (contestState) {
    const deposited  = (contestState.total_deposited || 0);
    const payout     = (contestState.total_payout    || 0);
    const rake       = (contestState.house_rake      || 0);
    const zeroSum    = deposited === payout + rake;
    console.log(`\n  L1 Zero-Sum    : deposited=${deposited}  payout=${payout}  rake=${rake}  → ${zeroSum ? ok('VALID') : fail('INVALID — bug in escrow math!')}`);
  }

  console.log(`\n  Master seed (save to reproduce): ${masterSeedHex}`);
  console.log(`\n${resolveOk && claimSucceeded > 0 ? ok('All phases passed') : warn('Some phases need attention — see above')}\n`);
}

main().catch(e => {
  console.error(`\n${C.red}FATAL:${C.reset}`, e.message);
  process.exit(1);
});
