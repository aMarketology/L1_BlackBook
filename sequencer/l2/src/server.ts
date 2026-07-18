import express from 'express';
import { ed25519 as ed } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import { getBalance, buildMerkleTree, getLatestBatchId, submitOraclePendingRoot, pushPayoutsToL1 } from '@bb/shared';
import type { SequencerConfig, DatabaseType, BbEntry } from '@bb/shared';
import { registerLock } from './lockIngest.js';
import {
  createMarket,
  getMarket,
  getAllMarkets,
  lockMarket,
  placeBet,
  resolveMarket,
  getAllBalances,
} from './markets.js';
import { sealAndSubmit } from './batchSealer.js';
import type { MarketStatus, BetSide, MarketOutcome } from './markets.js';

// ─── Ed25519 verification ─────────────────────────────────────────────────────

function verifyEd25519(message: string, signatureHex: string, publicKeyHex: string): boolean {
  try {
    const sig = hexToBytes(signatureHex);
    const pk = hexToBytes(publicKeyHex);
    const msg = new TextEncoder().encode(message);
    return ed.verify(sig, msg, pk);
  } catch {
    return false;
  }
}

// ─── Server factory ───────────────────────────────────────────────────────────

export function createServer(config: SequencerConfig, db: DatabaseType) {
  const app = express();
  app.use(express.json());

  // ── GET /health ──────────────────────────────────────────────────────────
  // Used by Docker health check and load balancers.
  app.get('/health', (_req, res) => {
    const batchId = getLatestBatchId(db, 'L2');
    res.json({ status: 'ok', rollup: 'L2', latest_batch_id: batchId });
  });

  // ── POST /register-lock ─────────────────────────────────────────────────
  // User submits a lock_id from L1. Sequencer verifies → consumes on L1 →
  // credits off-chain balance. After this the user bets at L2 speed.
  app.post('/register-lock', async (req, res) => {
    const { lock_id } = req.body as { lock_id?: string };
    if (!lock_id || typeof lock_id !== 'string') {
      res.status(400).json({ error: 'lock_id (string) is required' });
      return;
    }
    try {
      const result = await registerLock(config, db, lock_id);
      res.json(result);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // ── GET /balances/:address ────────────────────────────────────────────────
  app.get('/balances/:address', (req, res) => {
    const lamports = getBalance(db, 'L2', req.params.address, 'BB');
    res.json({
      address: req.params.address,
      bb_lamports: lamports.toString(),
      bb: Number(lamports) / 100_000,
    });
  });

  // ── GET /proof/:address ─────────────────────────────────────────────────
  // Returns a Merkle inclusion proof for `address` against the latest SEALED
  // batch. A fresh seal is triggered first so the proof is always valid against
  // the root L1 has stored. Pass the returned batch_id + proof to
  // POST /rollup/L2/exit on L1.
  app.get('/proof/:address', async (req, res) => {
    const address = req.params.address;

    // Seal current state first so proof matches the root L1 has stored.
    await sealAndSubmit(config, db, 0).catch(() => { /* ignore if nothing to seal */ });

    const balances = getAllBalances(db);
    if (balances.length === 0) {
      res.status(404).json({ error: 'No balances to prove against' });
      return;
    }

    const entries: BbEntry[] = balances.map(b => ({
      type: 'BB',
      address: b.address,
      lamports: b.lamports,
    }));

    const idx = entries.findIndex(e => e.address === address);
    if (idx === -1) {
      res.status(404).json({ error: `No balance found for ${address}` });
      return;
    }

    const { root, proofs } = buildMerkleTree('L2', entries);
    const siblings = proofs[idx];
    const batchId = getLatestBatchId(db, 'L2');
    if (batchId === 0) {
      res.status(409).json({ error: 'No batch sealed yet — place a bet and try again' });
      return;
    }

    res.json({
      address,
      batch_id: batchId,
      balance_lamports: entries[idx].lamports.toString(),
      merkle_root: root,
      proof_siblings: siblings,
      sibling_is_right: siblings.map(() => false),
    });
  });

  // ── POST /markets ─────────────────────────────────────────────────────────
  // Create a new prediction market.
  // TODO: restrict to oracle / admin key in production.
  app.post('/markets', (req, res) => {
    const { market_id, question } = req.body as { market_id?: string; question?: string };
    if (!market_id || !question) {
      res.status(400).json({ error: 'market_id and question are required' });
      return;
    }
    try {
      createMarket(db, market_id, question);
      res.status(201).json({ market_id, status: 'OPEN' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(409).json({ error: msg });
    }
  });

  // ── GET /markets ──────────────────────────────────────────────────────────
  app.get('/markets', (req, res) => {
    const status = req.query.status as MarketStatus | undefined;
    const markets = getAllMarkets(db, status);
    res.json(markets);
  });

  // ── GET /markets/:id ──────────────────────────────────────────────────────
  app.get('/markets/:id', (req, res) => {
    const market = getMarket(db, req.params.id);
    if (!market) { res.status(404).json({ error: 'Market not found' }); return; }
    res.json(market);
  });

  // ── POST /markets/:id/lock ────────────────────────────────────────────────
  // Freeze betting (OPEN → LOCKED). Oracle / admin only.
  app.post('/markets/:id/lock', (req, res) => {
    try {
      lockMarket(db, req.params.id);
      res.json({ market_id: req.params.id, status: 'LOCKED' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // ── POST /markets/:id/bet ─────────────────────────────────────────────────
  // Place an off-chain bet. Signed by the bettor's Ed25519 wallet key.
  //
  // Body:   { wallet_address, side, amount_lamports, public_key,
  //           signature, timestamp, nonce }
  // Message: "L2_BET:{market_id}:{wallet_address}:{side}:{amount_lamports}:{timestamp}:{nonce}"
  app.post('/markets/:id/bet', (req, res) => {
    const {
      wallet_address, side, amount_lamports,
      public_key, signature, timestamp, nonce,
    } = req.body as {
      wallet_address?: string;
      side?: string;
      amount_lamports?: number;
      public_key?: string;
      signature?: string;
      timestamp?: number;
      nonce?: string;
    };

    if (!wallet_address || !side || !amount_lamports || !public_key || !signature || !timestamp || !nonce) {
      res.status(400).json({ error: 'wallet_address, side, amount_lamports, public_key, signature, timestamp, nonce are all required' });
      return;
    }
    if (side !== 'YES' && side !== 'NO') {
      res.status(400).json({ error: 'side must be YES or NO' });
      return;
    }
    if (!Number.isInteger(amount_lamports) || amount_lamports <= 0) {
      res.status(400).json({ error: 'amount_lamports must be a positive integer' });
      return;
    }

    // Freshness
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 60) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }

    // Signature
    const message = `L2_BET:${req.params.id}:${wallet_address}:${side}:${amount_lamports}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    try {
      placeBet(db, req.params.id, wallet_address, side as BetSide, BigInt(amount_lamports));
      res.json({
        ok: true,
        market_id: req.params.id,
        wallet_address,
        side,
        amount_lamports,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // ── POST /markets/:id/resolve ─────────────────────────────────────────────
  // Resolve a market and immediately seal a Merkle batch to L1.
  // Oracle / admin only. Authenticated by the sequencer's Ed25519 key.
  //
  // Body: { outcome: 'YES' | 'NO', public_key, signature, timestamp, nonce }
  // Message: "L2_RESOLVE:{market_id}:{outcome}:{timestamp}:{nonce}"
  app.post('/markets/:id/resolve', async (req, res) => {
    const { outcome, public_key, signature, timestamp, nonce } = req.body as {
      outcome?: string;
      public_key?: string;
      signature?: string;
      timestamp?: number;
      nonce?: string;
    };
    if (outcome !== 'YES' && outcome !== 'NO') {
      res.status(400).json({ error: 'outcome must be YES or NO' });
      return;
    }

    // ── Sequencer-key authentication ──────────────────────────────────────
    // Only the authorized sequencer may call /resolve.
    if (!public_key || !signature || !timestamp || !nonce) {
      res.status(400).json({ error: 'public_key, signature, timestamp, nonce are required' });
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - timestamp) > 60) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }
    if (public_key !== config.keypair.publicKeyHex) {
      res.status(403).json({ error: 'Caller is not the authorized sequencer' });
      return;
    }
    const resolveMsg = `L2_RESOLVE:${req.params.id}:${outcome}:${timestamp}:${nonce}`;
    if (!verifyEd25519(resolveMsg, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    try {
      const payouts = resolveMarket(db, req.params.id, outcome as MarketOutcome, 0);
      // Immediately anchor the updated balances on L1 (Rollup Hub submit_root).
      const sealResult = await sealAndSubmit(config, db, 0);

      if (sealResult) {
        // Record the batch sealing details on the resolved market
        db.prepare(`
          UPDATE l2_markets
          SET batch_id = ?, merkle_root = ?
          WHERE market_id = ?
        `).run(sealResult.batchId, sealResult.merkleRoot, req.params.id);
      }

      // ── Push winnings to L1 wallets ────────────────────────────────────
      // Build Merkle tree from the sealed snapshot and extract per-winner
      // proofs, then call POST /escrow/push_payouts so BB tokens land in
      // each winner's native L1 wallet immediately — no manual claim needed.
      if (sealResult && payouts.length > 0) {
        try {
          const { getAllBalances } = await import('./markets.js');
          const balances = getAllBalances(db);
          const entries: BbEntry[] = balances.map(b => ({
            type: 'BB' as const,
            address: b.address,
            lamports: b.lamports,
          }));
          const { proofs } = buildMerkleTree(config.rollupId ?? 'L2', entries);

          // Map each winner payout to its proof in the tree.
          // Skip the dealer fee entry ('dealer_reserve' is not a real L1 wallet).
          const payoutPushes = payouts
            .filter(p => p.wallet_address !== 'dealer_reserve' && !p.wallet_address.startsWith('dealer'))
            .map(p => {
              const idx = entries.findIndex(e => e.address === p.wallet_address);
              return idx >= 0
                ? { wallet: p.wallet_address, amountBb: p.payout_lamports, proof: proofs[idx] }
                : null;
            })
            .filter((x): x is { wallet: string; amountBb: bigint; proof: string[] } => x !== null);

          if (payoutPushes.length > 0) {
            pushPayoutsToL1(config, req.params.id, sealResult.merkleRoot, payoutPushes)
              .then(() => console.log(`[L2] ✅ Pushed ${payoutPushes.length} payout(s) to L1 for ${req.params.id}`))
              .catch((err: unknown) => {
                const msg = err instanceof Error ? err.message : String(err);
                console.warn(`[L2] ⚠️  push_payouts failed for ${req.params.id}: ${msg}`);
              });
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          console.warn(`[L2] ⚠️  Could not build payout proofs for ${req.params.id}: ${msg}`);
        }
      }

      // Submit to Oracle dispute window (non-blocking — failure is logged but
      // does not roll back the market resolution or the Rollup Hub anchor).
      if (sealResult) {
        submitOraclePendingRoot(
          config,
          req.params.id,
          outcome as 'YES' | 'NO',
          sealResult.merkleRoot,
          sealResult.batchId,
        ).catch((err: unknown) => {
          const msg = err instanceof Error ? err.message : String(err);
          console.warn(`[Oracle] submit-pending-root failed for market ${req.params.id}: ${msg}`);
        });
      }

      res.json({
        market_id: req.params.id,
        outcome,
        payout_count: payouts.length,
        batch: sealResult ?? null,
        oracle_dispute_window_opened: sealResult !== null,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(400).json({ error: msg });
    }
  });

  // ── GET /da/:market_id ───────────────────────────────────────────────────
  // Returns the full DA receipt with market details, status, outcome, and list of winners with pro-rata payouts.
  app.get('/da/:market_id', (req, res) => {
    try {
      const market = getMarket(db, req.params.market_id);
      if (!market) {
        res.status(404).json({ error: `Market ${req.params.market_id} not found` });
        return;
      }

      if (market.status !== 'RESOLVED') {
        res.json({
          market_id: market.market_id,
          question: market.question,
          status: market.status,
          outcome: null,
          total_yes_pool: market.total_yes_pool.toString(),
          total_no_pool: market.total_no_pool.toString(),
          winners: [],
          note: "Market is not resolved — no winners or DA receipt available yet"
        });
        return;
      }

      const outcome = market.outcome!;
      const totalPool = BigInt(market.total_yes_pool) + BigInt(market.total_no_pool);
      const winningPool = outcome === 'YES' ? BigInt(market.total_yes_pool) : BigInt(market.total_no_pool);
      const losingSide = outcome === 'YES' ? 'NO' : 'YES';

      const dealerFeeBps = Number(process.env.DEALER_FEE_BPS ?? '100');
      const dealerFee = totalPool * BigInt(dealerFeeBps) / 10_000n;
      const distributedPool = totalPool - dealerFee;

      const winners: { wallet_address: string; payout_lamports: string }[] = [];

      if (winningPool === 0n) {
        // Refund losers
        const losers = db.prepare(`
          SELECT wallet_address, amount_lamports FROM l2_positions
          WHERE market_id = ? AND bet_side = ?
        `).all(market.market_id, losingSide) as { wallet_address: string; amount_lamports: number }[];

        for (const pos of losers) {
          winners.push({
            wallet_address: pos.wallet_address,
            payout_lamports: pos.amount_lamports.toString(),
          });
        }
      } else {
        const dbWinners = db.prepare(`
          SELECT wallet_address, amount_lamports FROM l2_positions
          WHERE market_id = ? AND bet_side = ?
        `).all(market.market_id, outcome) as { wallet_address: string; amount_lamports: number }[];

        for (const pos of dbWinners) {
          const payout = (BigInt(pos.amount_lamports) * distributedPool) / winningPool;
          winners.push({
            wallet_address: pos.wallet_address,
            payout_lamports: payout.toString(),
          });
        }
      }

      res.json({
        market_id: market.market_id,
        question: market.question,
        status: market.status,
        outcome,
        total_yes_pool: market.total_yes_pool.toString(),
        total_no_pool: market.total_no_pool.toString(),
        batch_id: market.batch_id ?? null,
        merkle_root: market.merkle_root ?? null,
        winners,
        note: "Full DA receipt (winner list + proofs) is archived. Use GET /da/:market_id/claim/:address to generate individual Merkle claim tickets for L1."
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  // ── GET /da/:market_id/claim/:address ─────────────────────────────────────
  // Returns a per-winner Merkle claim ticket that can be directly submitted to POST /da/claim on L1.
  app.get('/da/:market_id/claim/:address', (req, res) => {
    try {
      const { market_id, address } = req.params;
      const market = getMarket(db, market_id);
      if (!market) {
        res.status(404).json({ error: `Market ${market_id} not found` });
        return;
      }

      if (market.status !== 'RESOLVED') {
        res.status(400).json({ error: `Market ${market_id} is in status ${market.status} — only resolved markets have claimable states` });
        return;
      }

      const batchId = market.batch_id;
      if (!batchId) {
        res.status(409).json({ error: `Market ${market_id} is resolved but its state batch ID was not recorded` });
        return;
      }

      // Load the batch to retrieve the balances snapshot
      const batch = db.prepare(`
        SELECT balances_snapshot FROM batches
        WHERE rollup_id = 'L2' AND batch_id = ?
      `).get(batchId) as { balances_snapshot: string | null } | undefined;

      if (!batch || !batch.balances_snapshot) {
        res.status(404).json({ error: `Could not load balances snapshot for batch #${batchId}` });
        return;
      }

      const balances = JSON.parse(batch.balances_snapshot) as { address: string; lamports: string }[];
      const entries: BbEntry[] = balances.map(b => ({
        type: 'BB',
        address: b.address,
        lamports: BigInt(b.lamports),
      }));

      const idx = entries.findIndex(e => e.address === address);
      if (idx === -1) {
        res.status(404).json({ error: `No balance found for address ${address} in batch #${batchId} representing resolved market ${market_id}` });
        return;
      }

      const { root, proofs } = buildMerkleTree('L2', entries);
      const siblings = proofs[idx];

      res.json({
        rollup_id: 'L2',
        market_id,
        wallet_address: address,
        balance_lamports: entries[idx].lamports.toString(),
        proof_siblings: siblings,
        sibling_is_right: siblings.map(() => false),
        merkle_root: root,
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      res.status(500).json({ error: msg });
    }
  });

  return app;
}
