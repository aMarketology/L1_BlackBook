import express from 'express';
import { ed25519 as ed } from '@noble/curves/ed25519';
import { hexToBytes } from '@noble/hashes/utils';
import {
  getBalance,
  buildMerkleTree,
  getLatestBatchId,
  getLock,
  consumeLock,
  upsertLock,
  consumeLockLocal,
} from '@bb/shared';
import type { SequencerConfig, DatabaseType, BbEntry } from '@bb/shared';
import { registerLock } from './lockIngest.js';
import {
  launchCoin,
  buyCoin,
  sellCoin,
  getCoin,
  getAllCoins,
  getHolding,
  getAllBalances,
  recordNonce,
  MAX_TAX_BPS,
  MIN_INITIAL_LIQUIDITY_BB,
  LAMPORTS_PER_BB,
  COIN_UNIT,
} from './coins.js';
import type { CurveType } from './coins.js';

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

function freshTimestamp(timestamp: number): boolean {
  const now = Math.floor(Date.now() / 1000);
  return Math.abs(now - timestamp) <= 60;
}

// ─── Server factory ───────────────────────────────────────────────────────────

export function createServer(config: SequencerConfig, db: DatabaseType) {
  const app = express();
  app.use(express.json());

  // ── POST /register-lock ─────────────────────────────────────────────────
  // Trader on-ramp: convert an L1 lock_id into a tradable off-chain $BB balance.
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
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // ── POST /launch-coin ─────────────────────────────────────────────────────
  // Launch a new Creator Coin. Consumed by sdk/TokenFactory.ts.
  //
  // Body: { creator_wallet, name, symbol, description|null, tax_rate_bps,
  //         tax_destination, initial_liquidity_bb, curve_type,
  //         bancor_weight_ppm|null, public_key, signature, timestamp, nonce,
  //         lock_id }
  // Message: "L5_LAUNCH:{creator_wallet}:{symbol}:{tax_rate_bps}:{initial_liquidity_bb}:{timestamp}:{nonce}"
  app.post('/launch-coin', async (req, res) => {
    const b = req.body as Record<string, unknown>;
    const creator_wallet      = b.creator_wallet as string | undefined;
    const name                = b.name as string | undefined;
    const symbolRaw           = b.symbol as string | undefined;
    const description         = (b.description as string | null | undefined) ?? null;
    const tax_rate_bps        = b.tax_rate_bps as number | undefined;
    const tax_destination     = b.tax_destination as string | undefined;
    const initial_liquidity_bb = b.initial_liquidity_bb as number | undefined;
    const curve_type          = b.curve_type as CurveType | undefined;
    const bancor_weight_ppm   = (b.bancor_weight_ppm as number | null | undefined) ?? null;
    const public_key          = b.public_key as string | undefined;
    const signature           = b.signature as string | undefined;
    const timestamp           = b.timestamp as number | undefined;
    const nonce               = b.nonce as string | undefined;
    const lock_id             = b.lock_id as string | undefined;

    // ── Presence ────────────────────────────────────────────────────────────
    if (!creator_wallet || !name || !symbolRaw || tax_rate_bps === undefined ||
        !tax_destination || initial_liquidity_bb === undefined || !curve_type ||
        !public_key || !signature || timestamp === undefined || !nonce || !lock_id) {
      res.status(400).json({ error: 'Missing required field(s) in launch-coin request' });
      return;
    }

    const symbol = symbolRaw.trim().toUpperCase();

    // ── Guardrails (mirror the L1 / SDK rules) ───────────────────────────────
    if (symbol.length < 2 || symbol.length > 10 || !/^[A-Z0-9]+$/.test(symbol)) {
      res.status(400).json({ error: 'symbol must be 2–10 uppercase alphanumeric chars' });
      return;
    }
    if (name.trim().length === 0 || name.length > 64) {
      res.status(400).json({ error: 'name is required and must be ≤ 64 chars' });
      return;
    }
    if (!Number.isInteger(tax_rate_bps) || tax_rate_bps < 0 || tax_rate_bps > MAX_TAX_BPS) {
      res.status(400).json({ error: `tax_rate_bps must be an integer in [0, ${MAX_TAX_BPS}] (honeypot prevention)` });
      return;
    }
    if (!Number.isInteger(initial_liquidity_bb) || BigInt(initial_liquidity_bb) < MIN_INITIAL_LIQUIDITY_BB) {
      res.status(400).json({ error: `initial_liquidity_bb must be an integer ≥ ${MIN_INITIAL_LIQUIDITY_BB} lamports` });
      return;
    }
    if (curve_type !== 'CONSTANT_PRODUCT' && curve_type !== 'BANCOR_VAMM') {
      res.status(400).json({ error: 'curve_type must be CONSTANT_PRODUCT or BANCOR_VAMM' });
      return;
    }
    if (curve_type === 'BANCOR_VAMM') {
      if (bancor_weight_ppm === null || !Number.isInteger(bancor_weight_ppm) ||
          bancor_weight_ppm < 10_000 || bancor_weight_ppm > 1_000_000) {
        res.status(400).json({ error: 'bancor_weight_ppm must be an integer in [10_000, 1_000_000] for BANCOR_VAMM' });
        return;
      }
    }
    if (description && description.length > 280) {
      res.status(400).json({ error: 'description must be ≤ 280 chars' });
      return;
    }

    // ── Freshness + identity + signature ─────────────────────────────────────
    if (!freshTimestamp(timestamp)) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }
    if (public_key !== creator_wallet) {
      res.status(400).json({ error: 'public_key must equal creator_wallet' });
      return;
    }
    const message = `L5_LAUNCH:${creator_wallet}:${symbol}:${tax_rate_bps}:${initial_liquidity_bb}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    if (getCoin(db, symbol)) {
      res.status(409).json({ error: `Coin ${symbol} already exists` });
      return;
    }

    // ── Verify the L1 lock backs the declared liquidity, then consume it ─────
    let l1Lock;
    try {
      l1Lock = await getLock(config, lock_id);
    } catch (err) {
      res.status(400).json({ error: `Lock lookup failed: ${err instanceof Error ? err.message : String(err)}` });
      return;
    }
    if (l1Lock.rollup_id !== 'L5') {
      res.status(400).json({ error: `Lock ${lock_id} belongs to rollup ${l1Lock.rollup_id}, not L5` });
      return;
    }
    if (l1Lock.creator_address !== creator_wallet) {
      res.status(400).json({ error: 'Lock owner does not match creator_wallet' });
      return;
    }
    if (l1Lock.consumed) {
      res.status(409).json({ error: `Lock ${lock_id} is already consumed` });
      return;
    }
    if (l1Lock.bb_lamports !== initial_liquidity_bb) {
      res.status(400).json({ error: `Lock amount ${l1Lock.bb_lamports} != initial_liquidity_bb ${initial_liquidity_bb}` });
      return;
    }

    try {
      await consumeLock(config, lock_id);
    } catch (err) {
      res.status(502).json({ error: `Failed to consume lock on L1: ${err instanceof Error ? err.message : String(err)}` });
      return;
    }

    // ── Atomic local commit: nonce + lock record + coin launch ───────────────
    let result;
    try {
      const launchTxn = db.transaction(() => {
        if (!recordNonce(db, nonce)) throw new Error('nonce already used');
        upsertLock(db, lock_id, 'L5', l1Lock.creator_address, l1Lock.bb_lamports, l1Lock.token_symbol_hint);
        consumeLockLocal(db, lock_id);
        return launchCoin(db, {
          symbol,
          name: name.trim(),
          description,
          creatorWallet: creator_wallet,
          taxRateBps: tax_rate_bps,
          taxDestination: tax_destination.trim(),
          initialLiquidityLamports: BigInt(initial_liquidity_bb),
          curveType: curve_type,
          bancorWeightPpm: bancor_weight_ppm,
          lockId: lock_id,
        });
      });
      result = launchTxn();
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
      return;
    }

    const launchedAt = Math.floor(Date.now() / 1000);
    res.status(201).json({
      success: true,
      symbol: result.symbol,
      name: name.trim(),
      creator_wallet,
      total_supply: result.totalSupply.toString(),
      creator_share: result.creatorShare.toString(),
      pool_share: result.poolShare.toString(),
      tax_rate_bps,
      tax_destination: tax_destination.trim(),
      curve_type,
      bancor_weight_ppm,
      initial_liquidity_bb_lamports: initial_liquidity_bb,
      initial_liquidity_bb: initial_liquidity_bb / Number(LAMPORTS_PER_BB),
      initial_price_bb_per_coin: result.initialPriceBbPerCoin,
      launched_at: launchedAt,
      message: `Creator Coin ${result.symbol} launched on L5 (fair launch — 100% of supply in the bonding curve)`,
    });
  });

  // ── GET /coins ──────────────────────────────────────────────────────────
  app.get('/coins', (_req, res) => {
    res.json(getAllCoins(db));
  });

  // ── GET /coins/:symbol ────────────────────────────────────────────────────
  app.get('/coins/:symbol', (req, res) => {
    const coin = getCoin(db, req.params.symbol.toUpperCase());
    if (!coin) { res.status(404).json({ error: 'Coin not found' }); return; }
    res.json(coin);
  });

  // ── GET /coins/:symbol/holders/:address ──────────────────────────────────
  app.get('/coins/:symbol/holders/:address', (req, res) => {
    const symbol = req.params.symbol.toUpperCase();
    const amount = getHolding(db, symbol, req.params.address);
    res.json({
      symbol,
      address: req.params.address,
      amount: amount.toString(),
      coins: Number(amount) / Number(COIN_UNIT),
    });
  });

  // ── POST /coins/:symbol/buy ─────────────────────────────────────────────
  // Buy coins with off-chain $BB along the constant-product curve.
  // Body:    { wallet_address, bb_in_lamports, public_key, signature, timestamp, nonce }
  // Message: "L5_BUY:{symbol}:{wallet_address}:{bb_in_lamports}:{timestamp}:{nonce}"
  app.post('/coins/:symbol/buy', (req, res) => {
    const symbol = req.params.symbol.toUpperCase();
    const { wallet_address, bb_in_lamports, public_key, signature, timestamp, nonce } =
      req.body as {
        wallet_address?: string; bb_in_lamports?: number; public_key?: string;
        signature?: string; timestamp?: number; nonce?: string;
      };

    if (!wallet_address || bb_in_lamports === undefined || !public_key || !signature || timestamp === undefined || !nonce) {
      res.status(400).json({ error: 'wallet_address, bb_in_lamports, public_key, signature, timestamp, nonce are all required' });
      return;
    }
    if (!Number.isInteger(bb_in_lamports) || bb_in_lamports <= 0) {
      res.status(400).json({ error: 'bb_in_lamports must be a positive integer' });
      return;
    }
    if (!freshTimestamp(timestamp)) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }
    if (public_key !== wallet_address) {
      res.status(400).json({ error: 'public_key must equal wallet_address' });
      return;
    }
    const message = `L5_BUY:${symbol}:${wallet_address}:${bb_in_lamports}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    try {
      const result = buyCoin(db, symbol, wallet_address, BigInt(bb_in_lamports), nonce);
      res.json({
        ok: true,
        symbol: result.symbol,
        wallet_address: result.wallet,
        bb_spent_lamports: result.bbAmount.toString(),
        coins_received: result.coinAmount.toString(),
        tax_coins: result.taxAmount.toString(),
        reserve_bb: result.reserveBb.toString(),
        reserve_coin: result.reserveCoin.toString(),
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // ── POST /coins/:symbol/sell ────────────────────────────────────────────
  // Sell coins back for off-chain $BB along the constant-product curve.
  // Body:    { wallet_address, coin_in, public_key, signature, timestamp, nonce }
  // Message: "L5_SELL:{symbol}:{wallet_address}:{coin_in}:{timestamp}:{nonce}"
  app.post('/coins/:symbol/sell', (req, res) => {
    const symbol = req.params.symbol.toUpperCase();
    const { wallet_address, coin_in, public_key, signature, timestamp, nonce } =
      req.body as {
        wallet_address?: string; coin_in?: number; public_key?: string;
        signature?: string; timestamp?: number; nonce?: string;
      };

    if (!wallet_address || coin_in === undefined || !public_key || !signature || timestamp === undefined || !nonce) {
      res.status(400).json({ error: 'wallet_address, coin_in, public_key, signature, timestamp, nonce are all required' });
      return;
    }
    if (!Number.isInteger(coin_in) || coin_in <= 0) {
      res.status(400).json({ error: 'coin_in must be a positive integer' });
      return;
    }
    if (!freshTimestamp(timestamp)) {
      res.status(400).json({ error: 'timestamp outside ±60 s window' });
      return;
    }
    if (public_key !== wallet_address) {
      res.status(400).json({ error: 'public_key must equal wallet_address' });
      return;
    }
    const message = `L5_SELL:${symbol}:${wallet_address}:${coin_in}:${timestamp}:${nonce}`;
    if (!verifyEd25519(message, signature, public_key)) {
      res.status(401).json({ error: 'Invalid signature' });
      return;
    }

    try {
      const result = sellCoin(db, symbol, wallet_address, BigInt(coin_in), nonce);
      res.json({
        ok: true,
        symbol: result.symbol,
        wallet_address: result.wallet,
        coins_sold: result.coinAmount.toString(),
        bb_received_lamports: result.bbAmount.toString(),
        tax_bb_lamports: result.taxAmount.toString(),
        reserve_bb: result.reserveBb.toString(),
        reserve_coin: result.reserveCoin.toString(),
      });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
    }
  });

  // ── GET /balances/:address ────────────────────────────────────────────────
  app.get('/balances/:address', (req, res) => {
    const lamports = getBalance(db, 'L5', req.params.address, 'BB');
    res.json({
      address: req.params.address,
      bb_lamports: lamports.toString(),
      bb: Number(lamports) / Number(LAMPORTS_PER_BB),
    });
  });

  // ── GET /proof/:address ─────────────────────────────────────────────────
  // Exit-ready Merkle inclusion proof for `address` against the current $BB
  // balance set. Direction (sibling_is_right) is all-false because the L1
  // verifier sorts (min,max) internally.
  app.get('/proof/:address', (req, res) => {
    const address = req.params.address;
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

    const { root, proofs } = buildMerkleTree('L5', entries);
    const siblings = proofs[idx];
    const batchId = getLatestBatchId(db, 'L5');
    if (batchId === 0) {
      res.status(409).json({ error: 'No batch sealed yet — wait for a PoH seal' });
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

  return app;
}
