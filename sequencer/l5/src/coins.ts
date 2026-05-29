import { getBalance, creditBalance } from '@bb/shared';
import type { DatabaseType } from '@bb/shared';

// ─── Constants (must match the TokenFactory SDK + L1 guardrails) ───────────────

/** Maximum allowed transfer tax in basis points (1 000 bps = 10 %). */
export const MAX_TAX_BPS = 1_000;

/** Basis-point denominator. */
export const BPS_DENOM = 10_000n;

/** Minimum $BB lamports required to seed pool liquidity (1 BB = 100 000 lamports). */
export const MIN_INITIAL_LIQUIDITY_BB = 100_000n;

/** $BB lamports per whole BB (5 decimals). */
export const LAMPORTS_PER_BB = 100_000n;

/** Creator Coin decimals. */
export const COIN_DECIMALS = 6;

/** Creator Coin base units per whole coin (6 decimals). */
export const COIN_UNIT = 1_000_000n;

/** Fixed total supply for every Creator Coin (1 quadrillion base units). */
export const TOTAL_SUPPLY = 1_000_000_000_000_000n;

// ─── Types ─────────────────────────────────────────────────────────────────────

export type CurveType = 'CONSTANT_PRODUCT' | 'BANCOR_VAMM';

export interface CoinRow {
  symbol: string;
  name: string;
  description: string | null;
  creator_wallet: string;
  total_supply: number;
  tax_rate_bps: number;
  tax_destination: string;
  curve_type: CurveType;
  bancor_weight_ppm: number | null;
  reserve_bb: number;
  reserve_coin: number;
  lock_id: string;
  launched_at: number;
}

export interface LaunchParams {
  symbol: string;
  name: string;
  description: string | null;
  creatorWallet: string;
  taxRateBps: number;
  taxDestination: string;
  initialLiquidityLamports: bigint;
  curveType: CurveType;
  bancorWeightPpm: number | null;
  lockId: string;
}

export interface LaunchResult {
  symbol: string;
  totalSupply: bigint;
  creatorShare: bigint;
  poolShare: bigint;
  reserveBb: bigint;
  reserveCoin: bigint;
  initialPriceBbPerCoin: number;
}

export interface TradeResult {
  symbol: string;
  wallet: string;
  /** Coin base units received (buy) or spent (sell). */
  coinAmount: bigint;
  /** $BB lamports spent (buy) or received (sell). */
  bbAmount: bigint;
  /** Tax skimmed from the output (coin base units on buy, $BB lamports on sell). */
  taxAmount: bigint;
  reserveBb: bigint;
  reserveCoin: bigint;
}

// ─── Replay protection ─────────────────────────────────────────────────────────

/**
 * Atomically record a nonce. Returns true if the nonce was fresh (inserted),
 * false if it was already used (replay). Must be called inside the same
 * transaction as the action it guards.
 */
export function recordNonce(db: DatabaseType, nonce: string): boolean {
  const result = db.prepare(
    `INSERT OR IGNORE INTO l5_nonces (nonce) VALUES (?)`,
  ).run(nonce);
  return Number(result.changes) > 0;
}

// ─── Coin reads ──────────────────────────────────────────────────────────────

export function getCoin(db: DatabaseType, symbol: string): CoinRow | undefined {
  return db.prepare(
    `SELECT * FROM l5_coins WHERE symbol = ?`,
  ).get(symbol) as CoinRow | undefined;
}

export function getAllCoins(db: DatabaseType): CoinRow[] {
  return db.prepare(
    `SELECT * FROM l5_coins ORDER BY launched_at DESC`,
  ).all() as unknown as CoinRow[];
}

export function getHolding(
  db: DatabaseType,
  symbol: string,
  wallet: string,
): bigint {
  const row = db.prepare(
    `SELECT amount FROM l5_holdings WHERE symbol = ? AND wallet_address = ?`,
  ).get(symbol, wallet) as { amount: number } | undefined;
  return BigInt(row?.amount ?? 0);
}

/** Add (or subtract, if negative) coin base units to a wallet's holding. */
function adjustHolding(
  db: DatabaseType,
  symbol: string,
  wallet: string,
  delta: bigint,
): void {
  db.prepare(`
    INSERT INTO l5_holdings (symbol, wallet_address, amount)
    VALUES (?, ?, ?)
    ON CONFLICT(symbol, wallet_address) DO UPDATE SET
      amount = amount + excluded.amount
  `).run(symbol, wallet, Number(delta));
}

// ─── Launch ──────────────────────────────────────────────────────────────────

/**
 * Launch a new Creator Coin (fair launch — 100 % of supply seeds the pool).
 *
 * The full TOTAL_SUPPLY becomes the pool's coin reserve and the locked $BB
 * becomes the pool's BB reserve, establishing the constant-product invariant
 * `reserve_bb * reserve_coin = k`. The creator receives no pre-mine
 * (creatorShare = 0); their stake is the BB liquidity they locked.
 *
 * Caller is responsible for verifying + consuming the L1 lock and asserting
 * `initialLiquidityLamports` matches the locked amount BEFORE calling this.
 *
 * @throws if the symbol already exists.
 */
export function launchCoin(db: DatabaseType, params: LaunchParams): LaunchResult {
  const existing = getCoin(db, params.symbol);
  if (existing) {
    throw new Error(`Coin ${params.symbol} already exists`);
  }
  if (params.initialLiquidityLamports < MIN_INITIAL_LIQUIDITY_BB) {
    throw new Error(
      `initialLiquidity ${params.initialLiquidityLamports} below minimum ${MIN_INITIAL_LIQUIDITY_BB}`,
    );
  }

  const reserveBb = params.initialLiquidityLamports;
  const reserveCoin = TOTAL_SUPPLY;

  db.prepare(`
    INSERT INTO l5_coins (
      symbol, name, description, creator_wallet, total_supply,
      tax_rate_bps, tax_destination, curve_type, bancor_weight_ppm,
      reserve_bb, reserve_coin, lock_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    params.symbol,
    params.name,
    params.description,
    params.creatorWallet,
    TOTAL_SUPPLY,
    params.taxRateBps,
    params.taxDestination,
    params.curveType,
    params.bancorWeightPpm,
    reserveBb,
    reserveCoin,
    params.lockId,
  );

  // initial price of 1 whole coin in whole BB (display only).
  // price = (reserveBb / LAMPORTS_PER_BB) / (reserveCoin / COIN_UNIT)
  const initialPriceBbPerCoin =
    (Number(reserveBb) / Number(LAMPORTS_PER_BB)) /
    (Number(reserveCoin) / Number(COIN_UNIT));

  return {
    symbol: params.symbol,
    totalSupply: TOTAL_SUPPLY,
    creatorShare: 0n,
    poolShare: TOTAL_SUPPLY,
    reserveBb,
    reserveCoin,
    initialPriceBbPerCoin,
  };
}

// ─── Trading (constant-product bonding curve) ──────────────────────────────────

/**
 * Buy Creator Coins with $BB along the constant-product curve.
 *
 * Mechanics (pure integer math):
 *   k                = reserve_bb * reserve_coin
 *   new_reserve_bb   = reserve_bb + bb_in
 *   new_reserve_coin = floor(k / new_reserve_bb)
 *   coin_out_gross   = reserve_coin - new_reserve_coin
 *   tax              = floor(coin_out_gross * tax_rate_bps / 10_000)
 *   coin_out_net     = coin_out_gross - tax
 *
 * Tax routing: BURN ⇒ total_supply -= tax; otherwise credited to the
 * destination wallet's holding. $BB is conserved (moves user balance → pool).
 *
 * Replay protection: `nonce` is recorded atomically inside the trade
 * transaction; a reused nonce rolls the whole trade back.
 *
 * @throws if nonce reused, coin missing, bb_in non-positive, balance insufficient, or output 0.
 */
export function buyCoin(
  db: DatabaseType,
  symbol: string,
  wallet: string,
  bbIn: bigint,
  nonce: string,
): TradeResult {
  if (bbIn <= 0n) throw new Error('bb_in must be positive');

  return db.transaction((): TradeResult => {
    if (!recordNonce(db, nonce)) throw new Error('nonce already used');
    const coin = getCoin(db, symbol);
    if (!coin) throw new Error(`Coin ${symbol} not found`);
    if (coin.curve_type !== 'CONSTANT_PRODUCT') {
      throw new Error(`Curve type ${coin.curve_type} not supported for trading yet`);
    }

    const balance = getBalance(db, 'L5', wallet, 'BB');
    if (balance < bbIn) {
      throw new Error(`Insufficient $BB: have ${balance} lamports, need ${bbIn}`);
    }

    const reserveBb = BigInt(coin.reserve_bb);
    const reserveCoin = BigInt(coin.reserve_coin);
    const k = reserveBb * reserveCoin;

    const newReserveBb = reserveBb + bbIn;
    const newReserveCoin = k / newReserveBb; // floor
    const coinOutGross = reserveCoin - newReserveCoin;
    if (coinOutGross <= 0n) throw new Error('Trade too small — zero coin output');

    const tax = (coinOutGross * BigInt(coin.tax_rate_bps)) / BPS_DENOM;
    const coinOutNet = coinOutGross - tax;

    // Debit buyer $BB → it moves into the pool reserve.
    creditBalance(db, 'L5', wallet, 'BB', -bbIn, 0);
    // Credit buyer the net coins.
    adjustHolding(db, symbol, wallet, coinOutNet);

    let newTotalSupply = BigInt(coin.total_supply);
    if (tax > 0n) {
      if (coin.tax_destination === 'BURN') {
        newTotalSupply -= tax; // coins removed from circulation
      } else {
        adjustHolding(db, symbol, coin.tax_destination, tax);
      }
    }

    db.prepare(`
      UPDATE l5_coins SET reserve_bb = ?, reserve_coin = ?, total_supply = ?
      WHERE symbol = ?
    `).run(Number(newReserveBb), Number(newReserveCoin), Number(newTotalSupply), symbol);

    return {
      symbol,
      wallet,
      coinAmount: coinOutNet,
      bbAmount: bbIn,
      taxAmount: tax,
      reserveBb: newReserveBb,
      reserveCoin: newReserveCoin,
    };
  })();
}

/**
 * Sell Creator Coins back for $BB along the constant-product curve.
 *
 * Mechanics (pure integer math):
 *   k                = reserve_bb * reserve_coin
 *   new_reserve_coin = reserve_coin + coin_in
 *   new_reserve_bb   = floor(k / new_reserve_coin)
 *   bb_out_gross     = reserve_bb - new_reserve_bb
 *   tax              = floor(bb_out_gross * tax_rate_bps / 10_000)
 *   bb_out_net       = bb_out_gross - tax
 *
 * Tax routing: BURN ⇒ tax stays in the pool reserve ($BB cannot be destroyed
 * at L5 — returning it to the pool is the solvency-safe analog); otherwise the
 * tax is credited to the destination wallet's $BB balance. $BB is conserved.
 *
 * Replay protection: `nonce` is recorded atomically inside the trade
 * transaction; a reused nonce rolls the whole trade back.
 *
 * @throws if nonce reused, coin missing, coin_in non-positive, holding insufficient, or output 0.
 */
export function sellCoin(
  db: DatabaseType,
  symbol: string,
  wallet: string,
  coinIn: bigint,
  nonce: string,
): TradeResult {
  if (coinIn <= 0n) throw new Error('coin_in must be positive');

  return db.transaction((): TradeResult => {
    if (!recordNonce(db, nonce)) throw new Error('nonce already used');
    const coin = getCoin(db, symbol);
    if (!coin) throw new Error(`Coin ${symbol} not found`);
    if (coin.curve_type !== 'CONSTANT_PRODUCT') {
      throw new Error(`Curve type ${coin.curve_type} not supported for trading yet`);
    }

    const holding = getHolding(db, symbol, wallet);
    if (holding < coinIn) {
      throw new Error(`Insufficient ${symbol}: have ${holding}, need ${coinIn}`);
    }

    const reserveBb = BigInt(coin.reserve_bb);
    const reserveCoin = BigInt(coin.reserve_coin);
    const k = reserveBb * reserveCoin;

    const newReserveCoin = reserveCoin + coinIn;
    const newReserveBb = k / newReserveCoin; // floor
    const bbOutGross = reserveBb - newReserveBb;
    if (bbOutGross <= 0n) throw new Error('Trade too small — zero $BB output');

    const tax = (bbOutGross * BigInt(coin.tax_rate_bps)) / BPS_DENOM;
    const bbOutNet = bbOutGross - tax;

    // Debit seller coins → they move into the pool reserve.
    adjustHolding(db, symbol, wallet, -coinIn);
    // Credit seller the net $BB.
    creditBalance(db, 'L5', wallet, 'BB', bbOutNet, 0);

    // Tax routing for $BB output.
    let effectiveReserveBb = newReserveBb;
    if (tax > 0n) {
      if (coin.tax_destination === 'BURN') {
        effectiveReserveBb = newReserveBb + tax; // keep tax in the pool
      } else {
        creditBalance(db, 'L5', coin.tax_destination, 'BB', tax, 0);
      }
    }

    db.prepare(`
      UPDATE l5_coins SET reserve_bb = ?, reserve_coin = ?
      WHERE symbol = ?
    `).run(Number(effectiveReserveBb), Number(newReserveCoin), symbol);

    return {
      symbol,
      wallet,
      coinAmount: coinIn,
      bbAmount: bbOutNet,
      taxAmount: tax,
      reserveBb: effectiveReserveBb,
      reserveCoin: newReserveCoin,
    };
  })();
}

// ─── Balance snapshot ─────────────────────────────────────────────────────────

/**
 * Return all non-zero L5 $BB balances.
 * Used by the batch sealer to build the full Merkle state snapshot that backs
 * L1 exits. Creator Coin holdings are intentionally excluded — they are not
 * exitable; users must swap coins back to $BB first.
 */
export function getAllBalances(
  db: DatabaseType,
): { address: string; lamports: bigint }[] {
  const rows = db.prepare(`
    SELECT address, bb_lamports
    FROM balances
    WHERE rollup_id = 'L5' AND asset_type = 'BB' AND bb_lamports > 0
    ORDER BY address ASC
  `).all() as { address: string; bb_lamports: number }[];
  return rows.map(r => ({ address: r.address, lamports: BigInt(r.bb_lamports) }));
}
