import { getBalance, creditBalance } from '@bb/shared';
import type { DatabaseType } from '@bb/shared';

// ─── Constants ────────────────────────────────────────────────────────────────

/**
 * Dealer house fee rate in basis points (100 bps = 1%).
 * The fee is taken from the total pool before pro-rata distribution to winners.
 * Credited to DEALER_ADDRESS (configured via environment variable).
 * Defaults to 100 bps (1%).
 */
const DEALER_FEE_BPS = Number(process.env.DEALER_FEE_BPS ?? '100');
/**
 * L1 wallet address of the market maker / prize pool operator.
 * Receives the house fee from every resolved market.
 * The dealer's L2 balance accumulates and is included in the Merkle tree —
 * they exit to L1 via the same Rollup Hub proof mechanism as users.
 */
const DEALER_ADDRESS = process.env.DEALER_ADDRESS ?? 'dealer_reserve';

// ─── Types ────────────────────────────────────────────────────────────────────

export type MarketStatus = 'OPEN' | 'LOCKED' | 'RESOLVED';
export type BetSide = 'YES' | 'NO';
export type MarketOutcome = 'YES' | 'NO';

export interface MarketRow {
  market_id: string;
  question: string;
  status: MarketStatus;
  outcome: MarketOutcome | null;
  total_yes_pool: number;
  total_no_pool: number;
  created_at_ts: number;
  resolved_at_ts: number | null;
}

export interface PositionRow {
  market_id: string;
  wallet_address: string;
  bet_side: BetSide;
  amount_lamports: number;
  placed_at_ts: number;
}

export interface PayoutRecord {
  wallet_address: string;
  payout_lamports: bigint;
}

// ─── Market CRUD ──────────────────────────────────────────────────────────────

export function createMarket(
  db: DatabaseType,
  marketId: string,
  question: string,
): void {
  db.prepare(`
    INSERT INTO l2_markets (market_id, question, status)
    VALUES (?, ?, 'OPEN')
  `).run(marketId, question);
}

export function getMarket(db: DatabaseType, marketId: string): MarketRow | undefined {
  return db.prepare(
    `SELECT * FROM l2_markets WHERE market_id = ?`,
  ).get(marketId) as MarketRow | undefined;
}

export function getAllMarkets(db: DatabaseType, status?: MarketStatus): MarketRow[] {
  if (status) {
    return db.prepare(
      `SELECT * FROM l2_markets WHERE status = ? ORDER BY created_at_ts DESC`,
    ).all(status) as unknown as MarketRow[];
  }
  return db.prepare(
    `SELECT * FROM l2_markets ORDER BY created_at_ts DESC`,
  ).all() as unknown as MarketRow[];
}

/** Transition OPEN → LOCKED. No new bets accepted after this. */
export function lockMarket(db: DatabaseType, marketId: string): void {
  const result = db.prepare(`
    UPDATE l2_markets SET status = 'LOCKED'
    WHERE market_id = ? AND status = 'OPEN'
  `).run(marketId);
  if (result.changes === 0) {
    throw new Error(`Market ${marketId} is not OPEN or does not exist`);
  }
}

// ─── Betting ──────────────────────────────────────────────────────────────────

/**
 * Place (or add to) an off-chain bet.
 *
 * Rules enforced atomically inside a SQLite transaction:
 *   - Market must be OPEN.
 *   - Wallet balance must cover the stake.
 *   - Wallet cannot switch sides after an initial bet.
 *   - Bets on the same side accumulate into one position row.
 *
 * The balance debit is immediate — the user's funds are committed the moment
 * the bet lands. Payouts are credited only on resolution.
 */
export function placeBet(
  db: DatabaseType,
  marketId: string,
  walletAddress: string,
  side: BetSide,
  amountLamports: bigint,
): void {
  const txn = db.transaction(() => {
    const market = getMarket(db, marketId);
    if (!market) throw new Error(`Market ${marketId} not found`);
    if (market.status !== 'OPEN') {
      throw new Error(`Market ${marketId} is ${market.status} — bets are closed`);
    }

    const balance = getBalance(db, 'L2', walletAddress, 'BB');
    if (balance < amountLamports) {
      throw new Error(
        `Insufficient balance: have ${balance} lamports, need ${amountLamports}`,
      );
    }

    // Prevent side-switching
    const existing = db.prepare(
      `SELECT bet_side FROM l2_positions WHERE market_id = ? AND wallet_address = ?`,
    ).get(marketId, walletAddress) as { bet_side: BetSide } | undefined;
    if (existing && existing.bet_side !== side) {
      throw new Error(
        `Wallet already has a ${existing.bet_side} position — cannot switch sides`,
      );
    }

    // Debit wallet balance (batchId=0 = pending next seal)
    creditBalance(db, 'L2', walletAddress, 'BB', -amountLamports, 0);

    // Upsert position — merge into existing stake if same side.
    // Pass amountLamports as BigInt: node:sqlite maps bigint → INTEGER (exact),
    // whereas Number() maps to REAL which loses precision above 2^53 lamports.
    db.prepare(`
      INSERT INTO l2_positions (market_id, wallet_address, bet_side, amount_lamports)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(market_id, wallet_address) DO UPDATE SET
        amount_lamports = amount_lamports + excluded.amount_lamports
    `).run(marketId, walletAddress, side, amountLamports);

    // Update pool totals (bigint → INTEGER, exact for all realistic bet sizes)
    const col = side === 'YES' ? 'total_yes_pool' : 'total_no_pool';
    db.prepare(
      `UPDATE l2_markets SET ${col} = ${col} + ? WHERE market_id = ?`,
    ).run(amountLamports, marketId);
  });

  txn();
}

// ─── Resolution ───────────────────────────────────────────────────────────────

/**
 * Resolve a market and pro-rata credit winners.
 *
 * Zero-sum invariant: every lamport staked is returned to winners.
 * Integer division dust (at most 1 lamport per winner) accumulates in the
 * L2 operational reserve and is anchored in the next Merkle batch.
 *
 * Edge case — nobody bet the winning side: the losing side is fully refunded.
 *
 * @param batchId  The batch_id being prepared (stamped on creditBalance rows).
 * @returns        PayoutRecord[] — pass these directly as BbEntries for the
 *                 Merkle tree if you want a proof-per-winner structure,
 *                 or call getAllBalances() for the full state snapshot.
 */
export function resolveMarket(
  db: DatabaseType,
  marketId: string,
  outcome: MarketOutcome,
  batchId: number,
): PayoutRecord[] {
  const payouts: PayoutRecord[] = [];

  const txn = db.transaction(() => {
    const market = getMarket(db, marketId);
    if (!market) throw new Error(`Market ${marketId} not found`);
    if (market.status === 'RESOLVED') throw new Error(`Market ${marketId} already resolved`);

    const totalPool = BigInt(market.total_yes_pool) + BigInt(market.total_no_pool);
    const winningPool = outcome === 'YES'
      ? BigInt(market.total_yes_pool)
      : BigInt(market.total_no_pool);
    const losingSide: BetSide = outcome === 'YES' ? 'NO' : 'YES';

    // ── Dealer house fee ───────────────────────────────────────────────────
    // Fee = floor(totalPool * DEALER_FEE_BPS / 10_000).
    // Taken from totalPool before distribution so the invariant holds:
    //   totalPool = dealerFee + sum(payouts)
    const dealerFee = totalPool * BigInt(DEALER_FEE_BPS) / 10_000n;
    const distributedPool = totalPool - dealerFee;
    if (dealerFee > 0n) {
      creditBalance(db, 'L2', DEALER_ADDRESS, 'BB', dealerFee, batchId);
      payouts.push({ wallet_address: DEALER_ADDRESS, payout_lamports: dealerFee });
    }

    if (winningPool === 0n) {
      // Edge case: no bets on the winning side — full refund to the losing side.
      // Dealer fee is NOT taken on refund — return 100% to users.
      const losers = db.prepare(`
        SELECT wallet_address, amount_lamports FROM l2_positions
        WHERE market_id = ? AND bet_side = ?
      `).all(marketId, losingSide) as { wallet_address: string; amount_lamports: number }[];

      for (const pos of losers) {
        const refund = BigInt(pos.amount_lamports);
        creditBalance(db, 'L2', pos.wallet_address, 'BB', refund, batchId);
        payouts.push({ wallet_address: pos.wallet_address, payout_lamports: refund });
      }
    } else {
      // Normal case: pro-rata payout from distributedPool (after dealer fee) to winners.
      // payout_i = (stake_i / winningPool) * distributedPool — pure integer arithmetic.
      const winners = db.prepare(`
        SELECT wallet_address, amount_lamports FROM l2_positions
        WHERE market_id = ? AND bet_side = ?
      `).all(marketId, outcome) as { wallet_address: string; amount_lamports: number }[];

      for (const pos of winners) {
        const payout = (BigInt(pos.amount_lamports) * distributedPool) / winningPool;
        creditBalance(db, 'L2', pos.wallet_address, 'BB', payout, batchId);
        payouts.push({ wallet_address: pos.wallet_address, payout_lamports: payout });
      }
      // Dust (totalPool - sum(payouts)) stays in the L2 reserve — anchored in the root.
    }

    // Stamp the market resolved
    db.prepare(`
      UPDATE l2_markets
      SET status = 'RESOLVED', outcome = ?, resolved_at_ts = unixepoch()
      WHERE market_id = ?
    `).run(outcome, marketId);
  });

  txn();
  return payouts;
}

// ─── Balance snapshot ─────────────────────────────────────────────────────────

/**
 * Return all non-zero L2 BB balances.
 * Used by the batch sealer to build the full Merkle state snapshot.
 */
export function getAllBalances(
  db: DatabaseType,
): { address: string; lamports: bigint }[] {
  const rows = db.prepare(`
    SELECT address, bb_lamports
    FROM balances
    WHERE rollup_id = 'L2' AND asset_type = 'BB' AND bb_lamports > 0
    ORDER BY address ASC
  `).all() as { address: string; bb_lamports: number }[];
  return rows.map(r => ({ address: r.address, lamports: BigInt(r.bb_lamports) }));
}
