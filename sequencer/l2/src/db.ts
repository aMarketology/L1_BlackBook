import { openDb } from '@bb/shared';
import type { DatabaseType } from '@bb/shared';

// ─── L2-specific schema ───────────────────────────────────────────────────────
//
// Bolted on top of the generic shared schema (locks, balances, batches,
// slot_watermark). All monetary values are stored as INTEGER lamports —
// never floats.

const L2_SCHEMA = `
  -- One row per prediction market.
  CREATE TABLE IF NOT EXISTS l2_markets (
    market_id       TEXT    PRIMARY KEY,
    question        TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'OPEN',  -- 'OPEN' | 'LOCKED' | 'RESOLVED'
    outcome         TEXT,                             -- 'YES' | 'NO' (set on resolution)
    total_yes_pool  INTEGER NOT NULL DEFAULT 0,       -- lamports staked YES
    total_no_pool   INTEGER NOT NULL DEFAULT 0,       -- lamports staked NO
    created_at_ts   INTEGER NOT NULL DEFAULT (unixepoch()),
    resolved_at_ts  INTEGER                           -- unix ts, null until resolved
  );

  CREATE INDEX IF NOT EXISTS idx_markets_status ON l2_markets(status);

  -- One row per (market, wallet). A wallet holds exactly one side per market.
  -- Switching sides after placement is rejected to prevent manipulation.
  -- amount_lamports accumulates if the wallet bets the same side multiple times.
  CREATE TABLE IF NOT EXISTS l2_positions (
    market_id       TEXT    NOT NULL,
    wallet_address  TEXT    NOT NULL,
    bet_side        TEXT    NOT NULL,  -- 'YES' | 'NO'
    amount_lamports INTEGER NOT NULL,  -- total staked by this wallet in this market
    placed_at_ts    INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (market_id, wallet_address)
  );

  CREATE INDEX IF NOT EXISTS idx_positions_market ON l2_positions(market_id);
  CREATE INDEX IF NOT EXISTS idx_positions_wallet ON l2_positions(wallet_address);
`;

// ─── Open ──────────────────────────────────────────────────────────────────────

/**
 * Open the L2 SQLite database, applying both the shared base schema and the
 * L2-specific market/position tables.  Safe to call multiple times.
 */
export function openL2Db(dbPath: string): DatabaseType {
  const db = openDb(dbPath);
  db.exec(L2_SCHEMA);
  return db;
}
