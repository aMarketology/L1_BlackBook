import { openDb } from '@bb/shared';
import type { DatabaseType } from '@bb/shared';

// ─── L5-specific schema ───────────────────────────────────────────────────────
//
// Bolted on top of the generic shared schema (locks, balances, batches,
// slot_watermark). $BB balances live in the shared `balances` table (asset_type
// 'BB') — those are what the batch sealer anchors on L1 for exits.
//
// Creator Coin holdings are L5-internal and CANNOT be exited to L1 directly:
// a user must swap coins back to $BB on the bonding curve, then exit the $BB.
//
// All monetary values are stored as INTEGER (lamports for BB, base units for
// coins) — never floats.

const L5_SCHEMA = `
  -- One row per launched Creator Coin. symbol is the primary key.
  CREATE TABLE IF NOT EXISTS l5_coins (
    symbol            TEXT    PRIMARY KEY,
    name              TEXT    NOT NULL,
    description       TEXT,
    creator_wallet    TEXT    NOT NULL,
    total_supply      INTEGER NOT NULL,                 -- coin base units (6 decimals)
    tax_rate_bps      INTEGER NOT NULL DEFAULT 0,        -- 0..1000 (≤10%)
    tax_destination   TEXT    NOT NULL,                  -- 'BURN' or an L1 wallet address
    curve_type        TEXT    NOT NULL,                  -- 'CONSTANT_PRODUCT' | 'BANCOR_VAMM'
    bancor_weight_ppm INTEGER,                           -- null unless BANCOR_VAMM
    reserve_bb        INTEGER NOT NULL,                  -- $BB lamports held in the pool
    reserve_coin      INTEGER NOT NULL,                  -- coin base units held in the pool
    lock_id           TEXT    NOT NULL,                  -- L1 lock that seeded the BB reserve
    launched_at       INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE INDEX IF NOT EXISTS idx_l5_coins_creator ON l5_coins(creator_wallet);

  -- One row per (coin, wallet). Creator Coin balances — NOT exitable to L1.
  CREATE TABLE IF NOT EXISTS l5_holdings (
    symbol         TEXT    NOT NULL,
    wallet_address TEXT    NOT NULL,
    amount         INTEGER NOT NULL DEFAULT 0,           -- coin base units
    PRIMARY KEY (symbol, wallet_address)
  );

  CREATE INDEX IF NOT EXISTS idx_l5_holdings_wallet ON l5_holdings(wallet_address);

  -- Replay protection for signed launch/buy/sell actions.
  CREATE TABLE IF NOT EXISTS l5_nonces (
    nonce      TEXT    PRIMARY KEY,
    used_at_ts INTEGER NOT NULL DEFAULT (unixepoch())
  );
`;

// ─── Open ──────────────────────────────────────────────────────────────────────

/**
 * Open the L5 SQLite database, applying both the shared base schema and the
 * L5-specific coin/holding/nonce tables. Safe to call multiple times.
 */
export function openL5Db(dbPath: string): DatabaseType {
  const db = openDb(dbPath);
  db.exec(L5_SCHEMA);
  return db;
}
