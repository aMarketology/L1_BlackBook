import Database from "better-sqlite3";
import { mkdirSync } from "fs";
import { dirname } from "path";

export type SigState =
  | "Seen"
  | "AwaitingFinality"
  | "Parsed"
  | "Ignored"
  | "Submitting"
  | "Processed"
  | "Retry";

export interface SigRow {
  sig: string;
  state: SigState;
  reason: string | null;
  wallet: string | null;
  asset: string | null;
  amount_micro: bigint | null;
  tx_slot: number | null;
  submit_attempts: number;
  next_retry_at: number | null;
  created_at: number;
  updated_at: number;
}

const MIGRATIONS = [
  `CREATE TABLE IF NOT EXISTS cursor (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    last_signature TEXT,
    updated_at INTEGER NOT NULL
  )`,

  `CREATE TABLE IF NOT EXISTS signatures (
    sig TEXT PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN (
      'Seen','AwaitingFinality','Parsed','Ignored','Submitting','Processed','Retry'
    )),
    reason TEXT,
    wallet TEXT,
    asset TEXT,
    amount_micro INTEGER,
    tx_slot INTEGER,
    submit_attempts INTEGER NOT NULL DEFAULT 0,
    next_retry_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`,

  `CREATE INDEX IF NOT EXISTS idx_sig_state ON signatures(state)`,
  `CREATE INDEX IF NOT EXISTS idx_sig_retry ON signatures(next_retry_at) WHERE state = 'Retry'`,
];

export function openDb(path: string): Database.Database {
  mkdirSync(dirname(path), { recursive: true });
  const db = new Database(path);
  db.pragma("journal_mode = WAL");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");
  for (const sql of MIGRATIONS) {
    db.exec(sql);
  }
  return db;
}
