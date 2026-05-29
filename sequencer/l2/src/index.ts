import { openL2Db } from './db.js';
import { createServer } from './server.js';
import { startPohLoop } from './pohLoop.js';
import type { SequencerConfig } from '@bb/shared';

// ─── Validate required env vars ───────────────────────────────────────────────

const privkey = process.env.L2_SEQUENCER_PRIVKEY;
const pubkey  = process.env.L2_SEQUENCER_PUBKEY;

if (!privkey || privkey.length !== 64) {
  console.error('[L2] L2_SEQUENCER_PRIVKEY must be a 64-char hex Ed25519 private key seed');
  process.exit(1);
}
if (!pubkey || pubkey.length !== 64) {
  console.error('[L2] L2_SEQUENCER_PUBKEY must be a 64-char hex Ed25519 public key');
  process.exit(1);
}

// ─── Build config ─────────────────────────────────────────────────────────────

const config: SequencerConfig = {
  rollupId:      'L2',
  l1HttpUrl:     process.env.L1_HTTP_URL     ?? 'http://localhost:8080',
  l1WsUrl:       process.env.L1_WS_URL       ?? 'ws://localhost:8080/ws',
  dbPath:        process.env.DB_PATH         ?? './data/l2.sqlite',
  port:          Number(process.env.PORT         ?? '7072'),
  slotsPerBatch: Number(process.env.SLOTS_PER_BATCH ?? '25'),
  keypair: {
    privateKeyHex: privkey,
    publicKeyHex:  pubkey,
  },
};

// ─── Bootstrap ────────────────────────────────────────────────────────────────

const db  = openL2Db(config.dbPath);
const app = createServer(config, db);

app.listen(config.port, () => {
  console.log(`[L2 Sequencer] Listening on :${config.port}`);
  console.log(`[L2 Sequencer] L1 HTTP : ${config.l1HttpUrl}`);
  console.log(`[L2 Sequencer] L1 WS   : ${config.l1WsUrl}`);
  console.log(`[L2 Sequencer] Batch   : every ${config.slotsPerBatch} slots`);
  console.log(`[L2 Sequencer] Pubkey  : ${pubkey}`);
});

startPohLoop(config, db);
