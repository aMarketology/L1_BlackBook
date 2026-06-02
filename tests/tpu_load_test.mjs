/**
 * BlackBook L1 — UDP TPU Load Test
 *
 * Generates properly signed TpuPacket structs, serializes them with bincode,
 * and blasts them at UDP :8003 across many independent wallet pairs to saturate
 * all 4 Rayon/Sealevel threads without hitting the O(n²) single-account bottleneck.
 *
 * Wire format source of truth: runtime/tpu.rs  (TpuPacket struct)
 * Signing message format:
 *   chain_id(u8) || from_utf8 || '|' || to_utf8 || '|' ||
 *   amount_le64 || '|' || timestamp_le64 || '|' || nonce_utf8
 *
 * Usage:
 *   node tests/tpu_load_test.mjs
 *   node tests/tpu_load_test.mjs --wallets 1000 --rate 3000 --duration 30
 *
 * Flags:
 *   --wallets   N   Number of unique keypairs to generate  (default: 500)
 *   --rate      N   Target transactions per second          (default: 2000, max 4800 due to QoS 5k/s/IP)
 *   --duration  N   How many seconds to run                 (default: 20)
 *   --host      S   TPU host                                (default: 91.98.196.34)
 *   --port      N   TPU UDP port                            (default: 8003)
 *   --metrics   S   HTTP base URL to poll /metrics          (default: http://91.98.196.34:8080)
 */

import dgram from 'dgram';
import nacl  from 'tweetnacl';
import bs58  from 'bs58';

// ── CLI args ─────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(flag, def) {
  const i = args.indexOf(flag);
  return i !== -1 ? args[i + 1] : def;
}

const TARGET_HOST    = getArg('--host',     '91.98.196.34');
const TPU_PORT       = parseInt(getArg('--port',     '8003'));
const METRICS_BASE   = getArg('--metrics',  `http://${TARGET_HOST}:8080`);
const NUM_WALLETS    = parseInt(getArg('--wallets',  '500'));
const TARGET_TPS     = parseInt(getArg('--rate',     '2000'));
const DURATION_SECS  = parseInt(getArg('--duration', '20'));
const CHAIN_ID       = 1;            // EXPECTED_CHAIN_ID in tpu.rs
const AMOUNT_LAMPORTS = 1000n;       // 0.01 BB — non-zero required by tpu.rs field sanity check

// The QoS ceiling in tpu.rs is 5,000 packets/s per source IP — stay under it.
if (TARGET_TPS > 4800) {
  console.error('❌  --rate exceeds QoS ceiling of 5,000/s/IP. Use ≤ 4800.');
  process.exit(1);
}

// ── Bincode helpers (matches bincode v1 default config used by Rust) ─────────
// bincode v1 encodes:
//   String  → u64 LE length prefix + UTF-8 bytes
//   u64     → 8 bytes LE
//   u8      → 1 byte
//   Option  → 0x00 (None) | 0x01 + inner (Some)

function writeBincodeString(str) {
  const strBuf = Buffer.from(str, 'utf8');
  const lenBuf = Buffer.alloc(8);
  lenBuf.writeBigUInt64LE(BigInt(strBuf.length));
  return Buffer.concat([lenBuf, strBuf]);
}

function writeU64LE(bigint) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(bigint);
  return buf;
}

/** Serializes TpuPacket in the exact field order declared in runtime/tpu.rs */
function serializeTpuPacket(pkt) {
  return Buffer.concat([
    writeBincodeString(pkt.from),
    writeBincodeString(pkt.to),
    writeU64LE(pkt.amount),
    writeBincodeString(pkt.public_key),
    writeBincodeString(pkt.signature),
    writeU64LE(pkt.timestamp),
    writeBincodeString(pkt.nonce),
    Buffer.from([pkt.chain_id]),       // u8
    writeU64LE(pkt.priority),
    Buffer.from([0x00]),               // tx_type: Option<String> = None
  ]);
}

// ── Wallet generation ────────────────────────────────────────────────────────

function generateWallet() {
  const kp = nacl.sign.keyPair();
  return {
    keypair:   kp,
    address:   bs58.encode(kp.publicKey),           // BS58(pubkey) — L1 address format
    pubkeyHex: Buffer.from(kp.publicKey).toString('hex'),
  };
}

// ── Build + sign one packet ──────────────────────────────────────────────────

function buildPacket(sender, toAddress, nonce) {
  const timestamp = BigInt(Math.floor(Date.now() / 1000));

  // Canonical signing message — must exactly match runtime/tpu.rs § 6:
  //   chain_id(1) || from_utf8 || '|' || to_utf8 || '|' ||
  //   amount_le64(8) || '|' || timestamp_le64(8) || '|' || nonce_utf8
  const msg = Buffer.concat([
    Buffer.from([CHAIN_ID]),
    Buffer.from(sender.address,  'utf8'),
    Buffer.from('|'),
    Buffer.from(toAddress,       'utf8'),
    Buffer.from('|'),
    writeU64LE(AMOUNT_LAMPORTS),
    Buffer.from('|'),
    writeU64LE(timestamp),
    Buffer.from('|'),
    Buffer.from(nonce,           'utf8'),
  ]);

  const sigBytes = nacl.sign.detached(msg, sender.keypair.secretKey);
  const sigHex   = Buffer.from(sigBytes).toString('hex');

  return serializeTpuPacket({
    from:       sender.address,
    to:         toAddress,
    amount:     AMOUNT_LAMPORTS,
    public_key: sender.pubkeyHex,
    signature:  sigHex,
    timestamp,
    nonce,
    chain_id:   CHAIN_ID,
    priority:   0n,
  });
}

// ── Stats ────────────────────────────────────────────────────────────────────

let sent   = 0;
let errors = 0;
let bytes  = 0;

function printStats(elapsed) {
  const tps  = elapsed > 0 ? (sent / elapsed).toFixed(0) : '–';
  const mbps = elapsed > 0 ? ((bytes / elapsed) / 1_048_576).toFixed(2) : '–';
  process.stdout.write(
    `\r  ⚡  sent=${sent.toLocaleString()}  err=${errors}  ` +
    `${tps} tx/s  ${mbps} MB/s  ${elapsed.toFixed(1)}s elapsed   `
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║   $BB L1 — UDP/bincode TPU Load Test  (TypeScript)      ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log(`  Target  : ${TARGET_HOST}:${TPU_PORT}`);
  console.log(`  Wallets : ${NUM_WALLETS} unique Ed25519 keypairs`);
  console.log(`  Rate    : ${TARGET_TPS} tx/s  ×  ${DURATION_SECS}s  = ${(TARGET_TPS * DURATION_SECS).toLocaleString()} total`);
  console.log(`  Amount  : ${AMOUNT_LAMPORTS} lamports / tx (${Number(AMOUNT_LAMPORTS) / 100_000} BB)`);
  console.log(`  Chain   : ${CHAIN_ID}`);
  console.log();

  // ── 1. Pre-generate wallets ───────────────────────────────────────────────
  process.stdout.write(`🔑  Generating ${NUM_WALLETS} keypairs...`);
  const wallets = Array.from({ length: NUM_WALLETS }, generateWallet);
  console.log(` done.  Sample: ${wallets[0].address}`);

  // ── 2. Bind UDP socket ────────────────────────────────────────────────────
  const client = dgram.createSocket('udp4');
  await new Promise((res, rej) => client.bind(0, err => err ? rej(err) : res()));
  console.log(`📡  UDP bound on ${JSON.stringify(client.address())}`);
  console.log();

  // ── 3. Blast loop (fixed-rate interval) ──────────────────────────────────
  //
  // Interval fires every 10ms. Each tick sends (TARGET_TPS / 100) packets.
  // This keeps burst size manageable and avoids flooding the kernel send buffer.
  //
  const TICK_MS       = 10;
  const PKTS_PER_TICK = Math.ceil(TARGET_TPS / (1000 / TICK_MS));
  let   nonceCounter  = Date.now();
  let   txIdx         = 0;
  const startTime     = Date.now();
  const endTime       = startTime + DURATION_SECS * 1000;

  const statsInterval = setInterval(() => {
    printStats((Date.now() - startTime) / 1000);
  }, 500);

  await new Promise(resolve => {
    const ticker = setInterval(() => {
      if (Date.now() >= endTime) {
        clearInterval(ticker);
        resolve();
        return;
      }

      for (let i = 0; i < PKTS_PER_TICK; i++) {
        // Round-robin sender; pick a different wallet as recipient to avoid
        // all txs touching the same account (would collapse to single thread in Sealevel)
        const senderIdx    = txIdx % wallets.length;
        const recipientIdx = (txIdx + Math.floor(wallets.length / 2)) % wallets.length;
        const sender       = wallets[senderIdx];
        const recipient    = wallets[recipientIdx];
        const nonce        = `${nonceCounter++}`;

        try {
          const pkt = buildPacket(sender, recipient.address, nonce);
          client.send(pkt, TPU_PORT, TARGET_HOST, err => {
            if (err) { errors++; }
            else     { sent++;  bytes += pkt.length; }
          });
        } catch (e) {
          errors++;
        }

        txIdx++;
      }
    }, TICK_MS);
  });

  clearInterval(statsInterval);
  const elapsed = (Date.now() - startTime) / 1000;
  printStats(elapsed);
  console.log('\n');

  // ── 4. Final report ───────────────────────────────────────────────────────
  console.log('══════════════════════════════════════════════════════════');
  console.log(`  Packets sent   : ${sent.toLocaleString()}`);
  console.log(`  Errors         : ${errors}`);
  console.log(`  Effective rate : ${(sent / elapsed).toFixed(0)} tx/s`);
  console.log(`  Throughput     : ${((bytes / elapsed) / 1_048_576).toFixed(2)} MB/s`);
  console.log(`  Avg pkt size   : ${sent > 0 ? Math.round(bytes / sent) : 0} bytes`);
  console.log('══════════════════════════════════════════════════════════');
  console.log();
  console.log('📊  Pull live metrics from the node:');
  console.log(`    curl -s ${METRICS_BASE}/metrics | head -40`);
  console.log(`    curl -s ${METRICS_BASE}/stats`);
  console.log();
  console.log('ℹ   Transactions will pass signature verification but will');
  console.log('    fail balance checks (wallets have no BB on-chain).');
  console.log('    This still saturates the Ed25519 CPU pipeline and');
  console.log('    measures raw ingestion throughput up to the exec stage.');

  client.close();
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
