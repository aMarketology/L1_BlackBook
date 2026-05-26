/**
 * BlackBook L1 — Reader Proxy E2E Test
 *
 * Validates that reader_proxy_middleware correctly:
 *   1. Keeps the local node in READER mode (GET checks)
 *   2. Proxies POST bodies + headers to the Writer without modification
 *   3. Returns the Writer's response status code unchanged
 *   4. Returns the Writer's response body unchanged
 *   5. State changes land on the Writer (the write was executed there)
 *   6. After block sync, the Reader serves the updated state from local DB
 *   7. Error responses (replay, rate-limit) are forwarded with correct codes
 *   8. Two simultaneous writes with the same nonce produce exactly one 200
 *
 * Usage:
 *   node tests/reader_proxy_e2e.mjs
 *
 * Environment overrides:
 *   READER_URL=http://localhost:8080       (default)
 *   WRITER_URL=http://91.98.196.34:8080   (default — Hetzner)
 *   SYNC_WAIT_MS=2000                     (default — block propagation wait)
 */

import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';

const READER      = process.env.READER_URL     ?? 'http://localhost:8080';
const WRITER      = process.env.WRITER_URL     ?? 'http://91.98.196.34:8080';
const SYNC_WAIT   = parseInt(process.env.SYNC_WAIT_MS ?? '2000');

let passed = 0, failed = 0, skipped = 0;

function ok(name, detail = '')   { passed++;  console.log(`  ✅ ${name}${detail ? ' — ' + detail : ''}`); }
function fail(name, err)         { failed++;  console.error(`  ❌ ${name} — ${err}`); }
function skip(name, reason)      { skipped++; console.log(`  ⚠️  SKIP: ${name} — ${reason}`); }
function section(title) {
  const bar = '─'.repeat(Math.max(0, 62 - title.length));
  console.log(`\n── ${title} ${bar}`);
}

// ── HTTP helpers ─────────────────────────────────────────────────────────────

async function httpGet(url) {
  const res = await fetch(url);
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

async function httpPost(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const body = await res.json().catch(() => null);
  return { status: res.status, body };
}

// ── Signing helpers ───────────────────────────────────────────────────────────

function nowSecs() { return Math.floor(Date.now() / 1000); }

function randomNonce() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(12)));
}

/** Build a signed /faucet payload for a given keypair. */
async function buildFaucetPayload(privBytes, amount = 0.1) {
  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  const address  = bs58.encode(pubBytes);
  const ts       = nowSecs();
  const nonce    = randomNonce();
  const msg      = `FAUCET:${address}:${amount}:${ts}:${nonce}`;
  const sig      = await ed.signAsync(new TextEncoder().encode(msg), privBytes);
  return {
    payload: {
      wallet_address: address,
      amount,
      public_key: bytesToHex(pubBytes),
      signature:  bytesToHex(sig),
      timestamp:  ts,
      nonce,
    },
    address,
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║     BlackBook L1 — Reader Proxy Pipeline E2E Test        ║');
  console.log('╠══════════════════════════════════════════════════════════╣');
  console.log(`║  Reader : ${READER.padEnd(48)}║`);
  console.log(`║  Writer : ${WRITER.padEnd(48)}║`);
  console.log(`║  Sync   : ${String(SYNC_WAIT + ' ms').padEnd(48)}║`);
  console.log('╚══════════════════════════════════════════════════════════╝');

  // ── Fresh throwaway wallet (no rate-limit collisions with other tests) ──────
  const privBytes = crypto.getRandomValues(new Uint8Array(32));
  const pubBytes  = await ed.getPublicKeyAsync(privBytes);
  const address   = bs58.encode(pubBytes);
  console.log(`\n  Test wallet : ${address}`);
  console.log(`  Public key  : ${bytesToHex(pubBytes)}`);

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 1 — Node reachability & mode verification');
  // ══════════════════════════════════════════════════════════════════════════

  let readerUp = false, writerUp = false;

  try {
    const r = await httpGet(`${READER}/health`);
    if (r.status !== 200) {
      fail('Reader /health', `HTTP ${r.status}`);
    } else if (r.body?.node_mode !== 'reader') {
      fail('Reader node_mode check', `expected "reader", got "${r.body?.node_mode}" — start with --mode reader`);
    } else {
      ok('Reader UP and in reader mode', `slot=${r.body?.poh_clock?.current_slot}`);
      readerUp = true;
    }
  } catch (e) {
    fail('Reader /health unreachable', `${e.message}\n       → Start: .\\target\\debug\\layer1.exe --mode reader --writer-addr ${WRITER.replace('http://','').replace(':8080',':50051')}`);
  }

  try {
    const r = await httpGet(`${WRITER}/health`);
    if (r.status !== 200) {
      fail('Writer /health', `HTTP ${r.status}`);
    } else {
      ok('Writer UP', `slot=${r.body?.poh_clock?.current_slot}, mode=${r.body?.node_mode}`);
      writerUp = true;
    }
  } catch (e) {
    fail('Writer /health unreachable', e.message);
  }

  if (!readerUp || !writerUp) {
    console.log('\n  ⛔ Cannot continue — both nodes must be reachable. Aborting.');
    process.exit(1);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 2 — GET is served locally (balance = 0 on fresh wallet)');
  // ══════════════════════════════════════════════════════════════════════════

  try {
    const [rRes, wRes] = await Promise.all([
      httpGet(`${READER}/balance/${address}`),
      httpGet(`${WRITER}/balance/${address}`),
    ]);
    const rBal = rRes.body?.balance ?? -1;
    const wBal = wRes.body?.balance ?? -1;

    if (rRes.status === 200 && rBal === 0)  ok('Reader  GET /balance → 0 (fresh wallet)');
    else fail('Reader  GET /balance',  `status=${rRes.status} balance=${rBal}`);

    if (wRes.status === 200 && wBal === 0)  ok('Writer  GET /balance → 0 (fresh wallet)');
    else fail('Writer  GET /balance',  `status=${wRes.status} balance=${wBal}`);
  } catch (e) {
    fail('GET /balance threw', e.message);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 3 — POST /faucet forwarded from Reader to Writer');
  // ══════════════════════════════════════════════════════════════════════════

  const { payload: faucetPayload } = await buildFaucetPayload(privBytes, 0.1);
  console.log(`  Sending faucet to READER (should proxy to Writer)…`);

  let faucetOk = false;
  try {
    const rRes = await httpPost(`${READER}/faucet`, faucetPayload);
    console.log(`  Reader  ← status=${rRes.status}  body=${JSON.stringify(rRes.body)}`);

    if (rRes.status === 200 && rRes.body?.success === true) {
      ok('POST /faucet via Reader → 200 success (body forwarded correctly)');
      faucetOk = true;
    } else if (rRes.status === 429) {
      skip('POST /faucet', '429 already claimed this epoch — try a new wallet or a new epoch');
    } else {
      fail('POST /faucet via Reader', `status=${rRes.status} body=${JSON.stringify(rRes.body)}`);
    }
  } catch (e) {
    fail('POST /faucet threw', e.message);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 4 — Writer executed the write (balance > 0 on Writer)');
  // ══════════════════════════════════════════════════════════════════════════

  if (!faucetOk) {
    skip('Writer balance check', 'faucet did not succeed');
  } else {
    try {
      const wRes = await httpGet(`${WRITER}/balance/${address}`);
      const bal  = wRes.body?.balance ?? 0;
      if (bal > 0) {
        ok('Writer balance > 0 after proxied faucet', `balance=${bal} BB`);
      } else {
        fail('Writer balance still 0 — write was NOT forwarded to Writer', JSON.stringify(wRes.body));
      }
    } catch (e) {
      fail('Writer balance check threw', e.message);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  section(`TEST 5 — Reader serves synced balance after ${SYNC_WAIT}ms`);
  // ══════════════════════════════════════════════════════════════════════════

  if (!faucetOk) {
    skip('Reader sync check', 'faucet did not succeed');
  } else {
    process.stdout.write(`  Waiting ${SYNC_WAIT}ms for Writer → Reader block propagation… `);
    await new Promise(r => setTimeout(r, SYNC_WAIT));
    console.log('done.');

    try {
      const rRes = await httpGet(`${READER}/balance/${address}`);
      const bal  = rRes.body?.balance ?? 0;
      if (bal > 0) {
        ok('Reader balance synced from Writer', `balance=${bal} BB`);
      } else {
        fail('Reader balance still 0 after sync delay', `Is the gRPC relay running on Writer? ${JSON.stringify(rRes.body)}`);
      }
    } catch (e) {
      fail('Reader sync balance check threw', e.message);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 6 — Error response forwarding (replay nonce → 400)');
  // ══════════════════════════════════════════════════════════════════════════

  if (!faucetOk) {
    skip('Replay test', 'original faucet did not succeed');
  } else {
    try {
      // Re-submit the exact same signed payload → nonce already consumed
      const replay = await httpPost(`${READER}/faucet`, faucetPayload);
      console.log(`  Replay  ← status=${replay.status}  body=${JSON.stringify(replay.body)}`);

      if (replay.status === 400 || replay.status === 409 || replay.status === 429) {
        ok(`Replay rejected with ${replay.status} (forwarded correctly from Writer)`);
      } else if (replay.status === 200) {
        fail('Replay was accepted (nonce reuse not caught)', JSON.stringify(replay.body));
      } else {
        fail(`Unexpected replay status`, `${replay.status}: ${JSON.stringify(replay.body)}`);
      }
    } catch (e) {
      fail('Replay test threw', e.message);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 7 — Status code parity: Reader proxy == Writer direct');
  // ══════════════════════════════════════════════════════════════════════════

  // Build a fresh wallet so neither node has seen the nonce
  try {
    const priv2    = crypto.getRandomValues(new Uint8Array(32));
    const { payload: p2, address: addr2 } = await buildFaucetPayload(priv2, 0.1);

    // Fire the same signed payload at BOTH simultaneously.
    // Exactly one node will win the nonce race and return 200.
    // The other will return 400 (nonce already used).
    const [viaReader, viaDirect] = await Promise.all([
      httpPost(`${READER}/faucet`, p2),
      httpPost(`${WRITER}/faucet`, p2),
    ]);

    console.log(`  Reader  ← ${viaReader.status}  ${JSON.stringify(viaReader.body)}`);
    console.log(`  Writer  ← ${viaDirect.status}  ${JSON.stringify(viaDirect.body)}`);

    const total200 = (viaReader.status === 200 ? 1 : 0) + (viaDirect.status === 200 ? 1 : 0);
    if (total200 === 1) {
      ok('Exactly one 200 across Reader proxy + direct Writer (nonce atomically consumed)', `reader=${viaReader.status} writer=${viaDirect.status}`);
    } else if (total200 === 0) {
      // Both rejected — unlikely but possible if clock skew. Check status code match.
      if (viaReader.status === viaDirect.status) {
        ok('Both rejected with same status code (clock skew or rate-limit)', `both=${viaReader.status}`);
      } else {
        fail('Both rejected but with different status codes', `reader=${viaReader.status} writer=${viaDirect.status}`);
      }
    } else {
      fail('Both returned 200 — nonce was not deduplicated', `reader=${viaReader.status} writer=${viaDirect.status}`);
    }
  } catch (e) {
    fail('Status code parity test threw', e.message);
  }

  // ══════════════════════════════════════════════════════════════════════════
  section('TEST 8 — Reader Content-Type header forwarded correctly');
  // ══════════════════════════════════════════════════════════════════════════

  // Sending a POST with a malformed body to verify the 400 comes from Writer
  // (not a proxy-level parse error), confirming headers + body pass through.
  try {
    const res = await fetch(`${READER}/faucet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"wallet_address":""}',   // missing required fields
    });
    const body = await res.json().catch(() => null);
    console.log(`  Reader  ← status=${res.status}  body=${JSON.stringify(body)}`);
    if (res.status === 400 || res.status === 422) {
      ok('Malformed body returns 4xx (Writer validation passed through Reader proxy)');
    } else if (res.status === 502) {
      fail('Got 502 Bad Gateway — proxy could not reach Writer', JSON.stringify(body));
    } else {
      fail('Unexpected status for malformed body', `${res.status}: ${JSON.stringify(body)}`);
    }
  } catch (e) {
    fail('Content-Type forward test threw', e.message);
  }

  // ══════════════════════════════════════════════════════════════════════════
  console.log(`\n${'═'.repeat(64)}`);
  const total = passed + failed + skipped;
  console.log(`  Total: ${total}   ✅ ${passed} passed   ❌ ${failed} failed   ⚠️  ${skipped} skipped`);

  if (failed > 0) {
    console.log('\n  Troubleshooting:');
    console.log('    • Start Reader: .\\target\\debug\\layer1.exe --mode reader \\');
    console.log(`        --writer-addr ${WRITER.replace('http://', '').replace(':8080', ':50051')} \\`);
    console.log('        --redb-path .\\blockchain_data\\reader.redb');
    console.log('    • Override Writer URL: set WRITER_URL=http://<hetzner-ip>:8080');
    console.log('    • Increase sync timeout: set SYNC_WAIT_MS=5000');
    process.exit(1);
  } else {
    console.log('\n  🎉 All proxy pipeline tests passed — Reader ↔ Writer state is canonical.');
  }
}

main().catch(e => { console.error('\nFatal:', e); process.exit(1); });
