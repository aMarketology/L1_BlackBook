// ============================================================================
// BLACKBOOK L1 — TRANSACTION FLOOD TEST
// ============================================================================
//
// Generates real Ed25519 keypairs and floods the chain with properly-signed
// transactions to stress test:
//
//   1. Faucet drip (signed)
//   2. Admin mint (fund test wallets)
//   3. Transfer (signed Ed25519)
//   4. Gulf Stream / Sealevel (signed)
//   5. Concurrent load
//
// Run:  node sdk/flood_test.mjs
// ============================================================================

import { webcrypto } from 'crypto';

const API  = process.env.API_URL || 'http://localhost:8080';
const RPC  = process.env.RPC_URL || 'http://localhost:8899';

const C = {
  reset: '\x1b[0m', green: '\x1b[32m', red: '\x1b[31m',
  yellow: '\x1b[33m', cyan: '\x1b[36m', bold: '\x1b[1m', dim: '\x1b[2m',
};

let passed = 0, failed = 0;

// ============================================================================
// ED25519 CRYPTO (using Node.js native)
// ============================================================================

async function generateKeypair() {
  const keyPair = await webcrypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const privRaw = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const pubRaw  = new Uint8Array(await webcrypto.subtle.exportKey('raw', keyPair.publicKey));
  // PKCS8 for Ed25519: last 32 bytes are the secret key seed
  const seed = privRaw.slice(privRaw.length - 32);
  return {
    publicKey: pubRaw,
    privateKey: keyPair.privateKey,
    pubHex: toHex(pubRaw),
    seedHex: toHex(seed),
  };
}

async function sign(privateKey, message) {
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const sig = new Uint8Array(await webcrypto.subtle.sign('Ed25519', privateKey, msgBytes));
  return toHex(sig);
}

function toHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function uuid() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
    const r = Math.random() * 16 | 0;
    return (c === 'x' ? r : (r & 0x3 | 0x8)).toString(16);
  });
}

// ============================================================================
// HTTP HELPERS
// ============================================================================

async function get(path) {
  const r = await fetch(`${API}${path}`);
  return { status: r.status, data: await r.json() };
}

async function post(path, body) {
  const r = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await r.text();
  try { return { status: r.status, data: JSON.parse(text) }; }
  catch { return { status: r.status, data: { raw: text } }; }
}

function test(name, ok, detail = '') {
  if (ok) { passed++; console.log(`${C.green}  ✓${C.reset} ${name} ${C.dim}${detail}${C.reset}`); }
  else    { failed++; console.log(`${C.red}  ✗${C.reset} ${name} ${C.yellow}${detail}${C.reset}`); }
}

function section(t) { console.log(`\n${C.cyan}${C.bold}═══ ${t} ═══${C.reset}`); }

// ============================================================================
// PHASE 1: FUND WALLETS VIA ADMIN MINT
// ============================================================================

async function fundWallets(keypairs) {
  section('PHASE 1: FUND WALLETS (admin/mint)');
  let funded = 0;
  const amount = 10000.0;

  const results = await Promise.all(keypairs.map(kp =>
    post('/admin/mint', { to: kp.pubHex, amount, dealer_signature: 'stress_test' })
  ));

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r.data.success) {
      funded++;
    } else {
      console.log(`${C.red}    Mint failed for wallet ${i}: ${JSON.stringify(r.data)}${C.reset}`);
    }
  }

  test(`Funded ${funded}/${keypairs.length} wallets with ${amount} BB each`, funded === keypairs.length);

  // Verify balances
  const bal = await get(`/balance/${keypairs[0].pubHex}`);
  test(`Wallet 0 balance = ${bal.data.balance}`, parseFloat(bal.data.balance) === amount, bal.data.balance);

  return funded;
}

// ============================================================================
// PHASE 2: SIGNED TRANSFERS
// ============================================================================

async function floodTransfers(keypairs, count) {
  section(`PHASE 2: SIGNED TRANSFERS (${count} txs)`);

  let success = 0, errors = 0;
  const errorMap = {};
  const start = Date.now();

  for (let i = 0; i < count; i++) {
    const fromIdx = i % keypairs.length;
    const toIdx = (i + 1) % keypairs.length;
    const kp = keypairs[fromIdx];
    const recipient = keypairs[toIdx].pubHex;
    const amount = 0.01;
    const nonce = uuid();
    const timestamp = Math.floor(Date.now() / 1000);

    const payload = JSON.stringify({ to: recipient, amount });
    const chainId = 0xBB;

    // Build message: [chainId][payload]\n[timestamp]\n[nonce]
    const msgParts = new Uint8Array([
      chainId,
      ...new TextEncoder().encode(payload),
      ...new TextEncoder().encode('\n'),
      ...new TextEncoder().encode(timestamp.toString()),
      ...new TextEncoder().encode('\n'),
      ...new TextEncoder().encode(nonce),
    ]);

    const sigHex = await sign(kp.privateKey, msgParts);

    const r = await post('/transfer/simple', {
      public_key: kp.pubHex,
      wallet_address: kp.pubHex,
      payload,
      timestamp,
      nonce,
      chain_id: chainId,
      signature: sigHex,
    });

    if (r.data.success) {
      success++;
    } else {
      errors++;
      const errMsg = r.data.error || 'unknown';
      errorMap[errMsg] = (errorMap[errMsg] || 0) + 1;
      if (errors <= 3) console.log(`${C.yellow}    Error ${i}: ${errMsg}${C.reset}`);
    }
  }

  const elapsed = Date.now() - start;
  const tps = Math.round(success / (elapsed / 1000));

  test(`Transfers: ${success}/${count} succeeded`, success > 0, `${tps} TPS`);
  if (Object.keys(errorMap).length > 0) {
    console.log(`${C.yellow}    Error breakdown:${C.reset}`);
    for (const [err, cnt] of Object.entries(errorMap)) {
      console.log(`${C.yellow}      ${cnt}x: ${err.slice(0, 100)}${C.reset}`);
    }
  }

  return { success, errors, tps, elapsed };
}

// ============================================================================
// PHASE 3: GULF STREAM / SEALEVEL SUBMIT
// ============================================================================

async function floodSealevel(keypairs, count) {
  section(`PHASE 3: SEALEVEL/GULF STREAM (${count} txs)`);

  let success = 0, errors = 0;
  const errorMap = {};
  const start = Date.now();

  for (let i = 0; i < count; i++) {
    const fromIdx = i % keypairs.length;
    const toIdx = (i + 1) % keypairs.length;
    const kp = keypairs[fromIdx];
    const to = keypairs[toIdx].pubHex;
    const amount = 0.001;
    const nonce = uuid();
    const timestamp = Math.floor(Date.now() / 1000);

    const message = `SEALEVEL:${kp.pubHex}:${to}:${amount}:${timestamp}:${nonce}`;
    const sigHex = await sign(kp.privateKey, message);

    const r = await post('/sealevel/submit', {
      from: kp.pubHex,
      to,
      amount,
      signature: sigHex,
      timestamp,
      nonce,
    });

    if (r.data.success) {
      success++;
    } else {
      errors++;
      const errMsg = r.data.error || 'unknown';
      errorMap[errMsg] = (errorMap[errMsg] || 0) + 1;
      if (errors <= 3) console.log(`${C.yellow}    Error ${i}: ${errMsg}${C.reset}`);
    }
  }

  const elapsed = Date.now() - start;
  const tps = Math.round(success / (elapsed / 1000));

  test(`Sealevel: ${success}/${count} succeeded`, success > 0, `${tps} TPS`);
  if (Object.keys(errorMap).length > 0) {
    console.log(`${C.yellow}    Error breakdown:${C.reset}`);
    for (const [err, cnt] of Object.entries(errorMap)) {
      console.log(`${C.yellow}      ${cnt}x: ${err.slice(0, 100)}${C.reset}`);
    }
  }

  return { success, errors, tps, elapsed };
}

// ============================================================================
// PHASE 4: CONCURRENT BURST
// ============================================================================

async function concurrentBurst(keypairs, burstSize) {
  section(`PHASE 4: CONCURRENT BURST (${burstSize} simultaneous)`);

  const start = Date.now();
  let success = 0, errors = 0;

  const promises = [];
  for (let i = 0; i < burstSize; i++) {
    const fromIdx = i % keypairs.length;
    const toIdx = (i + 1) % keypairs.length;
    const kp = keypairs[fromIdx];
    const to = keypairs[toIdx].pubHex;
    const amount = 0.001;
    const nonce = uuid();
    const timestamp = Math.floor(Date.now() / 1000);

    const payload = JSON.stringify({ to, amount });
    const chainId = 0xBB;
    const msgParts = new Uint8Array([
      chainId,
      ...new TextEncoder().encode(payload),
      ...new TextEncoder().encode('\n'),
      ...new TextEncoder().encode(timestamp.toString()),
      ...new TextEncoder().encode('\n'),
      ...new TextEncoder().encode(nonce),
    ]);

    promises.push(
      sign(kp.privateKey, msgParts).then(sigHex =>
        post('/transfer/simple', {
          public_key: kp.pubHex,
          wallet_address: kp.pubHex,
          payload,
          timestamp,
          nonce,
          chain_id: chainId,
          signature: sigHex,
        })
      ).then(r => {
        if (r.data.success) success++;
        else errors++;
      }).catch(() => errors++)
    );
  }

  await Promise.all(promises);
  const elapsed = Date.now() - start;
  const tps = Math.round(success / (elapsed / 1000));

  test(`Burst: ${success}/${burstSize} succeeded`, success > 0, `${tps} TPS in ${elapsed}ms`);
  return { success, errors, tps, elapsed };
}

// ============================================================================
// PHASE 5: VERIFY ON-CHAIN STATE
// ============================================================================

async function verifyChainState(keypairs) {
  section('PHASE 5: VERIFY ON-CHAIN STATE');

  // Check PoH is still running
  const poh = await get('/poh/status');
  test('PoH still running after flood', poh.data.is_running === true, `slot ${poh.data.current_slot}`);

  // Check latest block has transactions
  const latest = await get('/poh/block/latest');
  if (latest.data.success && latest.data.block) {
    const b = latest.data.block;
    test(`Latest block slot=${b.slot}`, true, `tx_count=${b.tx_count}, leader=${b.leader}`);
    test('Block has transactions', b.tx_count > 0, `${b.tx_count} txs`);

    // Fetch with full tx details
    const full = await get(`/poh/block/${b.slot}`);
    if (full.data.block?.transactions) {
      test('Block has transaction details', full.data.block.transactions.length > 0,
           `${full.data.block.transactions.length} txs with hashes`);
    }
  }

  // Turbine still working
  const turbine = await get('/turbine/status');
  test('Turbine still active', turbine.data.data_shreds > 0,
       `${turbine.data.data_shreds} data + ${turbine.data.fec_shreds} FEC shreds`);

  // Tower BFT
  const tower = await get('/consensus/tower');
  test('Tower BFT responding', tower.status === 200);

  // Verify balances changed
  let totalBal = 0;
  for (const kp of keypairs) {
    const b = await get(`/balance/${kp.pubHex}`);
    totalBal += parseFloat(b.data.balance) || 0;
  }
  test('Total balance across wallets > 0', totalBal > 0, `${totalBal.toFixed(2)} BB`);

  // Check ledger has entries
  // (Ledger validation handled separately — skipping in flood test)

  // Stats
  const stats = await get('/stats');
  test('Stats endpoint healthy', stats.status === 200);

  return { totalBal };
}

// ============================================================================
// PHASE 6: SUSTAINED LOAD (30 seconds)
// ============================================================================

async function sustainedLoad(keypairs, durationSec) {
  section(`PHASE 6: SUSTAINED LOAD (${durationSec}s)`);

  const start = Date.now();
  const end = start + (durationSec * 1000);
  let totalSent = 0, totalSuccess = 0, totalErrors = 0;
  let batchNum = 0;

  while (Date.now() < end) {
    batchNum++;
    const batchSize = 20;
    const promises = [];

    for (let i = 0; i < batchSize; i++) {
      const fromIdx = (totalSent + i) % keypairs.length;
      const toIdx = (totalSent + i + 1) % keypairs.length;
      const kp = keypairs[fromIdx];
      const to = keypairs[toIdx].pubHex;
      const amount = 0.001;
      const nonce = uuid();
      const timestamp = Math.floor(Date.now() / 1000);

      const payload = JSON.stringify({ to, amount });
      const chainId = 0xBB;
      const msgParts = new Uint8Array([
        chainId,
        ...new TextEncoder().encode(payload),
        ...new TextEncoder().encode('\n'),
        ...new TextEncoder().encode(timestamp.toString()),
        ...new TextEncoder().encode('\n'),
        ...new TextEncoder().encode(nonce),
      ]);

      promises.push(
        sign(kp.privateKey, msgParts).then(sigHex =>
          post('/transfer/simple', {
            public_key: kp.pubHex,
            wallet_address: kp.pubHex,
            payload,
            timestamp,
            nonce,
            chain_id: chainId,
            signature: sigHex,
          })
        ).then(r => {
          if (r.data.success) totalSuccess++;
          else totalErrors++;
        }).catch(() => totalErrors++)
      );
    }

    totalSent += batchSize;
    await Promise.all(promises);

    // Progress every 5 batches
    if (batchNum % 5 === 0) {
      const elapsed = ((Date.now() - start) / 1000).toFixed(1);
      const currentTps = Math.round(totalSuccess / (elapsed));
      process.stdout.write(`\r  📊 ${elapsed}s: ${totalSent} sent, ${totalSuccess} ok, ${totalErrors} err, ~${currentTps} TPS`);
    }
  }

  const elapsed = (Date.now() - start) / 1000;
  const tps = Math.round(totalSuccess / elapsed);
  console.log('');  // newline after \r
  test(`Sustained: ${totalSuccess}/${totalSent} in ${elapsed.toFixed(1)}s`, totalSuccess > 0, `${tps} TPS avg`);

  return { totalSent, totalSuccess, totalErrors, tps, elapsed };
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log(`${C.bold}
╔═══════════════════════════════════════════════════════════════════╗
║           BLACKBOOK L1 — TRANSACTION FLOOD TEST                   ║
║           API: ${API.padEnd(20)}  RPC: ${RPC.padEnd(20)}          ║
╚═══════════════════════════════════════════════════════════════════╝
${C.reset}`);

  // Connectivity check
  const health = await get('/health').catch(() => null);
  if (!health || health.status !== 200) {
    console.log(`${C.red}Server not reachable at ${API}. Start with: cargo run${C.reset}`);
    process.exit(1);
  }
  console.log(`${C.green}Server is up: ${JSON.stringify(health.data)}${C.reset}`);

  // Generate wallets
  section('KEYPAIR GENERATION');
  const NUM_WALLETS = 10;
  console.log(`  Generating ${NUM_WALLETS} Ed25519 keypairs...`);
  const keypairs = [];
  for (let i = 0; i < NUM_WALLETS; i++) {
    keypairs.push(await generateKeypair());
  }
  console.log(`  ${C.green}✓${C.reset} ${keypairs.length} wallets ready`);
  console.log(`  ${C.dim}Wallet 0: ${keypairs[0].pubHex.slice(0, 16)}...${C.reset}`);

  // Run phases
  await fundWallets(keypairs);
  const transfers = await floodTransfers(keypairs, 50);
  const sealevel  = await floodSealevel(keypairs, 30);
  const burst     = await concurrentBurst(keypairs, 100);
  const chain     = await verifyChainState(keypairs);
  const sustained = await sustainedLoad(keypairs, 15);

  // Final verification
  section('FINAL CHAIN STATE');
  const finalPoh = await get('/poh/status');
  const finalBlock = await get('/poh/block/latest');
  console.log(`  PoH slot: ${finalPoh.data.current_slot}`);
  console.log(`  Latest block: slot=${finalBlock.data.block?.slot}, txs=${finalBlock.data.block?.tx_count}`);

  // Summary
  console.log(`\n${C.bold}═══════════════════════════════════════════════════════════════════${C.reset}`);
  console.log(`${C.bold}FLOOD TEST SUMMARY${C.reset}`);
  console.log(`  ${C.green}Passed: ${passed}${C.reset}`);
  console.log(`  ${C.red}Failed: ${failed}${C.reset}`);
  console.log(`  Total tests: ${passed + failed}`);
  console.log('');
  console.log(`  Transfers:  ${transfers.success}/${50} @ ${transfers.tps} TPS`);
  console.log(`  Sealevel:   ${sealevel.success}/${30} @ ${sealevel.tps} TPS`);
  console.log(`  Burst:      ${burst.success}/${100} @ ${burst.tps} TPS`);
  console.log(`  Sustained:  ${sustained.totalSuccess}/${sustained.totalSent} @ ${sustained.tps} TPS (${sustained.elapsed.toFixed(1)}s)`);
  console.log(`${C.bold}═══════════════════════════════════════════════════════════════════${C.reset}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(e); process.exit(1); });
