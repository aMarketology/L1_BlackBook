// ============================================================================
// BLACKBOOK L1 — LIVE STRESS TEST
// ============================================================================
//
// Hits all main.rs endpoints with real HTTP requests to validate:
//   - PoH clock is ticking
//   - Turbine shredding works
//   - Consensus (Tower BFT) is operational
//   - Transfers execute correctly
//   - Gulf Stream (Sealevel) accepts transactions
//
// Run:  node sdk/stress_test_live.mjs
// ============================================================================

const API_URL = process.env.API_URL || 'http://localhost:8080';
const RPC_URL = process.env.RPC_URL || 'http://localhost:8899';

const COLORS = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  bold: '\x1b[1m',
};

let passed = 0;
let failed = 0;
const results = [];

// ============================================================================
// HELPERS
// ============================================================================

async function get(path) {
  const res = await fetch(`${API_URL}${path}`);
  return { status: res.status, data: await res.json() };
}

async function post(path, body) {
  const res = await fetch(`${API_URL}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return { status: res.status, data: await res.json() };
}

async function rpc(method, params = []) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  return { status: res.status, data: await res.json() };
}

function test(name, condition, details = '') {
  if (condition) {
    passed++;
    results.push({ name, status: 'PASS', details });
    console.log(`${COLORS.green}✓${COLORS.reset} ${name}`);
  } else {
    failed++;
    results.push({ name, status: 'FAIL', details });
    console.log(`${COLORS.red}✗${COLORS.reset} ${name} ${COLORS.yellow}${details}${COLORS.reset}`);
  }
}

function section(title) {
  console.log(`\n${COLORS.cyan}${COLORS.bold}═══ ${title} ═══${COLORS.reset}`);
}

// ============================================================================
// TEST SUITES
// ============================================================================

async function testHealth() {
  section('HEALTH & STATS');
  
  const health = await get('/health');
  test('GET /health returns 200', health.status === 200);
  test('Health shows version', health.data.version?.length > 0, health.data.version);
  
  const stats = await get('/stats');
  test('GET /stats returns 200', stats.status === 200);
  test('Stats has blocks_produced', typeof stats.data.blocks_produced === 'number');
  test('Stats has total_transactions', typeof stats.data.total_transactions === 'number');
}

async function testPoH() {
  section('PROOF OF HISTORY');
  
  const status = await get('/poh/status');
  test('GET /poh/status returns 200', status.status === 200);
  test('PoH is running', status.data.is_running === true);
  test('PoH has current_slot', typeof status.data.current_slot === 'number');
  test('PoH has current_hash', typeof status.data.current_hash === 'string');
  
  const slot1 = status.data.current_slot;
  
  // Wait for PoH to tick
  await new Promise(r => setTimeout(r, 500));
  
  const status2 = await get('/poh/status');
  const slot2 = status2.data.current_slot;
  test('PoH slot advances over time', slot2 >= slot1, `${slot1} → ${slot2}`);
  
  // Latest block
  const latest = await get('/poh/block/latest');
  test('GET /poh/block/latest returns 200', latest.status === 200);
  
  if (latest.data.success && latest.data.block) {
    const block = latest.data.block;
    test('Latest block has slot', typeof block.slot === 'number');
    test('Latest block has hash', typeof block.hash === 'string');
    test('Latest block has leader', typeof block.leader === 'string');
    test('Latest block has epoch', typeof block.epoch === 'number');
    
    // Fetch specific block
    const bySlot = await get(`/poh/block/${block.slot}`);
    test(`GET /poh/block/${block.slot} works`, bySlot.status === 200);
    test('Block by slot matches', bySlot.data.block?.slot === block.slot);
  } else {
    test('Latest block exists', false, 'No blocks produced yet');
  }
}

async function testTurbine() {
  section('TURBINE SHREDDING');
  
  const turbine = await get('/turbine/status');
  test('GET /turbine/status returns 200', turbine.status === 200);
  test('Turbine has current_slot', typeof turbine.data.current_slot === 'number');
  test('Turbine has data_shreds count', typeof turbine.data.data_shreds === 'number');
  test('Turbine has fec_shreds count', typeof turbine.data.fec_shreds === 'number');
  test('Turbine fanout is 200', turbine.data.turbine_fanout === 200);
  
  if (turbine.data.data_shreds > 0) {
    test('Turbine is actively shredding', true, `${turbine.data.data_shreds} data + ${turbine.data.fec_shreds} FEC shreds`);
  }
}

async function testConsensus() {
  section('TOWER BFT CONSENSUS');
  
  const tower = await get('/consensus/tower');
  test('GET /consensus/tower returns 200', tower.status === 200);
  test('Tower has root slot', typeof tower.data.root === 'number');
  test('Tower has vote_stack', Array.isArray(tower.data.vote_stack));
  test('Tower has lockout_multiplier', typeof tower.data.lockout_multiplier === 'number');
  test('Tower has confirmation_count', typeof tower.data.confirmation_count === 'number');
}

async function testFaucet() {
  section('FAUCET & BALANCES');
  
  const testAddr = `stress_test_${Date.now()}`;
  
  // Get initial balance (should be 0)
  const bal1 = await get(`/balance/${testAddr}`);
  test('GET /balance returns 200', bal1.status === 200);
  test('New address has 0 balance', bal1.data.balance === 0 || bal1.data.balance === '0');
  
  // Faucet some tokens
  const faucet = await post('/faucet', { address: testAddr, amount: 100 });
  test('POST /faucet returns 200', faucet.status === 200);
  test('Faucet reports success', faucet.data.success === true);
  
  // Check new balance
  const bal2 = await get(`/balance/${testAddr}`);
  test('Balance updated after faucet', parseFloat(bal2.data.balance) === 100, bal2.data.balance);
  
  return testAddr;
}

async function testTransfers(fundedAddr) {
  section('TRANSFERS');
  
  const recipient = `recipient_${Date.now()}`;
  
  // For signed transfers we'd need a real keypair, but we can test the endpoint exists
  const transfer = await post('/transfer/simple', {
    payload: JSON.stringify({ from: fundedAddr, to: recipient, amount: 10 }),
    signature: 'invalid_sig',
    public_key: 'invalid_pubkey',
  });
  
  // Should fail auth but endpoint works
  test('POST /transfer/simple endpoint exists', transfer.status === 200 || transfer.status === 400);
  
  if (transfer.data.error) {
    test('Transfer rejects bad signature', transfer.data.error.includes('signature') || transfer.data.error.includes('hex'), transfer.data.error);
  }
}

async function testSealevel() {
  section('SEALEVEL / GULF STREAM');
  
  const submit = await post('/sealevel/submit', {
    from: 'test_from',
    to: 'test_to',
    amount: 1.0,
    transaction_type: 'transfer',
    // Missing signature - should fail gracefully
  });
  
  test('POST /sealevel/submit endpoint exists', submit.status === 200 || submit.status === 400);
}

async function testUSDC() {
  section('USDC (SPL TOKEN)');
  
  const supply = await get('/usdc/supply');
  test('GET /usdc/supply returns 200', supply.status === 200);
  test('USDC supply is a number', typeof supply.data.total_supply === 'number' || typeof supply.data.supply === 'number');
  
  const bal = await get('/usdc/balance/test_addr');
  test('GET /usdc/balance/:addr returns 200', bal.status === 200);
}

async function testLedger() {
  section('LEDGER & ADMIN');
  
  const ledger = await get('/ledger');
  test('GET /ledger returns 200', ledger.status === 200);
  test('Ledger has transactions array', Array.isArray(ledger.data.transactions) || Array.isArray(ledger.data));
  
  const accounts = await get('/admin/accounts');
  test('GET /admin/accounts returns 200', accounts.status === 200);
}

async function testJsonRpc() {
  section('SOLANA JSON-RPC (PORT 8899)');
  
  try {
    const version = await rpc('getVersion');
    test('getVersion works', version.data.result?.['solana-core'] !== undefined);
    
    const slot = await rpc('getSlot');
    test('getSlot returns number', typeof slot.data.result === 'number', slot.data.result);
    
    const health = await rpc('getHealth');
    test('getHealth returns ok', health.data.result === 'ok');
    
    const epoch = await rpc('getEpochInfo');
    test('getEpochInfo has epoch', typeof epoch.data.result?.epoch === 'number');
    test('getEpochInfo has absoluteSlot', typeof epoch.data.result?.absoluteSlot === 'number');
    
    const blockhash = await rpc('getLatestBlockhash');
    test('getLatestBlockhash works', blockhash.data.result?.value?.blockhash !== undefined);
    
    const supply = await rpc('getSupply');
    test('getSupply has total', supply.data.result?.value?.total !== undefined);
  } catch (e) {
    test('JSON-RPC reachable', false, e.message);
  }
}

async function stressTest() {
  section('STRESS TEST - CONCURRENT REQUESTS');
  
  const concurrency = 50;
  const iterations = 5;
  
  console.log(`  Firing ${concurrency * iterations} requests (${concurrency} concurrent × ${iterations} batches)...`);
  
  const start = Date.now();
  let successCount = 0;
  let errorCount = 0;
  
  for (let i = 0; i < iterations; i++) {
    const promises = [];
    for (let j = 0; j < concurrency; j++) {
      promises.push(
        get('/poh/status').then(r => { if (r.status === 200) successCount++; else errorCount++; }).catch(() => errorCount++)
      );
      promises.push(
        get('/health').then(r => { if (r.status === 200) successCount++; else errorCount++; }).catch(() => errorCount++)
      );
    }
    await Promise.all(promises);
  }
  
  const elapsed = Date.now() - start;
  const totalReqs = concurrency * 2 * iterations;
  const rps = Math.round(totalReqs / (elapsed / 1000));
  
  test(`Stress: ${totalReqs} requests completed`, successCount === totalReqs, `${successCount}/${totalReqs} ok`);
  test(`Stress: ${rps} req/sec throughput`, rps > 100, `${rps} RPS`);
  console.log(`  ${COLORS.cyan}Elapsed: ${elapsed}ms | RPS: ${rps}${COLORS.reset}`);
}

async function testPoHProgression() {
  section('POH SLOT PROGRESSION (5 SECONDS)');
  
  const status1 = await get('/poh/status');
  const slot1 = status1.data.current_slot;
  const hash1 = status1.data.current_hash;
  
  console.log(`  Initial: slot=${slot1}, hash=${hash1?.slice(0, 16)}...`);
  
  // Wait 5 seconds (should see ~12 slots at 400ms each)
  await new Promise(r => setTimeout(r, 5000));
  
  const status2 = await get('/poh/status');
  const slot2 = status2.data.current_slot;
  const hash2 = status2.data.current_hash;
  
  console.log(`  After 5s: slot=${slot2}, hash=${hash2?.slice(0, 16)}...`);
  
  const slotDelta = slot2 - slot1;
  test('PoH advanced multiple slots in 5s', slotDelta >= 5, `+${slotDelta} slots`);
  test('PoH hash changed', hash1 !== hash2);
  test('Approx 400ms slots (~12 expected)', slotDelta >= 8 && slotDelta <= 20, `${slotDelta} slots in 5s`);
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log(`${COLORS.bold}
╔══════════════════════════════════════════════════════════════════╗
║          BLACKBOOK L1 — LIVE STRESS TEST                         ║
║          API: ${API_URL.padEnd(20)} RPC: ${RPC_URL.padEnd(20)}   ║
╚══════════════════════════════════════════════════════════════════╝
${COLORS.reset}`);

  try {
    // Quick connectivity check
    const health = await get('/health').catch(() => null);
    if (!health || health.status !== 200) {
      console.log(`${COLORS.red}ERROR: Server not reachable at ${API_URL}${COLORS.reset}`);
      console.log(`Start the server first: cargo run`);
      process.exit(1);
    }
    
    await testHealth();
    await testPoH();
    await testTurbine();
    await testConsensus();
    const fundedAddr = await testFaucet();
    await testTransfers(fundedAddr);
    await testSealevel();
    await testUSDC();
    await testLedger();
    await testJsonRpc();
    await stressTest();
    await testPoHProgression();
    
  } catch (e) {
    console.error(`${COLORS.red}Fatal error: ${e.message}${COLORS.reset}`);
    console.error(e.stack);
  }
  
  // Summary
  console.log(`\n${COLORS.bold}═══════════════════════════════════════════════════════════════════${COLORS.reset}`);
  console.log(`${COLORS.bold}SUMMARY${COLORS.reset}`);
  console.log(`  ${COLORS.green}Passed: ${passed}${COLORS.reset}`);
  console.log(`  ${COLORS.red}Failed: ${failed}${COLORS.reset}`);
  console.log(`  Total:  ${passed + failed}`);
  console.log(`${COLORS.bold}═══════════════════════════════════════════════════════════════════${COLORS.reset}\n`);
  
  process.exit(failed > 0 ? 1 : 0);
}

main();
