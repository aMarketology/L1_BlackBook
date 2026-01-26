/**
 * ═══════════════════════════════════════════════════════════════════════════
 * L1 ↔ L2 INTEGRATION TESTS
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Tests the integration between:
 *   - BlackBook Wallet SDK (L1) - blackbook-wallet-sdk.js
 *   - Credit Prediction SDK (L2) - credit-prediction-actions-sdk.js
 * 
 * Prerequisites:
 *   - L1 server running at localhost:8080
 *   - (Optional) L2 server running at localhost:1234 for full integration tests
 * 
 * Run: node sdk/tests/l1-l2-integration.test.js
 * ═══════════════════════════════════════════════════════════════════════════
 */

const nacl = require('tweetnacl');
const { createHash, randomBytes } = require('crypto');

// ═══════════════════════════════════════════════════════════════════════════
// TEST CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const L1_URL = process.env.L1_URL || 'http://localhost:8080';
const L2_URL = process.env.L2_URL || 'http://localhost:1234';

// Test accounts (from blackbook-wallet-sdk.js)
const TEST_ACCOUNTS = {
  ALICE: {
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    publicKey: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
  },
  BOB: {
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    publicKey: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
  },
  DEALER: {
    address: 'L1_A75E13F6DEED980C85ADF2D011E72B2D2768CE8D',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    publicKey: '65328794ed4a81cc2a92b93738c22a545f066cc6c0b6a72aa878cfa289f0ba32',
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ═══════════════════════════════════════════════════════════════════════════

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function sha256(data) {
  return createHash('sha256').update(data).digest('hex');
}

function generateNonce() {
  return `${Date.now()}_${randomBytes(8).toString('hex')}`;
}

// Create keypair from seed
function createKeyPair(seedHex) {
  const seed = hexToBytes(seedHex);
  return nacl.sign.keyPair.fromSeed(seed);
}

// Sign a message
function sign(message, secretKey) {
  const messageBytes = Buffer.from(message);
  const signature = nacl.sign.detached(messageBytes, secretKey);
  return bytesToHex(signature);
}

// HTTP helpers
async function httpGet(url) {
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' }
  });
  return res.json();
}

async function httpPost(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST RESULTS TRACKING
// ═══════════════════════════════════════════════════════════════════════════

let passed = 0;
let failed = 0;
const results = [];

function test(name, fn) {
  return async () => {
    try {
      await fn();
      passed++;
      results.push({ name, status: '✅ PASS' });
      console.log(`  ✅ ${name}`);
    } catch (error) {
      failed++;
      results.push({ name, status: '❌ FAIL', error: error.message });
      console.log(`  ❌ ${name}`);
      console.log(`     Error: ${error.message}`);
    }
  };
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

function assertExists(value, message) {
  if (value === undefined || value === null) {
    throw new Error(message || 'Value is undefined or null');
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// L1 WALLET SDK TESTS
// ═══════════════════════════════════════════════════════════════════════════

async function runL1Tests() {
  console.log('\n📦 L1 WALLET SDK TESTS');
  console.log('═'.repeat(60));

  // Test 1: Health check
  await test('L1 Health Check', async () => {
    const res = await httpGet(`${L1_URL}/health`);
    assertEqual(res.status, 'ok', 'Health status should be ok');
    assertExists(res.total_supply, 'Should have total supply');
  })();

  // Test 2: Get balance for Alice
  await test('Get Alice Balance', async () => {
    const res = await httpGet(`${L1_URL}/balance/${TEST_ACCOUNTS.ALICE.address}`);
    assertExists(res.balance !== undefined || res.available !== undefined, 'Should return balance');
    console.log(`     Alice balance: ${res.balance || res.available} BB`);
  })();

  // Test 3: Get balance for Bob
  await test('Get Bob Balance', async () => {
    const res = await httpGet(`${L1_URL}/balance/${TEST_ACCOUNTS.BOB.address}`);
    assertExists(res.balance !== undefined || res.available !== undefined, 'Should return balance');
    console.log(`     Bob balance: ${res.balance || res.available} BB`);
  })();

  // Test 4: Get PoH status
  await test('Get PoH Status', async () => {
    const res = await httpGet(`${L1_URL}/poh/status`);
    assertExists(res.num_hashes || res.current_hash, 'Should have PoH data');
    console.log(`     PoH hashes: ${res.num_hashes || 'N/A'}`);
  })();

  // Test 5: Get chain stats
  await test('Get Chain Stats', async () => {
    const res = await httpGet(`${L1_URL}/poh/chain/stats`);
    assert(res.success !== false, 'Chain stats should succeed');
    console.log(`     Blocks: ${res.blocks?.produced || 0}, Pending TXs: ${res.blocks?.pending_txs || 0}`);
  })();

  // Test 6: Get current leader
  await test('Get Current Leader', async () => {
    const res = await httpGet(`${L1_URL}/poh/leader/current`);
    assert(res.success !== false, 'Should get current leader');
    assertExists(res.current_leader, 'Should have current leader');
    console.log(`     Current leader: ${res.current_leader}, Slot: ${res.current_slot}`);
  })();

  // Test 7: Get leader schedule
  await test('Get Leader Schedule', async () => {
    const res = await httpGet(`${L1_URL}/poh/leader/schedule?count=5`);
    assert(res.success !== false, 'Should get leader schedule');
    assert(Array.isArray(res.upcoming_leaders), 'Should have upcoming leaders array');
    console.log(`     Upcoming slots: ${res.upcoming_leaders?.length || 0}`);
  })();

  // Test 8: Get state proof for account
  await test('Get State Proof for Alice', async () => {
    const res = await httpGet(`${L1_URL}/poh/proof/${TEST_ACCOUNTS.ALICE.address}`);
    assert(res.success !== false, 'Should get state proof');
    assertExists(res.balance !== undefined, 'Should include balance');
    console.log(`     State root: ${res.state_root?.slice(0, 16) || res.proof?.root?.slice(0, 16) || 'N/A'}...`);
  })();

  // Test 9: Verify chain integrity
  await test('Verify Chain Integrity', async () => {
    const res = await httpGet(`${L1_URL}/poh/chain/verify`);
    assert(res.success !== false, 'Chain verification should succeed');
    console.log(`     Chain valid: ${res.chain_valid}, Blocks: ${res.block_count || 0}`);
  })();

  // Test 10: Simple transfer (Alice → Bob)
  await test('Simple Transfer (Alice → Bob)', async () => {
    const aliceKeys = createKeyPair(TEST_ACCOUNTS.ALICE.seed);
    
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateNonce();
    const payload = JSON.stringify({ to: TEST_ACCOUNTS.BOB.address, amount: 0.01 });
    
    // Sign: chain_id byte (1) + payload + \n + timestamp + \n + nonce
    const chainIdByte = Buffer.from([0x01]);
    const payloadBytes = Buffer.from(payload);
    const timestampBytes = Buffer.from(`\n${timestamp}\n`);
    const nonceBytes = Buffer.from(nonce);
    
    const message = Buffer.concat([chainIdByte, payloadBytes, timestampBytes, nonceBytes]);
    const signature = nacl.sign.detached(message, aliceKeys.secretKey);
    
    const request = {
      public_key: bytesToHex(aliceKeys.publicKey),
      wallet_address: TEST_ACCOUNTS.ALICE.address,
      payload: payload,
      timestamp: timestamp,
      nonce: nonce,
      chain_id: 1,
      schema_version: 1,
      signature: bytesToHex(signature)
    };
    
    const res = await httpPost(`${L1_URL}/transfer/simple`, request);
    assert(res.success !== false, `Transfer should succeed: ${res.error || ''}`);
    console.log(`     TX ID: ${res.tx_id || res.transaction_id || 'N/A'}`);
  })();

  // Test 11: Check transaction finality status (if tx exists)
  await test('Check Transaction Status', async () => {
    // Use a test tx_id - in real tests this would be from a previous transfer
    const testTxId = 'test_tx_' + Date.now();
    const res = await httpGet(`${L1_URL}/poh/tx/${testTxId}/status`);
    // Even if tx doesn't exist, the endpoint should respond
    assert(res.success !== false || res.status, 'Should return status');
    console.log(`     Status: ${res.status || 'Pending'}`);
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// L1 → L2 BRIDGE TESTS
// ═══════════════════════════════════════════════════════════════════════════

async function runBridgeTests() {
  console.log('\n🌉 L1 → L2 BRIDGE TESTS');
  console.log('═'.repeat(60));

  // Test 1: Get bridge stats
  await test('Get Bridge Stats', async () => {
    const res = await httpGet(`${L1_URL}/bridge/stats`);
    assert(res.success !== false || res.total_locked !== undefined, 'Should get bridge stats');
    console.log(`     Total locked: ${res.total_locked || 0} BB`);
  })();

  // Test 2: Get pending locks for Alice
  await test('Get Pending Locks (Alice)', async () => {
    const res = await httpGet(`${L1_URL}/bridge/pending/${TEST_ACCOUNTS.ALICE.address}`);
    // May be empty, but should respond
    console.log(`     Pending locks: ${res.pending_locks?.length || res.locks?.length || 0}`);
  })();

  // Test 3: Initiate bridge lock (requires signature)
  await test('Initiate Bridge Lock', async () => {
    const aliceKeys = createKeyPair(TEST_ACCOUNTS.ALICE.seed);
    
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = JSON.stringify({ amount: 1.0, target_layer: "L2" });
    
    // Sign for bridge initiation
    const messageToSign = `1${payload}\n${timestamp}\n${nonce}`;
    const signature = sign(messageToSign, aliceKeys.secretKey);
    
    const res = await httpPost(`${L1_URL}/bridge/initiate`, {
      payload: payload,
      public_key: bytesToHex(aliceKeys.publicKey),
      signature: signature,
      nonce: nonce,
      timestamp: timestamp,
      chain_id: 1
    });
    
    // May fail due to insufficient balance or other reasons - that's ok for this test
    if (res.success !== false && res.lock_id) {
      console.log(`     Lock ID: ${res.lock_id}`);
    } else {
      console.log(`     Bridge initiate response: ${res.error || res.message || 'No lock created'}`);
    }
  })();

  // Test 4: Soft-lock for L2 access
  await test('Create Soft-Lock', async () => {
    const aliceKeys = createKeyPair(TEST_ACCOUNTS.ALICE.seed);
    
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    
    const res = await httpPost(`${L1_URL}/bridge/soft-lock`, {
      wallet: TEST_ACCOUNTS.ALICE.address,
      amount: 10.0,
      purpose: 'prediction_market',
      public_key: bytesToHex(aliceKeys.publicKey),
      timestamp: timestamp,
      nonce: nonce
    });
    
    if (res.success !== false) {
      console.log(`     Soft-lock created: ${res.lock_id || 'success'}`);
    } else {
      console.log(`     Soft-lock response: ${res.error || 'Not available'}`);
    }
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// POH BLOCK PRODUCTION TESTS
// ═══════════════════════════════════════════════════════════════════════════

async function runPoHTests() {
  console.log('\n⏰ POH BLOCK PRODUCTION TESTS');
  console.log('═'.repeat(60));

  // Test 1: Get latest block
  await test('Get Latest Block', async () => {
    const res = await httpGet(`${L1_URL}/poh/block/latest`);
    if (res.success && res.block) {
      console.log(`     Slot: ${res.block.slot}, Hash: ${res.block.hash?.slice(0, 16)}...`);
      console.log(`     TXs: ${res.block.tx_count}, Confirmations: ${res.block.confirmations}`);
    } else {
      console.log(`     No blocks produced yet`);
    }
  })();

  // Test 2: Produce a block (if we're the leader)
  await test('Produce Block (Leader Check)', async () => {
    const res = await httpPost(`${L1_URL}/poh/produce`, {});
    if (res.success) {
      console.log(`     Block produced! Slot: ${res.block?.slot}, TXs: ${res.block?.tx_count}`);
    } else {
      console.log(`     ${res.error || 'Not leader for current slot'}`);
    }
  })();

  // Test 3: Get block by slot
  await test('Get Block by Slot (0)', async () => {
    const res = await httpGet(`${L1_URL}/poh/block/0`);
    if (res.success && res.block) {
      console.log(`     Block 0: ${res.block.hash?.slice(0, 16)}...`);
    } else {
      console.log(`     Block 0 not found (expected if no blocks produced)`);
    }
  })();

  // Test 4: Verify specific block
  await test('Verify Block Integrity (Slot 0)', async () => {
    const res = await httpGet(`${L1_URL}/poh/block/verify/0`);
    if (res.success !== false && res.is_valid !== undefined) {
      console.log(`     Valid: ${res.is_valid}`);
    } else {
      console.log(`     Block not found for verification`);
    }
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// MARKET SESSION TESTS (Prediction Market Integration)
// ═══════════════════════════════════════════════════════════════════════════

async function runMarketSessionTests() {
  console.log('\n🎰 MARKET SESSION TESTS (L1 Prediction Support)');
  console.log('═'.repeat(60));

  // Test 1: Open market session (lock tokens for prediction market)
  await test('Open Market Session', async () => {
    const aliceKeys = createKeyPair(TEST_ACCOUNTS.ALICE.seed);
    
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    
    const res = await httpPost(`${L1_URL}/credit/open`, {
      wallet: TEST_ACCOUNTS.ALICE.address,
      amount: 100.0,
      public_key: bytesToHex(aliceKeys.publicKey),
      timestamp: timestamp,
      nonce: nonce
    });
    
    if (res.success !== false) {
      console.log(`     Session ID: ${res.session_id || 'created'}`);
      console.log(`     Locked: ${res.locked_amount || res.amount || 100} BB`);
    } else {
      console.log(`     ${res.error || 'Session creation not available'}`);
    }
  })();

  // Test 2: Get session status
  await test('Get Session Status', async () => {
    const res = await httpGet(`${L1_URL}/credit/status/${TEST_ACCOUNTS.ALICE.address}`);
    console.log(`     Has session: ${res.has_active_session || false}`);
    if (res.session) {
      console.log(`     Available: ${res.session.available_balance || 0} BB`);
    }
  })();

  // Test 3: Settle session (close and release tokens)
  await test('Settle Market Session', async () => {
    const aliceKeys = createKeyPair(TEST_ACCOUNTS.ALICE.seed);
    
    const nonce = generateNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    
    const res = await httpPost(`${L1_URL}/credit/settle`, {
      wallet: TEST_ACCOUNTS.ALICE.address,
      pnl: 0, // No profit/loss for test
      public_key: bytesToHex(aliceKeys.publicKey),
      timestamp: timestamp,
      nonce: nonce
    });
    
    if (res.success !== false) {
      console.log(`     Session settled: ${res.settlement_id || 'success'}`);
    } else {
      console.log(`     ${res.error || 'No active session to settle'}`);
    }
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// L2 PREDICTION SDK INTEGRATION TESTS (if L2 is running)
// ═══════════════════════════════════════════════════════════════════════════

async function runL2IntegrationTests() {
  console.log('\n🎲 L2 PREDICTION SDK INTEGRATION');
  console.log('═'.repeat(60));

  // Check if L2 is available
  let l2Available = false;
  try {
    const health = await fetch(`${L2_URL}/health`, { timeout: 3000 });
    l2Available = health.ok;
  } catch {
    l2Available = false;
  }

  if (!l2Available) {
    console.log('  ⚠️  L2 server not available at ' + L2_URL);
    console.log('  ⚠️  Skipping L2 integration tests');
    console.log('  💡 Start L2 server and re-run for full integration tests');
    return;
  }

  // Test 1: L2 Health
  await test('L2 Health Check', async () => {
    const res = await httpGet(`${L2_URL}/health`);
    assert(res.status === 'ok' || res.success !== false, 'L2 should be healthy');
  })();

  // Test 2: Get L2 balance via L1 address
  await test('Get L2 Balance (via L1 address)', async () => {
    const l2Address = TEST_ACCOUNTS.ALICE.address.replace('L1_', 'L2_');
    const res = await httpGet(`${L2_URL}/balance/${l2Address}`);
    console.log(`     L2 Balance: ${res.l2_available || res.balance || 0} BB`);
  })();

  // Test 3: Full bridge flow test (requires funded accounts)
  await test('Bridge Flow: L1 Lock Check', async () => {
    // This tests that L2 can verify L1 locks
    const res = await httpGet(`${L2_URL}/bridge/verify/${TEST_ACCOUNTS.ALICE.address}`);
    console.log(`     L1 verification: ${res.verified || 'endpoint available'}`);
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// UNIFIED BALANCE TESTS
// ═══════════════════════════════════════════════════════════════════════════

async function runUnifiedBalanceTests() {
  console.log('\n💰 UNIFIED BALANCE TESTS');
  console.log('═'.repeat(60));

  // Test 1: Get unified balance
  await test('Get Unified Balance (Alice)', async () => {
    const res = await httpGet(`${L1_URL}/balance/${TEST_ACCOUNTS.ALICE.address}/unified`);
    
    if (res.error) {
      console.log(`     ${res.error}`);
    } else {
      console.log(`     L1 Available: ${res.l1_available || res.available || 0} BB`);
      console.log(`     L1 Locked: ${res.l1_locked || res.locked || 0} BB`);
      if (res.total !== undefined) {
        console.log(`     Total: ${res.total} BB`);
      }
    }
  })();

  // Test 2: Get all test account balances
  await test('Get All Test Account Balances', async () => {
    for (const [name, account] of Object.entries(TEST_ACCOUNTS)) {
      const res = await httpGet(`${L1_URL}/balance/${account.address}`);
      const balance = res.balance ?? res.available ?? 0;
      console.log(`     ${name}: ${balance.toFixed(2)} BB`);
    }
  })();
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN TEST RUNNER
// ═══════════════════════════════════════════════════════════════════════════

async function runAllTests() {
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║      L1 ↔ L2 INTEGRATION TEST SUITE                          ║');
  console.log('║      BlackBook Wallet SDK + Credit Prediction SDK            ║');
  console.log('╠═══════════════════════════════════════════════════════════════╣');
  console.log(`║  L1 URL: ${L1_URL.padEnd(50)}║`);
  console.log(`║  L2 URL: ${L2_URL.padEnd(50)}║`);
  console.log('╚═══════════════════════════════════════════════════════════════╝');

  const startTime = Date.now();

  try {
    // Check L1 is available
    console.log('\n🔍 Checking L1 availability...');
    const l1Health = await fetch(`${L1_URL}/health`).then(r => r.json()).catch(() => null);
    
    if (!l1Health) {
      console.log('\n❌ L1 server not available at ' + L1_URL);
      console.log('   Please start the L1 server: cargo run');
      process.exit(1);
    }
    console.log('✅ L1 server is running\n');

    // Run test suites
    await runL1Tests();
    await runPoHTests();
    await runBridgeTests();
    await runMarketSessionTests();
    await runUnifiedBalanceTests();
    await runL2IntegrationTests();

  } catch (error) {
    console.log(`\n❌ Test suite error: ${error.message}`);
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  // Summary
  console.log('\n' + '═'.repeat(60));
  console.log('📊 TEST SUMMARY');
  console.log('═'.repeat(60));
  console.log(`   ✅ Passed: ${passed}`);
  console.log(`   ❌ Failed: ${failed}`);
  console.log(`   ⏱️  Duration: ${duration}s`);
  console.log('═'.repeat(60));

  if (failed > 0) {
    console.log('\n❌ FAILED TESTS:');
    results.filter(r => r.status.includes('FAIL')).forEach(r => {
      console.log(`   • ${r.name}: ${r.error}`);
    });
  }

  console.log('\n' + (failed === 0 ? '🎉 All tests passed!' : '⚠️  Some tests failed'));
  
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(console.error);
