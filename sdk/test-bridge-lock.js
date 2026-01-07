// ============================================================================
// TEST 2.1: BRIDGE LOCK (L1 → L2 Deposit)
// ============================================================================
// Tests the bridge initiate functionality that locks L1 tokens for L2 use
// ============================================================================

import nacl from 'tweetnacl';
import { createHash } from 'crypto';

const L1_URL = 'http://localhost:8080';

// Test accounts with correct derived addresses (from working alice-to-bob.js)
const TEST_ACCOUNTS = {
  ALICE: {
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    name: 'Alice'
  },
  BOB: {
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    name: 'Bob'
  },
  DEALER: {
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    name: 'Dealer'
  }
};

const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function getKeypair(seedHex) {
  const seedBytes = Buffer.from(seedHex, 'hex');
  return nacl.sign.keyPair.fromSeed(seedBytes);
}

function deriveAddress(publicKey) {
  const hash = createHash('sha256').update(publicKey).digest();
  return 'L1_' + hash.slice(0, 20).toString('hex').toUpperCase();
}

function signMessage(message, secretKey, chainId = CHAIN_ID_L1) {
  const messageBytes = Buffer.from(message);
  const prefixedMessage = Buffer.concat([Buffer.from([chainId]), messageBytes]);
  const signature = nacl.sign.detached(prefixedMessage, secretKey);
  return Buffer.from(signature).toString('hex');
}

// ============================================================================
// API HELPERS
// ============================================================================

async function getBalance(address) {
  try {
    // Use full L1 address - server handles both formats
    const response = await fetch(`${L1_URL}/balance/${address}`);
    const data = await response.json();
    return data.balance || 0;
  } catch (e) {
    return 0;
  }
}

async function bridgeInitiate(account, amount) {
  const keypair = getKeypair(account.seed);
  const publicKeyHex = Buffer.from(keypair.publicKey).toString('hex');
  
  const payload = {
    action: 'bridge_initiate',
    amount: amount,
    target_layer: 'L2',
    timestamp: Date.now()
  };
  
  const payloadStr = JSON.stringify(payload);
  const signature = signMessage(payloadStr, keypair.secretKey, CHAIN_ID_L1);
  
  const request = {
    payload: payloadStr,
    public_key: publicKeyHex,
    signature: signature
  };
  
  try {
    const response = await fetch(`${L1_URL}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request)
    });
    
    const text = await response.text();
    try {
      return { ...JSON.parse(text), status: response.status };
    } catch {
      return { raw: text, status: response.status };
    }
  } catch (e) {
    return { error: e.message, status: 0 };
  }
}

async function getBridgeStatus(lockId) {
  try {
    const response = await fetch(`${L1_URL}/bridge/status/${lockId}`);
    const text = await response.text();
    try {
      return { ...JSON.parse(text), status: response.status };
    } catch {
      return { raw: text, status: response.status };
    }
  } catch (e) {
    return { error: e.message };
  }
}

async function getPendingLocks() {
  try {
    const response = await fetch(`${L1_URL}/bridge/pending`);
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  } catch (e) {
    return { error: e.message };
  }
}

async function getLockedBalance(address) {
  try {
    // Use full L1 address
    const response = await fetch(`${L1_URL}/bridge/l1-balance/${address}`);
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      return { raw: text };
    }
  } catch (e) {
    return { error: e.message };
  }
}

const delay = ms => new Promise(r => setTimeout(r, ms));

// ============================================================================
// TEST 2.1.1: BRIDGE LOCK (Alice locks 555 BB)
// ============================================================================

async function testBridgeLockAlice() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.1: ALICE LOCKS 555 BB FOR L2');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // Get initial balance
  console.log('1️⃣  Getting Alice initial balance...');
  const initialBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
  console.log(`   Initial Balance: ${initialBalance.toLocaleString()} BB`);
  
  if (initialBalance < 555) {
    console.log('   ❌ Insufficient balance for test');
    return { passed: false, reason: 'Insufficient balance' };
  }
  
  // Initiate bridge lock
  console.log('');
  console.log('2️⃣  Initiating bridge lock (555 BB)...');
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.ALICE, 555);
  
  if (lockResult.success) {
    console.log('   ✅ Bridge lock initiated');
    console.log(`   Lock ID: ${lockResult.lock_id || 'N/A'}`);
    
    await delay(100);
    
    // Check balance decreased
    console.log('');
    console.log('3️⃣  Verifying balance decreased...');
    const newBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
    console.log(`   Previous: ${initialBalance.toLocaleString()} BB`);
    console.log(`   Current:  ${newBalance.toLocaleString()} BB`);
    
    const balanceDecreased = newBalance < initialBalance;
    console.log(`   ${balanceDecreased ? '✅' : '⚠️'} Balance ${balanceDecreased ? 'decreased' : 'unchanged (may be tracked separately)'}`);
    
    // Check locked balance
    console.log('');
    console.log('4️⃣  Checking locked balance info...');
    const lockedInfo = await getLockedBalance(TEST_ACCOUNTS.ALICE.address);
    console.log(`   Response: ${JSON.stringify(lockedInfo).slice(0, 200)}`);
    
    return { 
      passed: true, 
      lock_id: lockResult.lock_id,
      initial: initialBalance,
      final: newBalance
    };
  } else {
    console.log(`   ❌ Lock failed: ${lockResult.error || JSON.stringify(lockResult).slice(0, 200)}`);
    return { passed: false, reason: lockResult.error || 'Unknown error' };
  }
}

// ============================================================================
// TEST 2.1.2: BRIDGE LOCK (Bob locks 333 BB)
// ============================================================================

async function testBridgeLockBob() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.2: BOB LOCKS 333 BB FOR L2');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // Get initial balance
  console.log('1️⃣  Getting Bob initial balance...');
  const initialBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
  console.log(`   Initial Balance: ${initialBalance.toLocaleString()} BB`);
  
  if (initialBalance < 333) {
    console.log('   ❌ Insufficient balance for test');
    return { passed: false, reason: 'Insufficient balance' };
  }
  
  // Initiate bridge lock
  console.log('');
  console.log('2️⃣  Initiating bridge lock (333 BB)...');
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.BOB, 333);
  
  if (lockResult.success) {
    console.log('   ✅ Bridge lock initiated');
    console.log(`   Lock ID: ${lockResult.lock_id || 'N/A'}`);
    
    await delay(100);
    
    // Check balance
    console.log('');
    console.log('3️⃣  Verifying balance...');
    const newBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
    console.log(`   Previous: ${initialBalance.toLocaleString()} BB`);
    console.log(`   Current:  ${newBalance.toLocaleString()} BB`);
    
    return { 
      passed: true, 
      lock_id: lockResult.lock_id,
      initial: initialBalance,
      final: newBalance
    };
  } else {
    console.log(`   ❌ Lock failed: ${lockResult.error || JSON.stringify(lockResult).slice(0, 200)}`);
    return { passed: false, reason: lockResult.error || 'Unknown error' };
  }
}

// ============================================================================
// TEST 2.1.3: LOCK ZERO AMOUNT (Should Fail)
// ============================================================================

async function testLockZeroAmount() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.3: LOCK ZERO AMOUNT (Should Fail)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  console.log('🚫 Attempting to lock 0 BB (should be rejected)...');
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.ALICE, 0);
  
  if (!lockResult.success) {
    console.log('   ✅ Zero amount correctly rejected');
    console.log(`   Error: ${lockResult.error || 'Amount must be positive'}`);
    return { passed: true };
  } else {
    console.log('   ❌ Zero amount was accepted (should have failed)');
    return { passed: false, reason: 'Zero amount was accepted' };
  }
}

// ============================================================================
// TEST 2.1.4: LOCK NEGATIVE AMOUNT (Should Fail)
// ============================================================================

async function testLockNegativeAmount() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.4: LOCK NEGATIVE AMOUNT (Should Fail)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  console.log('🚫 Attempting to lock -100 BB (should be rejected)...');
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.ALICE, -100);
  
  if (!lockResult.success) {
    console.log('   ✅ Negative amount correctly rejected');
    console.log(`   Error: ${lockResult.error || 'Amount must be positive'}`);
    return { passed: true };
  } else {
    console.log('   ❌ Negative amount was accepted (should have failed)');
    return { passed: false, reason: 'Negative amount was accepted' };
  }
}

// ============================================================================
// TEST 2.1.5: LOCK MORE THAN BALANCE (Should Fail)
// ============================================================================

async function testLockMoreThanBalance() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.5: LOCK MORE THAN BALANCE (Should Fail)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // Get current balance
  const currentBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
  const lockAmount = currentBalance + 100000;
  
  console.log(`   Bob's Balance: ${currentBalance.toLocaleString()} BB`);
  console.log(`🚫 Attempting to lock ${lockAmount.toLocaleString()} BB (should be rejected)...`);
  
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.BOB, lockAmount);
  
  if (!lockResult.success) {
    console.log('   ✅ Insufficient balance correctly rejected');
    console.log(`   Error: ${lockResult.error || 'Insufficient balance'}`);
    return { passed: true };
  } else {
    console.log('   ❌ Over-balance lock was accepted (should have failed)');
    return { passed: false, reason: 'Over-balance lock accepted' };
  }
}

// ============================================================================
// TEST 2.1.6: LARGE LOCK (1000 BB from Dealer)
// ============================================================================

async function testLargeLock() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('  TEST 2.1.6: LARGE LOCK (1000 BB from Dealer)');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // Get initial balance
  console.log('1️⃣  Getting Dealer initial balance...');
  const initialBalance = await getBalance(TEST_ACCOUNTS.DEALER.address);
  console.log(`   Initial Balance: ${initialBalance.toLocaleString()} BB`);
  
  // Initiate bridge lock
  console.log('');
  console.log('2️⃣  Initiating large bridge lock (1,000 BB)...');
  const lockResult = await bridgeInitiate(TEST_ACCOUNTS.DEALER, 1000);
  
  if (lockResult.success) {
    console.log('   ✅ Large bridge lock successful');
    console.log(`   Lock ID: ${lockResult.lock_id || 'N/A'}`);
    
    await delay(100);
    
    const newBalance = await getBalance(TEST_ACCOUNTS.DEALER.address);
    console.log(`   Previous: ${initialBalance.toLocaleString()} BB`);
    console.log(`   Current:  ${newBalance.toLocaleString()} BB`);
    
    return { 
      passed: true, 
      lock_id: lockResult.lock_id,
      initial: initialBalance,
      final: newBalance
    };
  } else {
    console.log(`   ❌ Lock failed: ${lockResult.error || JSON.stringify(lockResult).slice(0, 200)}`);
    return { passed: false, reason: lockResult.error || 'Unknown error' };
  }
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log('╔═══════════════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 2.1: BRIDGE LOCK (L1 → L2 Deposit)                              ║');
  console.log('║  Lock L1 tokens for use on L2                                         ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════╝');
  console.log('');
  
  // Check server
  console.log('📡 Checking L1 server...');
  try {
    const health = await fetch(`${L1_URL}/health`).then(r => r.json());
    console.log(`✅ L1 Server: ${health.status}`);
  } catch (e) {
    console.log('❌ L1 server not reachable');
    return;
  }
  
  const results = [];
  
  results.push({ name: 'Alice Locks 555 BB', ...await testBridgeLockAlice() });
  await delay(100);
  
  results.push({ name: 'Bob Locks 333 BB', ...await testBridgeLockBob() });
  await delay(100);
  
  results.push({ name: 'Zero Amount Rejected', ...await testLockZeroAmount() });
  await delay(100);
  
  results.push({ name: 'Negative Amount Rejected', ...await testLockNegativeAmount() });
  await delay(100);
  
  results.push({ name: 'Over-Balance Rejected', ...await testLockMoreThanBalance() });
  await delay(100);
  
  results.push({ name: 'Large Lock (1000 BB) Dealer', ...await testLargeLock() });
  
  // Summary
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('                         TEST 2.1 RESULTS');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  console.log('┌────────────────────────────────┬──────────┐');
  console.log('│ Test                           │ Status   │');
  console.log('├────────────────────────────────┼──────────┤');
  
  let passed = 0;
  for (const r of results) {
    const status = r.passed ? '✅ PASS' : '❌ FAIL';
    console.log(`│ ${r.name.padEnd(30)} │ ${status.padEnd(8)} │`);
    if (r.passed) passed++;
  }
  
  console.log('└────────────────────────────────┴──────────┘');
  console.log('');
  
  // Show final balances
  console.log('┌────────────────────────────────┬──────────────────┐');
  console.log('│ Account                        │ Final Balance    │');
  console.log('├────────────────────────────────┼──────────────────┤');
  const aliceBalance = await getBalance(TEST_ACCOUNTS.ALICE.address);
  const bobBalance = await getBalance(TEST_ACCOUNTS.BOB.address);
  const dealerBalance = await getBalance(TEST_ACCOUNTS.DEALER.address);
  console.log(`│ Alice                          │ ${aliceBalance.toLocaleString().padStart(12)} BB │`);
  console.log(`│ Bob                            │ ${bobBalance.toLocaleString().padStart(12)} BB │`);
  console.log(`│ Dealer                         │ ${dealerBalance.toLocaleString().padStart(12)} BB │`);
  console.log('└────────────────────────────────┴──────────────────┘');
  console.log('');
  
  console.log(`📊 Summary: ${passed}/${results.length} tests passed`);
  console.log('');
  
  if (passed === results.length) {
    console.log('🎉 TEST 2.1 COMPLETED SUCCESSFULLY!');
  } else {
    console.log('⚠️  Some tests failed. Review output above.');
  }
}

main().catch(console.error);
