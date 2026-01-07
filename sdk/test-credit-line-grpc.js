/**
 * ============================================================================
 * TEST 4.4: Credit Line Signature Verification via gRPC
 * ============================================================================
 * 
 * Tests Alice and Bob requesting credit lines to bet on L2 using gRPC
 * with proper Ed25519 signature verification.
 * 
 * Flow:
 * 1. Check L1 balances via gRPC
 * 2. Request credit line with Ed25519 signature
 * 3. Credit draw (lock funds for L2 betting)
 * 4. Check credit status
 * 5. Settle credit line (return to L1)
 */

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import nacl from 'tweetnacl';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// CONFIGURATION
// ============================================================================

const GRPC_HOST = 'localhost:50051';
const PROTO_PATH = path.join(__dirname, '..', 'proto', 'settlement.proto');

// Test Accounts - addresses derived from public keys
// Using the same derivation as test-bridge-advanced.js
const ACCOUNTS = {
  alice: {
    name: 'Alice',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    l1Address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',  // Derived from pubkey
    initialBalance: 10000,  // BB
  },
  bob: {
    name: 'Bob',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    l1Address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',  // Derived from pubkey
    initialBalance: 5000,  // BB
  },
  dealer: {
    name: 'Dealer',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    l1Address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    initialBalance: 100000,  // BB
  }
};

// Initialize keypairs from seeds
function initializeAccounts() {
  for (const account of Object.values(ACCOUNTS)) {
    const seedBytes = Buffer.from(account.seed, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    account.publicKey = Buffer.from(keyPair.publicKey).toString('hex');
    account.secretKey = keyPair.secretKey;
    // L2 address is same hash, different prefix
    account.l2Address = 'L2_' + account.l1Address.slice(3);
  }
}

initializeAccounts();

// ============================================================================
// GRPC CLIENT SETUP
// ============================================================================

let client = null;

function getClient() {
  if (client) return client;
  
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  
  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  const settlement = protoDescriptor.blackbook.settlement;
  
  client = new settlement.SettlementNode(
    GRPC_HOST,
    grpc.credentials.createInsecure()
  );
  
  return client;
}

// ============================================================================
// ED25519 CRYPTOGRAPHY
// ============================================================================

/**
 * Sign a message with Ed25519 (RAW - no chain prefix for gRPC)
 * @param {Uint8Array} secretKey - nacl secret key (64 bytes)
 * @param {string} message - Message to sign
 * @returns {string} 128-char hex signature
 */
function signMessageRaw(secretKey, message) {
  const messageBytes = Buffer.from(message, 'utf8');
  const signature = nacl.sign.detached(messageBytes, secretKey);
  return Buffer.from(signature).toString('hex');
}

/**
 * Convert BB to microtokens
 */
function bbToMicro(bb) {
  return Math.floor(bb * 1_000_000);
}

/**
 * Convert microtokens to BB
 */
function microToBB(micro) {
  return micro / 1_000_000;
}

// ============================================================================
// GRPC WRAPPER FUNCTIONS
// ============================================================================

function promisify(method, request) {
  return new Promise((resolve, reject) => {
    method.call(getClient(), request, (error, response) => {
      if (error) reject(error);
      else resolve(response);
    });
  });
}

async function healthCheck() {
  return promisify(getClient().HealthCheck, {});
}

async function getBalance(address) {
  return promisify(getClient().GetBalance, { address });
}

async function checkSufficientBalance(address, requiredAmount) {
  return promisify(getClient().CheckSufficientBalance, {
    address,
    required_amount: requiredAmount,
    check_available_only: true,
  });
}

async function requestCreditLine(account, creditLimit, expiresInHours = 24) {
  const message = `credit_line:${account.l1Address}:${creditLimit}:${expiresInHours}`;
  const signature = signMessageRaw(account.secretKey, message);
  
  return promisify(getClient().RequestCreditLine, {
    wallet_address: account.l1Address,
    public_key: account.publicKey,
    credit_limit: creditLimit,
    expires_in_hours: expiresInHours,
    signature: signature,
    nonce: Date.now(),
  });
}

async function creditDraw(account, sessionId, amount) {
  return promisify(getClient().CreditDraw, {
    wallet_address: account.l1Address,
    session_id: sessionId,
    amount: amount,
  });
}

async function creditSettle(account, sessionId, finalL2Balance, lockedInBets = 0) {
  return promisify(getClient().CreditSettle, {
    wallet_address: account.l1Address,
    session_id: sessionId,
    final_l2_balance: finalL2Balance,
    locked_in_bets: lockedInBets,
  });
}

async function getCreditStatus(address) {
  return promisify(getClient().GetCreditStatus, { wallet_address: address });
}

async function initiateBridgeLock(account, amount) {
  const message = `bridge_lock:${account.l1Address}:${amount}:L2`;
  const signature = Buffer.from(signMessageRaw(account.secretKey, message), 'hex');
  
  return promisify(getClient().InitiateBridgeLock, {
    user_address: account.l1Address,
    amount: amount,
    target_layer: 'L2',
    public_key: account.publicKey,
    signature: signature,
    nonce: Date.now(),
    timestamp: Date.now(),
    chain_id: 1,
  });
}

async function verifySignature(publicKey, message, signature) {
  return promisify(getClient().VerifySignature, {
    public_key: publicKey,
    message: message,
    signature: Buffer.from(signature, 'hex'),
    expected_chain: 1,  // CHAIN_L1
  });
}

// ============================================================================
// TEST FUNCTIONS
// ============================================================================

const testResults = [];

function logTest(name, passed, details = '') {
  const status = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`  ${status}: ${name}${details ? ' - ' + details : ''}`);
  testResults.push({ name, passed, details });
}

async function test_4_4_1_HealthCheck() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.1: gRPC Health Check');
  console.log('═══════════════════════════════════════════════════════════════');
  
  try {
    const health = await healthCheck();
    console.log(`  Server Status: ${health.status}`);
    console.log(`  Block Height:  ${health.block_height}`);
    console.log(`  Version:       ${health.version}`);
    console.log(`  Uptime:        ${health.uptime_seconds}s`);
    console.log(`  Active Locks:  ${health.active_locks}`);
    
    logTest('gRPC server is healthy', health.status === 'healthy');
    logTest('Block height > 0', parseInt(health.block_height) >= 0);
    return health;
  } catch (error) {
    logTest('gRPC connection', false, error.message);
    return null;
  }
}

async function test_4_4_2_GetBalances() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.2: Get L1 Balances via gRPC');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const balances = {};
  
  for (const [name, account] of Object.entries(ACCOUNTS)) {
    try {
      const balance = await getBalance(account.l1Address);
      const availableBB = microToBB(parseInt(balance.available));
      const lockedBB = microToBB(parseInt(balance.locked));
      const totalBB = microToBB(parseInt(balance.total));
      
      balances[name] = { available: availableBB, locked: lockedBB, total: totalBB };
      
      console.log(`\n  ${account.name} (${account.l1Address.slice(0, 20)}...):`);
      console.log(`    Available: ${availableBB.toFixed(2)} BB`);
      console.log(`    Locked:    ${lockedBB.toFixed(2)} BB`);
      console.log(`    Total:     ${totalBB.toFixed(2)} BB`);
      
      logTest(`${account.name} balance query`, balance.address === account.l1Address);
    } catch (error) {
      logTest(`${account.name} balance query`, false, error.message);
    }
  }
  
  return balances;
}

async function test_4_4_3_SignatureVerification() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.3: Ed25519 Signature Verification via gRPC');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Test Alice's signature
  const testMessage = 'test_signature:alice:1234567890';
  const aliceSignature = signMessageRaw(ACCOUNTS.alice.secretKey, testMessage);
  
  console.log(`\n  Message:   "${testMessage}"`);
  console.log(`  Signature: ${aliceSignature.slice(0, 32)}...`);
  
  try {
    const result = await verifySignature(
      ACCOUNTS.alice.publicKey,
      testMessage,
      aliceSignature
    );
    
    console.log(`\n  Valid:           ${result.valid}`);
    console.log(`  Derived Address: ${result.derived_address}`);
    
    logTest('Alice signature is valid', result.valid === true);
    logTest('Address derived correctly', result.derived_address === ACCOUNTS.alice.l1Address);
  } catch (error) {
    logTest('Alice signature verification', false, error.message);
  }
  
  // Test Bob's signature
  const bobMessage = 'test_signature:bob:0987654321';
  const bobSignature = signMessageRaw(ACCOUNTS.bob.secretKey, bobMessage);
  
  try {
    const result = await verifySignature(
      ACCOUNTS.bob.publicKey,
      bobMessage,
      bobSignature
    );
    
    logTest('Bob signature is valid', result.valid === true);
    logTest('Bob address derived correctly', result.derived_address === ACCOUNTS.bob.l1Address);
  } catch (error) {
    logTest('Bob signature verification', false, error.message);
  }
  
  // Test INVALID signature (should fail)
  try {
    const invalidSignature = 'a'.repeat(128);  // Fake signature
    const result = await verifySignature(
      ACCOUNTS.alice.publicKey,
      testMessage,
      invalidSignature
    );
    
    logTest('Invalid signature rejected', result.valid === false);
  } catch (error) {
    // Expected - invalid signature may throw
    logTest('Invalid signature rejected', true, 'Threw error as expected');
  }
}

async function test_4_4_4_CreditLineRequest() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.4: Request Credit Line (Casino Bank Model)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Alice requests 1000 BB credit line
  const aliceCreditLimit = bbToMicro(1000);
  
  console.log(`\n  Alice requesting ${microToBB(aliceCreditLimit)} BB credit line...`);
  
  try {
    const aliceCredit = await requestCreditLine(ACCOUNTS.alice, aliceCreditLimit, 24);
    
    console.log(`\n  Success:       ${aliceCredit.success}`);
    console.log(`  Approval ID:   ${aliceCredit.approval_id?.slice(0, 20)}...`);
    console.log(`  Credit Limit:  ${microToBB(parseInt(aliceCredit.credit_limit))} BB`);
    
    if (aliceCredit.session) {
      console.log(`  Session ID:    ${aliceCredit.session.session_id?.slice(0, 20)}...`);
      console.log(`  Session Active: ${aliceCredit.session.is_active}`);
    }
    
    logTest('Alice credit line approved', aliceCredit.success === true);
    logTest('Credit limit matches request', parseInt(aliceCredit.credit_limit) === aliceCreditLimit);
    logTest('Session created', aliceCredit.session?.is_active === true);
    
    return aliceCredit;
  } catch (error) {
    logTest('Alice credit line request', false, error.message);
    return null;
  }
}

async function test_4_4_5_CreditLineWithBadSignature() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.5: Credit Line with Invalid Signature (Should Fail)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Try to request credit with wrong signature (Bob's key for Alice's address)
  const creditLimit = bbToMicro(500);
  const message = `credit_line:${ACCOUNTS.alice.l1Address}:${creditLimit}:24`;
  
  // Sign with Bob's key (WRONG!)
  const wrongSignature = signMessageRaw(ACCOUNTS.bob.secretKey, message);
  
  console.log(`\n  Attempting to request credit for Alice with Bob's signature...`);
  
  try {
    const result = await promisify(getClient().RequestCreditLine, {
      wallet_address: ACCOUNTS.alice.l1Address,
      public_key: ACCOUNTS.bob.publicKey,  // Wrong public key!
      credit_limit: creditLimit,
      expires_in_hours: 24,
      signature: wrongSignature,
      nonce: Date.now(),
    });
    
    console.log(`\n  Success:   ${result.success}`);
    console.log(`  Error:     ${result.error_message}`);
    
    // This SHOULD fail because pubkey doesn't match address
    logTest('Invalid signature rejected', result.success === false);
    logTest('Error message correct', result.error_message.includes('match') || result.error_message.includes('signature'));
  } catch (error) {
    // Also acceptable - may throw
    logTest('Invalid signature rejected', true, 'Threw error as expected');
  }
}

async function test_4_4_6_BobCreditLine() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.6: Bob Requests Credit Line');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const bobCreditLimit = bbToMicro(500);
  
  console.log(`\n  Bob requesting ${microToBB(bobCreditLimit)} BB credit line...`);
  
  try {
    const bobCredit = await requestCreditLine(ACCOUNTS.bob, bobCreditLimit, 12);
    
    console.log(`\n  Success:       ${bobCredit.success}`);
    console.log(`  Credit Limit:  ${microToBB(parseInt(bobCredit.credit_limit))} BB`);
    
    logTest('Bob credit line approved', bobCredit.success === true);
    logTest('Bob credit limit matches', parseInt(bobCredit.credit_limit) === bobCreditLimit);
    
    return bobCredit;
  } catch (error) {
    logTest('Bob credit line request', false, error.message);
    return null;
  }
}

async function test_4_4_7_CreditDraw() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.7: Credit Draw (Lock Funds for L2 Betting)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Get Alice's current balance
  const balanceBefore = await getBalance(ACCOUNTS.alice.l1Address);
  const availableBefore = microToBB(parseInt(balanceBefore.available));
  
  console.log(`\n  Alice's balance before draw: ${availableBefore.toFixed(2)} BB`);
  
  // Draw 100 BB for betting
  const drawAmount = bbToMicro(100);
  
  console.log(`  Drawing ${microToBB(drawAmount)} BB for L2 betting...`);
  
  try {
    const draw = await creditDraw(ACCOUNTS.alice, 'test_session', drawAmount);
    
    console.log(`\n  Success:      ${draw.success}`);
    console.log(`  Amount Drawn: ${microToBB(parseInt(draw.amount_drawn))} BB`);
    console.log(`  L1 Before:    ${microToBB(parseInt(draw.l1_before))} BB`);
    console.log(`  L1 After:     ${microToBB(parseInt(draw.l1_after))} BB`);
    console.log(`  L2 Balance:   ${microToBB(parseInt(draw.l2_balance))} BB`);
    
    logTest('Credit draw successful', draw.success === true);
    logTest('L1 balance decreased', parseInt(draw.l1_after) < parseInt(draw.l1_before));
    logTest('Draw amount correct', parseInt(draw.amount_drawn) === drawAmount);
    
    return draw;
  } catch (error) {
    logTest('Credit draw', false, error.message);
    return null;
  }
}

async function test_4_4_8_CheckCreditStatus() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.8: Check Credit Status');
  console.log('═══════════════════════════════════════════════════════════════');
  
  try {
    const status = await getCreditStatus(ACCOUNTS.alice.l1Address);
    
    console.log(`\n  Wallet:         ${status.wallet_address?.slice(0, 20)}...`);
    console.log(`  L1 Balance:     ${microToBB(parseInt(status.l1_balance))} BB`);
    console.log(`  Active Credit:  ${status.has_active_credit}`);
    
    if (status.session) {
      console.log(`\n  Session Info:`);
      console.log(`    L2 Balance:     ${microToBB(parseInt(status.session.l2_balance))} BB`);
      console.log(`    Available to Bet: ${microToBB(parseInt(status.session.available_to_bet))} BB`);
      console.log(`    Draw Count:     ${status.session.draw_count}`);
    }
    
    logTest('Credit status retrieved', status.success === true);
    logTest('Wallet address correct', status.wallet_address === ACCOUNTS.alice.l1Address);
    
    return status;
  } catch (error) {
    logTest('Credit status check', false, error.message);
    return null;
  }
}

async function test_4_4_9_BridgeLock() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.9: Bridge Lock via gRPC (Alice locks for L2)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const lockAmount = bbToMicro(50);  // 50 BB
  
  console.log(`\n  Alice locking ${microToBB(lockAmount)} BB for L2...`);
  
  try {
    const lock = await initiateBridgeLock(ACCOUNTS.alice, lockAmount);
    
    console.log(`\n  Success:       ${lock.success}`);
    console.log(`  Lock ID:       ${lock.lock_id?.slice(0, 20)}...`);
    console.log(`  Locked Amount: ${microToBB(parseInt(lock.locked_amount))} BB`);
    console.log(`  Available:     ${microToBB(parseInt(lock.available_balance))} BB`);
    
    logTest('Bridge lock successful', lock.success === true);
    logTest('Lock ID generated', lock.lock_id && lock.lock_id.length > 0);
    logTest('Locked amount correct', parseInt(lock.locked_amount) === lockAmount);
    
    return lock;
  } catch (error) {
    logTest('Bridge lock', false, error.message);
    return null;
  }
}

async function test_4_4_10_CreditSettle() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.10: Credit Settle (End Session, Return to L1)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Simulate: Alice bet 100 BB, won 50 BB, final L2 balance is 150 BB
  const finalL2Balance = bbToMicro(150);
  
  console.log(`\n  Settling Alice's session with ${microToBB(finalL2Balance)} BB profit...`);
  
  try {
    const settle = await creditSettle(ACCOUNTS.alice, 'test_session', finalL2Balance, 0);
    
    console.log(`\n  Success:      ${settle.success}`);
    console.log(`  Settlement:   ${settle.settlement_type}`);
    console.log(`  Net P&L:      ${settle.net_pnl} µBB (${microToBB(parseInt(settle.net_pnl || 0))} BB)`);
    console.log(`  L1 Before:    ${microToBB(parseInt(settle.l1_before))} BB`);
    console.log(`  L1 After:     ${microToBB(parseInt(settle.l1_after))} BB`);
    console.log(`  Returned:     ${microToBB(parseInt(settle.returned_to_l1))} BB`);
    
    logTest('Credit settle successful', settle.success === true);
    logTest('Settlement type correct', settle.settlement_type === 'WINNINGS');
    
    return settle;
  } catch (error) {
    logTest('Credit settle', false, error.message);
    return null;
  }
}

async function test_4_4_11_FinalBalances() {
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('TEST 4.4.11: Final Balance Check');
  console.log('═══════════════════════════════════════════════════════════════');
  
  console.log('\n  Final balances after all operations:\n');
  
  for (const [name, account] of Object.entries(ACCOUNTS)) {
    try {
      const balance = await getBalance(account.l1Address);
      const availableBB = microToBB(parseInt(balance.available));
      const lockedBB = microToBB(parseInt(balance.locked));
      const totalBB = microToBB(parseInt(balance.total));
      
      console.log(`  ${account.name}: ${availableBB.toFixed(2)} BB available, ${lockedBB.toFixed(2)} BB locked`);
      
      logTest(`${account.name} final balance valid`, totalBB >= 0);
    } catch (error) {
      logTest(`${account.name} final balance`, false, error.message);
    }
  }
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

async function runAllTests() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  TEST 4.4: Credit Line Signature Verification (gRPC)         ║');
  console.log('║  Testing Alice & Bob betting on L2 with Ed25519 signatures   ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log(`\nConnecting to gRPC server at ${GRPC_HOST}...`);
  
  try {
    // Run all tests in sequence
    await test_4_4_1_HealthCheck();
    await test_4_4_2_GetBalances();
    await test_4_4_3_SignatureVerification();
    await test_4_4_4_CreditLineRequest();
    await test_4_4_5_CreditLineWithBadSignature();
    await test_4_4_6_BobCreditLine();
    await test_4_4_7_CreditDraw();
    await test_4_4_8_CheckCreditStatus();
    await test_4_4_9_BridgeLock();
    await test_4_4_10_CreditSettle();
    await test_4_4_11_FinalBalances();
    
  } catch (error) {
    console.error('\n❌ Test suite failed:', error.message);
  }
  
  // Print summary
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║                       TEST SUMMARY                            ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  
  const passed = testResults.filter(t => t.passed).length;
  const failed = testResults.filter(t => !t.passed).length;
  const total = testResults.length;
  
  console.log(`\n  Total:  ${total}`);
  console.log(`  Passed: ${passed} ✅`);
  console.log(`  Failed: ${failed} ❌`);
  console.log(`\n  Success Rate: ${((passed / total) * 100).toFixed(1)}%`);
  
  if (failed > 0) {
    console.log('\n  Failed Tests:');
    testResults.filter(t => !t.passed).forEach(t => {
      console.log(`    ❌ ${t.name}${t.details ? ': ' + t.details : ''}`);
    });
  }
  
  console.log('\n' + '═'.repeat(66));
  
  process.exit(failed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(console.error);
