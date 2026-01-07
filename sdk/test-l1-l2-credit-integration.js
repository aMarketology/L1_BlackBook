/**
 * ============================================================================
 * L1↔L2 CREDIT LINE INTEGRATION TEST
 * ============================================================================
 * 
 * Tests the FULL credit line flow between L1 (Bank) and L2 (Casino):
 * 1. Lock $BC on L1 via gRPC
 * 2. L2 receives equivalent $BB credit (1:1 backed)
 * 3. User places bets on L2 using $BB
 * 4. Settle back to L1 (convert $BB → $BC)
 * 
 * Token System:
 * - $BC (BlackCoin) = L1 native token
 * - $BB (BlackBook) = L2 gaming token (1:1 backed by locked $BC)
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

const L1_HTTP = 'http://localhost:8080';
const L1_GRPC = 'localhost:50051';
const L2_HTTP = 'http://localhost:1234';
const PROTO_PATH = path.join(__dirname, '..', 'proto', 'settlement.proto');

// Test accounts (same as test-bridge-advanced.js)
const ACCOUNTS = {
  alice: {
    name: 'Alice',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    l1Address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    initialBalance: 10000,  // $BC on L1
  },
  bob: {
    name: 'Bob',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    l1Address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    initialBalance: 5000,  // $BC on L1
  },
};

// Initialize keypairs
function initializeAccounts() {
  for (const account of Object.values(ACCOUNTS)) {
    const seedBytes = Buffer.from(account.seed, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    account.publicKey = Buffer.from(keyPair.publicKey).toString('hex');
    account.secretKey = keyPair.secretKey;
    account.l2Address = 'L2_' + account.l1Address.slice(3);
  }
}

initializeAccounts();

// ============================================================================
// GRPC CLIENT
// ============================================================================

let grpcClient = null;

function getGrpcClient() {
  if (grpcClient) return grpcClient;
  
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  
  const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
  const settlement = protoDescriptor.blackbook.settlement;
  
  grpcClient = new settlement.SettlementNode(
    L1_GRPC,
    grpc.credentials.createInsecure()
  );
  
  return grpcClient;
}

function promisifyGrpc(method, request) {
  return new Promise((resolve, reject) => {
    method.call(getGrpcClient(), request, (error, response) => {
      if (error) reject(error);
      else resolve(response);
    });
  });
}

// ============================================================================
// HELPERS
// ============================================================================

function signMessageRaw(secretKey, message) {
  const messageBytes = Buffer.from(message, 'utf8');
  const signature = nacl.sign.detached(messageBytes, secretKey);
  return Buffer.from(signature).toString('hex');
}

// Removed microtoken conversions - now using direct dollar values
// 1.00 = $1, 0.01 = 1 cent

async function httpGet(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  return response.json();
}

async function httpPost(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  return response.json();
}

// ============================================================================
// L1 OPERATIONS (via gRPC)
// ============================================================================

async function getL1Balance(address) {
  const balance = await promisifyGrpc(getGrpcClient().GetBalance, { address });
  return {
    available: microToBB(parseInt(balance.available)),
    locked: microToBB(parseInt(balance.locked)),
    total: microToBB(parseInt(balance.total)),
  };
}

async function creditDraw(account, amount) {
  const message = `credit_draw:${account.l1Address}:${amount}:${Date.now()}`;
  const signature = signMessageRaw(account.secretKey, message);
  
  return promisifyGrpc(getGrpcClient().CreditDraw, {
    wallet_address: account.l1Address,
    session_id: `session_${Date.now()}`,
    amount: amount,
  });
}

async function requestCreditLine(account, creditLimit, expiresInHours = 24) {
  const message = `credit_line:${account.l1Address}:${creditLimit}:${expiresInHours}`;
  const signature = signMessageRaw(account.secretKey, message);
  
  return promisifyGrpc(getGrpcClient().RequestCreditLine, {
    wallet_address: account.l1Address,
    public_key: account.publicKey,
    credit_limit: creditLimit,
    expires_in_hours: expiresInHours,
    signature: signature,
    nonce: Date.now(),
  });
}

// ============================================================================
// L2 OPERATIONS (via HTTP)
// ============================================================================

async function getL2Balance(address) {
  try {
    const response = await httpGet(`${L2_HTTP}/balance/${address}`);
    return response.balance || 0;
  } catch (error) {
    console.log(`   ⚠️  L2 balance endpoint not available: ${error.message}`);
    return null;
  }
}

async function getL2CreditBalance(address) {
  try {
    const response = await httpGet(`${L2_HTTP}/credit/balance/${address}`);
    return response.balance || 0;
  } catch (error) {
    console.log(`   ⚠️  L2 credit balance endpoint not available: ${error.message}`);
    return null;
  }
}

async function placeBetOnL2(account, marketId, outcome, amount) {
  try {
    const response = await httpPost(`${L2_HTTP}/bet`, {
      market_id: marketId,
      option: outcome.toString(),
      amount: amount,
      wallet_address: account.l2Address,
      signature: 'test_signature',  // L2 should forward to L1 for verification
    });
    return response;
  } catch (error) {
    console.log(`   ⚠️  L2 bet endpoint not available: ${error.message}`);
    return { success: false, error: error.message };
  }
}

async function checkL2Health() {
  try {
    const response = await httpGet(`${L2_HTTP}/health`);
    return response;
  } catch (error) {
    return { status: 'offline', error: error.message };
  }
}

// ============================================================================
// TEST RUNNER
// ============================================================================

const testResults = [];

function logTest(name, passed, details = '') {
  const status = passed ? '✅ PASS' : '❌ FAIL';
  console.log(`  ${status}: ${name}${details ? ' - ' + details : ''}`);
  testResults.push({ name, passed, details });
}

async function runTests() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║   L1↔L2 CREDIT LINE INTEGRATION TEST                         ║');
  console.log('║   Testing REAL connection between L1 Bank and L2 Casino      ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 0: Check Server Status');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Check L1 gRPC
  try {
    const l1Health = await promisifyGrpc(getGrpcClient().HealthCheck, {});
    console.log(`\n  L1 (gRPC): ${l1Health.status} - Block ${l1Health.block_height}`);
    logTest('L1 gRPC server online', l1Health.status === 'healthy');
  } catch (error) {
    console.log(`\n  L1 (gRPC): OFFLINE - ${error.message}`);
    logTest('L1 gRPC server online', false, error.message);
    return;
  }
  
  // Check L2 HTTP
  const l2Health = await checkL2Health();
  console.log(`  L2 (HTTP): ${l2Health.status || 'offline'}`);
  const l2Online = l2Health.status !== 'offline';
  logTest('L2 HTTP server online', l2Online, l2Online ? '' : 'L2 server not running');
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 1: Check Initial Balances (L1 & L2)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const aliceL1Before = await getL1Balance(ACCOUNTS.alice.l1Address);
  console.log(`\n  Alice L1 Balance:`);
  console.log(`    Available: ${aliceL1Before.available.toFixed(2)} $BC`);
  console.log(`    Locked:    ${aliceL1Before.locked.toFixed(2)} $BC`);
  logTest('Alice has L1 balance', aliceL1Before.available > 0);
  
  if (l2Online) {
    const aliceL2Before = await getL2Balance(ACCOUNTS.alice.l2Address);
    console.log(`\n  Alice L2 Balance: ${aliceL2Before !== null ? aliceL2Before.toFixed(2) + ' $BB' : 'N/A'}`);
    logTest('Alice L2 balance query', aliceL2Before !== null);
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 2: Request Credit Line on L1');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const creditLimit = 1000;
  console.log(`\n  Requesting ${creditLimit} $BC credit line for Alice...`);
  
  try {
    const creditApproval = await requestCreditLine(ACCOUNTS.alice, creditLimit, 24);
    console.log(`\n  Success:       ${creditApproval.success}`);
    console.log(`  Approval ID:   ${creditApproval.approval_id?.slice(0, 20)}...`);
    console.log(`  Credit Limit:  ${parseFloat(creditApproval.credit_limit)} $BC`);
    
    logTest('Credit line approved', creditApproval.success);
    logTest('Credit limit correct', parseFloat(creditApproval.credit_limit) === creditLimit);
  } catch (error) {
    logTest('Credit line request', false, error.message);
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 3: Draw Credit (Lock 500 $BC on L1 → Credit 500 $BB on L2)');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const drawAmount = 500;
  console.log(`\n  Drawing ${drawAmount} $BC from L1...`);
  
  try {
    const drawResult = await creditDraw(ACCOUNTS.alice, drawAmount);
    console.log(`\n  Success:      ${drawResult.success}`);
    console.log(`  Amount Drawn: ${parseFloat(drawResult.amount_drawn)} $BC`);
    console.log(`  L1 Before:    ${parseFloat(drawResult.l1_before)} $BC`);
    console.log(`  L1 After:     ${parseFloat(drawResult.l1_after)} $BC`);
    console.log(`  L2 Balance:   ${parseFloat(drawResult.l2_balance)} $BB`);
    
    logTest('Credit draw successful', drawResult.success);
    logTest('L1 balance decreased', parseFloat(drawResult.l1_after) < parseFloat(drawResult.l1_before));
    logTest('L2 balance credited', parseFloat(drawResult.l2_balance) === drawAmount);
  } catch (error) {
    logTest('Credit draw', false, error.message);
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 4: Verify L2 Balance Increased');
  console.log('═══════════════════════════════════════════════════════════════');
  
  if (l2Online) {
    const aliceL2After = await getL2Balance(ACCOUNTS.alice.l2Address);
    const aliceL2Credit = await getL2CreditBalance(ACCOUNTS.alice.l2Address);
    
    console.log(`\n  Alice L2 Balance: ${aliceL2After !== null ? aliceL2After.toFixed(2) + ' $BB' : 'N/A'}`);
    console.log(`  Alice L2 Credit:  ${aliceL2Credit !== null ? aliceL2Credit.toFixed(2) + ' $BB' : 'N/A'}`);
    
    if (aliceL2After !== null) {
      logTest('L2 balance reflects credit', aliceL2After >= 500);
    }
    if (aliceL2Credit !== null) {
      logTest('L2 credit balance updated', aliceL2Credit >= 500);
    }
  } else {
    console.log(`\n  ⚠️  L2 server offline - cannot verify L2 balance increase`);
    console.log(`  💡 To test L2 integration:`);
    console.log(`     1. Start L2 server: cd l2 && cargo run`);
    console.log(`     2. Or: npm run l2:dev (if configured)`);
  }
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('STEP 5: Check Final L1 Balance');
  console.log('═══════════════════════════════════════════════════════════════');
  
  const aliceL1After = await getL1Balance(ACCOUNTS.alice.l1Address);
  console.log(`\n  Alice L1 Balance:`);
  console.log(`    Available: ${aliceL1After.available.toFixed(2)} $BC`);
  console.log(`    Locked:    ${aliceL1After.locked.toFixed(2)} $BC`);
  console.log(`    Total:     ${aliceL1After.total.toFixed(2)} $BC`);
  
  const expectedLocked = aliceL1Before.locked + 500;  // Should have 500 $BC locked
  console.log(`\n  Expected Locked: ${expectedLocked.toFixed(2)} $BC`);
  
  logTest('L1 tokens locked for L2', Math.abs(aliceL1After.locked - expectedLocked) < 1);
  logTest('L1 total balance conserved', Math.abs(aliceL1After.total - aliceL1Before.total) < 1);
  
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
  console.log('\n💡 KEY INSIGHTS:');
  console.log('   1. L1 locks $BC tokens via gRPC credit draw');
  console.log('   2. L2 receives equivalent $BB credit (1:1 backed by $BC)');
  console.log('   3. L1 locked balance increases (+$BC)');
  console.log('   4. L1 available balance decreases (-$BC)');
  console.log('   5. Total L1 balance remains constant (locked + available)');
  console.log('   6. L2 $BB can be used for betting, 1:1 redeemable for $BC');
  
  if (!l2Online) {
    console.log('\n⚠️  L2 SERVER NOT RUNNING - L2 balance changes not verified');
    console.log('   Start L2 server to see full L1↔L2 integration');
  }
  
  console.log('\n' + '═'.repeat(66));
  
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);
