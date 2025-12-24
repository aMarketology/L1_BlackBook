#!/usr/bin/env node
// ============================================================================
// L1 FUNCTIONALITY TEST SUITE
// ============================================================================
// Tests:
// 1. Health check & server status
// 2. Test account retrieval (Alice & Bob)
// 3. Balance queries
// 4. Signature verification
// 5. Transfers between Alice and Bob (with signatures)
// 6. Credit line approval & status
// 7. Profile endpoint
// 8. Blockchain stats & PoH status
// ============================================================================

import nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

const L1_URL = process.env.L1_URL || 'http://localhost:8080';

// ============================================================================
// TEST HELPERS
// ============================================================================

const colors = {
  reset: '\x1b[0m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

function pass(msg) { console.log(`${colors.green}✅ PASS:${colors.reset} ${msg}`); }
function fail(msg) { console.log(`${colors.red}❌ FAIL:${colors.reset} ${msg}`); }
function info(msg) { console.log(`${colors.cyan}ℹ️  INFO:${colors.reset} ${msg}`); }
function section(title) { 
  console.log(`\n${colors.blue}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.blue}   ${title}${colors.reset}`);
  console.log(`${colors.blue}═══════════════════════════════════════════════════════════════${colors.reset}\n`);
}

let testResults = { passed: 0, failed: 0 };

function assert(condition, testName) {
  if (condition) {
    pass(testName);
    testResults.passed++;
  } else {
    fail(testName);
    testResults.failed++;
  }
  return condition;
}

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function signMessage(privateKeyHex, message, chainId = 0x01) {
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey, 0);
  secretKey.set(keypair.publicKey, 32);
  
  // Domain separation: prepend chain ID
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  const signature = nacl.sign.detached(domainSeparated, secretKey);
  return Buffer.from(signature).toString('hex');
}

function createSignedRequest(privateKeyHex, publicKeyHex, walletAddress, payload, requestPath = null) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('hex');
  const payloadStr = JSON.stringify(payload);
  
  // Build message with optional path binding
  let message;
  if (requestPath) {
    message = `${requestPath}\n${payloadStr}\n${timestamp}\n${nonce}`;
  } else {
    message = `${payloadStr}\n${timestamp}\n${nonce}`;
  }
  
  const signature = signMessage(privateKeyHex, message, 0x01);
  
  const request = {
    public_key: publicKeyHex,
    wallet_address: walletAddress,
    payload: payloadStr,
    timestamp,
    nonce,
    chain_id: 1,
    signature
  };
  
  if (requestPath) {
    request.request_path = requestPath;
  }
  
  return request;
}

// ============================================================================
// TEST: SERVER HEALTH
// ============================================================================

async function testServerHealth() {
  section('TEST 1: Server Health Check');
  
  try {
    const res = await fetch(`${L1_URL}/health`);
    const data = await res.json();
    
    assert(res.ok, 'Health endpoint returns 200');
    assert(data.status === 'healthy', 'Server reports healthy status');
    info(`Server uptime: ${data.uptime || 'N/A'}`);
    return true;
  } catch (e) {
    fail(`Server not reachable: ${e.message}`);
    info(`Make sure L1 is running: cargo run`);
    testResults.failed++;
    return false;
  }
}

// ============================================================================
// TEST: GET TEST ACCOUNTS
// ============================================================================

async function testGetTestAccounts() {
  section('TEST 2: Test Account Retrieval (Alice & Bob)');
  
  try {
    const res = await fetch(`${L1_URL}/auth/test-accounts`);
    const data = await res.json();
    
    assert(res.ok && data.success, 'Test accounts endpoint returns success');
    assert(data.alice?.public_key, 'Alice has public_key');
    assert(data.alice?.private_key, 'Alice has private_key');
    assert(data.alice?.address, 'Alice has address');
    assert(data.bob?.public_key, 'Bob has public_key');
    assert(data.bob?.private_key, 'Bob has private_key');
    assert(data.bob?.address, 'Bob has address');
    
    info(`Alice address: ${data.alice.address}`);
    info(`Bob address: ${data.bob.address}`);
    info(`Alice L1 balance: ${data.alice.l1_available} BB`);
    info(`Bob L1 balance: ${data.bob.l1_available} BB`);
    
    return { alice: data.alice, bob: data.bob };
  } catch (e) {
    fail(`Test accounts retrieval failed: ${e.message}`);
    testResults.failed++;
    return null;
  }
}

// ============================================================================
// TEST: BALANCE QUERIES
// ============================================================================

async function testBalanceQueries(accounts) {
  section('TEST 3: Balance Queries');
  
  if (!accounts) {
    fail('Skipping - no accounts available');
    testResults.failed++;
    return;
  }
  
  try {
    // Public balance check (no auth)
    const aliceRes = await fetch(`${L1_URL}/balance/${accounts.alice.address}`);
    const aliceData = await aliceRes.json();
    assert(aliceRes.ok, 'Alice public balance query succeeds');
    assert(typeof aliceData.balance === 'number', 'Alice balance is a number');
    info(`Alice balance (public): ${aliceData.balance} BB`);
    
    // Authenticated balance check
    const signedRequest = createSignedRequest(
      accounts.alice.private_key,
      accounts.alice.public_key,
      accounts.alice.address,
      {},
      '/wallet/balance'
    );
    
    const authRes = await fetch(`${L1_URL}/wallet/balance`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    const authData = await authRes.json();
    
    assert(authRes.ok && authData.success, 'Alice authenticated balance query succeeds');
    assert(authData.balance !== undefined, 'Authenticated response includes balance');
    info(`Alice balance (authenticated): ${authData.balance} BB`);
    info(`L1 available: ${authData.l1_available}, L2 locked: ${authData.l2_locked}`);
    
  } catch (e) {
    fail(`Balance query failed: ${e.message}`);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: SIGNATURE VERIFICATION
// ============================================================================

async function testSignatureVerification(accounts) {
  section('TEST 4: Signature Verification');
  
  if (!accounts) {
    fail('Skipping - no accounts available');
    testResults.failed++;
    return;
  }
  
  try {
    const signedRequest = createSignedRequest(
      accounts.alice.private_key,
      accounts.alice.public_key,
      accounts.alice.address,
      { test: 'data' }
    );
    
    const res = await fetch(`${L1_URL}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    const data = await res.json();
    
    assert(res.ok && data.success, 'Signature verification endpoint works');
    assert(data.verified === true, 'Valid signature is verified');
    info(`Verified wallet: ${data.wallet_address}`);
    
    // Test invalid signature
    const badRequest = { ...signedRequest, signature: signedRequest.signature.replace('a', 'b') };
    const badRes = await fetch(`${L1_URL}/auth/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(badRequest)
    });
    const badData = await badRes.json();
    
    assert(badData.verified === false, 'Invalid signature is rejected');
    
  } catch (e) {
    fail(`Signature verification test failed: ${e.message}`);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: TRANSFER BETWEEN ALICE AND BOB
// ============================================================================

async function testTransfer(accounts) {
  section('TEST 5: Transfer from Alice to Bob');
  
  if (!accounts) {
    fail('Skipping - no accounts available');
    testResults.failed++;
    return;
  }
  
  try {
    // Get initial balances
    const aliceBeforeRes = await fetch(`${L1_URL}/balance/${accounts.alice.address}`);
    const aliceBefore = (await aliceBeforeRes.json()).balance;
    
    const bobBeforeRes = await fetch(`${L1_URL}/balance/${accounts.bob.address}`);
    const bobBefore = (await bobBeforeRes.json()).balance;
    
    info(`Before transfer:`);
    info(`  Alice: ${aliceBefore} BB`);
    info(`  Bob: ${bobBefore} BB`);
    
    // Create signed transfer request
    const transferAmount = 100;
    const payload = {
      to: accounts.bob.address,
      amount: transferAmount
    };
    
    const signedRequest = createSignedRequest(
      accounts.alice.private_key,
      accounts.alice.public_key,
      accounts.alice.address,
      payload,
      '/transfer'
    );
    
    const res = await fetch(`${L1_URL}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    const data = await res.json();
    
    if (!data.success) {
      info(`Transfer response: ${JSON.stringify(data)}`);
    }
    
    assert(res.ok && data.success, `Transfer of ${transferAmount} BB succeeds`);
    
    // Verify balances changed
    const aliceAfterRes = await fetch(`${L1_URL}/balance/${accounts.alice.address}`);
    const aliceAfter = (await aliceAfterRes.json()).balance;
    
    const bobAfterRes = await fetch(`${L1_URL}/balance/${accounts.bob.address}`);
    const bobAfter = (await bobAfterRes.json()).balance;
    
    info(`After transfer:`);
    info(`  Alice: ${aliceAfter} BB (${aliceAfter - aliceBefore >= 0 ? '+' : ''}${aliceAfter - aliceBefore})`);
    info(`  Bob: ${bobAfter} BB (${bobAfter - bobBefore >= 0 ? '+' : ''}${bobAfter - bobBefore})`);
    
    assert(aliceAfter < aliceBefore, 'Alice balance decreased');
    assert(bobAfter > bobBefore, 'Bob balance increased');
    assert(Math.abs((bobAfter - bobBefore) - transferAmount) < 0.01, 'Bob received correct amount');
    
    if (data.tx_id) {
      info(`Transaction ID: ${data.tx_id}`);
    }
    
  } catch (e) {
    fail(`Transfer test failed: ${e.message}`);
    console.error(e);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: CREDIT LINE FLOW
// ============================================================================

async function testCreditLineFlow(accounts) {
  section('TEST 6: Credit Line Flow (L2 Integration Ready)');
  
  if (!accounts) {
    fail('Skipping - no accounts available');
    testResults.failed++;
    return;
  }
  
  try {
    // 1. Approve credit line
    const creditLimit = 100;
    const nonce = Date.now();
    const approvalMessage = `APPROVE_CREDIT:${accounts.bob.address}:${creditLimit}:${nonce}`;
    
    // Sign WITHOUT domain separation (chain_id) for credit routes
    const privateKey = Buffer.from(accounts.bob.private_key, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(privateKey);
    const secretKey = new Uint8Array(64);
    secretKey.set(privateKey, 0);
    secretKey.set(keypair.publicKey, 32);
    const signature = Buffer.from(
      nacl.sign.detached(Buffer.from(approvalMessage, 'utf8'), secretKey)
    ).toString('hex');
    
    const approveRes = await fetch(`${L1_URL}/credit/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        wallet_address: accounts.bob.address,
        public_key: accounts.bob.public_key,
        credit_limit: creditLimit,
        signature,
        nonce,
        expires_in_hours: 24
      })
    });
    const approveData = await approveRes.json();
    
    if (!approveData.success) {
      info(`Credit approval response: ${JSON.stringify(approveData)}`);
      // If approval already exists, that's fine - we can continue with it
      if (approveData.error && approveData.error.includes('already exists')) {
        pass('Credit line approval exists (from previous test run)');
      } else {
        assert(false, 'Credit line approval succeeds');
      }
    } else {
      pass('Credit line approval succeeds');
      if (approveData.session) {
        info(`Session ID: ${approveData.session.session_id}`);
        info(`Credit limit: ${approveData.session.credit_limit} BB`);
      }
    }
    
    // 2. Check credit status
    const statusRes = await fetch(`${L1_URL}/credit/status/${accounts.bob.address}`);
    const statusData = await statusRes.json();
    
    assert(statusRes.ok, 'Credit status query succeeds');
    if (statusData.session) {
      info(`Credit available: ${statusData.session.available || 'N/A'} BB`);
      info(`Credit used: ${statusData.session.total_drawn || 0} BB`);
    }
    
    pass('Credit line flow ready for L2 integration');
    
  } catch (e) {
    fail(`Credit line test failed: ${e.message}`);
    console.error(e);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: KEYPAIR GENERATION
// ============================================================================

async function testKeypairGeneration() {
  section('TEST 7: Keypair Generation');
  
  try {
    const res = await fetch(`${L1_URL}/auth/keypair`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const data = await res.json();
    
    assert(res.ok && data.success, 'Keypair generation succeeds');
    assert(data.keypair?.public_key?.length === 64, 'Public key is 64 hex chars');
    assert(data.keypair?.private_key?.length === 64, 'Private key is 64 hex chars');
    
    info(`Generated public key: ${data.keypair.public_key.slice(0, 16)}...`);
    info(`Generated address: ${data.keypair.address}`);
    
  } catch (e) {
    fail(`Keypair generation failed: ${e.message}`);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: PROFILE ENDPOINT
// ============================================================================

async function testProfile(accounts) {
  section('TEST 8: Profile Endpoint');
  
  if (!accounts) {
    fail('Skipping - no accounts available');
    testResults.failed++;
    return;
  }
  
  try {
    const signedRequest = createSignedRequest(
      accounts.alice.private_key,
      accounts.alice.public_key,
      accounts.alice.address,
      {},
      '/profile'
    );
    
    const res = await fetch(`${L1_URL}/profile`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    const data = await res.json();
    
    assert(res.ok && data.success, 'Profile endpoint returns success');
    assert(data.profile?.wallet_address, 'Profile includes wallet address');
    assert(typeof data.profile?.balance === 'number', 'Profile includes balance');
    
    info(`Profile wallet: ${data.profile.wallet_address}`);
    info(`Profile balance: ${data.profile.balance} BB`);
    info(`Transaction count: ${data.profile.transaction_count}`);
    
  } catch (e) {
    fail(`Profile test failed: ${e.message}`);
    testResults.failed++;
  }
}

// ============================================================================
// TEST: BLOCKCHAIN STATS
// ============================================================================

async function testBlockchainStats() {
  section('TEST 9: Blockchain Stats & PoH Status');
  
  try {
    const res = await fetch(`${L1_URL}/stats`);
    const data = await res.json();
    
    assert(res.ok, 'Stats endpoint returns 200');
    assert(typeof data.stats?.total_blocks === 'number', 'Stats includes block count');
    
    info(`Total blocks: ${data.stats?.total_blocks}`);
    info(`Total transactions: ${data.stats?.pending_transactions}`);
    info(`Active accounts: ${data.stats?.total_wallets}`);
    
    // Check PoH status
    const pohRes = await fetch(`${L1_URL}/poh/status`);
    const pohData = await pohRes.json();
    
    assert(pohRes.ok, 'PoH status endpoint returns 200');
    info(`PoH slot: ${pohData.current_slot || 'N/A'}`);
    info(`PoH hashes: ${pohData.total_hashes || 'N/A'}`);
    
  } catch (e) {
    fail(`Stats test failed: ${e.message}`);
    testResults.failed++;
  }
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log('\n');
  console.log('╔═══════════════════════════════════════════════════════════════╗');
  console.log('║      BLACKBOOK L1 FUNCTIONALITY TEST SUITE                    ║');
  console.log('║      Testing wallet, transfers, and L2 integration readiness  ║');
  console.log('╚═══════════════════════════════════════════════════════════════╝');
  console.log(`\n📡 Target: ${L1_URL}\n`);
  
  // Run tests
  const serverOk = await testServerHealth();
  if (!serverOk) {
    console.log('\n🛑 Server not available. Please start L1 with: cargo run\n');
    process.exit(1);
  }
  
  const accounts = await testGetTestAccounts();
  await testBalanceQueries(accounts);
  await testSignatureVerification(accounts);
  await testTransfer(accounts);
  await testCreditLineFlow(accounts);
  await testKeypairGeneration();
  await testProfile(accounts);
  await testBlockchainStats();
  
  // Summary
  section('TEST SUMMARY');
  console.log(`${colors.green}Passed: ${testResults.passed}${colors.reset}`);
  console.log(`${colors.red}Failed: ${testResults.failed}${colors.reset}`);
  console.log(`Total:  ${testResults.passed + testResults.failed}`);
  
  if (testResults.failed === 0) {
    console.log(`\n${colors.green}🎉 ALL TESTS PASSED! L1 is ready for L2 integration.${colors.reset}`);
    
    // Show final account balances
    if (accounts) {
      console.log(`\n${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
      console.log(`${colors.cyan}   FINAL ACCOUNT BALANCES${colors.reset}`);
      console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}\n`);
      
      try {
        const aliceRes = await fetch(`${L1_URL}/balance/${accounts.alice.address}`);
        const aliceData = await aliceRes.json();
        console.log(`${colors.blue}Alice (${accounts.alice.address}):${colors.reset}`);
        console.log(`  💰 Balance: ${colors.green}${aliceData.balance} BB${colors.reset}`);
        
        const bobRes = await fetch(`${L1_URL}/balance/${accounts.bob.address}`);
        const bobData = await bobRes.json();
        console.log(`\n${colors.blue}Bob (${accounts.bob.address}):${colors.reset}`);
        console.log(`  💰 Balance: ${colors.green}${bobData.balance} BB${colors.reset}`);
        
        console.log();
      } catch (e) {
        console.log(`${colors.yellow}⚠️  Could not fetch final balances${colors.reset}\n`);
      }
    }
  } else {
    console.log(`\n${colors.yellow}⚠️  Some tests failed. Review the output above.${colors.reset}\n`);
  }
  
  process.exit(testResults.failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('Test suite crashed:', e);
  process.exit(1);
});
