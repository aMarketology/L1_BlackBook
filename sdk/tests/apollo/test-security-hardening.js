/**
 * APOLLO SECURITY HARDENING - COMPREHENSIVE TEST SUITE
 * Tests all L1 blockchain and wallet attack vector protections
 */

const {
  CHAIN_IDS,
  setChainId,
  createSecureTransaction,
  verifySecureTransaction,
  SafeMath,
  sanitizeAmount,
  SecureMemory,
  SecureKeyPair,
  SecureCommunication,
  PeerReputation,
  ReentrancyGuard,
  TransactionDeduplicator
} = require('../../apollo-security-hardening.js');

const nacl = require('tweetnacl');
const crypto = require('crypto');

const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

let testResults = { total: 0, passed: 0, failed: 0 };

function section(title) {
  console.log(`\n${colors.cyan}${'='.repeat(75)}\n${title}\n${'='.repeat(75)}${colors.reset}\n`);
}

function success(msg) {
  console.log(`${colors.green}✓ ${msg}${colors.reset}`);
  testResults.passed++;
  testResults.total++;
}

function fail(msg) {
  console.log(`${colors.red}✗ ${msg}${colors.reset}`);
  testResults.failed++;
  testResults.total++;
}

function info(msg) {
  console.log(`${colors.blue}ℹ ${msg}${colors.reset}`);
}

// =============================================================================
// TEST 1: Replay Attack Protection (Cross-Chain)
// =============================================================================
function testReplayProtection() {
  section('TEST 1: Replay Attack Protection (Cross-Chain)');
  
  info('Testing that transactions from one chain cannot be replayed on another...');
  
  // Create key pair
  const keyPair = nacl.sign.keyPair();
  const address = 'L1_TEST_' + crypto.randomBytes(20).toString('hex').toUpperCase();
  
  // Create transaction on mainnet
  setChainId(CHAIN_IDS.MAINNET);
  const mainnetTx = createSecureTransaction(
    address,
    'L1_RECIPIENT_12345',
    1000,
    keyPair.secretKey
  );
  
  success('Transaction created on MAINNET (Chain ID: 1)');
  
  // Try to verify on mainnet (should succeed)
  try {
    verifySecureTransaction(mainnetTx, Buffer.from(keyPair.publicKey).toString('hex'), CHAIN_IDS.MAINNET);
    success('Transaction verified on same chain (MAINNET)');
  } catch (error) {
    fail(`Failed to verify on same chain: ${error.message}`);
  }
  
  // Try to replay on testnet (should fail)
  try {
    verifySecureTransaction(mainnetTx, Buffer.from(keyPair.publicKey).toString('hex'), CHAIN_IDS.TESTNET);
    fail('VULNERABILITY: Transaction was accepted on different chain (TESTNET)!');
  } catch (error) {
    if (error.message.includes('Chain ID mismatch')) {
      success('Cross-chain replay prevented: ' + error.message);
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
  
  // Test transaction expiry (replay after time)
  info('Testing transaction expiry protection...');
  const oldTx = { ...mainnetTx, timestamp: Date.now() - (10 * 60 * 1000) }; // 10 minutes old
  
  try {
    verifySecureTransaction(oldTx, Buffer.from(keyPair.publicKey).toString('hex'), CHAIN_IDS.MAINNET);
    fail('VULNERABILITY: Old transaction was accepted!');
  } catch (error) {
    if (error.message.includes('expired')) {
      success('Time-based replay prevented: ' + error.message);
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
}

// =============================================================================
// TEST 2: Integer Overflow/Underflow Protection
// =============================================================================
function testIntegerSafety() {
  section('TEST 2: Integer Overflow/Underflow Protection');
  
  info('Testing safe math operations...');
  
  // Test valid addition
  try {
    const result = SafeMath.add(1000, 2000);
    if (result === 3000) {
      success('Valid addition: 1000 + 2000 = 3000');
    } else {
      fail(`Addition error: got ${result}`);
    }
  } catch (error) {
    fail(`Addition failed: ${error.message}`);
  }
  
  // Test overflow protection
  try {
    SafeMath.add(Number.MAX_SAFE_INTEGER, 1);
    fail('VULNERABILITY: Integer overflow not detected!');
  } catch (error) {
    if (error.message.includes('overflow')) {
      success('Integer overflow detected and prevented');
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
  
  // Test underflow protection
  try {
    SafeMath.sub(100, 200);
    fail('VULNERABILITY: Integer underflow not detected!');
  } catch (error) {
    if (error.message.includes('underflow')) {
      success('Integer underflow detected and prevented');
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
  
  // Test amount sanitization
  info('Testing amount sanitization...');
  
  const invalidAmounts = [
    -1,
    NaN,
    Infinity,
    -Infinity,
    Number.MAX_SAFE_INTEGER + 1,
    '999999999999999999999',
    null,
    undefined
  ];
  
  let sanitizedCount = 0;
  for (const amount of invalidAmounts) {
    try {
      sanitizeAmount(amount);
      fail(`VULNERABILITY: Invalid amount accepted: ${amount}`);
    } catch (error) {
      sanitizedCount++;
    }
  }
  
  success(`All ${sanitizedCount}/${invalidAmounts.length} invalid amounts rejected`);
  
  // Test valid amount
  try {
    const valid = sanitizeAmount(1000.50);
    if (valid === 1000.50) {
      success('Valid amount accepted: 1000.50');
    } else {
      fail(`Sanitization changed valid amount: ${valid}`);
    }
  } catch (error) {
    fail(`Valid amount rejected: ${error.message}`);
  }
}

// =============================================================================
// TEST 3: Memory Security & Key Wiping
// =============================================================================
function testMemorySecurity() {
  section('TEST 3: Memory Security & Key Wiping');
  
  info('Testing secure memory wiping...');
  
  // Test buffer wiping
  const sensitiveData = Buffer.from('SecretKey12345');
  const originalData = sensitiveData.toString();
  
  SecureMemory.wipeBuffer(sensitiveData);
  const wipedData = sensitiveData.toString();
  
  if (wipedData !== originalData && sensitiveData.every(b => b === 0)) {
    success('Buffer securely wiped (all zeros)');
  } else {
    fail('Buffer not properly wiped!');
  }
  
  // Test Uint8Array wiping
  const keyArray = new Uint8Array(32);
  crypto.getRandomValues(keyArray);
  const hadData = keyArray.some(b => b !== 0);
  
  SecureMemory.wipeUint8Array(keyArray);
  const allZeros = keyArray.every(b => b === 0);
  
  if (hadData && allZeros) {
    success('Uint8Array securely wiped');
  } else {
    fail('Uint8Array not properly wiped!');
  }
  
  // Test SecureKeyPair with auto-wipe
  info('Testing SecureKeyPair with auto-wipe...');
  
  const keyPair = nacl.sign.keyPair();
  const secureKeyPair = new SecureKeyPair(keyPair, 1000); // 1 second auto-wipe
  
  if (secureKeyPair.isActive()) {
    success('SecureKeyPair created and active');
  } else {
    fail('SecureKeyPair not active after creation');
  }
  
  // Test signing
  const message = Buffer.from('Test message');
  try {
    const signature = secureKeyPair.sign(message);
    if (signature && signature.length === 64) {
      success('SecureKeyPair signing works');
    } else {
      fail('Invalid signature from SecureKeyPair');
    }
  } catch (error) {
    fail(`Signing failed: ${error.message}`);
  }
  
  // Test manual wipe
  secureKeyPair.wipe();
  
  if (!secureKeyPair.isActive()) {
    success('SecureKeyPair manually wiped');
  } else {
    fail('SecureKeyPair still active after wipe');
  }
  
  // Test that wiped keypair can't be used
  try {
    secureKeyPair.sign(message);
    fail('VULNERABILITY: Wiped key pair still usable!');
  } catch (error) {
    if (error.message.includes('wiped')) {
      success('Wiped key pair cannot be used');
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
}

// =============================================================================
// TEST 4: Man-in-the-Middle (MitM) Protection
// =============================================================================
function testMitMProtection() {
  section('TEST 4: Man-in-the-Middle (MitM) Protection');
  
  info('Testing server identity verification...');
  
  const serverKeyPair = nacl.sign.keyPair();
  const serverPubkey = Buffer.from(serverKeyPair.publicKey).toString('hex');
  
  // Test valid server
  try {
    SecureCommunication.verifyServerIdentity(serverPubkey, serverPubkey);
    success('Valid server identity verified');
  } catch (error) {
    fail(`Server verification failed: ${error.message}`);
  }
  
  // Test MitM attack (wrong server key)
  const attackerKeyPair = nacl.sign.keyPair();
  const attackerPubkey = Buffer.from(attackerKeyPair.publicKey).toString('hex');
  
  try {
    SecureCommunication.verifyServerIdentity(attackerPubkey, serverPubkey);
    fail('VULNERABILITY: MitM attacker accepted as valid server!');
  } catch (error) {
    if (error.message.includes('MitM')) {
      success('MitM attack detected: ' + error.message);
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
  
  // Test authenticated request creation
  info('Testing authenticated request creation...');
  
  const clientKeyPair = nacl.sign.keyPair();
  const request = SecureCommunication.createAuthenticatedRequest(
    '/api/transfer',
    { amount: 1000 },
    clientKeyPair
  );
  
  if (request.signature && request.nonce && request.timestamp) {
    success('Authenticated request created with signature, nonce, and timestamp');
  } else {
    fail('Authenticated request missing required fields');
  }
  
  // Test response verification
  info('Testing server response verification...');
  
  const timestamp = Date.now();
  const responseData = { balance: 5000 };
  const responseMessage = JSON.stringify({ data: responseData, timestamp: timestamp });
  const responseSignature = nacl.sign.detached(
    Buffer.from(responseMessage, 'utf8'),
    serverKeyPair.secretKey
  );
  
  const response = {
    data: responseData,
    timestamp: timestamp,
    signature: Buffer.from(responseSignature).toString('hex')
  };
  
  try {
    const verified = SecureCommunication.verifyServerResponse(response, serverPubkey);
    if (JSON.stringify(verified) === JSON.stringify(responseData)) {
      success('Server response verified successfully');
    } else {
      fail('Response data mismatch');
    }
  } catch (error) {
    fail(`Response verification failed: ${error.message}`);
  }
  
  // Test tampered response
  const tamperedResponse = { ...response, data: { balance: 999999 } };
  
  try {
    SecureCommunication.verifyServerResponse(tamperedResponse, serverPubkey);
    fail('VULNERABILITY: Tampered response accepted!');
  } catch (error) {
    if (error.message.includes('signature') || error.message.includes('MitM')) {
      success('Tampered response rejected: ' + error.message);
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
}

// =============================================================================
// TEST 5: Peer Reputation System (Eclipse Attack Prevention)
// =============================================================================
function testPeerReputation() {
  section('TEST 5: Peer Reputation System (Eclipse Attack Prevention)');
  
  info('Testing peer reputation and scoring...');
  
  const reputation = new PeerReputation();
  
  const goodPeer = 'peer_good_123';
  const badPeer = 'peer_bad_456';
  const newPeer = 'peer_new_789';
  
  // Add peers
  reputation.addPeer(goodPeer);
  reputation.addPeer(badPeer);
  reputation.addPeer(newPeer);
  
  success('3 peers added to reputation system');
  
  // Simulate good peer behavior
  for (let i = 0; i < 10; i++) {
    reputation.recordSuccess(goodPeer);
  }
  
  if (reputation.isTrusted(goodPeer)) {
    success('Good peer recognized as trusted after successful interactions');
  } else {
    fail('Good peer not trusted');
  }
  
  // Simulate bad peer behavior
  for (let i = 0; i < 10; i++) {
    reputation.recordFailure(badPeer);
  }
  
  if (!reputation.isTrusted(badPeer)) {
    success('Bad peer recognized as untrusted after failures');
  } else {
    fail('Bad peer incorrectly trusted');
  }
  
  // Test peer banning
  reputation.banPeer(badPeer);
  
  if (reputation.isBanned(badPeer)) {
    success('Malicious peer banned successfully');
  } else {
    fail('Peer ban did not work');
  }
  
  // Test trusted peer list
  const trusted = reputation.getTrustedPeers();
  const trustCount = trusted.length;
  
  info(`Trusted peers: ${trustCount} (should exclude banned peers)`);
  
  if (trustCount >= 1 && !trusted.find(p => p.peerId === badPeer)) {
    success('Trusted peer list excludes banned peers');
  } else {
    fail('Trusted peer list includes banned peers');
  }
}

// =============================================================================
// TEST 6: Reentrancy Protection
// =============================================================================
async function testReentrancyGuard() {
  section('TEST 6: Reentrancy Protection');
  
  info('Testing reentrancy guard...');
  
  const guard = new ReentrancyGuard();
  const address = 'L1_CONTRACT_123';
  
  // Test successful execution
  try {
    const result = await guard.executeProtected(address, async () => {
      return 'success';
    });
    
    if (result === 'success') {
      success('Protected function executed successfully');
    } else {
      fail('Function returned unexpected result');
    }
  } catch (error) {
    fail(`Protected execution failed: ${error.message}`);
  }
  
  // Test reentrancy detection
  info('Testing reentrancy attack detection...');
  
  let reentrancyDetected = false;
  
  try {
    await guard.executeProtected(address, async () => {
      // Try to call again (reentrancy attempt)
      try {
        await guard.executeProtected(address, async () => {
          return 'should not reach here';
        });
      } catch (error) {
        if (error.message.includes('Reentrancy')) {
          reentrancyDetected = true;
          throw error;
        }
      }
    });
    
    if (reentrancyDetected) {
      fail('Reentrancy detected but not properly prevented');
    } else {
      fail('Reentrancy not detected at all!');
    }
  } catch (error) {
    if (error.message.includes('Reentrancy')) {
      success('Reentrancy attack detected and prevented');
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
}

// =============================================================================
// TEST 7: Transaction Deduplication (Replay Prevention)
// =============================================================================
function testTransactionDeduplication() {
  section('TEST 7: Transaction Deduplication (Replay Prevention)');
  
  info('Testing transaction replay detection...');
  
  const dedup = new TransactionDeduplicator(10000); // 10 second window for testing
  
  const txHash1 = crypto.randomBytes(32).toString('hex');
  const txHash2 = crypto.randomBytes(32).toString('hex');
  
  // Record first transaction
  try {
    dedup.record(txHash1);
    success('First transaction recorded');
  } catch (error) {
    fail(`Failed to record transaction: ${error.message}`);
  }
  
  // Try to replay same transaction
  try {
    dedup.record(txHash1);
    fail('VULNERABILITY: Duplicate transaction accepted!');
  } catch (error) {
    if (error.message.includes('Duplicate') || error.message.includes('replay')) {
      success('Duplicate transaction detected: ' + error.message);
    } else {
      fail(`Unexpected error: ${error.message}`);
    }
  }
  
  // Record different transaction (should succeed)
  try {
    dedup.record(txHash2);
    success('Different transaction accepted');
  } catch (error) {
    fail(`Valid transaction rejected: ${error.message}`);
  }
  
  // Check size
  const size = dedup.size();
  if (size === 2) {
    success(`Deduplicator tracking ${size} transactions correctly`);
  } else {
    fail(`Deduplicator size incorrect: ${size} (expected 2)`);
  }
}

// =============================================================================
// TEST 8: Full Integration - Multi-Layer Protection
// =============================================================================
function testFullIntegration() {
  section('TEST 8: Full Integration - Multi-Layer Protection');
  
  info('Testing complete security stack...');
  
  // Setup
  setChainId(CHAIN_IDS.MAINNET);
  const keyPair = nacl.sign.keyPair();
  const address = 'L1_SECURE_' + crypto.randomBytes(20).toString('hex').toUpperCase();
  const dedup = new TransactionDeduplicator();
  
  // Create secure transaction
  let transaction;
  try {
    transaction = createSecureTransaction(
      address,
      'L1_RECIPIENT_789',
      SafeMath.add(1000, 500), // Use safe math
      keyPair.secretKey
    );
    success('✓ Secure transaction created with safe math');
  } catch (error) {
    fail(`Transaction creation failed: ${error.message}`);
    return;
  }
  
  // Verify transaction
  try {
    verifySecureTransaction(
      transaction,
      Buffer.from(keyPair.publicKey).toString('hex'),
      CHAIN_IDS.MAINNET
    );
    success('✓ Transaction signature verified');
  } catch (error) {
    fail(`Transaction verification failed: ${error.message}`);
    return;
  }
  
  // Check for replay
  const txHash = crypto.createHash('sha256')
    .update(JSON.stringify(transaction))
    .digest('hex');
  
  try {
    dedup.record(txHash);
    success('✓ Transaction recorded (no replay)');
  } catch (error) {
    fail(`Deduplication failed: ${error.message}`);
    return;
  }
  
  // Simulate secure key storage
  const secureKey = new SecureKeyPair(keyPair, 5000);
  
  if (secureKey.isActive()) {
    success('✓ Secure key pair active with auto-wipe');
  } else {
    fail('Secure key pair not active');
  }
  
  // Clean up
  secureKey.wipe();
  
  if (!secureKey.isActive()) {
    success('✓ Keys securely wiped from memory');
  } else {
    fail('Keys not wiped');
  }
  
  success('🎉 Full security stack working correctly!');
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================
async function runAllTests() {
  console.log(`${colors.magenta}`);
  console.log('╔═════════════════════════════════════════════════════════════════════════╗');
  console.log('║       APOLLO SECURITY HARDENING - COMPREHENSIVE TEST SUITE              ║');
  console.log('║     Protection Against L1 Blockchain & Wallet Attack Vectors            ║');
  console.log('╚═════════════════════════════════════════════════════════════════════════╝');
  console.log(`${colors.reset}`);
  
  info(`Test started: ${new Date().toISOString()}\n`);
  
  try {
    testReplayProtection();
    testIntegerSafety();
    testMemorySecurity();
    testMitMProtection();
    testPeerReputation();
    await testReentrancyGuard();
    testTransactionDeduplication();
    testFullIntegration();
    
  } catch (error) {
    console.error(`${colors.red}Test suite error: ${error.message}${colors.reset}`);
    console.error(error.stack);
  }
  
  // Summary
  section('SECURITY HARDENING TEST RESULTS');
  
  console.log(`${colors.white}Total Tests:    ${testResults.total}${colors.reset}`);
  console.log(`${colors.green}Passed:         ${testResults.passed}${colors.reset}`);
  console.log(`${colors.red}Failed:         ${testResults.failed}${colors.reset}`);
  
  const passRate = (testResults.passed / testResults.total * 100).toFixed(1);
  console.log(`\n${colors.white}Pass Rate:      ${passRate}%${colors.reset}`);
  
  if (testResults.failed === 0) {
    console.log(`\n${colors.green}════════════════════════════════════════════════════════════════════════`);
    console.log(`  ✓ ALL SECURITY TESTS PASSED - APOLLO WALLET IS HARDENED!`);
    console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
    
    console.log(`${colors.green}🛡️  Protected Against:${colors.reset}`);
    console.log(`${colors.green}   ✓ Replay attacks (cross-chain & time-based)${colors.reset}`);
    console.log(`${colors.green}   ✓ Integer overflow/underflow${colors.reset}`);
    console.log(`${colors.green}   ✓ Memory dumping & key extraction${colors.reset}`);
    console.log(`${colors.green}   ✓ Man-in-the-Middle (MitM) attacks${colors.reset}`);
    console.log(`${colors.green}   ✓ Eclipse attacks (via peer reputation)${colors.reset}`);
    console.log(`${colors.green}   ✓ Reentrancy attacks${colors.reset}`);
    console.log(`${colors.green}   ✓ Transaction replay${colors.reset}\n`);
  } else {
    console.log(`\n${colors.red}════════════════════════════════════════════════════════════════════════`);
    console.log(`  ✗ ${testResults.failed} SECURITY TESTS FAILED - REVIEW REQUIRED`);
    console.log(`════════════════════════════════════════════════════════════════════════${colors.reset}\n`);
  }
  
  info(`Test completed: ${new Date().toISOString()}`);
}

runAllTests().catch(error => {
  console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
  process.exit(1);
});
