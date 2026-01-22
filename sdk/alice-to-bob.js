/**
 * ALICE ↔ BOB TRANSFER TEST
 * ==========================
 * Exponential transfer pattern: 5 → 25 → 125 → 625 → 3125 → ...
 * Alternates: Alice→Bob, Bob→Alice, Alice→Bob, ...
 * Continues until insufficient balance
 * 
 * Uses SDK TEST_ACCOUNTS as single source of truth
 */

import nacl from 'tweetnacl';

const L1_URL = 'http://localhost:8080';
const CHAIN_ID_L1 = 0x01;

// ============================================================================
// TEST ACCOUNTS (correctly derived from seeds)
// Address = L1_ + SHA256(pubkey)[0..20].toUpperCase()
// ============================================================================
const TEST_ACCOUNTS = {
  ALICE: {
    username: 'alice_test',
    email: 'alice@blackbook.test',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    publicKey: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    startingBalance: 20000.0,
  },
  BOB: {
    username: 'bob_test',
    email: 'bob@blackbook.test',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    publicKey: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    startingBalance: 10000.0,
  }
};

// ============================================================================
// CRYPTO UTILITIES
// ============================================================================

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

function generateNonce() {
  return crypto.randomUUID();
}

// ============================================================================
// ACCOUNT SETUP (from SDK)
// ============================================================================

// The SDK's publicKey field is actually the 32-byte seed for Ed25519 derivation
const ALICE = {
  name: 'Alice',
  address: TEST_ACCOUNTS.ALICE.address,
  seed: TEST_ACCOUNTS.ALICE.publicKey,  // 32-byte seed hex
  startingBalance: TEST_ACCOUNTS.ALICE.startingBalance
};

const BOB = {
  name: 'Bob', 
  address: TEST_ACCOUNTS.BOB.address,
  seed: TEST_ACCOUNTS.BOB.publicKey,  // 32-byte seed hex
  startingBalance: TEST_ACCOUNTS.BOB.startingBalance
};

// Derive Ed25519 keypair from seed
function deriveKeypair(seedHex) {
  const seed = hexToBytes(seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  return {
    publicKey: bytesToHex(keypair.publicKey),
    secretKey: keypair.secretKey  // 64 bytes: seed + public key
  };
}

// ============================================================================
// SIGNING (V2 Format - SDK Compatible)
// ============================================================================

async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function createSignedRequest(account, to, amount) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  
  // Derive keypair from seed
  const { publicKey, secretKey } = deriveKeypair(account.seed);
  
  // V2 format: Canonical payload hash (ordered fields)
  // Schema: ['from', 'to', 'amount', 'timestamp', 'nonce']
  const canonical = `${account.address}|${to}|${amount}|${timestamp}|${nonce}`;
  const payloadHash = await sha256(canonical);
  
  // Build signing message with domain separation
  const requestPath = '/transfer';
  const domainPrefix = `BLACKBOOK_L${CHAIN_ID_L1}${requestPath}`;
  const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
  
  // Sign with Ed25519
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, secretKey);
  
  return {
    public_key: publicKey,
    payload_hash: payloadHash,
    payload_fields: {
      from: account.address,
      to: to,
      amount: amount,
      timestamp: timestamp,
      nonce: nonce
    },
    operation_type: 'transfer',
    schema_version: 2,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: CHAIN_ID_L1,
    request_path: requestPath,
    signature: bytesToHex(signature)
  };
}

// ============================================================================
// API HELPERS
// ============================================================================

async function getBalance(address) {
  const res = await fetch(`${L1_URL}/balance/${address}`);
  const data = await res.json();
  return data.balance || 0;
}

async function transfer(fromAccount, toAddress, amount) {
  const signedRequest = await createSignedRequest(fromAccount, toAddress, amount);
  
  const res = await fetch(`${L1_URL}/transfer`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(signedRequest)
  });
  
  return {
    status: res.status,
    data: await res.json()
  };
}

async function healthCheck() {
  try {
    const res = await fetch(`${L1_URL}/health`);
    return await res.json();
  } catch (e) {
    return null;
  }
}

// ============================================================================
// TEST EXECUTION
// ============================================================================

async function runExponentialTransfers() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════════╗');
  console.log('║  ALICE ↔ BOB EXPONENTIAL TRANSFER TEST                                ║');
  console.log('║  Pattern: 5 → 25 → 125 → 625 → 3125 → ... (×5 each round)             ║');
  console.log('║  Alternates: Alice→Bob, Bob→Alice, Alice→Bob, ...                     ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════╝');
  console.log('');
  
  // Health check
  console.log('📡 Checking L1 server...');
  const health = await healthCheck();
  if (!health) {
    console.log('❌ L1 server not responding at', L1_URL);
    process.exit(1);
  }
  console.log(`✅ L1 Server: ${health.status}, Block Height: ${health.block_height}`);
  console.log('');
  
  // Initial balances
  console.log('💰 Initial Balances:');
  let aliceBalance = await getBalance(ALICE.address);
  let bobBalance = await getBalance(BOB.address);
  console.log(`   Alice (${ALICE.address.slice(0,14)}...): ${aliceBalance} BB`);
  console.log(`   Bob   (${BOB.address.slice(0,14)}...): ${bobBalance} BB`);
  console.log('');
  
  // Transfer pattern
  const MULTIPLIER = 5;
  let amount = 5;  // Start at 5 BB
  let round = 1;
  
  // DYNAMIC START: Whoever has MORE balance sends first
  // This ensures tests work regardless of previous runs
  let aliceToBoB = aliceBalance >= bobBalance;
  console.log(`📍 Starting with ${aliceToBoB ? 'Alice' : 'Bob'} (higher balance: ${aliceToBoB ? aliceBalance : bobBalance} BB)`);
  
  const results = [];
  
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('                         TRANSFER ROUNDS                               ');
  console.log('═══════════════════════════════════════════════════════════════════════');
  
  while (true) {
    const sender = aliceToBoB ? ALICE : BOB;
    const receiver = aliceToBoB ? BOB : ALICE;
    const senderBalance = aliceToBoB ? aliceBalance : bobBalance;
    
    console.log('');
    console.log(`📤 Round ${round}: ${sender.name} → ${receiver.name} : ${amount} BB`);
    console.log(`   ${sender.name}'s balance before: ${senderBalance} BB`);
    
    // Check if sender has enough
    if (senderBalance < amount) {
      console.log(`   ⛔ INSUFFICIENT BALANCE: ${sender.name} has ${senderBalance} BB, needs ${amount} BB`);
      results.push({
        round,
        from: sender.name,
        to: receiver.name,
        amount,
        success: false,
        reason: `Insufficient balance (${senderBalance} < ${amount})`
      });
      break;
    }
    
    // Execute transfer
    const result = await transfer(sender, receiver.address, amount);
    
    if (result.status === 200 && result.data.success) {
      console.log(`   ✅ SUCCESS!`);
      
      // Update tracked balances
      if (aliceToBoB) {
        aliceBalance -= amount;
        bobBalance += amount;
      } else {
        bobBalance -= amount;
        aliceBalance += amount;
      }
      
      console.log(`   Alice: ${aliceBalance} BB | Bob: ${bobBalance} BB`);
      
      results.push({
        round,
        from: sender.name,
        to: receiver.name,
        amount,
        success: true
      });
    } else {
      console.log(`   ❌ FAILED: ${result.data.error || result.data.message || JSON.stringify(result.data)}`);
      results.push({
        round,
        from: sender.name,
        to: receiver.name,
        amount,
        success: false,
        reason: result.data.error || result.data.message
      });
      break;
    }
    
    // Next round
    round++;
    amount *= MULTIPLIER;
    aliceToBoB = !aliceToBoB;  // Alternate direction
    
    // Add delay between transfers for realistic timing
    await new Promise(resolve => setTimeout(resolve, 50));
    
    // Safety limit (prevent infinite loops)
    if (round > 20) {
      console.log('   ⚠️ Reached 20 rounds, stopping...');
      break;
    }
  }
  
  // Final balances (verify from server)
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('                           FINAL RESULTS                               ');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  
  const aliceFinal = await getBalance(ALICE.address);
  const bobFinal = await getBalance(BOB.address);
  
  console.log('💰 Final Balances (from server):');
  console.log(`   Alice: ${aliceFinal} BB`);
  console.log(`   Bob:   ${bobFinal} BB`);
  console.log('');
  
  // Summary table
  console.log('📊 Transfer Summary:');
  console.log('┌───────┬─────────┬─────────┬────────────┬──────────┐');
  console.log('│ Round │ From    │ To      │ Amount     │ Status   │');
  console.log('├───────┼─────────┼─────────┼────────────┼──────────┤');
  
  for (const r of results) {
    const status = r.success ? '✅ OK' : '❌ FAIL';
    const amountStr = `${r.amount} BB`.padEnd(10);
    console.log(`│ ${String(r.round).padEnd(5)} │ ${r.from.padEnd(7)} │ ${r.to.padEnd(7)} │ ${amountStr} │ ${status.padEnd(8)} │`);
  }
  
  console.log('└───────┴─────────┴─────────┴────────────┴──────────┘');
  console.log('');
  
  const passed = results.filter(r => r.success).length;
  const failed = results.filter(r => !r.success).length;
  
  console.log(`✅ Passed: ${passed} transfers`);
  console.log(`❌ Failed: ${failed} transfers`);
  console.log('');
  
  // Calculate total transferred
  const totalTransferred = results.filter(r => r.success).reduce((sum, r) => sum + r.amount, 0);
  console.log(`💸 Total transferred: ${totalTransferred} BB ($${(totalTransferred * 0.01).toFixed(2)} USD)`);
  console.log('');
  
  // L1 Balance Summary
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('                        L1 BALANCE SUMMARY                             ');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  console.log('┌─────────┬──────────────────────────────────────────────┬─────────────┐');
  console.log('│ Account │ L1 Address                                   │ Balance     │');
  console.log('├─────────┼──────────────────────────────────────────────┼─────────────┤');
  console.log(`│ Alice   │ ${ALICE.address} │ ${String(aliceFinal).padStart(8)} BB │`);
  console.log(`│ Bob     │ ${BOB.address} │ ${String(bobFinal).padStart(8)} BB │`);
  console.log('└─────────┴──────────────────────────────────────────────┴─────────────┘');
  console.log('');
  
  // Exit code
  process.exit(failed > 0 && passed === 0 ? 1 : 0);
}

// ============================================================================
// MAIN
// ============================================================================

runExponentialTransfers().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
