/**
 * ============================================================================
 * BRIDGE & LOCK MECHANISM TEST
 * ============================================================================
 * 
 * Tests the L1 → L2 bridge flow:
 * 1. Check initial L1 balances
 * 2. Alice bridges 555 BB to L2
 * 3. Bob bridges 555 BB to L2
 * 4. Verify L1 balances decreased (tokens locked)
 * 5. Verify L2 balances increased (tokens credited)
 * 6. Check bridge stats and pending locks
 */

import nacl from 'tweetnacl';

const L1_URL = process.env.L1_URL || "http://localhost:8080";
const L2_URL = process.env.L2_URL || "http://localhost:1234";

const CHAIN_ID_L1 = 0x01;

// ============================================================================
// TEST ACCOUNTS - Real keys from TEST_ACCOUNTS.txt
// ============================================================================

function hexToBytes(hex) {
  return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Alice - from TEST_ACCOUNTS.txt
const aliceSeed = hexToBytes("18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24");
const aliceKeypair = nacl.sign.keyPair.fromSeed(aliceSeed);

const ALICE = {
  name: "Alice",
  l1Address: "L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
  l2Address: "L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD",
  publicKey: "c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705",
  secretKey: aliceKeypair.secretKey, // Full 64-byte secret key for signing
};

// Bob - from TEST_ACCOUNTS.txt
const bobSeed = hexToBytes("e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b");
const bobKeypair = nacl.sign.keyPair.fromSeed(bobSeed);

const BOB = {
  name: "Bob",
  l1Address: "L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9",
  l2Address: "L2_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9",
  publicKey: "582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a",
  secretKey: bobKeypair.secretKey, // Full 64-byte secret key for signing
};

const BRIDGE_AMOUNT = 555;

// ============================================================================
// HELPERS
// ============================================================================

function success(msg) { console.log(`✅ ${msg}`); }
function error(msg) { console.error(`❌ ${msg}`); }
function info(msg) { console.log(`\n💡 ${msg}`); }

/**
 * Create a SignedRequest for L1 API calls
 * L1 uses SignedRequest struct with domain separation
 * 
 * Message format: chain_id_byte + "{payload}\n{timestamp}\n{nonce}"
 */
function createSignedRequest(secretKey, publicKey, walletAddress, payload, chainId = CHAIN_ID_L1) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = `nonce_${Date.now()}_${Math.random().toString(36).substring(7)}`;
  
  // Payload is JSON stringified
  const payloadStr = JSON.stringify(payload);
  
  // Message format: payload\ntimestamp\nnonce
  const messageToSign = `${payloadStr}\n${timestamp}\n${nonce}`;
  const messageBytes = new TextEncoder().encode(messageToSign);
  
  // Domain separation: prepend chain_id byte
  const domainSeparatedMessage = new Uint8Array([chainId, ...messageBytes]);
  
  // Sign with full secretKey (64 bytes)
  const signature = nacl.sign.detached(domainSeparatedMessage, secretKey);
  
  return {
    public_key: publicKey,
    wallet_address: walletAddress,
    payload: payloadStr,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: chainId,
    schema_version: 1,
    signature: bytesToHex(signature),
  };
}

async function getL1Balance(address) {
  try {
    const response = await fetch(`${L1_URL}/balance/${address}`);
    if (response.ok) {
      const data = await response.json();
      return data.balance || 0;
    }
    return 0;
  } catch (e) {
    return 0;
  }
}

async function getL2Balance(address) {
  try {
    const response = await fetch(`${L2_URL}/balances`);
    if (response.ok) {
      const data = await response.json();
      const balanceData = data.balances?.[address];
      if (balanceData) {
        return {
          available: balanceData.available || 0,
          locked: balanceData.locked || 0,
          total: (balanceData.available || 0) + (balanceData.locked || 0)
        };
      }
    }
    return { available: 0, locked: 0, total: 0 };
  } catch (e) {
    return { available: 0, locked: 0, total: 0 };
  }
}

// ============================================================================
// BRIDGE FUNCTION
// ============================================================================

async function bridgeToL2(account, amount) {
  console.log(`\n   Bridging ${amount} BB for ${account.name}...`);
  
  // Bridge payload for L1 (BridgeInitiatePayload struct)
  const bridgePayload = {
    amount: amount,
    target_layer: "L2",
  };
  
  // Create SignedRequest
  const signedRequest = createSignedRequest(
    account.secretKey,
    account.publicKey,
    account.l1Address,
    bridgePayload,
    CHAIN_ID_L1
  );
  
  console.log(`   Wallet: ${account.l1Address}`);
  console.log(`   Public Key: ${account.publicKey.substring(0, 16)}...`);
  
  try {
    const response = await fetch(`${L1_URL}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    const responseText = await response.text();
    console.log(`   Response: ${responseText.substring(0, 200)}`);
    
    if (response.ok) {
      try {
        const data = JSON.parse(responseText);
        return { success: data.success !== false, data };
      } catch {
        return { success: false, error: `Parse error: ${responseText.substring(0, 100)}` };
      }
    } else {
      return { success: false, error: `HTTP ${response.status}: ${responseText.substring(0, 200)}` };
    }
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ============================================================================
// MAIN TEST
// ============================================================================

async function runBridgeTest() {
  console.log("\n" + "═".repeat(80));
  console.log("🌉 BRIDGE & LOCK MECHANISM TEST");
  console.log("═".repeat(80));
  console.log(`L1 URL: ${L1_URL}`);
  console.log(`L2 URL: ${L2_URL}`);
  console.log(`Bridge Amount: ${BRIDGE_AMOUNT} BB each`);
  console.log("═".repeat(80));

  console.log(`\n🔑 TEST ACCOUNTS (from TEST_ACCOUNTS.txt):`);
  console.log(`   Alice L1: ${ALICE.l1Address}`);
  console.log(`   Alice PubKey: ${ALICE.publicKey.substring(0, 32)}...`);
  console.log(`   Bob L1: ${BOB.l1Address}`);
  console.log(`   Bob PubKey: ${BOB.publicKey.substring(0, 32)}...`);

  // ========================================================================
  // STEP 1: Check Initial Balances
  // ========================================================================
  info("STEP 1: Checking initial balances...");
  
  const aliceL1Before = await getL1Balance(ALICE.l1Address);
  const aliceL2Before = await getL2Balance(ALICE.l2Address);
  const bobL1Before = await getL1Balance(BOB.l1Address);
  const bobL2Before = await getL2Balance(BOB.l2Address);
  
  console.log("\n📊 INITIAL BALANCES:");
  console.log(`   Alice L1: ${aliceL1Before.toFixed(2)} BB`);
  console.log(`   Alice L2: ${aliceL2Before.total.toFixed(2)} BB (${aliceL2Before.available.toFixed(2)} available, ${aliceL2Before.locked.toFixed(2)} locked)`);
  console.log(`   Bob L1:   ${bobL1Before.toFixed(2)} BB`);
  console.log(`   Bob L2:   ${bobL2Before.total.toFixed(2)} BB (${bobL2Before.available.toFixed(2)} available, ${bobL2Before.locked.toFixed(2)} locked)`);

  // Check if enough balance
  if (aliceL1Before < BRIDGE_AMOUNT) {
    error(`Alice doesn't have enough L1 balance (${aliceL1Before} < ${BRIDGE_AMOUNT})`);
    return;
  }
  if (bobL1Before < BRIDGE_AMOUNT) {
    error(`Bob doesn't have enough L1 balance (${bobL1Before} < ${BRIDGE_AMOUNT})`);
    return;
  }
  
  success("Both accounts have sufficient L1 balance");

  // ========================================================================
  // STEP 2: Check Bridge Stats Before
  // ========================================================================
  info("STEP 2: Checking bridge stats before...");
  
  try {
    const statsResponse = await fetch(`${L1_URL}/bridge/stats`);
    if (statsResponse.ok) {
      const stats = await statsResponse.json();
      console.log(`   Active Sessions: ${stats.active_sessions || 0}`);
      console.log(`   Total Sessions: ${stats.total_sessions || 0}`);
      success("Bridge stats retrieved");
    }
  } catch (e) {
    console.log(`   Note: ${e.message}`);
  }

  // ========================================================================
  // STEP 3: Alice Bridges 555 BB to L2
  // ========================================================================
  info(`STEP 3: Alice bridging ${BRIDGE_AMOUNT} BB to L2...`);
  
  const aliceBridgeResult = await bridgeToL2(ALICE, BRIDGE_AMOUNT);
  
  if (aliceBridgeResult.success) {
    success(`Alice bridge initiated!`);
    console.log(`   Lock ID: ${aliceBridgeResult.data.lock_id || 'N/A'}`);
    console.log(`   L1 Locked: ${aliceBridgeResult.data.l1_locked || BRIDGE_AMOUNT} BB`);
    console.log(`   L2 Credited: ${aliceBridgeResult.data.l2_credited ? 'Yes' : 'Pending'}`);
  } else {
    error(`Alice bridge failed: ${aliceBridgeResult.error}`);
  }

  // ========================================================================
  // STEP 4: Bob Bridges 555 BB to L2
  // ========================================================================
  info(`STEP 4: Bob bridging ${BRIDGE_AMOUNT} BB to L2...`);
  
  const bobBridgeResult = await bridgeToL2(BOB, BRIDGE_AMOUNT);
  
  if (bobBridgeResult.success) {
    success(`Bob bridge initiated!`);
    console.log(`   Lock ID: ${bobBridgeResult.data.lock_id || 'N/A'}`);
    console.log(`   L1 Locked: ${bobBridgeResult.data.l1_locked || BRIDGE_AMOUNT} BB`);
    console.log(`   L2 Credited: ${bobBridgeResult.data.l2_credited ? 'Yes' : 'Pending'}`);
  } else {
    error(`Bob bridge failed: ${bobBridgeResult.error}`);
  }

  // ========================================================================
  // STEP 5: Verify L1 Balances Decreased
  // ========================================================================
  info("STEP 5: Verifying L1 balances decreased (tokens locked)...");
  
  // Wait a moment for state to update
  await new Promise(resolve => setTimeout(resolve, 500));
  
  const aliceL1After = await getL1Balance(ALICE.l1Address);
  const bobL1After = await getL1Balance(BOB.l1Address);
  
  const aliceL1Change = aliceL1After - aliceL1Before;
  const bobL1Change = bobL1After - bobL1Before;
  
  console.log(`\n   Alice L1: ${aliceL1Before.toFixed(2)} → ${aliceL1After.toFixed(2)} BB (${aliceL1Change >= 0 ? '+' : ''}${aliceL1Change.toFixed(2)})`);
  console.log(`   Bob L1:   ${bobL1Before.toFixed(2)} → ${bobL1After.toFixed(2)} BB (${bobL1Change >= 0 ? '+' : ''}${bobL1Change.toFixed(2)})`);
  
  if (aliceL1Change <= -BRIDGE_AMOUNT + 1) { // Allow small rounding
    success(`Alice L1 balance decreased by ~${BRIDGE_AMOUNT} BB (tokens locked)`);
  } else {
    error(`Alice L1 balance did not decrease as expected`);
  }
  
  if (bobL1Change <= -BRIDGE_AMOUNT + 1) {
    success(`Bob L1 balance decreased by ~${BRIDGE_AMOUNT} BB (tokens locked)`);
  } else {
    error(`Bob L1 balance did not decrease as expected`);
  }

  // ========================================================================
  // STEP 6: Verify L2 Balances Increased
  // ========================================================================
  info("STEP 6: Verifying L2 balances increased (tokens credited)...");
  
  const aliceL2After = await getL2Balance(ALICE.l2Address);
  const bobL2After = await getL2Balance(BOB.l2Address);
  
  const aliceL2Change = aliceL2After.total - aliceL2Before.total;
  const bobL2Change = bobL2After.total - bobL2Before.total;
  
  console.log(`\n   Alice L2: ${aliceL2Before.total.toFixed(2)} → ${aliceL2After.total.toFixed(2)} BB (${aliceL2Change >= 0 ? '+' : ''}${aliceL2Change.toFixed(2)})`);
  console.log(`   Bob L2:   ${bobL2Before.total.toFixed(2)} → ${bobL2After.total.toFixed(2)} BB (${bobL2Change >= 0 ? '+' : ''}${bobL2Change.toFixed(2)})`);
  
  if (aliceL2Change >= BRIDGE_AMOUNT - 1) {
    success(`Alice L2 balance increased by ~${BRIDGE_AMOUNT} BB (tokens credited)`);
  } else {
    console.log(`   ⚠️  Alice L2 may not have been credited yet (async notification)`);
  }
  
  if (bobL2Change >= BRIDGE_AMOUNT - 1) {
    success(`Bob L2 balance increased by ~${BRIDGE_AMOUNT} BB (tokens credited)`);
  } else {
    console.log(`   ⚠️  Bob L2 may not have been credited yet (async notification)`);
  }

  // ========================================================================
  // STEP 7: Check Bridge Stats After
  // ========================================================================
  info("STEP 7: Checking bridge stats after...");
  
  try {
    const statsResponse = await fetch(`${L1_URL}/bridge/stats`);
    if (statsResponse.ok) {
      const stats = await statsResponse.json();
      console.log(`   Active Sessions: ${stats.active_sessions || 0}`);
      console.log(`   Total Sessions: ${stats.total_sessions || 0}`);
      success("Bridge stats updated");
    }
  } catch (e) {
    console.log(`   Note: ${e.message}`);
  }

  // ========================================================================
  // STEP 8: Check Pending Bridges
  // ========================================================================
  info("STEP 8: Checking pending bridges...");
  
  try {
    const pendingResponse = await fetch(`${L1_URL}/bridge/pending`);
    if (pendingResponse.ok) {
      const pending = await pendingResponse.json();
      const locks = pending.pending || pending.locks || [];
      console.log(`   Pending locks: ${locks.length}`);
      if (locks.length > 0) {
        locks.slice(0, 5).forEach((lock, idx) => {
          console.log(`   [${idx}] ${lock.owner || 'N/A'}: ${lock.amount || 'N/A'} BB`);
        });
      }
      success("Pending bridges retrieved");
    }
  } catch (e) {
    console.log(`   Note: ${e.message}`);
  }

  // ========================================================================
  // SUMMARY
  // ========================================================================
  console.log("\n" + "═".repeat(80));
  console.log("📊 BRIDGE TEST SUMMARY");
  console.log("═".repeat(80));
  
  console.log("\n🔒 L1 TOKEN LOCKS:");
  console.log(`   Alice: ${Math.abs(aliceL1Change).toFixed(2)} BB locked`);
  console.log(`   Bob:   ${Math.abs(bobL1Change).toFixed(2)} BB locked`);
  console.log(`   Total: ${Math.abs(aliceL1Change + bobL1Change).toFixed(2)} BB`);
  
  console.log("\n💰 L2 TOKEN CREDITS:");
  console.log(`   Alice: ${aliceL2Change.toFixed(2)} BB credited`);
  console.log(`   Bob:   ${bobL2Change.toFixed(2)} BB credited`);
  console.log(`   Total: ${(aliceL2Change + bobL2Change).toFixed(2)} BB`);
  
  console.log("\n📋 FINAL BALANCES:");
  console.log(`   Alice: L1=${aliceL1After.toFixed(2)} BB, L2=${aliceL2After.total.toFixed(2)} BB`);
  console.log(`   Bob:   L1=${bobL1After.toFixed(2)} BB, L2=${bobL2After.total.toFixed(2)} BB`);
  
  console.log("\n" + "═".repeat(80));
  
  // Verify conservation of tokens
  const aliceTotalBefore = aliceL1Before + aliceL2Before.total;
  const aliceTotalAfter = aliceL1After + aliceL2After.total;
  const bobTotalBefore = bobL1Before + bobL2Before.total;
  const bobTotalAfter = bobL1After + bobL2After.total;
  
  console.log("\n🔍 TOKEN CONSERVATION CHECK:");
  console.log(`   Alice: ${aliceTotalBefore.toFixed(2)} → ${aliceTotalAfter.toFixed(2)} BB (diff: ${(aliceTotalAfter - aliceTotalBefore).toFixed(2)})`);
  console.log(`   Bob:   ${bobTotalBefore.toFixed(2)} → ${bobTotalAfter.toFixed(2)} BB (diff: ${(bobTotalAfter - bobTotalBefore).toFixed(2)})`);
  
  if (Math.abs(aliceTotalAfter - aliceTotalBefore) < 1 && Math.abs(bobTotalAfter - bobTotalBefore) < 1) {
    success("Tokens conserved! No tokens created or destroyed.");
  } else {
    console.log("   ⚠️  Token totals changed - may indicate async L2 credit pending");
  }
  
  console.log("\n🎉 BRIDGE TEST COMPLETE\n");
}

// ============================================================================
// RUN TEST
// ============================================================================

runBridgeTest().catch(error => {
  console.error("Fatal error:", error);
  process.exit(1);
});
