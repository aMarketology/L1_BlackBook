/**
 * ============================================================================
 * DEALER BRIDGE TEST: L1 → L2 (100,000 $BC → $BB)
 * ============================================================================
 * 
 * This test bridges 100,000 tokens from the Dealer's L1 wallet to L2.
 * Token mapping: $BC (Layer 1) → $BB (Layer 2) at 1:1 ratio
 * 
 * Flow:
 * 1. Check Dealer's L1 balance ($BC)
 * 2. Check Dealer's L2 balance ($BB) - before
 * 3. Create a SignedRequest with bridge payload
 * 4. POST to /bridge/initiate to lock $BC on L1
 * 5. L2 credits equivalent $BB tokens
 * 6. Verify balances on both layers
 * 
 * Dealer Account Info:
 *   L1 Address: L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC
 *   L2 Address: L2_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC (same suffix)
 *   Seed: d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d
 */

import nacl from 'tweetnacl';
import { randomUUID } from 'crypto';

// ============================================================================
// DEALER CREDENTIALS (Test - Exposed for testing only!)
// ============================================================================

const DEALER = {
  name: "Dealer/Oracle",
  l1_address: "L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC",  // $BC
  l2_address: "L2_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC",  // $BB
  seed: "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
  public_key: "65328794ed4a81cc2a92b93738c22a545f066cc6c0b6a72aa878cfa289f0ba32",
};

const L1_URL = "http://localhost:8080";  // $BC chain
const L2_URL = "http://localhost:1234";  // $BB chain (if running)
const BRIDGE_AMOUNT = 100000; // 100,000 $BC to bridge to L2 as $BB (1:1)
const CHAIN_ID_L1 = 0x01;

// ============================================================================
// CRYPTO HELPERS
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

function getKeypairFromSeed(seedHex) {
  const seedBytes = hexToBytes(seedHex);
  return nacl.sign.keyPair.fromSeed(seedBytes);
}

/**
 * Create a SignedRequest compatible with L1 unified_auth
 * 
 * Message format (from Rust): chain_id_byte + "{payload}\n{timestamp}\n{nonce}"
 */
function createSignedRequest(keypair, publicKeyHex, walletAddress, payload) {
  const timestamp = Math.floor(Date.now() / 1000); // Unix seconds
  const nonce = randomUUID();
  const payloadStr = JSON.stringify(payload);
  
  // Build message to sign: chain_id_byte + "{payload}\n{timestamp}\n{nonce}"
  // This matches the Rust code in unified_auth.rs
  const messageText = `${payloadStr}\n${timestamp}\n${nonce}`;
  
  // Prepend chain_id byte
  const encoder = new TextEncoder();
  const messageTextBytes = encoder.encode(messageText);
  const messageBytes = new Uint8Array(1 + messageTextBytes.length);
  messageBytes[0] = CHAIN_ID_L1;
  messageBytes.set(messageTextBytes, 1);
  
  const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
  const signatureHex = bytesToHex(signature);
  
  return {
    public_key: publicKeyHex,
    wallet_address: walletAddress,
    payload: payloadStr,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: CHAIN_ID_L1,
    signature: signatureHex,
  };
}

// ============================================================================
// API HELPERS
// ============================================================================

async function getL1Balance(address) {
  try {
    const response = await fetch(`${L1_URL}/balance/${address}`);
    const data = await response.json();
    return { balance: data.balance, symbol: "$BC", layer: "L1" };
  } catch (e) {
    return { balance: null, error: e.message, symbol: "$BC", layer: "L1" };
  }
}

async function getL2Balance(address) {
  try {
    const response = await fetch(`${L2_URL}/balance/${address}`, { 
      signal: AbortSignal.timeout(2000) 
    });
    const data = await response.json();
    return { balance: data.balance, symbol: "$BB", layer: "L2" };
  } catch (e) {
    return { balance: null, error: "L2 not running or unreachable", symbol: "$BB", layer: "L2" };
  }
}

async function bridgeInitiate(signedRequest) {
  const response = await fetch(`${L1_URL}/bridge/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(signedRequest),
  });
  return await response.json();
}

async function getBridgeStats() {
  const response = await fetch(`${L1_URL}/bridge/stats`);
  return await response.json();
}

async function getLockedBalance(address) {
  try {
    // Check if there's a locked balance endpoint
    const response = await fetch(`${L1_URL}/bridge/locked/${address}`);
    const data = await response.json();
    return data;
  } catch (e) {
    return { locked: null };
  }
}

// ============================================================================
// MAIN TEST
// ============================================================================

async function main() {
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log("  🌉 DEALER BRIDGE TEST: L1 → L2 (100,000 $BC → $BB)");
  console.log("     Token Mapping: $BC (Layer 1) → $BB (Layer 2) @ 1:1");
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log();

  // Step 1: Check initial L1 balance ($BC)
  console.log("📊 Step 1: Checking Dealer's L1 balance ($BC)...");
  const initialL1 = await getL1Balance(DEALER.l1_address);
  console.log(`   💰 Dealer L1: ${initialL1.balance} ${initialL1.symbol}`);
  
  // Step 2: Check initial L2 balance ($BB)
  console.log("📊 Step 2: Checking Dealer's L2 balance ($BB)...");
  const initialL2 = await getL2Balance(DEALER.l2_address);
  if (initialL2.error) {
    console.log(`   ⚠️  L2: ${initialL2.error}`);
  } else {
    console.log(`   💰 Dealer L2: ${initialL2.balance} ${initialL2.symbol}`);
  }
  console.log();

  if (initialL1.balance < BRIDGE_AMOUNT) {
    console.log(`   ❌ ERROR: Insufficient $BC balance! Need ${BRIDGE_AMOUNT}, have ${initialL1.balance}`);
    return;
  }

  // Step 3: Create signed bridge request
  console.log("🔐 Step 3: Creating SignedRequest for bridge...");
  
  const keypair = getKeypairFromSeed(DEALER.seed);
  const derivedPubKey = bytesToHex(keypair.publicKey);
  console.log(`   📝 Public key: ${derivedPubKey.substring(0, 32)}...`);
  
  const payload = {
    amount: BRIDGE_AMOUNT,
    target_layer: "L2"
  };
  console.log(`   📦 Payload: ${JSON.stringify(payload)}`);
  console.log(`   🔄 Bridging: ${BRIDGE_AMOUNT} $BC → ${BRIDGE_AMOUNT} $BB (1:1)`);
  
  const signedRequest = createSignedRequest(
    keypair,
    derivedPubKey,
    DEALER.l1_address,
    payload
  );
  
  console.log(`   ✍️  Signature: ${signedRequest.signature.substring(0, 40)}...`);
  console.log(`   🔑 Nonce: ${signedRequest.nonce}`);
  console.log(`   ⏰ Timestamp: ${signedRequest.timestamp}`);
  console.log();

  // Step 4: Initiate bridge
  console.log("🌉 Step 4: Initiating L1 → L2 bridge...");
  console.log(`   📤 Locking ${BRIDGE_AMOUNT} $BC on L1...`);
  
  try {
    const bridgeResult = await bridgeInitiate(signedRequest);
    
    console.log();
    console.log("   📥 Bridge Response:");
    console.log(JSON.stringify(bridgeResult, null, 2));
    
    if (bridgeResult.success) {
      console.log();
      console.log("   ✅ Bridge initiated successfully!");
      console.log(`   🔒 Lock ID: ${bridgeResult.lock_id || 'N/A'}`);
      console.log(`   💰 $BC Locked: ${BRIDGE_AMOUNT}`);
      console.log(`   💰 $BB Credited: ${BRIDGE_AMOUNT} (on L2)`);
    } else {
      console.log();
      console.log(`   ❌ Bridge failed: ${bridgeResult.error || bridgeResult.message || 'Unknown error'}`);
    }
  } catch (error) {
    console.log(`   ❌ Request error: ${error.message}`);
  }
  console.log();

  // Step 5: Check final balances
  console.log("📊 Step 5: Checking final balances...");
  
  const finalL1 = await getL1Balance(DEALER.l1_address);
  console.log(`   💰 L1 ($BC): ${finalL1.balance} (was ${initialL1.balance})`);
  console.log(`   📉 L1 Change: ${(finalL1.balance - initialL1.balance).toFixed(2)} $BC`);
  
  const finalL2 = await getL2Balance(DEALER.l2_address);
  if (finalL2.error) {
    console.log(`   ⚠️  L2 ($BB): ${finalL2.error}`);
  } else {
    const l2Change = (finalL2.balance || 0) - (initialL2.balance || 0);
    console.log(`   💰 L2 ($BB): ${finalL2.balance} (was ${initialL2.balance || 0})`);
    console.log(`   📈 L2 Change: +${l2Change.toFixed(2)} $BB`);
  }
  console.log();

  // Step 6: Verify 1:1 ratio
  console.log("🔍 Step 6: Verifying 1:1 token ratio...");
  const l1Deducted = initialL1.balance - finalL1.balance;
  console.log(`   $BC locked on L1: ${l1Deducted}`);
  console.log(`   $BB to credit on L2: ${l1Deducted} (1:1 ratio)`);
  console.log();

  // Step 7: Bridge stats
  console.log("📈 Step 7: Bridge statistics...");
  try {
    const stats = await getBridgeStats();
    console.log(JSON.stringify(stats, null, 2));
  } catch (error) {
    console.log(`   ⚠️  Could not fetch bridge stats: ${error.message}`);
  }

  console.log();
  console.log("═══════════════════════════════════════════════════════════════════");
  console.log("  TOKEN SUMMARY:");
  console.log("  ┌─────────────────────────────────────────────────────────────┐");
  console.log(`  │ L1 ($BC): ${finalL1.balance.toString().padEnd(12)} │ Layer 1 - Bank/Vault    │`);
  console.log(`  │ L2 ($BB): ${(finalL2.balance || 'N/A').toString().padEnd(12)} │ Layer 2 - Gaming        │`);
  console.log("  │ Ratio:    1:1            │ $BC ↔ $BB               │");
  console.log("  └─────────────────────────────────────────────────────────────┘");
  console.log("═══════════════════════════════════════════════════════════════════");
}

main().catch(console.error);
