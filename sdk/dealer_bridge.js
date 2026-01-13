/**
 * Bridge DEALER funds from L1 → L2
 */

import nacl from 'tweetnacl';
import crypto from 'crypto';

// Simple UUID v4 generator (no external dependency)
function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const L1_URL = 'http://localhost:8080';
const L2_URL = 'http://localhost:1234';

// DEALER credentials
const DEALER = {
  privateKey: 'e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae',
  get publicKey() {
    const privKeyBytes = Buffer.from(this.privateKey, 'hex');
    const keypair = nacl.sign.keyPair.fromSeed(privKeyBytes);
    return Buffer.from(keypair.publicKey).toString('hex');
  },
  get l1Address() {
    const pubKeyBuffer = Buffer.from(this.publicKey, 'hex');
    const hash = crypto.createHash('sha256').update(pubKeyBuffer).digest('hex');
    return `L1_${hash.substring(0, 40).toUpperCase()}`;
  },
  get l2Address() {
    const pubKeyBuffer = Buffer.from(this.publicKey, 'hex');
    const hash = crypto.createHash('sha256').update(pubKeyBuffer).digest('hex');
    return `L2_${hash.substring(0, 40).toUpperCase()}`;
  }
};

// Sign message for L1 (chain_id + payload + timestamp + nonce)
function signL1Message(payload, timestamp, nonce, privateKey) {
  const chainIdByte = Buffer.from([0x01]); // L1 chain ID
  const payloadStr = JSON.stringify(payload);
  const message = Buffer.concat([
    chainIdByte,
    Buffer.from(`${payloadStr}\n${timestamp}\n${nonce}`)
  ]);
  
  const privKeyBytes = Buffer.from(privateKey, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privKeyBytes);
  const signature = nacl.sign.detached(message, keypair.secretKey);
  
  return Buffer.from(signature).toString('hex');
}

// Sign message for L2 (address:timestamp)
function signL2Message(address, timestamp, privateKey) {
  const message = `${address}:${timestamp}`;
  const messageBytes = Buffer.from(message);
  
  const privKeyBytes = Buffer.from(privateKey, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privKeyBytes);
  const signature = nacl.sign.detached(messageBytes, keypair.secretKey);
  
  return Buffer.from(signature).toString('hex');
}

async function bridgeDealerFunds(amount) {
  console.log('╔════════════════════════════════════════════════════════════════╗');
  console.log('║              🌉 DEALER L1 → L2 BRIDGE                         ║');
  console.log('╚════════════════════════════════════════════════════════════════╝\n');
  
  console.log(`💼 DEALER Account:`);
  console.log(`   L1: ${DEALER.l1Address}`);
  console.log(`   L2: ${DEALER.l2Address}`);
  console.log(`   Amount: ${amount} $BC\n`);
  
  // Step 1: Check L1 balance
  console.log('1️⃣  Checking L1 balance...');
  const l1BalResp = await fetch(`${L1_URL}/balance/${DEALER.l1Address}`);
  const l1BalData = await l1BalResp.json();
  console.log(`   L1 Balance: ${l1BalData.balance} $BC\n`);
  
  if (l1BalData.balance < amount) {
    throw new Error(`Insufficient L1 balance: ${l1BalData.balance} < ${amount}`);
  }
  
  // Step 2: Initiate bridge on L1 (lock funds)
  console.log('2️⃣  Initiating bridge on L1 (locking funds)...');
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = uuidv4();
  
  const bridgePayload = {
    amount: amount,
    target_layer: "L2"
  };
  
  const l1Signature = signL1Message(bridgePayload, timestamp, nonce, DEALER.privateKey);
  
  const l1BridgeReq = {
    payload: JSON.stringify(bridgePayload),
    public_key: DEALER.publicKey,
    signature: l1Signature,
    nonce: nonce,
    timestamp: timestamp,
    chain_id: 1
  };
  
  console.log(`   Payload: ${JSON.stringify(bridgePayload)}`);
  console.log(`   Timestamp: ${timestamp}`);
  console.log(`   Nonce: ${nonce}`);
  
  const l1BridgeResp = await fetch(`${L1_URL}/bridge/initiate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(l1BridgeReq)
  });
  
  if (!l1BridgeResp.ok) {
    const error = await l1BridgeResp.text();
    throw new Error(`L1 bridge failed: ${l1BridgeResp.status} - ${error}`);
  }
  
  const l1BridgeResult = await l1BridgeResp.json();
  console.log(`   ✅ L1 Bridge Success!`);
  console.log(`   Lock ID: ${l1BridgeResult.lock_id || 'N/A'}`);
  console.log(`   New L1 Balance: ${l1BridgeResult.new_balance || 'N/A'} $BC\n`);
  
  // Step 3: Credit on L2
  console.log('3️⃣  Crediting L2 account...');
  
  const lockId = l1BridgeResult.lock_id || `bridge_${nonce}`;
  
  // L1 signature for L2: "BRIDGE_LOCK:{user_address}:{amount}:{lock_id}"
  const l1BridgeMessage = `BRIDGE_LOCK:${DEALER.l1Address}:${amount}:${lockId}`;
  const l1BridgeMessageBytes = Buffer.from(l1BridgeMessage);
  const privKeyBytes = Buffer.from(DEALER.privateKey, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privKeyBytes);
  const l1BridgeSig = nacl.sign.detached(l1BridgeMessageBytes, keypair.secretKey);
  const l1BridgeSigHex = Buffer.from(l1BridgeSig).toString('hex');
  
  const l2CreditReq = {
    user_address: DEALER.l1Address, // L1 address (will be converted to L2)
    amount: amount,
    lock_id: lockId,
    l1_public_key: DEALER.publicKey,
    l1_signature: l1BridgeSigHex,
    timestamp: timestamp
  };
  
  console.log(`   Lock ID: ${lockId}`);
  console.log(`   Message: ${l1BridgeMessage.substring(0, 60)}...`);
  
  const l2CreditResp = await fetch(`${L2_URL}/bridge/credit`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(l2CreditReq)
  });
  
  if (!l2CreditResp.ok) {
    const error = await l2CreditResp.text();
    throw new Error(`L2 credit failed: ${l2CreditResp.status} - ${error}`);
  }
  
  const l2CreditResult = await l2CreditResp.json();
  console.log(`   ✅ L2 Credit Success!`);
  console.log(`   New L2 Balance: ${l2CreditResult.new_balance || l2CreditResult.balance} $BB\n`);
  
  // Step 4: Verify final balances
  console.log('4️⃣  Verifying final balances...');
  
  const finalL1Resp = await fetch(`${L1_URL}/balance/${DEALER.l1Address}`);
  const finalL1 = await finalL1Resp.json();
  
  const finalL2Resp = await fetch(`${L2_URL}/balance/${DEALER.l2Address}`);
  const finalL2 = await finalL2Resp.json();
  
  console.log(`   L1: ${finalL1.balance} $BC (locked: ${amount})`);
  console.log(`   L2: ${finalL2.available} $BB\n`);
  
  console.log('═══════════════════════════════════════════════════════════════════');
  console.log('✅ BRIDGE COMPLETE!');
  console.log('═══════════════════════════════════════════════════════════════════\n');
  
  return {
    l1Balance: finalL1.balance,
    l2Balance: finalL2.available,
    bridgedAmount: amount
  };
}

// Main execution
const AMOUNT_TO_BRIDGE = 50000; // Bridge 50k to L2, keep 50k on L1

bridgeDealerFunds(AMOUNT_TO_BRIDGE)
  .then(result => {
    console.log('Bridge successful:', result);
    process.exit(0);
  })
  .catch(error => {
    console.error('❌ Bridge failed:', error.message);
    process.exit(1);
  });
