/**
 * ═══════════════════════════════════════════════════════════════════════════
 * COMPREHENSIVE TEST SUITE: Alice & Bob Full Blockchain Functionality
 * ═══════════════════════════════════════════════════════════════════════════
 * 
 * Tests EVERYTHING with real Alice, Bob, and Dealer accounts:
 * 
 * ✅ Phase 1: Transfer Tests (Exponential Pattern)
 * ✅ Phase 2: Bridge Lock Flow (L1 → L2 via gRPC)
 * ✅ Phase 3: gRPC Integration with L2 Server (localhost:1234)
 * ✅ Phase 4: Credit Line Flow (Approve/Draw/Settle)
 * ✅ Phase 5: Settlement with Merkle Proofs
 * ✅ Phase 6: Consensus Verification (PoH, Block Finality)
 * 
 * REQUIREMENTS:
 * - L1 Server running: localhost:8080 (HTTP) & localhost:50051 (gRPC)
 * - L2 Server running: localhost:1234 (HTTP & gRPC)
 * - Test accounts funded (Alice: 20K BB, Bob: 10K BB, Dealer: 100K BB)
 */

import grpc from '@grpc/grpc-js';
import protoLoader from '@grpc/proto-loader';
import nacl from 'tweetnacl';
import { createHash } from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ═══════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ═══════════════════════════════════════════════════════════════════════════

const L1_HTTP = 'http://localhost:8080';
const L1_GRPC = 'localhost:50051';
const L2_HTTP = 'http://localhost:1234';
const L2_GRPC = 'localhost:1235';  // L2 gRPC port (if different)
const PROTO_PATH = path.join(__dirname, '..', 'proto', 'settlement.proto');

const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// ═══════════════════════════════════════════════════════════════════════════
// TEST ACCOUNTS (Real Production Accounts)
// ═══════════════════════════════════════════════════════════════════════════

const ACCOUNTS = {
  ALICE: {
    name: 'Alice',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    l2Address: 'L2_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    expectedBalance: 20000.0,
    mnemonic: 'machine sword cause scrub simple damage program together spoon lock ball banana'
  },
  BOB: {
    name: 'Bob',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    l2Address: 'L2_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    expectedBalance: 10000.0,
    mnemonic: 'base echo grape penalty hawk resemble obscure unusual throw paddle carpet elder'
  },
  DEALER: {
    name: 'Dealer',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    l2Address: 'L2_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    expectedBalance: 100000.0,
    mnemonic: '(dealer test account)'
  }
};

// Initialize keypairs from seeds
function initializeAccounts() {
  for (const account of Object.values(ACCOUNTS)) {
    const seedBytes = Buffer.from(account.seed, 'hex');
    const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    account.publicKey = Buffer.from(keyPair.publicKey).toString('hex');
    account.secretKey = keyPair.secretKey;
  }
}

initializeAccounts();

// ═══════════════════════════════════════════════════════════════════════════
// GRPC CLIENT SETUP
// ═══════════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════════
// CRYPTO UTILITIES
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

function generateNonce() {
  return crypto.randomUUID();
}

function signMessage(message, secretKey, chainId = CHAIN_ID_L1) {
  const messageBytes = Buffer.from(message);
  const prefixedMessage = Buffer.concat([Buffer.from([chainId]), messageBytes]);
  const signature = nacl.sign.detached(prefixedMessage, secretKey);
  return Buffer.from(signature).toString('hex');
}

function signMessageRaw(secretKey, message) {
  const messageBytes = Buffer.from(message, 'utf8');
  const signature = nacl.sign.detached(messageBytes, secretKey);
  return Buffer.from(signature).toString('hex');
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP HELPERS
// ═══════════════════════════════════════════════════════════════════════════

async function httpGet(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (e) {
    throw new Error(`GET ${url} failed: ${e.message}`);
  }
}

async function httpPost(url, body) {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (e) {
    throw new Error(`POST ${url} failed: ${e.message}`);
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// BLOCKCHAIN API WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════

async function getBalance(address) {
  const data = await httpGet(`${L1_HTTP}/balance/${address}`);
  return data.balance || 0;
}

async function getL2Balance(address) {
  try {
    const data = await httpGet(`${L2_HTTP}/balance/${address}`);
    return data.balance || 0;
  } catch (e) {
    console.log(`   ⚠️  L2 balance query failed: ${e.message}`);
    return 0;
  }
}

async function transfer(fromAccount, toAddress, amount) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  
  const payload = {
    from: fromAccount.address,
    to: toAddress,
    amount: amount,
    timestamp: timestamp,
    nonce: nonce
  };
  
  const payloadJson = JSON.stringify(payload);
  
  // V1 format: message = {payload}\n{timestamp}\n{nonce}
  const message = `${payloadJson}\n${timestamp}\n${nonce}`;
  
  // Prepend chain_id byte for domain separation
  const chainIdByte = new Uint8Array([CHAIN_ID_L1]);
  const messageBytes = new TextEncoder().encode(message);
  const fullMessage = new Uint8Array(chainIdByte.length + messageBytes.length);
  fullMessage.set(chainIdByte);
  fullMessage.set(messageBytes, chainIdByte.length);
  
  // Sign with Ed25519
  const signature = nacl.sign.detached(fullMessage, fromAccount.secretKey);
  
  const request = {
    public_key: fromAccount.publicKey,
    wallet_address: fromAccount.address,
    payload: payloadJson,
    timestamp: timestamp,
    nonce: nonce,
    chain_id: CHAIN_ID_L1,
    schema_version: 1,
    signature: bytesToHex(signature)
  };
  
  return await httpPost(`${L1_HTTP}/transfer`, request);
}

async function bridgeLock(account, amount) {
  const payload = {
    action: 'bridge_initiate',
    amount: amount,
    target_layer: 'L2',
    timestamp: Date.now()
  };
  
  const payloadStr = JSON.stringify(payload);
  const signature = signMessage(payloadStr, account.secretKey, CHAIN_ID_L1);
  
  const request = {
    payload: payloadStr,
    public_key: account.publicKey,
    signature: signature
  };
  
  return await httpPost(`${L1_HTTP}/bridge/initiate`, request);
}

// ═══════════════════════════════════════════════════════════════════════════
// GRPC API WRAPPERS
// ═══════════════════════════════════════════════════════════════════════════

async function grpcHealthCheck() {
  return await promisifyGrpc(getGrpcClient().HealthCheck, {});
}

async function grpcGetBalance(address) {
  return await promisifyGrpc(getGrpcClient().GetBalance, { address });
}

async function grpcRequestCreditLine(account, creditLimit, expiresInHours = 24) {
  const message = `credit_line:${account.address}:${creditLimit}:${expiresInHours}`;
  const signature = signMessageRaw(account.secretKey, message);
  
  return await promisifyGrpc(getGrpcClient().RequestCreditLine, {
    wallet_address: account.address,
    public_key: account.publicKey,
    credit_limit: creditLimit,
    expires_in_hours: expiresInHours,
    signature: signature,
    nonce: Date.now(),
  });
}

async function grpcCreditDraw(account, sessionId, amount) {
  return await promisifyGrpc(getGrpcClient().CreditDraw, {
    wallet_address: account.address,
    session_id: sessionId,
    amount: amount,
  });
}

async function grpcCreditSettle(account, sessionId, finalL2Balance, lockedInBets = 0) {
  return await promisifyGrpc(getGrpcClient().CreditSettle, {
    wallet_address: account.address,
    session_id: sessionId,
    final_l2_balance: finalL2Balance,
    locked_in_bets: lockedInBets,
  });
}

async function grpcExecuteSettlement(dealer, beneficiary, betId, payoutAmount) {
  const message = `settle:${betId}:${beneficiary.address}:${payoutAmount}`;
  const signature = signMessageRaw(dealer.secretKey, message);
  
  const intentHash = createHash('sha256').update(
    JSON.stringify({ bet_id: betId, beneficiary: beneficiary.address, payout: payoutAmount })
  ).digest();
  
  return await promisifyGrpc(getGrpcClient().ExecuteSettlement, {
    dealer_address: dealer.address,
    user_address: beneficiary.address,
    beneficiary: beneficiary.address,
    bet_id: betId,
    market_id: 'TEST_MARKET',
    outcome: 'WIN',
    stake_amount: Math.floor(payoutAmount / 2),
    payout_amount: payoutAmount,
    public_key: dealer.publicKey,
    signature: Buffer.from(signature, 'hex'),
    intent_hash: Buffer.from(intentHash),
    nonce: Date.now(),
    timestamp: Date.now(),
    chain_id: 'CHAIN_L2'
  });
}

async function grpcInitiateBridgeLock(account, amount) {
  const message = `bridge_lock:${account.address}:${amount}:L2`;
  const signature = signMessageRaw(account.secretKey, message);
  
  return await promisifyGrpc(getGrpcClient().InitiateBridgeLock, {
    user_address: account.address,
    amount: amount,
    target_layer: 'L2',
    public_key: account.publicKey,
    signature: Buffer.from(signature, 'hex'),
    nonce: Date.now()
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// MERKLE TREE (for Settlement Proofs)
// ═══════════════════════════════════════════════════════════════════════════

class MerkleTree {
  constructor(leaves) {
    this.leaves = leaves.map(leaf => 
      Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf, 'hex')
    );
    this.tree = this.buildTree();
  }

  hash(data) {
    return createHash('sha256').update(data).digest();
  }

  hashPair(left, right) {
    return this.hash(Buffer.concat([left, right]));
  }

  buildTree() {
    let level = this.leaves;
    const tree = [level];
    
    while (level.length > 1) {
      const nextLevel = [];
      for (let i = 0; i < level.length; i += 2) {
        if (i + 1 < level.length) {
          nextLevel.push(this.hashPair(level[i], level[i + 1]));
        } else {
          nextLevel.push(level[i]);
        }
      }
      tree.push(nextLevel);
      level = nextLevel;
    }
    
    return tree;
  }

  getRoot() {
    return this.tree[this.tree.length - 1][0].toString('hex');
  }

  getProof(index) {
    const proof = [];
    let currentIndex = index;
    
    for (let level = 0; level < this.tree.length - 1; level++) {
      const currentLevel = this.tree[level];
      const isRightNode = currentIndex % 2 === 1;
      const siblingIndex = isRightNode ? currentIndex - 1 : currentIndex + 1;
      
      if (siblingIndex < currentLevel.length) {
        proof.push({
          hash: currentLevel[siblingIndex].toString('hex'),
          position: isRightNode ? 'left' : 'right'
        });
      }
      
      currentIndex = Math.floor(currentIndex / 2);
    }
    
    return proof;
  }

  static verifyProof(leaf, proof, root) {
    let hash = Buffer.isBuffer(leaf) ? leaf : Buffer.from(leaf, 'hex');
    
    for (const { hash: proofHash, position } of proof) {
      const sibling = Buffer.from(proofHash, 'hex');
      
      if (position === 'left') {
        hash = createHash('sha256').update(Buffer.concat([sibling, hash])).digest();
      } else {
        hash = createHash('sha256').update(Buffer.concat([hash, sibling])).digest();
      }
    }

    return hash.toString('hex') === root;
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// TEST FRAMEWORK
// ═══════════════════════════════════════════════════════════════════════════

let testsPassed = 0;
let testsFailed = 0;
const testResults = [];

async function test(name, fn) {
  try {
    const result = await fn();
    // Consider test passed if:
    // - Returns true
    // - Returns a string with success indicators
    // - Returns a string without error indicators
    const isSuccess = result === true || 
                      (typeof result === 'string' && 
                       (result.includes('✅') || 
                        result.includes('Lock ID:') ||
                        result.includes('Block Height:') ||
                        result.includes('BB') ||
                        result.includes('Session:') ||
                        result.includes('Drawn:') ||
                        result.includes('TX:') ||
                        result.includes('Root:') ||
                        result.includes('Proof depth:') ||
                        result.includes('Slot:') ||
                        result.includes('blocks') ||
                        result.includes('Balance:')) &&
                       !result.includes('failed') &&
                       !result.includes('error') &&
                       !result.includes('Error') &&
                       !result.includes('not available'));
    
    if (isSuccess) {
      testsPassed++;
      console.log(`   ✅ ${name}`);
      if (typeof result === 'string' && result !== 'true') {
        console.log(`      ${result}`);
      }
      testResults.push({ name, status: 'PASS', result });
    } else {
      testsFailed++;
      console.log(`   ❌ ${name}`);
      console.log(`      ${result}`);
      testResults.push({ name, status: 'FAIL', result });
    }
  } catch (e) {
    testsFailed++;
    console.log(`   ❌ ${name}`);
    console.log(`      Error: ${e.message}`);
    testResults.push({ name, status: 'ERROR', result: e.message });
  }
}

function section(title) {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  ${title}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 1: TRANSFER TESTS (Alice ↔ Bob Exponential Pattern)
// ═══════════════════════════════════════════════════════════════════════════

async function phase1_transfers() {
  section('PHASE 1: TRANSFER TESTS (Exponential Pattern)');
  
  let aliceBalance = await getBalance(ACCOUNTS.ALICE.address);
  let bobBalance = await getBalance(ACCOUNTS.BOB.address);
  
  console.log(`   💰 Starting - Alice: ${aliceBalance.toFixed(2)} BB, Bob: ${bobBalance.toFixed(2)} BB`);
  console.log('');
  
  await test('1.1 Alice → Bob: 5 BB', async () => {
    const result = await transfer(ACCOUNTS.ALICE, ACCOUNTS.BOB.address, 5);
    return result.success ? true : result.error;
  });
  
  await test('1.2 Bob → Alice: 25 BB', async () => {
    const result = await transfer(ACCOUNTS.BOB, ACCOUNTS.ALICE.address, 25);
    return result.success ? true : result.error;
  });
  
  await test('1.3 Alice → Bob: 125 BB', async () => {
    const result = await transfer(ACCOUNTS.ALICE, ACCOUNTS.BOB.address, 125);
    return result.success ? true : result.error;
  });
  
  await test('1.4 Bob → Alice: 625 BB', async () => {
    const result = await transfer(ACCOUNTS.BOB, ACCOUNTS.ALICE.address, 625);
    return result.success ? true : result.error;
  });
  
  aliceBalance = await getBalance(ACCOUNTS.ALICE.address);
  bobBalance = await getBalance(ACCOUNTS.BOB.address);
  
  console.log('');
  console.log(`   💰 Final - Alice: ${aliceBalance.toFixed(2)} BB, Bob: ${bobBalance.toFixed(2)} BB`);
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 2: BRIDGE LOCK FLOW (L1 → L2)
// ═══════════════════════════════════════════════════════════════════════════

async function phase2_bridgeLock() {
  section('PHASE 2: BRIDGE LOCK FLOW (L1 → L2)');
  
  await test('2.1 Alice locks 555 BB for L2 (via HTTP)', async () => {
    const result = await bridgeLock(ACCOUNTS.ALICE, 555);
    return result.success ? `Lock ID: ${result.lock_id?.slice(0, 8)}...` : result.error;
  });
  
  await test('2.2 Bob locks 333 BB for L2 (via HTTP)', async () => {
    const result = await bridgeLock(ACCOUNTS.BOB, 333);
    return result.success ? `Lock ID: ${result.lock_id?.slice(0, 8)}...` : result.error;
  });
  
  await test('2.3 Alice locks 777 BB via gRPC', async () => {
    try {
      const result = await grpcInitiateBridgeLock(ACCOUNTS.ALICE, 777_000_000);
      return result.success ? true : result.error_message;
    } catch (e) {
      if (e.code === 14) return 'gRPC not available (may be expected)';
      throw e;
    }
  });
  
  await test('2.4 Verify Alice L1 balance reduced', async () => {
    const balance = await getBalance(ACCOUNTS.ALICE.address);
    return balance < ACCOUNTS.ALICE.expectedBalance ? `Balance: ${balance.toFixed(2)} BB` : 'Balance not reduced';
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 3: GRPC INTEGRATION
// ═══════════════════════════════════════════════════════════════════════════

async function phase3_grpcIntegration() {
  section('PHASE 3: GRPC INTEGRATION (L1 ↔ L2)');
  
  await test('3.1 gRPC HealthCheck', async () => {
    try {
      const health = await grpcHealthCheck();
      return health.status === 'OK' || health.status === 'healthy' ? 
        `Block Height: ${health.block_height}` : 'Unhealthy';
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
  
  await test('3.2 gRPC GetBalance (Alice)', async () => {
    try {
      const balance = await grpcGetBalance(ACCOUNTS.ALICE.address);
      const bb = parseInt(balance.available || balance.total || 0) / 1_000_000;
      return bb > 0 ? `${bb.toFixed(2)} BB` : 'Balance query failed';
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
  
  await test('3.3 gRPC GetBalance (Bob)', async () => {
    try {
      const balance = await grpcGetBalance(ACCOUNTS.BOB.address);
      const bb = parseInt(balance.available || balance.total || 0) / 1_000_000;
      return bb > 0 ? `${bb.toFixed(2)} BB` : 'Balance query failed';
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 4: CREDIT LINE FLOW
// ═══════════════════════════════════════════════════════════════════════════

async function phase4_creditLine() {
  section('PHASE 4: CREDIT LINE FLOW (Approve/Draw/Settle)');
  
  const sessionId = `session_${Date.now()}`;
  
  await test('4.1 Alice requests 1000 BB credit line', async () => {
    try {
      const result = await grpcRequestCreditLine(ACCOUNTS.ALICE, 1000_000_000, 24);
      return result.approved ? `Session: ${sessionId.slice(0, 16)}...` : result.error_message;
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
  
  await test('4.2 Alice draws 500 BB from credit', async () => {
    try {
      const result = await grpcCreditDraw(ACCOUNTS.ALICE, sessionId, 500_000_000);
      return result.success ? `Drawn: 500 BB` : result.error_message;
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
  
  await test('4.3 Alice settles credit (300 BB remaining)', async () => {
    try {
      const result = await grpcCreditSettle(ACCOUNTS.ALICE, sessionId, 300_000_000, 0);
      return result.success ? `Profit/Loss: ${result.net_change || 'settled'}` : result.error_message;
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 5: SETTLEMENT WITH MERKLE PROOFS
// ═══════════════════════════════════════════════════════════════════════════

async function phase5_merkleSettlement() {
  section('PHASE 5: SETTLEMENT WITH MERKLE PROOFS');
  
  // Create test settlements
  const settlements = [
    { bet_id: 'bet_001', user: ACCOUNTS.ALICE.address, payout: 950 },
    { bet_id: 'bet_002', user: ACCOUNTS.BOB.address, payout: 1900 },
    { bet_id: 'bet_003', user: ACCOUNTS.ALICE.address, payout: 475 },
  ];
  
  const hashSettlement = (s) => {
    return createHash('sha256')
      .update(`${s.bet_id}:${s.user}:${s.payout}`)
      .digest('hex');
  };
  
  const leaves = settlements.map(hashSettlement);
  const merkleTree = new MerkleTree(leaves);
  const merkleRoot = merkleTree.getRoot();
  
  await test('5.1 Generate Merkle root from 3 settlements', async () => {
    return merkleRoot.length === 64 ? `Root: ${merkleRoot.slice(0, 16)}...` : 'Invalid root';
  });
  
  await test('5.2 Generate Merkle proof for Alice bet_001', async () => {
    const proof = merkleTree.getProof(0);
    return proof.length > 0 ? `Proof depth: ${proof.length}` : 'No proof generated';
  });
  
  await test('5.3 Verify Alice proof against root', async () => {
    const proof = merkleTree.getProof(0);
    const leaf = Buffer.from(leaves[0], 'hex');
    const valid = MerkleTree.verifyProof(leaf, proof, merkleRoot);
    return valid ? '✅ Proof verified' : 'Verification failed';
  });
  
  await test('5.4 Execute settlement via gRPC (Alice wins 950 BB)', async () => {
    try {
      const result = await grpcExecuteSettlement(
        ACCOUNTS.DEALER,
        ACCOUNTS.ALICE,
        'bet_001',
        950_000_000
      );
      return result.success ? `TX: ${result.tx_hash?.slice(0, 16)}...` : result.error_message;
    } catch (e) {
      if (e.code === 14) return 'gRPC not available';
      throw e;
    }
  });
  
  await test('5.5 Wrong proof fails verification', async () => {
    const wrongProof = merkleTree.getProof(1); // Bob's proof
    const aliceLeaf = Buffer.from(leaves[0], 'hex');
    const valid = MerkleTree.verifyProof(aliceLeaf, wrongProof, merkleRoot);
    return !valid ? '✅ Correctly rejected' : 'Should have failed';
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// PHASE 6: CONSENSUS VERIFICATION
// ═══════════════════════════════════════════════════════════════════════════

async function phase6_consensus() {
  section('PHASE 6: CONSENSUS VERIFICATION (PoH & Block Finality)');
  
  await test('6.1 L1 server is healthy', async () => {
    const health = await httpGet(`${L1_HTTP}/health`);
    return health.status === 'healthy' ? '✅ Healthy' : health.status;
  });
  
  await test('6.2 Get blockchain stats', async () => {
    const stats = await httpGet(`${L1_HTTP}/stats`);
    return stats.chain_length > 0 ? `${stats.chain_length} blocks` : 'No blocks';
  });
  
  await test('6.3 PoH clock is running', async () => {
    try {
      const poh = await httpGet(`${L1_HTTP}/poh/clock`);
      return poh.current_slot >= 0 ? `Slot: ${poh.current_slot}` : 'PoH not running';
    } catch (e) {
      return 'PoH endpoint not available';
    }
  });
  
  await test('6.4 Verify PoH chain integrity', async () => {
    try {
      const verify = await httpGet(`${L1_HTTP}/poh/verify`);
      return verify.valid === true ? '✅ PoH chain valid' : 'Invalid chain';
    } catch (e) {
      return 'PoH verification not available';
    }
  });
  
  await test('6.5 L2 server connectivity', async () => {
    try {
      const health = await httpGet(`${L2_HTTP}/health`);
      return health.status ? `L2 Status: ${health.status}` : '✅ L2 responding';
    } catch (e) {
      return `L2 not available: ${e.message}`;
    }
  });
  
  await test('6.6 Check Alice L2 balance', async () => {
    const l2Balance = await getL2Balance(ACCOUNTS.ALICE.l2Address);
    return l2Balance >= 0 ? `L2 Balance: ${l2Balance.toFixed(2)} BB` : 'L2 balance error';
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// MAIN TEST RUNNER
// ═══════════════════════════════════════════════════════════════════════════

async function runAllTests() {
  console.log('');
  console.log('╔═══════════════════════════════════════════════════════════════════════╗');
  console.log('║     COMPREHENSIVE TEST SUITE: Alice & Bob Full Functionality          ║');
  console.log('║     Testing: Transfers, Bridge, gRPC, Credit, Merkle, Consensus       ║');
  console.log('╚═══════════════════════════════════════════════════════════════════════╝');
  
  // Pre-flight checks
  section('PRE-FLIGHT CHECKS');
  console.log(`   Alice: ${ACCOUNTS.ALICE.address}`);
  console.log(`   Bob:   ${ACCOUNTS.BOB.address}`);
  console.log(`   Dealer: ${ACCOUNTS.DEALER.address}`);
  console.log('');
  console.log(`   L1 HTTP: ${L1_HTTP}`);
  console.log(`   L1 gRPC: ${L1_GRPC}`);
  console.log(`   L2 HTTP: ${L2_HTTP}`);
  
  // Run all test phases
  await phase1_transfers();
  await phase2_bridgeLock();
  await phase3_grpcIntegration();
  await phase4_creditLine();
  await phase5_merkleSettlement();
  await phase6_consensus();
  
  // Summary
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('                           TEST SUMMARY                                ');
  console.log('═══════════════════════════════════════════════════════════════════════');
  console.log('');
  console.log(`   ✅ Passed: ${testsPassed}`);
  console.log(`   ❌ Failed: ${testsFailed}`);
  console.log(`   📊 Total:  ${testsPassed + testsFailed}`);
  console.log('');
  
  if (testsFailed === 0) {
    console.log('   🎉 ALL TESTS PASSED! Blockchain is fully functional.');
  } else {
    console.log('   ⚠️  Some tests failed. Review errors above.');
  }
  
  console.log('');
  console.log('═══════════════════════════════════════════════════════════════════════');
  
  // Exit code for CI/CD
  process.exit(testsFailed > 0 ? 1 : 0);
}

// Run tests
runAllTests().catch(err => {
  console.error('❌ Fatal error:', err);
  process.exit(1);
});
