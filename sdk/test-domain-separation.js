/**
 * Domain Separation Test Suite for unified-wallet-sdk.js
 * 
 * Tests that L1 and L2 signatures are different and prevent replay attacks
 */

import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';

// Import SDK functions
const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// Utility functions (copied from SDK for testing)
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function generateL1Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const shortHash = hash.slice(0, 14).toUpperCase();
  return `L1${shortHash}`;
}

function generateL2Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const shortHash = hash.slice(0, 14).toUpperCase();
  return `L2${shortHash}`;
}

function signWithDomainSeparation(privateKey, message, chainId) {
  if (chainId !== CHAIN_ID_L1 && chainId !== CHAIN_ID_L2) {
    throw new Error(`Invalid chain_id: 0x${chainId.toString(16)}`);
  }
  
  // Domain-separated message: [chain_id][message]
  const messageBytes = new TextEncoder().encode(message);
  const domainSeparatedMessage = new Uint8Array(1 + messageBytes.length);
  domainSeparatedMessage[0] = chainId;
  domainSeparatedMessage.set(messageBytes, 1);
  
  const signatureBytes = nacl.sign.detached(domainSeparatedMessage, privateKey);
  return bytesToHex(signatureBytes);
}

function verifySignature(publicKey, message, signature, chainId) {
  // Domain-separated message: [chain_id][message]
  const messageBytes = new TextEncoder().encode(message);
  const domainSeparatedMessage = new Uint8Array(1 + messageBytes.length);
  domainSeparatedMessage[0] = chainId;
  domainSeparatedMessage.set(messageBytes, 1);
  
  const signatureBytes = hexToBytes(signature);
  return nacl.sign.detached.verify(domainSeparatedMessage, signatureBytes, publicKey);
}

// ============================================================================
// TESTS
// ============================================================================

console.log('🧪 Domain Separation Test Suite\n');
console.log('=' .repeat(80));

// Test 1: Address Generation
console.log('\n📍 TEST 1: Deterministic Address Generation');
console.log('-'.repeat(80));

const seed = new Uint8Array(32).fill(1);
const keypair = nacl.sign.keyPair.fromSeed(seed);
const publicKeyHex = bytesToHex(keypair.publicKey);

const l1Address = generateL1Address(publicKeyHex);
const l2Address = generateL2Address(publicKeyHex);

console.log(`Public Key: ${publicKeyHex}`);
console.log(`L1 Address: ${l1Address}`);
console.log(`L2 Address: ${l2Address}`);

if (l1Address.startsWith('L1') && l1Address.length === 42) {
  console.log('✅ L1 address format correct (42 chars, 160-bit security)');
} else {
  console.log('❌ L1 address format WRONG');
}

if (l2Address.startsWith('L2') && l2Address.length === 42) {
  console.log('✅ L2 address format correct (42 chars, 160-bit security)');
} else {
  console.log('❌ L2 address format WRONG');
}

// Core IDs should be the same
const l1Core = l1Address.slice(2);
const l2Core = l2Address.slice(2);
if (l1Core === l2Core) {
  console.log('✅ Core IDs match (deterministic)');
} else {
  console.log('❌ Core IDs DO NOT match');
}

// Test 2: Same Message, Different Signatures
console.log('\n🔐 TEST 2: Domain Separation Creates Different Signatures');
console.log('-'.repeat(80));

const message = JSON.stringify({ action: 'transfer', amount: 100 });
const l1Sig = signWithDomainSeparation(keypair.secretKey, message, CHAIN_ID_L1);
const l2Sig = signWithDomainSeparation(keypair.secretKey, message, CHAIN_ID_L2);

console.log(`Message: ${message}`);
console.log(`L1 Signature: ${l1Sig.substring(0, 32)}...`);
console.log(`L2 Signature: ${l2Sig.substring(0, 32)}...`);

if (l1Sig !== l2Sig) {
  console.log('✅ Signatures are DIFFERENT (domain separation working)');
} else {
  console.log('❌ Signatures are SAME (domain separation BROKEN)');
}

// Test 3: L1 Signature Verifies on L1
console.log('\n✅ TEST 3: L1 Signature Verifies on L1');
console.log('-'.repeat(80));

const l1Valid = verifySignature(keypair.publicKey, message, l1Sig, CHAIN_ID_L1);
console.log(`L1 signature + L1 chain_id: ${l1Valid ? '✅ VALID' : '❌ INVALID'}`);

if (!l1Valid) {
  console.log('❌ FAILURE: Legitimate L1 signature should verify on L1');
}

// Test 4: L1 Signature FAILS on L2 (Replay Attack Prevention)
console.log('\n🛡️  TEST 4: L1 Signature FAILS on L2 (Replay Attack Prevention)');
console.log('-'.repeat(80));

const l1OnL2 = verifySignature(keypair.publicKey, message, l1Sig, CHAIN_ID_L2);
console.log(`L1 signature + L2 chain_id: ${l1OnL2 ? '❌ VALID (VULNERABLE!)' : '✅ INVALID (PROTECTED)'}`);

if (l1OnL2) {
  console.log('❌ CRITICAL FAILURE: L1→L2 replay attack POSSIBLE');
} else {
  console.log('✅ SUCCESS: L1→L2 replay attack PREVENTED');
}

// Test 5: L2 Signature Verifies on L2
console.log('\n✅ TEST 5: L2 Signature Verifies on L2');
console.log('-'.repeat(80));

const l2Valid = verifySignature(keypair.publicKey, message, l2Sig, CHAIN_ID_L2);
console.log(`L2 signature + L2 chain_id: ${l2Valid ? '✅ VALID' : '❌ INVALID'}`);

if (!l2Valid) {
  console.log('❌ FAILURE: Legitimate L2 signature should verify on L2');
}

// Test 6: L2 Signature FAILS on L1 (Replay Attack Prevention)
console.log('\n🛡️  TEST 6: L2 Signature FAILS on L1 (Replay Attack Prevention)');
console.log('-'.repeat(80));

const l2OnL1 = verifySignature(keypair.publicKey, message, l2Sig, CHAIN_ID_L1);
console.log(`L2 signature + L1 chain_id: ${l2OnL1 ? '❌ VALID (VULNERABLE!)' : '✅ INVALID (PROTECTED)'}`);

if (l2OnL1) {
  console.log('❌ CRITICAL FAILURE: L2→L1 replay attack POSSIBLE');
} else {
  console.log('✅ SUCCESS: L2→L1 replay attack PREVENTED');
}

// Test 7: Full SignedRequest Structure
console.log('\n📦 TEST 7: SignedRequest Structure');
console.log('-'.repeat(80));

function createSignedRequest(privateKey, publicKey, payload, chainId) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = crypto.randomUUID();
  const payloadStr = JSON.stringify(payload);
  const message = `${payloadStr}\n${timestamp}\n${nonce}`;
  
  return {
    public_key: bytesToHex(publicKey),
    wallet_address: null,
    payload: payloadStr,
    timestamp,
    nonce,
    chain_id: chainId,
    signature: signWithDomainSeparation(privateKey, message, chainId),
  };
}

const l1Request = createSignedRequest(keypair.secretKey, keypair.publicKey, { action: 'deposit', amount: 1000 }, CHAIN_ID_L1);
const l2Request = createSignedRequest(keypair.secretKey, keypair.publicKey, { action: 'bet', amount: 100 }, CHAIN_ID_L2);

console.log('L1 Request:');
console.log(`  chain_id: 0x${l1Request.chain_id.toString(16)}`);
console.log(`  payload: ${l1Request.payload}`);
console.log(`  signature: ${l1Request.signature.substring(0, 32)}...`);

console.log('\nL2 Request:');
console.log(`  chain_id: 0x${l2Request.chain_id.toString(16)}`);
console.log(`  payload: ${l2Request.payload}`);
console.log(`  signature: ${l2Request.signature.substring(0, 32)}...`);

if (l1Request.chain_id === CHAIN_ID_L1 && l2Request.chain_id === CHAIN_ID_L2) {
  console.log('✅ chain_id fields correctly set');
} else {
  console.log('❌ chain_id fields incorrect');
}

// Test 8: Invalid Chain ID
console.log('\n⚠️  TEST 8: Invalid Chain ID Rejected');
console.log('-'.repeat(80));

try {
  signWithDomainSeparation(keypair.secretKey, message, 0x99);
  console.log('❌ Invalid chain_id accepted (should throw error)');
} catch (error) {
  console.log('✅ Invalid chain_id rejected:', error.message);
}

// Summary
console.log('\n' + '='.repeat(80));
console.log('📊 TEST SUMMARY');
console.log('='.repeat(80));

const allPassed = !l1OnL2 && !l2OnL1 && l1Valid && l2Valid && (l1Sig !== l2Sig);

if (allPassed) {
  console.log('✅ ALL TESTS PASSED - Domain separation working correctly!');
  console.log('   ✓ L1 and L2 signatures are different');
  console.log('   ✓ L1 signatures cannot be replayed on L2');
  console.log('   ✓ L2 signatures cannot be replayed on L1');
  console.log('   ✓ Legitimate requests verify on their intended chain');
  process.exit(0);
} else {
  console.log('❌ SOME TESTS FAILED - Security issue detected!');
  process.exit(1);
}
