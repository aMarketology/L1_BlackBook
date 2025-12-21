#!/usr/bin/env node
// ============================================================================
// VERIFY WALLET FLOW - End-to-End Test
// ============================================================================
//
// This script verifies the complete wallet creation flow:
// 1. Generate mnemonic from BIP-39
// 2. Derive keypair via SLIP-0010
// 3. Generate L1/L2 addresses from public key
// 4. Sign transactions with domain separation
// 5. Verify signatures work correctly
//
// RUN: node sdk/verify-wallet-flow.js
// ============================================================================

import nacl from 'tweetnacl';
import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import CryptoJS from 'crypto-js';

const L1_DERIVATION_PATH = "m/44'/1337'/0'/0'/0'";
const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// ============================================================================
// CRYPTO HELPERS
// ============================================================================

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function generateL1Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  return `L1${hash.slice(0, 40).toUpperCase()}`;
}

function generateL2Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  return `L2${hash.slice(0, 40).toUpperCase()}`;
}

// ============================================================================
// WALLET CREATION FLOW
// ============================================================================

console.log('═══════════════════════════════════════════════════════════════════════');
console.log('   BLACKBOOK WALLET FLOW VERIFICATION');
console.log('═══════════════════════════════════════════════════════════════════════\n');

// Step 1: Generate BIP-39 mnemonic
console.log('📝 Step 1: Generate BIP-39 Mnemonic');
console.log('─────────────────────────────────────');
const mnemonic = bip39.generateMnemonic(128);  // 12 words
console.log(`   Mnemonic: ${mnemonic}`);
console.log(`   Word count: ${mnemonic.split(' ').length}`);
console.log(`   Valid: ${bip39.validateMnemonic(mnemonic) ? '✅' : '❌'}\n`);

// Step 2: Derive keypair using SLIP-0010
console.log('🔑 Step 2: Derive Ed25519 Keypair (SLIP-0010)');
console.log('─────────────────────────────────────────────');
const seed = bip39.mnemonicToSeedSync(mnemonic);
const seedHex = seed.toString('hex');
const { key } = derivePath(L1_DERIVATION_PATH, seedHex);
const keypair = nacl.sign.keyPair.fromSeed(key);

const publicKeyHex = bytesToHex(keypair.publicKey);
const privateKeyHex = bytesToHex(key);  // 32-byte seed

console.log(`   Derivation Path: ${L1_DERIVATION_PATH}`);
console.log(`   Public Key: ${publicKeyHex}`);
console.log(`   Private Key (seed): ${privateKeyHex}`);
console.log(`   Key sizes: pub=${keypair.publicKey.length}B, priv=${keypair.secretKey.length}B\n`);

// Step 3: Generate L1/L2 addresses
console.log('📍 Step 3: Generate L1/L2 Addresses');
console.log('───────────────────────────────────');
const l1Address = generateL1Address(publicKeyHex);
const l2Address = generateL2Address(publicKeyHex);

console.log(`   L1 Address: ${l1Address} (${l1Address.length} chars)`);
console.log(`   L2 Address: ${l2Address} (${l2Address.length} chars)`);
console.log(`   Address format: L1/L2 + 40 hex chars (160-bit security)\n`);

// Step 4: Sign messages with domain separation
console.log('🔏 Step 4: Sign with Domain Separation');
console.log('──────────────────────────────────────');

function signWithDomainSeparation(message, chainId) {
  const messageBytes = new TextEncoder().encode(message);
  const domainMessage = new Uint8Array(1 + messageBytes.length);
  domainMessage[0] = chainId;
  domainMessage.set(messageBytes, 1);
  return nacl.sign.detached(domainMessage, keypair.secretKey);
}

function verifyWithDomainSeparation(message, signature, chainId) {
  const messageBytes = new TextEncoder().encode(message);
  const domainMessage = new Uint8Array(1 + messageBytes.length);
  domainMessage[0] = chainId;
  domainMessage.set(messageBytes, 1);
  return nacl.sign.detached.verify(domainMessage, signature, keypair.publicKey);
}

const testMessage = JSON.stringify({
  action: 'transfer',
  to: 'L1DEADBEEF1234567890ABCDEF1234567890ABCD',
  amount: 100.0,
  timestamp: Date.now()
});

// Sign for L1
const l1Signature = signWithDomainSeparation(testMessage, CHAIN_ID_L1);
const l1SigHex = bytesToHex(l1Signature);
console.log(`   L1 Signature: ${l1SigHex.slice(0, 32)}...`);

// Sign for L2
const l2Signature = signWithDomainSeparation(testMessage, CHAIN_ID_L2);
const l2SigHex = bytesToHex(l2Signature);
console.log(`   L2 Signature: ${l2SigHex.slice(0, 32)}...`);

console.log(`   Signatures different: ${l1SigHex !== l2SigHex ? '✅ YES (domain separation working)' : '❌ NO (BROKEN!)'}\n`);

// Step 5: Verify signatures
console.log('✅ Step 5: Verify Signatures');
console.log('───────────────────────────');

const l1VerifyL1 = verifyWithDomainSeparation(testMessage, l1Signature, CHAIN_ID_L1);
const l1VerifyL2 = verifyWithDomainSeparation(testMessage, l1Signature, CHAIN_ID_L2);
const l2VerifyL1 = verifyWithDomainSeparation(testMessage, l2Signature, CHAIN_ID_L1);
const l2VerifyL2 = verifyWithDomainSeparation(testMessage, l2Signature, CHAIN_ID_L2);

console.log(`   L1 sig verified on L1 chain: ${l1VerifyL1 ? '✅' : '❌'} (should be ✅)`);
console.log(`   L1 sig verified on L2 chain: ${l1VerifyL2 ? '❌ REPLAY ATTACK!' : '✅'} (should be ✅ rejected)`);
console.log(`   L2 sig verified on L1 chain: ${l2VerifyL1 ? '❌ REPLAY ATTACK!' : '✅'} (should be ✅ rejected)`);
console.log(`   L2 sig verified on L2 chain: ${l2VerifyL2 ? '✅' : '❌'} (should be ✅)\n`);

// Step 6: Reconstruct wallet from private key
console.log('🔄 Step 6: Reconstruct Wallet from Private Key');
console.log('──────────────────────────────────────────────');

const reconstructedKeypair = nacl.sign.keyPair.fromSeed(hexToBytes(privateKeyHex));
const reconstructedPubKey = bytesToHex(reconstructedKeypair.publicKey);
const reconstructedL1 = generateL1Address(reconstructedPubKey);

console.log(`   Original pubkey:      ${publicKeyHex.slice(0, 32)}...`);
console.log(`   Reconstructed pubkey: ${reconstructedPubKey.slice(0, 32)}...`);
console.log(`   Match: ${publicKeyHex === reconstructedPubKey ? '✅' : '❌'}\n`);

// Summary
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('   VERIFICATION SUMMARY');
console.log('═══════════════════════════════════════════════════════════════════════');

const allPassed = 
  bip39.validateMnemonic(mnemonic) &&
  l1Address.length === 42 &&
  l2Address.length === 42 &&
  l1SigHex !== l2SigHex &&
  l1VerifyL1 && !l1VerifyL2 && !l2VerifyL1 && l2VerifyL2 &&
  publicKeyHex === reconstructedPubKey;

if (allPassed) {
  console.log('\n   🎉 ALL TESTS PASSED!\n');
  console.log('   The wallet creation flow is working correctly:');
  console.log('   ✅ BIP-39 mnemonic generation');
  console.log('   ✅ SLIP-0010 key derivation');
  console.log('   ✅ 160-bit address generation (42 chars)');
  console.log('   ✅ Domain separation (L1/L2 signatures different)');
  console.log('   ✅ Replay attack prevention');
  console.log('   ✅ Wallet reconstruction from seed\n');
} else {
  console.log('\n   ❌ SOME TESTS FAILED!\n');
  process.exit(1);
}

// Output test account for use in other tests
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('   GENERATED TEST ACCOUNT (for use in tests)');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log(`
{
  mnemonic: "${mnemonic}",
  public_key: "${publicKeyHex}",
  private_key: "${privateKeyHex}",
  l1_address: "${l1Address}",
  l2_address: "${l2Address}",
  derivation_path: "${L1_DERIVATION_PATH}"
}
`);
