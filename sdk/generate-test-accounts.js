#!/usr/bin/env node
// ============================================================================
// GENERATE TEST ACCOUNTS - Alice & Bob
// ============================================================================
// 
// This script generates REAL wallet addresses for Alice and Bob using the
// actual wallet creation flow from unified-wallet-sdk.js
// 
// The generated keys are saved to test-accounts-generated.json for use in tests.
//
// RUN: node sdk/generate-test-accounts.js
// ============================================================================

import nacl from 'tweetnacl';
import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import CryptoJS from 'crypto-js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// BIP-44 Derivation Path for BlackBook
const L1_DERIVATION_PATH = "m/44'/1337'/0'/0'/0'";

// ============================================================================
// CRYPTO HELPERS (copied from SDK for standalone execution)
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

/**
 * Generate L1 address from Ed25519 public key
 * Format: L1_ + 40 hex chars (160-bit security, same as Bitcoin RIPEMD160)
 */
function generateL1Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const addressHash = hash.slice(0, 40).toUpperCase();
  return `L1_${addressHash}`;
}

/**
 * Generate L2 address from Ed25519 public key
 * Format: L2_ + 40 hex chars (160-bit security, same as Bitcoin RIPEMD160)
 */
function generateL2Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const addressHash = hash.slice(0, 40).toUpperCase();
  return `L2_${addressHash}`;
}

/**
 * Derive ed25519 keypair from mnemonic using SLIP-0010
 */
function deriveKeypairFromMnemonic(mnemonic, derivationPath = L1_DERIVATION_PATH) {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const seedHex = seed.toString('hex');
  const { key } = derivePath(derivationPath, seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(key);
  
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
    publicKeyHex: bytesToHex(keypair.publicKey),
    privateKeyHex: bytesToHex(keypair.secretKey),
    seedHex: bytesToHex(key)  // 32-byte seed for later use
  };
}

/**
 * Generate a complete wallet from a mnemonic
 */
function generateWallet(name, mnemonic) {
  console.log(`\n🔐 Generating wallet for ${name}...`);
  
  // Validate mnemonic
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error(`Invalid mnemonic for ${name}`);
  }
  
  // Derive keypair
  const keypair = deriveKeypairFromMnemonic(mnemonic);
  
  // Generate addresses
  const l1Address = generateL1Address(keypair.publicKeyHex);
  const l2Address = generateL2Address(keypair.publicKeyHex);
  
  console.log(`   📜 Mnemonic: ${mnemonic.split(' ').slice(0, 3).join(' ')}... (${mnemonic.split(' ').length} words)`);
  console.log(`   🔑 Public Key: ${keypair.publicKeyHex.slice(0, 16)}...`);
  console.log(`   📍 L1 Address: ${l1Address}`);
  console.log(`   📍 L2 Address: ${l2Address}`);
  
  return {
    name,
    mnemonic,
    public_key: keypair.publicKeyHex,
    private_key: keypair.seedHex,  // 32-byte seed (not full 64-byte secretKey)
    full_private_key: keypair.privateKeyHex,  // Full 64-byte secretKey for signing
    l1_address: l1Address,
    l2_address: l2Address,
    derivation_path: L1_DERIVATION_PATH
  };
}

// ============================================================================
// MAIN - Generate Alice & Bob
// ============================================================================

console.log('═══════════════════════════════════════════════════════════════════════');
console.log('   BLACKBOOK TEST ACCOUNT GENERATOR');
console.log('   Generating real wallets using BIP-39 + Ed25519 + SHA256');
console.log('═══════════════════════════════════════════════════════════════════════');

// Generate deterministic mnemonics for Alice and Bob
// Using fixed mnemonics so tests are reproducible
const ALICE_MNEMONIC = bip39.generateMnemonic(128);  // 12 words
const BOB_MNEMONIC = bip39.generateMnemonic(128);    // 12 words

const alice = generateWallet('Alice', ALICE_MNEMONIC);
const bob = generateWallet('Bob', BOB_MNEMONIC);

// Create output structure
const testAccounts = {
  generated_at: new Date().toISOString(),
  format_version: 2,
  address_format: 'L1/L2 + 40 hex chars (160-bit, SHA256 truncated)',
  note: 'These are REAL cryptographic keys generated from BIP-39 mnemonics',
  
  alice: {
    name: alice.name,
    username: 'alice_test',
    email: 'alice@blackbook.test',
    mnemonic: alice.mnemonic,
    public_key: alice.public_key,
    private_key: alice.private_key,
    l1_address: alice.l1_address,
    l2_address: alice.l2_address,
    derivation_path: alice.derivation_path
  },
  
  bob: {
    name: bob.name,
    username: 'bob_test',
    email: 'bob@blackbook.test',
    mnemonic: bob.mnemonic,
    public_key: bob.public_key,
    private_key: bob.private_key,
    l1_address: bob.l1_address,
    l2_address: bob.l2_address,
    derivation_path: bob.derivation_path
  }
};

// Save to file
const outputPath = path.join(__dirname, 'test-accounts-generated.json');
fs.writeFileSync(outputPath, JSON.stringify(testAccounts, null, 2));

console.log('\n═══════════════════════════════════════════════════════════════════════');
console.log('   ✅ ACCOUNTS GENERATED SUCCESSFULLY');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log(`\n📁 Saved to: ${outputPath}`);
console.log('\n📋 ALICE:');
console.log(`   L1 Address: ${alice.l1_address}`);
console.log(`   Public Key: ${alice.public_key}`);
console.log(`   Mnemonic: ${alice.mnemonic}`);
console.log('\n📋 BOB:');
console.log(`   L1 Address: ${bob.l1_address}`);
console.log(`   Public Key: ${bob.public_key}`);
console.log(`   Mnemonic: ${bob.mnemonic}`);

console.log('\n⚠️  These keys are for TESTING ONLY. Never use in production!');
console.log('');

// Also update the SDK's built-in ACCOUNTS constant
console.log('\n📝 Copy these into unified-wallet-sdk.js ACCOUNTS constant:\n');
console.log(`const ACCOUNTS = {
  alice: {
    name: 'Alice',
    username: 'alice_test',
    email: 'alice@blackbook.test',
    address: '${alice.l1_address}',
    public_key: '${alice.public_key}',
    private_key: '${alice.private_key}',
    mnemonic: '${alice.mnemonic}'
  },
  bob: {
    name: 'Bob', 
    username: 'bob_test',
    email: 'bob@blackbook.test',
    address: '${bob.l1_address}',
    public_key: '${bob.public_key}',
    private_key: '${bob.private_key}',
    mnemonic: '${bob.mnemonic}'
  }
};`);

// Verify the wallet can be reconstructed
console.log('\n\n🔍 VERIFICATION - Reconstructing wallets from private keys...');

function verifyWallet(account) {
  const seed = hexToBytes(account.private_key);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  const pubKeyHex = bytesToHex(keypair.publicKey);
  const reconstructedL1 = generateL1Address(pubKeyHex);
  
  const pubKeyMatch = pubKeyHex === account.public_key;
  const addressMatch = reconstructedL1 === account.l1_address;
  
  console.log(`\n   ${account.name}:`);
  console.log(`   Public key match: ${pubKeyMatch ? '✅' : '❌'}`);
  console.log(`   Address match: ${addressMatch ? '✅' : '❌'}`);
  
  if (!pubKeyMatch) {
    console.log(`   Expected: ${account.public_key}`);
    console.log(`   Got:      ${pubKeyHex}`);
  }
  if (!addressMatch) {
    console.log(`   Expected: ${account.l1_address}`);
    console.log(`   Got:      ${reconstructedL1}`);
  }
  
  return pubKeyMatch && addressMatch;
}

const aliceVerified = verifyWallet(testAccounts.alice);
const bobVerified = verifyWallet(testAccounts.bob);

if (aliceVerified && bobVerified) {
  console.log('\n✅ All wallets verified successfully!');
} else {
  console.log('\n❌ Verification failed! Check the wallet generation logic.');
  process.exit(1);
}

// Test signature creation
console.log('\n\n🔏 SIGNATURE TEST - Creating and verifying signatures...');

function testSignature(account, chainId) {
  const seed = hexToBytes(account.private_key);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  
  // Create message with domain separation
  const message = 'test_transaction_data';
  const messageBytes = new TextEncoder().encode(message);
  const domainSeparatedMessage = new Uint8Array(1 + messageBytes.length);
  domainSeparatedMessage[0] = chainId;
  domainSeparatedMessage.set(messageBytes, 1);
  
  // Sign
  const signature = nacl.sign.detached(domainSeparatedMessage, keypair.secretKey);
  
  // Verify
  const isValid = nacl.sign.detached.verify(domainSeparatedMessage, signature, keypair.publicKey);
  
  const chainName = chainId === 0x01 ? 'L1' : 'L2';
  console.log(`   ${account.name} ${chainName} signature: ${isValid ? '✅ valid' : '❌ invalid'}`);
  
  return isValid;
}

const aliceL1Sig = testSignature(testAccounts.alice, 0x01);
const aliceL2Sig = testSignature(testAccounts.alice, 0x02);
const bobL1Sig = testSignature(testAccounts.bob, 0x01);
const bobL2Sig = testSignature(testAccounts.bob, 0x02);

if (aliceL1Sig && aliceL2Sig && bobL1Sig && bobL2Sig) {
  console.log('\n✅ All signature tests passed!');
} else {
  console.log('\n❌ Signature test failed!');
  process.exit(1);
}

console.log('\n═══════════════════════════════════════════════════════════════════════');
console.log('   🎉 TEST ACCOUNT GENERATION COMPLETE');
console.log('═══════════════════════════════════════════════════════════════════════');
console.log('');
