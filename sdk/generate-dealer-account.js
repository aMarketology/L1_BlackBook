#!/usr/bin/env node
// ============================================================================
// DEALER ACCOUNT GENERATOR
// ============================================================================
// Generates the House/Oracle/Dealer account for Layer 2 operations
// This account has special privileges:
// - Create prediction markets
// - Resolve markets (declare winners)
// - Push payouts to winners
// - Infinite L2 liquidity (backed by L1 vault)
//
// RUN: node sdk/generate-dealer-account.js

import * as bip39 from 'bip39';
import { derivePath } from 'ed25519-hd-key';
import nacl from 'tweetnacl';
import CryptoJS from 'crypto-js';

// ============================================================================
// ADDRESS GENERATION
// ============================================================================

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate L2 address from Ed25519 public key
 * Format: L2_ + 40 hex chars (160-bit security)
 */
function generateL2Address(publicKeyHex) {
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const addressHash = hash.slice(0, 40).toUpperCase();
  return `L2_${addressHash}`;
}

/**
 * Derive Ed25519 keypair from mnemonic
 */
function deriveKeypairFromMnemonic(mnemonic, derivationPath = "m/44'/1337'/0'/0'/0'") {
  const seed = bip39.mnemonicToSeedSync(mnemonic);
  const seedHex = seed.toString('hex');
  const { key } = derivePath(derivationPath, seedHex);
  const keypair = nacl.sign.keyPair.fromSeed(key);
  
  return {
    publicKey: keypair.publicKey,
    privateKey: keypair.secretKey,
    publicKeyHex: bytesToHex(keypair.publicKey),
    privateKeyHex: bytesToHex(keypair.secretKey)
  };
}

// ============================================================================
// GENERATE DEALER ACCOUNT
// ============================================================================

console.log('');
console.log('🎰 GENERATING DEALER/ORACLE/HOUSE ACCOUNT');
console.log('═══════════════════════════════════════════════════════════');
console.log('');

// Generate a unique mnemonic for the Dealer
const dealerMnemonic = bip39.generateMnemonic(256); // 24 words for extra security
console.log('📜 Generated 24-word mnemonic (BACKUP THIS!):');
console.log('');
console.log(`   ${dealerMnemonic}`);
console.log('');

// Derive keypair
const dealerKeypair = deriveKeypairFromMnemonic(dealerMnemonic);
const dealerAddress = generateL2Address(dealerKeypair.publicKeyHex);

console.log('🔑 Dealer Account Details:');
console.log('');
console.log(`   L2 Address:   ${dealerAddress}`);
console.log(`   Public Key:   ${dealerKeypair.publicKeyHex}`);
console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('⚠️  ADD TO .env FILE (NEVER COMMIT TO GIT):');
console.log('═══════════════════════════════════════════════════════════');
console.log('');
console.log(`DEALER_PRIVATE_KEY=${dealerKeypair.privateKeyHex.slice(0, 64)}`);
console.log(`DEALER_PUBLIC_KEY=${dealerKeypair.publicKeyHex}`);
console.log(`DEALER_ADDRESS=${dealerAddress}`);
console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('');
console.log('📝 IMPORTANT SECURITY NOTES:');
console.log('');
console.log('1. ⚠️  BACKUP the 24-word mnemonic in a secure location');
console.log('2. ⚠️  Add the private key to .env file');
console.log('3. ⚠️  NEVER commit .env to version control');
console.log('4. ⚠️  Add .env to .gitignore');
console.log('5. ⚠️  Use environment variables in production');
console.log('');
console.log('═══════════════════════════════════════════════════════════');
console.log('');

// Output JSON format for easy copying
const dealerAccount = {
  name: 'Dealer',
  role: 'Oracle/House',
  layer: 'L2',
  address: dealerAddress,
  public_key: dealerKeypair.publicKeyHex,
  private_key: dealerKeypair.privateKeyHex.slice(0, 64), // 32-byte seed
  mnemonic: dealerMnemonic,
  derivation_path: "m/44'/1337'/0'/0'/0'",
  created_at: new Date().toISOString()
};

console.log('📄 JSON Format (for dealer-account.json):');
console.log('');
console.log(JSON.stringify(dealerAccount, null, 2));
console.log('');
