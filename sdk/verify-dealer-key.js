#!/usr/bin/env node
import nacl from 'tweetnacl';
import fs from 'fs';
import path from 'path';

// Load .env
const envPath = path.resolve(process.cwd(), '..', '.env');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf8');
  envContent.split('\n').forEach(line => {
    const [key, ...valueParts] = line.split('=');
    if (key && valueParts.length > 0) {
      const value = valueParts.join('=').trim();
      if (!process.env[key.trim()]) {
        process.env[key.trim()] = value;
      }
    }
  });
}

const DEALER_PRIVATE_KEY = process.env.DEALER_PRIVATE_KEY;
const EXPECTED_PUBLIC_KEY = "07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a";

console.log('\n🔐 Dealer Keypair Verification\n');
console.log('Private Key:', DEALER_PRIVATE_KEY);
console.log('Expected Public Key:', EXPECTED_PUBLIC_KEY);

if (!DEALER_PRIVATE_KEY) {
  console.log('❌ DEALER_PRIVATE_KEY not found in .env');
  process.exit(1);
}

// Derive public key from private key
const privateKey = Buffer.from(DEALER_PRIVATE_KEY, 'hex');
const keypair = nacl.sign.keyPair.fromSeed(privateKey);
const derivedPublicKey = Buffer.from(keypair.publicKey).toString('hex');

console.log('Derived Public Key:', derivedPublicKey);

if (derivedPublicKey === EXPECTED_PUBLIC_KEY) {
  console.log('✅ Keys match! Keypair is valid.');
} else {
  console.log('❌ Keys DO NOT match! The private key does not correspond to the expected public key.');
  console.log('\n⚠️  Either:');
  console.log('   1. Update DEALER_PUBLIC_KEY in unified_auth.rs to:', derivedPublicKey);
  console.log('   2. OR get the correct private key for public key:', EXPECTED_PUBLIC_KEY);
}

// Test signing
const CHAIN_ID_L1 = 0x01;
const message = "test message";
const domainSeparated = Buffer.concat([
  Buffer.from([CHAIN_ID_L1]),
  Buffer.from(message, 'utf8')
]);

const secretKey = new Uint8Array(64);
secretKey.set(privateKey, 0);
secretKey.set(keypair.publicKey, 32);

const signature = nacl.sign.detached(domainSeparated, secretKey);
const signatureHex = Buffer.from(signature).toString('hex');

console.log('\n🔏 Signature Test:');
console.log('Message:', message);
console.log('Signature:', signatureHex);

// Verify
const verified = nacl.sign.detached.verify(domainSeparated, signature, keypair.publicKey);
console.log('Self-verification:', verified ? '✅ Valid' : '❌ Invalid');
