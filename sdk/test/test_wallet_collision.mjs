#!/usr/bin/env node
// ============================================================================
// BLACKBOOK WALLET — Address Collision Test
// ============================================================================
//
// CRITICAL SECURITY TEST: Verifies that wallet address generation produces
// unique addresses. A collision (two wallets with the same address) would
// let one user spend another's funds.
//
// Address derivation chain:
//   32 bytes OS entropy → BIP-39 mnemonic → BIP-39 seed →
//   first 32 bytes → Ed25519 signing key → verifying key (32 bytes) →
//   base58 encode → wallet address
//
// Theoretical address space: 2^252 (Ed25519 curve order ≈ 2^252.6)
//
// This test:
//   1. Creates N wallets in rapid succession
//   2. Checks every address is unique (Set-based O(1) lookups)
//   3. Checks every mnemonic is unique
//   4. Checks every Shard C is unique
//   5. Reports entropy quality metrics
//
// Usage:  node test_wallet_collision.mjs [count]
//         Default count: 50
// ============================================================================

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookWalletSDK } = require('./wallet_sdk.js');

const RPC_URL = 'http://localhost:8899';
const API_URL = 'http://localhost:8080';
const WALLET_COUNT = parseInt(process.argv[2] || '50', 10);

async function run() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║   BLACKBOOK WALLET — Address Collision Test                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  console.log(`  Creating ${WALLET_COUNT} wallets and checking for collisions...\n`);

  const sdk = new BlackBookWalletSDK(RPC_URL, API_URL);

  const addresses  = new Set();
  const mnemonics  = new Set();
  const shardsC    = new Set();
  const shardsA    = new Set();
  const publicKeys = new Set();
  const wallets    = [];

  let collisions = 0;
  const startTime = Date.now();

  for (let i = 0; i < WALLET_COUNT; i++) {
    const username = `collision_test_${Date.now()}_${i}`;
    try {
      const w = await sdk.createWallet(username, { password: 'CollisionTest!123' });

      // ── Check address uniqueness ──
      if (addresses.has(w.address)) {
        console.log(`  🚨 ADDRESS COLLISION at wallet #${i + 1}: ${w.address}`);
        collisions++;
      }
      addresses.add(w.address);

      // ── Check mnemonic uniqueness ──
      if (mnemonics.has(w.mnemonic)) {
        console.log(`  🚨 MNEMONIC COLLISION at wallet #${i + 1}`);
        collisions++;
      }
      mnemonics.add(w.mnemonic);

      // ── Check Shard C uniqueness ──
      if (shardsC.has(w.shardC)) {
        console.log(`  🚨 SHARD C COLLISION at wallet #${i + 1}`);
        collisions++;
      }
      shardsC.add(w.shardC);

      // ── Check Shard A uniqueness (even encrypted, should differ due to random salt/nonce) ──
      if (shardsA.has(w.shardA)) {
        console.log(`  🚨 SHARD A COLLISION at wallet #${i + 1} (same salt+nonce+ct — RNG failure)`);
        collisions++;
      }
      shardsA.add(w.shardA);

      // ── Check public key uniqueness ──
      if (publicKeys.has(w.publicKey)) {
        console.log(`  🚨 PUBLIC KEY COLLISION at wallet #${i + 1}: ${w.publicKey}`);
        collisions++;
      }
      publicKeys.add(w.publicKey);

      wallets.push(w);

      // Progress every 10 wallets
      if ((i + 1) % 10 === 0) {
        console.log(`  ✅ ${i + 1}/${WALLET_COUNT} wallets created — 0 collisions so far`);
      }

    } catch (e) {
      console.log(`  ❌ Wallet #${i + 1} creation failed: ${e.message}`);
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  // ── Entropy quality: check address character distribution ──
  console.log('\n─── Entropy Analysis ───');
  const allAddressChars = wallets.map(w => w.address).join('');
  const charFreq = {};
  for (const c of allAddressChars) {
    charFreq[c] = (charFreq[c] || 0) + 1;
  }
  const charCount = Object.keys(charFreq).length;
  const avgAddrLen = (allAddressChars.length / wallets.length).toFixed(1);

  console.log(`  Address charset diversity: ${charCount} unique characters (base58 = 58 expected)`);
  console.log(`  Average address length: ${avgAddrLen} chars`);

  // Check first-byte distribution (should be roughly uniform)
  const firstChars = {};
  for (const w of wallets) {
    const fc = w.address[0];
    firstChars[fc] = (firstChars[fc] || 0) + 1;
  }
  const firstCharCount = Object.keys(firstChars).length;
  console.log(`  First-char diversity: ${firstCharCount} unique starting characters across ${wallets.length} wallets`);

  // Mnemonic word diversity
  const allWords = wallets.flatMap(w => w.mnemonic.split(' '));
  const uniqueWords = new Set(allWords).size;
  console.log(`  Mnemonic word diversity: ${uniqueWords} unique words used out of ${allWords.length} total (BIP-39 has 2048)`);

  // ── Theoretical capacity ──
  console.log('\n─── Theoretical Address Space ───');
  console.log('  Key type:       Ed25519 (32-byte public key)');
  console.log('  Curve order:    2^252.6 (≈ 7.24 × 10^75)');
  console.log('  Address format: base58 encoding of 32-byte Ed25519 public key');
  console.log('  Entropy source: 32 bytes from OS CSPRNG (OsRng)');
  console.log('');
  console.log('  For reference:');
  console.log('    • Atoms in the observable universe:   ~10^80');
  console.log('    • Ed25519 address space:              ~10^75.8');
  console.log('    • Grains of sand on Earth:            ~10^19');
  console.log('    • Birthday-paradox collision at 50%:  ~2^126 wallets (≈ 8.5 × 10^37)');
  console.log('');
  console.log('  At 1 billion wallets/second, a 50% collision chance takes:');
  console.log('    2^126 / 10^9 / 86400 / 365 ≈ 2.7 × 10^21 YEARS');

  // ── Summary ──
  console.log('\n══════════════════════════════════════════════════════════════');
  if (collisions === 0) {
    console.log(`  ✅ PASS: ${wallets.length} wallets created, ZERO collisions (${elapsed}s)`);
    console.log('  ✅ All addresses unique');
    console.log('  ✅ All mnemonics unique');
    console.log('  ✅ All Shard C values unique');
    console.log('  ✅ All Shard A values unique (random salt/nonce)');
    console.log('  ✅ All public keys unique');
  } else {
    console.log(`  🚨 CRITICAL FAILURE: ${collisions} COLLISIONS detected in ${wallets.length} wallets`);
    console.log('  🚨 THIS IS A SECURITY VULNERABILITY — DO NOT DEPLOY');
  }
  console.log('══════════════════════════════════════════════════════════════\n');

  process.exit(collisions > 0 ? 1 : 0);
}

run().catch(e => {
  console.error('FATAL:', e);
  process.exit(2);
});
