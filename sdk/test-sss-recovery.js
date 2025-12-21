/**
 * test-sss-recovery.js - Test SSS Recovery System
 * 
 * Demonstrates the full wallet creation and recovery flow
 */

import nacl from 'tweetnacl';
import * as walletRecovery from './wallet-recovery.js';
import CryptoJS from 'crypto-js';

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

console.log('🧪 Testing SSS Recovery System\n');
console.log('='.repeat(80));

async function testFullFlow() {
  // Test Configuration
  const PIN = '123456';
  const SERVER_KEY = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  
  console.log('\n📝 STEP 1: Create New Wallet');
  console.log('-'.repeat(80));
  
  // Generate a new keypair
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  
  const seedHex = bytesToHex(seed);
  const publicKeyHex = bytesToHex(keypair.publicKey);
  
  // Generate address
  const hash = CryptoJS.SHA256(publicKeyHex).toString(CryptoJS.enc.Hex);
  const shortHash = hash.slice(0, 14).toUpperCase();
  const l1Address = `L1${shortHash}`;
  const l2Address = `L2${shortHash}`;
  
  console.log(`✅ Created wallet:`);
  console.log(`   Seed: ${seedHex.substring(0, 32)}...`);
  console.log(`   Public Key: ${publicKeyHex.substring(0, 32)}...`);
  console.log(`   L1 Address: ${l1Address}`);
  console.log(`   L2 Address: ${l2Address}`);
  
  console.log('\n🔀 STEP 2: Create SSS Recovery Shares');
  console.log('-'.repeat(80));
  
  const shares = await walletRecovery.createRecoveryShares(seedHex, PIN, SERVER_KEY);
  
  console.log(`✅ Created 3 encrypted shares:`);
  console.log(`   Share 1 (Server): ${shares.serverShare.encrypted.substring(0, 32)}...`);
  console.log(`   Share 2 (Cloud):  ${shares.cloudShare.encrypted.substring(0, 32)}...`);
  console.log(`   Share 3 (Email):  ${shares.emailShare.encrypted.substring(0, 32)}...`);
  
  console.log('\n🔐 STEP 3: Simulate Password Reset (Lose Access)');
  console.log('-'.repeat(80));
  
  console.log('❌ User forgets password');
  console.log('❌ Cannot decrypt vault with old password');
  console.log('✅ User still has: PIN + Cloud backup + Server share');
  
  console.log('\n🔄 STEP 4: Recover Wallet with PIN + Cloud Backup');
  console.log('-'.repeat(80));
  
  const recoveredSeed = await walletRecovery.recoverSeedFromShares(
    shares.serverShare,
    shares.cloudShare,
    PIN,
    SERVER_KEY
  );
  
  console.log(`✅ Recovered seed: ${recoveredSeed.substring(0, 32)}...`);
  
  // Verify recovery
  if (recoveredSeed === seedHex) {
    console.log('✅ RECOVERY SUCCESSFUL - Seeds match!');
  } else {
    console.log('❌ RECOVERY FAILED - Seeds do not match!');
    process.exit(1);
  }
  
  // Re-derive keypair from recovered seed
  const recoveredKeypair = nacl.sign.keyPair.fromSeed(
    new Uint8Array(recoveredSeed.match(/.{2}/g).map(byte => parseInt(byte, 16)))
  );
  
  const recoveredPublicKeyHex = bytesToHex(recoveredKeypair.publicKey);
  
  if (recoveredPublicKeyHex === publicKeyHex) {
    console.log('✅ Public key matches - Full wallet recovered!');
  } else {
    console.log('❌ Public key mismatch!');
    process.exit(1);
  }
  
  console.log('\n🔄 STEP 5: Alternative Recovery with Email Backup');
  console.log('-'.repeat(80));
  
  const recoveredSeed2 = await walletRecovery.recoverSeedFromShares(
    shares.serverShare,
    shares.emailShare,  // Using email instead of cloud
    PIN,
    SERVER_KEY
  );
  
  if (recoveredSeed2 === seedHex) {
    console.log('✅ Alternative recovery successful (Server + Email)');
  } else {
    console.log('❌ Alternative recovery failed');
    process.exit(1);
  }
  
  console.log('\n🛡️  STEP 6: Test Security (Wrong PIN)');
  console.log('-'.repeat(80));
  
  try {
    await walletRecovery.recoverSeedFromShares(
      shares.serverShare,
      shares.cloudShare,
      '999999',  // Wrong PIN
      SERVER_KEY
    );
    console.log('❌ SECURITY FAILURE: Wrong PIN accepted!');
    process.exit(1);
  } catch (error) {
    console.log('✅ Security working: Wrong PIN rejected');
    console.log(`   Error: ${error.message}`);
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('🎉 ALL TESTS PASSED');
  console.log('='.repeat(80));
  console.log('');
  console.log('Summary:');
  console.log('  ✅ Wallet created with domain-separated addresses');
  console.log('  ✅ SSS shares created (3 shares, threshold 2)');
  console.log('  ✅ Recovery with Server + Cloud successful');
  console.log('  ✅ Recovery with Server + Email successful');
  console.log('  ✅ Wrong PIN rejected (security working)');
  console.log('');
  console.log('Next steps:');
  console.log('  1. Integrate with Supabase for server share storage');
  console.log('  2. Implement cloud backup download/upload');
  console.log('  3. Implement email backup sending');
  console.log('  4. Add password re-encryption after recovery');
}

testFullFlow().catch(error => {
  console.error('\n❌ TEST FAILED:', error.message);
  console.error(error.stack);
  process.exit(1);
});
