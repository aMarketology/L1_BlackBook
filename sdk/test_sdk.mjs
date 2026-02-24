#!/usr/bin/env node
// ============================================================================
// BLACKBOOK SDK v3.0 — Integration Test Suite
// ============================================================================
// Tests the full wallet lifecycle:
//   1. Network connectivity (health, version, epoch)
//   2. Create wallet (BIP-39 + Shamir 2/3 SSS)
//   3. Verify wallet creation response
//   4. Save/load wallet from localStorage-style storage
//   5. Get Shard B from node
//   6. SSS Verify: A+B combo
//   7. SSS Verify: A+C combo
//   8. SSS Verify: B+C combo
//   9. Faucet: mint tokens to new wallet
//  10. Balance check
//  11. Transfer with SSS
//
// Usage: node test_sdk.mjs
// ============================================================================

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookSDK, LAMPORTS_PER_BB, SSS_COMBOS } = require('./blackbook_sdk.js');

// ── Config ──────────────────────────────────────────────────
const RPC_URL = 'http://localhost:8899';
const API_URL = 'http://localhost:8080';
const TEST_PASSWORD = 'TestPassword123!';
const TEST_USERNAME = 'sdk_test_user';

let passed = 0;
let failed = 0;
let skipped = 0;

function ok(name, detail = '') {
  passed++;
  console.log(`  ✅ ${name}${detail ? ' — ' + detail : ''}`);
}
function fail(name, err) {
  failed++;
  console.log(`  ❌ ${name} — ${err}`);
}
function skip(name, reason) {
  skipped++;
  console.log(`  ⏭️  ${name} — SKIP: ${reason}`);
}

// ============================================================================
// TEST RUNNER
// ============================================================================
async function main() {
  console.log('');
  console.log('═══════════════════════════════════════════════════════');
  console.log('  BLACKBOOK SDK v3.0 — Integration Tests');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`  RPC: ${RPC_URL}`);
  console.log(`  API: ${API_URL}`);
  console.log('');

  const bb = new BlackBookSDK(RPC_URL, API_URL, { timeout: 15_000 });

  // ── 1. Network ────────────────────────────────────────────
  console.log('📡 1. NETWORK');

  try {
    const health = await bb.getHealth();
    ok('getHealth()', JSON.stringify(health));
  } catch (e) {
    fail('getHealth()', e.message);
    console.log('\n⛔ Node not running. Start with: $env:SERVER_MASTER_KEY="test-master-key-32chars!!"; cargo run');
    process.exit(1);
  }

  try {
    const version = await bb.getVersion();
    ok('getVersion()', version['solana-core'] || JSON.stringify(version));
  } catch (e) { fail('getVersion()', e.message); }

  try {
    const epoch = await bb.getEpochInfo();
    ok('getEpochInfo()', `slot=${epoch.absoluteSlot} epoch=${epoch.epoch} height=${epoch.blockHeight}`);
  } catch (e) { fail('getEpochInfo()', e.message); }

  try {
    const genesis = await bb.getGenesisHash();
    ok('getGenesisHash()', genesis.slice(0, 16) + '…');
  } catch (e) { fail('getGenesisHash()', e.message); }

  try {
    const supply = await bb.getSupply();
    ok('getSupply()', `${supply.totalBB} BB total`);
  } catch (e) { fail('getSupply()', e.message); }

  try {
    const blockhash = await bb.getLatestBlockhash();
    ok('getLatestBlockhash()', JSON.stringify(blockhash).slice(0, 60) + '…');
  } catch (e) { fail('getLatestBlockhash()', e.message); }

  // ── 2. Create Wallet ──────────────────────────────────────
  console.log('\n🔐 2. WALLET CREATION');

  let wallet = null;
  try {
    wallet = await bb.createWallet(TEST_USERNAME, { password: TEST_PASSWORD });

    // Validate response structure
    const requiredFields = ['walletId', 'address', 'mnemonic', 'shardA', 'shardC', 'publicKey', 'shardAIsEncrypted'];
    const missing = requiredFields.filter(f => wallet[f] === undefined || wallet[f] === null);
    if (missing.length > 0) {
      fail('createWallet() fields', `Missing: ${missing.join(', ')}`);
    } else {
      ok('createWallet()', `address=${wallet.address.slice(0, 12)}…`);
    }

    // Validate specifics
    if (wallet.shardAIsEncrypted !== true) {
      fail('shardAIsEncrypted', `Expected true, got ${wallet.shardAIsEncrypted}`);
    } else {
      ok('shardAIsEncrypted', 'true (password-encrypted)');
    }

    const words = wallet.mnemonic.split(' ');
    if (words.length === 24) {
      ok('mnemonic', `24 words: "${words[0]} ${words[1]} … ${words[22]} ${words[23]}"`);
    } else {
      fail('mnemonic', `Expected 24 words, got ${words.length}`);
    }

    if (wallet.shardA && wallet.shardA.length > 20) {
      ok('shardA', `${wallet.shardA.length} chars (encrypted blob)`);
    } else {
      fail('shardA', `Too short: ${wallet.shardA?.length || 0} chars`);
    }

    if (wallet.shardC && wallet.shardC.length > 20) {
      ok('shardC', `${wallet.shardC.length} chars (raw hex)`);
    } else {
      fail('shardC', `Too short: ${wallet.shardC?.length || 0} chars`);
    }

  } catch (e) {
    fail('createWallet()', e.message);
  }

  if (!wallet) {
    console.log('\n⛔ Wallet creation failed — cannot continue with remaining tests.');
    printSummary();
    process.exit(1);
  }

  // ── 3. Wallet Session Storage ─────────────────────────────
  console.log('\n💾 3. WALLET SESSION STORAGE (simulated)');

  // Simulate localStorage for Node.js
  if (typeof globalThis.localStorage === 'undefined') {
    const store = {};
    globalThis.localStorage = {
      getItem: (k) => store[k] || null,
      setItem: (k, v) => { store[k] = v; },
      removeItem: (k) => { delete store[k]; },
    };
  }

  try {
    bb.saveWalletLocal(wallet);
    ok('saveWalletLocal()', 'saved to localStorage');
  } catch (e) { fail('saveWalletLocal()', e.message); }

  try {
    const loaded = bb.loadWalletLocal();
    if (loaded && loaded.walletId === wallet.walletId && loaded.shardA === wallet.shardA) {
      ok('loadWalletLocal()', `walletId=${loaded.walletId.slice(0, 12)}… shardA matches`);
    } else {
      fail('loadWalletLocal()', 'Data mismatch');
    }
  } catch (e) { fail('loadWalletLocal()', e.message); }

  try {
    bb.saveShardALocal(wallet.walletId, wallet.shardA);
    const loaded = bb.loadShardALocal(wallet.walletId);
    if (loaded === wallet.shardA) {
      ok('saveShardALocal / loadShardALocal', 'round-trip matches');
    } else {
      fail('saveShardALocal / loadShardALocal', 'mismatch');
    }
  } catch (e) { fail('saveShardALocal', e.message); }

  try {
    bb.deleteWalletLocal(wallet.walletId);
    const loaded = bb.loadWalletLocal();
    if (loaded === null) {
      ok('deleteWalletLocal()', 'session cleared');
    } else {
      fail('deleteWalletLocal()', 'session still present');
    }
  } catch (e) { fail('deleteWalletLocal()', e.message); }

  // ── 4. Get Shard B ────────────────────────────────────────
  console.log('\n☁️  4. SHARD B RETRIEVAL');

  let shardB = null;
  try {
    const result = await bb.getShardB(wallet.walletId);
    shardB = result.shardB;
    if (shardB && shardB.length > 20) {
      ok('getShardB()', `${shardB.length} chars, status=${result.status}`);
    } else {
      fail('getShardB()', `Too short: ${shardB?.length || 0}`);
    }
  } catch (e) { fail('getShardB()', e.message); }

  // ── 5. SSS Verification — All 3 Combos ───────────────────
  console.log('\n🧪 5. SSS 2/3 VERIFICATION');

  // A+B
  if (shardB) {
    try {
      const result = await bb.verifySssWithCombo({
        combo: 'AB',
        walletId: wallet.walletId,
        shardA: wallet.shardA,
        shardB: shardB,
        password: TEST_PASSWORD,
      });
      if (result.matches) {
        ok('SSS Verify A+B', `✅ match=true derived=${result.derivedAddress.slice(0, 12)}…`);
      } else {
        fail('SSS Verify A+B', `match=false derived=${result.derivedAddress}`);
      }
    } catch (e) { fail('SSS Verify A+B', e.message); }
  } else {
    skip('SSS Verify A+B', 'No Shard B available');
  }

  // A+C
  try {
    const result = await bb.verifySssWithCombo({
      combo: 'AC',
      walletId: wallet.walletId,
      shardA: wallet.shardA,
      shardC: wallet.shardC,
      password: TEST_PASSWORD,
    });
    if (result.matches) {
      ok('SSS Verify A+C', `✅ match=true derived=${result.derivedAddress.slice(0, 12)}…`);
    } else {
      fail('SSS Verify A+C', `match=false derived=${result.derivedAddress}`);
    }
  } catch (e) { fail('SSS Verify A+C', e.message); }

  // B+C
  if (shardB) {
    try {
      const result = await bb.verifySssWithCombo({
        combo: 'BC',
        walletId: wallet.walletId,
        shardB: shardB,
        shardC: wallet.shardC,
      });
      if (result.matches) {
        ok('SSS Verify B+C', `✅ match=true derived=${result.derivedAddress.slice(0, 12)}…`);
      } else {
        fail('SSS Verify B+C', `match=false derived=${result.derivedAddress}`);
      }
    } catch (e) { fail('SSS Verify B+C', e.message); }
  } else {
    skip('SSS Verify B+C', 'No Shard B available');
  }

  // A+B with auto-fetch
  try {
    const result = await bb.verifySssWithCombo({
      combo: 'AB',
      walletId: wallet.walletId,
      shardA: wallet.shardA,
      // shardB intentionally omitted — should auto-fetch
      password: TEST_PASSWORD,
    });
    if (result.matches) {
      ok('SSS Verify A+B (auto-fetch B)', `✅ match=true`);
    } else {
      fail('SSS Verify A+B (auto-fetch B)', `match=false`);
    }
  } catch (e) { fail('SSS Verify A+B (auto-fetch B)', e.message); }

  // Invalid combo
  try {
    await bb.verifySssWithCombo({ combo: 'XY', walletId: wallet.walletId });
    fail('SSS invalid combo', 'Should have thrown');
  } catch (e) {
    if (e.message.includes('Invalid combo')) {
      ok('SSS invalid combo throws', e.message);
    } else {
      fail('SSS invalid combo throws', e.message);
    }
  }

  // Wrong password should fail
  try {
    const result = await bb.verifySssWithCombo({
      combo: 'AB',
      walletId: wallet.walletId,
      shardA: wallet.shardA,
      shardB: shardB,
      password: 'WrongPassword!',
    });
    if (!result.matches) {
      ok('SSS wrong password = no match', 'correctly rejected');
    } else {
      fail('SSS wrong password', 'Should not match with wrong password');
    }
  } catch (e) {
    // Server may return error instead of { matches: false }
    ok('SSS wrong password = error', e.message.slice(0, 60));
  }

  // ── 6. Faucet ─────────────────────────────────────────────
  console.log('\n💧 6. FAUCET');

  try {
    const result = await bb.faucet(wallet.address, 10);
    ok('faucet(10 BB)', JSON.stringify(result).slice(0, 80));
  } catch (e) { fail('faucet()', e.message); }

  // ── 7. Balance ────────────────────────────────────────────
  console.log('\n💰 7. BALANCE');

  try {
    const bal = await bb.getBalance(wallet.address);
    ok('getBalance()', `${bal.bb} BB (${bal.lamports} lamports)`);
  } catch (e) { fail('getBalance()', e.message); }

  try {
    const bals = await bb.getBalances([
      wallet.address,
      '4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby',
    ]);
    const count = Object.keys(bals).length;
    ok('getBalances() batch', `${count} accounts returned`);
  } catch (e) { fail('getBalances()', e.message); }

  try {
    const info = await bb.getAccountInfo(wallet.address);
    if (info) {
      ok('getAccountInfo()', `lamports=${info.lamports} owner=${info.owner}`);
    } else {
      skip('getAccountInfo()', 'account not found on SVM (may need faucet to create)');
    }
  } catch (e) { fail('getAccountInfo()', e.message); }

  // ── 8. Transfer with SSS ──────────────────────────────────
  console.log('\n📤 8. TRANSFER WITH SSS');

  const recipientAddr = '4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby'; // Max's address
  try {
    // First check if we have balance
    const bal = await bb.getBalance(wallet.address);
    if (bal.bb >= 1.0) {
      const result = await bb.transferWithSSS(
        wallet.walletId,
        recipientAddr,
        0.5,
        wallet.shardA,
        TEST_PASSWORD,
      );
      if (result.success) {
        ok('transferWithSSS()', `sig=${result.signature.slice(0, 16)}… sent 0.5 BB`);
      } else {
        fail('transferWithSSS()', 'success=false');
      }
    } else {
      skip('transferWithSSS()', `Need >= 1 BB, have ${bal.bb} BB`);
    }
  } catch (e) { fail('transferWithSSS()', e.message); }

  // ── 9. Transactions ───────────────────────────────────────
  console.log('\n📜 9. TRANSACTIONS');

  try {
    const sigs = await bb.getSignaturesForAddress(recipientAddr, 5);
    ok('getSignaturesForAddress()', `${sigs?.length || 0} transactions`);
  } catch (e) { fail('getSignaturesForAddress()', e.message); }

  // ── 10. Utilities ─────────────────────────────────────────
  console.log('\n🔧 10. UTILITIES');

  try {
    const lamports = BlackBookSDK.toLamports(1.5);
    if (lamports === 1_500_000_000) ok('toLamports(1.5)', '1500000000'); else fail('toLamports', lamports);
  } catch (e) { fail('toLamports', e.message); }

  try {
    const bb_val = BlackBookSDK.toBB(2_500_000_000);
    if (bb_val === 2.5) ok('toBB(2500000000)', '2.5'); else fail('toBB', bb_val);
  } catch (e) { fail('toBB', e.message); }

  try {
    const formatted = BlackBookSDK.formatBB(10_500_000_000);
    ok('formatBB()', formatted);
  } catch (e) { fail('formatBB', e.message); }

  try {
    const short = BlackBookSDK.shortAddr('4PtfY2ySdcGpshvfqfnaNyAVBFKtpLbZ4HTBHZBT2oby');
    if (short === '4PtfY2…2oby') ok('shortAddr()', short); else fail('shortAddr', short);
  } catch (e) { fail('shortAddr', e.message); }

  try {
    const ago = BlackBookSDK.timeAgo(Math.floor(Date.now() / 1000) - 30);
    ok('timeAgo(30s)', ago);
  } catch (e) { fail('timeAgo', e.message); }

  // SSS_COMBOS constant
  try {
    if (SSS_COMBOS && SSS_COMBOS.AB && SSS_COMBOS.AC && SSS_COMBOS.BC) {
      ok('SSS_COMBOS exported', `${Object.keys(SSS_COMBOS).join(', ')}`);
    } else {
      fail('SSS_COMBOS', 'Missing combos');
    }
  } catch (e) { fail('SSS_COMBOS', e.message); }

  // WalletConnect helpers
  try {
    const config = bb.getChainConfig();
    if (config.chainId === 'solana:blackbook-l1' && config.nativeCurrency.symbol === 'BB') {
      ok('getChainConfig()', config.chainId);
    } else {
      fail('getChainConfig()', JSON.stringify(config));
    }
  } catch (e) { fail('getChainConfig', e.message); }

  try {
    const ns = bb.getWCNamespaces();
    if (ns.solana && ns.solana.methods.includes('solana_signTransaction')) {
      ok('getWCNamespaces()', 'solana namespace valid');
    } else {
      fail('getWCNamespaces()', JSON.stringify(ns));
    }
  } catch (e) { fail('getWCNamespaces', e.message); }

  try {
    const addr = bb.parseWCAddress({ namespaces: { solana: { accounts: ['solana:blackbook-l1:ABC123'] } } });
    if (addr === 'ABC123') ok('parseWCAddress()', addr); else fail('parseWCAddress', addr);
  } catch (e) { fail('parseWCAddress', e.message); }

  try {
    const addr = bb.parseWCAddress({});
    if (addr === null) ok('parseWCAddress(empty)', 'null'); else fail('parseWCAddress(empty)', addr);
  } catch (e) { fail('parseWCAddress(empty)', e.message); }

  // JWT setter
  try {
    bb.setJWT('test-token');
    if (bb.jwt === 'test-token') ok('setJWT()', 'set successfully');
    bb.setJWT(null);
  } catch (e) { fail('setJWT', e.message); }

  // ── Summary ───────────────────────────────────────────────
  printSummary();
}

function printSummary() {
  console.log('');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`  RESULTS: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  console.log('═══════════════════════════════════════════════════════');
  if (failed === 0) {
    console.log('  🎉 ALL TESTS PASSED');
  } else {
    console.log(`  ⚠️  ${failed} test(s) need attention`);
  }
  console.log('');
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => {
  console.error('💥 Unhandled error:', e);
  process.exit(1);
});
