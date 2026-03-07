#!/usr/bin/env node
// ============================================================================
// BLACKBOOK WALLET SDK — Integration Test Suite
// ============================================================================
//
// Tests the full wallet lifecycle end-to-end against a running node.
//
//   1.  Constructor & URL config
//   2.  createWallet (with password)
//   3.  createWallet (without password)
//   4.  Validate wallet create response shape
//   5.  getBalance (newly created wallet — should be 0)
//   6.  getBalanceREST
//   7.  Faucet — mint tokens to new wallet
//   8.  getBalance (after faucet — should be > 0)
//   9.  getShardB
//  10.  verifySss (A + B)
//  11.  verifySssCombo('AB')
//  12.  verifySssCombo('AC')
//  13.  verifySssCombo('BC')
//  14.  transfer (SSS-authenticated)
//  15.  transfer — insufficient balance guard
//  16.  transfer — wrong password guard
//  17.  getTransactionHistory
//  18.  getTransaction (by sig)
//  19.  Session: saveWalletLocal / loadWalletLocal / deleteWalletLocal
//  20.  Session: saveShardALocal / loadShardALocal / deleteShardALocal
//  21.  Static: toLamports / toBB
//  22.  Static: formatBB / shortAddr
//  23.  SSS_COMBOS constant
//  24.  setJWT
//  25.  Error: timeout
//
// Usage:  node test_wallet_sdk.mjs
// Requires: Node 18+ (native fetch) and a running BlackBook node
// ============================================================================

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookWalletSDK, LAMPORTS_PER_BB, CHAIN_ID, MAX_FAUCET_BB, SSS_COMBOS } = require('./wallet_sdk.js');

// ── Config ──────────────────────────────────────────────────
const RPC_URL = 'http://localhost:8899';
const API_URL = 'http://localhost:8080';
const TEST_PASSWORD = 'WalletTestPass!456';
const TEST_USERNAME = 'wallet_sdk_test_' + Date.now();

let passed = 0;
let failed = 0;
let skipped = 0;
const errors = [];

// Wallet state that flows through the test
let wallet = null;       // from createWallet
let walletNoPw = null;   // createWallet without password
let transferSig = null;  // from transfer

function ok(name, detail = '') {
  passed++;
  console.log(`  ✅ ${name}${detail ? ' — ' + detail : ''}`);
}
function fail(name, err) {
  failed++;
  errors.push({ name, err: String(err) });
  console.log(`  ❌ ${name} — ${err}`);
}
function skip(name, reason) {
  skipped++;
  console.log(`  ⏭️  ${name} — SKIP: ${reason}`);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

// Polyfill localStorage for Node.js (tests 19-20)
if (typeof globalThis.localStorage === 'undefined') {
  const store = {};
  globalThis.localStorage = {
    getItem(k) { return store[k] ?? null; },
    setItem(k, v) { store[k] = String(v); },
    removeItem(k) { delete store[k]; },
  };
}

// ============================================================================
// TEST RUNNER
// ============================================================================

async function run() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║   BLACKBOOK WALLET SDK — Integration Tests                 ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const sdk = new BlackBookWalletSDK(RPC_URL, API_URL);

  // ── 1. Constructor ────────────────────────────────────────────
  console.log('─── Constructor & Config ───');
  try {
    assert(sdk.rpcUrl === 'http://localhost:8899', 'rpcUrl mismatch');
    assert(sdk.apiUrl === 'http://localhost:8080', 'apiUrl mismatch');
    assert(sdk.timeout === 30000, 'timeout default');
    assert(sdk.jwt === null, 'jwt should be null');

    const s2 = new BlackBookWalletSDK('http://localhost:8899///', null, { jwt: 'tok', timeout: 5000 });
    assert(s2.rpcUrl === 'http://localhost:8899', 'trailing slash');
    assert(s2.jwt === 'tok', 'jwt not set');
    assert(s2.timeout === 5000, 'custom timeout');

    ok('Constructor', 'URL normalisation, jwt, timeout');
  } catch (e) { fail('Constructor', e.message); }

  // ── 2. createWallet (with password) ───────────────────────────
  console.log('\n─── Create Wallet ───');
  try {
    wallet = await sdk.createWallet(TEST_USERNAME, { password: TEST_PASSWORD });
    assert(wallet.walletId, 'missing walletId');
    assert(wallet.address, 'missing address');
    assert(wallet.walletId === wallet.address, 'walletId !== address');
    assert(wallet.mnemonic, 'missing mnemonic');
    assert(wallet.shardA, 'missing shardA');
    assert(wallet.shardC, 'missing shardC');
    assert(wallet.publicKey, 'missing publicKey');
    assert(wallet.shardAIsEncrypted === true, 'shardA should be encrypted');
    ok('createWallet(password)', `addr: ${wallet.address.slice(0, 12)}…`);
  } catch (e) { fail('createWallet(password)', e.message); }

  // ── 3. createWallet (without password) ────────────────────────
  try {
    walletNoPw = await sdk.createWallet(TEST_USERNAME + '_nopw');
    assert(walletNoPw.walletId, 'missing walletId');
    assert(walletNoPw.shardAIsEncrypted === false, 'shardA should NOT be encrypted');
    assert(walletNoPw.shardA.length > 10, 'shardA too short (raw hex)');
    ok('createWallet(no password)', `addr: ${walletNoPw.address.slice(0, 12)}…, shard raw hex`);
  } catch (e) { fail('createWallet(no password)', e.message); }

  // ── 4. Validate response shape ────────────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');
    const words = wallet.mnemonic.split(' ');
    assert(words.length === 24, `mnemonic should be 24 words, got ${words.length}`);
    assert(wallet.address.length >= 32, 'address too short for base58');
    // Shard A encrypted format: salt:nonce:ciphertext (3 parts)
    const parts = wallet.shardA.split(':');
    assert(parts.length === 3, `encrypted shardA should have 3 parts (salt:nonce:ct), got ${parts.length}`);
    assert(parts[0].length > 5, 'salt too short');
    assert(parts[1].length > 5, 'nonce too short');
    assert(parts[2].length > 10, 'ciphertext too short');
    // Shard C should be raw hex
    assert(/^[0-9a-f]+$/i.test(wallet.shardC), 'shardC is not valid hex');
    ok('Response shape', `24-word mnemonic, 3-part encrypted shardA, hex shardC`);
  } catch (e) { fail('Response shape', e.message); }

  // ── 5. getBalance (new wallet = 0) ────────────────────────────
  console.log('\n─── Balance ───');
  try {
    if (!wallet) throw new Error('no wallet');
    const bal = await sdk.getBalance(wallet.address);
    assert(typeof bal.lamports === 'number', 'lamports not a number');
    assert(typeof bal.bb === 'number', 'bb not a number');
    assert(bal.bb === 0, `new wallet should have 0 BB, got ${bal.bb}`);
    ok('getBalance(new wallet)', `${bal.bb} BB`);
  } catch (e) { fail('getBalance(new wallet)', e.message); }

  // ── 6. getBalanceREST ──────────────────────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');
    const info = await sdk.getBalanceREST(wallet.address);
    assert(info.address === wallet.address, 'address mismatch');
    assert(info.balance === 0 || info.balance === 0.0, 'balance should be 0');
    assert(info.unit === 'BB', 'unit should be BB');
    ok('getBalanceREST()', `${info.balance} ${info.unit}`);
  } catch (e) { fail('getBalanceREST()', e.message); }

  // ── 7. Faucet ──────────────────────────────────────────────────
  console.log('\n─── Faucet ───');
  try {
    if (!wallet) throw new Error('no wallet');
    const result = await sdk.faucet(wallet.address, 0.1, wallet.sessionToken);
    assert(result.success === true, `faucet failed: ${JSON.stringify(result)}`);
    assert(result.minted === 0.1, `minted ${result.minted}, expected 0.1`);
    assert(result.to === wallet.address, 'faucet to mismatch');
    ok('faucet(0.1 BB)', `minted: ${result.minted}, new_balance: ${result.new_balance}`);
  } catch (e) { fail('faucet(500 BB)', e.message); }

  // ── 8. getBalance (after faucet) ───────────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');
    const bal = await sdk.getBalance(wallet.address);
    assert(bal.bb > 0, `balance should be > 0 after faucet, got ${bal.bb}`);
    ok('getBalance(after faucet)', `${bal.bb} BB`);
  } catch (e) { fail('getBalance(after faucet)', e.message); }

  // ── 9. getShardB ───────────────────────────────────────────────
  console.log('\n─── Shard B ───');
  let shardBBlob = null;
  try {
    if (!wallet) throw new Error('no wallet');
    const resp = await sdk.getShardB(wallet.address);
    assert(resp.shardB, 'missing shardB');
    assert(typeof resp.shardB === 'string', 'shardB not a string');
    assert(resp.shardB.length > 10, 'shardB too short');
    shardBBlob = resp.shardB;
    ok('getShardB()', `blob length: ${resp.shardB.length}, status: ${resp.status}`);
  } catch (e) { fail('getShardB()', e.message); }

  // ── 10-13. SSS Verification ────────────────────────────────────
  console.log('\n─── SSS Verification ───');

  // 10. Raw verifySss (A + B)
  try {
    if (!wallet || !shardBBlob) throw new Error('no wallet or shardB');
    const result = await sdk.verifySss({
      walletId: wallet.address,
      shard1: wallet.shardA,
      shard2: shardBBlob,
      password: TEST_PASSWORD,
      shard2IsServerEncrypted: true,
    });
    assert(result.success === true, 'verifySss failed');
    assert(result.matches === true, 'derived address does not match');
    assert(result.derivedAddress === wallet.address, 'derived addr mismatch');
    ok('verifySss(A+B raw)', `matches: ${result.matches}`);
  } catch (e) { fail('verifySss(A+B raw)', e.message); }

  // 11. verifySssCombo('AB')
  try {
    if (!wallet) throw new Error('no wallet');
    const result = await sdk.verifySssCombo({
      combo: 'AB',
      walletId: wallet.address,
      shardA: wallet.shardA,
      password: TEST_PASSWORD,
    });
    assert(result.success === true, 'combo AB failed');
    assert(result.matches === true, 'combo AB mismatch');
    ok("verifySssCombo('AB')", `auto-fetched shard B, matches: ${result.matches}`);
  } catch (e) { fail("verifySssCombo('AB')", e.message); }

  // 12. verifySssCombo('AC')
  try {
    if (!wallet) throw new Error('no wallet');
    const result = await sdk.verifySssCombo({
      combo: 'AC',
      walletId: wallet.address,
      shardA: wallet.shardA,
      shardC: wallet.shardC,
      password: TEST_PASSWORD,
    });
    assert(result.success === true, 'combo AC failed');
    assert(result.matches === true, 'combo AC mismatch');
    ok("verifySssCombo('AC')", `matches: ${result.matches}`);
  } catch (e) { fail("verifySssCombo('AC')", e.message); }

  // 13. verifySssCombo('BC')
  try {
    if (!wallet) throw new Error('no wallet');
    const result = await sdk.verifySssCombo({
      combo: 'BC',
      walletId: wallet.address,
      shardC: wallet.shardC,
    });
    assert(result.success === true, 'combo BC failed');
    assert(result.matches === true, 'combo BC mismatch');
    ok("verifySssCombo('BC')", `auto-fetched shard B, matches: ${result.matches}`);
  } catch (e) { fail("verifySssCombo('BC')", e.message); }

  // ── 14. Transfer (SSS) ────────────────────────────────────────
  console.log('\n─── Transfers ───');
  try {
    if (!wallet || !walletNoPw) throw new Error('no wallets');
    const result = await sdk.transfer(
      wallet.address,
      walletNoPw.address,
      0.01,                 // 0.01 BB
      wallet.shardA,
      TEST_PASSWORD,
    );
    assert(result.success === true, `transfer failed: ${JSON.stringify(result)}`);
    assert(result.from === wallet.address, 'from mismatch');
    assert(result.to === walletNoPw.address, 'to mismatch');
    assert(result.amount === 0.01, `amount ${result.amount}, expected 0.01`);
    assert(typeof result.signature === 'string', 'missing signature');
    assert(result.signature.length > 10, 'signature too short');
    transferSig = result.signature;
    ok('transfer(0.01 BB)', `sig: ${result.signature.slice(0, 12)}…, fromBal: ${result.fromBalance}, toBal: ${result.toBalance}`);
  } catch (e) { fail('transfer(10 BB)', e.message); }

  // ── 15. Transfer — insufficient balance ────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');
    await sdk.transfer(
      wallet.address,
      walletNoPw.address,
      999999999,           // Way more than balance
      wallet.shardA,
      TEST_PASSWORD,
    );
    fail('transfer(insufficient)', 'should have thrown');
  } catch (e) {
    const msg = e.message.toLowerCase();
    assert(msg.includes('insufficient') || msg.includes('balance') || msg.includes('error'),
      `expected balance error, got: ${e.message}`);
    ok('transfer(insufficient)', `correctly rejected: "${e.message.slice(0, 60)}"`);
  }

  // ── 16. Transfer — wrong password ──────────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');
    await sdk.transfer(
      wallet.address,
      walletNoPw.address,
      1,
      wallet.shardA,
      'WRONG_PASSWORD_XYZ',
    );
    fail('transfer(wrong password)', 'should have thrown');
  } catch (e) {
    assert(e.message.length > 0, 'error message empty');
    ok('transfer(wrong password)', `correctly rejected: "${e.message.slice(0, 60)}"`);
  }

  // ── 17. Transaction history ────────────────────────────────────
  console.log('\n─── Transaction History ───');
  try {
    if (!wallet) throw new Error('no wallet');
    const history = await sdk.getTransactionHistory(wallet.address, 10);
    assert(Array.isArray(history), 'history not an array');
    ok('getTransactionHistory()', `${history.length} transactions found`);
  } catch (e) { fail('getTransactionHistory()', e.message); }

  // ── 18. getTransaction (by sig) ────────────────────────────────
  try {
    if (transferSig) {
      const tx = await sdk.getTransaction(transferSig);
      if (tx === null) {
        ok('getTransaction()', 'returned null (tx not indexed yet)');
      } else {
        ok('getTransaction()', `slot: ${tx.slot}`);
      }
    } else {
      skip('getTransaction()', 'no transfer signature available');
    }
  } catch (e) { fail('getTransaction()', e.message); }

  // ── 19. localStorage Session ───────────────────────────────────
  console.log('\n─── Session (localStorage) ───');
  try {
    if (!wallet) throw new Error('no wallet');

    // Save
    sdk.saveWalletLocal(wallet);

    // Load
    const loaded = sdk.loadWalletLocal();
    assert(loaded !== null, 'loadWalletLocal returned null');
    assert(loaded.walletId === wallet.walletId, 'walletId mismatch');
    assert(loaded.address === wallet.address, 'address mismatch');
    assert(loaded.shardA === wallet.shardA, 'shardA mismatch');
    assert(loaded.shardAIsEncrypted === true, 'shardAIsEncrypted mismatch');
    assert(loaded.publicKey === wallet.publicKey, 'publicKey mismatch');
    assert(loaded.createdAt, 'missing createdAt');

    // Delete
    sdk.deleteWalletLocal(wallet.walletId);
    const afterDelete = sdk.loadWalletLocal();
    assert(afterDelete === null, 'wallet should be null after delete');

    ok('save/load/deleteWalletLocal', 'full round-trip');
  } catch (e) { fail('save/load/deleteWalletLocal', e.message); }

  // ── 20. Shard A local storage ──────────────────────────────────
  try {
    if (!wallet) throw new Error('no wallet');

    sdk.saveShardALocal(wallet.walletId, wallet.shardA);
    const loaded = sdk.loadShardALocal(wallet.walletId);
    assert(loaded === wallet.shardA, 'shardA mismatch after load');

    sdk.deleteShardALocal(wallet.walletId);
    const afterDel = sdk.loadShardALocal(wallet.walletId);
    assert(afterDel === null, 'shardA should be null after delete');

    ok('save/load/deleteShardALocal', 'full round-trip');
  } catch (e) { fail('save/load/deleteShardALocal', e.message); }

  // ── 21-22. Static Utilities ────────────────────────────────────
  console.log('\n─── Static Utilities ───');
  try {
    assert(BlackBookWalletSDK.toLamports(1) === 100_000, 'toLamports(1)');
    assert(BlackBookWalletSDK.toLamports(0.5) === 50_000, 'toLamports(0.5)');
    assert(BlackBookWalletSDK.toBB(100_000) === 1, 'toBB(1e5)');
    assert(BlackBookWalletSDK.toBB(0) === 0, 'toBB(0)');
    ok('toLamports / toBB', 'round-trip correct');
  } catch (e) { fail('toLamports / toBB', e.message); }

  try {
    const formatted = BlackBookWalletSDK.formatBB(2500000000, 2);
    assert(typeof formatted === 'string', 'formatBB not string');
    assert(formatted.includes('25,000') || formatted.includes('25000'), `unexpected: ${formatted}`);

    const short = BlackBookWalletSDK.shortAddr('8CZJAZnbm85qywRfAw1tXRnAvACPciuYvK36A4BS3hCm');
    assert(short.includes('…'), 'no ellipsis in shortAddr');
    assert(short.startsWith('8CZJAZ'), 'wrong prefix');

    ok('formatBB / shortAddr', `"${formatted}", "${short}"`);    
  } catch (e) { fail('formatBB / shortAddr', e.message); }

  // ── 23. SSS_COMBOS ────────────────────────────────────────────
  try {
    assert(SSS_COMBOS.AB, 'missing AB combo');
    assert(SSS_COMBOS.AC, 'missing AC combo');
    assert(SSS_COMBOS.BC, 'missing BC combo');
    assert(SSS_COMBOS.AB.shards[0] === 'A', 'AB shard 0');
    assert(SSS_COMBOS.AB.shards[1] === 'B', 'AB shard 1');
    assert(SSS_COMBOS.AC.desc === 'User + Cold', 'AC desc');
    ok('SSS_COMBOS', 'AB, AC, BC all valid');
  } catch (e) { fail('SSS_COMBOS', e.message); }

  // ── 24. setJWT ─────────────────────────────────────────────────
  try {
    assert(sdk.jwt === null, 'jwt should start null');
    sdk.setJWT('my-test-token');
    assert(sdk.jwt === 'my-test-token', 'jwt not set');
    sdk.setJWT(null);
    assert(sdk.jwt === null, 'jwt not cleared');
    ok('setJWT()', 'set and clear');
  } catch (e) { fail('setJWT()', e.message); }

  // ── 25. Timeout ────────────────────────────────────────────────
  console.log('\n─── Error Handling ───');
  try {
    const slowSdk = new BlackBookWalletSDK('http://10.255.255.1:9999', null, { timeout: 500 });
    await slowSdk.getBalance('test');
    fail('Timeout', 'should have thrown');
  } catch (e) {
    ok('Timeout handling', `correctly threw: "${e.message.slice(0, 60)}"`);
  }

  // ── Invalid combo ──────────────────────────────────────────────
  try {
    await sdk.verifySssCombo({ combo: 'XY', walletId: 'test' });
    fail('Invalid combo', 'should have thrown');
  } catch (e) {
    assert(e.message.includes('Invalid combo'), `wrong error: ${e.message}`);
    ok('Invalid combo', `correctly threw: "${e.message}"`);
  }

  // ── Faucet bounds ──────────────────────────────────────────────
  try {
    await sdk.faucet('some_addr', -5);
    fail('Faucet negative', 'should have thrown');
  } catch (e) {
    assert(e.message.includes('positive'), `wrong error: ${e.message}`);
    ok('Faucet negative guard', `correctly threw: "${e.message}"`);
  }

  // ── Exports ────────────────────────────────────────────────────
  console.log('\n─── Exports ───');
  try {
    assert(typeof BlackBookWalletSDK === 'function', 'BlackBookWalletSDK not a function');
    assert(LAMPORTS_PER_BB === 100_000, 'LAMPORTS wrong');
    assert(CHAIN_ID === 0xBB, 'CHAIN_ID wrong');
    assert(MAX_FAUCET_BB === 99_999, 'MAX_FAUCET_BB wrong');
    ok('Module exports', 'BlackBookWalletSDK, LAMPORTS_PER_BB, CHAIN_ID, MAX_FAUCET_BB, SSS_COMBOS');
  } catch (e) { fail('Module exports', e.message); }

  // ── Summary ────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log(`  WALLET SDK RESULTS: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  if (errors.length > 0) {
    console.log('\n  FAILURES:');
    errors.forEach(e => console.log(`    ❌ ${e.name}: ${e.err}`));
  }
  console.log('══════════════════════════════════════════════════════════════\n');

  process.exit(failed > 0 ? 1 : 0);
}

run().catch(e => {
  console.error('FATAL:', e);
  process.exit(2);
});
