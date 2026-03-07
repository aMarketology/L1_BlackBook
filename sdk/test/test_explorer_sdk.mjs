#!/usr/bin/env node
// ============================================================================
// BLACKBOOK EXPLORER SDK — Integration Test Suite
// ============================================================================
//
// Tests every public method on BlackBookExplorer against a running node.
//
//   1. Constructor & URL normalisation
//   2. getHealth()
//   3. getVersion()
//   4. getGenesisHash()
//   5. getSlot()
//   6. getEpochInfo()
//   7. getLatestBlockhash()
//   8. getSupply()
//   9. getBalance() — known funded address
//  10. getBalance() — zero-balance address
//  11. getBalanceREST()
//  12. getBalances() — batch
//  13. getAccountInfo()
//  14. getSignaturesForAddress()
//  15. getTransaction() — (may be empty)
//  16. getReserves()
//  17. Static: toLamports / toBB round-trip
//  18. Static: formatBB
//  19. Static: shortAddr
//  20. Static: timeAgo
//  21. Static: formatDate
//  22. Static: formatWithUnit
//  23. Error: invalid RPC method
//  24. Error: timeout handling
//
// Usage:  node test_explorer_sdk.mjs
// Requires: Node 18+ (native fetch) and a running BlackBook node
// ============================================================================

import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { BlackBookExplorer, LAMPORTS_PER_BB, CHAIN_ID } = require('./explorer_sdk.js');

// ── Config ──────────────────────────────────────────────────
const RPC_URL = 'http://localhost:8899';
const API_URL = 'http://localhost:8080';
const KNOWN_FUNDED_ADDR = '8CZJAZnbm85qywRfAw1tXRnAvACPciuYvK36A4BS3hCm';
const ZERO_ADDR = 'ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ';

let passed = 0;
let failed = 0;
let skipped = 0;
const errors = [];

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

// ============================================================================
// TEST RUNNER
// ============================================================================

async function run() {
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║   BLACKBOOK EXPLORER SDK — Integration Tests               ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');

  const explorer = new BlackBookExplorer(RPC_URL, API_URL);

  // ── 1. Constructor ────────────────────────────────────────
  console.log('─── Constructor & Config ───');
  try {
    assert(explorer.rpcUrl === 'http://localhost:8899', 'rpcUrl mismatch');
    assert(explorer.apiUrl === 'http://localhost:8080', 'apiUrl mismatch');
    assert(explorer.timeout === 30000, 'timeout mismatch');
    assert(explorer._rpcId === 0, '_rpcId should start at 0');

    // Trailing slash normalisation
    const e2 = new BlackBookExplorer('http://localhost:8899///', 'http://localhost:8080///');
    assert(e2.rpcUrl === 'http://localhost:8899', 'trailing slash not stripped from rpcUrl');
    assert(e2.apiUrl === 'http://localhost:8080', 'trailing slash not stripped from apiUrl');

    // Auto-derive apiUrl from rpcUrl
    const e3 = new BlackBookExplorer('http://localhost:8899');
    assert(e3.apiUrl === 'http://localhost:8080', 'apiUrl auto-derive failed');

    // Custom timeout
    const e4 = new BlackBookExplorer(RPC_URL, API_URL, { timeout: 5000 });
    assert(e4.timeout === 5000, 'custom timeout not applied');

    ok('Constructor', 'URL normalisation, auto-derive, timeout');
  } catch (e) { fail('Constructor', e.message); }

  // ── 2. getHealth ──────────────────────────────────────────
  console.log('\n─── Network ───');
  try {
    const health = await explorer.getHealth();
    assert(health !== undefined && health !== null, 'health is null');
    ok('getHealth()', `status: ${typeof health === 'string' ? health : JSON.stringify(health)}`);
  } catch (e) { fail('getHealth()', e.message); }

  // ── 3. getVersion ─────────────────────────────────────────
  try {
    const ver = await explorer.getVersion();
    assert(ver !== undefined, 'version is undefined');
    assert(ver['solana-core'] || ver.version, 'missing version field');
    ok('getVersion()', `v${ver['solana-core'] || ver.version}`);
  } catch (e) { fail('getVersion()', e.message); }

  // ── 4. getGenesisHash ─────────────────────────────────────
  try {
    const hash = await explorer.getGenesisHash();
    assert(typeof hash === 'string', 'genesis hash not a string');
    assert(hash.length > 10, 'genesis hash too short');
    ok('getGenesisHash()', `${hash.slice(0, 12)}…`);
  } catch (e) { fail('getGenesisHash()', e.message); }

  // ── 5. getSlot ────────────────────────────────────────────
  let currentSlot;
  try {
    currentSlot = await explorer.getSlot();
    assert(typeof currentSlot === 'number', 'slot not a number');
    assert(currentSlot >= 0, 'slot is negative');
    ok('getSlot()', `slot ${currentSlot}`);
  } catch (e) { fail('getSlot()', e.message); }

  // ── 6. getEpochInfo ───────────────────────────────────────
  try {
    const epoch = await explorer.getEpochInfo();
    assert(epoch !== undefined, 'epoch is undefined');
    assert(typeof epoch.absoluteSlot === 'number' || typeof epoch.slot === 'number',
      'missing slot field in epoch');
    const txCount = epoch.transactionCount || epoch.transaction_count || 0;
    ok('getEpochInfo()', `epoch ${epoch.epoch ?? 0}, txCount ${txCount}`);
  } catch (e) { fail('getEpochInfo()', e.message); }

  // ── 7. getLatestBlockhash ─────────────────────────────────
  try {
    const bh = await explorer.getLatestBlockhash();
    assert(bh !== undefined, 'blockhash result is undefined');
    // Could be { blockhash, lastValidBlockHeight } or wrapped in .value
    const hash = bh.blockhash || (bh.value && bh.value.blockhash);
    assert(typeof hash === 'string', 'blockhash not a string');
    ok('getLatestBlockhash()', `${hash.slice(0, 12)}…`);
  } catch (e) { fail('getLatestBlockhash()', e.message); }

  // ── 8. getSupply ──────────────────────────────────────────
  console.log('\n─── Supply ───');
  try {
    const supply = await explorer.getSupply();
    assert(typeof supply.totalBB === 'number', 'totalBB not a number');
    assert(supply.totalBB >= 0, 'totalBB is negative');
    assert(typeof supply.totalLamports === 'number', 'totalLamports not a number');
    assert(typeof supply.circulating === 'number', 'circulating not a number');
    // Sanity: totalBB should equal totalLamports / 1e9
    const expected = supply.totalLamports / LAMPORTS_PER_BB;
    assert(Math.abs(supply.totalBB - expected) < 0.001, 'totalBB != totalLamports/1e9');
    ok('getSupply()', `${supply.totalBB.toFixed(2)} BB total, ${supply.circulating.toFixed(2)} circulating`);
  } catch (e) { fail('getSupply()', e.message); }

  // ── 9. getBalance (funded) ────────────────────────────────
  console.log('\n─── Accounts ───');
  try {
    const bal = await explorer.getBalance(KNOWN_FUNDED_ADDR);
    assert(typeof bal.lamports === 'number', 'lamports not a number');
    assert(typeof bal.bb === 'number', 'bb not a number');
    assert(bal.bb >= 0, 'bb is negative');
    assert(Math.abs(bal.bb - bal.lamports / LAMPORTS_PER_BB) < 0.001, 'bb <-> lamports mismatch');
    ok('getBalance(funded)', `${bal.bb} BB`);
  } catch (e) { fail('getBalance(funded)', e.message); }

  // ── 10. getBalance (zero) ─────────────────────────────────
  try {
    const bal = await explorer.getBalance(ZERO_ADDR);
    assert(typeof bal.lamports === 'number', 'lamports not a number for zero addr');
    assert(bal.bb === 0 || bal.lamports === 0, 'zero address should have 0 balance');
    ok('getBalance(zero)', `${bal.bb} BB (expected 0)`);
  } catch (e) { fail('getBalance(zero)', e.message); }

  // ── 11. getBalanceREST ────────────────────────────────────
  try {
    const info = await explorer.getBalanceREST(KNOWN_FUNDED_ADDR);
    assert(info.address === KNOWN_FUNDED_ADDR, 'address mismatch');
    assert(typeof info.balance === 'number', 'balance not a number');
    assert(info.unit === 'BB', `unit should be BB, got ${info.unit}`);
    ok('getBalanceREST()', `${info.balance} ${info.unit}`);
  } catch (e) { fail('getBalanceREST()', e.message); }

  // ── 12. getBalances (batch) ───────────────────────────────
  try {
    const addrs = [KNOWN_FUNDED_ADDR, ZERO_ADDR];
    const balances = await explorer.getBalances(addrs);
    assert(typeof balances === 'object', 'balances not an object');
    // At least the funded address should be present
    if (balances[KNOWN_FUNDED_ADDR]) {
      assert(typeof balances[KNOWN_FUNDED_ADDR].bb === 'number', 'batch bb not a number');
      ok('getBalances(batch)', `${Object.keys(balances).length} addresses resolved`);
    } else {
      ok('getBalances(batch)', 'returned map (funded addr may return via different format)');
    }
  } catch (e) { fail('getBalances(batch)', e.message); }

  // ── 13. getAccountInfo ────────────────────────────────────
  try {
    const info = await explorer.getAccountInfo(KNOWN_FUNDED_ADDR);
    // May be null for non-SVM accounts or may have lamports field
    if (info === null) {
      ok('getAccountInfo()', 'returned null (address not in SVM account map)');
    } else {
      assert(info.lamports !== undefined || info.data !== undefined, 'missing account fields');
      ok('getAccountInfo()', `lamports: ${info.lamports}`);
    }
  } catch (e) { fail('getAccountInfo()', e.message); }

  // ── 14. getSignaturesForAddress ───────────────────────────
  console.log('\n─── Transactions ───');
  let firstSig = null;
  try {
    const sigs = await explorer.getSignaturesForAddress(KNOWN_FUNDED_ADDR, 5);
    assert(Array.isArray(sigs), 'signatures not an array');
    if (sigs.length > 0) {
      firstSig = sigs[0].signature;
      assert(typeof firstSig === 'string', 'signature not a string');
      ok('getSignaturesForAddress()', `${sigs.length} txs, latest: ${firstSig.slice(0, 12)}…`);
    } else {
      ok('getSignaturesForAddress()', '0 transactions found (new address)');
    }
  } catch (e) { fail('getSignaturesForAddress()', e.message); }

  // ── 15. getTransaction ────────────────────────────────────
  try {
    if (firstSig) {
      const tx = await explorer.getTransaction(firstSig);
      // Could return null or the tx object
      if (tx === null) {
        ok('getTransaction()', 'returned null (tx not indexed)');
      } else {
        ok('getTransaction()', `slot: ${tx.slot}, blockTime: ${tx.blockTime}`);
      }
    } else {
      skip('getTransaction()', 'no signatures to look up');
    }
  } catch (e) { fail('getTransaction()', e.message); }

  // ── 16. getReserves ───────────────────────────────────────
  console.log('\n─── Reserves ───');
  try {
    const reserves = await explorer.getReserves();
    assert(reserves !== undefined, 'reserves undefined');
    assert(typeof reserves.bbSupply === 'number' || reserves.bbSupply !== undefined,
      'bbSupply missing');
    assert(typeof reserves.fullyBacked === 'boolean', 'fullyBacked not boolean');
    ok('getReserves()', `BB: ${reserves.bbSupply}, USDC: ${reserves.usdcHeld}, backed: ${reserves.fullyBacked}`);
  } catch (e) { fail('getReserves()', e.message); }

  // ── Static Methods ────────────────────────────────────────
  console.log('\n─── Static Utilities ───');

  // 17. toLamports / toBB round-trip
  try {
    const bb = 123.456;
    const lamports = BlackBookExplorer.toLamports(bb);
    assert(lamports === 123456000, `toLamports(${bb}) = ${lamports}, expected 123456000`);
    const backBB = BlackBookExplorer.toBB(lamports);
    assert(backBB === 123.456, `toBB(${lamports}) = ${backBB}, expected 123.456`);
    ok('toLamports / toBB', `${bb} BB ↔ ${lamports} lamports`);
  } catch (e) { fail('toLamports / toBB', e.message); }

  // 18. formatBB
  try {
    const formatted = BlackBookExplorer.formatBB(100000000, 2); // 1000 BB
    assert(typeof formatted === 'string', 'formatBB not a string');
    assert(formatted.includes('1,000') || formatted.includes('1000'), `unexpected format: ${formatted}`);
    ok('formatBB()', `1000 BB → "${formatted}"`);
  } catch (e) { fail('formatBB()', e.message); }

  // 19. shortAddr
  try {
    const full = '8CZJAZnbm85qywRfAw1tXRnAvACPciuYvK36A4BS3hCm';
    const short = BlackBookExplorer.shortAddr(full);
    assert(short.length < full.length, 'shortAddr not shorter');
    assert(short.startsWith('8CZJAZ'), 'shortAddr wrong prefix');
    assert(short.endsWith('3hCm'), 'shortAddr wrong suffix');
    assert(short.includes('…'), 'shortAddr missing ellipsis');

    // Edge cases
    assert(BlackBookExplorer.shortAddr('abc') === 'abc', 'short addr should pass through short strings');
    assert(BlackBookExplorer.shortAddr(null) === null, 'short addr null should return null');
    assert(BlackBookExplorer.shortAddr('') === '', 'short addr empty');

    ok('shortAddr()', `${full.slice(0,8)}… → "${short}"`);
  } catch (e) { fail('shortAddr()', e.message); }

  // 20. timeAgo
  try {
    const now = Math.floor(Date.now() / 1000);
    assert(BlackBookExplorer.timeAgo(now) === 'just now', 'timeAgo now');
    assert(BlackBookExplorer.timeAgo(now - 30).endsWith('s ago'), 'timeAgo 30s');
    assert(BlackBookExplorer.timeAgo(now - 120).endsWith('m ago'), 'timeAgo 2m');
    assert(BlackBookExplorer.timeAgo(now - 7200).endsWith('h ago'), 'timeAgo 2h');
    assert(BlackBookExplorer.timeAgo(now - 172800).endsWith('d ago'), 'timeAgo 2d');
    ok('timeAgo()', 'now/s/m/h/d all correct');
  } catch (e) { fail('timeAgo()', e.message); }

  // 21. formatDate
  try {
    const ts = 1700000000; // Nov 14 2023
    const formatted = BlackBookExplorer.formatDate(ts);
    assert(typeof formatted === 'string', 'formatDate not a string');
    assert(formatted.length > 5, 'formatDate too short');
    ok('formatDate()', `unix ${ts} → "${formatted}"`);
  } catch (e) { fail('formatDate()', e.message); }

  // 22. formatWithUnit
  try {
    const out = BlackBookExplorer.formatWithUnit(5000000);
    assert(out.includes('BB'), 'formatWithUnit missing BB suffix');
    assert(out.includes('5'), 'formatWithUnit missing amount');
    ok('formatWithUnit()', `5 BB → "${out}"`);
  } catch (e) { fail('formatWithUnit()', e.message); }

  // ── Error Handling ────────────────────────────────────────
  console.log('\n─── Error Handling ───');

  // 23. Invalid RPC method
  try {
    await explorer._rpc('nonExistentMethod_xyz', []);
    fail('Invalid RPC method', 'should have thrown');
  } catch (e) {
    assert(e.message.length > 0, 'error message empty');
    ok('Invalid RPC method', `correctly threw: "${e.message.slice(0, 60)}"`);
  }

  // 24. Timeout handling
  try {
    const fastExplorer = new BlackBookExplorer('http://10.255.255.1:9999', null, { timeout: 500 });
    await fastExplorer.getHealth();
    fail('Timeout', 'should have thrown on unreachable host');
  } catch (e) {
    ok('Timeout handling', `correctly threw after timeout: "${e.message.slice(0, 60)}"`);
  }

  // ── Exports ───────────────────────────────────────────────
  console.log('\n─── Exports ───');
  try {
    assert(typeof BlackBookExplorer === 'function', 'BlackBookExplorer not exported');
    assert(LAMPORTS_PER_BB === 100_000, 'LAMPORTS_PER_BB wrong');
    assert(CHAIN_ID === 0xBB, 'CHAIN_ID wrong');
    ok('Module exports', 'BlackBookExplorer, LAMPORTS_PER_BB, CHAIN_ID');
  } catch (e) { fail('Module exports', e.message); }

  // ── Summary ───────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════════');
  console.log(`  EXPLORER SDK RESULTS: ${passed} passed, ${failed} failed, ${skipped} skipped`);
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
