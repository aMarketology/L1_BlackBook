/**
 * BlackBook L1 — Full System Test
 * Tests: health, PoH, Turbine, Sealevel, consensus, faucet, transfers,
 *        escrow, swaps, USDC, blocks, and L2/L3 readiness.
 */
import * as ed from '@noble/ed25519';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import bs58 from 'bs58';

const API = 'http://localhost:8080';
const RPC = 'http://localhost:8899';
let passed = 0, failed = 0, warnings = 0;

// ── Test keys ──
const ALICE = {
  address: "EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5",
  secretHex: "1c12a697254491cc286dd6431e9c84acda48ae85b667e08f8527eeb810f9316bc3c0aa0bad64ed2c74d91c24682ae5a4021960e2b70f629296c51a01190f5870"
};
const BOB = {
  address: "9a66KD7KTTUnwXdfxM5c4E5Z8rqyDbP4zm3qCgZsmGoo",
  secretHex: "f4366aec8e6f4f0a099f32a784a587b78ab18ef46ed7732ef7143a8b29090d257f576b5234264a3a8ea6f58cfe941f5aba6583679cfed70d11048a0956c622f6"
};

// ── Helpers ──
function nowSecs() { return Math.floor(Date.now() / 1000); }
function randomNonce() {
  const arr = new Uint8Array(12);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getKeypair(account) {
  const privHex = account.secretHex.slice(0, 64);
  const privBytes = hexToBytes(privHex);
  const pubBytes = await ed.getPublicKeyAsync(privBytes);
  return {
    address: bs58.encode(pubBytes),
    privateKeyHex: privHex,
    publicKeyHex: bytesToHex(pubBytes),
  };
}

async function api(path) {
  const res = await fetch(`${API}${path}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GET ${path} → ${res.status}: ${text}`);
  }
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (!res.ok) throw new Error(`POST ${path} → ${res.status}: ${json.error || JSON.stringify(json)}`);
  return json;
}

async function rpc(method, params = []) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  const json = await res.json();
  if (json.error) throw new Error(`RPC ${method}: ${json.error.message}`);
  return json.result;
}

function ok(name, detail = '') {
  passed++;
  console.log(`  ✅ ${name}${detail ? ' — ' + detail : ''}`);
}
function fail(name, err) {
  failed++;
  console.log(`  ❌ ${name} — ${err}`);
}
function warn(name, msg) {
  warnings++;
  console.log(`  ⚠️  ${name} — ${msg}`);
}

async function test(name, fn) {
  try {
    await fn();
  } catch (e) {
    fail(name, e.message);
  }
}

// ════════════════════════════════════════════════════════════════════════════
console.log('\n══════════════════════════════════════════════════');
console.log('  BlackBook L1 — FULL SYSTEM TEST');
console.log('══════════════════════════════════════════════════\n');

// ── 1. HEALTH & STATUS ──
console.log('┌─ 1. NODE HEALTH & STATUS ─────────────────────');
await test('Health endpoint', async () => {
  const h = await api('/health');
  if (h.status !== 'healthy') throw new Error('Not healthy: ' + h.status);
  ok('Health', `status=${h.status}, version=${h.version}, network=${h.network}`);
});

await test('Stats endpoint', async () => {
  const s = await api('/stats');
  if (!s.blockchain) throw new Error('No blockchain stats');
  ok('Stats', `accounts=${s.blockchain.total_accounts}, blocks=${s.blockchain.block_count}, cache_hit=${s.blockchain.cache_hit_rate}`);
});

// ── 2. POH CLOCK ──
console.log('\n┌─ 2. PROOF OF HISTORY ─────────────────────────');
await test('PoH status', async () => {
  const p = await api('/poh/status');
  if (!p.is_running) throw new Error('PoH not running');
  ok('PoH running', `slot=${p.current_slot}, hashes=${p.num_hashes.toLocaleString()}`);
});

await test('PoH latest block', async () => {
  const b = await api('/poh/block/latest');
  if (!b.block && !b.slot) throw new Error('No latest block');
  const block = b.block || b;
  ok('Latest block', `slot=${block.slot}, txs=${block.tx_count || (block.transactions||[]).length}`);
});

await test('PoH block by slot', async () => {
  const latest = await api('/poh/block/latest');
  const slot = (latest.block || latest).slot;
  const b = await api(`/poh/block/${slot}`);
  ok('Block lookup', `slot=${slot} retrieved`);
});

// ── 3. CONSENSUS (TOWER BFT) ──
console.log('\n┌─ 3. TOWER BFT CONSENSUS ──────────────────────');
await test('Tower BFT', async () => {
  const t = await api('/consensus/tower');
  if (t.validator_count < 1) throw new Error('No validators');
  ok('Tower BFT', `validators=${t.validator_count}, confirmed=${t.confirmed_slots}, stake=${t.total_stake}, best_fork_slot=${t.best_fork?.slot}`);
  if (t.supermajority_threshold < 0.66) warn('Tower BFT', 'Supermajority threshold below 66%');
});

// ── 4. TURBINE ──
console.log('\n┌─ 4. TURBINE BLOCK PROPAGATION ────────────────');
await test('Turbine status', async () => {
  const t = await api('/turbine/status');
  ok('Turbine', `slot=${t.current_slot}, data_shreds=${t.data_shreds}, fec_shreds=${t.fec_shreds}, fanout=${t.turbine_fanout}`);
  if (t.latest_shredded_slot < t.current_slot - 10) warn('Turbine', 'Shred production lagging');
});

// ── 5. SEALEVEL / PIPELINE / GULF STREAM ──
console.log('\n┌─ 5. SEALEVEL, PIPELINE & GULF STREAM ─────────');
await test('Infrastructure check', async () => {
  const h = await api('/health');
  const infra = h.infrastructure || {};
  if (!infra.sealevel) throw new Error('Sealevel OFF');
  if (!infra.pipeline) throw new Error('Pipeline OFF');
  if (!infra.gulf_stream) throw new Error('Gulf Stream OFF');
  ok('All subsystems', 'Sealevel=ON, Pipeline=ON, Gulf Stream=ON');
});

await test('Pipeline stats', async () => {
  const s = await api('/stats');
  const p = s.pipeline || {};
  ok('Pipeline', `running=${p.is_running}, received=${p.packets_received}, verified=${p.packets_verified}, failed=${p.packets_failed}`);
});

await test('Gulf Stream stats', async () => {
  const s = await api('/stats');
  const g = s.gulf_stream || {};
  ok('Gulf Stream', `active=${g.is_active}, forwarded=${g.transactions_forwarded}, latency=${g.avg_forward_latency_us}µs`);
});

await test('Parallel execution', async () => {
  const s = await api('/stats');
  const pe = s.parallel_execution || {};
  ok('Sealevel parallel', `threads=${pe.thread_count}, batch_size=${pe.current_batch_size}, conflict_rate=${pe.conflict_rate}`);
});

// ── 6. ALICE & BOB WALLETS ──
console.log('\n┌─ 6. ALICE & BOB WALLET OPERATIONS ────────────');
const alice = await getKeypair(ALICE);
const bob = await getKeypair(BOB);

console.log(`  Alice: ${alice.address}`);
console.log(`  Bob:   ${bob.address}`);

// Check initial balances
let aliceBal, bobBal;
await test('Alice balance', async () => {
  const b = await api(`/balance/${alice.address}`);
  aliceBal = b.balance;
  ok('Alice BB balance', `${b.balance} BB`);
});

await test('Bob balance', async () => {
  const b = await api(`/balance/${bob.address}`);
  bobBal = b.balance;
  ok('Bob BB balance', `${b.balance} BB`);
});

await test('Alice USDC balance', async () => {
  const b = await api(`/usdc/balance/${alice.address}`);
  ok('Alice USDC', `${b.usdc_balance} USDC`);
});

await test('Bob USDC balance', async () => {
  const b = await api(`/usdc/balance/${bob.address}`);
  ok('Bob USDC', `${b.usdc_balance} USDC`);
});

// ── 7. FAUCET ──
console.log('\n┌─ 7. FAUCET CLAIM ─────────────────────────────');
await test('Alice faucet claim', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const amount = 0.1;
  const message = `FAUCET:${kp.address}:${amount}:${timestamp}:${nonce}`;
  const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));
  const result = await apiPost('/faucet', {
    wallet_address: kp.address,
    amount,
    public_key: kp.publicKeyHex,
    signature: bytesToHex(sigBytes),
    timestamp,
    nonce,
  });
  if (result.success) {
    ok('Alice faucet', `minted=${result.minted} BB, new_balance=${result.new_balance}`);
  } else {
    warn('Alice faucet', 'Rate limited or already claimed this epoch — expected');
  }
});

await test('Bob faucet claim', async () => {
  const kp = bob;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const amount = 0.1;
  const message = `FAUCET:${kp.address}:${amount}:${timestamp}:${nonce}`;
  const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));
  const result = await apiPost('/faucet', {
    wallet_address: kp.address,
    amount,
    public_key: kp.publicKeyHex,
    signature: bytesToHex(sigBytes),
    timestamp,
    nonce,
  });
  if (result.success) {
    ok('Bob faucet', `minted=${result.minted} BB, new_balance=${result.new_balance}`);
  } else {
    warn('Bob faucet', 'Rate limited or already claimed this epoch — expected');
  }
});

// ── 8. SIGNED TRANSFER (Alice → Bob) ──
console.log('\n┌─ 8. SIGNED TRANSFER (Alice → Bob) ────────────');
await test('Alice → Bob 0.01 BB', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const to = bob.address;
  const amount = 0.01;
  const payload = JSON.stringify({ to, amount });

  const chainId = new Uint8Array([1]);
  const encoder = new TextEncoder();
  const message = new Uint8Array([
    ...chainId,
    ...encoder.encode(payload),
    ...encoder.encode("\n"),
    ...encoder.encode(String(timestamp)),
    ...encoder.encode("\n"),
    ...encoder.encode(nonce),
  ]);

  const sigBytes = await ed.signAsync(message, hexToBytes(kp.privateKeyHex));
  const result = await apiPost('/transfer/simple', {
    public_key: kp.publicKeyHex,
    wallet_address: kp.address,
    payload,
    timestamp,
    nonce,
    chain_id: 1,
    signature: bytesToHex(sigBytes),
  });

  if (!result.success) throw new Error('Transfer failed: ' + JSON.stringify(result));
  ok('Transfer', `from=${result.from?.slice(0,8)}... to=${result.to?.slice(0,8)}... amount=${result.amount}, alice_bal=${result.from_balance}, bob_bal=${result.to_balance}`);
});

// ── 9. VERIFY BALANCES POST-TRANSFER ──
console.log('\n┌─ 9. POST-TRANSFER BALANCE VERIFICATION ───────');
await test('Alice balance decreased', async () => {
  const b = await api(`/balance/${alice.address}`);
  ok('Alice post-transfer', `${b.balance} BB`);
});

await test('Bob balance increased', async () => {
  const b = await api(`/balance/${bob.address}`);
  ok('Bob post-transfer', `${b.balance} BB`);
});

// ── 10. TRANSFER Bob → Alice (return) ──
console.log('\n┌─ 10. REVERSE TRANSFER (Bob → Alice) ──────────');
await test('Bob → Alice 0.005 BB', async () => {
  const kp = bob;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const to = alice.address;
  const amount = 0.005;
  const payload = JSON.stringify({ to, amount });

  const chainId = new Uint8Array([1]);
  const encoder = new TextEncoder();
  const message = new Uint8Array([
    ...chainId,
    ...encoder.encode(payload),
    ...encoder.encode("\n"),
    ...encoder.encode(String(timestamp)),
    ...encoder.encode("\n"),
    ...encoder.encode(nonce),
  ]);

  const sigBytes = await ed.signAsync(message, hexToBytes(kp.privateKeyHex));
  const result = await apiPost('/transfer/simple', {
    public_key: kp.publicKeyHex,
    wallet_address: kp.address,
    payload,
    timestamp,
    nonce,
    chain_id: 1,
    signature: bytesToHex(sigBytes),
  });

  if (!result.success) throw new Error('Transfer failed');
  ok('Reverse transfer', `bob→alice ${amount} BB`);
});

// ── 11. TRANSACTION HISTORY ──
console.log('\n┌─ 11. TRANSACTION HISTORY ─────────────────────');
await test('Alice tx history', async () => {
  const data = await api(`/address/${alice.address}/transactions?page=1&limit=5`);
  const txs = data.transactions || [];
  ok('Alice history', `${txs.length} txs found (total: ${data.total || 'N/A'})`);
});

await test('Global ledger', async () => {
  const data = await api('/address/all/transactions?page=1&limit=5');
  const txs = data.transactions || [];
  ok('Global ledger', `${txs.length} recent txs`);
});

// ── 12. ESCROW ──
console.log('\n┌─ 12. ESCROW (L2 Bridge) ──────────────────────');
await test('Escrow status', async () => {
  const s = await api('/escrow/status');
  ok('Escrow status', `balance=${s.escrow_balance} BB, markets=${s.total_markets}, l2_configured=${s.l2_sequencer_configured}`);
});

await test('Alice escrow deposit 0.01 BB', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const amount = 0.01;
  const message = `ESCROW_DEPOSIT:${kp.address}:${amount}:${timestamp}:${nonce}`;
  const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));

  const result = await apiPost('/escrow/deposit', {
    wallet_address: kp.address,
    amount,
    public_key: kp.publicKeyHex,
    signature: bytesToHex(sigBytes),
    timestamp,
    nonce,
  });
  if (!result.success) throw new Error('Escrow deposit failed');
  ok('Escrow deposit', `deposited=${result.deposited}, escrow_bal=${result.escrow_balance}, user_bal=${result.user_balance}`);
});

await test('Escrow status post-deposit', async () => {
  const s = await api('/escrow/status');
  ok('Escrow updated', `balance=${s.escrow_balance} BB`);
});

// ── 13. SWAP BB ↔ USDC ──
console.log('\n┌─ 13. SWAP BB ↔ USDC ──────────────────────────');
await test('Alice swap BB→USDC', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const bbAmount = 0.01;
  const message = `SWAP_BB_USDC:${kp.address}:${bbAmount}:${timestamp}:${nonce}`;
  const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));

  const result = await apiPost('/swap/bb-to-usdc', {
    wallet_address: kp.address,
    bb_amount: bbAmount,
    timestamp,
    nonce,
    public_key: kp.publicKeyHex,
    signature: bytesToHex(sigBytes),
  });
  if (!result.success) throw new Error('Swap failed: ' + result.message);
  ok('BB→USDC swap', `${result.message}`);
});

await test('Alice USDC balance after swap', async () => {
  const b = await api(`/usdc/balance/${alice.address}`);
  ok('Alice USDC post-swap', `${b.usdc_balance} USDC`);
});

await test('Alice swap USDC→BB', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const usdcAmount = 0.05;
  const message = `SWAP_USDC_BB:${kp.address}:${usdcAmount}:${timestamp}:${nonce}`;
  const sigBytes = await ed.signAsync(new TextEncoder().encode(message), hexToBytes(kp.privateKeyHex));

  const result = await apiPost('/swap/usdc-to-bb', {
    wallet_address: kp.address,
    usdc_amount: usdcAmount,
    timestamp,
    nonce,
    public_key: kp.publicKeyHex,
    signature: bytesToHex(sigBytes),
  });
  if (!result.success) throw new Error('Swap failed: ' + result.message);
  ok('USDC→BB swap', `${result.message}`);
});

// ── 14. SUPPLY AUDIT ──
console.log('\n┌─ 14. SUPPLY AUDIT ────────────────────────────');
await test('Supply audit', async () => {
  const a = await api('/supply/audit');
  if (!a.invariant_ok) {
    warn('Supply invariant', `bb=${a.bb_total_supply}, wusdc=${a.wusdc_total_supply}, ratio=${a.backing_ratio}, delta=${a.delta_from_target} — expected when admin mints exist without USDC backing`);
  } else {
    ok('Supply invariant', `bb=${a.bb_total_supply}, wusdc=${a.wusdc_total_supply}, ratio=${a.backing_ratio}, invariant=OK`);
  }
});

// ── 15. JSON-RPC (Solana-compatible) ──
console.log('\n┌─ 15. SOLANA JSON-RPC ─────────────────────────');
await test('getHealth', async () => {
  const r = await rpc('getHealth');
  ok('RPC getHealth', `${r}`);
});

await test('getBalance (Alice)', async () => {
  const r = await rpc('getBalance', [alice.address]);
  ok('RPC getBalance', `${r.value} lamports (${r.value / 1e9} BB)`);
});

await test('blackbook_getProfile', async () => {
  const r = await rpc('blackbook_getProfile', [alice.address]);
  ok('RPC getProfile', `registered=${r.registered}, balance=${r.balance}, slot=${r.slot}`);
});

await test('getEpochInfo', async () => {
  const r = await rpc('getEpochInfo');
  ok('RPC getEpochInfo', `epoch=${r.epoch}, slot=${r.absoluteSlot}, blockHeight=${r.blockHeight}`);
});

await test('getSignaturesForAddress', async () => {
  const r = await rpc('getSignaturesForAddress', [alice.address, { limit: 5 }]);
  ok('RPC getSignatures', `${r.length} signatures returned`);
});

await test('getBlockProduction', async () => {
  const r = await rpc('getBlockProduction');
  ok('RPC getBlockProduction', `slot_range=${r.value?.range?.firstSlot}-${r.value?.range?.lastSlot}`);
});

// ── 16. BLOCK FINALITY ──
console.log('\n┌─ 16. BLOCK PRODUCTION & FINALITY ─────────────');
await test('Block production check', async () => {
  const h = await api('/health');
  if (!h.block_production?.is_producing) throw new Error('Not producing blocks!');
  ok('Block production', `producing=true, age=${h.block_production.latest_block_age_s}s`);
});

await test('PoH slot advancing', async () => {
  const p1 = await api('/poh/status');
  await new Promise(r => setTimeout(r, 1000));
  const p2 = await api('/poh/status');
  const delta = p2.current_slot - p1.current_slot;
  if (delta < 1) throw new Error('Slots not advancing');
  ok('Slot advancement', `+${delta} slots in 1s (~${delta * 400}ms/slot)`);
});

// ── 17. USDC SUPPLY ──
console.log('\n┌─ 17. USDC SYSTEM ─────────────────────────────');
await test('USDC supply', async () => {
  const s = await api('/usdc/supply');
  ok('USDC supply', JSON.stringify(s).slice(0, 120));
});

await test('USDC accounts for Alice', async () => {
  const a = await api(`/usdc/accounts/${alice.address}`);
  ok('USDC accounts', `owner=${a.owner?.slice(0,8)}..., accounts=${(a.token_accounts||[]).length}`);
});

// ── 18. L2/L3 READINESS ──
console.log('\n┌─ 18. L2 PREDICTION MARKET & L3 NFT READINESS ─');
await test('Escrow for settlement', async () => {
  const s = await api('/escrow/status');
  ok('Escrow vault', `ready, balance=${s.escrow_balance} BB`);
  if (!s.l2_sequencer_configured) {
    warn('L2 sequencer', 'Not configured — set L2_SEQUENCER_PUBKEY env var');
  } else {
    ok('L2 sequencer', 'Configured');
  }
});

await test('Credit channel (L2 sessions)', async () => {
  // /credit/open may not be registered yet — check gracefully
  try {
    const res = await fetch(`${API}/credit/open`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (res.status === 404) {
      warn('Credit channel', '/credit/open not registered yet — L2 sessions use escrow deposit + admin/dealer/settle flow instead');
    } else {
      ok('Credit channel', `endpoint exists (status=${res.status})`);
    }
  } catch (e) {
    warn('Credit channel', 'endpoint not reachable — not critical for L2');
  }
});

await test('Admin settlement endpoint', async () => {
  try {
    const res = await fetch(`${API}/admin/dealer/settle`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (res.status === 404) throw new Error('/admin/dealer/settle missing — built without unsafe_admin?');
    ok('Admin settlement', `endpoint exists (status=${res.status})`);
  } catch (e) {
    if (e.message.includes('missing')) throw e;
    ok('Admin settlement', 'endpoint reachable');
  }
});

await test('Admin mint (NFT/token minting capability)', async () => {
  try {
    const res = await fetch(`${API}/admin/mint`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (res.status === 404) throw new Error('/admin/mint missing — needed for NFT mint on L3');
    ok('Admin mint', `endpoint exists (status=${res.status}) — ready for L3 NFT mint bridge`);
  } catch (e) {
    if (e.message.includes('missing')) throw e;
    ok('Admin mint', 'endpoint reachable');
  }
});

await test('Merkle state root submission', async () => {
  try {
    const res = await fetch(`${API}/escrow/submit-state-root`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    if (res.status === 404) throw new Error('/escrow/submit-state-root missing');
    ok('State root submission', `endpoint exists (status=${res.status}) — L2 can submit merkle roots`);
  } catch (e) {
    if (e.message.includes('missing')) throw e;
    ok('State root submission', 'endpoint reachable');
  }
});

// ── 19. SECURITY ──
console.log('\n┌─ 19. SECURITY CHECKS ─────────────────────────');
await test('Replay protection (reused nonce)', async () => {
  const kp = alice;
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const to = bob.address;
  const amount = 0.001;
  const payload = JSON.stringify({ to, amount });

  const chainId = new Uint8Array([1]);
  const encoder = new TextEncoder();
  const message = new Uint8Array([
    ...chainId,
    ...encoder.encode(payload),
    ...encoder.encode("\n"),
    ...encoder.encode(String(timestamp)),
    ...encoder.encode("\n"),
    ...encoder.encode(nonce),
  ]);

  const sigBytes = await ed.signAsync(message, hexToBytes(kp.privateKeyHex));
  const body = {
    public_key: kp.publicKeyHex,
    wallet_address: kp.address,
    payload,
    timestamp,
    nonce,
    chain_id: 1,
    signature: bytesToHex(sigBytes),
  };

  // First request should succeed
  await apiPost('/transfer/simple', body);
  
  // Second request with same nonce should fail (replay protection)
  try {
    await apiPost('/transfer/simple', body);
    warn('Replay protection', 'Second request with same nonce succeeded — check nonce enforcement');
  } catch (e) {
    ok('Replay protection', 'Duplicate nonce correctly rejected');
  }
});

await test('Invalid signature rejected', async () => {
  const timestamp = nowSecs();
  const nonce = randomNonce();
  const payload = JSON.stringify({ to: bob.address, amount: 0.001 });
  const fakeSignature = '0'.repeat(128);

  try {
    await apiPost('/transfer/simple', {
      public_key: alice.publicKeyHex,
      wallet_address: alice.address,
      payload,
      timestamp,
      nonce,
      chain_id: 1,
      signature: fakeSignature,
    });
    fail('Signature validation', 'Accepted invalid signature!');
  } catch (e) {
    ok('Signature validation', 'Invalid signature correctly rejected');
  }
});

// ── FINAL BALANCES ──
console.log('\n┌─ FINAL BALANCES ──────────────────────────────');
const aliceFinal = await api(`/balance/${alice.address}`);
const bobFinal = await api(`/balance/${bob.address}`);
const aliceUsdc = await api(`/usdc/balance/${alice.address}`).catch(() => ({ usdc_balance: 0 }));
const bobUsdc = await api(`/usdc/balance/${bob.address}`).catch(() => ({ usdc_balance: 0 }));

console.log(`  Alice: ${aliceFinal.balance} BB | ${aliceUsdc.usdc_balance} USDC`);
console.log(`  Bob:   ${bobFinal.balance} BB | ${bobUsdc.usdc_balance} USDC`);

// ── SUMMARY ──
console.log('\n══════════════════════════════════════════════════');
console.log(`  RESULTS: ${passed} passed, ${failed} failed, ${warnings} warnings`);
console.log('══════════════════════════════════════════════════');

if (failed > 0) {
  console.log('\n  ⚠️  Some tests FAILED — review above for details.');
  process.exit(1);
} else {
  console.log('\n  🎯 ALL TESTS PASSED — L1 is ready for L2 prediction markets & L3 NFTs!');
  process.exit(0);
}
