// ─────────────────────────────────────────────────────────────────────────────
// L2 Sequencer end-to-end smoke test (LOCAL ONLY).
//
//   L1   : http://localhost:8080   (cargo run --features unsafe_admin)
//   L2   : http://localhost:7072   (npm run dev in sequencer/l2)
//
// Flow: mint BB -> lock_bb -> register-lock -> bet -> resolve (seal+submit_root)
//       -> fetch Merkle proof -> exit BB to L1 -> assert L1 balances.
//
// Two users, zero-sum market:
//   userA bets 50 BB YES, userB bets 50 BB NO, outcome = YES.
//   => L2: A = 150 BB, B = 50 BB.  Exit both, vault drains 200 BB.
// ─────────────────────────────────────────────────────────────────────────────
import { ed25519 as ed } from '@noble/curves/ed25519';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

const L1 = process.env.L1_URL ?? 'http://localhost:8080';
const L2 = process.env.L2_URL ?? 'http://localhost:7072';
const LAMPORTS_PER_BB = 100_000;

// ── base58 (Bitcoin/Solana alphabet) ────────────────────────────────────────
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58encode(bytes) {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += B58[digits[i]];
  return out;
}

// ── helpers ───────────────────────────────────────────────────────────────────
const now = () => Math.floor(Date.now() / 1000);
const nonce = () => bytesToHex(randomBytes(8));
const enc = (s) => new TextEncoder().encode(s);

function makeUser(label) {
  const priv = randomBytes(32);
  const pub = ed.getPublicKey(priv);
  return { label, priv, pubHex: bytesToHex(pub), address: base58encode(pub) };
}
function sign(msg, priv) { return bytesToHex(ed.sign(enc(msg), priv)); }

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`POST ${url} -> ${r.status}: ${JSON.stringify(j)}`);
  return j;
}
async function get(url) {
  const r = await fetch(url);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`GET ${url} -> ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

function assert(cond, msg) {
  if (!cond) { console.error(`\n❌ ASSERT FAILED: ${msg}`); process.exit(1); }
  console.log(`   ✓ ${msg}`);
}

// ── L1 / L2 operations ─────────────────────────────────────────────────────────
async function mint(user, bb) {
  // Use the public /faucet endpoint — no unsafe_admin needed on production.
  // Faucet is capped at MAX_FAUCET_BB (0.1 BB). L1 clamps amount server-side
  // then builds the canonical message with the clamped value, so we must sign
  // with the same clamped value.
  // Canonical message: "FAUCET:{addr}:{clamped_amount}:{ts}:{nonce}"
  const MAX_FAUCET_BB = 0.1;
  const clamped = Math.min(bb, MAX_FAUCET_BB);
  const ts = now(), n = nonce();
  const msg = `FAUCET:${user.address}:${clamped}:${ts}:${n}`;
  return post(`${L1}/faucet`, {
    wallet_address: user.address,
    amount: clamped,
    public_key: user.pubHex,
    signature: sign(msg, user.priv),
    timestamp: ts,
    nonce: n,
  });
}

async function lockBb(user, lamports) {
  const ts = now(), n = nonce();
  const msg = `ROLLUP_LOCK_BB:L2:${user.address}:${lamports}::${ts}:${n}`;
  const res = await post(`${L1}/rollup/L2/lock_bb`, {
    wallet_address: user.address,
    bb_lamports: lamports,
    public_key: user.pubHex,
    signature: sign(msg, user.priv),
    timestamp: ts,
    nonce: n,
  });
  return res.lock_id;
}

async function placeBet(user, marketId, side, lamports) {
  const ts = now(), n = nonce();
  const msg = `L2_BET:${marketId}:${user.address}:${side}:${lamports}:${ts}:${n}`;
  return post(`${L2}/markets/${marketId}/bet`, {
    wallet_address: user.address,
    side,
    amount_lamports: lamports,
    public_key: user.pubHex,
    signature: sign(msg, user.priv),
    timestamp: ts,
    nonce: n,
  });
}

async function exitBb(user) {
  const proof = await get(`${L2}/proof/${user.address}`);
  const ts = now(), n = nonce();
  const batchId = proof.batch_id;
  const msg = `ROLLUP_EXIT:L2:BB:${user.address}:${batchId}:${ts}:${n}`;
  const res = await post(`${L1}/rollup/L2/exit`, {
    address: user.address,
    asset_type: 'BB',
    balance_lamports: Number(proof.balance_lamports),
    batch_id: batchId,
    proof_siblings: proof.proof_siblings,
    sibling_is_right: proof.sibling_is_right,
    public_key: user.pubHex,
    signature: sign(msg, user.priv),
    timestamp: ts,
    nonce: n,
  });
  return { res, proof };
}

const l1Bb = async (addr) => (await get(`${L1}/balance/${addr}`)).balance;
const l2Lamports = async (addr) => BigInt((await get(`${L2}/balances/${addr}`)).bb_lamports);

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log('═══ L2 SEQUENCER SMOKE TEST ═══\n');

  const A = makeUser('A');
  const B = makeUser('B');
  console.log(`userA ${A.address}`);
  console.log(`userB ${B.address}\n`);

  // Scale to faucet cap: 0.1 BB per user = 10_000 lamports each.
  // Zero-sum market: A bets 5_000 lamports YES, B bets 5_000 lamports NO.
  // Outcome YES => A wins the pot => A = 10_000 lamports, B = 5_000 lamports.
  const FULL  = 0.1 * LAMPORTS_PER_BB;   // 10_000 lamports  (0.1 BB)
  const HALF  = 0.05 * LAMPORTS_PER_BB;  //  5_000 lamports  (0.05 BB)
  const HUNDRED = FULL;
  const FIFTY   = HALF;

  console.log('① Mint 0.1 BB to each user on L1 (faucet cap)');
  await mint(A, 0.1);
  await mint(B, 0.1);
  // Faucet returns 0.1 BB — balance may show as a small float; check > 0
  const balA = await l1Bb(A.address);
  const balB = await l1Bb(B.address);
  assert(balA > 0, `L1 userA balance > 0 (got ${balA})`);
  assert(balB > 0, `L1 userB balance > 0 (got ${balB})`);
  console.log(`   A=${balA} BB, B=${balB} BB`);

  console.log('\n② Lock 0.1 BB each into the L2 vault (lock_bb)');
  const lockA = await lockBb(A, FULL);
  const lockB = await lockBb(B, FULL);
  console.log(`   lockA=${lockA}`);
  console.log(`   lockB=${lockB}`);
  assert((await l1Bb(A.address)) === 0, 'L1 userA balance = 0 after lock');
  assert((await l1Bb(B.address)) === 0, 'L1 userB balance = 0 after lock');

  console.log('\n③ Register locks on L2 (verify -> consume -> credit)');
  await post(`${L2}/register-lock`, { lock_id: lockA });
  await post(`${L2}/register-lock`, { lock_id: lockB });
  assert((await l2Lamports(A.address)) === BigInt(FULL), 'L2 userA = 10_000 lamports');
  assert((await l2Lamports(B.address)) === BigInt(FULL), 'L2 userB = 10_000 lamports');

  console.log('\n④ Create market + place bets');
  const marketId = `m_${nonce()}`;
  await post(`${L2}/markets`, { market_id: marketId, question: 'Smoke test: YES or NO?' });
  await placeBet(A, marketId, 'YES', HALF);
  await placeBet(B, marketId, 'NO', HALF);
  assert((await l2Lamports(A.address)) === BigInt(FULL - HALF), 'L2 userA = 5_000 after bet');
  assert((await l2Lamports(B.address)) === BigInt(FULL - HALF), 'L2 userB = 5_000 after bet');

  console.log('\n⑤ Resolve YES (seals batch + submits root to L1)');
  const resolve = await post(`${L2}/markets/${marketId}/resolve`, { outcome: 'YES' });
  console.log(`   batch=${JSON.stringify(resolve.batch)}`);
  assert(resolve.batch && resolve.batch.batchId >= 1, 'batch sealed + root submitted');
  // A wins pot: A = 5_000 (unbet) + 5_000 (bet returned) + 5_000 (B's pot) = 15_000; B keeps unbet 5_000
  assert((await l2Lamports(A.address)) === BigInt(15000), 'L2 userA = 15_000 (winner takes pot)');
  assert((await l2Lamports(B.address)) === BigInt(HALF), 'L2 userB = 5_000 (loser keeps unbet half)');

  console.log('\n⑥ Exit userA (0.15 BB) to L1 with Merkle proof');
  const exA = await exitBb(A);
  console.log(`   proof depth=${exA.proof.proof_siblings.length} root=${exA.proof.merkle_root.slice(0, 16)}…`);
  assert(exA.res.success === true, 'userA exit accepted');
  const exitBalA = await l1Bb(A.address);
  assert(exitBalA > 0.14, `L1 userA balance > 0.14 BB after exit (got ${exitBalA})`);
  console.log(`   L1 userA = ${exitBalA} BB`);

  console.log('\n⑦ Exit userB (0.05 BB) to L1 with Merkle proof');
  const exB = await exitBb(B);
  assert(exB.res.success === true, 'userB exit accepted');
  const exitBalB = await l1Bb(B.address);
  assert(exitBalB > 0.04, `L1 userB balance > 0.04 BB after exit (got ${exitBalB})`);
  console.log(`   L1 userB = ${exitBalB} BB`);

  console.log('\n⑧ Double-spend guard: re-exit userA must be rejected');
  let rejected = false;
  try { await exitBb(A); } catch (e) { rejected = true; console.log(`   (rejected: ${e.message.slice(0, 80)}…)`); }
  assert(rejected, 'second userA exit rejected (double-spend seal)');

  console.log('\n═══ ✅ SMOKE TEST PASSED ═══');
}

main().catch((e) => { console.error('\n💥', e); process.exit(1); });
