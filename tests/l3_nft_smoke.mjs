// ─────────────────────────────────────────────────────────────────────────────
// L3 NFT Sequencer — end-to-end smoke test (LOCAL ONLY).
//
//   L1   : http://localhost:8080   (cargo run --features unsafe_admin)
//   L3   : http://localhost:7073   (npm run dev in sequencer/l3, SLOTS_PER_BATCH=1)
//
// Full flow:
//   1. Admin mint 500 BB to Alice on L1
//   2. Alice locks 200 BB into the L3 rollup vault on L1
//   3. Alice mints NFT "smoke-col / 1" on L3 (Ed25519 signed)
//   4. POST /admin/seal on L3 → forced batch seal → Merkle root anchored on L1
//   5. Alice exits the NFT from L3 to L1 with the Merkle proof
//   6. GET /nft/smoke-col/1 on L1 — asserts NFT is anchored with correct owner
// ─────────────────────────────────────────────────────────────────────────────
import { ed25519 as ed } from '@noble/curves/ed25519';
import { bytesToHex, randomBytes } from '@noble/hashes/utils';

const L1 = 'http://localhost:8080';
const L3 = 'http://localhost:7073';
const LAMPORTS_PER_BB = 100_000;

// ── Alice (from test_keys.json) ──────────────────────────────────────────────
const ALICE_SECRET = '1c12a697254491cc286dd6431e9c84acda48ae85b667e08f8527eeb810f9316bc3c0aa0bad64ed2c74d91c24682ae5a4021960e2b70f629296c51a01190f5870';
const ALICE_PRIV   = hexToBytes(ALICE_SECRET.slice(0, 64)); // 32-byte seed
const ALICE_PUB    = ed.getPublicKey(ALICE_PRIV);
const ALICE_PUBHEX = bytesToHex(ALICE_PUB);
// Alice's address is base58(ALICE_PUB) — matches test_keys.json
const ALICE_ADDR   = 'EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5';

// ── NFT fixture ───────────────────────────────────────────────────────────────
const COLLECTION    = 'SMOKE_COL';          // uppercase alphanumeric for L1 symbol_hint
const TOKEN_ID      = '1';               // stored as TEXT in L3 SQLite
const TOKEN_ID_U64  = 1;                 // u64 in L1 ExitRequest
const META_HASH     = 'deadbeef'.repeat(8);          // 64-char fake SHA-256
const META_URI      = 'ipfs://bafkreitest000000000000000000000000000000000';

// ── helpers ───────────────────────────────────────────────────────────────────
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}
const ts    = () => Math.floor(Date.now() / 1000);
const nonce = () => bytesToHex(randomBytes(8));
const enc   = (s) => new TextEncoder().encode(s);
const sign  = (msg, priv) => bytesToHex(ed.sign(enc(msg), priv));

async function post(url, body) {
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`POST ${url} → ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

async function get(url) {
  const r = await fetch(url);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`GET ${url} → ${r.status}: ${JSON.stringify(j)}`);
  return j;
}

function assert(cond, msg) {
  if (!cond) { console.error(`\n❌  ASSERT FAILED: ${msg}`); process.exit(1); }
  console.log(`   ✓  ${msg}`);
}

// ── Step helpers ──────────────────────────────────────────────────────────────

async function adminMint(addr, bb) {
  return post(`${L1}/admin/mint`, { to: addr, amount: bb, dealer_signature: 'dev' });
}

async function lockBb(priv, pubHex, addr, lamports) {
  const t = ts(); const n = nonce();
  const msg = `ROLLUP_LOCK_BB:L3:${addr}:${lamports}:${COLLECTION}:${t}:${n}`;
  return post(`${L1}/rollup/L3/lock_bb`, {
    wallet_address: addr, bb_lamports: lamports, token_symbol_hint: COLLECTION,
    public_key: pubHex, signature: sign(msg, priv), timestamp: t, nonce: n,
  });
}

async function l3MintNft(priv, pubHex, ownerAddr) {
  const t = ts(); const n = nonce();
  const msg = `L3_MINT:${COLLECTION}:${TOKEN_ID}:${ownerAddr}:${META_HASH}:${t}:${n}`;
  return post(`${L3}/mint`, {
    collection_id: COLLECTION, token_id: TOKEN_ID,
    owner_address: ownerAddr, metadata_hash: META_HASH, metadata_uri: META_URI,
    public_key: pubHex, signature: sign(msg, priv), timestamp: t, nonce: n,
  });
}

async function forceSeal() {
  return post(`${L3}/admin/seal`, {});
}

async function exitNft(priv, pubHex, addr, batchId, siblings, siblingIsRight) {
  const t = ts(); const n = nonce();
  const msg = `ROLLUP_EXIT:L3:NFT:${addr}:${batchId}:${t}:${n}`;
  return post(`${L1}/rollup/L3/exit`, {
    address: addr, asset_type: 'NFT',
    collection_id: COLLECTION, nft_token_id: TOKEN_ID_U64,
    metadata_uri: META_URI, metadata_hash: META_HASH,
    batch_id: batchId, proof_siblings: siblings, sibling_is_right: siblingIsRight,
    public_key: pubHex, signature: sign(msg, priv), timestamp: t, nonce: n,
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────

console.log('\n════════════════════════════════════════════════════════');
console.log('  L3 NFT Sequencer — smoke test');
console.log('════════════════════════════════════════════════════════\n');

// ── 0. Health checks ──────────────────────────────────────────────────────────
console.log('[ 0 ] Health checks …');
const l1Health = await get(`${L1}/health`);
assert(l1Health.status === 'healthy' || l1Health.status === 'alive' || l1Health.is_producing !== undefined, 'L1 is reachable');
assert(l1Health.node_mode !== 'reader', 'L1 is in writer mode (not reader)');

const l3Health = await get(`${L3}/health`).catch(() => null);
assert(l3Health !== null, `L3 sequencer is reachable at ${L3}`);

// ── 1. Admin mint 500 BB to Alice ─────────────────────────────────────────────
console.log('\n[ 1 ] Admin mint 500 BB to Alice …');
await adminMint(ALICE_ADDR, 500);
const balBefore = await get(`${L1}/balance/${ALICE_ADDR}`);
const balBeforeLamports = Math.round((balBefore.balance_lamports ?? balBefore.balance * LAMPORTS_PER_BB));
assert(balBeforeLamports >= 500 * LAMPORTS_PER_BB, `Alice has ≥500 BB (got ${balBeforeLamports} lamports)`);

// ── 2. Alice locks 200 BB into L3 rollup vault ────────────────────────────────
console.log('\n[ 2 ] Alice locks 200 BB into L3 vault …');
const lockResp = await lockBb(ALICE_PRIV, ALICE_PUBHEX, ALICE_ADDR, 200 * LAMPORTS_PER_BB);
assert(lockResp.lock_id, `Got lock_id: ${lockResp.lock_id}`);
const lockId = lockResp.lock_id;

const balAfterLock = await get(`${L1}/balance/${ALICE_ADDR}`);
const balAfterLockLamports = Math.round((balAfterLock.balance_lamports ?? balAfterLock.balance * LAMPORTS_PER_BB));
assert(
  balAfterLockLamports <= balBeforeLamports - 200 * LAMPORTS_PER_BB,
  `Alice's L1 balance decreased by 200 BB (before=${balBeforeLamports} after=${balAfterLockLamports})`,
);

// ── 3. Mint NFT on L3 ─────────────────────────────────────────────────────────
console.log(`\n[ 3 ] Mint NFT ${COLLECTION}/${TOKEN_ID} to Alice on L3 …`);
const mintResp = await l3MintNft(ALICE_PRIV, ALICE_PUBHEX, ALICE_ADDR);
assert(mintResp.collection_id === COLLECTION, `Mint returned collection_id=${mintResp.collection_id}`);
assert(mintResp.token_id === TOKEN_ID,         `Mint returned token_id=${mintResp.token_id}`);

// Verify NFT is queryable on L3
const l3Nft = await get(`${L3}/nfts/${COLLECTION}/${TOKEN_ID}`);
assert(l3Nft.owner_address === ALICE_ADDR, `L3 NFT owner is Alice`);
assert(l3Nft.metadata_hash === META_HASH,  `L3 NFT metadata_hash matches fixture`);

// ── 4. Force batch seal (submits Merkle root to L1) ──────────────────────────
console.log('\n[ 4 ] Force batch seal on L3 …');
const sealResp = await forceSeal();
assert(typeof sealResp.batch_id === 'number',      `Seal returned batch_id=${sealResp.batch_id}`);
assert(sealResp.merkle_root?.length === 64,         `Merkle root is 64-char hex`);
assert(sealResp.entry_count >= 1,                   `Entry count ≥ 1 (got ${sealResp.entry_count})`);
assert(sealResp.proofs?.length >= 1,                `Got proof data for ${sealResp.proofs?.length} NFT(s)`);

const batchId = sealResp.batch_id;
// Find the proof for our specific NFT
const nftProof = sealResp.proofs.find(p =>
  p.collection_id === COLLECTION && p.token_id === TOKEN_ID
);
assert(nftProof !== undefined, `Proof found for ${COLLECTION}/${TOKEN_ID}`);

// Verify the root was stored on L1
const l1Root = await get(`${L1}/rollup/L3/roots/${batchId}`).catch(() => null);
assert(l1Root !== null, `L1 has a state root for batch ${batchId}`);
assert(
  l1Root.merkle_root === sealResp.merkle_root || l1Root.root === sealResp.merkle_root,
  `L1 stored root matches seal response root`,
);

// ── 5. Alice exits NFT from L3 to L1 ─────────────────────────────────────────
console.log('\n[ 5 ] Alice exits NFT to L1 …');
const exitResp = await exitNft(
  ALICE_PRIV, ALICE_PUBHEX, ALICE_ADDR,
  batchId, nftProof.siblings, nftProof.sibling_is_right,
);
assert(exitResp.success === true,               `Exit succeeded`);
assert(exitResp.asset_type === 'NFT',           `Exit asset_type=NFT`);
assert(exitResp.collection_id === COLLECTION,   `Exit collection_id matches`);

// ── 6. Verify NFT is anchored on L1 ──────────────────────────────────────────
console.log('\n[ 6 ] Verify NFT anchored on L1 …');
const l1Nft = await get(`${L1}/nft/${COLLECTION}/${TOKEN_ID}`);
assert(l1Nft.collection_id === COLLECTION, `L1 NFT collection_id matches`);
assert(l1Nft.token_id      === TOKEN_ID,   `L1 NFT token_id matches`);
assert(l1Nft.owner         === ALICE_ADDR, `L1 NFT owner is Alice`);
assert(l1Nft.metadata_hash === META_HASH,  `L1 NFT metadata_hash matches`);
assert(l1Nft.metadata_uri  === META_URI,   `L1 NFT metadata_uri matches`);

// ── 7. Double-spend rejection ─────────────────────────────────────────────────
console.log('\n[ 7 ] Double-spend rejection …');
try {
  await exitNft(ALICE_PRIV, ALICE_PUBHEX, ALICE_ADDR, batchId, nftProof.siblings, nftProof.sibling_is_right);
  assert(false, 'Second exit should have been rejected');
} catch (e) {
  assert(e.message.includes('409') || e.message.includes('403') || e.message.includes('already'),
    `Double-spend correctly rejected: ${e.message.slice(0, 80)}`);
}

// ── Done ──────────────────────────────────────────────────────────────────────
console.log('\n════════════════════════════════════════════════════════');
console.log('  ✅  L3 NFT smoke test PASSED');
console.log('════════════════════════════════════════════════════════\n');
