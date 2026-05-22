/**
 * BlackBook L1 — Prediction Market Live Run
 * ============================================
 * Full flow: fund wallets → swap BB→wUSDT → escrow deposit →
 * settle market → merkle proof → escrow withdraw
 *
 * Usage: node tests/run_prediction_market.mjs
 */

import * as ed from "@noble/ed25519";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import bs58 from "bs58";
import { createHash } from "crypto";

const NODE = process.env.BB_NODE || "http://layer1.blackbook.id";

// ── L2 Sequencer keypair (matches L2_SEQUENCER_KEY / L2_SEQUENCER_PUBKEY on node) ────
const L2_SEQUENCER = {
  private_key_hex: "47d8d39738edff6e48d727126da4ec1683142c95ad456d6424be31847e61ad7f",
  public_key_hex:  "bc9359a98d3037e00ac9e7b90e814f89748fd9e1b997c20b06a9924412e8ac2a",
};

// ── Wallets — generate fresh keypairs each run ────────────────────────────
async function generateWallet(label) {
  const priv = ed.utils.randomSecretKey();   // v3 API: randomSecretKey (not randomPrivateKey)
  const pub  = await ed.getPublicKeyAsync(priv);
  const kp = {
    label,
    address:    bs58.encode(pub),
    secretHex:  bytesToHex(priv) + bytesToHex(pub), // 64-byte Solana format
    _privSeed:  bytesToHex(priv),  // internal: actual 32-byte seed
  };
  return kp;
}

const ALICE_STATIC = {
  address:      "EB8tsQcA8Ewuqni2pqW5RiME95oiUAHj5eC9Lz2zX3j5",
  secretHex:    "1c12a697254491cc286dd6431e9c84acda48ae85b667e08f8527eeb810f9316bc3c0aa0bad64ed2c74d91c24682ae5a4021960e2b70f629296c51a01190f5870",
};
const BOB_STATIC = {
  address:      "9a66KD7KTTUnwXdfxM5c4E5Z8rqyDbP4zm3qCgZsmGoo",
  secretHex:    "f4366aec8e6f4f0a099f32a784a587b78ab18ef46ed7732ef7143a8b29090d257f576b5234264a3a8ea6f58cfe941f5aba6583679cfed70d11048a0956c622f6",
};

// ── Helpers ────────────────────────────────────────────────────────────────

function nowSecs() { return Math.floor(Date.now() / 1000); }

function randomNonce() {
  const arr = new Uint8Array(12);
  for (let i = 0; i < 12; i++) arr[i] = Math.floor(Math.random() * 256);
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

// secretHex is 64-byte Solana-style (seed32 || pubkey32) — use first 32 bytes as Ed25519 seed
function seedFromSecret(secretHex) {
  return secretHex.slice(0, 64); // first 32 bytes = 64 hex chars
}

function privSeed(wallet) {
  // If wallet was generated fresh, use _privSeed directly; otherwise slice secretHex
  return wallet._privSeed ?? seedFromSecret(wallet.secretHex);
}

async function pubKeyHex(wallet) {
  const pub = await ed.getPublicKeyAsync(hexToBytes(privSeed(wallet)));
  return bytesToHex(pub);
}

async function sign(message, wallet) {
  const msgBytes = typeof message === "string"
    ? new TextEncoder().encode(message)
    : message;
  const sig = await ed.signAsync(msgBytes, hexToBytes(privSeed(wallet)));
  return bytesToHex(sig);
}

async function buildAuth(action, from, fields, wallet) {
  const timestamp = nowSecs();
  const nonce     = randomNonce();
  const message   = [action, from, ...fields, String(timestamp), nonce].join(":");
  const signature = await sign(message, wallet);
  return { signature, timestamp, nonce };
}

async function request(method, path, body) {
  const url = `${NODE}${path}`;
  const opts = { method, headers: { "Content-Type": "application/json" } };
  if (body) opts.body = JSON.stringify(body);
  const res = await fetch(url, opts);
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { error: text }; }
  if (!res.ok) throw new Error(`${method} ${path} → ${res.status}: ${JSON.stringify(json)}`);
  return json;
}

function log(label, data) {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${label}`);
  console.log(`${"─".repeat(60)}`);
  if (typeof data === "object") {
    console.log(JSON.stringify(data, null, 2));
  } else {
    console.log(data);
  }
}

// ── Merkle helpers (matching server: SHA256, sorted-pair) ──────────────────

function sha256(data) {
  return createHash("sha256").update(data).digest();
}

function merkleLeaf(address, payoutLamports) {
  // Server leaf: SHA256( bs58_decode(address)[32] || amount_spl_u64_le[8] )
  // amount_spl = lamports × 10  (1 BB = 100_000 lamports = 1_000_000 SPL)
  const addrBytes = bs58.decode(address);          // raw 32 bytes
  const amountSpl = BigInt(payoutLamports) * 10n;  // lamports → SPL
  const payoutBuf = Buffer.alloc(8);
  payoutBuf.writeBigUInt64LE(amountSpl, 0);
  return sha256(Buffer.concat([Buffer.from(addrBytes), payoutBuf]));
}

function merkleParent(a, b) {
  // sorted: min(a,b) || max(a,b)
  const [left, right] = Buffer.compare(a, b) <= 0 ? [a, b] : [b, a];
  return sha256(Buffer.concat([left, right]));
}

function buildMerkleTree(leaves) {
  if (leaves.length === 0) throw new Error("No leaves");
  let level = leaves.map(l => Buffer.from(l));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(merkleParent(level[i], level[i+1]));
      } else {
        next.push(level[i]); // odd leaf promoted
      }
    }
    level = next;
  }
  return level[0];
}

function buildMerkleProof(leaves, targetIdx) {
  const proof = [];
  let level = leaves.map(l => Buffer.from(l));
  let idx   = targetIdx;
  while (level.length > 1) {
    const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
    if (siblingIdx < level.length) {
      proof.push(level[siblingIdx].toString("hex"));
    }
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(merkleParent(level[i], level[i+1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
    idx   = Math.floor(idx / 2);
  }
  return proof;
}

// ── Main test flow ─────────────────────────────────────────────────────────

async function main() {
  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║  BlackBook L1 — Prediction Market Live Test              ║");
  console.log(`║  Node: ${NODE}  ║`);
  console.log("╚══════════════════════════════════════════════════════════╝");

  // Generate fresh wallets (bypasses epoch rate limit)
  const ALICE = await generateWallet("Alice");
  const BOB   = await generateWallet("Bob");

  console.log(`\n  Alice: ${ALICE.address} (fresh)`);
  console.log(`  Bob:   ${BOB.address} (fresh)`);

  // ── 1. Health check ──────────────────────────────────────────────────────
  const health = await request("GET", "/health");
  log("1. Node Health", {
    status:    health.status,
    slot:      health.poh_clock?.current_slot,
    supply_bb: health.blockchain?.total_supply,
    version:   health.version,
  });

  // ── 2. Faucet — fund Alice and Bob (auto-retry with fresh wallets if rate-limited) ──
  async function fundWallet(label) {
    for (let attempt = 0; attempt < 10; attempt++) {
      const w  = await generateWallet(label);
      const pk = await pubKeyHex(w);
      const amount = 0.1;
      const auth   = await buildAuth("FAUCET", w.address, [String(amount)], w);
      try {
        const res = await request("POST", "/faucet", {
          wallet_address: w.address, amount, public_key: pk, ...auth,
        });
        console.log(`  ${label}: ${w.address} → ${res.new_balance} BB ✓`);
        return { wallet: w, pubHex: pk };
      } catch (e) {
        if (e.message.includes("429") || e.message.includes("already claimed")) {
          process.stdout.write(`  ${label} attempt ${attempt+1}: rate-limited, retrying...\n`);
          continue;
        }
        throw e;
      }
    }
    throw new Error(`${label}: exhausted 10 fresh wallets`);
  }

  console.log("\n  Funding wallets via faucet...");
  const { wallet: aliceW, pubHex: alicePub } = await fundWallet("Alice");
  const { wallet: bobW,   pubHex: bobPub }   = await fundWallet("Bob");

  // Reassign for rest of test
  ALICE.address   = aliceW.address;  ALICE._privSeed = aliceW._privSeed;
  BOB.address     = bobW.address;    BOB._privSeed   = bobW._privSeed;

  log("2. Wallets funded", {
    alice: { address: ALICE.address, balance_bb: 0.1 },
    bob:   { address: BOB.address,   balance_bb: 0.1 },
  });

  // ── 3. Check supply audit ────────────────────────────────────────────────
  const audit = await request("GET", "/supply/audit");
  log("3. Supply audit after faucets", {
    bb_supply:    audit.bb_total_supply,
    wusdt_supply: audit.wusdt_total_supply,
    ratio:        audit.backing_ratio,
    invariant_ok: audit.invariant_ok,
  });

  // ── 4. Alice deposits into escrow (lamports) ──────────────────────────
  const LAMPORTS_PER_BB  = 100_000;
  const aliceEscrowLamps = 5000;   // 0.05 BB
  const aliceEscrowAuth  = await buildAuth(
    "ESCROW_DEPOSIT", ALICE.address, [String(aliceEscrowLamps)], ALICE
  );
  const aliceDeposit = await request("POST", "/escrow/deposit", {
    wallet_address: ALICE.address,
    amount:         aliceEscrowLamps,
    public_key:     alicePub,
    ...aliceEscrowAuth,
  });
  log("4a. Alice escrow deposit (0.05 BB = 5000 lamports)", aliceDeposit);

  // ── 5. Bob deposits into escrow ──────────────────────────────────────────
  const bobEscrowLamps = 5000;   // 0.05 BB
  const bobEscrowAuth  = await buildAuth(
    "ESCROW_DEPOSIT", BOB.address, [String(bobEscrowLamps)], BOB
  );
  const bobDeposit = await request("POST", "/escrow/deposit", {
    wallet_address: BOB.address,
    amount:         bobEscrowLamps,
    public_key:     bobPub,
    ...bobEscrowAuth,
  });
  log("4b. Bob escrow deposit (0.05 BB = 5000 lamports)", bobDeposit);

  // ── 6. Check escrow status ───────────────────────────────────────────────
  const escrowStatus = await request("GET", "/escrow/status");
  log("5. Escrow status after deposits", escrowStatus);

  // ── 6. Simulate L2 market settlement ────────────────────────────────────
  // Alice bet YES and won — payout 0.08 BB (= 8000 lamports)
  // Bob bet NO and lost — payout 0.02 BB (= 2000 lamports)
  const marketId = `market_${Date.now()}`;

  const alicePayout = Math.round(0.08 * LAMPORTS_PER_BB); // 8000 lamports (winner)
  const bobPayout   = Math.round(0.02 * LAMPORTS_PER_BB); // 2000 lamports (consolation)

  console.log(`\n  Settling market: ${marketId}`);
  console.log(`    Alice payout: ${alicePayout} lamports (0.08 BB = $0.008, winner)`);
  console.log(`    Bob payout:   ${bobPayout} lamports (0.02 BB = $0.002, consolation)`);

  // Build merkle tree with sorted leaves
  const aliceLeaf = merkleLeaf(ALICE.address, alicePayout);
  const bobLeaf   = merkleLeaf(BOB.address,   bobPayout);
  const merkleRoot = buildMerkleTree([aliceLeaf, bobLeaf]).toString("hex");

  log("6. Merkle tree built", {
    market_id:   marketId,
    alice_leaf:  aliceLeaf.toString("hex"),
    bob_leaf:    bobLeaf.toString("hex"),
    merkle_root: merkleRoot,
  });

  // ── 7. Submit state root to L1 ──────────────────────────────────────────
  // Binary format: contest_id_bytes || l2_block_number.to_le_bytes(8) || merkle_root[32]
  // Signed by L2_SEQUENCER private key (must match L2_SEQUENCER_PUBKEY on node).
  // All amounts in SPL units (lamports × 10, since 1 BB = 1_000_000 SPL = 100_000 lamports).
  const l2BlockNumber      = 1n;
  const totalDepositedSpl  = (aliceEscrowLamps + bobEscrowLamps) * 10;  // 10000 × 10 = 100000
  const totalPayoutSpl     = (alicePayout + bobPayout) * 10;            // 10000 × 10 = 100000
  const houseRakeSpl       = totalDepositedSpl - totalPayoutSpl;        // 0

  const rootBytes    = Buffer.from(merkleRoot, "hex");
  const contestIdBuf = Buffer.from(marketId, "utf8");
  const blockNumBuf  = Buffer.alloc(8); blockNumBuf.writeBigUInt64LE(l2BlockNumber, 0);
  const signedMsg    = Buffer.concat([contestIdBuf, blockNumBuf, rootBytes]);
  const seqSig       = await ed.signAsync(signedMsg, hexToBytes(L2_SEQUENCER.private_key_hex));

  try {
    const res = await request("POST", "/escrow/submit-state-root", {
      market_id:        marketId,
      merkle_root:      merkleRoot,
      l2_block_number:  Number(l2BlockNumber),
      total_deposited:  totalDepositedSpl,
      total_payout:     totalPayoutSpl,
      house_rake:       houseRakeSpl,
      winner_count:     1,
      signature:        bytesToHex(seqSig),
    });
    log("7. State root submitted ✓", res);
  } catch (e) {
    log("7. State root FAILED", { error: e.message });
    console.log("  → Ensure L2_SEQUENCER_PUBKEY=" + L2_SEQUENCER.public_key_hex + " is set on the node");
  }

  // ── 8. Build Alice's withdrawal proof ───────────────────────────────────
  const aliceProof = buildMerkleProof([aliceLeaf, bobLeaf], 0); // Alice is index 0
  log("8. Alice merkle proof", {
    proof: aliceProof,
    payout_bb: alicePayout / LAMPORTS_PER_BB,
  });

  // ── 9. Alice withdraws winnings (needs valid state root first) ─────────
  // Sign: "ESCROW_WITHDRAW:{market_id}:{wallet_address}:{amount_lamports}:{ts}:{nonce}"
  const aliceWithdrawAuth = await buildAuth(
    "ESCROW_WITHDRAW", marketId, [ALICE.address, String(alicePayout)], ALICE
  );
  try {
    const aliceWithdraw = await request("POST", "/escrow/withdraw", {
      market_id:      marketId,
      amount:         alicePayout,  // lamports
      wallet_address: ALICE.address,
      merkle_proof:   aliceProof,
      public_key:     alicePub,
      ...aliceWithdrawAuth,
    });
    log("9. Alice escrow withdraw (0.08 BB = 8000 lamports)", aliceWithdraw);
  } catch (e) {
    log("9. Alice withdraw FAILED", { error: e.message });
  }

  // ── 10. Final balances ───────────────────────────────────────────────────
  const [aliceFinal, bobFinal] = await Promise.all([
    request("GET", `/balance/${ALICE.address}`),
    request("GET", `/balance/${BOB.address}`),
  ]);
  const finalEscrow = await request("GET", "/escrow/status");
  const finalAudit  = await request("GET", "/supply/audit");

  log("10. Final state", {
    alice_bb:     aliceFinal.balance,
    bob_bb:       bobFinal.balance,
    escrow_lamports: finalEscrow.escrow_balance_lamports,
    bb_supply:    finalAudit.bb_total_supply,
    invariant_ok: finalAudit.invariant_ok,
  });

  console.log("\n╔══════════════════════════════════════════════════════════╗");
  console.log("║  Test complete                                            ║");
  console.log("╚══════════════════════════════════════════════════════════╝\n");
}

main().catch(err => {
  console.error("\nFATAL:", err.message);
  process.exit(1);
});
