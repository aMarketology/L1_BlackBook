# ZKP.md — Zero-Knowledge Proofs on BlackBook L1

> How BlackBook uses cryptographic proofs to validate transactions without burning
> electricity on redundant computation — and how we keep it honest with independent verifiers.

---

## 1. The Problem ZKPs Solve

In a traditional blockchain (Bitcoin, Ethereum, early Solana), every validator node re-executes every transaction from scratch. If 1,000 nodes are running, the same arithmetic is computed 1,000 times. This is intentional — it's how the network detects cheating. But it comes at a massive cost: energy, hardware, and time.

**Zero-Knowledge Proofs flip this model.** Instead of everyone checking the math, one designated node (the **Prover**) does the full computation and then generates a compact cryptographic certificate — the **proof** — that says:

> *"I ran these 10,000 transactions against this state, and the resulting state root is X. Here is mathematical evidence that I did this correctly. You do not need to re-run a single transaction to verify I am telling the truth."*

Any node that receives this proof can check its validity in **milliseconds**, regardless of how many transactions it covers. The proof is small (a few hundred bytes), fast to verify, and impossible to forge without knowing the actual correct answer.

---

## 2. How It Works — Step by Step

### 2.1 The Prover Node

At the end of each block, the BlackBook **Writer** (block producer) acts as the Prover:

```
┌─────────────────────────────────────────────────────┐
│  WRITER NODE — Block N                              │
│                                                     │
│  1. Execute all transactions via SVM (sealevel)     │
│     → transfer(alice → bob, 50 BB)                  │
│     → transfer(agent_7 → agent_12, 0.0001 BB)       │
│     → ... (up to 50,000 tx/block)                   │
│                                                     │
│  2. Compute new state root                          │
│     → Merkle root of all account balances           │
│     → Committed to the PoH hash chain               │
│                                                     │
│  3. Generate ZK Validity Proof                      │
│     → Input:  pre-state root + transaction list     │
│     → Output: post-state root + proof (≈ 288 bytes) │
│     → Using: PLONK proving system (halo2 crate)     │
│                                                     │
│  4. Broadcast: (block_header + proof) to all nodes  │
└─────────────────────────────────────────────────────┘
```

The proof is attached to the block header alongside the PoH hash. It is a **mathematical commitment** — if even one transaction in the block was executed incorrectly, the proof will fail verification. It cannot be faked.

### 2.2 The Verifier Nodes

Every Reader node that receives the block runs a **proof verification** before accepting the block as valid:

```
┌─────────────────────────────────────────────────────┐
│  READER NODE — Verifying Block N                    │
│                                                     │
│  Input received:                                    │
│    - block_header (prev_hash, state_root, slot)     │
│    - proof (288 bytes)                              │
│                                                     │
│  Verification:                                      │
│    1. Check PoH linkage: hash(prev_hash) == slot    │
│    2. Run proof.verify(public_inputs) → true/false  │
│       (microseconds — no tx re-execution needed)    │
│    3. If true  → accept block, update local state   │
│    4. If false → reject block, alert network        │
│                                                     │
│  Time cost: ~2–5 ms regardless of tx count         │
└─────────────────────────────────────────────────────┘
```

This is the key insight: **verification is O(1) with respect to transaction count.** A block with 100 transactions and a block with 100,000 transactions both take the same ~2–5 ms to verify.

---

## 3. BlackBook's Verification Policy

ZKP math is cryptographically sound — a valid proof cannot lie. However, BlackBook operates with an additional layer of **social trust minimization**: we never rely on a single proof acceptance from a single node. We require a minimum number of independent verifiers to confirm the proof before a block is considered finalized.

### 3.1 Verification Tiers

| Network Stage | Required Verifiers | Policy |
|---------------|--------------------|--------|
| **Launch (now)** | **1 independent verifier** | At least 1 Reader node must verify and countersign the proof before the block advances the finality root. |
| **Growth (50–500 users)** | **2 independent verifiers** | Two geographically separate Reader nodes must both confirm. Protects against a compromised or malfunctioning single Reader. |
| **Scale (500+ users / multi-Writer)** | **3 independent verifiers** | Three independent confirmations required. At this stage, the network is Byzantine fault tolerant against a single malicious verifier. |

### 3.2 Why Not Just Trust the Math?

The cryptographic proof itself cannot lie — **but the node generating it can**. Specifically:

- A **compromised Prover** could produce a correct proof over a fraudulent set of transactions (e.g., transactions that were never broadcast, or that double-spend).
- A **silent bug** in the proving circuit could produce a valid-looking proof for an incorrect state transition.

By requiring **1+ independent node(s) to verify the proof against the same public inputs** (the PoH hash, the pre-state root, the transaction set Merkle root), we ensure that:

1. The transactions in the proof match what was actually broadcast to the network.
2. The pre-state root the Prover used matches the independently computed state root.
3. Any discrepancy is caught immediately and the block is rejected.

### 3.3 What a Verifier Actually Checks

```
Verifier inputs (public — anyone can see these):
  - pre_state_root: the Merkle root of all accounts BEFORE this block
  - tx_set_root:    Merkle root of all transactions in this block  
  - post_state_root: the claimed Merkle root AFTER execution
  - poh_hash:        the PoH slot hash this block is bound to

Verifier runs:
  proof.verify(pre_state_root, tx_set_root, post_state_root, poh_hash)
  → returns: true | false

If true:  verifier signs (block_hash + verifier_identity) with Ed25519
          and broadcasts the countersignature to the network.
If false: verifier broadcasts a REJECT with the block_hash and
          its own independently computed post_state_root.
```

A block is only accepted into the finality root once the required number of countersignatures have been collected by the Writer.

---

## 4. The Proving System — PLONK via halo2

BlackBook will use the **PLONK** proving system, implemented via the Rust [`halo2`](https://github.com/zcash/halo2) crate (developed by the Zcash Foundation, production-grade since 2021).

**Why PLONK over Groth16:**

| Property | Groth16 | PLONK (halo2) |
|----------|---------|----------------|
| Trusted setup | Per-circuit (risky) | Universal (one-time) |
| Proof size | ~192 bytes | ~288–512 bytes |
| Verification time | ~1 ms | ~2–5 ms |
| Recursion (proof of proofs) | Hard | Native |
| Rust crate maturity | Good | Excellent |

PLONK's **universal trusted setup** means we run it once for the BlackBook circuit, and it never needs to change as the protocol evolves. Groth16 requires a new ceremony every time the circuit changes — not viable for an actively developed chain.

---

## 5. Integration with Existing BlackBook Architecture

The ZKP layer slots in between the SVM execution and the PoH commitment:

```
┌──────────────────────────────────────────────────────────┐
│                     BLOCK PRODUCTION                     │
│                                                          │
│  [1] Gulf Stream    →  transaction queue                 │
│  [2] Sealevel SVM   →  parallel execution (existing)     │
│  [3] flush_block()  →  dirty accounts written to ReDB    │
│  [4] ZKP Prover     →  NEW: generate validity proof      │  ← new
│  [5] PoH commit     →  hash(prev_poh || proof_hash)      │  ← updated
│  [6] Turbine        →  shred + broadcast block           │
│                                                          │
└──────────────────────────────────────────────────────────┘
```

The `flush_block()` function in `src/svm/accounts_db.rs` already produces the pre/post state diffs needed to build the proving circuit inputs. The ZKP module wraps this output.

**New module to add:**
```
src/
  zkp/
    mod.rs          ← circuit definition (SVM state transition)
    prover.rs       ← generate proof from flush_block() output
    verifier.rs     ← verify incoming block proofs
    types.rs        ← BlockProof, VerifierSignature structs
```

---

## 6. Rollout Plan

| Phase | Milestone | What Ships |
|-------|-----------|------------|
| **Phase 0 (now)** | Launch without ZKP | Tower BFT + PoH provide consensus. No ZKP yet. Focus: get 100 users on-chain. |
| **Phase 1 (Month 2-3)** | ZKP circuit design | Define the SVM state transition circuit in halo2. Produce test proofs offline. |
| **Phase 2 (Month 3-4)** | Prover integration | Wire prover into `flush_block()`. Proofs generated per-block but not yet required for acceptance. |
| **Phase 3 (Month 4-5)** | Verifier integration | 1 Reader node verifies each block proof. Block rejection on invalid proof goes live. |
| **Phase 4 (Growth)** | Threshold verification | Increase to 2, then 3 required verifiers as Reader count grows. |
| **Phase 5 (Scale)** | Recursive proofs | Batch multiple blocks into a single proof. Full light-client support. |

---

## 7. What This Enables Long-Term

Once ZKP verification is live, several features become possible that are otherwise impractical:

- **Light clients on mobile/IoT:** A phone can verify the entire chain history is honest by checking a single recursive proof — without downloading any blocks.
- **Private AI agent transactions:** ZKPs can prove an agent has sufficient balance to pay without revealing the actual balance (shielded transfers).
- **Cross-chain bridges without trusted oracles:** A ZKP can prove a transaction happened on BlackBook to an Ethereum smart contract — no relayer, no multisig, just math.
- **Sub-second finality guarantees:** Once a proof is verified, finality is mathematically certain — not probabilistic like PoW chains.

---

*Last updated: 2026-03-22. ZKP integration is Phase 1 post-launch. Launch target: get 100 users on-chain first (see NEXT-STEPS.md § 9).*
