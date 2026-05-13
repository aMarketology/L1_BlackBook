# The L2 Robot: Merkle Root Settlement Guide

This document defines exactly what needs to be built on your Layer 2 (L2) Node/Server to successfully negotiate a Merkle Root payout with your Layer 1 (L1) BlackBook Blockchain.

Since the L1 Escrow Gateway is 100% complete and waiting on Port 50052, this is the exact, step-by-step logic your L2 must execute to unlock payouts successfully.

---

## The Core Objective

Your "L2 Robot" (a background worker process on your game server) must:
1. Detect a finished contest.
2. Group all winning bets.
3. Compute exactly how much SPL (BlackBook tokens) each winner gets.
4. Construct a Merkle Tree from these winners.
5. Create a specific, canonically-packed array of bytes.
6. Sign those bytes with an Ed25519 Private Key.
7. Transmit the payload over gRPC to L1.

---

## 1. The Anatomy of a Merkle Leaf

The L1 node has a very specific way it checks the math when a user tries to withdraw their funds. If your L2 builds the tree differently, the user's withdrawal will fail.

**The L1 `withdraw` endpoint checks the leaf like this:**
```rust
// FROM L1 CODE (src/contracts/global_escrow/mod.rs)
let mut leaf_data = Vec::with_capacity(32 + 8);
leaf_data.extend_from_slice(&pubkey_raw_32);
leaf_data.extend_from_slice(&amount_spl.to_le_bytes());
let leaf_hash = Sha256::digest(&leaf_data);
```

### How L2 MUST Build the Leaves:
For every single winner in the contest, your L2 must create a leaf hash.

1. **User Pubkey:** Take the user's Solana-style Base58 address (e.g. `bb_123...`) and decode it into exactly 32 raw bytes.
2. **User Amount:** Calculate the exact payout in **SPL Units** (`1 BB = 1,000,000 SPL`). It must be a 64-bit unsigned integer (`u64`), represented in Little-Endian byte order (8 bytes).
3. **Concat & Hash:** Append the 8-byte amount directly to the end of the 32-byte pubkey, creating a 40-byte array. Take the `SHA-256` hash of those 40 bytes.

---

## 2. Building the Merkle Tree (The Hash Function)

Once you have all the individual `SHA-256` leaf hashes for the winners, you must build the tree up to the single 32-byte Root.

**Crucial L1 Invariant: Lexicographical Sorting**
When the L1 combines two nodes together to move up the tree, it ALWAYS sorts them from smallest to largest before hashing them. This means the L2 *must* do the exact same thing when generating the root.

### How L2 MUST Hash Nodes Together:
```rust
// pseudo-code for combining sibling A and sibling B
if hash_A < hash_B {
    let combined = concat(hash_A, hash_B);
    return SHA256(combined);
} else {
    let combined = concat(hash_B, hash_A);
    return SHA256(combined);
}
```

You repeat this process layer by layer until you are left with a single 32-byte hash. This is your `merkle_root`.

---

## 3. The Zero-Sum Invariant (Crucial)

The L1 `submit_merkle_root` handler has a strict solvency check:

```rust
// FROM L1 CODE (src/settlement/mod.rs)
if req.total_deposited != req.total_payout.saturating_add(req.house_rake) {
    return Err(Status::invalid_argument("zero-sum violated..."));
}
```

Before your L2 Robot fires the gRPC request, it must guarantee:
*   `total_deposited`: The exact total SPL tokens all users put into the market.
*   `total_payout`: The exact total SPL tokens assigned to the winners in the Merkle Tree.
*   `house_rake`: The exact SPL tokens the platform keeps.

If `payout + rake` is off by even 1 single SPL unit (0.000001 BB), the L1 will reject the Merkle Root with a `zero-sum violated` error.

---

## 4. Packing the "Signed Message"

To prove to the L1 that your official L2 actually computed this root (and not a hacker injecting fake winners), the L1 requires an Ed25519 signature.

However, you don't just sign the Merkle Root. The L1 expects the signature to cover a very specific canonical message to prevent replay attacks across different markets.

**The L1 Verifies This Exact Format:**
```rust
// FROM L1 CODE (src/settlement/mod.rs)
let mut signed_message: Vec<u8> = Vec::with_capacity(req.contest_id.len() + 8 + 32);
signed_message.extend_from_slice(req.contest_id.as_bytes());
signed_message.extend_from_slice(&req.l2_block_number.to_le_bytes());
signed_message.extend_from_slice(&req.merkle_root);
```

### How L2 MUST Sign The Data:
Your L2 Robot needs access to your `SEQUENCER_PRIVATE_KEY`.

1. Take the text of the `contest_id` (e.g. `"mrbeast_views_001"`).
2. Take your monotonic `l2_block_number` (e.g. `42`) as an 8-byte little-endian array.
3. Take the 32-byte `merkle_root` you generated in Step 2.
4. Concat them in that exact order.
5. Use your `SEQUENCER_PRIVATE_KEY` to generate a 64-byte Ed25519 signature of that entire byte array.

---

## 5. The gRPC Transmission (The Final Step)

Now that you have all the cryptographic artifacts, your L2 robot simply packs them into the Protobuf format defined in `proto/settlement.proto` and fires them to port `50052`.

### The Expected Protobuf Payload:
```json
{
    "contest_id": "mrbeast_views_001",
    "merkle_root": "[32 bytes array]",
    "winner_count": 54,
    "total_deposited": 55000000, 
    "total_payout": 50000000,    
    "house_rake": 5000000,       
    "winning_outcome": "over_100_million",
    "resolved_at": 1718000000,
    "receipt_hash": "a1b2c3d4...", 
    "oracle_proof": "https://youtube.com/...",
    "l2_block_number": 42,
    "signed_message": "[The concatenated bytes from Step 4]",
    "sequencer_pubkey": "[Your 32 byte Sequencer Public Key]",
    "sequencer_sig": "[The 64 byte Ed25519 signature from Step 4]"
}
```

Once transmitted via `client.submit_merkle_root(request)`, the L1 Node will verify the signature, verify the zero-sum invariant, store the 32-byte root into ReDB, and open the withdrawal window for the users.

---

## 6. Storing the Proofs on L2
The L1 *only* stores the 32-byte Root. It does not store who won what. 

Because the users have to bring their own proof to the L1 `withdraw` endpoint, your L2 Robot must save every single user's `merkle_proof` array (the sibling hashes connecting their leaf to the root) into your Supabase database. 

When a user opens your app, your L2 API fetches their specific proof array from Supabase and hands it to their frontend so they can click "Claim".