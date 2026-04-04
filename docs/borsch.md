# Borsh in BlackBook Layer 1

## Current Context on Chain
Currently, the BlackBook Layer 1 repository already includes the `borsh` dependency in its `Cargo.toml`. 

- **Version**: We are using `borsh` version `1.3` with the `derive` feature enabled.
- **Solana Compatibility**: We already utilize `solana-borsh` as part of our Solana compatibility libraries. 
- **Determinism**: We explicitly chose Borsh over `bincode` because **Borsh is deterministic**. This determinism is critical and fundamentally required when computing cryptographic hashes for Merkle proofs across the chain state.

## Why Borsh is Needed for Turbine (Production Note)
Currently, in our codebase (specifically within `TurbineShredder` in `src/poh_blockchain.rs`), block data is being serialized into chunks for Turbine shredding using `serde_json`. 

**The Problem with JSON**: 
JSON is a human-readable text format, which makes it far too bloated for high-throughput network propagation. Using JSON drastically increases the payload size and network bandwidth overhead.

**The Borsh Solution**:
In a production Layer 1 environment, this `serde_json` serialization of blocks must be swapped out for binary serialization like **Borsh**. 

### How it Works
By replacing `serde_json::to_vec(block)` with `borsh::to_vec(block)`:
1. **Compression**: The block size is compressed by approximately 50-80% before it is shredded.
2. **Speed & Throughput**: Smaller shreds mean less latency transmitting over the Turbine propagation tree, fewer shreds generated overall, and faster UDP packet broadcasting. 
3. **Consistency**: We maintain the deterministic structural guarantees needed by Solana-compatible programs and our Merkle tree root validation. 

### Implementation Action
The primary transition involves updating any `FinalizedBlock` serialization inside the `TurbineShredder` and `TurbinePropagator` network logic to derive and implement `BorshSerialize` / `BorshDeserialize`, swapping out the bloated string payloads for efficient byte-packed structs.
