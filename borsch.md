Perfect strategy! This is exactly how Solana does it - Borsh for internal efficiency, JSON for external readability. Let me create a plan for implementing this hybrid approach.

Plan: Borsh-inside-JSON Hybrid Serialization
TL;DR: Implement a dual-layer serialization where node-to-node communication uses pure Borsh for speed/compactness, while RPC/API uses JSON envelopes containing Base64-encoded Borsh payloads for the actual transaction/block data.

Steps
Add Borsh derive macros to core types in core.rs - Add #[derive(BorshSerialize, BorshDeserialize)] to Transaction, Block, and ParallelScheduler structs alongside existing Serde derives

Add Borsh derives to PoH types in consensus.rs - Add Borsh to PoHEntry, Slot, PoHBlock, ValidatorStake, and LeaderScheduleEntry for fast validator-to-validator propagation

Create serialization helpers in enhanced_transaction.rs - Add BorshEnvelope struct with methods: to_base64(), from_base64(), and JSON wrapper for RPC responses containing {"data": "<base64-borsh>", "encoding": "base64"}

Update Gulf Stream forwarding - Use pure Borsh when forwarding transactions to upcoming leaders (internal), but accept JSON+Base64 from RPC clients (external)

Add Borsh to block propagation (Turbine-prep) - Serialize blocks as Borsh for future node-to-node shred propagation, keeping JSON for API block queries

Update RPC response format in main.rs - Transaction submission accepts {"transaction": "<base64-borsh-tx>"}, returns {"signature": "...", "slot": N}

Further Considerations
Base64 vs Hex encoding? Base64 is ~33% more compact than Hex. Recommend Base64 for production. Preference?

Backward compatibility? Keep pure JSON endpoints for debugging/dev mode? Add ?encoding=json query param option?

Which types to Borsh first? Start with Transaction and Block (hottest paths), then expand to PoHEntry and smart contracts?



-------------------------------


 True Rollup L2 (more scalable, more complex)If you really want a separate rollup for privacy, speed, or thousands of simultaneous markets:Deposit Phase  User deposits DIME to an L1 escrow contract (rollup bridge).  
L2 nodes see the deposit via L1 events → credit the user’s L2 balance.

Betting on L2  All trading, order matching, position updates happen inside L2 state (fast, cheap, private if you want).  
No L1 balance moves yet.

Resolution & Settlement Batch  When market resolves, sequencer creates a batch containing:  Final outcome  
Merkle root of all payouts (winner → amount)

Batch is posted to L1 rollup contract (as calldata / blob / PoH-mixed entry).

L1 Executes the Manipulation  L1 rollup contract verifies the batch (fraud-proof window or zk-proof).  
Once accepted, L1 contract does bulk transfers from the global escrow vault to winner wallets (or lets winners withdraw with a Merkle proof).  
Again, everything is atomic per batch → zero-sum preserved.

Polymarket does a hybrid of this: off-chain CLOB + on-chain settlement on Polygon (their “L1” for that app). The final redemption of shares for USDC happens in one on-chain transaction.Key Safety Guarantees (both approaches)Escrow — Funds are locked in a contract/PDA/vault that only the program/rollup contract can move.  
Atomicity — Settlement is one transaction or one verified batch → either everything succeeds or nothing moves.  
Conservation — You can prove on-chain that total_out == total_in - rake.  
Censorship resistance — Once a bet is placed on L1 (or deposited to L1), the outcome is forced-included via your PoH ordering.  
Auditability — Every transfer is on L1 forever.

Bottom Line for Your ProjectStart with Option 1 (on-chain program on your L1).
It is dramatically simpler, inherits full PoH finality, needs no bridge, and still gives you exactly the zero-sum prediction market you want.
You can later add a rollup on top if you need massive scale.
Your dime-pegged token works perfectly — just treat it like USDC/SPL in the examples above.
Zero-sum is enforced by the math inside the program + escrow model. No trust required.

This is not theoretical — thousands of prediction markets already run this exact way on Solana and Ethereum L2s today. You can copy the pattern almost 1:1 in your Rust codebase.If you want the actual Rust pseudocode for the settlement instruction (Option 1) or the batch payout Merkle proof (Option 2), just say the word and I’ll give you the next layer of detail.

