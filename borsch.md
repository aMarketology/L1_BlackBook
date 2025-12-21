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