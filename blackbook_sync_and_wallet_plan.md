# BlackBook Project Sync & Wallet Update Plan

This document summarizes our recent work on the L1_BlackBook blockchain and outlines the exact steps needed to update the frontend `blackbook-wallet` to support the newly implemented features.

## 1. What We Worked On Last & What We Achieved

In our last sessions, we focused on finalizing the core tokenomics of the L1 blockchain and ensuring it is production-ready.

**Key Achievements:**
1. **Production Audit**: We conducted a thorough review of the blockchain codebase and generated `clean_blockchain.md`, detailing what needs to be pruned and highlighting critical airtightness gaps (like unauthenticated endpoints).
2. **MAXX ($XX) Token**: We successfully implemented the $XX bonding-curve speculation token across the chain, completing its math logic, SVM integration, and wallet SDK support.
3. **The New $DECAY Token (Phase 1)**: 
   - We conceptualized and built the `$DECAY` value-recapture token.
   - Unlike fungible tokens, `$DECAY` is an NFT-style object. Each token has its own backing (in wUSDT) and a use-counter.
   - Every "use" leaks 1% of its current backing into a central treasury. 
   - After 100 uses, the token becomes "dead" and requires a **recharge**.
   - Recharging creates a flywheel effect: it burns 5 `$XX` (MAXX) tokens and costs a wUSDT maintenance fee. 
   - We implemented this in `src/contracts/decay_token/mod.rs`, wired up 8 new REST endpoints in `src/main.rs`, added the necessary ReDB tables, and ensured the rust compiler (`cargo check`) passed cleanly with zero errors.
4. **Documentation**: We wrote `three_token_system.md` to explain how $BB, $XX, and $DECAY interact on-chain with wUSDT as the reserve currency.

---

## 2. Steps to Update `/blackbook-wallet`

Now that the backend fully supports the 4-token system ($BB, wUSDT, $XX, and $DECAY), the frontend `/blackbook-wallet` needs to be updated to let users view, mint, use, and recharge their `$DECAY` tokens.

Here is the step-by-step implementation guide for the wallet folder:

### Step 1: Fix Existing Build Blockers
*Before adding new features, we must fix the current TypeScript errors.*
* **File:** `src/pages/TransactionsPage.tsx`
* **Action:** Delete the duplicate `export default function TransactionsPage()` (lines 61 and 542). Keep only one. Add the missing import for `L2EventItem` from `../lib/sdk/l2-explorer.sdk`.

### Step 2: Register `$DECAY` in the Token Registry
* **File:** `src/lib/tokens.ts`
* **Action:** Add `$DECAY` to the `TOKEN_LIST`. Since it's an NFT-style token with individual instances, set `decimals: 0` and add a custom flag like `isNftLike: true`. This flag will tell the UI to display "× N tokens" instead of a fractional balance. 

### Step 3: Extend the Explorer SDK (Reads)
* **File:** `src/lib/sdk/explorer.sdk.ts`
* **Action:** 
  - Add TypeScript interfaces for `DecayToken`, `DecayOwnerResponse`, etc.
  - Add fetch methods to the `ExplorerSdk` class: `getDecayOwner(address)`, `getDecayToken(id)`, `getDecayTreasury()`, and `getDecaySupply()`.
  - Extend the `WalletSnapshot` interface to include `decay_count` and `decay_total_backing`, and update `getWalletSnapshot()` to fetch decay info in parallel.

### Step 4: Extend the Wallet SDK (Writes)
* **File:** `src/lib/sdk/wallet.sdk.ts`
* **Action:** Mirror the existing token action methods by adding `mintDecay()`, `useDecay()`, `rechargeDecay()`, and `stakeDecay()`. These will POST to the new unauthenticated v1 endpoints we built on the backend.

### Step 5: Wire `$DECAY` into the Global Context
* **File:** `src/context/BlackBookContext.tsx`
* **Action:** 
  - Add React state variables: `decayTokens`, `decayCount`, and `decayTotalBacking`.
  - Update the `refreshBalance` callback to include `explorerSdk.getDecayOwner()` in its `Promise.all` block.
  - Expose the decay arrays and the SDK write methods so UI components can consume them.

### Step 6: Update the UI Surfaces
* **File:** `src/pages/WalletPage.tsx` & `src/components/SwapModal.tsx`
  - **Action:** Update the token tabs to render NFT-style tokens correctly (e.g., "× 3 tokens" instead of a balance). Ensure `$DECAY` is filtered *out* of the SwapModal, as it cannot be traditionally swapped.
* **File:** `src/components/DecayInventory.tsx` *(New Component)*
  - **Action:** Build a dedicated panel that maps over `decayTokens`. Render each token's ID, backing value, uses (X/100), and status (ACTIVE / RECHARGE). Add action buttons for "Use", "Recharge" (if dead), and "Stake". Mount this component in the WalletPage when the active token tab is `$DECAY`.

### Step 7: Verify integration
* **Action:** Run `npm run build` inside `blackbook-wallet`. Test creating a `$DECAY` token by minting it with wUSDT, executing uses until the token dies, and confirming the `recharge` properly burns your MAXX balance.
