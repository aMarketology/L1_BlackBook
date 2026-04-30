# BlackBook Wallet — Four-Token Holdings Implementation Guide

> **Goal**: make a single BlackBook wallet address hold and display all four chain assets:
> **`$BB`** (native), **`wUSDT`** (SPL, 6 dec), **`$XX`/MAXX** (SPL, 12 dec), **`$DECAY`** (NFT-style per-token).
>
> The wallet already supports the first three. This guide adds **`$DECAY`** end-to-end and (optionally) renames `wUSDC` → `wUSDT` to match L1 reality.
>
> Audience: implementer working in [blackbook-wallet/](blackbook-wallet/). Estimated edit surface: 6 files.

---

## 0. Prerequisites & address model

A single Ed25519 base58 address — derived once in [blackbook-wallet/src/lib/crypto.ts](blackbook-wallet/src/lib/crypto.ts) via BIP39 → SLIP-0010 (`m/44'/1984'/0'/0'`) → `BlackBookWallet.fromPrivateKey()` — **already holds every SPL-style asset on the chain**, including `$DECAY`. There is **nothing to change in address generation**.

What we need to add is purely on the *display, fetch, and SDK* side.

Before starting, fix two pre-existing TS build blockers in [blackbook-wallet/src/pages/TransactionsPage.tsx](blackbook-wallet/src/pages/TransactionsPage.tsx):
- duplicate `export default function TransactionsPage()` (lines 61 + 542) — keep one
- missing `import { L2EventItem } from '../lib/sdk/l2-explorer.sdk';`

(Unrelated to `$DECAY`, but they'll block any fresh build.)

---

## Step 1 — Register `$DECAY` in the token registry

**File**: [blackbook-wallet/src/lib/tokens.ts](blackbook-wallet/src/lib/tokens.ts)

Append a `DECAY` entry to `TOKEN_LIST`. Because `$DECAY` is NFT-style (no fungible amount per address — you own *N tokens*, each with its own backing), use `decimals: 0` and treat the "balance" as a count.

```ts
{
  symbol: 'DECAY',
  name: 'Decay',
  decimals: 0,                  // count of NFT-style tokens owned
  isNftLike: true,              // new flag — UI uses this to render "× N tokens" instead of fractional
  color: '#FF6B35',             // burnt orange — value-recapture vibe
  icon: '⧖',                    // hourglass — implies decay
}
```

If the `Token` interface in this file does not already have `isNftLike?: boolean`, add it. Other UI code can ignore the flag and it remains backwards-compatible.

> If you also want to align `wUSDC` → `wUSDT` (L1 actually wraps Tether, not Circle), do it in this file in the same edit: rename the symbol/name and update the address constant. **Do not** rename the SDK method names yet — that is a wider refactor; the *display label* change is enough for users.

---

## Step 2 — Extend the explorer SDK with `$DECAY` reads

**File**: [blackbook-wallet/src/lib/sdk/explorer.sdk.ts](blackbook-wallet/src/lib/sdk/explorer.sdk.ts)

### 2a. Add types (near the existing `MaxxBalance`/`MaxxSupply` types)

```ts
export interface DecayToken {
  id: number;
  owner: string;
  backing_value: number;     // microUSDT
  uses_count: number;
  minted_slot: number;
  last_use_slot: number;
  lock_until_slot: number;
  recharge_count: number;
}

export interface DecayOwnerResponse {
  address: string;
  token_ids: number[];
  tokens: DecayToken[];
}

export interface DecayTreasuryResponse {
  treasury_address: string;
  treasury_wusdt_balance: number;
  vault_address: string;
  vault_wusdt_balance: number;
  total_minted: number;
  reserve_currency: 'wUSDT';
}

export interface DecaySupplyResponse {
  ticker: '$DECAY';
  token_name: 'DECAY';
  total_minted: number;
  max_uses_per_token: number;
  leak_pct_per_use: number;
}
```

### 2b. Add fetch methods on the `ExplorerSdk` class (mirror the `getMaxx*` block)

```ts
getDecayOwner(address: string): Promise<DecayOwnerResponse> {
  return this.json(`/decay/owner/${address}`);
}

getDecayToken(id: number): Promise<DecayToken> {
  return this.json(`/decay/token/${id}`);
}

getDecayTreasury(): Promise<DecayTreasuryResponse> {
  return this.json('/decay/treasury');
}

getDecaySupply(): Promise<DecaySupplyResponse> {
  return this.json('/decay/supply');
}
```

### 2c. Extend `WalletSnapshot` (currently around L191)

```ts
export interface WalletSnapshot {
  address: string;
  bb_balance: number;
  usdc_balance: number;
  usdc_raw: number;
  usdc_mint: string;
  maxx_balance: number;
  maxx_raw: number;
  maxx_mint: string;
  // NEW
  decay_count: number;          // total $DECAY tokens owned
  decay_total_backing: number;  // sum of backing_value across all owned tokens (microUSDT)
  decay_token_ids: number[];    // for cheap drill-down in UI
}
```

Update `getWalletSnapshot()` to fetch `getDecayOwner` in parallel (`Promise.all`) and reduce the response:

```ts
const decayCount = decay?.tokens.length ?? 0;
const decayTotalBacking =
  decay?.tokens.reduce((acc, t) => acc + (t.backing_value ?? 0), 0) ?? 0;
```

Wrap the call in `.catch(() => null)` so an L1 outage on the new endpoints never breaks the rest of the snapshot.

---

## Step 3 — Extend the wallet SDK with `$DECAY` write methods

**File**: [blackbook-wallet/src/lib/sdk/wallet.sdk.ts](blackbook-wallet/src/lib/sdk/wallet.sdk.ts)

Mirror the existing `buyMaxx`/`sellMaxx` pattern. v1 of these endpoints is unauthenticated on chain (matches `/maxx/*`), so the SDK just POSTs JSON.

```ts
async mintDecay(backingMicroUsdt: number) {
  return this.post('/decay/mint', {
    from: this.wallet.address,
    backing_amount: backingMicroUsdt,
  });
}

async useDecay(tokenId: number) {
  return this.post('/decay/use', {
    from: this.wallet.address,
    token_id: tokenId,
  });
}

async rechargeDecay(tokenId: number) {
  return this.post('/decay/recharge', {
    from: this.wallet.address,
    token_id: tokenId,
  });
}

async stakeDecay(tokenId: number, lockSlots: number) {
  return this.post('/decay/stake', {
    from: this.wallet.address,
    token_id: tokenId,
    lock_slots: lockSlots,
  });
}

async getMyDecay() {
  return this.explorer.getDecayOwner(this.wallet.address);
}
```

---

## Step 4 — Wire `$DECAY` into the global wallet context

**File**: [blackbook-wallet/src/context/BlackBookContext.tsx](blackbook-wallet/src/context/BlackBookContext.tsx)

### 4a. Add state

```ts
const [decayTokens, setDecayTokens] = useState<DecayToken[]>([]);
const [decayCount, setDecayCount] = useState<number>(0);
const [decayTotalBacking, setDecayTotalBacking] = useState<number>(0); // microUSDT
```

### 4b. Update `refreshBalance` (around L387)

Extend the `Promise.all` block:

```ts
const [b, u, x, d] = await Promise.all([
  explorerSdk.getBbBalance(wallet.address),
  explorerSdk.getUsdcBalance(wallet.address).catch(() => null),
  explorerSdk.getMaxxBalance(wallet.address).catch(() => null),
  explorerSdk.getDecayOwner(wallet.address).catch(() => null),  // NEW
]);
```

Then:

```ts
const tokens = d?.tokens ?? [];
setDecayTokens(tokens);
setDecayCount(tokens.length);
setDecayTotalBacking(tokens.reduce((a, t) => a + (t.backing_value ?? 0), 0));

setTokenBalances({
  BB: b.bb,
  wUSDT: (u?.balance ?? 0),       // (rename from wUSDC if you did Step 1's optional rename)
  MAXX: (x?.balance ?? 0),
  DECAY: tokens.length,            // count, not fractional
});
```

### 4c. Expose in context value

Add `decayTokens`, `decayCount`, `decayTotalBacking` plus the four new SDK actions (`mintDecay`, `useDecay`, `rechargeDecay`, `stakeDecay`) to the context object so any page can call them.

---

## Step 5 — Show `$DECAY` in the wallet UI

Two minimum changes to make the new asset visible.

### 5a. Token tabs (already iterate `TOKEN_LIST`)

Files: [blackbook-wallet/src/pages/WalletPage.tsx](blackbook-wallet/src/pages/WalletPage.tsx), [blackbook-wallet/src/components/SwapModal.tsx](blackbook-wallet/src/components/SwapModal.tsx).

These already render every entry in `TOKEN_LIST`. Once Step 1 is done, `$DECAY` shows up automatically as a tab. **For NFT-style tokens, render the balance as `× N tokens` instead of `N.NN`** — gate on the new `isNftLike` flag:

```tsx
const display = token.isNftLike
  ? `× ${tokenBalances[token.symbol] ?? 0}`
  : (tokenBalances[token.symbol] ?? 0).toFixed(token.decimals === 12 ? 6 : 4);
```

Also: do **not** include `$DECAY` in the swap source/dest token list — it isn't fungibly swappable. Filter it out where `SwapModal` builds its dropdown:

```tsx
const swappable = TOKEN_LIST.filter(t => !t.isNftLike);
```

### 5b. Dedicated inventory panel (new component)

Create [blackbook-wallet/src/components/DecayInventory.tsx](blackbook-wallet/src/components/DecayInventory.tsx). Pull `decayTokens`, `mintDecay`, `useDecay`, `rechargeDecay`, `stakeDecay` from context. Per-token row should show:

| field | source |
|---|---|
| ID | `token.id` |
| Backing | `token.backing_value / 1_000_000` wUSDT |
| Uses | `token.uses_count / 100` |
| Status | `is_dead` (uses≥100) ⇒ red "RECHARGE", else green "ACTIVE" |
| Lock | if `token.lock_until_slot > currentSlot` ⇒ "Staked until slot N" |
| Actions | `Use` (if active), `Recharge` (if dead), `Stake` (always) |

Mount it on `WalletPage` only when `activeToken === 'DECAY'`. This keeps the existing per-token tab UX consistent.

### 5c. Portfolio total (optional polish)

In [blackbook-wallet/src/pages/PortfolioPage.tsx](blackbook-wallet/src/pages/PortfolioPage.tsx) add a row:

```tsx
<PortfolioRow
  label="$DECAY backing"
  value={`${(decayTotalBacking / 1_000_000).toFixed(2)} wUSDT`}
  subtitle={`${decayCount} token${decayCount === 1 ? '' : 's'}`}
/>
```

This gives users one number that captures the dollar-equivalent locked in their `$DECAY` collection.

---

## Step 6 — Build & manual verification

```powershell
cd blackbook-wallet
npm run build
```

Expect zero TS errors (assuming Step 0's `TransactionsPage.tsx` fixes are in).

Manual smoke test against a running L1 node:

1. `BB` shows from faucet — ✓ (already works)
2. `wUSDT` shows after `swap BB→wUSDT` — ✓ (already works)
3. `$XX` mint via SwapModal `wUSDT→XX` — ✓ (already works)
4. **NEW**: `$DECAY` tab appears, shows `× 0 tokens`. Click "Mint" → enter `5` wUSDT → confirm → row appears with `5.00 wUSDT backing, 0/100 uses, ACTIVE`.
5. Click "Use" three times → backing drops geometrically (5.00 → 4.95 → 4.9005 → 4.851), uses count climbs to 3.
6. Spam "Use" until dead (uses = 100, status = RECHARGE) → click "Recharge" → row resets to `0/100 uses, ACTIVE`, your `$XX` balance drops by 5, your `wUSDT` balance drops by 2 (or 1.5 if staked first), and `decay_treasury` (visible via dev console: `await explorerSdk.getDecayTreasury()`) climbs.
7. Confirm wallet address is **the same one** holding `$BB`, `wUSDT`, `$XX`, and `$DECAY` — single base58 string in the header.

---

## Step 7 — File checklist

| File | Change |
|---|---|
| [blackbook-wallet/src/pages/TransactionsPage.tsx](blackbook-wallet/src/pages/TransactionsPage.tsx) | Fix duplicate default export + add `L2EventItem` import (build blocker) |
| [blackbook-wallet/src/lib/tokens.ts](blackbook-wallet/src/lib/tokens.ts) | Register `DECAY`; add `isNftLike` flag |
| [blackbook-wallet/src/lib/sdk/explorer.sdk.ts](blackbook-wallet/src/lib/sdk/explorer.sdk.ts) | Types + `getDecay*` methods + extend `WalletSnapshot` |
| [blackbook-wallet/src/lib/sdk/wallet.sdk.ts](blackbook-wallet/src/lib/sdk/wallet.sdk.ts) | `mintDecay`, `useDecay`, `rechargeDecay`, `stakeDecay`, `getMyDecay` |
| [blackbook-wallet/src/context/BlackBookContext.tsx](blackbook-wallet/src/context/BlackBookContext.tsx) | New state + extend `refreshBalance` + expose actions |
| [blackbook-wallet/src/components/DecayInventory.tsx](blackbook-wallet/src/components/DecayInventory.tsx) (new) | Per-token list, action buttons |
| [blackbook-wallet/src/pages/WalletPage.tsx](blackbook-wallet/src/pages/WalletPage.tsx) | Render `<DecayInventory />` when `activeToken === 'DECAY'` |
| [blackbook-wallet/src/components/SwapModal.tsx](blackbook-wallet/src/components/SwapModal.tsx) | Filter out NFT-like tokens |
| [blackbook-wallet/src/pages/PortfolioPage.tsx](blackbook-wallet/src/pages/PortfolioPage.tsx) | Optional: portfolio row for total `$DECAY` backing |

---

## Step 8 — Out of scope (deferred to Phase 2 / 3)

- **Auth on POST endpoints**: `/decay/mint|use|recharge|stake` and `/maxx/buy|sell` are unauthenticated in v1 — same as `/transfer/simple`. The wallet does not yet sign these requests. Tracked in [clean_blockchain.md](clean_blockchain.md) airtightness gap #1 and Phase 2 of [decay_token.md](decay_token.md).
- **`wUSDC` → `wUSDT` full rename**: SDK methods are still named `getUsdcBalance`, `swapBbToUsdc`. A complete rename is a separate refactor; the user-visible label change in `tokens.ts` is sufficient for this guide.
- **Treasury yield routing**: Phase 4 of [decay_token.md](decay_token.md) — off-chain.
- **Per-`$DECAY` transferability**: not yet implemented on chain. If/when added, a `transferDecay(token_id, to)` SDK method follows the same pattern as the others.

---

## Done

After Step 6 the wallet address holds, displays, and can interact with all four assets:

```
BB        × 1.23456                 (native)
wUSDT     × 12.500000               (SPL)
MAXX      × 0.123456789012          (SPL, bonding curve)
DECAY     × 3 tokens (15.00 wUSDT backing)   (NFT-style)
```

One address, one mnemonic, four assets, zero address derivation work.
