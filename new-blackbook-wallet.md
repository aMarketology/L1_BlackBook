# BlackBook Wallet — Full Build Context

**Goal:** Launch a production Next.js web wallet with WalletConnect v2, live USDC proof-of-reserves,
and an on-chain SVM swap contract (BB ↔ USDC). This document is the single source of truth for the
entire wallet build.

---

## 1. What Already Exists

### Node (L1_BlackBook — Rust v5.0.0)
| Item | Location | Status |
|---|---|---|
| JSON-RPC server | `src/solana_rpc/mod.rs` | ✅ Running port 8899 |
| HTTP API server | `src/main.rs` | ✅ Running port 8080 |
| SVM (Sealevel VM) | `src/svm/` | ✅ Always-on (no feature flag) |
| SPL Token (USDC) | `src/svm/spl_token.rs` | ✅ Mint/transfer/balance endpoints live |
| Proof of Reserves | `src/proof_of_reserves.rs` | ✅ Merkle tree + USDC tracking |
| Accounts DB | `src/svm/accounts_db.rs` | ✅ `total_lamports()` method exists |
| Web wallet (embedded) | `src/wallet_page.rs` | ✅ Served at GET /wallet |
| Transfer endpoint | `POST /transfer/simple` | ✅ Active |
| Wallet SSS 2-of-3 | `src/wallet_unified/` | ✅ Create/sign/share endpoints |
| getTokenAccountsByOwner | `src/solana_rpc/mod.rs` | ✅ Returns real USDC data |
| getTokenSupply | `src/solana_rpc/mod.rs` | ✅ Live |
| getTokenAccountBalance | `src/solana_rpc/mod.rs` | ✅ Live |
| USDC mint bootstrap | `src/main.rs` | ✅ Auto at startup (Dealer as authority) |

### Next.js Wallet (blackbook-wallet — already scaffolded at `C:\Users\maxd1\Documents\GitHub\blackbook-wallet\`)
| File | Status |
|---|---|
| `package.json` | ✅ Created |
| `tsconfig.json` | ✅ Created |
| `next.config.ts` | ✅ Created |
| `tailwind.config.ts` | ✅ Created |
| `app/layout.tsx` | ✅ Created |
| `app/page.tsx` | ✅ Created — main wallet page |
| `app/globals.css` | ✅ Created |
| `lib/rpc.ts` | ✅ Created — typed RPC client |
| `lib/types.ts` | ✅ Created — all TypeScript types |
| `lib/format.ts` | ✅ Created — formatBB, timeAgo, shortAddr |
| `config/accounts.ts` | ✅ Created — 5 known genesis accounts |
| `hooks/useStats.ts` | ✅ Created — network stats, 5s refresh |
| `hooks/useBalances.ts` | ✅ Created — batch balances, 8s refresh |
| `hooks/useTransactions.ts` | ✅ Created — TX history per account |
| `hooks/useToast.ts` | ✅ Created — toast notification state |
| `components/Header.tsx` | ✅ Created |
| `components/StatsBar.tsx` | ✅ Created |
| `components/AccountCard.tsx` | ✅ Created |
| `components/AccountDetail.tsx` | ✅ Created |
| `components/SendPanel.tsx` | ✅ Created — with quick-fill buttons |
| `components/TxHistory.tsx` | ✅ Created |
| `components/AddressLookup.tsx` | ✅ Created |
| `components/ToastContainer.tsx` | ✅ Created |
| `README.md` | ✅ Created |
| `.env.local.example` | ✅ Created |

---

## 2. Genesis Accounts (v2 — Shamir SSS)

| Name | Role | Address | Balance |
|---|---|---|---|
| Max | admin 🔑 | `GWj5GobRe4ir2sJ8ag9F7NaZKd8BhbWDcMCQAnpCPozV` | 10,000 BB |
| Alice | user | `EnrFA23SmrsUhbQ2z5GjZNafnyyz7qQtsVspgDGkBNQk` | 1,325 BB |
| Bob | user | `mmyQSriTrPjrLfquDYZYgAJEAYAoiiDT8srCoLGSdZd` | 1,650 BB |
| Apollo | user | `EfpwG4yyikxU91zAdJiSd9DpGKAQWPGPyH7xDQSQDyQb` | 775 BB |
| Dealer | dealer 🏦 | `3CTtQicXmRZv7Dhnq8TfipfHVAiYFagBiLXBeRQdpFEp` | 98,750 BB |

LAMPORTS_PER_BB = 1,000,000,000

---

## 3. Node Config

```
BlackBook L1 Genesis Hash: BUWkCKtL8JdbhfNsJDERS7vrL6c6H8TPWBg8d3SAuJXR
                           (SHA256("BLACKBOOK_L1_GENESIS_2025"))
JSON-RPC:   port 8899  (jsonrpsee + CORS allow-all + INFO logging)
HTTP API:   port 8080  (axum)
gRPC:       port 50051
Slot tick:  every 600ms (PoH interval)
Build:      cargo build / cargo run (no feature flags — SVM is always-on)
Version:    5.0.0
```

---

## 4. What Needs To Be Built (Priority Order)

### Phase A — Complete the existing wallet (1–2 days)
1. `npm install` in `blackbook-wallet/` (run `cmd /c "cd /d ... && npm install"`)
2. `npm run dev` — confirm it loads at localhost:3000
3. ~~Fix the `getSupply` bug on the node~~ ✅ Fixed — SVM is always-on, no `--features svm` needed

### Phase B — WalletConnect v2 (2–3 days)
See section 5 below.

### Phase C — USDC / Proof of Reserves display (1–2 days)
See section 6 below.

### Phase D — SVM Swap Contract (1–2 weeks)
See section 7 below.

### Phase E — Launch
See section 8 below.

---

## 5. WalletConnect v2 Integration

### What WalletConnect v2 does
Allows mobile wallets (Phantom, Backpack, Trust, etc.) to connect to your web wallet via QR code or
deep link. The user scans a QR, approves the connection in their mobile app, and your web wallet can
then request transaction signatures from that mobile wallet.

For BlackBook specifically: since our chain is not listed in WalletConnect's official chain registry,
we register it as a custom EVM/SVM-compatible chain using the CAP-2 standard.

### Required packages
```bash
npm install @walletconnect/modal @walletconnect/sign-client @walletconnect/utils
```

### Get a WalletConnect Project ID
1. Go to https://cloud.walletconnect.com
2. Create a new project ("BlackBook Wallet")
3. Copy the Project ID → add to `.env.local`:

```env
NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=your_project_id_here
```

### BlackBook Chain Registration
WalletConnect uses CAIP-2 chain identifiers. Format: `namespace:chainId`

For Solana-compatible chains: `solana:blackbook-l1`

```typescript
// lib/walletconnect.ts
import SignClient from '@walletconnect/sign-client'

export const BB_CHAIN_ID = 'solana:blackbook-l1'

export const BB_CHAIN_METADATA = {
  name: 'BlackBook L1',
  description: 'BlackBook Digital Central Bank',
  url: 'https://blackbook.finance',
  icons: ['https://blackbook.finance/logo.png'],
}

export async function createWCClient() {
  return await SignClient.init({
    projectId: process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID!,
    metadata: BB_CHAIN_METADATA,
  })
}
```

### WalletConnect flow in the wallet
```
User clicks "Connect Wallet"
  → WalletConnect Modal opens (QR code)
  → User scans with Phantom / Trust / any WC-compatible wallet
  → Session established
  → wallet.address appears in the header
  → Send transactions route through the mobile wallet for signing
  → Node broadcasts via sendTransaction RPC
```

### New files needed
```
hooks/useWalletConnect.ts     — session management, connect/disconnect
components/ConnectButton.tsx  — "Connect Wallet" button + address pill
components/WCModal.tsx        — wraps @walletconnect/modal
```

### `hooks/useWalletConnect.ts` (scaffold)
```typescript
'use client'

import { useCallback, useEffect, useState } from 'react'
import SignClient from '@walletconnect/sign-client'
import { BB_CHAIN_ID, createWCClient } from '@/lib/walletconnect'

export function useWalletConnect() {
  const [client, setClient] = useState<Awaited<ReturnType<typeof createWCClient>> | null>(null)
  const [session, setSession] = useState<unknown>(null)
  const [address, setAddress] = useState<string | null>(null)

  useEffect(() => {
    createWCClient().then(setClient)
  }, [])

  const connect = useCallback(async () => {
    if (!client) return

    const { uri, approval } = await client.connect({
      requiredNamespaces: {
        solana: {
          methods: ['solana_signTransaction', 'solana_signMessage'],
          chains: [BB_CHAIN_ID],
          events: ['accountsChanged'],
        },
      },
    })

    // Open QR modal
    if (uri) {
      const { WalletConnectModal } = await import('@walletconnect/modal')
      const modal = new WalletConnectModal({
        projectId: process.env.NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID!,
      })
      modal.openModal({ uri })
    }

    const session = await approval()
    setSession(session)
    const accounts = session.namespaces.solana?.accounts ?? []
    if (accounts.length > 0) {
      // Format: "solana:blackbook-l1:ADDRESS"
      setAddress(accounts[0].split(':')[2])
    }
  }, [client])

  const disconnect = useCallback(async () => {
    if (!client || !session) return
    await client.disconnect({
      topic: (session as { topic: string }).topic,
      reason: { code: 6000, message: 'User disconnected' },
    })
    setSession(null)
    setAddress(null)
  }, [client, session])

  return { address, connect, disconnect, connected: !!session }
}
```

---

## 6. USDC + Proof of Reserves

### Architecture
```
BlackBook L1 Node
  GET /reserves
  → returns:
    {
      bb_supply:        112500000000000,   // lamports (from total_lamports())
      bb_supply_human:  "112,500.00",
      usdc_held:        112500.00,         // USDC (6 decimals on Solana)
      usdc_reserve_wallet: "SolanaMainnetAddress...",
      ratio:            1.0,               // USDC / BB = must be >= 1.0
      merkle_root:      "abc123...",       // from proof_of_reserves.rs
      last_verified:    1708531200,        // Unix timestamp
    }

Next.js wallet
  app/reserves/page.tsx
  → fetches GET /api/reserves (Next.js API route)
  → /api/reserves fetches BB node + Solana mainnet simultaneously
  → displays the reserve dashboard
```

### Step 1 — Add GET /reserves to the Rust node

In `src/main.rs`, add a new axum route handler:

```rust
// src/main.rs — add this route
.route("/reserves", get(reserves_handler))
```

```rust
// New handler (add near bottom of main.rs or in a new src/reserves_api.rs)
use axum::{extract::State, Json};
use serde_json::json;

pub async fn reserves_handler(
    State(state): State<AppState>,
) -> Json<serde_json::Value> {
    let bb_supply = state.svm_db.total_lamports();
    let merkle_root = state.proof_of_reserves
        .read()
        .current_root()
        .unwrap_or_default();

    Json(json!({
        "bb_supply": bb_supply,
        "bb_supply_bb": bb_supply as f64 / 1_000_000_000.0,
        "merkle_root": merkle_root,
        "last_verified": chrono::Utc::now().timestamp(),
        // USDC reserve wallet is on Solana mainnet — queried by the Next.js layer
        "usdc_reserve_wallet": "INSERT_SOLANA_MAINNET_RESERVE_WALLET_ADDRESS"
    }))
}
```

### Step 2 — Next.js API route reads both sources simultaneously

```
app/api/reserves/route.ts
```

```typescript
// app/api/reserves/route.ts
import { NextResponse } from 'next/server'
import { Connection, PublicKey } from '@solana/web3.js'
import { getAccount, getMint } from '@solana/spl-token'

const BB_API = process.env.NEXT_PUBLIC_BB_API_URL ?? 'http://localhost:8080'
const SOLANA_RPC = 'https://api.mainnet-beta.solana.com'

// USDC mint on Solana mainnet
const USDC_MINT = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')

// Your designated reserve wallet on Solana mainnet
// This is a publicly known address — investors can verify on Solana Explorer
const RESERVE_WALLET = process.env.BB_RESERVE_WALLET_ADDRESS!

export async function GET() {
  const [bbRes, usdcBalance] = await Promise.all([
    fetch(`${BB_API}/reserves`).then(r => r.json()),
    fetchUsdcBalance(RESERVE_WALLET),
  ])

  const bbSupplyHuman = bbRes.bb_supply_bb as number
  const ratio = usdcBalance / bbSupplyHuman

  return NextResponse.json({
    bb_supply_lamports: bbRes.bb_supply,
    bb_supply: bbSupplyHuman,
    usdc_held: usdcBalance,
    usdc_reserve_wallet: RESERVE_WALLET,
    ratio,
    fully_backed: ratio >= 1.0,
    merkle_root: bbRes.merkle_root,
    last_verified: bbRes.last_verified,
    solana_explorer_url: `https://solscan.io/account/${RESERVE_WALLET}`,
  })
}

async function fetchUsdcBalance(walletAddress: string): Promise<number> {
  const connection = new Connection(SOLANA_RPC, 'confirmed')
  const wallet = new PublicKey(walletAddress)

  // Find the USDC associated token account
  const { TOKEN_PROGRAM_ID } = await import('@solana/spl-token')
  const tokenAccounts = await connection.getParsedTokenAccountsByOwner(wallet, {
    mint: USDC_MINT,
  })

  if (tokenAccounts.value.length === 0) return 0

  const balance = tokenAccounts.value[0].account.data.parsed.info.tokenAmount
  return parseFloat(balance.uiAmountString)
}
```

### Step 3 — Reserves page UI

```
app/reserves/page.tsx
```

```typescript
'use client'

import { useEffect, useState } from 'react'

interface ReservesData {
  bb_supply: number
  usdc_held: number
  usdc_reserve_wallet: string
  ratio: number
  fully_backed: boolean
  merkle_root: string
  last_verified: number
  solana_explorer_url: string
}

export default function ReservesPage() {
  const [data, setData] = useState<ReservesData | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = () =>
      fetch('/api/reserves')
        .then(r => r.json())
        .then(setData)
        .finally(() => setLoading(false))
    load()
    const id = setInterval(load, 15_000)
    return () => clearInterval(id)
  }, [])

  // UI displays:
  // - BB in circulation (big number)
  // - USDC in reserve (big number)
  // - Ratio bar (red if < 1.0, green if >= 1.0)
  // - Merkle root (copyable)
  // - Link to Solana Explorer for public verification
  // - "Last verified" timestamp
  // ...
}
```

### Required packages for the wallet repo
```bash
npm install @solana/web3.js @solana/spl-token
```

---

## 7. SVM Swap Contract (BB ↔ USDC)

### Overview
A simple on-chain AMM deployed to BlackBook's SVM. It holds a pool of BB and USDC tokens,
maintains a constant-product invariant (x * y = k), and allows anyone to swap in either direction.

Since BlackBook's SVM is Sealevel-compatible, this is a standard Solana program written in Rust
using `solana-program`. We deploy it to the BlackBook L1 chain.

### Contract architecture
```
SwapPool account (PDA):
  {
    bb_reserve:   u64,   // lamports of BB locked in pool
    usdc_reserve: u64,   // USDC (6 decimals) locked in pool
    fee_bps:      u16,   // swap fee in basis points (e.g. 30 = 0.3%)
    authority:    Pubkey, // pool admin
  }

Instructions:
  InitializePool(bb_amount, usdc_amount)  → seed the pool
  SwapBBForUSDC(bb_in, min_usdc_out)      → sell BB, receive USDC
  SwapUSDCForBB(usdc_in, min_bb_out)      → sell USDC, receive BB
  AddLiquidity(bb_amount, usdc_amount)    → LP provision
  RemoveLiquidity(lp_tokens)              → LP withdrawal
```

### Constant product formula
```
x * y = k

Swap BB → USDC:
  usdc_out = (usdc_reserve * bb_in * (10000 - fee_bps)) / ((bb_reserve * 10000) + (bb_in * (10000 - fee_bps)))

Price (no fee):
  price = usdc_reserve / bb_reserve
  (how many USDC per 1 BB)
```

### File location in this repo
```
programs/
  bb_swap/
    src/
      lib.rs          ← program entry point
      state.rs        ← SwapPool account struct
      instructions/
        initialize.rs
        swap_bb_for_usdc.rs
        swap_usdc_for_bb.rs
        liquidity.rs
      error.rs
    Cargo.toml
```

### `programs/bb_swap/src/lib.rs` (scaffold)
```rust
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    msg,
};

mod state;
mod instructions;
mod error;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    msg!("BBSwap: instruction received");
    instructions::route(program_id, accounts, instruction_data)
}
```

### `programs/bb_swap/src/state.rs`
```rust
use solana_program::pubkey::Pubkey;
use borsh::{BorshSerialize, BorshDeserialize};

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct SwapPool {
    pub is_initialized: bool,
    pub authority: Pubkey,
    pub bb_reserve: u64,
    pub usdc_reserve: u64,
    pub fee_bps: u16,          // 30 = 0.3%
    pub total_lp_tokens: u64,
    pub bump: u8,
}

impl SwapPool {
    pub const SIZE: usize = 1 + 32 + 8 + 8 + 2 + 8 + 1; // 60 bytes

    /// Constant product swap: compute output amount given input
    pub fn get_output_amount(&self, input: u64, input_is_bb: bool) -> u64 {
        let (in_reserve, out_reserve) = if input_is_bb {
            (self.bb_reserve, self.usdc_reserve)
        } else {
            (self.usdc_reserve, self.bb_reserve)
        };

        let fee_numerator = 10_000u128 - self.fee_bps as u128;
        let input_after_fee = input as u128 * fee_numerator;
        let numerator = input_after_fee * out_reserve as u128;
        let denominator = (in_reserve as u128 * 10_000) + input_after_fee;

        (numerator / denominator) as u64
    }

    /// Spot price: USDC per BB (scaled by 1e6)
    pub fn price_usdc_per_bb(&self) -> f64 {
        self.usdc_reserve as f64 / self.bb_reserve as f64
    }
}
```

### Deployment plan
1. Build the program: `cargo build-sbf --manifest-path programs/bb_swap/Cargo.toml`
2. Deploy to BlackBook L1: modify the node's `src/svm/` to accept `deploy_program` transactions
3. The program ID (pubkey) becomes the on-chain swap address
4. Seed the pool via `InitializePool` with initial BB + USDC reserves
5. Front-end connects via the swap UI

### Swap UI (wallet component)
```
app/swap/page.tsx     ← dedicated swap page
components/
  SwapPanel.tsx       ← token input boxes + price display + swap button
  PriceChart.tsx      ← real-time price from pool reserves (optional v2)
```

The swap UI flow:
```
User enters "10 BB"
  → wallet calculates: usdc_out = pool.get_output_amount(10 BB)
  → shows "You receive: ~10.02 USDC (fee: 0.3%)"
  → User clicks Swap
  → builds SwapBBForUSDC instruction
  → signs via WalletConnect (mobile) or local keypair
  → broadcasts via sendTransaction RPC
  → pool state updates on-chain
  → user's USDC balance increments
```

---

## 8. Launch Plan

### Environment variables (full `.env.local`)
```env
# BlackBook Node
NEXT_PUBLIC_BB_RPC_URL=https://rpc.blackbook.finance      # or ngrok URL for dev
NEXT_PUBLIC_BB_API_URL=https://api.blackbook.finance      # or ngrok URL for dev

# WalletConnect
NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=your_wc_project_id

# Reserves (server-side only, not NEXT_PUBLIC)
BB_RESERVE_WALLET_ADDRESS=SolanaMainnetWalletAddress

# Chain identity
NEXT_PUBLIC_BB_CHAIN_NAME=BlackBook L1
NEXT_PUBLIC_BB_CHAIN_ID=blackbook-l1
```

### Deploy to Vercel
```bash
cd blackbook-wallet
npx vercel

# Set all env vars in Vercel dashboard → Settings → Environment Variables
# Vercel will give you: https://blackbook-wallet.vercel.app
```

### Custom domain
Point `wallet.blackbook.finance` → Vercel deployment via CNAME.

### Pages & routes (final wallet structure)
```
/                 Main wallet (accounts, send, tx history)
/reserves         Proof of reserves dashboard (public, investor-facing)
/swap             BB ↔ USDC swap interface
/explorer         Block + transaction explorer
```

### Production checklist
- [x] `cargo build` passes (SVM always-on, no feature flags)
- [x] SVM + SPL Token endpoints live
- [x] getTokenAccountsByOwner returns real USDC data
- [x] USDC mint/transfer/balance/supply/accounts HTTP endpoints
- [ ] `npm install` in `blackbook-wallet/`
- [ ] `npm run build` passes with 0 TypeScript errors
- [ ] Node running with public URL (Railway / ngrok / own server)
- [ ] USDC reserve wallet funded on Solana mainnet
- [ ] WalletConnect Project ID created at cloud.walletconnect.com
- [ ] Deploy to Vercel + set env vars
- [ ] Custom domain configured
- [ ] `bb_swap` program built + deployed to BlackBook SVM
- [ ] Swap pool seeded with initial BB + USDC liquidity

---

## 9. Full Dependency List (wallet repo)

```json
{
  "dependencies": {
    "next": "15.1.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0",
    "clsx": "^2.1.1",
    "lucide-react": "^0.454.0",
    "@solana/web3.js": "^1.98.0",
    "@solana/spl-token": "^0.4.9",
    "@walletconnect/sign-client": "^2.17.0",
    "@walletconnect/modal": "^2.7.0",
    "@walletconnect/utils": "^2.17.0"
  },
  "devDependencies": {
    "@types/node": "^22.0.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "autoprefixer": "^10.4.20",
    "eslint": "^9.0.0",
    "eslint-config-next": "15.1.0",
    "postcss": "^8.4.49",
    "tailwindcss": "^3.4.15",
    "typescript": "^5.7.2"
  }
}
```

---

## 10. Key Design Decisions

| Decision | Choice | Reason |
|---|---|---|
| Wallet framework | Next.js 15 App Router | Server components + API routes in one repo |
| Styling | Tailwind CSS | Fast iteration, dark theme consistent with embedded wallet |
| WalletConnect namespace | `solana` | BlackBook SVM is Sealevel-compatible |
| USDC source | Solana mainnet SPL | Real USDC, verifiable by investors |
| Swap type | Constant-product AMM | Simplest correct AMM, battle-tested in production |
| Swap fee | 0.3% (30 bps) | Industry standard (Uniswap v2) |
| Reserves check frequency | 15 seconds | Balance between freshness and Solana RPC rate limits |
| Program language | Rust + solana-program | Native SVM, same toolchain as the node |

---

## 11. Relationship Between Components

```
┌─────────────────────────────────────────────────────────┐
│                  BlackBook L1 Node v5.0.0                │
│  port 8899 (JSON-RPC)   port 8080 (HTTP API)            │
│                                                          │
│  SVM always-on (no feature flag)                        │
│  SPL Token (USDC) ── mint/transfer/balance              │
│  proof_of_reserves.rs (BB + USDC tracking)              │
│  getTokenAccountsByOwner returns real data               │
│  bb_swap program (on-chain — TODO)                      │
└────────────────────┬────────────────────────────────────┘
                     │ JSON-RPC / REST
                     ▼
┌─────────────────────────────────────────────────────────┐
│              blackbook-wallet (Next.js)                  │
│                                                          │
│  /          → view balances, send BB                    │
│  /reserves  → proof of reserves dashboard               │
│  /swap      → BB ↔ USDC swap UI                        │
│                                                          │
│  WalletConnect v2 ←→ Phantom / Trust / any WC wallet   │
└────────────────────┬────────────────────────────────────┘
                     │ @solana/web3.js
                     ▼
┌─────────────────────────────────────────────────────────┐
│           Solana Mainnet (for USDC only)                 │
│  USDC SPL token balance in reserve wallet               │
│  Publicly verifiable at solscan.io                      │
└─────────────────────────────────────────────────────────┘
```

---

## 12. Next Immediate Steps

```
1.  cd blackbook-wallet
    cmd /c "npm install"
    — installs all existing deps, confirms package.json is valid

2.  cmd /c "npm run dev"
    — opens at http://localhost:3000
    — start BlackBook node first: cargo run

3.  cargo build
    — SVM is always-on, no feature flags needed
    — picks up all SPL Token + RPC fixes

4.  Create WalletConnect project at cloud.walletconnect.com
    — copy Project ID into .env.local

5.  npm install @solana/web3.js @solana/spl-token @walletconnect/sign-client @walletconnect/modal
    — adds USDC + WC deps

6.  Create lib/walletconnect.ts + hooks/useWalletConnect.ts + components/ConnectButton.tsx

7.  Add GET /reserves to src/main.rs in the Rust node

8.  Create app/api/reserves/route.ts in the wallet

9.  Create app/reserves/page.tsx (reserves dashboard)

10. Create programs/bb_swap/ — the on-chain swap contract

11. Create app/swap/page.tsx + components/SwapPanel.tsx

12. Deploy: Vercel + Railway (node) + custom domain
```
