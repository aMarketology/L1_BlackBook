# BlackBook L1: Hot Wallets & Prediction Market Escrow

This guide outlines how developers and prediction market dApps can programmatically generate hot wallets for users and securely lock/unlock funds into the Layer 1 Global Escrow Contract for Layer 2 gaming.

## 1. Creating a Hot Wallet (`wallet.sdk.ts`)

For users who do not have a browser extension (or if your dApp wants to instantly spin up a temporary hot wallet in the background), you should use the `wallet.sdk.ts` SDK.

It contains an offline, cryptographic wallet generator tailored perfectly for the BlackBook network's Ed25519 cryptography.

```typescript
import { BlackBookWallet } from "./sdk/wallet.sdk.ts";

async function createWallet() {
    // Instantly generates a fresh public/private keypair completely offline
    const myNewWallet = await BlackBookWallet.generate();

    console.log("New L1 Address:", myNewWallet.address); // e.g. '5imhnf...'
    console.log("Save this secure key:", myNewWallet.privateKeyHex);
    
    return myNewWallet;
}
```

> **Note on Compatibility:** Because BlackBook shares Solana's mathematical cryptography (Ed25519), the generated hot wallet can actually be imported directly into **Phantom** or **OneKey** later if the user wants to upgrade from a background hot wallet to a secure browser extension!

---

## 2. Locking Funds for Prediction Markets (`escrow.sdk.ts`)

To securely move funds from a user's L1 wallet into the Prediction Market (Layer 2) so they can start placing bets, they should use the `escrow.sdk.ts` SDK.

This SDK interacts with the **Global Escrow Contract** on the Layer 1. It cryptographically signs a transaction that locks their `$BB` tokens into the Escrow PDA (Program Derived Address). 

```typescript
import { BlackBookEscrowSDK } from "./sdk/escrow.sdk.ts";

async function fundPredictionMarket(myNewWallet) {
    const escrow = new BlackBookEscrowSDK({ 
        rpcUrl: "http://127.0.0.1:8080", 
        wallet: myNewWallet // The hot wallet we just generated
    });

    // Locks 50 BB into the Layer 1 Escrow Smart Contract.
    // The L2 Prediction Market immediately sees this and credits them 50 playing chips!
    console.log("Locking funds in Escrow...");
    await escrow.deposit(50.0);
    console.log("Success! Funds are ready on Layer 2.");
}
```

---

## 3. The Full Prediction Market Architecture

Here is the exact lifecycle of a user's funds when interacting with a BlackBook Prediction Market:

1. **Deposit (L1):** User calls `escrow.deposit(50.0)`. L1 locks the funds securely in the Global Escrow Contract. The L2 sequencer sees this and credits the user 50 chips.
2. **Play (L2):** User places bets fast and gas-free on the Layer 2 application's off-chain or rollup engine.
3. **Settle (L1/L2):** The L2 sequencer posts a cryptographic Merkle Root to the L1 containing the final game state and who won/lost.
4. **Withdraw (L1):** The user calls `escrow.withdraw(marketId, winnings_amount, merkle_proof)` on the L1. The smart contract cryptographically proves they won the bet against the posted state root, and instantly unlocks their `$BB` back into their main wallet!