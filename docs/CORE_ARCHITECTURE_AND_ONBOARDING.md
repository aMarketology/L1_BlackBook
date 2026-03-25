# BlackBook L1: Core Architecture & User Journey

## 1. The Streamlined Architecture
BlackBook L1 is deeply optimized for high-throughput AI agent microtransactions. To achieve our theoretical 600k TPS using 400ms slots, we have stripped away all bloated, unauthenticated REST API routes that bypassed the core execution engine. 

Now, **100% of state mutations** funnel strictly through the **Sealevel parallel execution pipeline** and **Gulf Stream** transaction intake. There are no backdoor balance manipulation endpoints.

## 2. Wallet Creation
You **do not** call an API endpoint to create a wallet. BlackBook uses standard asymmetric cryptography (like Solana).

1. **Generate locally**: The user or AI agent generates an **Ed25519 Keypair** offline on their device.
2. **Public Key = Address**: The public key, encoded in Base58, becomes their BlackBook L1 address.
3. **Private Key = Signer**: The private key is held securely by the user/agent and never touches the network. It is used exclusively to sign transaction payloads.

## 3. Onboarding: Getting wUSDC and BB
To enter the ecosystem, users bridge real capital (USDC) from an external chain (like Base or Ethereum) to BlackBook.

1. **L2 Deposit**: The user sends real USDC to the official Bridge Dealer address.
2. **Minting on L1**: The dealer records this via the `Deposit Gateway` (`/admin/deposit/record`).
3. **Zero-Sum Mechanics**: For every `1 real USDC` received, the gateway securely mints exactly `1 wUSDC` (Wrapped USDC) to the user's BlackBook wallet. 
4. **Gas Fuel**: Simultaneously, an auxiliary mint provides the user with native `BB` tokens (e.g., 10 BB per 1 USDC) so they can immediately pay transaction fees without a faucet.

## 4. Submitting Transactions
Because there are no direct balance-manipulation APIs, all actions must be cryptographically verified.

1. **Construct**: The user builds a standard instruction (e.g., Transfer, Swap, Contract Invocation).
2. **Sign**: The user signs the serialized payload locally using their Ed25519 Private Key.
3. **Submit**: The signed transaction is sent to the node via `POST /sealevel/submit` (or the standardized `/transfer/simple` wrapper).
4. **Execute**: Gulf Stream intakes the transaction, verifies the cryptographic signature against the sender's public key, deducts the `BB` gas fee, and Sealevel executes the instruction in parallel.

## 5. Converting wUSDC to BB (Ecosystem Usage)
Once on-chain, `wUSDC` acts as the stable value layer for AI agent payments. 
If a user or agent runs out of native `BB` for gas, they can:
- **Deposit more real USDC** to auto-mint the `wUSDC + BB` bundle.
- **Interact with an on-chain AMM smart contract** (operated strictly through Sealevel instructions) to swap `wUSDC` for `BB`.

## 6. Offboarding: Cashing Out
We maintain a strict 1:1 deflationary zero-sum invariant for withdrawals.

1. **Lock**: The user submits a signed transaction to the `Withdrawal Gateway` contract on L1, locking up their `wUSDC` and providing their destination L2/Ethereum address.
2. **Burn**: When the dealer authorizes the release, the L1 engine **permanently burns** the `wUSDC` from the supply so it can never be double-spent.
3. **Release**: The dealer sends the real USDC to the user's destination address on the external chain.
