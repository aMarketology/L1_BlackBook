# Layer 2 Betting Integration Requirements

**Status:** Layer 1 (L1) Settlement is 100% complete and cryptographically verified.
**L2 Environment:** The Layer 2 (L2) prediction market server (`blackbook-dealer`) is currently running on `http://localhost:1234`.

This document outlines the missing context required to script end-to-end simulated bets for Alice and Bob on the L2 game server. Once these fields are defined, we can build the automated test suite that bridges L2 betting execution with L1 Escrow settlement.

---

## 1. API Endpoint / Transport
Where does the L2 accept incoming prediction market bets?
* **Protocol:** [ e.g., HTTP REST, WebSockets, or gRPC ]
* **Method:** [ e.g., POST ]
* **URL/Path:** [ e.g., `http://localhost:1234/api/v1/bets/place` ]

## 2. Expected JSON Payload Schema
What is the exact data structure the L2 sequencer expects when a user submits a bet?

```json
// Example Structure - Please update with the actual expected fields
{
  "market_id": "string",
  "wallet_address": "string",
  "predicted_outcome": "boolean / string",
  "amount": "number",
  "public_key": "string (hex)",
  "signature": "string (hex)"
}
```

## 3. Cryptographic Signature Format (Ed25519)
The L2 must verify the user's intent to place a bet. What is the exact string or byte array format the user's wallet must sign? 

* **Signature Message Format:** [ e.g., `SIGN("PLACE_BET:{market_id}:{wallet_address}:{amount}:{outcome}:{nonce}")` ]
* **Encoding:** [ e.g., UTF-8 string encoding ]

---

## Next Steps for End-to-End Testing
Once the above L2 interface details are populated:
1. **Wallet Signatures:** We will update the test scripts (`sdk/escrow.sdk.ts` or `test_escrow_flow.mjs`) to generate valid Ed25519 signatures matching the format in Section 3.
2. **Execution:** Alice and Bob will transmit their signed bets to the L2 endpoint defined in Section 1.
3. **Settlement:** We will trigger the L2 to calculate the final odds, generate the resulting Merkle Root of the winners, and submit it to the `global_escrow` contract on L1 for trustless payout withdrawals.