# Manual test — zero-loss BB game

This is the click-through for the live local nodes. It is not an automated test.

Layer 1 is the Windows service on `http://localhost:8080`. Layer 2 is the dealer on `http://localhost:1234`. Both start again after you sign in to this PC. Layer 1 also starts at boot, before sign-in.

The game is zero-sum only if a bet locks BB on L1 and the payout comes back out of that same market escrow. A claim must not mint new BB.

## Before you start

1. Open the wallet app and sign in.
2. Open the wallet that owns the BB you want to test. The stranded lock belongs to `5hmGhDMUc1vN6qRbPrV8N25JdrW9Y2QG4mbwsoZwjX7J`. A different wallet will not see it.
3. Unlock the wallet. If the key is locked, Claim stays disabled.
4. Go to **Settings → Network** and choose **Localhost**.
   - L1 becomes `http://localhost:8080`.
   - L2 becomes `http://localhost:1234`.
5. Reload the app after switching. The choice is saved in this browser.

Do not use Production for this test. Production L2 is `https://layer2.blackbook.id`, not the dealer on this PC.

## What the two claims are

These are different buttons. Do not treat them as the same payout.

| Where | Button | What it does | What it does not do |
|---|---|---|---|
| Wallet | **Claim to L2** | Moves an unconsumed L1 lock into L2 dealer credit | Does not raise your L1 balance |
| Markets | **Claim Winnings** | After a market is resolved, pulls a Merkle payout from that market's escrow back to L1 | Does not appear on an open market |

The old pool `57d9e717-ad71-4393-9252-9eced6235bb4` is the first kind. It is `7,228,550,150` lamports, which is `72,285.50150` BB, hint `SURV51_W10_E`. It is still locked on L1. Claiming it makes that amount spendable on the dealer. It does not return it to the L1 wallet.

## 1. Check the nodes

In a browser:

- `http://localhost:8080/health` should say healthy.
- `http://localhost:1234/health` should say `"ok": true`.
- `http://localhost:1234/glass` is the dealer view.

The tray icons only show the ports. They do not open a terminal. Closing a window does not stop Layer 1.

## 2. Read the L1 balance

1. Open **Wallet**.
2. Note the BB balance before any bet.
3. After a bet, this number should fall by the locked amount. It should not fall by more than that.

Write the number down. The pass condition is that the same number comes back after a winning claim, minus nothing and plus nothing that was not already in the pool.

## 3. Place a small bet

1. Open **Minigames → Markets** (`/minigames/predict`).
2. Pick an open MLS market. Start with one share, or the smallest entry fee shown.
3. Select the outcome.
4. Place the bet and approve the signature.
5. Wait until the page says the bet was placed.

What should happen:

- L1 balance drops by the entry amount.
- The dealer shows the position.
- No second wallet is debited.
- Refreshing the page does not place the bet again.

If the bet fails after "Locking BB on L1" but before the bet is accepted, the lock is stranded. It should show on the Wallet page as **Pending L2 credit**. Use **Claim to L2** there. Do not lock the same amount again.

## 4. Claim an older stranded lock

1. Stay on the wallet that created the lock. For the `72,285.50150` BB lock, that is `5hmG…`.
2. Open **Wallet**.
3. Under the balance, look for **Pending L2 credit**.
4. The row should show the amount and the symbol hint.
5. Click **Claim to L2**.

What should happen:

- The button changes to **Claiming…** once.
- The row disappears after success.
- The L2 dealer balance for that wallet increases by the exact lock amount.
- The L1 wallet balance does not increase.
- Clicking again, or refreshing, does not credit the amount a second time.

This button is not on the live node yet. The wallet asks L1 for `/rollup/L2/locks/creator/<address>`, and the running service still returns 404. Restart Layer 1 onto the build that contains that route before this step. Until then, the card stays hidden even though the lock exists.

The unsigned rescue command cannot do this step. The dealer requires a fresh signature from the lock owner, and the amount must be the stored lamports, not a rounded or shortened number.

## 5. Claim winnings from an older resolved pool

1. Open **Markets**.
2. Find a market whose status is **Resolved** and whose outcome is shown.
3. The wallet must be the wallet that won.
4. Click **Claim Winnings**.

What should happen:

- The page fetches your proof from the dealer.
- It submits the withdrawal to L1.
- The L1 balance rises by the payout shown on the proof.
- The payout comes from that market's escrow. If the escrow is short, the claim fails. It must not pull from the L2 rollup vault and it must not mint BB.
- Claiming the same market again fails.

There is no `/claim` page. The button is on the resolved market card. It is hidden while the market is open or frozen.

## 6. Zero-loss check

After one full cycle, compare:

- L1 balance before the bet
- L1 balance after the bet
- L2 credit after **Claim to L2**, if a lock was stranded
- L1 balance after **Claim Winnings**

The winner's gain has to equal the rest of the pool, minus no hidden mint. The sum of L1 wallet balances plus locked escrow plus unconsumed locks should match the supply you wrote down at the start. If a claim succeeds while the market escrow is empty, that is a failure.

## Stop conditions

Stop the test if any of these happen:

- L1 balance rises on **Claim to L2**
- The same lock or the same resolved market pays twice
- A claim succeeds with the wallet locked
- A payout lands while the market escrow is empty
- The wallet is still pointed at `https://layer2.blackbook.id` during a local test
