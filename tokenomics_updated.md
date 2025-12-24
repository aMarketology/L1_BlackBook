# 🏴 BlackBook Tokenomics

## The $BB Stablecoin

**BlackBook ($BB) is a USD-pegged stablecoin with a fixed value of $0.01 per token.**

Unlike speculative cryptocurrencies, $BB maintains perfect price stability through an elastic supply model governed by the Genesis Act. There is no finite token cap—**Supply Always Equals Demand**.

---

## 💵 The Peg: $0.01 USD

| Property | Value |
|----------|-------|
| **Peg Target** | $0.01 USD |
| **100 BB** | = $1.00 USD |
| **1,000 BB** | = $10.00 USD |
| **10,000 BB** | = $100.00 USD |

### Why $0.01?

- **Micro-transaction friendly**: Bet 50 BB ($0.50) without friction
- **Psychologically intuitive**: Easy mental math (move decimal two places)
- **Gas efficiency**: Sub-cent transactions without dust problems
- **Gaming optimized**: Natural unit for prediction markets and wagering

---

## ⚖️ Elastic Supply Model

### The Genesis Act Principle

> *"Supply shall expand and contract to meet demand, maintaining the $0.01 peg at all times."*

```
┌─────────────────────────────────────────────────────────────────┐
│                    ELASTIC SUPPLY MODEL                         │
└─────────────────────────────────────────────────────────────────┘

    DEMAND INCREASES              DEMAND DECREASES
    (Price > $0.01)               (Price < $0.01)
          │                             │
          ▼                             ▼
    ┌───────────┐                 ┌───────────┐
    │   MINT    │                 │   BURN    │
    │  New BB   │                 │  Remove   │
    │  Tokens   │                 │  BB from  │
    │           │                 │  Supply   │
    └───────────┘                 └───────────┘
          │                             │
          ▼                             ▼
    Price returns                 Price returns
    to $0.01                      to $0.01
```

### How It Works

1. **User mints BB** → Protocol locks equivalent BB tokens in escrow
2. **User burns BB** → Protocol releases and destroys equivalent locked tokens
3. **No fractional reserve** → 1:1 backing at all times
4. **No external dependencies** → Self-collateralized system

---

## 🏦 Layer 3 Liquidity Pools

BlackBook implements a **three-layer architecture** where liquidity flows between settlement, execution, and application layers.

### The Three Layers

| Layer | Name | Function | Token State |
|-------|------|----------|-------------|
| **L1** | Settlement Layer | Final state, withdrawals, reserves | Spendable |
| **L2** | Execution Layer | Prediction markets, betting engine | Locked/At-Risk |
| **L3** | Liquidity Pools | Yield generation, market making | Staked |

### L3 Pool Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     L3 LIQUIDITY POOLS                          │
│              (Built on L1 Settlement Layer)                     │
└─────────────────────────────────────────────────────────────────┘

     ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
     │   RESERVE    │    │   MARKET     │    │   YIELD      │
     │    POOL      │    │   MAKER      │    │   VAULT      │
     ├──────────────┤    ├──────────────┤    ├──────────────┤
     │ Backs the    │    │ Provides     │    │ Generates    │
     │ $0.01 peg    │    │ liquidity    │    │ returns for  │
     │              │    │ to L2 bets   │    │ LPs          │
     │ Self-locked  │    │              │    │              │
     │ BB tokens    │    │ Dealer Model │    │ Fee sharing  │
     └──────────────┘    └──────────────┘    └──────────────┘
           │                    │                    │
           └────────────────────┴────────────────────┘
                               │
                               ▼
                    ┌──────────────────┐
                    │   L1 SETTLEMENT  │
                    │   (Final State)  │
                    └──────────────────┘
```

---

## 🔄 Liquidity Pool Types

### 1. Reserve Pool (Peg Stability)

The backbone of the $0.01 peg. Backed by cryptographically locked tokens with no external collateral.

| Parameter | Value |
|-----------|-------|
| Backing | Self-locked BB tokens |
| Lock Mechanism | Algorithmic escrow (immutable until burn) |
| Lock Duration | Permanent (until coin is sold/burned) |
| Redemption | Via token burn (destroys supply elastically) |

**Mechanism:**
- User mints 100 BB → 100 BB tokens are locked in perpetual escrow
- Locked tokens cannot be removed or accessed by protocol
- User sells/burns 100 BB → Locked tokens are released and destroyed
- Supply contracts elastically with demand
- No external dependencies, no custodial risk

### 2. Market Maker Pool (L2 Liquidity)

Provides instant liquidity for the L2 prediction engine (Dealer Model).

| Parameter | Value |
|-----------|-------|
| Purpose | Counterparty for all L2 bets |
| Source | LP deposits + protocol reserves |
| Risk | Market-neutral (balanced book) |
| Returns | Share of L2 trading fees |

**The Dealer Model:**
```
User bets 100 BB on "Heads"
        │
        ▼
┌─────────────────────────────────────────┐
│         MARKET MAKER POOL               │
│  (Acts as counterparty to all bets)     │
├─────────────────────────────────────────┤
│  • Accepts bet: 100 BB from User        │
│  • Outcome: Heads wins                  │
│  • Payout: 200 BB to User               │
│  • Pool P&L: -100 BB                    │
│                                         │
│  (Balanced by opposite bets + edge)     │
└─────────────────────────────────────────┘
```

### 3. Yield Vault (LP Returns)

Liquidity providers earn yield by staking BB into the protocol.

| Source | % of Fees | Description |
|--------|-----------|-------------|
| L2 Trading Fees | 70% | Prediction market rake |
| L1 Transfer Fees | 20% | On-chain transaction fees |
| Bridge Fees | 10% | L1↔L2 movement fees |

**LP Token Model:**
- Deposit BB → Receive bbLP tokens
- bbLP represents share of pool + accrued fees
- Withdraw anytime → Burn bbLP, receive BB + yield

---

## 📊 Fee Structure

All fees are denominated in BB and flow to liquidity providers.

| Action | Fee | Destination |
|--------|-----|-------------|
| L1 Transfer | 0.01 BB ($0.0001) | Yield Vault |
| L1→L2 Bridge | 0.1% of amount | Yield Vault |
| L2→L1 Settle | 0.1% of amount | Yield Vault |
| L2 Bet Rake | 1-2% of pot | Market Maker Pool |
| Instant Withdrawal | 0.5% | Reserve Pool |

---

## 🔐 The Dual-Layer State Model

Funds exist in one of two states at any time:

### Layer 1 (The Bank)

| Property | Description |
|----------|-------------|
| **State** | Idle, Spendable, Transferable |
| **Backing** | Self-locked BB tokens in Reserve Pool |
| **Actions** | Deposit, Withdraw, Transfer, Stake |

### Layer 2 (The Engine)

| Property | Description |
|----------|-------------|
| **State** | Locked, At-Risk |
| **Backing** | Market Maker Pool liquidity |
| **Actions** | Bet, Settle, Cashout |

### The Golden Rule

> **L2.available must ALWAYS be ZERO**

Funds on L2 are either:
- **Locked** in an active bet/position
- **Flushed** back to L1 immediately upon settlement

```
┌─────────────────────────────────────────────────────────────────┐
│                    FUND FLOW LIFECYCLE                          │
└─────────────────────────────────────────────────────────────────┘

  [Lock 100BB]       [L1 Balance]      [L2 Locked]      [L1 Balance]
       │                  │                 │                │
       ▼                  ▼                 ▼                ▼
   ┌───────┐          ┌───────┐         ┌───────┐        ┌───────┐
   │ LOCK  │    ──►   │ IDLE  │   ──►   │ AT    │  ──►   │ SETTLED│
   │ MINT  │          │ 100BB │         │ RISK  │        │ ±P&L  │
   └───────┘          └───────┘         └───────┘        └───────┘
       │                                                      │
       └──────────────────────────────────────────────────────┘
                    (Burn BB → Release locked tokens)
```

---

## 🏛️ Reserve Management

### Proof of Reserves

The Reserve Pool undergoes continuous verification:

| Check | Frequency | Method |
|-------|-----------|--------|
| On-chain balance | Real-time | Smart contract query |
| Locked token escrow | Real-time | On-chain verification |
| Full audit | Quarterly | Independent third-party |

### Reserve Formula

```
Circulating BB = Total BB Minted - Locked Tokens

Example:
  Total Minted: 100,000,000 BB
  Locked in Reserve: 100,000,000 BB
  Circulating: 0 BB
  (All minted BB is backed by locked equivalent)
  Peg: $0.01 per BB ✓
```

### Emergency Mechanisms

| Scenario | Response |
|----------|----------|
| Peg > $0.011 | Increase mint rate, incentivize deposits |
| Peg < $0.009 | Halt minting, incentivize burns |
| Reserve < 95% | Pause L2, force settlements |
| Reserve < 90% | Emergency redemption queue |

---

## 📈 Protocol Revenue

The protocol generates sustainable revenue without token inflation:

| Source | Annual Estimate | Use |
|--------|-----------------|-----|
| L2 Rake (1.5% avg) | Variable | LP rewards, operations |
| Bridge Fees | Variable | Infrastructure, development |
| Lock Fees | Variable | Protocol maintenance |

**Key Insight:** The protocol generates revenue from trading activity and bridge operations while maintaining the $0.01 peg through self-locked collateral.

---

## 🎯 Value Proposition Summary

```
┌─────────────────────────────────────────────────────────────────┐
│                    WHY $BB STABLECOIN?                          │
└─────────────────────────────────────────────────────────────────┘

  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
  │   STABILITY     │  │   UTILITY       │  │   YIELD         │
  ├─────────────────┤  ├─────────────────┤  ├─────────────────┤
  │ • $0.01 peg     │  │ • Instant bets  │  │ • LP rewards    │
  │ • 100% backed   │  │ • Micro-txns    │  │ • Fee sharing   │
  │ • No volatility │  │ • Fast settle   │  │ • Reserve yield │
  └─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## Conclusion

BlackBook ($BB) is not a speculative asset—it is **programmable money for prediction markets**.

By pegging to $0.01 USD and implementing elastic supply through the Genesis Act, we eliminate price volatility while enabling:

1. **Instant liquidity** through L3 pools
2. **Risk-free holding** via cryptographic self-locking
3. **Sustainable yield** for liquidity providers
4. **Friction-free betting** on the L2 engine

**Supply = Demand. Always.**

---

*Stability. Liquidity. Velocity.*

**This is BlackBook.**
