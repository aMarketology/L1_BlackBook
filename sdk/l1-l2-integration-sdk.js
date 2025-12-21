// ============================================================================
// BLACKBOOK L1↔L2 INTEGRATION SDK
// ============================================================================
//
// This SDK explains and implements the integration between:
//   L1 (Bank/Vault) - Holds real money, final settlement
//   L2 (Casino/Gaming) - Fast bets, instant UX
//
// ============================================================================
// ARCHITECTURE OVERVIEW
// ============================================================================
//
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │                        USER WALLET                                      │
//  │                   (One keypair, two views)                              │
//  │                                                                         │
//  │   Public Key: c0e349153cbc75e9529b5f1963205cab20253db573ec65e8ff31155d  │
//  │   Private Key: [encrypted in vault, decrypted client-side]              │
//  │                                                                         │
//  │   L1 Address: L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD               │
//  │   L2 Address: L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD               │
//  │              (Same hash, different layer prefix)                        │
//  └─────────────────────────────────────────────────────────────────────────┘
//                              │
//                              ▼
//  ┌─────────────────────────────────────────────────────────────────────────┐
//  │                                                                         │
//  │  ┌─────────────────────────┐     gRPC      ┌─────────────────────────┐  │
//  │  │     L1 (THE BANK)       │◄─────────────►│    L2 (THE CASINO)      │  │
//  │  │                         │   :50051      │                         │  │
//  │  │  • Real money storage   │               │  • Fast betting engine  │  │
//  │  │  • Ed25519 verification │               │  • Dealer fronts bets   │  │
//  │  │  • Final settlement     │               │  • Sub-second UX        │  │
//  │  │  • Bridge lock/unlock   │               │  • Requests reimburse   │  │
//  │  │                         │               │                         │  │
//  │  │  REST: localhost:8080   │               │  REST: localhost:3000   │  │
//  │  │  gRPC: localhost:50051  │               │  (calls L1 gRPC)        │  │
//  │  └─────────────────────────┘               └─────────────────────────┘  │
//  │                                                                         │
//  └─────────────────────────────────────────────────────────────────────────┘
//
// ============================================================================
// THE DEALER MODEL - Why Betting is Instant
// ============================================================================
//
// Traditional Model (SLOW):
//   Alice bets $50 → Wait for Bob to bet $50 → Match → Wait for result → Settle
//   Problem: Latency, counterparty risk, bad UX
//
// Dealer Model (INSTANT):
//   Alice bets $50 → Dealer takes bet immediately → Result → Dealer pays/collects
//   The Dealer is the house, always has liquidity, no waiting
//
// ┌─────────────────────────────────────────────────────────────────────────┐
// │  EXAMPLE: Alice bets $50 on Heads                                       │
// │                                                                         │
// │  BEFORE:  Alice L1: $1000    Dealer L1: $100,000                       │
// │                                                                         │
// │  1. Alice locks $50 for betting (L1 → L2 bridge)                        │
// │     Alice L1: $950 (available) + $50 (locked)                           │
// │                                                                         │
// │  2. Alice places bet on L2 - Dealer fronts it INSTANTLY                 │
// │     L2 says: "Dealer, front Alice's $50 bet"                            │
// │     Dealer agrees (Alice has locked balance)                            │
// │                                                                         │
// │  3. L2 requests reimbursement from L1                                   │
// │     L1 moves Alice's locked $50 → Dealer                                │
// │     Alice L1: $950 (available) + $0 (locked)                            │
// │     Dealer L1: $100,050                                                 │
// │                                                                         │
// │  4. Coin flip: HEADS! Alice wins!                                       │
// │     L2 tells L1: "Pay Alice $100 (2x stake)"                            │
// │                                                                         │
// │  5. L1 Settlement:                                                      │
// │     Dealer L1 → Alice L1: $100                                          │
// │     Alice L1: $1,050                                                    │
// │     Dealer L1: $99,950                                                  │
// │                                                                         │
// │  RESULT: Alice started with $1000, now has $1050 (+$50 profit)          │
// │          Dealer started with $100k, now has $99,950 (-$50)              │
// └─────────────────────────────────────────────────────────────────────────┘
//
// ============================================================================

import nacl from 'tweetnacl';
import { createHash, randomBytes } from 'crypto';

// ============================================================================
// CONSTANTS
// ============================================================================

export const CHAIN_ID_L1 = 0x01;  // Layer 1 (Bank)
export const CHAIN_ID_L2 = 0x02;  // Layer 2 (Casino)

export const L1_REST_URL = 'http://localhost:8080';
export const L1_GRPC_URL = 'localhost:50051';
export const L2_REST_URL = 'http://localhost:1234';  // Layer 2 betting server

export const MICROTOKENS_PER_BB = 1_000_000;  // 1 BB = 1,000,000 µBB

// Dealer address (the house)
export const DEALER_ADDRESS = 'L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3';
export const DEALER_L2_ADDRESS = 'L2_F5C46483E8A28394F5E8687DEADF6BD4E924CED3';

// Real L2 market (Tesla RoboTaxi)
export const TEST_MARKET_ID = 'tesla_rtaxi';

// ============================================================================
// ADDRESS UTILITIES
// ============================================================================

/**
 * Derive L1/L2 addresses from public key
 * Both layers use the same hash, just different prefix
 */
export function deriveAddresses(publicKeyHex) {
  const hash = createHash('sha256')
    .update(Buffer.from(publicKeyHex, 'hex'))
    .digest('hex')
    .slice(0, 40)
    .toUpperCase();
  
  return {
    l1: `L1_${hash}`,
    l2: `L2_${hash}`,
    hash: hash
  };
}

/**
 * Convert L1 address to L2 address (same hash, different prefix)
 */
export function l1ToL2Address(l1Address) {
  if (!l1Address.startsWith('L1_')) {
    throw new Error('Invalid L1 address format');
  }
  return 'L2_' + l1Address.slice(3);
}

/**
 * Convert L2 address to L1 address
 */
export function l2ToL1Address(l2Address) {
  if (!l2Address.startsWith('L2_')) {
    throw new Error('Invalid L2 address format');
  }
  return 'L1_' + l2Address.slice(3);
}

/**
 * Get base hash (without prefix)
 */
export function stripPrefix(address) {
  if (address.startsWith('L1_') || address.startsWith('L2_')) {
    return address.slice(3);
  }
  return address;
}

// ============================================================================
// AMOUNT UTILITIES
// ============================================================================

export function bbToMicrotokens(bb) {
  return Math.round(bb * MICROTOKENS_PER_BB);
}

export function microtokensToBb(microtokens) {
  return microtokens / MICROTOKENS_PER_BB;
}

// ============================================================================
// SIGNATURE UTILITIES
// ============================================================================

/**
 * Sign a message with domain separation (prevents L1/L2 replay)
 */
export function signWithDomainSeparation(privateKeyHex, message, chainId) {
  const domainSeparated = Buffer.concat([
    Buffer.from([chainId]),
    Buffer.from(message, 'utf8')
  ]);
  
  const privateKey = Buffer.from(privateKeyHex, 'hex');
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  const secretKey = new Uint8Array(64);
  secretKey.set(privateKey, 0);
  secretKey.set(keypair.publicKey, 32);
  
  const signature = nacl.sign.detached(domainSeparated, secretKey);
  return Buffer.from(signature).toString('hex');
}

/**
 * Create intent hash for bet (binds bet parameters)
 */
export function createIntentHash(params) {
  const data = JSON.stringify({
    market_id: params.marketId,
    outcome: params.outcome,
    stake: params.stake,
    user: params.userAddress,
    nonce: params.nonce,
    timestamp: params.timestamp
  });
  
  return createHash('sha256').update(data).digest();
}

// ============================================================================
// L1 CLIENT - Talk to the Bank
// ============================================================================

export class L1Client {
  constructor(baseUrl = L1_REST_URL) {
    this.baseUrl = baseUrl;
  }
  
  /**
   * Get L1 balance for an address
   * @param {string} l1Address - Must be L1_<40hex> format
   */
  async getBalance(l1Address) {
    if (!l1Address.startsWith('L1_')) {
      throw new Error('L1 balance query requires L1_ prefix');
    }
    
    const response = await fetch(`${this.baseUrl}/balance/${l1Address}`);
    const data = await response.json();
    
    if (!data.success) {
      throw new Error(data.error || 'Balance query failed');
    }
    
    return {
      address: data.address,
      balance: data.balance,
      layer: data.layer
    };
  }
  
  /**
   * Initiate bridge lock (L1 → L2)
   * Locks funds on L1 so they can be used on L2
   */
  async bridgeLock(userWallet, amount) {
    const nonce = Date.now();
    const payload = {
      action: 'bridge_lock',
      amount: bbToMicrotokens(amount),
      target_layer: 'L2',
      nonce,
      timestamp: Date.now()
    };
    
    const payloadStr = JSON.stringify(payload);
    const message = `${userWallet.publicKey}:${nonce}:${payload.timestamp}:${payloadStr}`;
    const signature = signWithDomainSeparation(userWallet.privateKey, message, CHAIN_ID_L1);
    
    const response = await fetch(`${this.baseUrl}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key: userWallet.publicKey,
        wallet_address: userWallet.l1Address,
        payload: payloadStr,
        signature,
        nonce: nonce.toString(),
        timestamp: payload.timestamp,
        chain_id: CHAIN_ID_L1
      })
    });
    
    return response.json();
  }
  
  /**
   * Transfer tokens on L1
   */
  async transfer(fromWallet, toAddress, amount) {
    const nonce = Date.now();
    const payload = { to: toAddress, amount };
    const payloadStr = JSON.stringify(payload);
    const message = `${fromWallet.publicKey}:${nonce}:${Date.now()}:${payloadStr}`;
    const signature = signWithDomainSeparation(fromWallet.privateKey, message, CHAIN_ID_L1);
    
    const response = await fetch(`${this.baseUrl}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        public_key: fromWallet.publicKey,
        wallet_address: fromWallet.l1Address,
        payload: payloadStr,
        signature,
        nonce: nonce.toString(),
        timestamp: Date.now(),
        chain_id: CHAIN_ID_L1
      })
    });
    
    return response.json();
  }
  
  /**
   * Check server health
   */
  async health() {
    const response = await fetch(`${this.baseUrl}/health`);
    return response.json();
  }
}

// ============================================================================
// L2 CLIENT - Talk to the Casino
// ============================================================================

export class L2Client {
  constructor(baseUrl = L2_REST_URL) {
    this.baseUrl = baseUrl;
  }
  
  /**
   * Check L2 server health
   */
  async health() {
    const response = await fetch(`${this.baseUrl}/health`);
    return response.json();
  }
  
  /**
   * Get L2 balance (funds available for betting)
   */
  async getBalance(userAddress) {
    // L2 uses addresses without L1_/L2_ prefix
    const cleanAddress = stripPrefix(userAddress);
    const response = await fetch(`${this.baseUrl}/balance/${cleanAddress}`);
    return response.json();
  }
  
  /**
   * Credit user on L2 (simulates L1→L2 bridge)
   */
  async credit(userAddress, amount) {
    const cleanAddress = stripPrefix(userAddress);
    const response = await fetch(`${this.baseUrl}/credit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: cleanAddress,
        amount: amount  // In BB
      })
    });
    return response.json();
  }
  
  /**
   * List all markets
   */
  async listMarkets() {
    const response = await fetch(`${this.baseUrl}/markets`);
    return response.json();
  }
  
  /**
   * Get market details
   */
  async getMarket(marketId) {
    const response = await fetch(`${this.baseUrl}/markets/${marketId}`);
    return response.json();
  }
  
  /**
   * Get buy price quote
   */
  async getQuote(marketId, outcome, amount) {
    const response = await fetch(`${this.baseUrl}/quote`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        market_id: marketId,
        outcome: outcome,
        amount: amount
      })
    });
    return response.json();
  }
  
  /**
   * Place a bet on L2 (CPMM market)
   * @param {string} userAddress - User's address (with or without prefix)
   * @param {string} marketId - Market ID (e.g., "tesla_rtaxi")
   * @param {string} outcome - "YES" or "NO"
   * @param {number} amount - Amount to bet in BB
   */
  async placeBet(userAddress, marketId, outcome, amount) {
    const cleanAddress = stripPrefix(userAddress);
    
    // Convert outcome string to index (0=YES, 1=NO)
    const outcomeIndex = outcome.toUpperCase() === 'YES' ? 0 : 1;
    
    const response = await fetch(`${this.baseUrl}/bet`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: cleanAddress,
        market_id: marketId,
        outcome: outcomeIndex,
        amount: amount
      })
    });
    
    return response.json();
  }
  
  /**
   * Get user's bets
   */
  async getUserBets(userAddress) {
    const cleanAddress = stripPrefix(userAddress);
    const response = await fetch(`${this.baseUrl}/bets/${cleanAddress}`);
    return response.json();
  }
  
  /**
   * Get user's position in a market
   */
  async getUserPosition(userAddress, marketId) {
    const cleanAddress = stripPrefix(userAddress);
    const response = await fetch(`${this.baseUrl}/position/${cleanAddress}/${marketId}`);
    return response.json();
  }
  
  /**
   * Sell tokens back to pool
   */
  async sellTokens(userAddress, marketId, outcome, amount) {
    const cleanAddress = stripPrefix(userAddress);
    
    const response = await fetch(`${this.baseUrl}/sell`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: cleanAddress,
        market_id: marketId,
        outcome: outcome,
        amount: amount
      })
    });
    
    return response.json();
  }
}

// ============================================================================
// UNIFIED WALLET - Manages both L1 and L2
// ============================================================================

export class UnifiedWallet {
  constructor(privateKeyHex, publicKeyHex = null, l1Address = null, l2Address = null) {
    this.privateKey = privateKeyHex;
    
    // Derive public key if not provided
    if (!publicKeyHex) {
      const keypair = nacl.sign.keyPair.fromSeed(Buffer.from(privateKeyHex, 'hex'));
      this.publicKey = Buffer.from(keypair.publicKey).toString('hex');
    } else {
      this.publicKey = publicKeyHex;
    }
    
    // Use provided addresses (for test accounts) or derive them
    if (l1Address && l2Address) {
      this.l1Address = l1Address;
      this.l2Address = l2Address;
      this.hash = stripPrefix(l1Address);
    } else {
      const addresses = deriveAddresses(this.publicKey);
      this.l1Address = addresses.l1;
      this.l2Address = addresses.l2;
      this.hash = addresses.hash;
    }
    
    // Clients
    this.l1Client = new L1Client();
    this.l2Client = new L2Client();
    
    // Cached balances
    this.l1Balance = 0;
    this.l2Balance = 0;
  }
  
  /**
   * Refresh balances from both layers
   */
  async refresh() {
    try {
      const l1Data = await this.l1Client.getBalance(this.l1Address);
      this.l1Balance = l1Data.balance;
    } catch (e) {
      console.error('L1 balance fetch failed:', e.message);
    }
    
    try {
      const l2Data = await this.l2Client.getBalance(this.l2Address);
      this.l2Balance = l2Data.balance || 0;
    } catch (e) {
      // L2 might not be running -silent fail
      this.l2Balance = 0;
    }
    
    return {
      l1: this.l1Balance,
      l2: this.l2Balance,
      total: this.l1Balance + this.l2Balance
    };
  }
  
  /**
   * Credit L2 balance (simulates L1→L2 bridge)
   */
  async creditL2(amount) {
    return this.l2Client.credit(this.l2Address, amount);
  }
  
  /**
   * Place a bet on L2
   */
  async placeBet(marketId, outcome, amount) {
    return this.l2Client.placeBet(this.l2Address, marketId, outcome, amount);
  }
  
  /**
   * Get markets from L2
   */
  async getMarkets() {
    return this.l2Client.listMarkets();
  }
  
  /**
   * Get market details
   */
  async getMarket(marketId) {
    return this.l2Client.getMarket(marketId);
  }
  
  /**
   * Get user's bets
   */
  async getBets() {
    return this.l2Client.getUserBets(this.l2Address);
  }
  
  /**
   * Get position in a market
   */
  async getPosition(marketId) {
    return this.l2Client.getUserPosition(this.l2Address, marketId);
  }
  
  /**
   * Transfer on L1
   */
  async transfer(toAddress, amount) {
    return this.l1Client.transfer(this, toAddress, amount);
  }
}

// ============================================================================
// TEST ACCOUNTS (Match L1 server's unified_auth.rs accounts)
// ============================================================================

export const TEST_ACCOUNTS = {
  alice: {
    // These are the ACTUAL addresses from L1 server
    // Must match src/integration/unified_auth.rs
    privateKey: '37b5e0e7f8a456d3b70ff2c4c5ea8f9e3c2c89c0f0a91e27e4d6f8c3e1a2b4d0',
    publicKey: 'c0e349153cbc75e9529b5f1963205cab20253db573ec65e8ff31155dc131bd05',
    l1Address: 'L1_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD',
    l2Address: 'L2_BF1565F0D56ED917FDF8263CCCB020706F5FB5DD',
    l1Balance: 10000,
    username: 'alice_test'
  },
  bob: {
    privateKey: '9f3c7e5a2b8d1f6e4c9a0d7e3b2f8c5e1a4d6f9c2b7e5a1d3f8c6e9b4a7d2f5e',
    publicKey: '582420216093fcff65b0eec2ca2c82279db682b076526c341b80d5e2dc5c32b7',
    l1Address: 'L1_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9',
    l2Address: 'L2_AE1CA8E0144C2D8DCFAC3748B36AE166D52F71D9',
    l1Balance: 5000,
    username: 'bob_test'
  },
  dealer: {
    privateKey: 'e5284bcb4d8fb72a8969d48a888512b1f42fe5c57d1ae5119a09785ba13654ae',
    publicKey: '07943256765557e704e4945aa4d1d56a1b0aac60bd8cc328faa99572aee5e84a',
    l1Address: 'L1_F5C46483E8A28394F5E8687DEADF6BD4E924CED3',
    l2Address: 'L2_F5C46483E8A28394F5E8687DEADF6BD4E924CED3',
    l1Balance: 100000,
    username: 'dealer_house'
  }
};

/**
    account.privateKey, 
    account.publicKey,
    account.l1Address,
    account.l2Address
  
 * Create a UnifiedWallet from a test account
 */
export function createTestWallet(accountName) {
  const account = TEST_ACCOUNTS[accountName];
  if (!account) throw new Error(`Unknown test account: ${accountName}`);
  return new UnifiedWallet(account.privateKey, account.publicKey);
}

// ============================================================================
// INTEGRATION FLOW EXAMPLES
// ============================================================================

/**
 * Example: Complete betting flow
 * 
 * This demonstrates the full L1↔L2 integration:
 * 1. Alice checks her L1 balance
 * 2. Alice locks funds for L2 betting
 * 3. Alice places a bet on L2 (Dealer fronts it)
 * 4. L2 requests reimbursement from L1
 * 5. Bet resolves, L2 tells L1 to settle
 * 6. L1 moves funds between Dealer and Alice
 */
export async function exampleBettingFlow() {
  console.log('═══════════════════════════════════════════════════════════════');
  console.log('  BLACKBOOK L1↔L2 INTEGRATION DEMO');
  console.log('═══════════════════════════════════════════════════════════════');
  
  // Create wallets
  const alice = createTestWallet('alice');
  const l1 = new L1Client();
  
  // Step 1: Check L1 balance
  console.log('\n📊 Step 1: Checking Alice\'s L1 balance...');
  try {
    const balance = await l1.getBalance(alice.l1Address);
    console.log(`   L1 Balance: ${balance.balance} BB`);
  } catch (e) {
    console.log(`   Error: ${e.message}`);
  }
  
  // Step 2: Lock funds for betting
  console.log('\n🔒 Step 2: Locking 100 BB for L2 betting...');
  console.log('   (This would call /bridge/initiate on L1)');
  console.log('   After lock: L1 available: 9,900 BB, L1 locked: 100 BB');
  
  // Step 3: Place bet on L2
  console.log('\n🎰 Step 3: Placing bet on L2...');
  console.log('   Market: "Will BTC hit $150k by EOY?"');
  console.log('   Outcome: YES');
  console.log('   Stake: 50 BB');
  console.log('   → Dealer fronts bet immediately (great UX!)');
  
  // Step 4: L2 requests reimbursement
  console.log('\n💰 Step 4: L2 → L1 Reimbursement (gRPC)...');
  console.log('   L2 calls: SettlementNode.RequestReimbursement');
  console.log('   L1 moves: Alice locked 50 → Dealer');
  console.log('   Alice locked: 50 BB, Dealer: +50 BB');
  
  // Step 5: Bet resolves
  console.log('\n🎲 Step 5: Market resolves to YES! Alice wins!');
  console.log('   Payout: 2x stake = 100 BB');
  
  // Step 6: Settlement
  console.log('\n✅ Step 6: L2 → L1 Settlement (gRPC)...');
  console.log('   L2 calls: SettlementNode.ExecuteSettlement');
  console.log('   L1 moves: Dealer → Alice: 100 BB');
  console.log('   Final: Alice L1: 10,050 BB (+50 profit)');
  
  console.log('\n═══════════════════════════════════════════════════════════════');
  console.log('  FLOW COMPLETE');
  console.log('═══════════════════════════════════════════════════════════════');
}

// ============================================================================
// GRPC MESSAGE BUILDERS (for L2 to call L1)
// ============================================================================

/**
 * Build a ReimbursementRequest message
 * Used by L2 when Dealer fronts a bet
 */
export function buildReimbursementRequest(params) {
  const { dealerWallet, userAddress, betId, amount, nonce } = params;
  
  const timestamp = Date.now();
  const message = JSON.stringify({
    dealer_address: dealerWallet.l1Address,
    user_address: userAddress,
    bet_id: betId,
    amount: bbToMicrotokens(amount),
    nonce,
    timestamp
  });
  
  const signature = signWithDomainSeparation(
    dealerWallet.privateKey, 
    message, 
    CHAIN_ID_L2  // L2 is making this request
  );
  
  return {
    dealer_address: dealerWallet.l1Address,
    user_address: userAddress,
    bet_id: betId,
    amount: bbToMicrotokens(amount),
    public_key: dealerWallet.publicKey,
    signature: Buffer.from(signature, 'hex'),
    nonce,
    timestamp,
    chain_id: CHAIN_ID_L2
  };
}

/**
 * Build a SettlementRequest message
 * Used by L2 when a bet resolves
 */
export function buildSettlementRequest(params) {
  const { 
    dealerWallet, 
    userAddress, 
    beneficiary,
    betId, 
    marketId,
    outcome,
    stakeAmount,
    payoutAmount,
    intentHash,
    nonce 
  } = params;
  
  const timestamp = Date.now();
  const message = JSON.stringify({
    dealer_address: dealerWallet.l1Address,
    user_address: userAddress,
    beneficiary,
    bet_id: betId,
    market_id: marketId,
    outcome,
    stake_amount: bbToMicrotokens(stakeAmount),
    payout_amount: bbToMicrotokens(payoutAmount),
    nonce,
    timestamp
  });
  
  const signature = signWithDomainSeparation(
    dealerWallet.privateKey,
    message,
    CHAIN_ID_L2
  );
  
  return {
    dealer_address: dealerWallet.l1Address,
    user_address: userAddress,
    beneficiary,
    bet_id: betId,
    market_id: marketId,
    outcome,
    stake_amount: bbToMicrotokens(stakeAmount),
    payout_amount: bbToMicrotokens(payoutAmount),
    public_key: dealerWallet.publicKey,
    signature: Buffer.from(signature, 'hex'),
    intent_hash: intentHash,
    nonce,
    timestamp,
    chain_id: CHAIN_ID_L2
  };
}

// ============================================================================
// EXPORTS
// ============================================================================

export default {
  // Constants
  CHAIN_ID_L1,
  CHAIN_ID_L2,
  DEALER_ADDRESS,
  L1_REST_URL,
  L1_GRPC_URL,
  L2_REST_URL,
  
  // Address utilities
  deriveAddresses,
  l1ToL2Address,
  l2ToL1Address,
  stripPrefix,
  
  // Amount utilities
  bbToMicrotokens,
  microtokensToBb,
  
  // Signature utilities
  signWithDomainSeparation,
  createIntentHash,
  
  // Clients
  L1Client,
  L2Client,
  UnifiedWallet,
  
  // Test accounts
  TEST_ACCOUNTS,
  createTestWallet,
  
  // gRPC message builders
  buildReimbursementRequest,
  buildSettlementRequest,
  
  // Examples
  exampleBettingFlow
};
